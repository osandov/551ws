#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_alg.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "http_parser.h"

enum {
	FD_SIGNAL,
	FD_SERVER,
	FD_CLIENT,
};

struct epoll_fd_data {
	int type;
};

enum {
	HEADER_STATE_NOTHING,
	HEADER_STATE_FIELD,
	HEADER_STATE_VALUE,
};

struct header {
	char *field, *value;
	size_t field_len, value_len;
};

struct ws_client {
	struct epoll_fd_data epoll;
	int fd;
	struct ws_client *next, *prev;
	http_parser parser;

	char *url;
	size_t url_len;

	int close;
	int header_state;
	struct header *headers;
	size_t num_headers;
};

/* Root directory of the web server. */
static char *root_path;

/* Server file descriptor. */
static int server_fd = -1;

/* Epoll file descriptor. */
static int epoll_fd = -1;

/* AF_ALG SHA-1 file descriptor. */
static int sha_fd = -1;

static struct ws_client *clients_head;
static http_parser_settings parser_settings;

static int log_level = 0;

 __attribute__((format(printf, 2, 3)))
static inline void wslog(int level, const char *format, ...)
{
	static time_t prev_time = 0;
	static struct timespec prev_tp = {};
	time_t t;
	struct tm tm;
	struct timespec tp;
	int ret;
	int len;
	char buf[100] = "";
	va_list ap;

	if (log_level < level)
		return;

	t = time(NULL);
	ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	if (ret == -1) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	if (!localtime_r(&t, &tm)) {
		perror("localtime_r");
		exit(EXIT_FAILURE);
	}
	ret = strftime(buf, sizeof(buf), "%b%d %T", &tm);
	if (ret == 0) {
		perror("strftime");
		exit(EXIT_FAILURE);
	}
	len = strlen(buf);
	if (t == prev_time) {
		struct timespec delta = tp;
		delta.tv_nsec -= prev_tp.tv_nsec;
		if (delta.tv_nsec < 0) {
			delta.tv_nsec += 1000000000L;
			delta.tv_sec--;
		}
		delta.tv_sec -= prev_tp.tv_sec;
		snprintf(buf, sizeof(buf), "%+ld.%09ld", (long)delta.tv_sec, delta.tv_nsec);
	}
	prev_time = t;
	prev_tp = tp;
	fprintf(stderr, "[%*s] ", len, buf);

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void log_accept(const struct sockaddr *addr, socklen_t addrlen, int fd)
{
	const struct sockaddr_in *addr_in;

	switch (addr->sa_family) {
	case AF_INET:
		addr_in = (const struct sockaddr_in *)addr;
		wslog(1, "accepted %d from %s:%" PRIu32 "\n", fd,
		      inet_ntoa(addr_in->sin_addr), addr_in->sin_port);
		break;
	case AF_INET6:
		break;
	default:
		wslog(1, "accepted %d from unknown family\n", fd);
		break;
	}
}

static void log_request(http_parser *parser)
{
	struct ws_client *client = parser->data;

	wslog(1, "\"%s %s\" from %d\n", http_method_str(parser->method),
	      client->url, client->fd);
	for (size_t i = 0; i < client->num_headers; i++)
		wslog(1, "header for %d \"%s: %s\"\n", client->fd,
		      client->headers[i].field, client->headers[i].value);
}

static int init_seccomp_sandbox(void)
{
	scmp_filter_ctx ctx = NULL;
	int ret;

	wslog(0, "sandboxing with seccomp-bpf\n");

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (!ctx)
		return -1;

	/* Allow exit_group() and rt_sigreturn(). */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	if (ret < 0)
		goto out;
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	if (ret < 0)
		goto out;

	/* Allow close(). */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (ret < 0)
		goto out;

	/* Allow epoll_wait() on the epoll fd. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 1,
			       SCMP_A0(SCMP_CMP_EQ, epoll_fd));
	if (ret < 0)
		goto out;

	/* Allow accept() on the server fd and the AF_ALG fd. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 1,
			       SCMP_A0(SCMP_CMP_EQ, server_fd));
	if (ret < 0)
		goto out;
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 1,
			       SCMP_A0(SCMP_CMP_EQ, sha_fd));
	if (ret < 0)
		goto out;

	/* Allow epoll_ctl() EPOLL_CTL_ADD on the epoll fd. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 2,
			       SCMP_A0(SCMP_CMP_EQ, epoll_fd),
			       SCMP_A1(SCMP_CMP_EQ, EPOLL_CTL_ADD));
	if (ret < 0)
		goto out;

	/* Allow read(). This is for the signal fd and the client fds. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if (ret < 0)
		goto out;

	/* Allow write(). This is for stderr and the client fds. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (ret < 0)
		goto out;

	/* Allow open() with O_RDONLY. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			       SCMP_A1(SCMP_CMP_MASKED_EQ,
				       O_RDONLY | O_RDWR | O_WRONLY,
				       O_RDONLY));
	if (ret < 0)
		goto out;

	/*
	 * Allow fstat() and stat(). The latter is used for timezone stuff in
	 * libc.
	 */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	if (ret < 0)
		goto out;
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	if (ret < 0)
		goto out;

	/* Allow lseek() for dprintf(). */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
	if (ret < 0)
		goto out;

	/* Allow sendfile(). */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
	if (ret < 0)
		goto out;

	/* Allow brk()/mmap()/munmap() for malloc. */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	if (ret < 0)
		goto out;
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
	if (ret < 0)
		goto out;
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
	if (ret < 0)
		goto out;

	/* Load the seccomp context into the kernel. */
	ret = seccomp_load(ctx);
	if (ret < 0)
		goto out;

out:
	seccomp_release(ctx);
	if (ret) {
		errno = -ret;
		return -1;
	}
	return 0;
}

static void add_client(int client_fd)
{
	struct ws_client *client;
	struct epoll_event event;
	int ret;

	client = calloc(1, sizeof(*client));
	if (!client) {
		perror("calloc");
		if (close(client_fd) == -1)
			perror("close");
		return;
	}

	client->epoll.type = FD_CLIENT;
	client->fd = client_fd;

	event.events = EPOLLIN;
	event.data.ptr = client;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
	if (ret == -1) {
		perror("epoll_ctl");
		free(client);
		if (close(client_fd) == -1)
			perror("close");
		return;
	}

	client->prev = NULL;
	client->next = clients_head;
	if (clients_head)
		clients_head->prev = client;
	clients_head = client;

	http_parser_init(&client->parser, HTTP_REQUEST);
	client->parser.data = client;
}

static void cleanup_client_http(struct ws_client *client)
{
	free(client->url);
	client->url = NULL;
	client->url_len = 0;
	for (size_t i = 0; i < client->num_headers; i++) {
		free(client->headers[i].field);
		free(client->headers[i].value);
	}
	free(client->headers);
	client->headers = NULL;
	client->num_headers = 0;
}

static void remove_client(struct ws_client *client)
{
	wslog(1, "removing client %d\n", client->fd);

	if (close(client->fd) == -1)
		perror("close");

	if (client->prev) {
		client->prev->next = client->next;
	} else {
		assert(client == clients_head);
		clients_head = client->next;
	}
	if (client->next)
		client->next->prev = client->prev;

	cleanup_client_http(client);
	free(client);
}

static void cleanup_clients(void)
{
	while (clients_head)
		remove_client(clients_head);
}

static int on_message_begin(http_parser *parser)
{
	struct ws_client *client = parser->data;

	cleanup_client_http(client);
	return 0;
}

static int on_url(http_parser *parser, const char *buf, size_t len)
{
	struct ws_client *client = parser->data;
	char *new_url;

	new_url = realloc(client->url, client->url_len + len + 1);
	if (!new_url) {
		perror("realloc");
		return -1;
	}

	client->url = new_url;
	memcpy(client->url + client->url_len, buf, len);
	client->url_len += len;
	client->url[client->url_len] = '\0';

	return 0;
}

static int on_header_field(http_parser *parser, const char *buf, size_t len)
{
	struct ws_client *client = parser->data;
	struct header *new_headers, *current_header;
	char *new_field;

	switch (client->header_state) {
	case HEADER_STATE_NOTHING:
	case HEADER_STATE_VALUE:
		/* New header started. */
		new_headers = realloc(client->headers,
				      sizeof(struct header) * (client->num_headers + 1));
		if (!new_headers) {
			perror("realloc");
			return -1;
		}
		client->headers = new_headers;
		client->num_headers++;
		memset(&client->headers[client->num_headers - 1], 0,
		       sizeof(struct header));

		/* Fallthrough. */
	case HEADER_STATE_FIELD:
		/* Previous name continues. */
		current_header = &client->headers[client->num_headers - 1];
		new_field = realloc(current_header->field,
				    current_header->field_len + len + 1);
		if (!new_field) {
			perror("realloc");
			return -1;
		}

		current_header->field = new_field;
		memcpy(current_header->field + current_header->field_len, buf,
		       len);
		current_header->field_len += len;
		current_header->field[current_header->field_len] = '\0';
		break;
	default:
		assert(0);
		break;
	}

	client->header_state = HEADER_STATE_FIELD;

	return 0;
}

static int on_header_value(http_parser *parser, const char *buf, size_t len)
{
	struct ws_client *client = parser->data;
	struct header *current_header;
	char *new_value;

	current_header = &client->headers[client->num_headers - 1];

	switch (client->header_state) {
	case HEADER_STATE_FIELD:
		/* Value for current header started. */
		/* Fallthrough. */
	case HEADER_STATE_VALUE:
		/* Value continues. */
		new_value = realloc(current_header->value,
				    current_header->value_len + len + 1);
		if (!new_value) {
			perror("realloc");
			return -1;
		}

		current_header->value = new_value;
		memcpy(current_header->value + current_header->value_len, buf,
		       len);
		current_header->value_len += len;
		current_header->value[current_header->value_len] = '\0';
		break;
	default:
		assert(0);
		break;
	}

	client->header_state = HEADER_STATE_VALUE;

	return 0;
}

static int send_http_response(http_parser *parser, int status_code,
			      char *status_msg, int fd)
{
	struct ws_client *client = parser->data;
	time_t t;
	struct tm tm;
	char date[30];
	struct stat st = {};
	int ret;
	ssize_t sret;
	int close_header, etag_header = 0;
	char etag[43];

	t = time(NULL);
	if (!gmtime_r(&t, &tm)) {
		perror("gmtime_r");
		abort();
	}

	ret = strftime(date, sizeof(date), "%a, %d %b %Y %T %Z", &tm);
	if (ret == 0) {
		perror("strftime");
		abort();
	}

	if (fd != -1) {
		ret = fstat(fd, &st);
		if (ret == -1) {
			perror("fstat");
			return -1;
		}
	}

	client->close = !http_should_keep_alive(parser);
	close_header = client->close && (parser->http_major > 1 ||
					 parser->http_minor >= 1);

	if (status_code == 200) {
		int opfd;
		off_t offset = 0;
		uint8_t buf[20];
		size_t i;

		/* Compute the SHA-1 of the file. */
		opfd = accept(sha_fd, NULL, NULL);
		if (opfd == -1) {
			perror("accept AF_ALG");
			goto respond;
		}
		while (offset < st.st_size) {
			sret = sendfile(opfd, fd, &offset, st.st_size - offset);
			if (sret == -1) {
				perror("sendfile AF_ALG");
				close(opfd);
				goto respond;
			}
		}
		sret = read(opfd, buf, 20);
		if (sret != sizeof(buf)) {
			assert(sret == -1);
			perror("read AF_ALG");
			close(opfd);
			goto respond;
		}
		close(opfd);

		/* Format the ETag as a quoted hexadecimal string. */
		etag[0] = '"';
		for (i = 0; i < 20; i++)
			sprintf(&etag[1 + 2 * i], "%02x", buf[i]);
		etag[41] = '"';
		etag[42] = '\0';
		etag_header = 1;

		/* Look for an If-None-Match header. */
		for (i = 0; i < client->num_headers; i++) {
			if (strcmp(client->headers[i].field, "If-None-Match") == 0)
				break;
		}

		if (i < client->num_headers &&
		    strcmp(client->headers[i].value, etag) == 0) {
			/*
			 * The If-None-Match matches the ETag, so the file
			 * hasn't changed. Replace the 200 with a 304 and don't
			 * send the file.
			 */
			status_code = 304;
			status_msg = "Not Modified";
			st.st_size = 0;
			etag_header = 0;
		}
	}

respond:
	ret = dprintf(client->fd, 
		      "HTTP/%hu.%hu %d %s\r\n"
		      "Server: 551ws\r\n"
		      "Date: %s\r\n"
		      "Content-Length: %jd\r\n",
		      parser->http_major, parser->http_minor,
		      status_code, status_msg, date,
		      (intmax_t)st.st_size);
	if (ret < 0) {
		perror("dprintf");
		return -1;
	}
	if (etag_header) {
		ret = dprintf(client->fd, "ETag: %s\r\n", etag);
		if (ret < 0) {
			perror("dprintf");
			return -1;
		}
	}
	if (close_header) {
		ret = dprintf(client->fd, "Connection: close\r\n");
		if (ret < 0) {
			perror("dprintf");
			return -1;
		}
	}
	ret = dprintf(client->fd, "\r\n");
	if (ret < 0) {
		perror("dprintf");
		return -1;
	}

	while (st.st_size > 0) {
		sret = sendfile(client->fd, fd, NULL, st.st_size);
		if (sret == -1) {
			perror("sendfile");
			return -1;
		}
		st.st_size -= sret;
	}

	return 0;
}

static int send_http_error(http_parser *parser, int status_code,
			   char *status_msg)
{
	char buf[9];
	int ret;
	int fd;

	ret = snprintf(buf, sizeof(buf), "%d.html", status_code);
	assert(ret < sizeof(buf));

	fd = open(buf, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
		perror("open");

	ret = send_http_response(parser, status_code, status_msg, fd);
	
	if (fd != -1) {
		if (close(fd) == -1)
			perror("close");
	}

	return ret;
}

static void decode_path(char *url_path)
{
	char *p = url_path, *q = url_path;
	uint8_t byte;
	char h, l;

	while (*p) {
		if (*p == '%' && (h = *(p + 1)) && (l = *(p + 2)) &&
		    isxdigit(h) && isxdigit(l)) {
			if ('a' <= h && h <= 'f')
				h -= ('a' - 10);
			else if ('A' <= h && h <= 'F')
				h -= ('A' - 10);
			else if ('0' <= h && h <= '9')
				h -= '0';
			if ('a' <= l && l <= 'f')
				l -= ('a' - 10);
			else if ('A' <= l && l <= 'F')
				l -= ('A' - 10);
			else if ('0' <= l && l <= '9')
				l -= '0';
			byte = (uint8_t)(h << 4) | (uint8_t)l;
			if (byte < 0x20 || byte > 0x7e) {
				*q++ = *p++;
				*q++ = *p++;
				*q++ = *p++;
			} else {
				*q++ = byte;
				p += 3;
			}
		} else {
			*q++ = *p++;
		}
	}
	*q = '\0';
}

static void remove_dot_components(char *url_path)
{
	char *p = url_path + 1, *q = url_path;

	assert(url_path[0] == '/');

	/*
	 * Loop through the path components.
	 *
	 * Loop invariant: q points to the location where we should output a
	 * slash followed by the next path component.
	 */
	while (1) {
		char *sep = strchrnul(p, '/');
		int len = sep - p;

		if (len == 2 && p[0] == '.' && p[1] == '.') {
			/* For "..", back up by one path component. */
			if (q != url_path) {
				while (*--q != '/')
					;
			}
		} else if (!((len == 0 && *sep) || (len == 1 && p[0] == '.'))) {
			/*
			 * For ".", do nothing. For "", only add it if it's the
			 * last component (e.g., add it in "/foo/", but not
			 * "/foo//bar".
			 */
			*q++ = '/';
			memmove(q, p, len);
			q += len;
		}

		if (*sep) {
			p = sep + 1;
		} else {
			break;
		}
	}
	if (q == url_path)
		*q++ = '/';
	*q = '\0';
}

static int on_message_complete(http_parser *parser)
{
	struct ws_client *client = parser->data;
	struct http_parser_url url;
	char *url_path;
	int fd;
	int ret;

	log_request(parser);

	if (parser->method != HTTP_GET)
		return send_http_error(parser, 501, "Not Implemented");

	ret = http_parser_parse_url(client->url, client->url_len,
				    0, &url);
	if (ret == -1 || !(url.field_set & (1 << UF_PATH)))
		return send_http_error(parser, 400, "Bad Request");

	url_path = client->url + url.field_data[UF_PATH].off;
	url_path[url.field_data[UF_PATH].len] = '\0';

	decode_path(url_path);
	remove_dot_components(url_path);

	assert(!strstr(url_path, "/../"));
	assert(!strstr(url_path, "/./"));
	assert(!strstr(url_path, "//"));
	assert(url_path[0] == '/');

	url_path++;
	fd = open(url_path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		switch (errno) {
		case EACCES:
		case ELOOP:
			return send_http_error(parser, 403, "Forbidden");
		case ENOENT:
			return send_http_error(parser, 404, "Not Found");
		default:
			return send_http_error(parser, 500, "Internal Server Error");
		}
	}

	ret = send_http_response(parser, 200, "OK", fd);

	if (close(fd) == -1)
		perror("close");

	return ret;
}

static void client_receive(struct ws_client *client)
{
	ssize_t ret, parsed;
	char buf[4096];

	ret = read(client->fd, buf, sizeof(buf));
	if (ret == -1) {
		perror("read");
		remove_client(client);
		return;
	}

	parsed = http_parser_execute(&client->parser, &parser_settings, buf, ret);

	if (client->parser.upgrade) {
		send_http_error(&client->parser, 501, "Not Implemented");
		remove_client(client);
		return;
	}
	if (parsed != ret) {
		if (HTTP_PARSER_ERRNO(&client->parser) >= HPE_INVALID_EOF_STATE)
			send_http_error(&client->parser, 400, "Bad Request");
		else
			send_http_error(&client->parser, 500, "Internal Server Error");
		remove_client(client);
		return;
	}

	if (ret == 0 || client->close)
		remove_client(client);
}

static void usage(int error)
{
	fprintf(error ? stderr : stdout,
		"Usage: %s -l ADDR:PORT -r ROOT_PATH [OPTION]...\n"
		"Run a minimal web server.\n"
		"\n"
		"Server options:\n"
		"  -l, --listen=ADDR:PORT    listen on address ADDR, port PORT (required)\n"
		"  -r, --root=ROOT_PATH      serve files from the directory ROOT_PATH (required)\n"
		"Security options:\n"
		"  -S, --seccomp             enable seccomp-bpf sandbox (recommended)\n"
		"Miscellaneous:\n"
		"  -d                        increase the debug level by one\n"
		"  --debug-level=DEBUG_LEVEL set the debug level to DEBUG_LEVEL\n"
		"  -h, --help                display this help text and exit\n",
		program_invocation_name);
	exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	char *node = NULL, *service = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	}, *addr = NULL;
	int seccomp = 0;
	sigset_t mask;
	struct epoll_event event, events[10];
	int ret, opt;
	ssize_t sret;
	int signal_fd = -1;
	struct epoll_fd_data signal_data, server_data;
	struct sockaddr_alg sha_sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1",
	};

	/* Parse command-line options. */
	while (1) {
		static struct option long_options[] = {
			{"listen",	required_argument,	NULL,	'l'},
			{"root",	required_argument,	NULL,	'r'},
			{"seccomp",	no_argument,		NULL,	'S'},
			{"debug-level",	required_argument,	NULL,	'd'},
			{"help",	no_argument, 		NULL,	'h'},
		};
		int c;

		c = getopt_long(argc, argv, "l:r:Sdh", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'l':
			free(node);
			node = NULL;
			free(service);
			service = NULL;
			ret = sscanf(optarg, "%m[^:]:%ms", &node, &service);
			if (ret != 2) {
				if (ret == -1) {
					perror("sscanf");
					exit(EXIT_FAILURE);
				}
				fprintf(stderr, "invalid listen address\n");
				goto usage_err;
			}
			break;
		case 'r':
			free(root_path);
			root_path = strdup(optarg);
			break;
		case 'S':
			seccomp = 1;
			break;
		case 'd':
			if (optarg)
				log_level = atoi(optarg);
			else
				log_level++;
			break;
		case 'h':
			free(node);
			free(service);
			free(root_path);
			usage(0);
			break;
		default:
usage_err:
			free(node);
			free(service);
			free(root_path);
			usage(1);
		}
	}
	if (!node || !service) {
		fprintf(stderr, "listen address is required\n");
		goto usage_err;
	}
	if (!root_path) {
		fprintf(stderr, "root path is required\n");
		goto usage_err;
	}

	/* Resolve the listen address. */
	wslog(0, "addr = %s:%s\n", node, service);
	ret = getaddrinfo(node, service, &hints, &addr);
	free(node);
	free(service);
	if (ret) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	/*
	 * Chdir to the root path.
	 * TODO: chroot would be better, but that requires CAP_SYS_CHROOT.
	 */
	wslog(0, "root = %s\n", root_path);
	ret = chdir(root_path);
	if (ret == -1) {
		perror("chdir");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Initialize the parser settings. */
	http_parser_settings_init(&parser_settings);
	parser_settings.on_message_begin = on_message_begin;
	parser_settings.on_url = on_url;
	parser_settings.on_header_field = on_header_field;
	parser_settings.on_header_value = on_header_value;
	parser_settings.on_message_complete = on_message_complete;

	/* Handle signals gracefully. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		perror("sigprocmask");
		ret = EXIT_FAILURE;
		goto out;
	}
	signal_fd = signalfd(-1, &mask, 0);
	if (signal_fd == -1) {
		perror("signalfd");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Create and bind the server socket and start listening. */

	wslog(0, "starting server...\n");

	server_fd = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol);
	if (server_fd == -1) {
		perror("socket");
		ret = EXIT_FAILURE;
		goto out;
	}
	opt = 1;
	ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	if (ret == -1) {
		perror("setsockopt");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = bind(server_fd, addr->ai_addr, addr->ai_addrlen);
	if (ret == -1) {
		perror("bind");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = listen(server_fd, SOMAXCONN);
	if (ret == -1) {
		perror("listen");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Set up epoll and add the signal fd and server fd. */
	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		perror("epoll_create1");
		ret = EXIT_FAILURE;
		goto out;
	}

	event.events = EPOLLIN;
	signal_data.type = FD_SIGNAL;
	event.data.ptr = &signal_data;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &event);
	if (ret == -1) {
		perror("epoll_ctl");
		ret = EXIT_FAILURE;
		goto out;
	}

	event.events = EPOLLIN;
	server_data.type = FD_SERVER;
	event.data.ptr = &server_data;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);
	if (ret == -1) {
		perror("epoll_ctl");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open an AF_ALG file descriptor for hashing files. */
	sha_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sha_fd == -1) {
		perror("socket AF_ALG");
		ret = EXIT_FAILURE;
		goto out;
	}
	ret = bind(sha_fd, (struct sockaddr *)&sha_sa, sizeof(sha_sa));
	if (ret == -1) {
		perror("bind AF_ALG");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Sandbox ourselves. */
	if (seccomp) {
		ret = init_seccomp_sandbox();
		if (ret == -1) {
			perror("seccomp");
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	wslog(0, "ready\n");

	/* Main event loop. */
	for (;;) {
		struct epoll_fd_data *data;
		struct signalfd_siginfo ssi;
		struct sockaddr client_addr;
		socklen_t client_addrlen = sizeof(client_addr);
		int client_fd;

		ret = epoll_wait(epoll_fd, events,
				 sizeof(events) / sizeof(events[0]), -1);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			ret = EXIT_FAILURE;
			goto out;
		}

		for (int i = 0; i < ret; i++) {
			data = events[i].data.ptr;
			switch (data->type) {
			case FD_SIGNAL:
				sret = read(signal_fd, &ssi, sizeof(ssi));
				if (sret == -1) {
					perror("read");
					ret = EXIT_FAILURE;
					goto out;
				}
				fprintf(stderr, "got signal %s; exiting\n",
					strsignal(ssi.ssi_signo));
				ret = EXIT_SUCCESS;
				goto out;
			case FD_SERVER:
				client_fd = accept(server_fd, &client_addr, &client_addrlen);
				if (client_fd == -1) {
					perror("accept");
					ret = EXIT_FAILURE;
					goto out;
				}
				log_accept(&client_addr, client_addrlen, client_fd);
				add_client(client_fd);
				break;
			case FD_CLIENT:
				client_receive((struct ws_client *)data);
				break;
			default:
				assert(0);
				break;
			}
		}
	}

out:
	cleanup_clients();
	if (sha_fd != -1) {
		if (close(sha_fd) == -1) {
			perror("close");
			ret = EXIT_FAILURE;
		}
	}
	if (epoll_fd != -1) {
		if (close(epoll_fd) == -1) {
			perror("close");
			ret = EXIT_FAILURE;
		}
	}
	if (server_fd != -1) {
		if (close(server_fd) == -1) {
			perror("close");
			ret = EXIT_FAILURE;
		}
	}
	if (signal_fd != -1) {
		if (close(signal_fd) == -1) {
			perror("close");
			ret = EXIT_FAILURE;
		}
	}
	free(root_path);
	if (addr)
		freeaddrinfo(addr);
	return ret;
}
