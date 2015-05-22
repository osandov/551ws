#include <assert.h>
#include "551r2.h"

static int (*orig_open)(const char *, int, ...);
static int (*orig_close)(int);
static int (*orig_fxstat)(int, int, struct stat *);

static void *log_mmap;
static size_t log_size;
static char *log_ptr;

__attribute__((constructor))
static void init(void)
{
	char *error;
	char *log_file;
	int log_fd;
	struct stat st;

	(void)dlerror();
	orig_open = dlsym(RTLD_NEXT, "open");
	orig_close = dlsym(RTLD_NEXT, "close");
	orig_fxstat = dlsym(RTLD_NEXT, "__fxstat");
	error = dlerror();
	if (error) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	log_file = getenv("551R2");
	if (!log_file) {
		fprintf(stderr, "551R2 environment variable must be set\n");
		exit(EXIT_FAILURE);
	}

	log_fd = orig_open(log_file, O_RDONLY);
	if (log_fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (orig_fxstat(1, log_fd, &st) == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	log_size = st.st_size;

	log_mmap = mmap(NULL, log_size, PROT_READ, MAP_SHARED, log_fd, 0);
	if (log_mmap == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	if (orig_close(log_fd) == -1)
		perror("close");

	log_ptr = log_mmap;
	if (memcmp(log_ptr, R2_LOG_MAGIC, R2_LOG_MAGIC_LEN) != 0) {
		fprintf(stderr, "log magic does not match\n");
		exit(EXIT_FAILURE);
	}
	log_ptr += R2_LOG_MAGIC_LEN;
}

static void *xalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

static void log_overflow(char *arg)
{
	fprintf(stderr, "log overflow on %s\n", arg);
	exit(EXIT_FAILURE);
}

static void log_func_mismatch(char *arg, int func)
{
	fprintf(stderr, "log mismatch on function %s (got %d)\n", arg, func);
	exit(EXIT_FAILURE);
}

static void log_mismatch(char *arg)
{
	fprintf(stderr, "log mismatch on argument %s\n", arg);
	exit(EXIT_FAILURE);
}

#define LOG_READ_FUNC(_func, var)			\
	struct _func##_log *var = (void *)log_ptr;	\
	log_ptr += sizeof(struct _func##_log);		\
	if ((log_ptr - (char *)log_mmap) > log_size)	\
		log_overflow(#_func);			\
	if (var->func != LOG_##_func)			\
		log_func_mismatch(#_func, var->func);	\
	(void)0

#define LOG_READ_STR(len, var)				\
	char *var = log_ptr;				\
	log_ptr += len;					\
	if ((log_ptr - (char *)log_mmap) > log_size)	\
		log_overflow(#var);			\
	(void)0

#define LOG_READ_ARRAY(type, num, var)			\
	type *var = (void *)log_ptr;			\
	log_ptr += num * sizeof(type);			\
	if ((log_ptr - (char *)log_mmap) > log_size)	\
		log_overflow(#var);			\
	(void)0

time_t time(time_t *t)
{
	LOG_READ_FUNC(time, log);

	if (t)
		*t = log->ret;
	return log->ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	LOG_READ_FUNC(clock_gettime, log);
	int ret;

	if (clk_id != log->clk_id)
		log_mismatch("clock_gettime.clk_id");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		*tp = log->res;
	}
	return ret;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	LOG_READ_FUNC(localtime_r, log);
	LOG_READ_STR(log->tm_zone_len, log_tm_zone);

	if (*timep != log->time)
		log_mismatch("localtime_r.time");

	*result = log->res;
	result->tm_zone = log_tm_zone;
	return result;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	LOG_READ_FUNC(gmtime_r, log);
	LOG_READ_STR(log->tm_zone_len, log_tm_zone);

	if (*timep != log->time)
		log_mismatch("gmtime_r.time");

	*result = log->res;
	result->tm_zone = log_tm_zone;
	return result;
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	struct addrinfo *ai;
	LOG_READ_FUNC(getaddrinfo, log);
	LOG_READ_STR(log->node_len, log_node);
	LOG_READ_STR(log->service_len, log_service);

	if (strcmp(node, log_node) != 0)
		log_mismatch("getaddrinfo.node");
	if (strcmp(service, log_service) != 0)
		log_mismatch("getaddrinfo.service");

	if (log->ret)
		return log->ret;

	ai = xalloc(sizeof(struct addrinfo));
	*ai = log->res;
	ai->ai_addr = xalloc(log->res.ai_addrlen);
	memcpy(ai->ai_addr, &log->res_addr, log->res.ai_addrlen);
	ai->ai_canonname = NULL; /* XXX */
	ai->ai_next = NULL; /* XXX */

	*res = ai;
	return 0;
}

void freeaddrinfo(struct addrinfo *res)
{
	free(res->ai_addr);
	free(res);
}

int chdir(const char *path)
{
	LOG_READ_FUNC(chdir, log);
	LOG_READ_STR(log->path_len, log_path);
	int ret;

	if (strcmp(path, log_path) != 0)
		log_mismatch("chdir.path");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	LOG_READ_FUNC(sigprocmask, log);
	int ret;

	if (how != log->how)
		log_mismatch("sigprocmask.how");
	if (memcmp(set, &log->set, sizeof(sigset_t)) != 0)
		log_mismatch("sigprocmask.set");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		if (oldset)
			*oldset = log->oldset;
	}
	return ret;
}

int signalfd(int fd, const sigset_t *mask, int flags)
{
	LOG_READ_FUNC(signalfd, log);
	int ret;

	if (fd != log->fd)
		log_mismatch("signalfd.fd");
	if (memcmp(mask, &log->mask, sizeof(sigset_t)) != 0)
		log_mismatch("signalfd.set");
	if (flags != log->flags)
		log_mismatch("signalfd.flags");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int socket(int domain, int type, int protocol)
{
	LOG_READ_FUNC(socket, log);
	int ret;

	if (domain != log->domain)
		log_mismatch("socket.domain");
	if (type != log->type)
		log_mismatch("socket.type");
	if (protocol != log->protocol)
		log_mismatch("socket.protocol");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	LOG_READ_FUNC(bind, log);
	int ret;

	if (sockfd != log->sockfd)
		log_mismatch("bind.sockfd");
	if (addrlen != log->addrlen)
		log_mismatch("bind.addrlen");
	if (memcmp(addr, &log->addr, addrlen) != 0)
		log_mismatch("bind.addr");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int listen(int sockfd, int backlog)
{
	LOG_READ_FUNC(listen, log);
	int ret;

	if (sockfd != log->sockfd)
		log_mismatch("listen.sockfd");
	if (backlog != log->backlog)
		log_mismatch("listen.backlog");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	LOG_READ_FUNC(accept, log);
	int ret;

	if (sockfd != log->sockfd)
		log_mismatch("accept.sockfd");
	if (addrlen && *addrlen != log->addrlen_in)
		log_mismatch("accept.addrlen_in");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		if (addrlen)
			*addrlen = log->addrlen_out;
		if (addr)
			memcpy(addr, &log->addr, log->addrlen_out);
	}
	return ret;
}

int epoll_create1(int flags)
{
	LOG_READ_FUNC(epoll_create1, log);
	int ret;

	if (flags != log->flags)
		log_mismatch("epoll_create1.flags");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

static struct epoll_data_mapping {
	epoll_data_t logged;
	epoll_data_t runtime;
	struct epoll_data_mapping *left, *right;
} *epoll_data_map;

static void epoll_data_add_mapping(epoll_data_t logged, epoll_data_t runtime)
{
	struct epoll_data_mapping **node = &epoll_data_map;

	while (*node) {
		if (logged.u64 < (*node)->logged.u64) {
			node = &(*node)->left;
		} else if (logged.u64 > (*node)->logged.u64) {
			node = &(*node)->right;
		} else {
			/*
			 * TODO: This can happen if malloc returned the same
			 * pointer for a second instance of the data in the log.
			 * If we implement removing mappings when the epoll
			 * event is removed, however, this shouldn't ever
			 * happen.
			 */
			(*node)->runtime = runtime;
			return;
		}
	}
	*node = xalloc(sizeof(struct epoll_data_mapping));
	(*node)->logged = logged;
	(*node)->runtime = runtime;
	(*node)->left = (*node)->right = NULL;
}

static epoll_data_t epoll_data_lookup_mapping(epoll_data_t logged)
{
	struct epoll_data_mapping *node = epoll_data_map;

	while (node) {
		if (logged.u64 < node->logged.u64)
			node = node->left;
		else if (logged.u64 > node->logged.u64)
			node = node->right;
		else
			return node->runtime;
	}
	assert(0);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	LOG_READ_FUNC(epoll_ctl, log);
	int ret;

	if (epfd != log->epfd)
		log_mismatch("epoll_ctl.epfd");
	if (op != log->op)
		log_mismatch("epoll_ctl.op");
	if (fd != log->fd)
		log_mismatch("epoll_ctl.fd");
	if (event->events != log->event.events)
		log_mismatch("epoll_ctl.event.events");

	/*
	 * event->data will be different because we don't intercept malloc, and
	 * some of these are on the stack. We need to map the logged event->data
	 * to the passed event->data so epoll_wait can return the real one.
	 */
	epoll_data_add_mapping(log->event.data, event->data);

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	LOG_READ_FUNC(epoll_wait, log);
	int ret;

	if (epfd != log->epfd)
		log_mismatch("epoll_wait.epfd");
	if (maxevents != log->maxevents)
		log_mismatch("epoll_wait.maxevents");
	if (timeout != log->timeout)
		log_mismatch("epoll_wait.timeout");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		LOG_READ_ARRAY(struct epoll_event, ret, log_events);
		memcpy(events, log_events, ret * sizeof(struct epoll_event));
		for (int i = 0; i < ret; i++)
			events[i].data = epoll_data_lookup_mapping(events[i].data);
	}
	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	LOG_READ_FUNC(read, log);
	ssize_t ret;

	if (fd != log->fd)
		log_mismatch("read.fd");
	if (count != log->count)
		log_mismatch("read.count");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		LOG_READ_STR(log->ret, log_buf);
		memcpy(buf, log_buf, log->ret);
	}
	return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	LOG_READ_FUNC(write, log);
	LOG_READ_STR(log->count, log_buf);
	ssize_t ret;

	if (fd != log->fd)
		log_mismatch("write.fd");
	if (count != log->count)
		log_mismatch("write.count");
	if (memcmp(buf, log_buf, count) != 0)
		log_mismatch("write.buf");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int open(const char *pathname, int flags, ...)
{
	LOG_READ_FUNC(open, log);
	LOG_READ_STR(log->pathname_len, log_pathname);
	va_list ap;
	mode_t mode;
	int ret;

	if (strcmp(pathname, log_pathname) != 0)
		log_mismatch("open.pathname");
	if (flags != log->flags)
		log_mismatch("open.flags");
	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		if (mode != log->mode)
			log_mismatch("open.mode");
	}

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int close(int fd)
{
	LOG_READ_FUNC(close, log);
	int ret;

	if (fd != log->fd)
		log_mismatch("close.fd");

	/*
	 * TODO: if this is a client file descriptor, remove epoll event
	 * mappings.
	 */

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
	}
	return ret;
}

int __fxstat(int ver, int fd, struct stat *buf)
{
	LOG_READ_FUNC(fxstat, log);
	int ret;

	if (ver != log->ver)
		log_mismatch("fxstat.ver");
	if (fd != log->fd)
		log_mismatch("fxstat.fd");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		*buf = log->res;
	}
	return ret;
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	LOG_READ_FUNC(sendfile, log);
	int ret;

	if (out_fd != log->out_fd)
		log_mismatch("sendfile.out_fd");
	if (in_fd != log->in_fd)
		log_mismatch("sendfile.in_fd");
	if (offset && *offset != log->offset_in)
		log_mismatch("sendfile.offset_in");
	if (count != log->count)
		log_mismatch("sendfile.count");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		ret = log->ret;
		LOG_READ_STR(log->ret, log_buf);
		if (!offset) {
			/*
			 * !offset is a hack to avoid printing the file contents
			 * twice: once for the hashing and once for the reply.
			 */
			fwrite(log_buf, 1, log->ret, stdout);
		}
		(void)log_buf;
		if (offset)
			*offset = log->offset_out;
	}
	return ret;
}

int dprintf(int fd, const char *format, ...)
{
	LOG_READ_FUNC(dprintf, log);
	int ret;
	va_list ap;
	char buf[4096];

	if (fd != log->fd)
		log_mismatch("dprintf.fd");

	if (log->ret < 0) {
		ret = -1;
		errno = -log->ret;
	} else {
		va_start(ap, format);
		ret = vsnprintf(buf, sizeof(buf), format, ap);
		va_end(ap);
		if (ret >= sizeof(buf)) {
			fprintf(stderr, "dprintf too big\n");
			exit(EXIT_FAILURE);
		}

		if (ret != log->ret)
			log_mismatch("dprintf.buf_len");

		LOG_READ_STR(log->ret, log_buf);
		fwrite(log_buf, 1, log->ret, stdout);

		if (memcmp(buf, log_buf, log->ret) != 0)
			log_mismatch("dprintf.buf");
	}
	return ret;
}
