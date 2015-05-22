#include "551r2.h"

static int log_fd = -1;

static time_t (*orig_time)(time_t *);
static int (*orig_clock_gettime)(clockid_t, struct timespec *);
static struct tm *(*orig_localtime_r)(const time_t *, struct tm *);
static struct tm *(*orig_gmtime_r)(const time_t *, struct tm *);
static int (*orig_getaddrinfo)(const char *, const char *,
			       const struct addrinfo *, struct addrinfo **);
static int (*orig_chdir)(const char *);
static int (*orig_sigprocmask)(int, const sigset_t *, sigset_t *);
static int (*orig_signalfd)(int, const sigset_t *, int);
static int (*orig_socket)(int, int, int);
static int (*orig_bind)(int, const struct sockaddr *, socklen_t);
static int (*orig_listen)(int, int);
static int (*orig_accept)(int, struct sockaddr *, socklen_t *);
static int (*orig_epoll_create1)(int);
static int (*orig_epoll_ctl)(int, int, int, struct epoll_event *);
static int (*orig_epoll_wait)(int, struct epoll_event *, int, int);
static ssize_t (*orig_read)(int, void *, size_t);
static ssize_t (*orig_write)(int, const void *, size_t);
static int (*orig_open)(const char *, int, ...);
static int (*orig_close)(int);
static int (*orig_fxstat)(int, int, struct stat *);

static void log_write(const void *buf, size_t count)
{
	ssize_t sret;

	while (count > 0) {
		sret = orig_write(log_fd, buf, count);
		if (sret == -1) {
			if (errno == EINTR)
				continue;
			perror("write");
			exit(EXIT_FAILURE);
		}
		buf += sret;
		count -= sret;
	}
}

__attribute__((constructor))
static void init(void)
{
	char *log_file;
	char *error;

	(void)dlerror();
	orig_time = dlsym(RTLD_NEXT, "time");
	orig_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
	orig_localtime_r = dlsym(RTLD_NEXT, "localtime_r");
	orig_gmtime_r = dlsym(RTLD_NEXT, "gmtime_r");
	orig_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
	orig_chdir = dlsym(RTLD_NEXT, "chdir");
	orig_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");
	orig_signalfd = dlsym(RTLD_NEXT, "signalfd");
	orig_socket = dlsym(RTLD_NEXT, "socket");
	orig_bind = dlsym(RTLD_NEXT, "bind");
	orig_listen = dlsym(RTLD_NEXT, "listen");
	orig_accept = dlsym(RTLD_NEXT, "accept");
	orig_epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");
	orig_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl"); 
	orig_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
	orig_read = dlsym(RTLD_NEXT, "read");
	orig_write = dlsym(RTLD_NEXT, "write");
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

	log_fd = orig_open(log_file, O_WRONLY | O_TRUNC | O_APPEND | O_CREAT, 0600);
	if (log_fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	log_write(R2_LOG_MAGIC, R2_LOG_MAGIC_LEN);
}

__attribute__((destructor))
static void fini(void)
{
	if (orig_close(log_fd) == -1)
		perror("close");
}

time_t time(time_t *t)
{
	struct time_log log = {
		LOG_time,
	};

	log.ret = orig_time(t);

	log_write(&log, sizeof(log));

	return log.ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	struct clock_gettime_log log = {
		LOG_clock_gettime,
		clk_id,
	};
	int ret;

	ret = orig_clock_gettime(clk_id, tp);
	if (ret == -1) {
		log.ret = -errno;
	} else {
		log.ret = ret;
		log.res = *tp;
	}

	log_write(&log, sizeof(log));

	return ret;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	struct localtime_r_log log = {
		LOG_localtime_r,
		*timep,
	};
	struct tm *res;

	res = orig_localtime_r(timep, &log.res);
	if (res) {
		*result = *res;
		log.tm_zone_len = strlen(log.res.tm_zone) + 1;
	}

	log_write(&log, sizeof(log));
	if (res)
		log_write(log.res.tm_zone, log.tm_zone_len);

	return res;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	struct gmtime_r_log log = {
		LOG_gmtime_r,
		*timep,
	};
	struct tm *res;

	res = orig_gmtime_r(timep, &log.res);
	if (res) {
		*result = *res;
		log.tm_zone_len = strlen(log.res.tm_zone) + 1;
	}

	log_write(&log, sizeof(log));
	if (res)
		log_write(log.res.tm_zone, log.tm_zone_len);

	return res;
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	struct getaddrinfo_log log = {
		LOG_getaddrinfo,
		strlen(node) + 1,
		strlen(service) + 1,
	};

	log.ret = orig_getaddrinfo(node, service, hints, res);
	if (!log.ret) {
		log.res = **res;
		memcpy(&log.res_addr, (*res)->ai_addr, (*res)->ai_addrlen);
	}

	log_write(&log, sizeof(log));
	log_write(node, log.node_len);
	log_write(service, log.service_len);

	return log.ret;
}

int chdir(const char *path)
{
	struct chdir_log log = {
		LOG_chdir,
		strlen(path) + 1,
	};
	int ret;

	ret = orig_chdir(path);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));
	log_write(path, log.path_len);

	return ret;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	struct sigprocmask_log log = {
		LOG_sigprocmask,
		how,
		*set,
	};
	int ret;

	ret = orig_sigprocmask(how, set, &log.oldset);
	if (ret == -1) {
		log.ret = -errno;
	} else {
		log.ret = ret;
		if (oldset)
			*oldset = log.oldset;
	}

	log_write(&log, sizeof(log));

	return ret;
}

int signalfd(int fd, const sigset_t *mask, int flags)
{
	struct signalfd_log log = {
		LOG_signalfd,
		fd,
		*mask,
		flags,
	};
	int ret;

	ret = orig_signalfd(fd, mask, flags);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

int socket(int domain, int type, int protocol)
{
	struct socket_log log = {
		LOG_socket,
		domain,
		type,
		protocol,
	};
	int ret;

	ret = orig_socket(domain, type, protocol);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct bind_log log = {
		LOG_bind,
		sockfd,
	};
	int ret;
	memcpy(&log.addr, addr, addrlen);
	log.addrlen = addrlen;

	ret = orig_bind(sockfd, addr, addrlen);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

int listen(int sockfd, int backlog)
{
	struct listen_log log = {
		LOG_listen,
		sockfd,
		backlog,
	};
	int ret;

	ret = orig_listen(sockfd, backlog);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct accept_log log = {
		LOG_accept,
		sockfd,
		addrlen ? *addrlen : 0,
	};
	int ret;

	ret = orig_accept(sockfd, addr, addrlen);
	if (ret == -1) {
		log.ret = -errno;
	} else {
		log.ret = ret;
		if (addr)
			memcpy(&log.addr, addr, *addrlen);
		if (addrlen)
			log.addrlen_out = *addrlen;
	}

	log_write(&log, sizeof(log));

	return ret;
}

int epoll_create1(int flags)
{
	struct epoll_create1_log log = {
		LOG_epoll_create1,
		flags,
	};
	int ret;

	ret = orig_epoll_create1(flags);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	struct epoll_ctl_log log = {
		LOG_epoll_ctl,
		epfd,
		op,
		fd,
		*event
	};
	int ret;

	ret = orig_epoll_ctl(epfd, op, fd, event);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	struct epoll_wait_log log = {
		LOG_epoll_wait,
		epfd,
		maxevents,
		timeout,
	};
	int ret;

	ret = orig_epoll_wait(epfd, events, maxevents, timeout);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));
	if (ret > 0)
		log_write(events, ret * sizeof(*events));

	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	struct read_log log = {
		LOG_read,
		fd,
		count,
	};
	ssize_t ret;

	ret = orig_read(fd, buf, count);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));
	if (ret > 0)
		log_write(buf, ret);

	return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	struct write_log log = {
		LOG_write,
		fd,
		count,
	};
	ssize_t ret;

	ret = orig_write(fd, buf, count);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));
	log_write(buf, count);

	return ret;
}

int open(const char *pathname, int flags, ...)
{
	struct open_log log = {
		LOG_open,
		strlen(pathname) + 1,
		flags,
	};
	va_list ap;
	int ret;

	if (flags & O_CREAT) {
		va_start(ap, flags);
		log.mode = va_arg(ap, mode_t);
		va_end(ap);
		ret = orig_open(pathname, flags, log.mode);
	} else {
		ret = orig_open(pathname, flags);
	}
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));
	log_write(pathname, log.pathname_len);

	return ret;
}

int close(int fd)
{
	struct close_log log = {
		LOG_close,
		fd,
	};
	int ret;

	ret = orig_close(fd);
	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));

	return ret;
}

/* See /usr/include/sys/stat.h; fstat is an inline wrapper around __fxstat. */
int __fxstat(int ver, int fd, struct stat *buf)
{
	struct fxstat_log log = {
		LOG_fxstat,
		ver,
		fd,
	};
	int ret;

	ret = orig_fxstat(ver, fd, buf);
	if (ret == -1) {
		log.ret = -errno;
	} else {
		log.ret = ret;
		log.res = *buf;
	}

	log_write(&log, sizeof(log));

	return ret;
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	struct sendfile_log log = {
		LOG_sendfile,
		out_fd,
		in_fd,
		offset ? *offset : 0,
		count,
	};
	off_t off;
	char buf[4096];
	ssize_t ret;

	if (offset) {
		off = *offset;
	} else {
		off = lseek(in_fd, 0, SEEK_CUR);
		if (off == -1)
			goto out;
	}

	if (count > sizeof(buf))
		count = sizeof(buf);

	ret = pread(in_fd, buf, count, off);
	if (ret != -1)
		ret = orig_write(out_fd, buf, ret);

out:
	if (ret == -1) {
		log.ret = -errno;
	} else {
		if (offset)
			log.offset_out = *offset = off + ret;
		else
			lseek(in_fd, ret, SEEK_CUR);
		log.ret = ret;
	}

	log_write(&log, sizeof(log));
	if (ret > 0)
		log_write(buf, ret);

	return ret;
}

int dprintf(int fd, const char *format, ...)
{

	struct dprintf_log log = {
		LOG_dprintf,
		fd,
	};
	va_list ap;
	int ret, done;
	ssize_t sret;
	char buf[4096];

	va_start(ap, format);
	ret = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	if (ret >= sizeof(buf)) {
		fprintf(stderr, "dprintf too big\n");
		exit(EXIT_FAILURE);
	}

	done = 0;
	while (done < ret) {
		sret = orig_write(fd, &buf[done], ret - done);
		if (sret == -1) {
			if (errno == EINTR)
				continue;
			ret = -1;
			break;
		}
		done += sret;
	}

	if (ret == -1)
		log.ret = -errno;
	else
		log.ret = ret;

	log_write(&log, sizeof(log));
	if (ret > 0)
		log_write(buf, ret);

	return ret;
}
