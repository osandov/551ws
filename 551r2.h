#ifndef _551R2_H
#define _551R2_H

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#define R2_LOG_MAGIC "551WSR2\0"
#define R2_LOG_MAGIC_LEN 8

enum {
	LOG_bogus,
	LOG_time,
	LOG_clock_gettime,
	LOG_localtime_r,
	LOG_gmtime_r,
	LOG_getaddrinfo,
	LOG_chdir,
	LOG_sigprocmask,
	LOG_signalfd,
	LOG_socket,
	LOG_bind,
	LOG_listen,
	LOG_accept,
	LOG_epoll_create1,
	LOG_epoll_ctl,
	LOG_epoll_wait,
	LOG_read,
	LOG_write,
	LOG_open,
	LOG_close,
	LOG_fstat,
	LOG_sendfile,
	LOG_dprintf,
};

struct time_log {
	int func;

	time_t ret;
};

struct clock_gettime_log {
	int func;

	clockid_t clk_id;

	int ret;
	struct timespec res;
};

struct localtime_r_log {
	int func;

	time_t time;

	struct tm res;
};

struct gmtime_r_log {
	int func;

	time_t time;

	struct tm res;
};

struct getaddrinfo_log {
	int func;

	size_t node_len, service_len;

	int ret;
	struct addrinfo res;
	struct sockaddr_storage res_addr;
	/*
	 * XXX: there's more out-of-line stuff in addrinfo, but this is all
	 * that's used.
	 */

	/* node, service */
};

struct sigprocmask_log {
	int func;

	int how;
	sigset_t set;

	int ret;
	sigset_t oldset;
};

struct signalfd_log {
	int func;

	int fd;
	sigset_t mask;
	int flags;

	int ret;
};

struct chdir_log {
	int func;

	size_t path_len;

	int ret;

	/* path */
};

struct socket_log {
	int func;

	int domain, type, protocol;

	int ret;
};

/* setsockopt is only used for SO_REUSEPORT, so no need to actually log it. */

struct bind_log {
	int func;

	int sockfd;
	struct sockaddr_storage addr;
	socklen_t addrlen;

	int ret;
};

struct listen_log {
	int func;

	int sockfd, backlog;

	int ret;
};

struct accept_log {
	int func;

	int sockfd;
	socklen_t addrlen_in;

	int ret;
	struct sockaddr_storage addr;
	socklen_t addrlen_out;
};

struct epoll_create1_log {
	int func;

	int flags;

	int ret;
};

struct epoll_ctl_log {
	int func;

	int epfd, op, fd;
	struct epoll_event event;

	int ret;
};

struct epoll_wait_log {
	int func;

	int epfd;
	int maxevents;
	int timeout;

	int ret;

	/* events */
};

/* TODO: seccomp? */

struct read_log {
	int func;

	int fd;
	size_t count;

	ssize_t ret;

	/* buf */
};

struct write_log {
	int func;

	int fd;
	size_t count;

	ssize_t ret;

	/* buf */
};

struct open_log {
	int func;

	size_t pathname_len;
	int flags;
	mode_t mode;

	int ret;

	/* pathname */
};

struct close_log {
	int func;

	int fd;

	int ret;
};

struct fstat_log {
	int func;

	int fd;

	int ret;
	struct stat res;
};

struct sendfile_log {
	int func;

	int out_fd, in_fd;
	off_t offset_in;
	size_t count;

	ssize_t ret;
	off_t offset_out;

	/* buf */
};

struct dprintf_log {
	int func;

	int fd;

	int ret;

	/* buf */
};

#endif /* _551R2_H */
