#include "551r2.h"

static void *log_mmap;
static size_t log_size;
static char *log_ptr;

__attribute__((constructor))
static void init(void)
{
	char *log_file;
	int log_fd;
	struct stat st;

	log_file = getenv("551R2");
	if (!log_file) {
		fprintf(stderr, "551R2 environment variable must be set\n");
		exit(EXIT_FAILURE);
	}

	log_fd = open(log_file, O_RDONLY);
	if (log_fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(log_fd, &st) == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	log_size = st.st_size;

	log_mmap = mmap(NULL, log_size, PROT_READ, MAP_SHARED, log_fd, 0);
	if (log_mmap == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	if (close(log_fd) == -1)
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
		ret = 0;
		*tp = log->res;
	}
	return ret;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	LOG_READ_FUNC(localtime_r, log);

	if (*timep != log->time)
		log_mismatch("localtime_r.time");

	*result = log->res;
	return result;
}

#if 0
struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	LOG_READ_FUNC(gmtime_r, log);

	if (*timep != log->time)
		log_mismatch("gmtime_r.time");

	*result = log->res;
	return result;
}
#endif

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
