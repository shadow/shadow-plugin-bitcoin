/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <execinfo.h>
#include <sys/socket.h>
#include <glib.h>
#include <gmodule.h>
#include <sys/poll.h>

#define BITCOIND_LIB_PREFIX "intercept_"

typedef ssize_t (*read_fp)(int, void*, size_t);
typedef ssize_t (*write_fp)(int, void*, size_t);
typedef int (*nanosleep_fp)(const struct timespec *, struct timespec *);
typedef int (*usleep_fp)(unsigned int);
typedef int (*sleep_fp)(unsigned int);
typedef int (*system_fp)(const char *);
typedef int (*sigprocmask_fp)(int, const sigset_t *, sigset_t *);
typedef int (*sigwait_fp)(const sigset_t *, int *);
typedef pid_t (*waitpid_fp)(pid_t, int *, int);
typedef int (*connect_fp)(int, const struct sockaddr *, socklen_t);
typedef int (*accept_fp)(int, struct sockaddr *, socklen_t *);
typedef int (*select_fp)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
typedef int (*pselect_fp)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *);
typedef int (*poll_fp)(struct pollfd *, nfds_t, int);
typedef ssize_t (*readv_fp)(int, const struct iovec *, int);
typedef ssize_t (*writev_fp)(int, const struct iovec *, int);
typedef ssize_t (*pread_fp)(int, void *, size_t, off_t);
typedef ssize_t (*pwrite_fp)(int, const void *, size_t, off_t);
typedef ssize_t (*recv_fp)(int, void *, size_t, int);
typedef ssize_t (*send_fp)(int, void *, size_t, int);
typedef ssize_t (*recvfrom_fp)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*sendto_fp)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

/* the key used to store each threads version of their searched function library.
 * the use this key to retrieve this library when intercepting functions from tor.
 */
GStaticPrivate bitcoindWorkerKey;

typedef struct _BitcoindPreloadWorker BitcoindPreloadWorker;
/* TODO fix func names */
struct _BitcoindPreloadWorker {
	GModule* handle;
	read_fp pth_read;
	write_fp pth_write;
};

/* scallionpreload_init must be called before this so the worker gets created */
static BitcoindPreloadWorker* _bitcoindpreload_getWorker() {
	/* get current thread's private worker object */
	BitcoindPreloadWorker* worker = g_static_private_get(&bitcoindWorkerKey);
	g_assert(worker);
	return worker;
}

static BitcoindPreloadWorker* _bitcoindpreload_newWorker(GModule* handle) {
	BitcoindPreloadWorker* worker = g_new0(BitcoindPreloadWorker, 1);
	worker->handle = handle;
	return worker;
}

/* here we search and save pointers to the functions we need to call when
 * we intercept tor's functions. this is initialized for each thread, and each
 * thread has pointers to their own functions (each has its own version of the
 * plug-in state). We dont register these function locations, because they are
 * not *node* dependent, only *thread* dependent.
 */

#define SETSYM_OR_FAIL_(handle,funcptr, funcstr) {	\
	dlerror(); \
	funcptr = dlsym(handle, funcstr); \
	char* errorMessage = dlerror(); \
	if(errorMessage != NULL) { \
		fprintf(stderr, "dlsym(%s): dlerror(): %s\n", funcstr, errorMessage); \
		exit(EXIT_FAILURE); \
	} else if(funcptr == NULL) { \
		fprintf(stderr, "dlsym(%s): returned NULL pointer\n", funcstr); \
		exit(EXIT_FAILURE); \
	} \
}

#define SETSYM_OR_FAIL(funcptr, funcstr) SETSYM_OR_FAIL_(RTLD_NEXT, funcptr, funcstr)
#define SETSYM_OR_FAIL_DEFAULT(funcptr, funcstr) SETSYM_OR_FAIL_(RTLD_DEFAULT, funcptr, funcstr)

void bitcoindpreload_init(GModule* handle) {
	BitcoindPreloadWorker* worker = _bitcoindpreload_newWorker(handle);

	/* lookup all our required symbols in this worker's module, asserting success */
	g_assert(g_module_symbol(handle, "pth_read", (gpointer*)&worker->pth_read));
	g_assert(g_module_symbol(handle, "pth_write", (gpointer*)&worker->pth_write));
	//g_assert(g_module_symbol(handle, BITCOIND_LIB_PREFIX "read", (gpointer*)&(worker->_read)));
	//g_assert(g_module_symbol(handle, BITCOIND_LIB_PREFIX "foo_test", (gpointer*)&(worker->_foo_test)));

	g_static_private_set(&bitcoindWorkerKey, worker, g_free);
}


#define ENSURE(prefix, func) { \
	if(!director.type.func) { \
		SETSYM_OR_FAIL(director.type.func, prefix #func); \
	} \
}

static __thread unsigned long isRecursive = 0;
__thread long isPlugin = 0;
void _mark_isPlugin() { isPlugin += 1; }
void _unmark_isPlugin() { isPlugin -= 1; }

int shd_dl_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
	return sigprocmask(how, set, oset);
}

ssize_t shd_dl_read(int fp, void *d, size_t s) {
	read_fp real;
	SETSYM_OR_FAIL(real, "read");
	_unmark_isPlugin();
	int rc = real(fp, d, s);
	_mark_isPlugin();
	return rc;
}
ssize_t shd_dl_write(int fp, void *d, size_t s) {
	write_fp real;
	SETSYM_OR_FAIL(real, "write");
	_unmark_isPlugin();
	int rc = real(fp, d, s);
	_mark_isPlugin();
	return rc;
}

ssize_t real_fprintf(FILE *stream, const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int s = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	return shd_dl_write(fileno(stream), buf, s);
}

ssize_t write(int fp, void *d, size_t s) {
	BitcoindPreloadWorker* worker = g_static_private_get(&bitcoindWorkerKey);
	//fprintf(stderr, "In bitcoind-preload.c write\n");
	//real_fprintf(stderr, "write[%d]:%d [%d]\n", isPlugin, fp, s);

	/* ensure don't intercept a local */
	if (worker && (isPlugin > 0)) {
		real_fprintf(stderr, "bitcoind-preload.c:write() about to go to pth\n");
		return worker->pth_write(fp, d, s);
	} else {
		return shd_dl_write(fp, d, s);
	}
}

ssize_t read(int fp, void *d, size_t s) {
	BitcoindPreloadWorker* worker = g_static_private_get(&bitcoindWorkerKey);

	fprintf(stderr, "In bitcoind-preload.c read\n");
	int rc;

	/* ensure don't intercept a local */
	//int ss = __sync_fetch_and_add(&isRecursive, 1);
	fprintf(stderr, "c\n");
	fprintf(stderr, "bitcoind-preload.c after fetch\n");
	if (worker) {
	//if (!ss && worker) {
		fprintf(stdout, "bitcoind-preload.c:read(%d) pass to gnu pth\n", fp);
		rc = worker->pth_read(fp, d, s);
		//rc = 0;
		fprintf(stdout, "bitcoind-preload.c:read(%d) pth read finished\n", fp);
	} else {
		read_fp real;
		SETSYM_OR_FAIL(real, "read");
		real_fprintf(stderr, "looking for real read real:%ld\n", real);
		real_fprintf(stderr, "bitcoind-preload.c:read(%d) real:%ld\n", fp, real);
		rc = real(fp, d, s);
		real_fprintf(stderr, "real read returned %d\n", rc);
	}
	//__sync_fetch_and_sub(&isRecursive, 1);
	real_fprintf(stderr, "returning %d\n", rc);
	return rc;
}
