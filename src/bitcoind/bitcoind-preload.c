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
#include <sys/poll.h>

#include <glib.h>
#include <gmodule.h>

#include "bitcoind.h"

#include "pth.h"

//#define BITCOIND_LIB_PREFIX "intercept_"

typedef int (*close_fp)(int);
typedef ssize_t (*read_fp)(int, void*, size_t);
typedef ssize_t (*write_fp)(int, const void*, size_t);
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

/* socket/io family */
typedef int (*socket_fp)(int, int, int);
typedef int (*socketpair_fp)(int, int, int, int[]);
typedef int (*bind_fp)(int, __CONST_SOCKADDR_ARG, socklen_t);
typedef int (*getsockname_fp)(int, __SOCKADDR_ARG, socklen_t*);
//typedef int (*connect_fp)(int, __const_sockaddr_arg, socklen_t);
typedef int (*getpeername_fp)(int, __SOCKADDR_ARG, socklen_t*);
//typedef size_t (*send_fp)(int, const void*, size_t, int);
//typedef size_t (*sendto_fp)(int, const void*, size_t, int, __const_sockaddr_arg, socklen_t);
typedef size_t (*sendmsg_fp)(int, const struct msghdr*, int);
//typedef size_t (*recv_fp)(int, void*, size_t, int);
//typedef size_t (*recvfrom_fp)(int, void*, size_t, int, __sockaddr_arg, socklen_t*);
typedef size_t (*recvmsg_fp)(int, struct msghdr*, int);
typedef int (*getsockopt_fp)(int, int, int, void*, socklen_t*);
typedef int (*setsockopt_fp)(int, int, int, const void*, socklen_t);
typedef int (*listen_fp)(int, int);
//typedef int (*accept_fp)(int, __sockaddr_arg, socklen_t*);
typedef int (*accept4_fp)(int, __SOCKADDR_ARG, socklen_t*, int);
typedef int (*shutdown_fp)(int, int);
typedef int (*pipe_fp)(int [2]);
typedef int (*pipe2_fp)(int [2], int);
//typedef size_t (*read_fp)(int, void*, int);
//typedef size_t (*write_fp)(int, const void*, int);
//typedef int (*close_fp)(int);
typedef int (*fcntl_fp)(int, int, ...);
typedef int (*ioctl_fp)(int, int, ...);

/* memory allocation family */
typedef void* (*malloc_fp)(size_t);
typedef void* (*calloc_fp)(size_t, size_t);
typedef void* (*realloc_fp)(void*, size_t);
typedef int (*posix_memalign_fp)(void**, size_t, size_t);
typedef void* (*memalign_fp)(size_t, size_t);
typedef void* (*aligned_alloc_fp)(size_t, size_t);
typedef void* (*valloc_fp)(size_t);
typedef void* (*pvalloc_fp)(size_t);
typedef void (*free_fp)(void*);

/* time family */
typedef int (*gettimeofday_fp)(struct timeval *tv, struct timezone *tz);
typedef time_t (*time_fp)(time_t*);
typedef int (*clock_gettime_fp)(clockid_t, struct timespec *);

/* name/address family */
/*
typedef int (*GethostnameFunc)(char*, size_t);
typedef int (*GetaddrinfoFunc)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
typedef int (*FreeaddrinfoFunc)(struct addrinfo*);
typedef int (*GetnameinfoFunc)(const struct sockaddr *, socklen_t, char *, size_t, char *, size_t, int);
typedef struct hostent* (*GethostbynameFunc)(const char*);
typedef int (*GethostbynameRFunc)(const char*, struct hostent*, char*, size_t, struct hostent**, int*);
typedef struct hostent* (*Gethostbyname2Func)(const char*, int);
typedef int (*Gethostbyname2RFunc)(const char*, int, struct hostent *, char *, size_t, struct hostent**, int*);
typedef struct hostent* (*GethostbyaddrFunc)(const void*, socklen_t, int);
typedef int (*GethostbyaddrRFunc)(const void*, socklen_t, int, struct hostent*, char*, size_t, struct hostent **, int*);
*/
/* random family */
/*
typedef int (*RandFunc)();
typedef int (*RandRFunc)(unsigned int*);
typedef void (*SrandFunc)(unsigned int);
typedef long int (*RandomFunc)(void);
typedef int (*RandomRFunc)(struct random_data*, int32_t*);
typedef void (*SrandomFunc)(unsigned int);
typedef int (*SrandomRFunc)(unsigned int, struct random_data*);
*/

/* pth */
typedef ssize_t (*pth_read_fp)(int, void*, size_t);
typedef ssize_t (*pth_write_fp)(int, const void*, size_t);
typedef int (*pth_nanosleep_fp)(const struct timespec *, struct timespec *);
typedef int (*pth_usleep_fp)(unsigned int);
typedef unsigned int  (*pth_sleep_fp)(unsigned int);
typedef void (*pth_init_fp)(void);
typedef pth_t (*pth_spawn_fp)(pth_attr_t attr, void *(*func)(void *), void *arg);
typedef pth_t (*pth_join_fp)(pth_t thread, void **retval);
typedef int (*pth_mutex_init_fp)(pth_mutex_t *);
typedef int (*pth_mutex_acquire_fp)(pth_mutex_t *, int, pth_event_t);
typedef int (*pth_mutex_release_fp)(pth_mutex_t *);
typedef int (*pth_cond_init_fp)(pth_cond_t *);
typedef int (*pth_cond_await_fp)(pth_cond_t *, pth_mutex_t *, pth_event_t);
typedef int (*pth_cond_notify_fp)(pth_cond_t *, int);
typedef int (*pth_key_create_fp)(pth_key_t *, void (*)(void *));
typedef int (*pth_key_delete_fp)(pth_key_t);
typedef int (*pth_key_setdata_fp)(pth_key_t, const void *);
typedef void *(*pth_key_getdata_fp)(pth_key_t);
typedef pth_attr_t (*pth_attr_of_fp)(pth_t t);
typedef int (*pth_attr_destroy_fp)(pth_attr_t a);
typedef int (*pth_attr_set_fp)(pth_attr_t a, int op, ...);

/* epoll */
typedef int (*epoll_create_fp)(int);
typedef int (*epoll_create1_fp)(int flags);
typedef int (*epoll_ctl_fp)(int epfd, int op, int fd, struct epoll_event *event);
typedef int (*epoll_wait_fp)(int epfd, struct epoll_event *events, int maxevents, int timeout);
typedef int (*epoll_pwait_fp)(int, struct epoll_event*, int, int, const sigset_t*);


/* pthread */

typedef int (*pthread_create_fp)(pthread_t*, const pthread_attr_t*,
        void *(*start_routine) (void *), void *arg);
typedef int (*pthread_detach_fp)(pthread_t);
typedef int (*pthread_join_fp)(pthread_t, void **);
typedef int (*pthread_once_fp)(pthread_once_t*, void (*init_routine)(void));
typedef int (*pthread_key_create_fp)(pthread_key_t*, void (*destructor)(void*));
typedef int (*pthread_setspecific_fp)(pthread_key_t, const void*);
typedef void* (*pthread_getspecific_fp)(pthread_key_t);
typedef int (*pthread_attr_setdetachstate_fp)(pthread_attr_t*, int);
typedef int (*pthread_attr_getdetachstate_fp)(const pthread_attr_t*, int*);
typedef int (*pthread_cond_init_fp)(pthread_cond_t*, const pthread_condattr_t*);
typedef int (*__pthread_cond_init_2_0_fp)(pthread_cond_t*, const pthread_condattr_t*);
typedef int (*pthread_cond_destroy_fp)(pthread_cond_t*);
typedef int (*pthread_cond_signal_fp)(pthread_cond_t*);
typedef int (*pthread_cond_broadcast_fp)(pthread_cond_t*);
typedef int (*pthread_cond_wait_fp)(pthread_cond_t*, pthread_mutex_t*);
typedef int (*pthread_cond_timedwait_fp)(pthread_cond_t*, pthread_mutex_t*, const struct timespec*);
typedef int (*pthread_mutex_init_fp)(pthread_mutex_t*,
              const pthread_mutexattr_t*);
typedef int (*pthread_mutex_destroy_fp)(pthread_mutex_t*);
typedef int (*pthread_mutex_lock_fp)(pthread_mutex_t*);
typedef int (*pthread_mutex_trylock_fp)(pthread_mutex_t*);
typedef int (*pthread_mutex_unlock_fp)(pthread_mutex_t*);


/* the key used to store each threads version of their searched function library.
 * the use this key to retrieve this library when intercepting functions from tor.
 */
//static GPrivate bitcoindWorkerKey = G_PRIVATE_INIT((GDestroyNotify)g_free);
static __thread void * pluginWorkerKey = NULL;
#define g_private_get(ptr) (*(ptr))


/* track if we are in a recursive loop to avoid infinite recursion.
 * threads MUST access this via &isRecursive to ensure each has its own copy
 * http://gcc.gnu.org/onlinedocs/gcc-4.3.6/gcc/Thread_002dLocal.html */
static __thread unsigned long isRecursive = 0;

typedef struct _FunctionTable FunctionTable;
struct _FunctionTable {
	close_fp close;
	read_fp read;
	write_fp write;
	usleep_fp usleep;
	nanosleep_fp nanosleep;
	sleep_fp sleep;

	/* socket/io family */
	socket_fp socket;
	socketpair_fp socketpair;
	bind_fp bind;
	getsockname_fp getsockname;
	getpeername_fp getpeername;
	sendmsg_fp sendmsg;
	recvmsg_fp recvmsg;
	getsockopt_fp getsockopt;
	setsockopt_fp setsockopt;
	listen_fp listen;
	accept4_fp accept4;
	shutdown_fp shutdown;
	pipe_fp pipe;
	pipe2_fp pipe2;
	fcntl_fp fcntl;
	ioctl_fp ioctl;

	/* memory allocation family */
	malloc_fp malloc;
	calloc_fp calloc;
	realloc_fp realloc;
	posix_memalign_fp posix_memalign;
	memalign_fp memalign;
	aligned_alloc_fp aligned_alloc;
	valloc_fp valloc;
	pvalloc_fp pvalloc;
	free_fp free;

	/* time family */
	clock_gettime_fp clock_gettime;
	time_fp time;
	gettimeofday_fp gettimeofday;

	/* event */
	epoll_create_fp epoll_create;
	epoll_create1_fp epoll_create1;
	epoll_ctl_fp epoll_ctl;
	epoll_wait_fp epoll_wait;
	epoll_pwait_fp epoll_pwait;
	
	/* pth */
	pth_read_fp pth_read;
	pth_write_fp pth_write;
	pth_usleep_fp pth_usleep;
	pth_nanosleep_fp pth_nanosleep;
	pth_sleep_fp pth_sleep;

	pth_init_fp pth_init;
	pth_join_fp pth_join;
	pth_spawn_fp pth_spawn;
	pth_mutex_init_fp pth_mutex_init;
	pth_mutex_acquire_fp pth_mutex_acquire;
	pth_mutex_release_fp pth_mutex_release;
	pth_cond_init_fp pth_cond_init;
	pth_cond_await_fp pth_cond_await;
	pth_cond_notify_fp pth_cond_notify;
	pth_key_create_fp pth_key_create;
	pth_key_delete_fp pth_key_delete;
	pth_key_setdata_fp pth_key_setdata;
	pth_key_getdata_fp pth_key_getdata;

	pth_attr_of_fp pth_attr_of;
	pth_attr_set_fp pth_attr_set;
	pth_attr_destroy_fp pth_attr_destroy;
	

	/* pthread */
	pthread_create_fp pthread_create;
	pthread_detach_fp pthread_detach;
	pthread_join_fp pthread_join;
	pthread_once_fp pthread_once;
	pthread_key_create_fp pthread_key_create;
	pthread_setspecific_fp pthread_setspecific;
	pthread_getspecific_fp pthread_getspecific;
	pthread_attr_setdetachstate_fp pthread_attr_setdetachstate;
	pthread_attr_getdetachstate_fp pthread_attr_getdetachstate;
	pthread_cond_init_fp pthread_cond_init;
	pthread_cond_destroy_fp pthread_cond_destroy;
	pthread_cond_signal_fp pthread_cond_signal;
	pthread_cond_broadcast_fp pthread_cond_broadcast;
	pthread_cond_wait_fp pthread_cond_wait;
	pthread_cond_timedwait_fp pthread_cond_timedwait;
	pthread_mutex_init_fp pthread_mutex_init;
	pthread_mutex_destroy_fp pthread_mutex_destroy;
	pthread_mutex_lock_fp pthread_mutex_lock;
	pthread_mutex_trylock_fp pthread_mutex_trylock;
	pthread_mutex_unlock_fp pthread_mutex_unlock;
};

typedef struct _BitcoindPreloadWorker BitcoindPreloadWorker;

struct _BitcoindPreloadWorker {
	GModule* handle;
	ExecutionContext activeContext;
	long isPlugin;
	FunctionTable ftable;
	unsigned long isRecursive;
};

/* here we search and save pointers to the functions we need to call when
 * we intercept tor's functions. this is initialized for each thread, and each
 * thread has pointers to their own functions (each has its own version of the
 * plug-in state). We dont register these function locations, because they are
 * not *node* dependent, only *thread* dependent.
 */

#define SETSYM_OR_FAIL_(handle, funcptr, funcstr) {	\
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

#define SETSYM_OR_FAIL_V_(handle,funcptr, funcstr, version) {	\
	dlerror(); \
	funcptr = dlvsym(handle, funcstr, version);	\
	char* errorMessage = dlerror(); \
	if(errorMessage != NULL) { \
		fprintf(stderr, "dlvsym(%s,%s): dlerror(): %s\n", funcstr, version, errorMessage); \
		exit(EXIT_FAILURE); \
	} else if(funcptr == NULL) { \
		fprintf(stderr, "dlvsym(%s,%s): returned NULL pointer\n", funcstr, version); \
		exit(EXIT_FAILURE); \
	} \
}
#define SETSYM_OR_FAIL(funcptr, funcstr) SETSYM_OR_FAIL_(RTLD_NEXT, funcptr, funcstr)
#define SETSYM_OR_FAIL_V(funcptr, funcstr, version) SETSYM_OR_FAIL_V_(RTLD_NEXT, funcptr, funcstr, version)
#define SETSYM_OR_FAIL_DEFAULT(funcptr, funcstr) SETSYM_OR_FAIL_(RTLD_DEFAULT, funcptr, funcstr)

#define _FTABLE_GUARD(rctype, func, ...)       \
    if(__sync_fetch_and_add(&isRecursive, 1)) {\
	    func##_fp real;\
	    SETSYM_OR_FAIL(real, #func);\
	    rctype rc = real(__VA_ARGS__);\
	    __sync_fetch_and_sub(&isRecursive, 1);\
            return rc;\
    }\
    BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);\
    if (!worker) {\
	    func##_fp real;\
	    SETSYM_OR_FAIL(real, #func);\
	    rctype rc = real(__VA_ARGS__);\
            __sync_fetch_and_sub(&isRecursive, 1);\
	    return rc;\
    }\
    if (worker->activeContext != EXECTX_PLUGIN) {\
	    rctype rc = worker->ftable.func(__VA_ARGS__);\
	    __sync_fetch_and_sub(&isRecursive, 1);\
	    return rc;\
    }\
    __sync_fetch_and_sub(&isRecursive, 1);\

#define _FTABLE_GUARD_V(rctype, func, version, ...)	\
    if(__sync_fetch_and_add(&isRecursive, 1)) {\
	    func##_fp real;\
	    SETSYM_OR_FAIL_V(real, #func, version);	\
	    rctype rc = real(__VA_ARGS__);\
	    __sync_fetch_and_sub(&isRecursive, 1);\
            return rc;\
    }\
    BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);\
    if (!worker) {\
	    func##_fp real;\
	    SETSYM_OR_FAIL_V(real, #func, version);	\
	    rctype rc = real(__VA_ARGS__);\
            __sync_fetch_and_sub(&isRecursive, 1);\
	    return rc;\
    }\
    if (worker->activeContext != EXECTX_PLUGIN) {\
	    rctype rc = worker->ftable.func(__VA_ARGS__);\
	    __sync_fetch_and_sub(&isRecursive, 1);\
	    return rc;\
    }\
    __sync_fetch_and_sub(&isRecursive, 1);\

#define _SHADOW_GUARD(rctype, func, ...) {			\
		_FTABLE_GUARD(rctype, func, __VA_ARGS__);	\
		worker->activeContext = EXECTX_PTH;		\
		int rc = worker->ftable.func(__VA_ARGS__);	\
		worker->activeContext = EXECTX_PLUGIN;		\
		return rc;					\
	}							\

#define _SHD_DL_BODY(func, ...) \
  {									\
    BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);	\
    assert(worker);							\
    ExecutionContext e = worker->activeContext;				\
    worker->activeContext = EXECTX_PTH;					\
    int rc = worker->ftable.func(__VA_ARGS__);				\
    worker->activeContext = e;						\
    return rc;}

int shd_dl_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
	return sigprocmask(how, set, oset);
}

ssize_t real_fprintf(FILE *stream, const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int s = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);
	if (worker) {
		ExecutionContext e = worker->activeContext;
		worker->activeContext = EXECTX_SHADOW;
		int rc = worker->ftable.write(fileno(stream), buf, s);
		worker->activeContext = e;
		return rc;
	} else {
		write_fp _write;
		SETSYM_OR_FAIL(_write, "write");
		return _write(fileno(stream), buf, s);
	}
}


ssize_t shd_dl_read(int fp, void *d, size_t s) _SHD_DL_BODY(read, fp, d, s);
ssize_t shd_dl_write(int fp, const void *d, size_t s) {
  _SHD_DL_BODY(write, fp, d, s);
}




#define _WORKER_SET(func) SETSYM_OR_FAIL(worker->ftable.func, #func)


void bitcoindpreload_init(GModule* handle) {
	BitcoindPreloadWorker* worker = g_new0(BitcoindPreloadWorker, 1);
	worker->handle = handle;

	/* lookup all our required symbols in this worker's module, asserting success */
	g_assert(g_module_symbol(handle, "pth_read", (gpointer*)&worker->ftable.pth_read));
	g_assert(g_module_symbol(handle, "pth_write", (gpointer*)&worker->ftable.pth_write));
	g_assert(g_module_symbol(handle, "pth_spawn", (gpointer*)&worker->ftable.pth_spawn));
	g_assert(g_module_symbol(handle, "pth_usleep", (gpointer*)&worker->ftable.pth_usleep));
	g_assert(g_module_symbol(handle, "pth_sleep", (gpointer*)&worker->ftable.pth_sleep));
	g_assert(g_module_symbol(handle, "pth_nanosleep", (gpointer*)&worker->ftable.pth_nanosleep));
	g_assert(g_module_symbol(handle, "pth_join", (gpointer*)&worker->ftable.pth_join));
	g_assert(g_module_symbol(handle, "pth_spawn", (gpointer*)&worker->ftable.pth_spawn));
	g_assert(g_module_symbol(handle, "pth_init", (gpointer*)&worker->ftable.pth_init));
	g_assert(g_module_symbol(handle, "pth_mutex_init", (gpointer*)&worker->ftable.pth_mutex_init));
	g_assert(g_module_symbol(handle, "pth_mutex_release", (gpointer*)&worker->ftable.pth_mutex_release));
	g_assert(g_module_symbol(handle, "pth_mutex_acquire", (gpointer*)&worker->ftable.pth_mutex_acquire));
	g_assert(g_module_symbol(handle, "pth_cond_init", (gpointer*)&worker->ftable.pth_cond_init));
	g_assert(g_module_symbol(handle, "pth_cond_await", (gpointer*)&worker->ftable.pth_cond_await));
	g_assert(g_module_symbol(handle, "pth_cond_notify", (gpointer*)&worker->ftable.pth_cond_notify));
	g_assert(g_module_symbol(handle, "pth_key_create", (gpointer*)&worker->ftable.pth_key_create));
	g_assert(g_module_symbol(handle, "pth_key_delete", (gpointer*)&worker->ftable.pth_key_delete));
	g_assert(g_module_symbol(handle, "pth_key_setdata", (gpointer*)&worker->ftable.pth_key_setdata));
	g_assert(g_module_symbol(handle, "pth_key_getdata", (gpointer*)&worker->ftable.pth_key_getdata));
	g_assert(g_module_symbol(handle, "pth_attr_of", (gpointer*)&worker->ftable.pth_attr_of));
	g_assert(g_module_symbol(handle, "pth_attr_set", (gpointer*)&worker->ftable.pth_attr_set));
	g_assert(g_module_symbol(handle, "pth_attr_destroy", (gpointer*)&worker->ftable.pth_attr_destroy));

	/* lookup system and pthread calls that exist outside of the plug-in module.
	 * do the lookup here and save to pointer so we dont have to redo the
	 * lookup on every syscall */
	SETSYM_OR_FAIL(worker->ftable.close, "close");
	SETSYM_OR_FAIL(worker->ftable.read, "read");
	SETSYM_OR_FAIL(worker->ftable.write, "write");
	SETSYM_OR_FAIL(worker->ftable.usleep, "usleep");
	SETSYM_OR_FAIL(worker->ftable.nanosleep, "nanosleep");
	SETSYM_OR_FAIL(worker->ftable.sleep, "sleep");
	SETSYM_OR_FAIL(worker->ftable.write, "write");

	/* time family */
	_WORKER_SET(gettimeofday);
	_WORKER_SET(time);
	_WORKER_SET(clock_gettime);

	/* event */
	_WORKER_SET(epoll_create);
	_WORKER_SET(epoll_create1);
	_WORKER_SET(epoll_ctl);
	_WORKER_SET(epoll_wait);
	_WORKER_SET(epoll_pwait);

	/* memory allocation family */
	_WORKER_SET(malloc);
	_WORKER_SET(calloc);
	_WORKER_SET(realloc);
	_WORKER_SET(posix_memalign);
	_WORKER_SET(memalign);
	_WORKER_SET(aligned_alloc);
	_WORKER_SET(valloc);
	_WORKER_SET(pvalloc);
	_WORKER_SET(free);


	/* pthread */
	_WORKER_SET(pthread_key_create);
	_WORKER_SET(pthread_cond_init);
	SETSYM_OR_FAIL(worker->ftable.pthread_create, "pthread_create");
	SETSYM_OR_FAIL(worker->ftable.pthread_detach, "pthread_detach");
	SETSYM_OR_FAIL(worker->ftable.pthread_join, "pthread_join");
	SETSYM_OR_FAIL(worker->ftable.pthread_once, "pthread_once");
	SETSYM_OR_FAIL(worker->ftable.pthread_setspecific, "pthread_setspecific");
	SETSYM_OR_FAIL(worker->ftable.pthread_getspecific, "pthread_getspecific");
	SETSYM_OR_FAIL(worker->ftable.pthread_attr_setdetachstate, "pthread_attr_setdetachstate");
	SETSYM_OR_FAIL(worker->ftable.pthread_attr_getdetachstate, "pthread_attr_getdetachstate");
	SETSYM_OR_FAIL(worker->ftable.pthread_cond_destroy, "pthread_cond_destroy");
	SETSYM_OR_FAIL(worker->ftable.pthread_cond_signal, "pthread_cond_signal");
	SETSYM_OR_FAIL(worker->ftable.pthread_cond_broadcast, "pthread_cond_broadcast");
	SETSYM_OR_FAIL(worker->ftable.pthread_cond_wait, "pthread_cond_wait");
	SETSYM_OR_FAIL(worker->ftable.pthread_cond_timedwait, "pthread_cond_timedwait");
	SETSYM_OR_FAIL(worker->ftable.pthread_mutex_init, "pthread_mutex_init");
	SETSYM_OR_FAIL(worker->ftable.pthread_mutex_destroy, "pthread_mutex_destroy");
	SETSYM_OR_FAIL(worker->ftable.pthread_mutex_lock, "pthread_mutex_lock");
	SETSYM_OR_FAIL(worker->ftable.pthread_mutex_trylock, "pthread_mutex_trylock");
	SETSYM_OR_FAIL(worker->ftable.pthread_mutex_unlock, "pthread_mutex_unlock");

	//g_private_set(&pluginWorkerKey, worker);
	//assert(g_private_get(&pluginWorkerKey));
	pluginWorkerKey = worker;

	assert(sizeof(pthread_t) >= sizeof(pth_t));
	assert(sizeof(pthread_attr_t) >= sizeof(pth_attr_t));
	assert(sizeof(pthread_mutex_t) >= sizeof(pth_mutex_t));
	assert(sizeof(pthread_cond_t) >= sizeof(pth_cond_t));
        assert(sizeof(pthread_key_t) >= sizeof(pth_key_t));
}

void bitcoindpreload_setContext(ExecutionContext ctx) {
    BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);
    worker->activeContext = ctx;
}



ssize_t write(int fp, const void *d, size_t s) {
	BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);
	ssize_t rc = 0;
	//real_fprintf(stderr, "write %d\n", worker->activeContext);

	if(worker && worker->activeContext == EXECTX_PLUGIN) {
		real_fprintf(stderr, "bitcoin mode passing to pth\n");
		assert(worker->ftable.pth_write);
		worker->activeContext = EXECTX_PTH;
		rc = worker->ftable.pth_write(fp, d, s);
		worker->activeContext = EXECTX_PLUGIN;
	} else if (worker) {
		// dont mess with shadow's calls, and dont change context 
		rc = worker->ftable.write(fp, d, s);
	} else {
		real_fprintf(stderr, "write skipping worker\n");
		write_fp write;
		SETSYM_OR_FAIL(write, "write");
		rc = write(fp, d, s);
	}

	return rc;
}

ssize_t read(int fp, void *d, size_t s) {
	BitcoindPreloadWorker* worker = g_private_get(&pluginWorkerKey);
	ssize_t rc = 0;
	if(worker && worker->activeContext == EXECTX_PLUGIN) {
		real_fprintf(stderr, "going to pth\n");
		worker->activeContext = EXECTX_PTH;
		rc = worker->ftable.pth_read(fp, d, s);
		worker->activeContext = EXECTX_PLUGIN;
	} else if (worker) {
		real_fprintf(stderr, "passing to shadow\n");
		// dont mess with shadow's calls, and dont change context 
		rc = worker->ftable.read(fp, d, s);
	} else {
		read_fp read;
		SETSYM_OR_FAIL(read, "read");
		rc = read(fp, d, s);
	}
	
	return rc;
}

int close(int fd) _SHADOW_GUARD(int, close, fd);

int usleep(unsigned int usec) {
  BitcoindPreloadWorker* worker_ = g_private_get(&pluginWorkerKey);
    real_fprintf(stderr, "usleep: activeContext:%d\n", worker_->activeContext);

	_FTABLE_GUARD(int, usleep, usec);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "about to pth_sleep\n");
	int rc = worker->ftable.pth_usleep(usec);
	worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int nanosleep(const struct timespec *rqtp, struct timespec *rmtp) {
	_FTABLE_GUARD(int, nanosleep, rqtp, rmtp);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "about to pth_nanosleep\n");
	int rc = worker->ftable.pth_nanosleep(rqtp, rmtp);
	worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

unsigned int sleep(unsigned int sec) {
	_FTABLE_GUARD(unsigned int, sleep, sec);
        worker->activeContext = EXECTX_PTH;
	int rc = worker->ftable.pth_sleep(sec);
	worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

/* time family */


int gettimeofday(struct timeval *tv, struct timezone *tz) _SHADOW_GUARD(int, gettimeofday, tv, tz);

/**
 * epoll
 **/

int epoll_create(int size) _SHADOW_GUARD(int, epoll_create, size);
int epoll_create1(int flags) _SHADOW_GUARD(int, epoll_create1, flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) 
	_SHADOW_GUARD(int, epoll_ctl, epfd, op, fd, event)
int epoll_wait(int epfd, struct epoll_event *events,
	       int maxevents, int timeout) 
	_SHADOW_GUARD(int, epoll_wait, epfd, events, maxevents, timeout);
int epoll_pwait(int epfd, struct epoll_event *events,
		int maxevents, int timeout, const sigset_t *ss) 
	_SHADOW_GUARD(int, epoll_pwait, epfd, events, maxevents, timeout, ss);



/* pth context keeping track of */
int pth_shadow_enter() {
	BitcoindPreloadWorker* worker = pluginWorkerKey;
	assert(worker);
	real_fprintf(stderr, "pth_shadow_enter:%d\n", worker->activeContext);
	worker->activeContext = EXECTX_PLUGIN;
	return worker->activeContext;
	
}
void pth_shadow_leave(int ctx) {
	BitcoindPreloadWorker* worker = pluginWorkerKey;
	assert(worker);
	real_fprintf(stderr, "pth_shadow_leave:%d\n", worker->activeContext);
	worker->activeContext = ctx;
}


/**
 * pthread
 */

/* general success return value */
#ifdef OK
#undef OK
#endif
#define OK 0

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
		   void *(*start_routine) (void *), void *arg) {
        _FTABLE_GUARD(int, pthread_create, thread, attr, start_routine, arg);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "passing to pth_pthread_create\n");
	pth_attr_t na;
	int rc;
	
	if (thread == NULL || start_routine == NULL) {
		errno = EINVAL;
		rc = EINVAL;
	} else {
		na = (attr != NULL) ? *((pth_attr_t*)attr) : PTH_ATTR_DEFAULT;
		
		*thread = (pthread_t)worker->ftable.pth_spawn(na, start_routine, arg);
		if (thread == NULL) {
			errno = EAGAIN;
			rc = EAGAIN;
		}
	}
	real_fprintf(stderr, "returning from pth_pthread_create\n");
	worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_join(pthread_t thread, void **retval) {
        _FTABLE_GUARD(int, pthread_join, thread, retval);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_join to pth\n");
	int rc;
        if (!worker->ftable.pth_join((pth_t)thread, retval)) {
		rc = errno;
        } else if(retval != NULL && *retval == PTH_CANCELED) {
		*retval = PTHREAD_CANCELED;
        }	
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_detach(pthread_t thread) {
        _FTABLE_GUARD(int, pthread_detach, thread);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
        pth_attr_t na;

        if (thread == 0) {
            errno = EINVAL;
            rc = EINVAL;
        } else if ((na = worker->ftable.pth_attr_of((pth_t)thread)) == NULL ||
                !worker->ftable.pth_attr_set(na, PTH_ATTR_JOINABLE, FALSE)) {
            rc = errno;
        } else {
            worker->ftable.pth_attr_destroy(na);
        }

        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
	_FTABLE_GUARD(int, pthread_once, once_control, init_routine);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
        if (once_control == NULL || init_routine == NULL) {
		errno = EINVAL;
		rc = EINVAL;
        } else {
		if (*once_control != 1) {
			worker->activeContext = EXECTX_PLUGIN;
			init_routine();
			worker->activeContext = EXECTX_PTH;
		}
		*once_control = 1;
        }
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void*)) {
	_FTABLE_GUARD(int, pthread_key_create, key, destructor);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_key_create:%d\n", key);
	worker->ftable.pth_init();
	int rc = 0;
        if (!worker->ftable.pth_key_create((pth_key_t *)key, destructor)) {
		rc = errno;
        }
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}


int pthread_setspecific(pthread_key_t key, const void *value)  {
	_FTABLE_GUARD(int, pthread_setspecific, key, value);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_setspecific:%d\n", key);
	int rc = 0;
        if (!worker->ftable.pth_key_setdata((pth_key_t)key, value)) {
		rc = errno;
        }
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}


void *pthread_getspecific(pthread_key_t key) {
	_FTABLE_GUARD(void *, pthread_getspecific, key);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_getspecific:%d\n", key);
	void* pointer = NULL;
        pointer = worker->ftable.pth_key_getdata((pth_key_t)key);
        worker->activeContext = EXECTX_PLUGIN;
	return pointer;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate) {
	_FTABLE_GUARD(int, pthread_attr_setdetachstate, attr, detachstate);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	assert(0);
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate) {
	_FTABLE_GUARD(int, pthread_attr_getdetachstate, attr, detachstate);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	assert(0);
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int PTHREAD_COND_IS_INITIALIZED(pthread_cond_t cond) {
        return !(((pth_cond_t*)&cond)->cn_state & PTH_COND_INITIALIZED);
	//pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
	//return !strncmp((const char *)&cond, (const char *)&empty, sizeof(pthread_cond_t));
}

int PTHREAD_MUTEX_IS_INITIALIZED(pthread_mutex_t mutex) {
        return !(((pth_mutex_t*)&mutex)->mx_state & PTH_MUTEX_INITIALIZED);
	//pthread_mutex_t empty = PTHREAD_MUTEX_INITIALIZER;
	//return !strncmp((const char *)&mutex, (const char *)&empty, sizeof(pthread_mutex_t));
}


int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) 
{
	_FTABLE_GUARD_V(int, pthread_cond_init, "GLIBC_2.3.2", cond, attr);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	worker->ftable.pth_init();
	if (cond == NULL)
		rc = EINVAL;
	else if (!worker->ftable.pth_cond_init((pth_cond_t *)cond))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_cond_destroy(pthread_cond_t *cond) {
	_FTABLE_GUARD(int, pthread_cond_destroy, cond);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	if (cond == NULL)
		rc = EINVAL;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_cond_signal(pthread_cond_t *cond) {
	_FTABLE_GUARD(int, pthread_cond_signal, cond);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	if (cond == NULL)
		rc = EINVAL;
	else if (PTHREAD_COND_IS_INITIALIZED(*cond)) {
		worker->activeContext = EXECTX_PLUGIN;
		if (pthread_cond_init(cond, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && !worker->ftable.pth_cond_notify((pth_cond_t *)cond, FALSE))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
	_FTABLE_GUARD(int, pthread_cond_broadcast, cond);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	if (cond == NULL)
		rc = EINVAL;
	else if (PTHREAD_COND_IS_INITIALIZED(*cond)) {
		worker->activeContext = EXECTX_PLUGIN;
		if (pthread_cond_init(cond, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && !worker->ftable.pth_cond_notify((pth_cond_t *)cond, TRUE))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
	_FTABLE_GUARD(int, pthread_cond_wait, cond, mutex);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	if (cond == NULL || mutex == NULL)
		rc = EINVAL;
	else if (PTHREAD_COND_IS_INITIALIZED(*cond)) {
		worker->activeContext = EXECTX_PLUGIN;
		if (pthread_cond_init(cond, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && PTHREAD_MUTEX_IS_INITIALIZED(*mutex)) {
		worker->activeContext = EXECTX_PLUGIN;
		if (pthread_mutex_init(mutex, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && !worker->ftable.pth_cond_await((pth_cond_t *)cond, (pth_mutex_t *)mutex, NULL))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
              const struct timespec *abstime) {
	_FTABLE_GUARD(int, pthread_cond_wait, cond, mutex);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	assert(0);
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
	_FTABLE_GUARD(int, pthread_mutex_init, mutex, attr);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	worker->ftable.pth_init();
	real_fprintf(stderr, "pthread_mutex_init: %p\n", mutex);
	if (mutex == NULL) {
		rc = EINVAL;
	} else if (!worker->ftable.pth_mutex_init((pth_mutex_t *)mutex))
		rc = errno;
	if (!rc) assert(!PTHREAD_MUTEX_IS_INITIALIZED(*mutex));
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
	_FTABLE_GUARD(int, pthread_mutex_destroy, mutex);
        worker->activeContext = EXECTX_PTH;
	int rc = 0;
	if (mutex == NULL)
		rc = EINVAL;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
	_FTABLE_GUARD(int, pthread_mutex_lock, mutex);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_mutex_lock:%p\n", mutex);
	int rc = 0;
	if (mutex == NULL) {
		rc = EINVAL;
	} else if (PTHREAD_MUTEX_IS_INITIALIZED(*mutex)) {
		real_fprintf(stderr, "pthread_mutex_lock: initializing\n");
		worker->activeContext = EXECTX_PLUGIN;
		if (pthread_mutex_init(mutex, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && !worker->ftable.pth_mutex_acquire((pth_mutex_t *)mutex, FALSE, NULL))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
	_FTABLE_GUARD(int, pthread_mutex_trylock, mutex);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_mutex_trylock:%p\n", mutex);
	int rc = 0;
	if (mutex == NULL) {
		rc = EINVAL;
	} else if (PTHREAD_MUTEX_IS_INITIALIZED(*mutex)) {
		worker->activeContext = EXECTX_PLUGIN;
		if (pthread_mutex_init(mutex, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && !worker->ftable.pth_mutex_acquire((pth_mutex_t *)mutex, TRUE, NULL))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
	_FTABLE_GUARD(int, pthread_mutex_unlock, mutex);
        worker->activeContext = EXECTX_PTH;
	real_fprintf(stderr, "pthread_mutex_unlock:%p\n", mutex);
	int rc = 0;
	if (mutex == NULL) {
		rc = EINVAL;
	} else if (PTHREAD_MUTEX_IS_INITIALIZED(*mutex)) {
		worker->activeContext = EXECTX_PLUGIN;
		assert(0);
		real_fprintf(stderr, "pthread_mutex_unlock: initializing\n");
		if (pthread_mutex_init(mutex, NULL) != OK)
			rc = errno;
		worker->activeContext = EXECTX_PTH;
	}
	if (!rc && !worker->ftable.pth_mutex_release((pth_mutex_t *)mutex))
		rc = errno;
        worker->activeContext = EXECTX_PLUGIN;
	return rc;
}




/* Inception! g_private_get is special because it's called by shadow before deciding
   whether to look up symbols again from the beginning. */
#ifdef g_private_get
#undef g_private_get
#endif

typedef gpointer (*g_private_get_fp)(GPrivate *key);
gpointer g_private_get(GPrivate *key) {
	if(__sync_fetch_and_add(&isRecursive, 1)) {
		g_private_get_fp real;
		real = dlsym(RTLD_NEXT, "g_private_get");
		gpointer rc = real(key);
		__sync_fetch_and_sub(&isRecursive, 1);
		return rc;
	}
	BitcoindPreloadWorker* worker = pluginWorkerKey;
	if (!worker) {
		g_private_get_fp real;
		real = dlsym(RTLD_NEXT, "g_private_get");
		gpointer rc = real(key);
		__sync_fetch_and_sub(&isRecursive, 1);
		return rc;
	}
	ExecutionContext e = worker->activeContext;
	worker->activeContext = EXECTX_SHADOW;
	g_private_get_fp real;
	real = dlsym(RTLD_NEXT, "g_private_get");
	gpointer rc = real(key);
	worker->activeContext = e;
	__sync_fetch_and_sub(&isRecursive, 1);
	return rc;
}
