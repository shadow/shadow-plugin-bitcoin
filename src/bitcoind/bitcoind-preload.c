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

#include "pth.h"
#include "bitcoind.h"

#define BITCOIND_LIB_PREFIX "intercept_"

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

/* pth */

typedef pth_t (*pth_spawn_fp)(pth_attr_t attr, void *(*func)(void *), void *arg);

/* pthread */

typedef int (*pthread_create_fp)(pthread_t*, const pthread_attr_t*,
        void *(*start_routine) (void *), void *arg);
typedef int (*pthread_detach_fp)(pthread_t);
typedef int (*pthread_join_fp)(pthread_t, void **);
typedef int (*pthread_once_fp)(pthread_once_t*, void (*init_routine)(void));
typedef int (*pthread_key_create_fp)(pthread_key_t*, void (*destructor)(void*));
typedef int (*pthread_setspecific_fp)(pthread_key_t, const void*);
typedef void* (*pthread_getspecific_fp)(pthread_key_t);
typedef int (*pthread_attr_setdetashstate_fp)(pthread_attr_t*, int);
typedef int (*pthread_attr_getdetachstate_fp)(const pthread_attr_t*, int*);
typedef int (*pthread_cond_init_fp)(pthread_cond_t*,
              const pthread_condattr_t*);
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
static GPrivate bitcoindWorkerKey = G_PRIVATE_INIT((GDestroyNotify)g_free);

typedef struct _FunctionTable FunctionTable;
struct _FunctionTable {
	read_fp read;
	write_fp write;
	
	read_fp pth_read;
	write_fp pth_write;
	pth_spawn_fp pth_spawn;
	
	pthread_create_fp pthread_create;
	pthread_detach_fp pthread_detach;
	pthread_join_fp pthread_join;
	pthread_once_fp pthread_once;
	pthread_key_create_fp pthread_key_create;
	pthread_setspecific_fp pthread_setspecific;
	pthread_getspecific_fp pthread_getspecific;
	pthread_attr_setdetashstate_fp pthread_attr_setdetashstate;
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

void bitcoindpreload_init(GModule* handle) {
	BitcoindPreloadWorker* worker = g_new0(BitcoindPreloadWorker, 1);
	worker->handle = handle;

	/* lookup all our required symbols in this worker's module, asserting success */
	g_assert(g_module_symbol(handle, "pth_read", (gpointer*)&worker->ftable.pth_read));
	g_assert(g_module_symbol(handle, "pth_write", (gpointer*)&worker->ftable.pth_write));
	g_assert(g_module_symbol(handle, "pth_spawn", (gpointer*)&worker->ftable.pth_spawn));

	/* lookup system and pthread calls that exist outside of the plug-in module.
	 * do the lookup here and save to pointer so we dont have to redo the
	 * lookup on every syscall */
	SETSYM_OR_FAIL(worker->ftable.read, "read");
	SETSYM_OR_FAIL(worker->ftable.write, "write");

	SETSYM_OR_FAIL(worker->ftable.pthread_create, "pthread_create");
	SETSYM_OR_FAIL(worker->ftable.pthread_detach, "pthread_detach");
	SETSYM_OR_FAIL(worker->ftable.pthread_join, "pthread_join");
	SETSYM_OR_FAIL(worker->ftable.pthread_once, "pthread_once");
	SETSYM_OR_FAIL(worker->ftable.pthread_key_create, "pthread_key_create");
	SETSYM_OR_FAIL(worker->ftable.pthread_setspecific, "pthread_setspecific");
	SETSYM_OR_FAIL(worker->ftable.pthread_getspecific, "pthread_getspecific");
	SETSYM_OR_FAIL(worker->ftable.pthread_attr_setdetashstate, "pthread_attr_setdetashstate");
	SETSYM_OR_FAIL(worker->ftable.pthread_attr_getdetachstate, "pthread_attr_getdetachstate");
	SETSYM_OR_FAIL(worker->ftable.pthread_cond_init, "pthread_cond_init");
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

	g_private_set(&bitcoindWorkerKey, worker);

	assert(sizeof(pthread_t) >= sizeof(pth_t));
	assert(sizeof(pthread_attr_t) >= sizeof(pth_attr_t));
}

void bitcoindpreload_setContext(ExecutionContext ctx) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    worker->activeContext = ctx;
}

/* pth intercepted functions */

int shd_dl_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
	return sigprocmask(how, set, oset);
}

/*
int shd_dl_nanosleep(const struct timespec *rqtp, struct timespec *rmtp) {
  return nanosleep(rqtp, rmtp);
}
int shd_dl_usleep(unsigned int usec) {
  return usleep(usec);
}
int shd_dl_sleep(unsigned int sec) {
  return sleep(sec);
}
int shd_dl_system(const char *cmd) {
  return system(cmd);
}
int shd_dl_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
  return sigprocmask(how, set, oset);
}
int shd_dl_sigwait(const sigset_t *set, int *sigp) {
  return sigwait(set, sigp);
}
pid_t shd_dl_waitpid(pid_t wpid, int *status, int options) {
  return waitpid(wpid, status, options);
}
int shd_dl_connect(int s, const struct sockaddr *addr, socklen_t addrlen) {
  return connect(s, addr, addrlen);
}
int shd_dl_accept(int s, struct sockaddr *addr, socklen_t *addrlen) {
  return accept(s, addr, addrlen);
}
int shd_dl_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
  return select(nfds, readfds, writefds, exceptfds, timeout);
}
int shd_dl_pselect(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, const struct timespec *ts, const sigset_t *mask) {
  return pselect(nfds, rfds, wfds, efds, ts, mask);
}
int shd_dl_poll(struct pollfd *pfd, nfds_t nfd, int timeout) {
  return poll(pfd, nfd, timeout);
}
ssize_t shd_dl_readv(int fd, const struct iovec *iov, int iovcnt) {
  return readv(fd, iov, iovcnt);
}
ssize_t shd_dl_writev(int fd, const struct iovec *iov, int iovcnt) {
  return writev(fd, iov, iovcnt);
}
ssize_t shd_dl_pread(int fd, void *buf, size_t nbytes, off_t offset) {
  return pread(fd, buf, nbytes, offset);
}
ssize_t shd_dl_pwrite(int fd, const void *buf, size_t nbytes, off_t offset) {
  return pwrite(fd, buf, nbytes, offset);
}
ssize_t shd_dl_recv(int fd, void *buf, size_t nbytes, int flags) {
  return recv(fd, buf, nbytes, flags);
}
ssize_t shd_dl_send(int fd, void *buf, size_t nbytes, int flags) {
  return send(fd, buf, nbytes, flags);
}
ssize_t shd_dl_recvfrom(int fd, void *buf, size_t nbytes, int flags, struct sockaddr *from, socklen_t *fromlen) {
  return recvfrom(fd, buf, nbytes, flags, from, fromlen);
}
ssize_t shd_dl_sendto(int fd, const void *buf, size_t nbytes, int flags, const struct sockaddr *to, socklen_t tolen) {
  return sendto(fd, buf, nbytes, flags, to, tolen);
}
*/

ssize_t shd_dl_read(int fp, void *d, size_t s) {
	LeveldbPreloadWorker* worker = g_private_get(&leveldbWorkerKey);
	assert(worker);
	ExecutionContext e = worker->activeContext;
	worker->activeContext = EXECTX_PTH;
	int rc = worker->ftable.read(fp, d, s);
	worker->activeContext = e;
	return rc;
}

ssize_t shd_dl_write(int fp, const void *d, size_t s) {
	LeveldbPreloadWorker* worker = g_private_get(&leveldbWorkerKey);
	assert(worker);
	ExecutionContext e = worker->activeContext;
	worker->activeContext = EXECTX_PTH;
	int rc = worker->ftable.write(fp, d, s);
	worker->activeContext = e;
	return rc;
}

//#define ENSURE(prefix, func) { \
//	if(!director.type.func) { \
//		SETSYM_OR_FAIL(director.type.func, prefix #func); \
//	} \
//}

//int shd_dl_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
//	return sigprocmask(how, set, oset);
//}

ssize_t write(int fp, const void *d, size_t s) {
	BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
	ssize_t rc = 0;

	if(worker && worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;
        rc = worker->ftable.pth_write(fp, d, s);
        worker->activeContext = EXECTX_BITCOIN;
	} else {
	    /* dont mess with shadow's calls, and dont change context */
	    rc = worker->ftable.write(fp, d, s);
	}

	return rc;
}

ssize_t read(int fp, void *d, size_t s) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    ssize_t rc = 0;

    if(worker && worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;
        rc = worker->ftable.pth_read(fp, d, s);
        worker->activeContext = EXECTX_BITCOIN;
    } else {
        /* dont mess with shadow's calls, and dont change context */
        rc = worker->ftable.read(fp, d, s);
    }

    return rc;
}

/**
 * pthreads
 */

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;
        pth_attr_t na;

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

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_create(thread, attr, start_routine, arg);
    }

    return rc;
}

int pthread_detach(pthread_t thread) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;
        pth_attr_t na;

        if (thread == 0) {
            errno = EINVAL;
            rc = EINVAL;
        } else if ((na = pth_attr_of((pth_t)thread)) == NULL ||
                !pth_attr_set(na, PTH_ATTR_JOINABLE, FALSE)) {
            rc = errno;
        } else {
            pth_attr_destroy(na);
        }

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_detach(thread);
    }

    return rc;
}

int pthread_join(pthread_t thread, void **retval) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;

        if (!pth_join((pth_t)thread, retval)) {
            rc = errno;
        } else if(retval != NULL && *retval == PTH_CANCELED) {
            *retval = PTHREAD_CANCELED;
        }

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_join(thread, retval);
    }

    return rc;
}

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;

        if (once_control == NULL || init_routine == NULL) {
            errno = EINVAL;
            rc = EINVAL;
        } else {
            if (*once_control != 1) {
                worker->activeContext = EXECTX_BITCOIN;
                init_routine();
                worker->activeContext = EXECTX_PTH;
            }
            *once_control = 1;
        }

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_once(once_control, init_routine);
    }

    return rc;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void*)) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;

        if (!pth_key_create((pth_key_t *)key, destructor)) {
            rc = errno;
        }

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_key_create(key, destructor);
    }

    return rc;
}

int pthread_setspecific(pthread_key_t key, const void *value) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;

        if (!pth_key_setdata((pth_key_t)key, value)) {
            rc = errno;
        }

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_setspecific(key, value);
    }

    return rc;
}

void *pthread_getspecific(pthread_key_t key) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    void* pointer = NULL;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;

        pointer = pth_key_getdata((pth_key_t)key);

        worker->activeContext = EXECTX_BITCOIN;
    } else {
        pointer = worker->ftable.pthread_getspecific(key);
    }

    return pointer;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;


    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_attr_setdetashstate(attr, detachstate);
    }

    return rc;
}

int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_attr_getdetachstate(attr, detachstate);
    }

    return rc;
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_cond_init(cond, attr);
    }

    return rc;
}

int pthread_cond_destroy(pthread_cond_t *cond) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_cond_destroy(cond);
    }

    return rc;
}

int pthread_cond_signal(pthread_cond_t *cond) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_cond_signal(cond);
    }

    return rc;
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_cond_broadcast(cond);
    }

    return rc;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_cond_wait(cond, mutex);
    }

    return rc;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
              const struct timespec *abstime) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_cond_timedwait(cond, mutex, abstime);
    }

    return rc;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;
    pth_mutex_t *m;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_mutex_init(mutex, attr);
    }

    return rc;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_mutex_destroy(mutex);
    }

    return rc;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_mutex_lock(mutex);
    }

    return rc;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_mutex_trylock(mutex);
    }

    return rc;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    BitcoindPreloadWorker* worker = g_private_get(&bitcoindWorkerKey);
    int rc = 0;

    if(worker->activeContext == EXECTX_BITCOIN) {
        worker->activeContext = EXECTX_PTH;



        worker->activeContext = EXECTX_BITCOIN;
    } else {
        rc = worker->ftable.pthread_mutex_unlock(mutex);
    }

    return rc;
}
