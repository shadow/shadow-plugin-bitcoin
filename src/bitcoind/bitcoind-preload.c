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

#include <glib.h>
#include <gmodule.h>

#define BITCOIND_LIB_PREFIX "intercept_"

typedef int (*foo_test_fp)(int);
typedef ssize_t (*read_fp)(int, void*, size_t);

/* the key used to store each threads version of their searched function library.
 * the use this key to retrieve this library when intercepting functions from tor.
 */
GStaticPrivate bitcoindWorkerKey;

typedef struct _BitcoindPreloadWorker BitcoindPreloadWorker;
/* TODO fix func names */
struct _BitcoindPreloadWorker {
	GModule* handle;
	read_fp pth_read;
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
	//g_assert(g_module_symbol(handle, BITCOIND_LIB_PREFIX "read", (gpointer*)&(worker->_read)));
	//g_assert(g_module_symbol(handle, BITCOIND_LIB_PREFIX "foo_test", (gpointer*)&(worker->_foo_test)));

	g_static_private_set(&bitcoindWorkerKey, worker, g_free);
}


#define ENSURE(prefix, func) { \
	if(!director.type.func) { \
		SETSYM_OR_FAIL(director.type.func, prefix #func); \
	} \
}

int foo_test(int a) {
	foo_test_fp real;
	SETSYM_OR_FAIL(real, "foo_test");
	fprintf(stderr, "bitcoind-preload.c:foo_test(%d) real:%d\n", a, real);
	return real(a);
}

static __thread unsigned long isRecursive = 0;

ssize_t read(int fp, void *d, size_t s) {
	BitcoindPreloadWorker* worker = g_static_private_get(&bitcoindWorkerKey);

	fprintf(stderr, "In bitcoind-preload.c read\n");
	int rc;

	/* ensure don't intercept a local */
	int ss = __sync_fetch_and_add(&isRecursive, 1);
	fprintf(stderr, "c\n");
	fprintf(stderr, "bitcoind-preload.c after fetch\n");
	if(!ss && worker) {
		fprintf(stderr, "bitcoind-preload.c:read(%d) pass to gnu pth\n", fp);
		rc = worker->pth_read(fp, d, s);
	} else {
		read_fp real;
		SETSYM_OR_FAIL(real, "read");
		fprintf(stderr, "looking for real read real:%ld\n", real);
		fprintf(stderr, "bitcoind-preload.c:read(%d) real:%ld\n", fp, real);
		rc = real(fp, d, s);
		fprintf(stderr, "real read returned %d\n", rc);
	}
	__sync_fetch_and_sub(&isRecursive, 1);
	fprintf(stderr, "returning %d\n", rc);
	return rc;
}
