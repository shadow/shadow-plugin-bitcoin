/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#include <sys/time.h>
#include <stdint.h>
#include <stdarg.h>

#include <glib.h>
#include <gmodule.h>

#define BITCOIND_LIB_PREFIX "intercept_"

typedef int (*foo_test_fp)(int);
typedef int (*read_fp)(int, void*, int);

/* the key used to store each threads version of their searched function library.
 * the use this key to retrieve this library when intercepting functions from tor.
 */
GStaticPrivate bitcoindWorkerKey;

typedef struct _BitcoindPreloadWorker BitcoindPreloadWorker;
/* TODO fix func names */
struct _BitcoindPreloadWorker {
	GModule* handle;
	read_fp _read;
	foo_test_fp _foo_test;
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

void bitcoindpreload_init(GModule* handle) {
	BitcoindPreloadWorker* worker = _bitcoindpreload_newWorker(handle);

	/* lookup all our required symbols in this worker's module, asserting success */
	g_assert(g_module_symbol(handle, BITCOIND_LIB_PREFIX "read", (gpointer*)&(worker->_read)));
	g_assert(g_module_symbol(handle, BITCOIND_LIB_PREFIX "foo_test", (gpointer*)&(worker->_foo_test)));

	g_static_private_set(&bitcoindWorkerKey, worker, g_free);
}

int foo_test(int a) {
	return _bitcoindpreload_getWorker()->_foo_test(a);
}

int read(int fp, void *d, int s) {
	_bitcoindpreload_getWorker()->_read(fp, d, s);
}
