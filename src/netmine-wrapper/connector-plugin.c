/*
 * See LICENSE for licensing information
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <glib.h>
#include <gmodule.h>

#include <shd-library.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <pth.h>

#include "../bitcoind/bitcoind-preload.h"

extern int plugin_main(int argc, char* argv[]);

/* functions that interface into shadow */
ShadowFunctionTable shadowlib;

#define ACTIVE_PLUGIN PLUGIN_NETMINE_CONNECTOR

void logwrapper(ShadowLogLevel level, const char *functionName, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	bitcoindpreload_setShadowContext();
	shadowlib.log(level, functionName, format, ap);
	bitcoindpreload_setPluginContext(ACTIVE_PLUGIN);
	va_end(ap);
}

static int main_epd = -1;

void _plugin_ctors() { }
void _plugin_dtors() { }

static pth_uctx_t plugin_context;
static pth_uctx_t master_context;


/* shadow is freeing an existing instance of this plug-in that we previously
 * created in plugin_new()
 */
static void plugin_free() {}

/* Subtract the `struct timeval' values X and Y,
        storing the result in RESULT.
        Return 1 if the difference is negative, otherwise 0. */
static int _timeval_subtract (result, x, y)
     struct timeval *result, *x, *y;
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}
	
	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;
	
	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}


/* shadow is notifying us that some descriptors are ready to read/write */
static void plugin_ready() {
	bitcoindpreload_setShadowContext();

	// Switch to the plugin running context
	int rc = pth_uctx_switch(master_context, plugin_context);
	assert(rc);

	// When the plugin returns, it should be because we've switched back in
	// due to an swapPlugin_epoll_wait call
}


int swapPlugin_epoll_wait(int epfd, struct epoll_event *events,
			  int maxevents, int timeout) {
	bitcoindpreload_setShadowContext();

	//shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "Registering a callback for %u ms", ms);
	shadowlib.createCallback((ShadowPluginCallbackFunc) plugin_ready, NULL, timeout);

	int rc = pth_uctx_switch(plugin_context, master_context);
	assert(rc);

	bitcoindpreload_setPluginContext(ACTIVE_PLUGIN);

	// When we make it here, an event should have occurred
	return epoll_wait(epfd, events, maxevents, 0);
}


/* shadow is creating a new instance of this plug-in as a node in
 * the simulation. argc and argv are as configured via the XML.
 */
struct args_t {int argc; char **argv; ShadowLogFunc slogf;};

void *_connector_new(struct args_t *args) {
	bitcoindpreload_setPluginContext(ACTIVE_PLUGIN);
	_plugin_ctors();
	assert(args);
	int argc = args->argc;
	char **argv = args->argv;
	ShadowLogFunc slogf = args->slogf;
	plugin_main(argc, argv);
	return 0;
}

void _connector_new_void(struct args_t *args) {
	_connector_new(args);
}

/* shadow is creating a new instance of this plug-in as a node in
 * the simulation. argc and argv are as configured via the XML.
 */
static void plugin_new(int argc, char* argv[]) {
	/* shadow wants to create a new node. pass this to the lower level
	 * plug-in function that implements this for both plug-in and non-plug-in modes.
	 * also pass along the interface shadow gave us earlier.
	 *
	 * the value of helloNodeInstance will be different for every node, because
	 * we did not set it in __shadow_plugin_init__(). this is desirable, because
	 * each node needs its own application state.
	 */
	bitcoindpreload_setPthContext();
	pth_init();

	//helloNodeInstance = hello_new(argc, argv, shadowlib.log);
	struct args_t args = {argc, argv, logwrapper};

	/* Instead of spawning a pth thread here, just create a new context */
	int rc = pth_uctx_create(&plugin_context);
	assert(rc);
	rc = pth_uctx_create(&master_context);
	assert(rc);
	rc = pth_uctx_make(plugin_context, NULL, 130000, NULL, _connector_new_void, &args, NULL);
	assert(rc);

	//pth_t t = pth_spawn(PTH_ATTR_DEFAULT, (void *(*)(void*))&_connector_new, &args);
	bitcoindpreload_setPluginContext(ACTIVE_PLUGIN);

	// Jog the threads once
	plugin_ready();

	bitcoindpreload_setShadowContext();
}

/* plug-in initialization. this only happens once per plug-in,
 * no matter how many nodes (instances of the plug-in) are configured.
 *
 * whatever state is configured in this function will become the default
 * starting state for each node.
 *
 * the "__shadow_plugin_init__" function MUST exist in every plug-in.
 */
void __shadow_plugin_init__(ShadowFunctionTable* shadowlibFuncs) {
	assert(shadowlibFuncs);

	/* locally store the functions we use to call back into shadow */
	shadowlib = *shadowlibFuncs;

	/*
	 * tell shadow how to call us back when creating/freeing nodes, and
	 * where to call to notify us when there is descriptor I/O
	 */
	bitcoindpreload_setShadowContext();
	int success = shadowlib.registerPlugin(&plugin_new, &plugin_free, &plugin_ready);

	/* we log through Shadow by using the log function it supplied to us */
	if(success) {
		shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__,
				"successfully registered connector plug-in state");
	} else {
		shadowlib.log(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"error registering connector plug-in state");
	}
}

/* called immediately after the plugin is loaded. shadow loads plugins once for
 * each worker thread. the GModule* is needed as a handle for g_module_symbol()
 * symbol lookups.
 * return NULL for success, or a string describing the error */

typedef void (*CRYPTO_lock_func)(int, int, const char*, int);
typedef unsigned long (*CRYPTO_id_func)(void);

const gchar* g_module_check_init(GModule *module) {
	fprintf(stderr, "gmodule init connector\n");
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)
	/* thread support enabled, how many locks does openssl want */
	int nLocks = CRYPTO_num_locks();

	/* do all the symbol lookups we will need now, and init thread-specific
	 * library of intercepted functions, init our global openssl locks. */
	bitcoindpreload_init(module, nLocks);

	/* make sure openssl uses Shadow's random sources and make crypto thread-safe
	 * get function pointers through LD_PRELOAD */
	const RAND_METHOD* shadowtor_randomMethod = RAND_get_rand_method();
	CRYPTO_lock_func shadowtor_lockFunc = CRYPTO_get_locking_callback();
	CRYPTO_id_func shadowtor_idFunc = CRYPTO_get_id_callback();

	CRYPTO_set_locking_callback(shadowtor_lockFunc);
	CRYPTO_set_id_callback(shadowtor_idFunc);
	RAND_set_rand_method(shadowtor_randomMethod);

	//.opensslThreadSupport = 1;
#else
	/* no thread support */
	//nodeinstance.opensslThreadSupport = 0;
#endif
	fprintf(stderr, "check_init done\n");
	return NULL;
}

void g_module_unload(GModule *module) {
}

int bitcoindplugin_cxa_atexit(void (*f)(void*), void * arg, void * dso_handle) { return 0; }
