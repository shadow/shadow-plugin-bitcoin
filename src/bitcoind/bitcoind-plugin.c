/*
 * See LICENSE for licensing information
 */

#include "bitcoind.h"
#include <pth.h>

/* functions that interface into shadow */
ShadowFunctionTable shadowlib;

/* our opaque instance of the hello node */
//BitcoinD* bcdNodeInstance = NULL;

/* Log function for Bitcoin */
typedef int (*bitcoind_logprintstr_fp)(const char*);
int CLogPrintStr(const char *s) {
  //real_fprintf(stderr, "%s", s);
  bitcoindpreload_setContext(EXECTX_SHADOW);
  shadowlib.log(SHADOW_LOG_LEVEL_INFO, __FUNCTION__, "%s", s);
  bitcoindpreload_setContext(EXECTX_PLUGIN);
  return 0;
}

static int main_epd = -1;


/* shadow is freeing an existing instance of this plug-in that we previously
 * created in helloplugin_new()
 */
static void bitcoindplugin_free() {
	/* shadow wants to free a node. pass this to the lower level
	 * plug-in function that implements this for both plug-in and non-plug-in modes.
	 */
}

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
static void bitcoindplugin_ready() {
	bitcoindpreload_setContext(EXECTX_SHADOW);

	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
    
	static int epd = -1;
	struct epoll_event ev = {};
	//shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "Master activated");

	epoll_wait(epd, &ev, 1, 0); // try to consume an event

	if (epd > -1) {
		epoll_ctl(main_epd, EPOLL_CTL_DEL, epd, NULL);
		epd = -1;
	}

	ev.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	pth_attr_set(pth_attr_of(pth_self()), PTH_ATTR_PRIO, PTH_PRIO_MIN);
	bitcoindpreload_setContext(EXECTX_PLUGIN);
	pth_yield(NULL); // go visit the scheduler at least once
	bitcoindpreload_setContext(EXECTX_SHADOW);

	while (pth_ctrl(PTH_CTRL_GETTHREADS_READY | PTH_CTRL_GETTHREADS_NEW)) {
		//pth_ctrl(PTH_CTRL_DUMPSTATE, stderr);
		pth_attr_set(pth_attr_of(pth_self()), PTH_ATTR_PRIO, PTH_PRIO_MIN);
		bitcoindpreload_setContext(EXECTX_PLUGIN);
		pth_yield(NULL);
		bitcoindpreload_setContext(EXECTX_SHADOW);
	}
	epd = pth_waiting_epoll();
	if (epd > -1) {
		ev.data.fd = epd;
		epoll_ctl(main_epd, EPOLL_CTL_ADD, epd, &ev);
	}
	//shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "Master exiting");

	/* Figure out when the next timer would be */
	struct timeval timeout = pth_waiting_timeout();
	if (!(timeout.tv_sec == 0 && timeout.tv_usec == 0)) {
		struct timeval now, delay;
		bitcoindpreload_setContext(EXECTX_PLUGIN);
		gettimeofday(&now, NULL);
		bitcoindpreload_setContext(EXECTX_SHADOW);
		uint ms;
		if (_timeval_subtract(&delay, &timeout, &now)) ms = 0;
		else ms = 1 + delay.tv_sec*1000 + (delay.tv_usec+1)/1000;
		//assert delay.tv_sec >= 0;
		assert(ms > 0);
		//pth_ctrl(PTH_CTRL_DUMPSTATE, stderr);
		//shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "Registering a callback for %u ms", ms);
		shadowlib.createCallback((ShadowPluginCallbackFunc) bitcoindplugin_ready, NULL, ms);
	}
}

/* shadow is creating a new instance of this plug-in as a node in
 * the simulation. argc and argv are as configured via the XML.
 */
struct args_t {int argc; char **argv; ShadowLogFunc slogf;};

void *_bitcoind_new(struct args_t *args) {
	assert(args);
	int argc = args->argc;
	char **argv = args->argv;
	ShadowLogFunc slogf = args->slogf;
	bitcoind_new(argc, argv, slogf);
	return 0;
}

/* shadow is creating a new instance of this plug-in as a node in
 * the simulation. argc and argv are as configured via the XML.
 */
static void bitcoindplugin_new(int argc, char* argv[]) {
	/* shadow wants to create a new node. pass this to the lower level
	 * plug-in function that implements this for both plug-in and non-plug-in modes.
	 * also pass along the interface shadow gave us earlier.
	 *
	 * the value of helloNodeInstance will be different for every node, because
	 * we did not set it in __shadow_plugin_init__(). this is desirable, because
	 * each node needs its own application state.
	 */
	init_tls();
	bitcoindpreload_setContext(EXECTX_PTH);
	pth_init();

	//helloNodeInstance = hello_new(argc, argv, shadowlib.log);
	struct args_t args = {argc, argv, shadowlib.log};
	pth_t t = pth_spawn(PTH_ATTR_DEFAULT, (void *(*)(void*))&_bitcoind_new, &args);
	bitcoindpreload_setContext(EXECTX_PLUGIN);

	// Jog the threads once
	bitcoindplugin_ready();

	bitcoindpreload_setContext(EXECTX_SHADOW);
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
	bitcoindpreload_setContext(EXECTX_SHADOW);
	int success = shadowlib.registerPlugin(&bitcoindplugin_new, &bitcoindplugin_free, &bitcoindplugin_ready);

	/* we log through Shadow by using the log function it supplied to us */
	if(success) {
		shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__,
				"successfully registered bitcoind plug-in state");
	} else {
		shadowlib.log(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"error registering bitcoind plug-in state");
	}
}

/* called immediately after the plugin is loaded. shadow loads plugins once for
 * each worker thread. the GModule* is needed as a handle for g_module_symbol()
 * symbol lookups.
 * return NULL for success, or a string describing the error */
const gchar* g_module_check_init(GModule *module) {
	/* clear our memory before initializing */
	//memset(&scallion, 0, sizeof(Scallion));
	fprintf(stderr, "gmodule init bitcoind\n");
	/* do all the symbol lookups we will need now, and init our thread-specific
	 * library of intercepted functions. */
	bitcoindpreload_init(module);
	fprintf(stderr, "check_init done\n");

	return NULL;
}

void g_module_unload(GModule *module) {
}
