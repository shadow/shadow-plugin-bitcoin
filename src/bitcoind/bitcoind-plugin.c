/*
 * See LICENSE for licensing information
 */

#include "bitcoind.h"
#include <pth.h>

/* functions that interface into shadow */
ShadowFunctionTable shadowlib;

/* our opaque instance of the hello node */
BitcoinD* bcdNodeInstance = NULL;


/* shadow is freeing an existing instance of this plug-in that we previously
 * created in helloplugin_new()
 */
static void bitcoindplugin_free() {
	/* shadow wants to free a node. pass this to the lower level
	 * plug-in function that implements this for both plug-in and non-plug-in modes.
	 */
    bitcoindpreload_setContext(EXECTX_BITCOIN);
	bitcoind_free(bcdNodeInstance);
	bitcoindpreload_setContext(EXECTX_SHADOW);
}

/* shadow is notifying us that some descriptors are ready to read/write */
static void bitcoindplugin_ready() {
    bitcoindpreload_setContext(EXECTX_BITCOIN);

	/* shadow wants to handle some descriptor I/O. pass this to the lower level
	 * plug-in function that implements this for both plug-in and non-plug-in modes.
	 */
	static int epd = -1;
	int ed = bitcoind_getEpollDescriptor(bcdNodeInstance);

	bitcoindpreload_setContext(EXECTX_SHADOW);
	shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "Master activated");
	bitcoindpreload_setContext(EXECTX_BITCOIN);

	struct epoll_event ev = {};
	epoll_wait(ed, &ev, 1, 0); // try to consume an event

	if (epd > -1) {
		epoll_ctl(ed, EPOLL_CTL_DEL, epd, NULL);
		epd = -1;
	}

	ev.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	bitcoindpreload_setContext(EXECTX_PTH);
	pth_attr_set(pth_attr_of(pth_self()), PTH_ATTR_PRIO, PTH_PRIO_MIN);
	pth_yield(NULL); // go visit the scheduler at least once
	while (pth_ctrl(PTH_CTRL_GETTHREADS_READY | PTH_CTRL_GETTHREADS_NEW)) {
		//pth_ctrl(PTH_CTRL_DUMPSTATE, stderr);
		pth_attr_set(pth_attr_of(pth_self()), PTH_ATTR_PRIO, PTH_PRIO_MIN);
		pth_yield(NULL);
	}
	epd = pth_waiting_epoll();
	bitcoindpreload_setContext(EXECTX_BITCOIN);
	if (epd > -1) {
		ev.data.fd = epd;
		epoll_ctl(ed, EPOLL_CTL_ADD, epd, &ev);
	}
	bitcoindpreload_setContext(EXECTX_SHADOW);
	shadowlib.log(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "Master exiting");

	/* Figure out when the next timer would be */
	bitcoindpreload_setContext(EXECTX_PTH);
	struct timeval timeout = pth_waiting_timeout();
	bitcoindpreload_setContext(EXECTX_BITCOIN);
	if (!(timeout.tv_sec == 0 && timeout.tv_usec == 0)) {
		struct timeval now, delay;
		gettimeofday(&now, NULL);
		uint ms;
		if (_timeval_subtract(&delay, &timeout, &now)) ms = 0;
		else ms = 1 + delay.tv_sec*1000 + (delay.tv_usec+1)/1000;

		bitcoindpreload_setContext(EXECTX_SHADOW);
		shadowlib.log(SHADOW_LOG_LEVEL_DEBUG, __FUNCTION__, "Registering a callback for %d ms", ms);
		shadowlib.createCallback((ShadowPluginCallbackFunc) bitcoind_ready, NULL, ms);
		bitcoindpreload_setContext(EXECTX_BITCOIN);
	}

	bitcoindpreload_setContext(EXECTX_SHADOW);
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
    bitcoindpreload_setContext(EXECTX_PTH);
	pth_init();

	bitcoindpreload_setContext(EXECTX_BITCOIN);
	bcdNodeInstance = bitcoind_new(argc, argv, shadowlib.log);

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

	return NULL;
}
