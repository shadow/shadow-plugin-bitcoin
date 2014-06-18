/*
 * See LICENSE for licensing information
 */

#include "bitcoind.h"
#include <pth.h>
#include <pthread.h>

/* all state is stored here */
struct _BitcoinD {
	/* the function we use to log messages
	 * needs level, functionname, and format */
	ShadowLogFunc slogf;

	/* main epoll descriptor */
	int ed;
};

void doNothing(void) { 
	fprintf(stderr, "_start_bitcoind:about to read\n");
	char buf[10] = "hiya!\n";
	write(2, buf, 6);
}

static void _start_bitcoind(BitcoinD *bcd) {
	//foo_test(12);
	fprintf(stderr, "_start_bitcoind:about to read\n");
	char buf[10] = "hiya!\n";
	bcd->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "shadow: about to read");
	//_mark_isPlugin();
	write(2, buf, 6);
	pthread_t thread;
	//pthread_attr_t attr;
	//pthread_attr_init(&attr);
	pthread_create(&thread, 0, doNothing, 0);
	pthread_destroy();

	//_unmark_isPlugin();
	
	//fprintf(stderr, "wrote\n");
	bcd->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "read 10 bytes from stdin");
}

/* if option is specified, run as client, else run as server */
static const char* USAGE = "USAGE: \n";

BitcoinD* bitcoind_new(int argc, char* argv[], ShadowLogFunc slogf) {
	assert(slogf);

	/* get memory for the new state */
	BitcoinD* bcd = calloc(1, sizeof(BitcoinD));
	assert(bcd);
	bcd->slogf = slogf;
	bcd->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, "bitcoin_new!!");

	pth_spawn(PTH_ATTR_DEFAULT, (void * (*) (void *)) _start_bitcoind, bcd);

	return bcd;
}

int bitcoind_getEpollDescriptor(BitcoinD *bcd) {
	assert(bcd);
	return bcd->ed;
}

void bitcoind_free(BitcoinD* bcd) {
	assert(bcd);
	free(bcd);
}

void bitcoind_ready(BitcoinD* bcd) {
}

int foo_test(int a) {
	fprintf(stderr, "bitcoind.c:foo_test(%d)\n", a);
	return a;
}
