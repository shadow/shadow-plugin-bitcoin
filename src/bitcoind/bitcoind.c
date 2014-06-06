/*
 * See LICENSE for licensing information
 */

#include "bitcoind.h"
#include <pth.h>

/* all state is stored here */
struct _BitcoinD {
	/* the function we use to log messages
	 * needs level, functionname, and format */
	ShadowLogFunc slogf;

	/* main epoll descriptor */
	int ed;
};

static void _start_bitcoind(BitcoinD *bcd) {
	//foo_test(12);
	char buf[10];
	fprintf(stderr, "About to read\n");
	read(0, buf, 10);
	printf("read 10 bytes from stdin\n");
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
	bitcoind_ready(bcd);

	return bcd;
}


void bitcoind_free(BitcoinD* bcd) {
	assert(bcd);

	free(bcd);
}

void bitcoind_ready(BitcoinD* bcd) {
	assert(bcd);
	struct epoll_event ev = {};
	ev.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
	static int epd = -1;
	if (epd > -1) {
		ev.data.fd = epd;
		epoll_ctl(bcd->ed, EPOLL_CTL_DEL, epd, &ev);
		epd = -1;
	}
	pth_yield(NULL);
	fprintf(stderr, "Master activate\n");
	while (pth_ctrl(PTH_CTRL_GETTHREADS_READY | PTH_CTRL_GETTHREADS_NEW)) {
		pth_ctrl(PTH_CTRL_DUMPSTATE, stderr);
		pth_attr_set(pth_attr_of(pth_self()), PTH_ATTR_PRIO, PTH_PRIO_MIN);
		pth_yield(NULL);
	}
	epd = pth_waiting_epoll();
	ev.data.fd = epd;
	epoll_ctl(bcd->ed, EPOLL_CTL_ADD, epd, &ev);
	fprintf(stderr, "Master exiting\n");
}

int foo_test(int a) {
	fprintf(stderr, "bitcoind.c:foo_test(%d)\n", a);
	return a;
}
