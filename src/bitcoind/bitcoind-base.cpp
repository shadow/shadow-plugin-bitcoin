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
#include <shd-library.h>
#include <sys/stat.h>
#include <pthread.h>
#include <boost/thread/once.hpp>
#include <string>

extern bool AppInit(int argc, char* argv[]);

static ShadowLogFunc slogf;

extern "C"
int bitcoind_logprintstr(const char *str) {
  slogf(SHADOW_LOG_LEVEL_MESSAGE, "bitcoind", "%s", str);
  return 0;
}

extern "C"
void bitcoind_new(int argc, char* argv[], ShadowLogFunc slogf_) {
        slogf = slogf_;
	AppInit(argc, argv);
	/*
	assert(slogf);
	fprintf(stderr, "_start_bitcoind:about to read\n");
	char buf[10] = "hiya!\n";
	write(2, buf, 6);
	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&thread, 0, &doNothing, 0);
	pthread_join(thread, 0);
	*/
}
