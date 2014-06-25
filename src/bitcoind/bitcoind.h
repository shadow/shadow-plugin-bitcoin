/*
 * See LICENSE for licensing information
 */

#ifndef BITCOIND_H_
#define BITCOIND_H_

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

typedef enum _ExecutionContext ExecutionContext;
enum _ExecutionContext {
    EXECTX_NONE, EXECTX_PLUGIN, EXECTX_PTH, EXECTX_SHADOW,
};

void bitcoindpreload_init(GModule* handle);
void bitcoindpreload_setContext(ExecutionContext ctx);


typedef struct _BitcoinD BitcoinD;

BitcoinD* bitcoind_new(int argc, char* argv[], ShadowLogFunc slogf);
void bitcoind_free(BitcoinD* h);
void bitcoind_ready(BitcoinD* h);
int bitcoind_getEpollDescirptor(BitcoinD* h);

#endif /* BITCOIND_H_ */
