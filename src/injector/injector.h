/*
 * See LICENSE for licensing information
 */

#ifndef INJECTOR_H_
#define INJECTOR_H_

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

#include "../bitcoind/bitcoind-preload.h"

typedef struct _BitcoinD BitcoinD;

int injector_new(int argc, char* argv[], ShadowLogFunc slogf);

#endif /* BITCOIND_H_ */
