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

#include <shd-library.h>

typedef struct _BitcoinD BitcoinD;

BitcoinD* bitcoind_new(int argc, char* argv[], ShadowLogFunc slogf);
void bitcoind_free(BitcoinD* h);
void bitcoind_ready(BitcoinD* h);

#endif /* BITCOIND_H_ */
