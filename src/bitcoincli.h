/*
 * See LICENSE for licensing information
 */

#ifndef BITCOINCLI_H_
#define BITCOINCLI_H_

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

typedef struct _BitcoinCLI BitcoinCLI;

BitcoinCLI* bitcoincli_new(int argc, char* argv[], ShadowLogFunc slogf);
void bitcoincli_free(BitcoinCLI* h);
void bitcoincli_ready(BitcoinCLI* h);

#endif /* BITCOINCLI_H_ */
