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
#include <pth.h>

#include "picocoin-config.h"
#include <ccoin/util.h>
#include <ccoin/mbr.h>
#include <ccoin/core.h>
#include <ccoin/buint.h>
#include <ccoin/net.h>
#include <ccoin/message.h>

#include "injector.h"

enum {
	PROTO_VERSION= 60002,
};

static ShadowLogFunc slogf;

const char block_hex[]="010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";
char block_bin[sizeof(block_hex)/2];

#include <signal.h>
int injector_new(int argc, char* argv[], ShadowLogFunc slogf_) {
	slogf = slogf_;
	assert(argc == 2);

	char *serverHostName = argv[1];

	/* get the address of the server */
	struct addrinfo* serverInfo;
	int res = getaddrinfo(serverHostName, NULL, NULL, &serverInfo);
	if(res == -1) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in getaddrinfo");
		return -1;
	}

	in_addr_t serverIP = ((struct sockaddr_in*)(serverInfo->ai_addr))->sin_addr.s_addr;
	freeaddrinfo(serverInfo);


	/* create the client socket and get a socket descriptor */
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in socket");
		return -1;
	}

	/* our client socket address information for connecting to the server */
	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = serverIP;
	serverAddress.sin_port = htons(8333);

	/* connect to server. since we are non-blocking, we expect this to return EINPROGRESS */
	res = connect(sd,(struct sockaddr *)  &serverAddress, sizeof(serverAddress));

	if (res == -1 && errno != EINPROGRESS) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in connect");
		return -1;
	}


	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sending begin");
	{
		struct msg_version mv;
		msg_version_init(&mv);
		mv.nVersion = PROTO_VERSION;
		mv.nTime = (int64_t) time(NULL);
		mv.nonce = 1324;
		sprintf(mv.strSubVer, "/picocoin:%s/", VERSION);
		mv.nStartingHeight = 10;
		bitcoindpreload_setShadowContext();
		GString *rs = ser_msg_version(&mv);
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "version", rs->str, rs->len);
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}
	{
		char a;
		//recv(sd, &a, 1, 0);
		sleep(2);
	}
	{
		bitcoindpreload_setShadowContext();
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "verack", NULL, 0);
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}
	{
		printf("strlen(block_hex):%d sizeof(block_hex):%d sizeof(block_bin):%d\n", strlen(block_hex), sizeof(block_hex), sizeof(block_bin));
		int len;
		if (!decode_hex(block_bin, sizeof(block_bin), block_hex, &len)) {
			fprintf(stderr, "Decode failed\n");
		}
		assert(len == sizeof(block_bin));
		//unhexlify(block_hex, block_bin);
		//strrev(block_bin);
		bitcoindpreload_setShadowContext();
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "block", block_bin, sizeof(block_bin));
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}

	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sending done");

	sleep(10);
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sleep done");

        return 0;
}


