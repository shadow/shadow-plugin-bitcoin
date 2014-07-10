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

const char *block_hex="0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
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
		msg_version_free(&mv);
	}
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sending done");

	sleep(10);
        return 0;
}


