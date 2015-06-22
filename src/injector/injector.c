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

#include "picocoin-config.h"
#include <ccoin/util.h>
#include <ccoin/mbr.h>
#include <ccoin/core.h>
#include <ccoin/buint.h>
#include <ccoin/net.h>
#include <ccoin/message.h>

#include "injector.h"

enum {
	PROTO_VERSION= 70002,
};

static ShadowLogFunc slogf;

#include <signal.h>

int send_getinfo(const char *serverHostName) {
	static const char getinfo_string[] = "POST / HTTP/1.1"
	  "User-Agent: bitcoin-json-rpc/v0.9.99.0-bdc7f1a-beta"
	  "Host: 127.0.0.1"
	  "Content-Type: application/json"
	  "Content-Length: 40"
	  "Connection: close"
	  "Accept: application/json"
	  "Authorization: Basic Yml0Y29pbnJwYzo0SjdZVUtnUkhkOGhVV3AxNGUyMzNwd21rUHRiblEyY1VTNFBNeGl5MUo2eg=="
	  ""
	  "{\"method\":\"getinfo\",\"params\":[],\"id\":1}";

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
	serverAddress.sin_port = htons(8332);

	/* connect to server. since we are non-blocking, we expect this to return EINPROGRESS */
	res = connect(sd,(struct sockaddr *)  &serverAddress, sizeof(serverAddress));

	if (res == -1 && errno != EINPROGRESS) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in connect");
		return -1;
	}

	int rc = send(sd, getinfo_string, sizeof(getinfo_string), 0);
	assert(rc == sizeof(getinfo_string));
	return 0;
}



int injector_new(int argc, char* argv[], ShadowLogFunc slogf_) {       
	slogf = slogf_;
	assert(argc >= 3);

	char serverHostName[1024];
	strcpy(serverHostName, argv[1]);
	char payload_path[1024];
	strcpy(payload_path, argv[2]);
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "payload_path:%s", payload_path);
	
	//send_getinfo(serverHostName);
	//return 0;

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

	//int buffersize = 1000*1*1000;  // default size
	//setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *) &buffersize, sizeof(buffersize));

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
		mv.nServices = 1;
		mv.nTime = (int64_t) time(NULL);
		mv.nonce = 1324;
		sprintf(mv.strSubVer, "/picocoin:%s/", VERSION);
		mv.nStartingHeight = 120595;
		bitcoindpreload_setShadowContext();
		GString *rs = ser_msg_version(&mv);
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "version", rs->str, rs->len);
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}

	sleep(2);

	{
		// Send the VERACK message
		bitcoindpreload_setShadowContext();
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "verack", NULL, 0);
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}

	{
		// Send the PING message
		struct msg_ping mv;
		msg_ping_init(&mv);
		bitcoindpreload_setShadowContext();
		GString *rs = ser_msg_ping(PROTO_VERSION, &mv);
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "ping", rs->str, rs->len);
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}

	sleep(2);

	{
		// Read the payload file and send it
		assert(argc > 2);
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__, payload_path);
		FILE *f = fopen(payload_path, "rb");
		assert(f);
		const int BUF = 200000;
		static char buf[BUF];
		int rc;
		int total_sent = 0;
		while ((rc = fread(buf, 1, BUF, f))) {
			printf("Sending payload: %d bytes\n", rc);
			char *ptr = buf;
			while (rc) {
				int sent = send(sd, ptr, rc, 0);
				if (sent == -1) {
					if (errno == EAGAIN) {
						usleep(5*1000);
						continue;
					} else {
						printf("Send failed: %d (%s)\n", errno, strerror(errno));
						exit(1);
					}
				}
				rc -= sent;
				ptr += sent;
				printf("Sent %d bytes, %d remaining\n", sent, rc);
				total_sent += sent;
			}
			usleep(10*1000);
		}
		printf("Sending done\n");
	}


	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sending done");
	
	sleep(60);
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sleep done");

	//close(sd);
        return 0;
}


