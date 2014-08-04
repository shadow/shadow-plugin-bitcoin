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

//const char block_hex[]="010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";
//const char block_hex[]="010000005ac2c47e00c37a83230c5521347528f72ced090d3845d23aa34b000000000000fa2775787c5b62bac40464034c6cbfb2737fc55e610e308e18116dcd1f845e0bf0e5b84dacb5001b7f9698000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03025139ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac000000000100000001982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e0000000049483045022002d7f085f43a1d10ec32528ec120a2f58f4ed1de98d04e751931b17ebf28d423022100f8e59cff374cc796d3e408159de169b303405d9a5d129897793f6ad3d77cd54c03ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"; // A fabricated block of height 120595
#include "BLOCK_303335.h"
//static const char block_hex[]=BLOCK_303335; 
//static const char block_hex[] = "020000007f39b22dc3f751fa2cb3f290a4907c9635b4f9da7e42b35b0000000000000000b35d1e399b1b3bda9a0ba250ae3d8135782e1679ee58f44efb2072310aa1c729968e8853422869187f9698000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0403e7a004ffffffff0100f90295000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000"; // A fabricated block of height 303335 with just coinbase

static const char block_hex[] = "020000007f39b22dc3f751fa2cb3f290a4907c9635b4f9da7e42b35b0000000000000000730a313f5a64b88781cbf55cf64f9f439ac803e1e1fdd65bd81a84fa5eaba218968e8853422869187f9698000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0403e7a004ffffffff0100f90295000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac000000000100000001982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e00000000494830450220323aa10deb4b6d07efa21f227da9cc13e019c95664b1ca17e451bbae29b71f14022100b592810a2dd95b430db0311f637122f6c780ee827a36b562e85090c684bf97d701ffffffff0100f2052a0100000017a914b010d9385e2588eb9b45bc75758226322f8ecd238700000000"; // A fabricated block of height 303335 spending block 2 coinbase

//static const char block_hex[] = "020000007f39b22dc3f751fa2cb3f290a4907c9635b4f9da7e42b35b00000000000000009bcd61c498f92f5f6b5449eceade076cd831bcfaebd9cc0477876d2d1ade99e7968e8853422869187f9698000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0403e7a004ffffffff0100f90295000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac000000000100000001982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e000000004948304502203f2fdf86708410e487a16b61b9c25df9223005949c6270cccbda243d6e62aac2022100b19920818bc005ad9ea38a9470655e3f1632e57333cfc036ba29c6a8faf8033d03ffffffff0100f2052a0100000017a914b010d9385e2588eb9b45bc75758226322f8ecd238700000000"; // A fabricated block of height 30335 creating a p2sh output
static char block_bin[sizeof(block_hex)/2];

//static const char tx_hex[]="0100000001982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e0000000048473044022068563ec5ef2fb98df73035e907a0e47190c91da6a572da8eb7167711e69165aa02200387881a82191f7f5e352c32c8bce12a96029ee6d4d0d742d69e3ab7adb259ff03ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"; // Spends 2nd block coinbase
//static const char tx_hex[]="0100000001bb627751db633f8c856069755ad4f77901b93a23236b63133400783788468bc400000000494830450221009be4aaec1c2d53546502ba3764eda342c225b7de853dfb5c0db76abfa861968a022006d72c3964aaf3c763eef2e02a25e9bc21cdf0bc780c3408cb7cb675da887a6503ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"; // Double spends coinbase in 120k

static const char tx_hex[]="010000000199437cbfff9ba34584a3ebf15069f756fdc076e2d5bbe65e279164ec62bccf0100000000fd470100483045022015ab15549da34f26fb643b4e60eebe556fd7d1da6af1a984d11ac7f8cf8c63530221008d075eb68432603c63da584e2929eee7b6321fd154aed99e118b93e01c5e693101483045022015ab15549da34f26fb643b4e60eebe556fd7d1da6af1a984d11ac7f8cf8c63530221008d075eb68432603c63da584e2929eee7b6321fd154aed99e118b93e01c5e693101483045022015ab15549da34f26fb643b4e60eebe556fd7d1da6af1a984d11ac7f8cf8c63530221008d075eb68432603c63da584e2929eee7b6321fd154aed99e118b93e01c5e6931014c69532102d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c2102d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c2102d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c53aeffffffff0100e1f5050000000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"; // Spends a txout from the previous block in fees

//static const char tx_hex[]="0100000001934e0299b5e715d96864e77161e0d143a1df1d299dec8941254f7fba4038391b00000000fd47010048304502201474e3eed9753af2b11e4ea0960e5d16a4636f130898bc7c7e65c93ec3f72d6b022100a2987d94d2865a431cd1028c34fca008c32775e91bb9b38d7b5b3fdaa5af93710148304502201474e3eed9753af2b11e4ea0960e5d16a4636f130898bc7c7e65c93ec3f72d6b022100a2987d94d2865a431cd1028c34fca008c32775e91bb9b38d7b5b3fdaa5af93710148304502201474e3eed9753af2b11e4ea0960e5d16a4636f130898bc7c7e65c93ec3f72d6b022100a2987d94d2865a431cd1028c34fca008c32775e91bb9b38d7b5b3fdaa5af9371014c69532102d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c2102d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c2102d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c53aeffffffff0100f2052a0100000017a914b010d9385e2588eb9b45bc75758226322f8ecd238700000000"; // Spends coinbase in block 2
static char tx_bin[sizeof(tx_hex)/2];

#include <signal.h>

int listener() {
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__, "unable to create socket");
		return -1;
	}

	/* setup the socket address info, client has outgoing connection to server */
	struct sockaddr_in bindAddress;
	memset(&bindAddress, 0, sizeof(bindAddress));
	bindAddress.sin_family = AF_INET;
	bindAddress.sin_addr.s_addr = INADDR_ANY;
	bindAddress.sin_port = htons(8333);

	/* bind the socket to the server port */
	int res = bind(sd, (struct sockaddr *) &bindAddress, sizeof(bindAddress));
	if (res == -1) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
		      "unable to start server: error in bind");
		return -1;
	}

	/* set as server socket that will listen for clients */
	res = listen(sd, 100);
	if (res == -1) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
		      "unable to start server: error in listen");
		return -1;
	}

	int client = accept(sd, 0, 0);
	if (client < 0) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
		      "unable to start server: error in accept");
		return -1;		
	}
	while (1) {
		static char buf[100000];
		int rc = recv(client, buf, 20000, 0);
		printf("Read %d bytes\n", rc);
		if (!rc) break;
	}
}

int injector_new(int argc, char* argv[], ShadowLogFunc slogf_) {       
	slogf = slogf_;
	assert(argc == 2);

	pthread_t thr;
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__, "creating thread");
	if (pthread_create(&thr, NULL, &listener, NULL)) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start listener thread");
		return -1;
	}
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__, "ok");

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
	sleep(2);

	/*
	{
		printf("strlen(block_hex):%d sizeof(block_hex):%d sizeof(block_bin):%d\n", strlen(block_hex), sizeof(block_hex), sizeof(block_bin));
		int len;
		len = sizeof(block_bin);
		if (!decode_hex(block_bin, sizeof(block_bin), block_hex, &len)) {
			fprintf(stderr, "Decode failed\n");
		}
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__, "decoded done");
		assert(len == sizeof(block_bin));
		bitcoindpreload_setShadowContext();
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "block", block_bin, sizeof(block_bin));
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}

	sleep(2);
	{
		int len;
		if (!decode_hex(tx_bin, sizeof(tx_bin), tx_hex, &len)) {
			fprintf(stderr, "Decode tx failed\n");
		}
		assert(len == sizeof(tx_bin));
		bitcoindpreload_setShadowContext();
		GString *msg = message_str(chain_metadata[CHAIN_BITCOIN].netmagic, "tx", tx_bin, sizeof(tx_bin));
		bitcoindpreload_setPluginContext(PLUGIN_INJECTOR);
		int rc = send(sd, msg->str, msg->len, 0);
		assert(rc == msg->len);
	}
	sleep(2);
	*/
	{
		// Read the payload file and send it
		const char *payload_path = "/home/amiller/experiment1_payload.dat";
		FILE *f = fopen(payload_path, "rb");
		assert(f);
		const int BUF = 50000;
		static char buf[BUF];
		int rc;
		while (rc = fread(buf, 1, BUF, f)) {
			printf("Sending payload: %d bytes\n", rc);
			while (rc) {
				int sent = send(sd, buf, rc, 0);
				rc -= sent;
				printf("Sent %d bytes, %d remaining\n", sent, rc);
			}
			usleep(10*1000);
		}
		printf("Sending done\n");
	}


	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sending done");

	sleep(10);
	slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
	      "sleep done");

	//close(sd);
	pthread_join(thr, NULL);
        return 0;
}


