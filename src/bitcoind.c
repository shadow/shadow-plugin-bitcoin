/*
 * See LICENSE for licensing information
 */

#include "hello.h"

#define HELLO_PORT 12345

/* all state for hello is stored here */
struct _Hello {
	/* the function we use to log messages
	 * needs level, functionname, and format */
	ShadowLogFunc slogf;

	/* the epoll descriptor to which we will add our sockets.
	 * we use this descriptor with epoll to watch events on our sockets. */
	int ed;

	/* track if our client got a response and we can exit */
	int isDone;

	struct {
		int sd;
		char* serverHostName;
		in_addr_t serverIP;
	} client;

	struct {
		int sd;
	} server;
};

/* if option is specified, run as client, else run as server */
static const char* USAGE = "USAGE: hello [hello_server_hostname]\n";

static int _hello_startClient(Hello* h, char* serverHostname) {
	h->client.serverHostName = strndup(serverHostname, (size_t)50);

	/* get the address of the server */
	struct addrinfo* serverInfo;
	int res = getaddrinfo(h->client.serverHostName, NULL, NULL, &serverInfo);
	if(res == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in getaddrinfo");
		return -1;
	}

	h->client.serverIP = ((struct sockaddr_in*)(serverInfo->ai_addr))->sin_addr.s_addr;
	freeaddrinfo(serverInfo);

	/* create the client socket and get a socket descriptor */
	h->client.sd = socket(AF_INET, (SOCK_STREAM | SOCK_NONBLOCK), 0);
	if(h->client.sd == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in socket");
		return -1;
	}

	/* our client socket address information for connecting to the server */
	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = h->client.serverIP;
	serverAddress.sin_port = htons(HELLO_PORT);

	/* connect to server. since we are non-blocking, we expect this to return EINPROGRESS */
	res = connect(h->client.sd,(struct sockaddr *)  &serverAddress, sizeof(serverAddress));
	if (res == -1 && errno != EINPROGRESS) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in connect");
		return -1;
	}

	/* specify the events to watch for on this socket.
	 * the client wants to know when it can send a hello message. */
	struct epoll_event ev;
	ev.events = EPOLLOUT;
	ev.data.fd = h->client.sd;

	/* start watching the client socket */
	res = epoll_ctl(h->ed, EPOLL_CTL_ADD, h->client.sd, &ev);
	if(res == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start client: error in epoll_ctl");
		return -1;
	}

	/* success! */
	return 0;
}

static int _hello_startServer(Hello* h) {
	/* create the socket and get a socket descriptor */
	h->server.sd = socket(AF_INET, (SOCK_STREAM | SOCK_NONBLOCK), 0);
	if (h->server.sd == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start server: error in socket");
		return -1;
	}

	/* setup the socket address info, client has outgoing connection to server */
	struct sockaddr_in bindAddress;
	memset(&bindAddress, 0, sizeof(bindAddress));
	bindAddress.sin_family = AF_INET;
	bindAddress.sin_addr.s_addr = INADDR_ANY;
	bindAddress.sin_port = htons(HELLO_PORT);

	/* bind the socket to the server port */
	int res = bind(h->server.sd, (struct sockaddr *) &bindAddress, sizeof(bindAddress));
	if (res == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start server: error in bind");
		return -1;
	}

	/* set as server socket that will listen for clients */
	res = listen(h->server.sd, 100);
	if (res == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start server: error in listen");
		return -1;
	}

	/* specify the events to watch for on this socket.
	 * the server wants to know when a client is connecting. */
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = h->server.sd;

	/* start watching the server socket */
	res = epoll_ctl(h->ed, EPOLL_CTL_ADD, h->server.sd, &ev);
	if(res == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"unable to start server: error in epoll_ctl");
		return -1;
	}

	/* success! */
	return 0;
}

Hello* hello_new(int argc, char* argv[], ShadowLogFunc slogf) {
	assert(slogf);

	if(argc < 1 || argc > 2) {
		slogf(SHADOW_LOG_LEVEL_WARNING, __FUNCTION__, USAGE);
		return NULL;
	}

	/* use epoll to asynchronously watch events for all of our sockets */
	int mainEpollDescriptor = epoll_create(1);
	if(mainEpollDescriptor == -1) {
		slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"Error in main epoll_create");
		close(mainEpollDescriptor);
		return NULL;
	}

	/* get memory for the new state */
	Hello* h = calloc(1, sizeof(Hello));
	assert(h);

	h->ed = mainEpollDescriptor;
	h->slogf = slogf;
	h->isDone = 0;

	/* extract the server hostname from argv if in client mode */
	int isFail = 0;
	if(argc == 2) {
		/* client mode */
		isFail = _hello_startClient(h, argv[1]);
	} else {
		/* server mode */
		isFail = _hello_startServer(h);
	}

	if(isFail) {
		hello_free(h);
		return NULL;
	} else {
		return h;
	}
}

void hello_free(Hello* h) {
	assert(h);

	if(h->client.sd)
		close(h->client.sd);
	if(h->client.serverHostName)
		free(h->client.serverHostName);
	if(h->ed)
		close(h->ed);

	free(h);
}

static void _hello_activateClient(Hello* h, int sd, uint32_t events) {
	ssize_t numBytes = 0;
	char message[10];
	assert(h->client.sd == sd);

	if(events & EPOLLOUT) {
		h->slogf(SHADOW_LOG_LEVEL_DEBUG, __FUNCTION__, "EPOLLOUT is set");
	}
	if(events & EPOLLIN) {
		h->slogf(SHADOW_LOG_LEVEL_DEBUG, __FUNCTION__, "EPOLLIN is set");
	}

	/* to keep things simple, there is explicitly no resilience here.
	 * we allow only one chance to send the message and one to receive the response.
	 */

	if(events & EPOLLOUT) {
		/* the kernel can accept data from us,
		 * and we care because we registered EPOLLOUT on sd with epoll */

		/* prepare the message */
		memset(message, 0, (size_t)10);
		snprintf(message, 10, "%s", "Hello?");

		/* send the message */
		numBytes = send(sd, message, (size_t)6, 0);

		/* log result */
		if(numBytes == 6) {
			h->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__,
					"successfully sent '%s' message", message);
		} else {
			h->slogf(SHADOW_LOG_LEVEL_WARNING, __FUNCTION__,
					"unable to send message");
		}

		/* tell epoll we don't care about writing anymore */
		struct epoll_event ev;
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = sd;
		epoll_ctl(h->ed, EPOLL_CTL_MOD, sd, &ev);
	} else if(events & EPOLLIN) {
		/* there is data available to read from the kernel,
		 * and we care because we registered EPOLLIN on sd with epoll */

		/* prepare to accept the message */
		memset(message, 0, (size_t)10);

		numBytes = recv(sd, message, (size_t)6, 0);

		/* log result */
		if(numBytes > 0) {
			h->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__,
					"successfully received '%s' message", message);
		} else {
			h->slogf(SHADOW_LOG_LEVEL_WARNING, __FUNCTION__,
					"unable to receive message");
		}

		/* tell epoll we no longer want to watch this socket */
		epoll_ctl(h->ed, EPOLL_CTL_DEL, sd, NULL);

		close(sd);
		h->client.sd = 0;
		h->isDone = 1;
	}
}

static void _hello_activateServer(Hello* h, int sd, uint32_t events) {
	ssize_t numBytes = 0;
	char message[10];
	struct epoll_event ev;

	if(events & EPOLLOUT) {
		h->slogf(SHADOW_LOG_LEVEL_DEBUG, __FUNCTION__, "EPOLLOUT is set");
	}
	if(events & EPOLLIN) {
		h->slogf(SHADOW_LOG_LEVEL_DEBUG, __FUNCTION__, "EPOLLIN is set");
	}

	if(sd == h->server.sd) {
		/* data on a listening socket means a new client connection */
		assert(events & EPOLLIN);

		/* accept new connection from a remote client */
		int newClientSD = accept(sd, NULL, NULL);

		/* now register this new socket so we know when its ready */
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = newClientSD;
		epoll_ctl(h->ed, EPOLL_CTL_ADD, newClientSD, &ev);
	} else {
		/* a client is communicating with us over an existing connection */
		if(events & EPOLLIN) {
			/* prepare to accept the message */
			memset(message, 0, (size_t)10);

			numBytes = recv(sd, message, (size_t)6, 0);

			/* log result */
			if(numBytes > 0) {
				h->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__,
						"successfully received '%s' message", message);
			} else if(numBytes == 0){
				/* client got response and closed */
				/* tell epoll we no longer want to watch this socket */
				epoll_ctl(h->ed, EPOLL_CTL_DEL, sd, NULL);
				close(sd);
			} else {
				h->slogf(SHADOW_LOG_LEVEL_WARNING, __FUNCTION__,
						"unable to receive message");
			}

			/* tell epoll we want to write the response now */
			memset(&ev, 0, sizeof(struct epoll_event));
			ev.events = EPOLLOUT;
			ev.data.fd = sd;
			epoll_ctl(h->ed, EPOLL_CTL_MOD, sd, &ev);
		} else if(events & EPOLLOUT) {
			/* prepare the response message */
			memset(message, 0, (size_t)10);
			snprintf(message, 10, "%s", "World!");

			/* send the message */
			numBytes = send(sd, message, (size_t)6, 0);

			/* log result */
			if(numBytes == 6) {
				h->slogf(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__,
						"successfully sent '%s' message", message);
			} else {
				h->slogf(SHADOW_LOG_LEVEL_WARNING, __FUNCTION__,
						"unable to send message");
			}

			/* now wait until we read 0 for client close event */
			memset(&ev, 0, sizeof(struct epoll_event));
			ev.events = EPOLLIN;
			ev.data.fd = sd;
			epoll_ctl(h->ed, EPOLL_CTL_MOD, sd, &ev);
		}
	}
}

void hello_ready(Hello* h) {
	assert(h);

	/* collect the events that are ready */
	struct epoll_event epevs[10];
	int nfds = epoll_wait(h->ed, epevs, 10, 0);
	if(nfds == -1) {
		h->slogf(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__,
				"error in epoll_wait");
		return;
	}

	/* activate correct component for every socket thats ready */
	for(int i = 0; i < nfds; i++) {
		int d = epevs[i].data.fd;
		uint32_t e = epevs[i].events;
		if(d == h->client.sd) {
			_hello_activateClient(h, d, e);
		} else {
			_hello_activateServer(h, d, e);
		}
	}
}

int hello_getEpollDescriptor(Hello* h) {
	assert(h);
	return h->ed;
}

int hello_isDone(Hello* h) {
	assert(h);
	return h->isDone;
}
