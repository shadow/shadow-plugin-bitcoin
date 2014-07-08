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

void *doNothing(void*) { 
	fprintf(stderr, "_start_bitcoind:about to read\n");
	char buf[10] = "hiya!\n";
	write(2, buf, 6);
	return NULL;
}

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

extern "C" {
pthread_key_t current_thread_tls_key;
boost::once_flag current_thread_tls_init_flag = BOOST_ONCE_INIT;

pthread_key_t epoch_tss_key;
pthread_once_t epoch_tss_key_flag = PTHREAD_ONCE_INIT;

boost::uintmax_t _once_global_epoch=UINTMAX_C(~0);
pthread_mutex_t _once_epoch_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t _once_epoch_cv = PTHREAD_COND_INITIALIZER;
}

extern "C"
void init_tls() {
  current_thread_tls_init_flag.epoch = 0;
  epoch_tss_key_flag = 0;
  {
    pthread_mutex_t dummy = PTHREAD_MUTEX_INITIALIZER;
    memcpy(&_once_epoch_mutex, &dummy, sizeof(dummy));
  }
  _once_global_epoch = UINTMAX_C(~0);
  {
    pthread_cond_t dummy = PTHREAD_COND_INITIALIZER;
    memcpy(&_once_epoch_cv, &dummy, sizeof(dummy));
  }
}

/*
namespace preload {
    pthread_key_t &_boosthack_current_thread_tls_key() {
      return current_thread_tls_key;
    }
    boost::once_flag &_boosthack_current_thread_tls_init_flag(void) {
      return current_thread_tls_init_flag;
    }
    pthread_key_t &_boosthack_epoch_tss_key() {
      return epoch_tss_key;
    }
    pthread_once_t &_boosthack_epoch_tss_key_flag() {
      return epoch_tss_key_flag;
    }
    BOOST_THREAD_DECL boost::uintmax_t &_boosthack_once_global_epoch() {
      return _once_global_epoch;
    }
    BOOST_THREAD_DECL pthread_mutex_t &_boosthack_once_epoch_mutex() { 
      return _once_epoch_mutex;
    }
    BOOST_THREAD_DECL pthread_cond_t &_boosthack_once_epoch_cv() { 
      return _once_epoch_cv;
    }
}
*/
namespace boost {
  namespace detail {
    pthread_key_t &_boosthack_current_thread_tls_key() {
      return current_thread_tls_key;
    }
    boost::once_flag &_boosthack_current_thread_tls_init_flag(void) {
      return current_thread_tls_init_flag;
    }
    pthread_key_t &_boosthack_epoch_tss_key() {
      return epoch_tss_key;
    }
    pthread_once_t &_boosthack_epoch_tss_key_flag() {
      return epoch_tss_key_flag;
    }
    BOOST_THREAD_DECL boost::uintmax_t &_boosthack_once_global_epoch() {
      return _once_global_epoch;
    }
    BOOST_THREAD_DECL pthread_mutex_t &_boosthack_once_epoch_mutex() { 
      return _once_epoch_mutex;
    }
    BOOST_THREAD_DECL pthread_cond_t &_boosthack_once_epoch_cv() { 
      return _once_epoch_cv;
    }
  }
}
