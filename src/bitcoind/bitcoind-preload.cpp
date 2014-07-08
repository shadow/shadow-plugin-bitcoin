#include <string>
#include <pthread.h>
#include <boost/thread/once.hpp>
#include <cstring>

extern "C" int CLogPrintStr(const char *);

int LogPrintStr(const std::string &str) { 
  return CLogPrintStr(str.c_str());
}

/*
namespace preload {
  extern pthread_key_t &_boosthack_current_thread_tls_key();
  extern boost::once_flag &_boosthack_current_thread_tls_init_flag(void);
  extern pthread_key_t &_boosthack_epoch_tss_key();
  extern pthread_once_t &_boosthack_epoch_tss_key_flag();
  extern BOOST_THREAD_DECL boost::uintmax_t &_boosthack_once_global_epoch();
  extern BOOST_THREAD_DECL pthread_mutex_t &_boosthack_once_epoch_mutex();
  extern BOOST_THREAD_DECL pthread_cond_t &_boosthack_once_epoch_cv();
}


namespace boost {
  namespace detail {
    pthread_key_t &_boosthack_current_thread_tls_key() {
      return preload::_boosthack_current_thread_tls_key();
    }
    boost::once_flag &_boosthack_current_thread_tls_init_flag() {
      return preload::_boosthack_current_thread_tls_init_flag();
    }
    pthread_key_t &_boosthack_epoch_tss_key() {
      return preload::_boosthack_epoch_tss_key();
    }
    pthread_once_t &_boosthack_epoch_tss_key_flag() {
      return preload::_boosthack_epoch_tss_key_flag();
    }
    BOOST_THREAD_DECL boost::uintmax_t &_boosthack_once_global_epoch() {
      return preload::_boosthack_once_global_epoch();
    }
    BOOST_THREAD_DECL pthread_mutex_t &_boosthack_once_epoch_mutex() { 
      return preload::_boosthack_once_epoch_mutex();
    }
    BOOST_THREAD_DECL pthread_cond_t &_boosthack_once_epoch_cv() { 
      return preload::_boosthack_once_epoch_cv();
    }
  }
}

*/
