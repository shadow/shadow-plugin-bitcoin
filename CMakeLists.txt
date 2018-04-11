project(shadow-plugin-bitcoin)

## ensure cmake version
cmake_minimum_required(VERSION 2.8.8 FATAL_ERROR)

## ensure unix environment (CMAKE_SYSTEM_NAME == "Linux")
if((NOT UNIX) OR (NOT ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")))
    message(FATAL_ERROR "Unix/Linux environment is required.")
endif()

## ensure out-of-source build
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "An out-of-source build is required. Please see the README.")
endif()

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

get_filename_component(BITCOIN_ROOT_DIR "${CMAKE_SOURCE_DIR}/build/bitcoin" ABSOLUTE)

## we need to know where shadow is installed
if("${SHADOW_ROOT}" STREQUAL "")
    set(SHADOW_ROOT "$ENV{HOME}/.shadow")
endif()
if(EXISTS "${SHADOW_ROOT}")
    message(STATUS "SHADOW_ROOT = ${SHADOW_ROOT}")
else()
    message(FATAL_ERROR "SHADOW_ROOT path does not exist: '${SHADOW_ROOT}'")
endif()

## by default, install to SHADOW_ROOT
if(NOT ${CMAKE_INSTALL_PREFIX})
    set(CMAKE_INSTALL_PREFIX "${SHADOW_ROOT}")
endif()

if(EXISTS "${SHADOW_ROOT}/share/cmake/Modules")
    set(CMAKE_MODULE_PATH "${SHADOW_ROOT}/share/cmake/Modules" ${CMAKE_MODULE_PATH})
endif()

include(ShadowTools)

message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")
message(STATUS "CMAKE_BINARY_DIR = ${CMAKE_BINARY_DIR}")
message(STATUS "BITCOIN_ROOT_DIR = ${BITCOIN_ROOT_DIR}")

find_package(RT REQUIRED)
find_package(DL REQUIRED)
find_package(GLIB REQUIRED)
find_package(OpenSSL REQUIRED ssl crypto)
find_package(Boost REQUIRED system filesystem program_options thread chrono)

message(STATUS "OpenSSL = ${OPENSSL_LIBRARIES}")
message(STATUS "boost = ${Boost_LIBRARIES}")
message(STATUS "boost = ${Boost_SYSTEM_LIBRARIES}")

include_directories(${BITCOIN_ROOT_DIR}/src)
include_directories(${BITCOIN_ROOT_DIR}/src/univalue/include)
include_directories(${BITCOIN_ROOT_DIR}/src/config)
include_directories(${Boost_INCLUDE_DIRS})

set(LIBBITCOIN_SERVER_SRCS
  ${BITCOIN_ROOT_DIR}/src/addrdb.cpp 
  ${BITCOIN_ROOT_DIR}/src/addrman.cpp 
  ${BITCOIN_ROOT_DIR}/src/consensus/tx_verify.cpp
  ${BITCOIN_ROOT_DIR}/src/bloom.cpp
  ${BITCOIN_ROOT_DIR}/src/blockencodings.cpp
  ${BITCOIN_ROOT_DIR}/src/chain.cpp
  ${BITCOIN_ROOT_DIR}/src/checkpoints.cpp
  ${BITCOIN_ROOT_DIR}/src/httprpc.cpp
  ${BITCOIN_ROOT_DIR}/src/httpserver.cpp
  ${BITCOIN_ROOT_DIR}/src/init.cpp
  ${BITCOIN_ROOT_DIR}/src/dbwrapper.cpp
  ${BITCOIN_ROOT_DIR}/src/merkleblock.cpp
  ${BITCOIN_ROOT_DIR}/src/miner.cpp
  ${BITCOIN_ROOT_DIR}/src/net.cpp
  ${BITCOIN_ROOT_DIR}/src/net_processing.cpp
  ${BITCOIN_ROOT_DIR}/src/noui.cpp
  ${BITCOIN_ROOT_DIR}/src/pow.cpp
  ${BITCOIN_ROOT_DIR}/src/rest.cpp
  ${BITCOIN_ROOT_DIR}/src/policy/fees.cpp
  ${BITCOIN_ROOT_DIR}/src/policy/policy.cpp
  ${BITCOIN_ROOT_DIR}/src/policy/rbf.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/blockchain.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/mining.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/misc.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/net.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/rawtransaction.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/safemode.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/server.cpp
  ${BITCOIN_ROOT_DIR}/src/script/sigcache.cpp
  ${BITCOIN_ROOT_DIR}/src/script/ismine.cpp
  ${BITCOIN_ROOT_DIR}/src/timedata.cpp
  ${BITCOIN_ROOT_DIR}/src/torcontrol.cpp
  ${BITCOIN_ROOT_DIR}/src/txdb.cpp
  ${BITCOIN_ROOT_DIR}/src/txmempool.cpp
  ${BITCOIN_ROOT_DIR}/src/ui_interface.cpp
  ${BITCOIN_ROOT_DIR}/src/validation.cpp
  ${BITCOIN_ROOT_DIR}/src/validationinterface.cpp
  ${BITCOIN_ROOT_DIR}/src/versionbits.cpp)


SET(LIBBITCOIN_COMMON_SRCS 
  ${BITCOIN_ROOT_DIR}/src/base58.cpp
  ${BITCOIN_ROOT_DIR}/src/bech32.cpp
  ${BITCOIN_ROOT_DIR}/src/chainparams.cpp
  ${BITCOIN_ROOT_DIR}/src/coins.cpp
  ${BITCOIN_ROOT_DIR}/src/compressor.cpp
  ${BITCOIN_ROOT_DIR}/src/core_read.cpp
  ${BITCOIN_ROOT_DIR}/src/core_write.cpp
  ${BITCOIN_ROOT_DIR}/src/key.cpp
  ${BITCOIN_ROOT_DIR}/src/keystore.cpp
  ${BITCOIN_ROOT_DIR}/src/netaddress.cpp
  ${BITCOIN_ROOT_DIR}/src/netbase.cpp
  ${BITCOIN_ROOT_DIR}/src/policy/feerate.cpp
  ${BITCOIN_ROOT_DIR}/src/protocol.cpp
  ${BITCOIN_ROOT_DIR}/src/scheduler.cpp
  ${BITCOIN_ROOT_DIR}/src/script/sign.cpp
  ${BITCOIN_ROOT_DIR}/src/script/standard.cpp
  ${BITCOIN_ROOT_DIR}/src/warnings.cpp)

SET(LIBBITCOIN_UTIL_SRCS
  ${BITCOIN_ROOT_DIR}/src/support/lockedpool.cpp
  ${BITCOIN_ROOT_DIR}/src/chainparamsbase.cpp
  ${BITCOIN_ROOT_DIR}/src/clientversion.cpp
  ${BITCOIN_ROOT_DIR}/src/compat/glibc_sanity.cpp
  ${BITCOIN_ROOT_DIR}/src/compat/glibcxx_sanity.cpp
  ${BITCOIN_ROOT_DIR}/src/compat/strnlen.cpp
  ${BITCOIN_ROOT_DIR}/src/fs.cpp
  ${BITCOIN_ROOT_DIR}/src/random.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/protocol.cpp
  ${BITCOIN_ROOT_DIR}/src/rpc/util.cpp
  ${BITCOIN_ROOT_DIR}/src/support/cleanse.cpp
  ${BITCOIN_ROOT_DIR}/src/sync.cpp
  ${BITCOIN_ROOT_DIR}/src/threadinterrupt.cpp
  ${BITCOIN_ROOT_DIR}/src/util.cpp
  ${BITCOIN_ROOT_DIR}/src/utilmoneystr.cpp
  ${BITCOIN_ROOT_DIR}/src/utilstrencodings.cpp
  ${BITCOIN_ROOT_DIR}/src/utiltime.cpp)

SET(LIBBITCOIN_CONSENSUS_SRCS
  ${BITCOIN_ROOT_DIR}/src/arith_uint256.cpp
  ${BITCOIN_ROOT_DIR}/src/consensus/merkle.cpp
  ${BITCOIN_ROOT_DIR}/src/hash.cpp
  ${BITCOIN_ROOT_DIR}/src/primitives/block.cpp
  ${BITCOIN_ROOT_DIR}/src/primitives/transaction.cpp
  ${BITCOIN_ROOT_DIR}/src/pubkey.cpp
  ${BITCOIN_ROOT_DIR}/src/script/bitcoinconsensus.cpp
  ${BITCOIN_ROOT_DIR}/src/script/interpreter.cpp
  ${BITCOIN_ROOT_DIR}/src/script/script.cpp
  ${BITCOIN_ROOT_DIR}/src/script/script_error.cpp
  ${BITCOIN_ROOT_DIR}/src/uint256.cpp
  ${BITCOIN_ROOT_DIR}/src/utilstrencodings.cpp)

SET(LIBBITCOIN_CRYPTO_SRCS
  ${BITCOIN_ROOT_DIR}/src/crypto/aes.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/chacha20.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/hmac_sha256.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/hmac_sha512.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/ripemd160.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/sha1.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/sha256.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/sha512.cpp
  ${BITCOIN_ROOT_DIR}/src/crypto/sha256_sse4.cpp)

SET(LIBLEVELDB_INT_SRCS
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/builder.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/c.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/dbformat.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/db_impl.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/db_iter.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/dumpfile.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/filename.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/log_reader.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/log_writer.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/memtable.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/repair.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/table_cache.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/version_edit.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/version_set.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/db/write_batch.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/block_builder.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/block.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/filter_block.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/format.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/iterator.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/merger.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/table_builder.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/table.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/table/two_level_iterator.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/arena.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/bloom.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/cache.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/coding.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/comparator.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/crc32c.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/env.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/env_posix.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/filter_policy.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/hash.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/histogram.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/logging.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/options.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/util/status.cc
  ${BITCOIN_ROOT_DIR}/src/leveldb/port/port_posix.cc
)
 
SET(LIBLEVELDB_SSE42_SRCS
  ${BITCOIN_ROOT_DIR}/src/leveldb/port/port_posix_sse.cc)

SET(LIBMEMENV_SRCS
  ${BITCOIN_ROOT_DIR}/src/leveldb/helpers/memenv/memenv.cc)

add_library(LIBBITCOIN_SERVER STATIC ${LIBBITCOIN_SERVER_SRCS})
add_library(LIBBITCOIN_COMMON STATIC ${LIBBITCOIN_COMMON_SRCS})
add_library(LIBUNIVALUE STATIC         
  ${BITCOIN_ROOT_DIR}/src/univalue/lib/univalue.cpp
  ${BITCOIN_ROOT_DIR}/src/univalue/lib/univalue_get.cpp
  ${BITCOIN_ROOT_DIR}/src/univalue/lib/univalue_read.cpp
  ${BITCOIN_ROOT_DIR}/src/univalue/lib/univalue_write.cpp)
add_library(LIBBITCOIN_UTIL STATIC ${LIBBITCOIN_UTIL_SRCS})
add_library(LIBBITCOIN_CONSENSUS STATIC ${LIBBITCOIN_CONSENSUS_SRCS})
add_library(LIBBITCOIN_CRYPTO STATIC ${LIBBITCOIN_CRYPTO_SRCS})
add_library(LIBLEVELDB_INT STATIC ${LIBLEVELDB_INT_SRCS})
add_library(LIBLEVELDB_SSE42 STATIC ${LIBLEVELDB_SSE42_SRCS})
add_library(LIBMEMENV STATIC ${LIBMEMENV_SRCS})
add_library(LIBSECP256K1 ${BITCOIN_ROOT_DIR}/src/secp256k1/src/secp256k1.c)



SET(GCC_DEFS "-DHAVE_CONFIG_H")
SET(AM_CPPFLAGS "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")
SET(BOOST_CPPFLAGS "-DBOOST_SP_USE_STD_ATOMIC -DBOOST_AC_USE_STD_ATOMIC -pthread -I/usr/include -DBOOST_NO_SCOPED_ENUMS -DBOOST_NO_CXX11_SCOPED_ENUMS")
SET(LEVELDB_CPPFLAGS "-I${BITCOIN_ROOT_DIR}/src/leveldb/include -I${BITCOIN_ROOT_DIR}/src/leveldb/helpers/memenv")
SET(UNIVALUE_CFLAGS "-I${BITCOIN_ROOT_DIR}/src/univalue/include")
SET(BITCOIN_INCLUDES "${BOOST_CPPFLAGS} ${LEVELDB_CPPFLAGS} -I${BITCOIN_ROOT_DIR}/src/secp256k1/include ${UNIVALUE_CFLAGS}")
SET(EVENT_PTHREADS_CFLAGS "-pthread")
SET(CPPFLAGS "-DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS")
SET(AM_CXXFLAGS "-Wstack-protector -fstack-protector-all")
SET(PIE_FLAGS "-fPIE")
# SET(CXXFLAGS "-g -O2 -Wall -Wextra -Wformat -Wvla -Wformat-security -Wno-unused-parameter")
SET(CXXFLAGS "-g -Wall -Wextra -Wformat -Wvla -Wformat-security -Wno-unused-parameter")
SET(LIBBITCOIN_SERVER_CPPFLAGS "${GCC_DEFS} ${AM_CPPFLAGS} ${BITCOIN_INCLUDES} ${EVENT_PTHREADS_CFLAGS} ${CPPFLAGS} ${AM_CXXFLAGS} ${PIE_FLAGS} ${CXXFLAGS}")

SET(LEVELDB_CPPFLAGS_INT "-I${BITCOIN_ROOT_DIR}/src/leveldb -DOS_LINUX -DLEVELDB_ATOMIC_PRESENT -D__STDC_LIMIT_MACROS -DLEVELDB_PLATFORM_POSIX")
SET(LIBSECP256K1_INC "-I${BITCOIN_ROOT_DIR}/src/secp256k1/ -I${BITCOIN_ROOT_DIR}/src/secp256k1/src -I${BITCOIN_ROOT_DIR}/src/secp256k1/include")
SET(LIBSECP256K1_CFLAGS "-g -O2 -W -std=c89 -pedantic -Wall -Wextra -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings -fvisibility=hidden -O3")


set_target_properties(LIBBITCOIN_SERVER PROPERTIES COMPILE_FLAGS ${LIBBITCOIN_SERVER_CPPFLAGS})
set_target_properties(LIBBITCOIN_COMMON PROPERTIES COMPILE_FLAGS ${LIBBITCOIN_SERVER_CPPFLAGS})
set_target_properties(LIBUNIVALUE PROPERTIES COMPILE_FLAGS "-DHAVE_CONFIG_H -I${BITCOIN_ROOT_DIR}/src/univalue -I${BITCOIN_ROOT_DIR}/src/univalue/include -g -O2 -fPIC -DPIC")
set_target_properties(LIBBITCOIN_UTIL PROPERTIES COMPILE_FLAGS ${LIBBITCOIN_SERVER_CPPFLAGS})
set_target_properties(LIBBITCOIN_CONSENSUS PROPERTIES COMPILE_FLAGS ${LIBBITCOIN_SERVER_CPPFLAGS})
set_target_properties(LIBBITCOIN_CRYPTO PROPERTIES COMPILE_FLAGS "${GCC_DEFS} ${AM_CPPFLAGS} ${CPPFLAGS} ${AM_CXXFLAGS} ${PIE_FLAGS} ${CXXFLAGS}")
set_target_properties(LIBLEVELDB_INT PROPERTIES COMPILE_FLAGS "${GCC_DEFS} ${CPPFLAGS} ${CXXFLAGS} ${AM_CPPFLAGS} ${LEVELDB_CPPFLAGS_INT} ${LEVELDB_CPPFLAGS} ${AM_CXXFLAGS} ${PIE_FLAGS}")
set_target_properties(LIBLEVELDB_SSE42 PROPERTIES COMPILE_FLAGS "${GCC_DEFS} ${CPPFLAGS} ${CXXFLAGS} ${AM_CPPFLAGS} ${LEVELDB_CPPFLAGS_INT} ${LEVELDB_CPPFLAGS} ${AM_CXXFLAGS} ${PIE_FLAGS}")
set_target_properties(LIBMEMENV PROPERTIES COMPILE_FLAGS "${GCC_DEFS} ${CPPFLAGS} ${CXXFLAGS} ${AM_CPPFLAGS} ${LEVELDB_CPPFLAGS_INT} ${LEVELDB_CPPFLAGS} ${AM_CXXFLAGS} ${PIE_FLAGS}")
set_target_properties(LIBSECP256K1 PROPERTIES COMPILE_FLAGS "${GCC_DEFS} ${LIBSECP256K1_INC} ${LIBSECP256K1_CFLAGS} -DSECP256K1_BUILD -fPIC -DPIC")

SET(BITCOIN_LDFLAGS "-pthread -Wl,-z,relro -Wl,-z,now -pie")

# add_executable(BITCOIND ${BITCOIN_ROOT_DIR}/src/bitcoind.cpp)
add_shadow_plugin(BITCOIND ${BITCOIN_ROOT_DIR}/src/bitcoind.cpp)
install(TARGETS BITCOIND DESTINATION plugins)

set_target_properties(BITCOIND PROPERTIES COMPILE_FLAGS "${GCC_DEFS} ${CPPFLAGS} ${CXXFLAGS} ${AM_CPPFLAGS} ${BITCOIN_INCLUDES} ${AM_CXXFLAGS} ${PIE_FLAGS}")

# set(OPENSSL_LIBRARIES "/home/csrc/.shadow/lib/libssl.so;/home/csrc/.shadow/lib/libcrypto.so")
link_directories(${SHADOW_ROOT}/lib/)
target_link_libraries(BITCOIND ${AM_CXXFLAGS} ${PIE_FLAGS} ${CXXFLAGS} ${BITCOIN_LDFLAGS})
target_link_libraries(BITCOIND LIBBITCOIN_SERVER LIBBITCOIN_COMMON LIBUNIVALUE LIBBITCOIN_UTIL LIBBITCOIN_CONSENSUS LIBBITCOIN_CRYPTO)
target_link_libraries(BITCOIND ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
target_link_libraries(BITCOIND LIBSECP256K1 LIBLEVELDB_INT LIBLEVELDB_SSE42 LIBMEMENV)
target_link_libraries(BITCOIND -levent_pthreads -levent)






