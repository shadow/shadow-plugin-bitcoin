#===================================================================
# Bitcoin source location
#===================================================================

#get_filename_component(BITCOIN_ROOT_DIR "${CMAKE_BINARY_DIR}/../bitcoin/src" ABSOLUTE)
set(BITCOIN_ROOT_DIR ${CMAKE_BINARY_DIR}/bitcoin)

#===================================================================
# Check Bitcoin Dependencies
#===================================================================

#find_package(GLIB REQUIRED)
#include_directories(${GLIB_INCLUDES})

# threads - set options BEFORE find_package()
set(CMAKE_THREAD_PREFER_PTHREAD ON)  
find_package(Threads REQUIRED)
if(NOT Threads_FOUND)
    message(FATAL_ERROR "Could not locate Threads.")
endif()
message(STATUS "CMAKE_USE_PTHREADS_INIT = ${CMAKE_USE_PTHREADS_INIT}")
message(STATUS "CMAKE_THREAD_LIBS_INIT = ${CMAKE_THREAD_LIBS_INIT}")

# boost - set options BEFORE find_package()
set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.45.0 REQUIRED COMPONENTS system filesystem thread program_options)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Could not locate Boost.")
endif()
message(STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES = ${Boost_LIBRARIES}")

# openssl
find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "Could not locate OpenSSL.")
endif()
message(STATUS "OPENSSL_VERSION = ${OPENSSL_VERSION}")
message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_LIBRARIES = ${OPENSSL_LIBRARIES}")

#===================================================================
# package files
#===================================================================

# bitcoin first
#aux_source_directory(${BITCOIN_ROOT_DIR}/src bitcoin_sources)
#list(REMOVE_ITEM bitcoin_sources
#    ${BITCOIN_ROOT_DIR}/src/db.cpp
#    ${BITCOIN_ROOT_DIR}/src/bitcoind.cpp
#    ${BITCOIN_ROOT_DIR}/src/bitcoin-cli.cpp
#    ${BITCOIN_ROOT_DIR}/src/bitcoind.cpp
#)

set(bitcoin_sources
    ${BITCOIN_ROOT_DIR}/src/addrman.cpp
    ${BITCOIN_ROOT_DIR}/src/alert.cpp  
    ${BITCOIN_ROOT_DIR}/src/bloom.cpp  
    ${BITCOIN_ROOT_DIR}/src/checkpoints.cpp
    ${BITCOIN_ROOT_DIR}/src/coins.cpp  
    ${BITCOIN_ROOT_DIR}/src/init.cpp   
    ${BITCOIN_ROOT_DIR}/src/keystore.cpp
    ${BITCOIN_ROOT_DIR}/src/leveldbwrapper.cpp
    ${BITCOIN_ROOT_DIR}/src/main.cpp   
    ${BITCOIN_ROOT_DIR}/src/miner.cpp  
    ${BITCOIN_ROOT_DIR}/src/net.cpp
    ${BITCOIN_ROOT_DIR}/src/noui.cpp   
    ${BITCOIN_ROOT_DIR}/src/rpcblockchain.cpp
    ${BITCOIN_ROOT_DIR}/src/rpcmining.cpp
    ${BITCOIN_ROOT_DIR}/src/rpcmisc.cpp
    ${BITCOIN_ROOT_DIR}/src/rpcnet.cpp 
    ${BITCOIN_ROOT_DIR}/src/rpcrawtransaction.cpp
    ${BITCOIN_ROOT_DIR}/src/rpcserver.cpp
    ${BITCOIN_ROOT_DIR}/src/txdb.cpp   
    ${BITCOIN_ROOT_DIR}/src/txmempool.cpp
    ${BITCOIN_ROOT_DIR}/src/base58.cpp 
    ${BITCOIN_ROOT_DIR}/src/allocators.cpp
    ${BITCOIN_ROOT_DIR}/src/chainparams.cpp
    ${BITCOIN_ROOT_DIR}/src/core.cpp   
    ${BITCOIN_ROOT_DIR}/src/hash.cpp   
    ${BITCOIN_ROOT_DIR}/src/key.cpp
    ${BITCOIN_ROOT_DIR}/src/netbase.cpp
    ${BITCOIN_ROOT_DIR}/src/protocol.cpp
    ${BITCOIN_ROOT_DIR}/src/rpcprotocol.cpp
    ${BITCOIN_ROOT_DIR}/src/script.cpp 
    ${BITCOIN_ROOT_DIR}/src/sync.cpp   
    ${BITCOIN_ROOT_DIR}/src/util.cpp   
    ${BITCOIN_ROOT_DIR}/src/version.cpp
    ${BITCOIN_ROOT_DIR}/src/rpcclient.cpp
)

#FILE(GLOB bitcoin_headers ${BITCOIN_ROOT_DIR}/src/*.h)

# now leveldb
aux_source_directory(${BITCOIN_ROOT_DIR}/src/leveldb/db leveldb_db_sources)
aux_source_directory(${BITCOIN_ROOT_DIR}/src/leveldb/util leveldb_util_sources)
aux_source_directory(${BITCOIN_ROOT_DIR}/src/leveldb/table leveldb_table_sources)
aux_source_directory(${BITCOIN_ROOT_DIR}/src/leveldb/port leveldb_port_sources)
aux_source_directory(${BITCOIN_ROOT_DIR}/src/leveldb/helpers/memenv leveldb_memenv_sources)
set(leveldb_all_sources
    ${leveldb_db_sources}
    ${leveldb_util_sources}
    ${leveldb_table_sources}
    ${leveldb_port_sources}
    ${leveldb_memenv_sources}
)

# do not include test files
set(leveldb_sources)
foreach(file ${leveldb_all_sources})
    if(NOT ${file} MATCHES "(.*)_test.c(.*)")
        set(leveldb_sources ${leveldb_sources} ${file})
        #message(STATUS "source ${file}")
    endif()
endforeach()

list(REMOVE_ITEM leveldb_sources
    ${BITCOIN_ROOT_DIR}/src/leveldb/db/db_bench.cc
    ${BITCOIN_ROOT_DIR}/src/leveldb/db/leveldb_main.cc
    ${BITCOIN_ROOT_DIR}/src/leveldb/port/port_win.cc
    ${BITCOIN_ROOT_DIR}/src/leveldb/util/testharness.cc
    ${BITCOIN_ROOT_DIR}/src/leveldb/util/testutil.cc
)
#===================================================================
# tweaks
#===================================================================

add_definitions( "-DHAS_BOOST -DHAVE_WORKING_BOOST_SLEEP" )

# Generate bitcoin-config.h substituting config vars for include:
#configure_file(${CONTRIB_CURRENT_SOURCE_DIR}/bitcoin-config.h.cmake
#               ${CMAKE_CURRENT_BINARY_DIR}/bitcoin-config.h @ONLY)
add_definitions( "-DHAVE_CONFIG_H" )

# needed so we include the correct port header for posix
add_definitions( "-DLEVELDB_PLATFORM_POSIX" )

#===================================================================
# includes
#===================================================================

include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${BITCOIN_ROOT_DIR}/src
    ${BITCOIN_ROOT_DIR}/src/leveldb
    ${BITCOIN_ROOT_DIR}/src/leveldb/include
    ${BITCOIN_ROOT_DIR}/src/leveldb/helpers
    ${BITCOIN_ROOT_DIR}/src/leveldb/helpers/memenv
)
include_directories(AFTER ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

#===================================================================
# build bitcode and plugins!
#===================================================================

add_bitcode(shadow-bitcoin-bitcode ${bitcoin_sources})
add_bitcode(shadow-leveldb-bitcode ${leveldb_sources})

# bitcoind plugin
add_bitcode(shadow-plugin-bitcoind-bitcode 
    ${BITCOIN_ROOT_DIR}/src/bitcoind.cpp
    bitcoind/bitcoind-plugin.c
    bitcoind/bitcoind.c
)
add_plugin(shadow-plugin-bitcoind 
    shadow-plugin-bitcoind-bitcode
    shadow-bitcoin-bitcode
    shadow-leveldb-bitcode
)
target_link_libraries(shadow-plugin-bitcoind 
    ${CMAKE_THREAD_LIBS_INIT}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
install(TARGETS shadow-plugin-bitcoind DESTINATION plugins)

# bitcoincli plugin
add_bitcode(shadow-plugin-bitcoincli-bitcode 
    ${BITCOIN_ROOT_DIR}/src/bitcoin-cli.cpp
    bitcoincli/bitcoincli-plugin.c
    bitcoincli/bitcoincli.c
)
add_plugin(shadow-plugin-bitcoincli 
    shadow-plugin-bitcoincli-bitcode
    shadow-bitcoin-bitcode
    shadow-leveldb-bitcode
)
target_link_libraries(shadow-plugin-bitcoincli 
    ${CMAKE_THREAD_LIBS_INIT}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
install(TARGETS shadow-plugin-bitcoincli DESTINATION plugins)
