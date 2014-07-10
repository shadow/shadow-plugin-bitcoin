#===================================================================
# Check Bitcoin Dependencies
#===================================================================
find_package(RT REQUIRED)
find_package(DL REQUIRED)
find_package(GLIB REQUIRED)

# threads - set options BEFORE find_package()
set(CMAKE_THREAD_PREFER_PTHREAD ON)  
find_package(Threads REQUIRED)
if(NOT Threads_FOUND)
    message(FATAL_ERROR "Could not locate Threads.")
endif()
message(STATUS "CMAKE_USE_PTHREADS_INIT = ${CMAKE_USE_PTHREADS_INIT}")
message(STATUS "CMAKE_THREAD_LIBS_INIT = ${CMAKE_THREAD_LIBS_INIT}")

# boost - set options BEFORE find_package()
#set(BOOST_INCLUDEDIR /home/amiller/.local/include)
#set(BOOST_LIBRARYDIR /home/amiller/.local/lib)
#set(Boost_NO_SYSTEM_PATHS ON) 
#set(Boost_USE_STATIC_LIBS OFF) 
#set(Boost_USE_MULTITHREADED ON)  
#set(Boost_USE_STATIC_RUNTIME OFF)
#find_package(Boost 1.45.0 REQUIRED COMPONENTS system filesystem thread program_options)
#if(NOT Boost_FOUND)
#    message(FATAL_ERROR "Could not locate Boost.")
#endif()
#message(STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}")
#message(STATUS "Boost_LIBRARIES = ${Boost_LIBRARIES}")

# openssl
find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "Could not locate OpenSSL.")
endif()
message(STATUS "OPENSSL_VERSION = ${OPENSSL_VERSION}")
message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_LIBRARIES = ${OPENSSL_LIBRARIES}")

#===================================================================
# boost
#===================================================================

set(BOOST_ROOT_DIR ${CMAKE_SOURCE_DIR}/build/boost_1_50_0)
message(STATUS "BOOST_ROOT_DIR = ${BOOST_ROOT_DIR}")

ADD_CUSTOM_COMMAND( OUTPUT ${BOOST_ROOT_DIR}/libs/program_options/src/program_options_utf8_codecvt_facet.cpp
                     COMMAND ln -s ${BOOST_ROOT_DIR}/libs/program_options/src/utf8_codecvt_facet.cpp ${BOOST_ROOT_DIR}/libs/program_options/src/program_options_utf8_codecvt_facet.cpp )

set(boost_sources
    ${BOOST_ROOT_DIR}/libs/chrono/src/chrono.cpp
    ${BOOST_ROOT_DIR}/libs/chrono/src/thread_clock.cpp
    ${BOOST_ROOT_DIR}/libs/chrono/src/process_cpu_clocks.cpp

    ${BOOST_ROOT_DIR}/libs/system/src/error_code.cpp

    ${BOOST_ROOT_DIR}/libs/thread/src/pthread/thread.cpp
    ${BOOST_ROOT_DIR}/libs/thread/src/pthread/once.cpp
    ${BOOST_ROOT_DIR}/libs/thread/src/future.cpp

    ${BOOST_ROOT_DIR}/libs/filesystem/src/codecvt_error_category.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/operations.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/path.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/path_traits.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/portability.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/unique_path.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/utf8_codecvt_facet.cpp
    ${BOOST_ROOT_DIR}/libs/filesystem/src/windows_file_codecvt.cpp

    ${BOOST_ROOT_DIR}/libs/program_options/src/cmdline.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/config_file.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/options_description.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/parsers.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/variables_map.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/value_semantic.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/positional_options.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/program_options_utf8_codecvt_facet.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/convert.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/winmain.cpp
    ${BOOST_ROOT_DIR}/libs/program_options/src/split.cpp
)

#===================================================================
# picocoin
#===================================================================
set(picocoin_ROOT_DIR ${CMAKE_SOURCE_DIR}/build/picocoin)
include_directories(${picocoin_ROOT_DIR}/ ${picocoin_ROOT_DIR}/include ${GLIB_INCLUDES})
set(picocoin_SOURCES
	${picocoin_ROOT_DIR}/lib/address.c
	${picocoin_ROOT_DIR}/lib/addr_match.c
	${picocoin_ROOT_DIR}/lib/base58.c
	${picocoin_ROOT_DIR}/lib/bignum.c
	${picocoin_ROOT_DIR}/lib/blkdb.c
	${picocoin_ROOT_DIR}/lib/block.c
	${picocoin_ROOT_DIR}/lib/blockfile.c
	${picocoin_ROOT_DIR}/lib/bloom.c
	${picocoin_ROOT_DIR}/lib/buffer.c
	${picocoin_ROOT_DIR}/lib/buint.c
	${picocoin_ROOT_DIR}/lib/checkpoints.c
	${picocoin_ROOT_DIR}/lib/core.c
	${picocoin_ROOT_DIR}/lib/coredefs.c
	${picocoin_ROOT_DIR}/lib/dns.c
	${picocoin_ROOT_DIR}/lib/file_seq.c
	${picocoin_ROOT_DIR}/lib/hexcode.c
	${picocoin_ROOT_DIR}/lib/key.c
	${picocoin_ROOT_DIR}/lib/keyset.c
	${picocoin_ROOT_DIR}/lib/keystore.c
	${picocoin_ROOT_DIR}/lib/mbr.c
	${picocoin_ROOT_DIR}/lib/memmem.c
	${picocoin_ROOT_DIR}/lib/message.c
	${picocoin_ROOT_DIR}/lib/net.c
	${picocoin_ROOT_DIR}/lib/script.c
	${picocoin_ROOT_DIR}/lib/script_eval.c
	${picocoin_ROOT_DIR}/lib/script_names.c
	${picocoin_ROOT_DIR}/lib/script_sign.c
	${picocoin_ROOT_DIR}/lib/serialize.c
	${picocoin_ROOT_DIR}/lib/util.c
	${picocoin_ROOT_DIR}/lib/utxo.c
)
add_bitcode(shadow-picocoin-bitcode ${picocoin_SOURCES})

#===================================================================
# bitcoin
#===================================================================

#get_filename_component(BITCOIN_ROOT_DIR "${CMAKE_BINARY_DIR}/../bitcoin/src" ABSOLUTE)
set(BITCOIN_ROOT_DIR ${CMAKE_SOURCE_DIR}/build/bitcoin)
message(STATUS "BITCOIN_ROOT_DIR = ${BITCOIN_ROOT_DIR}")

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

#===================================================================
# leveldb
#===================================================================

set(LEVELDB_ROOT_DIR ${BITCOIN_ROOT_DIR}/src/leveldb)
message(STATUS "LEVELDB_ROOT_DIR = ${LEVELDB_ROOT_DIR}")

aux_source_directory(${LEVELDB_ROOT_DIR}/db leveldb_db_sources)
aux_source_directory(${LEVELDB_ROOT_DIR}/util leveldb_util_sources)
aux_source_directory(${LEVELDB_ROOT_DIR}/table leveldb_table_sources)
aux_source_directory(${LEVELDB_ROOT_DIR}/port leveldb_port_sources)
aux_source_directory(${LEVELDB_ROOT_DIR}/helpers/memenv leveldb_memenv_sources)
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
    ${LEVELDB_ROOT_DIR}/db/db_bench.cc
    ${LEVELDB_ROOT_DIR}/db/leveldb_main.cc
    ${LEVELDB_ROOT_DIR}/port/port_win.cc
    ${LEVELDB_ROOT_DIR}/util/testharness.cc
    ${LEVELDB_ROOT_DIR}/util/testutil.cc
)

#===================================================================
# pth
#===================================================================

set(PTH_ROOT_DIR ${CMAKE_SOURCE_DIR}/build/gnu-pth)
message(STATUS "PTH_ROOT_DIR = ${PTH_ROOT_DIR}")

include_directories(${PTH_ROOT_DIR})

set(PTH_SOURCES
   ${PTH_ROOT_DIR}/pth_compat.c
   ${PTH_ROOT_DIR}/pth_debug.c
   ${PTH_ROOT_DIR}/pth_syscall.c
   ${PTH_ROOT_DIR}/pth_errno.c
   ${PTH_ROOT_DIR}/pth_ring.c
   ${PTH_ROOT_DIR}/pth_mctx.c
   ${PTH_ROOT_DIR}/pth_uctx.c
   ${PTH_ROOT_DIR}/pth_clean.c
   ${PTH_ROOT_DIR}/pth_time.c
   ${PTH_ROOT_DIR}/pth_tcb.c
   ${PTH_ROOT_DIR}/pth_util.c
   ${PTH_ROOT_DIR}/pth_pqueue.c
   ${PTH_ROOT_DIR}/pth_event.c
   ${PTH_ROOT_DIR}/pth_sched.c
   ${PTH_ROOT_DIR}/pth_data.c
   ${PTH_ROOT_DIR}/pth_msg.c
   ${PTH_ROOT_DIR}/pth_cancel.c
   ${PTH_ROOT_DIR}/pth_sync.c
   ${PTH_ROOT_DIR}/pth_attr.c
   ${PTH_ROOT_DIR}/pth_lib.c
   ${PTH_ROOT_DIR}/pth_fork.c
   ${PTH_ROOT_DIR}/pth_high.c
   ${PTH_ROOT_DIR}/pth_ext.c
   ${PTH_ROOT_DIR}/pth_string.c
#   ${PTH_ROOT_DIR}/pthread.c
)

ADD_CUSTOM_COMMAND (
   OUTPUT ${PTH_ROOT_DIR}/pth_p.h
   COMMAND ${PTH_ROOT_DIR}/shtool 
   ARGS scpp -o ${PTH_ROOT_DIR}/pth_p.h -t ${PTH_ROOT_DIR}/pth_p.h.in -Dcpp -Cintern -M '==\#==' ${PTH_SOURCES} ${PTH_ROOT_DIR}/pthread.c
   DEPENDS ${PTH_ROOT_DIR}/pth_p.h.in ${PTH_ROOT_DIR}/*.h ${PTH_SOURCES} ${PTH_ROOT_DIR}/pthread.c
)
ADD_CUSTOM_TARGET(generate_pth DEPENDS ${PTH_ROOT_DIR}/pth_p.h.in)
#set_property(SOURCE ${PTH_SOURCES} APPEND PROPERTY OBJECT_DEPENDS pth_p.h)
add_bitcode(shadow-pth-bitcode ${PTH_SOURCES})
add_dependencies(shadow-pth-bitcode generate_pth)


#===================================================================
# tweaks
#===================================================================

add_definitions( "-DHAS_BOOST -DHAVE_WORKING_BOOST_SLEEP" )

#-DBOOST_ALL_DYN_LINK=1
#-DBOOST_ALL_NO_LIB=1
#-DBOOST_CHRONO_STATIC_LINK=1
#-DBOOST_SYSTEM_DYN_LINK=1
#-DBOOST_SYSTEM_STATIC_LINK=1
#-DBOOST_SYSTEM_NO_DEPRECATED
#-DBOOST_FILESYSTEM_DYN_LINK=1
#-DBOOST_FILESYSTEM_STATIC_LINK=1
#-DBOOST_PROGRAM_OPTIONS_DYN_LINK=1
#-DBOOST_THREAD_POSIX
#-DBOOST_THREAD_BUILD_LIB=1

add_definitions( "-DBOOST_ALL_DYN_LINK=1 -DBOOST_ALL_NO_LIB=1 -DBOOST_THREAD_POSIX" )

# Generate bitcoin-config.h substituting config vars for include:
#configure_file(${CONTRIB_CURRENT_SOURCE_DIR}/bitcoin-config.h.cmake
#               ${CMAKE_CURRENT_BINARY_DIR}/bitcoin-config.h @ONLY)
add_definitions( "-DHAVE_CONFIG_H" )

# needed so we include the correct port header for posix
add_definitions( "-DLEVELDB_PLATFORM_POSIX" )
add_definitions( "-DLEVELDB_PLATFORM_POSIX" )

#===================================================================
# includes
#===================================================================

include_directories(${CMAKE_SOURCE_DIR}/src
    ${BOOST_ROOT_DIR}
    ${PTH_ROOT_DIR}
    ${BITCOIN_ROOT_DIR}/src
    ${BITCOIN_ROOT_DIR}/src/config
    ${LEVELDB_ROOT_DIR}
    ${LEVELDB_ROOT_DIR}/include
    ${LEVELDB_ROOT_DIR}/helpers
    ${LEVELDB_ROOT_DIR}/helpers/memenv
)
include_directories(AFTER ${OPENSSL_INCLUDE_DIR} ${RT_INCLUDES} ${DL_INCLUDES} ${GLIB_INCLUDES})

#===================================================================
# build bitcode and plugins!
#===================================================================

add_bitcode(shadow-boost-bitcode ${boost_sources})
add_bitcode(shadow-leveldb-bitcode ${leveldb_sources})
add_bitcode(shadow-bitcoin-bitcode ${bitcoin_sources})

# bitcoind plugin
add_bitcode(shadow-plugin-bitcoind-bitcode 
    bitcoind/bitcoind-plugin.c
    bitcoind/bitcoind-base.cpp
    ${BITCOIN_ROOT_DIR}/src/bitcoind.cpp
)
add_plugin(shadow-plugin-bitcoind 
    shadow-plugin-bitcoind-bitcode
    shadow-boost-bitcode
    shadow-pth-bitcode
    shadow-leveldb-bitcode
    shadow-bitcoin-bitcode
)
target_link_libraries(shadow-plugin-bitcoind 
    ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES} ${RT_LIBRARIES} ${DL_LIBRARIES}
)
install(TARGETS shadow-plugin-bitcoind DESTINATION plugins)


# injector plugin
add_bitcode(shadow-plugin-bitcoin-injector-bitcode
    injector/injector-plugin.c
    injector/injector.c
)
add_plugin(shadow-plugin-bitcoin-injector
    shadow-plugin-bitcoin-injector-bitcode
    shadow-picocoin-bitcode
    shadow-pth-bitcode
)
target_link_libraries(shadow-plugin-bitcoin-injector
    ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES} ${RT_LIBRARIES} ${DL_LIBRARIES}
)
install(TARGETS shadow-plugin-bitcoin-injector DESTINATION plugins)

# bitcoincli plugin
#add_bitcode(shadow-plugin-bitcoincli-bitcode 
#    ${BITCOIN_ROOT_DIR}/src/bitcoin-cli.cpp
#    bitcoincli/bitcoincli-plugin.c
#    bitcoincli/bitcoincli.c
#)
#add_plugin(shadow-plugin-bitcoincli 
#    shadow-plugin-bitcoincli-bitcode
#    shadow-boost-bitcode
#    shadow-leveldb-bitcode
#    shadow-bitcoin-bitcode
#)
#target_link_libraries(shadow-plugin-bitcoincli 
#    ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES} ${RT_LIBRARIES} ${DL_LIBRARIES}
#)
#install(TARGETS shadow-plugin-bitcoincli DESTINATION plugins)


## preload library for intercepting functions
add_library(shadow-preload-bitcoind SHARED bitcoind/bitcoind-preload.c bitcoind/bitcoind-preload.cpp)
target_link_libraries(shadow-preload-bitcoind
    ${GLIB_LIBRARIES} ${OPENSSL_LIBRARIES} ${RT_LIBRARIES} ${DL_LIBRARIES}
)
install(TARGETS shadow-preload-bitcoind DESTINATION lib)

