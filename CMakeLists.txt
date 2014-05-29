project(shadow-plugin-bitcoin)

## ensure cmake version
cmake_minimum_required(VERSION 2.8.8 FATAL_ERROR)

## ensure unix environment (CMAKE_SYSTEM_NAME == "Linux")
if((NOT UNIX) OR (NOT ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")))
    message(FATAL_ERROR "Unix/Linux environment is required.")
endif((NOT UNIX) OR (NOT ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")))

## ensure out-of-source build
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "An out-of-source build is required. Please see the README.")
endif("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")

## make it easier for sub-projects to add CFLAGS
macro(add_cflags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARGN}")
endmacro(add_cflags)

## now handle the options, set up our own flags
set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    message(STATUS "Release enabled. Setting '-DNDEBUG' and '-O3'.")
    add_definitions(-DNDEBUG)
    add_cflags(-O3)
else()
    message(STATUS "Debug enabled. Setting '-DDEBUG' and '-g'.")
    add_definitions(-DDEBUG)
    add_cflags(-g)
endif()

## get general includes
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(TestBigEndian)

## general tests and configurations
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

## we need to know where shadow is installed
if("${SHADOW_ROOT}" STREQUAL "")
    set(SHADOW_ROOT "$ENV{HOME}/.shadow")
endif("${SHADOW_ROOT}" STREQUAL "")
if(EXISTS "${SHADOW_ROOT}")
    message(STATUS "SHADOW_ROOT = ${SHADOW_ROOT}")
else()
    message(FATAL_ERROR "SHADOW_ROOT path does not exist: '${SHADOW_ROOT}'")
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${SHADOW_ROOT}")
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
if(EXISTS "${CMAKE_INSTALL_PREFIX}")
    message(STATUS "CMAKE_INSTALL_PREFIX = ${CMAKE_INSTALL_PREFIX}")
else()
    message(FATAL_ERROR "CMAKE_INSTALL_PREFIX path does not exist: '${CMAKE_INSTALL_PREFIX}'")
endif()

## we use cmake files from shadow
set(CMAKE_MODULE_PATH "${SHADOW_ROOT}/share/cmake/Modules")
if(EXISTS "${CMAKE_MODULE_PATH}")
    message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")
else()
    message(FATAL_ERROR "CMAKE_MODULE_PATH path does not exist: '${CMAKE_MODULE_PATH}'")
endif()
include_directories(${CMAKE_MODULE_PATH})
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/" ${CMAKE_MODULE_PATH})

## we need to use LLVM to build the plug-ins
set(LLVMHoistGlobalsPATH "${SHADOW_ROOT}/lib/LLVMHoistGlobals.so")
if(EXISTS "${LLVMHoistGlobalsPATH}")
    message(STATUS "LLVMHoistGlobalsPATH = ${LLVMHoistGlobalsPATH}")
else()
    message(FATAL_ERROR "LLVMHoistGlobalsPATH path does not exist: '${LLVMHoistGlobalsPATH}'")
endif()
include(LLVMTools)
add_custom_target(LLVMHoistGlobals)

## the plug-ins need to include shd-library.h and cmake files from shadow
include_directories(${SHADOW_ROOT}/include)

## plug-ins need to disable fortification to ensure syscalls are intercepted
#add_definitions(-D_GNU_SOURCE)
add_cflags("-fno-inline -fno-strict-aliasing -U_FORTIFY_SOURCE")

## CFLAGS status update
message(STATUS "CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

#get_filename_component(CURRENT_BITCOIN_DIR "${CMAKE_BINARY_DIR}/../bitcoin/src" ABSOLUTE)
set(CURRENT_BITCOIN_DIR /home/rob/dev/bitcoin)

#===================================================================
# Check Bitcoin Dependencies
#===================================================================

#find_package(GLIB REQUIRED)
#include_directories(${GLIB_INCLUDES})

find_package(Threads REQUIRED)

find_package(Boost 1.45.0 REQUIRED COMPONENTS system filesystem thread program_options)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Could not locate Boost.")
endif()
set(Boost_INCLUDES ${Boost_INCLUDE_DIRS})
set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF)
message (STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDES}")
message (STATUS "Boost_LIBRARIES = ${Boost_LIBRARIES}")

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message (STATUS "OPENSSL_INCLUDES = ${OPENSSL_INCLUDES}")
    message (STATUS "OPENSSL_LIBRARIES = ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not locate OpenSSL.")
endif()

find_package(LIBDB REQUIRED)

#===================================================================
# package files
#===================================================================

# bitcoin first
aux_source_directory(${CURRENT_BITCOIN_DIR}/src bitcoin_sources)
list(REMOVE_ITEM bitcoin_sources
    ${CURRENT_BITCOIN_DIR}/src/base58.cpp
    ${CURRENT_BITCOIN_DIR}/src/bitcoin-cli.cpp
    ${CURRENT_BITCOIN_DIR}/src/bitcoind.cpp
)

FILE(GLOB bitcoin_headers ${CURRENT_BITCOIN_DIR}/src/*.h)

# now leveldb
aux_source_directory(${CURRENT_BITCOIN_DIR}/src/leveldb/db leveldb_db_sources)
aux_source_directory(${CURRENT_BITCOIN_DIR}/src/leveldb/util leveldb_util_sources)
aux_source_directory(${CURRENT_BITCOIN_DIR}/src/leveldb/table leveldb_table_sources)
aux_source_directory(${CURRENT_BITCOIN_DIR}/src/leveldb/port leveldb_port_sources)
aux_source_directory(${CURRENT_BITCOIN_DIR}/src/leveldb/helpers/memenv leveldb_memenv_sources)
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
    ${CURRENT_BITCOIN_DIR}/src/leveldb/db/db_bench.cc
    ${CURRENT_BITCOIN_DIR}/src/leveldb/db/leveldb_main.cc
    ${CURRENT_BITCOIN_DIR}/src/leveldb/port/port_win.cc
    ${CURRENT_BITCOIN_DIR}/src/leveldb/util/testharness.cc
    ${CURRENT_BITCOIN_DIR}/src/leveldb/util/testutil.cc
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

# i dont know why this is not included automatically
#include_directories(/usr/include/c++/4.8.2/ /usr/include/c++/4.8.2/x86_64-redhat-linux/)

include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${CURRENT_BITCOIN_DIR}/src
    ${CURRENT_BITCOIN_DIR}/src/leveldb
    ${CURRENT_BITCOIN_DIR}/src/leveldb/include
    ${CURRENT_BITCOIN_DIR}/src/leveldb/helpers
    ${CURRENT_BITCOIN_DIR}/src/leveldb/helpers/memenv
)
include_directories(AFTER ${LIBDB_INCLUDES} ${Boost_INCLUDES} ${OPENSSL_INCLUDES})

#===================================================================
# start building bitcode and plugins!
#===================================================================

add_bitcode(shadow-bitcoin-bitcode ${bitcoin_sources})
add_bitcode(shadow-leveldb-bitcode ${leveldb_sources})

add_bitcode(shadow-plugin-bitcoind-bitcode 
    ${CURRENT_BITCOIN_DIR}/src/bitcoind.cpp 
    src/bitcoind-plugin.c
)
add_plugin(shadow-plugin-bitcoind 
    shadow-plugin-bitcoind-bitcode
    shadow-bitcoin-bitcode
    shadow-leveldb-bitcode
)
target_link_libraries(shadow-plugin-bitcoind 
    ${CMAKE_THREAD_LIBS_INIT}
    ${LIBDB_LIBRARIES}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

#add_bitcode(shadow-plugin-bitcoincli-bitcode ${CURRENT_BITCOIN_DIR}/src/bitcoin-cli.cpp src/bitcoincli-plugin.c)
#add_plugin(shadow-plugin-bitcoincli shadow-plugin-bitcoincli-bitcode shadow-bitcoin-bitcode shadow-leveldb-bitcode)
#target_link_libraries(shadow-plugin-bitcoind ${CMAKE_THREAD_LIBS_INIT} ${LIBDB_LIBRARIES} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})

