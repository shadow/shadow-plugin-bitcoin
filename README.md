# shadow-plugins-extra

Shadow plugin for bitcoind (the Satoshi reference client)

This repository holds a bitcoin plug-in for Shadow. It can be used to run a private bitcoin network on a single machine using the Shadow discrete-event network simulator. For more information about Shadow, see https://shadow.github.io and https://github.com/shadow.

# dependencies

Fedora:

```
sudo yum install libstdc++ libstdc++-devel boost boost-devel libdb4 libdb4-devel
```

# build

```
PKG_CONFIG_PATH=/home/rob/.shadow/lib/pkgconfig LDFLAGS=-L/home/rob/.shadow/lib CFLAGS=-I/home/rob/.shadow/include ./configure --prefix=/home/rob/.shadow --without-miniupnpc --without-gui --disable-wallet --disable-tests
```

## quick setup

```bash
mkdir build
cd build
CC=`which clang` CXX=`which clang++` cmake .. -DCMAKE_INSTALL_PREFIX=`readlink -f ~`/.shadow
make -jN
make install
```

Replace `N` with the number of cores you want to use for a parallel build.

## cmake options

The `cmake` command above takes multiple options, specified as

```bash
CC=`which clang` CXX=`which clang++` cmake .. -DOPT=VAL
```

+ SHADOW_ROOT = "path/to/shadow/install/root" (default is "~/.shadow")  
+ CMAKE_BUILD_TYPE = "Debug" or "Release" (default is "Debug")  
+ CMAKE_INSTALL_PREFIX = "path/to/install/root" (default is ${SHADOW_ROOT})  

For example:

```bash
CC=`which clang` CXX=`which clang++` cmake .. -DSHADOW_ROOT=/home/rob/.shadow -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/home/rob/.shadow
```

## troubleshooting

First try rebuilding to ensure that the cmake cache is up to date

```bash
rm -rf build
mkdir build
cd build
```

using `VERBOSE=1` for more verbose output

```bash
VERBOSE=1 CC=`which clang` CXX=`which clang++` cmake ..
make
```

# contributing

Please feel free to submit pull requests to contribute.

