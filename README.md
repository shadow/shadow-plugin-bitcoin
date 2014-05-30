# shadow-plugin-bitcoin

Shadow plugin for bitcoind (the Satoshi reference client)

This repository holds a Shadow plug-in that runs bitcoind. It can be used to run a private bitcoin network on a single machine using the Shadow discrete-event network simulator. For more information about Shadow, see https://shadow.github.io and https://github.com/shadow.

## dependencies

Fedora:

```
sudo yum install libstdc++ libstdc++-devel boost boost-devel
```

## setup plugin

### get and configure bitcoin

We need to get the bitcoin source so we can compile it into our Shadow plug-in, and then configure it to obtain a proper `bitcoin-config.h` file.

```bash
cd shadow-plugin-bitcoin
mkdir build
cd build
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
./autogen.sh
PKG_CONFIG_PATH=`readlink -f ~`/.shadow/lib/pkgconfig LDFLAGS=-L`readlink -f ~`/.shadow/lib CFLAGS=-I`readlink -f ~`/.shadow/include ./configure --prefix=`readlink -f ~`/.shadow --without-miniupnpc --without-gui --disable-wallet --disable-tests
cd ..
```

Note that `PKG_CONFIG_PATH`, `LDFLAGS`, and `CFLAGS` need to be set to specify a custom install path of a custom compiled OpenSSL.

### build plugin using cmake

```bash
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
CC=`which clang` CXX=`which clang++` cmake ..
VERBOSE=1 make
```

## contributing

Please feel free to submit pull requests to contribute.

