# Notes for "with-pth" development branch:
- use this version of shadow: https://github.com/amiller/shadow/next

# shadow-plugin-bitcoin

Shadow plugin for bitcoind (the Satoshi reference client)

This repository holds a Shadow plug-in that runs bitcoind. It can be used to run a private bitcoin network on a single machine using the Shadow discrete-event network simulator. For more information about Shadow, see https://shadow.github.io and https://github.com/shadow.

## dependencies

Fedora:

```bash
sudo yum install libstdc++ libstdc++-devel clang clang-devel llvm llvm-devel glib2 glib2-devel
```

Ubuntu:

```bash
sudo apt-get install libstdc++ libstdc++-dev clang llvm llvm-dev
```

## setup plug-in and custom build requirements

There are several custom build requirements which we will build from the `build` directory:

```bash
git clone git@github.com:amiller/shadow-plugin-bitcoin.git
cd shadow-plugin-bitcoin
git checkout with-pth
mkdir build; cd build
```

### openssl

```bash
wget https://www.openssl.org/source/openssl-1.0.1h.tar.gz
tar xaf openssl-1.0.1h.tar.gz
cd openssl-1.0.1h
./config --prefix=/home/${USER}/.shadow shared threads enable-ec_nistp_64_gcc_128 -fPIC
make depend
make
make install_sw
cd ..
```

### boost

```bash
wget http://downloads.sourceforge.net/project/boost/boost/1.50.0/boost_1_50_0.tar.gz
tar xaf boost_1_50_0.tar.gz
cd boost_1_50_0
./bootstrap.sh --with-libraries=filesystem,system,thread,program_options
cd ..
```

### gnu pth

```bash
git clone git@github.com:amiller/gnu-pth.git
cd gnu-pth
git checkout -b shadow
cd ..
```

### bitcoin

We need to get the bitcoin source so we can compile it into our Shadow plug-in, and then configure it to obtain a proper `bitcoin-config.h` file.

```bash
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
./autogen.sh
PKG_CONFIG_PATH=/home/${USER}/.shadow/lib/pkgconfig LDFLAGS=-L/home/${USER}/.shadow/lib CFLAGS=-I/home/${USER}/.shadow/include ./configure --prefix=/home/${USER}/.shadow --without-miniupnpc --without-gui --disable-wallet --disable-tests
cd ..
```

Note that `PKG_CONFIG_PATH`, `LDFLAGS`, and `CFLAGS` need to be set to specify the install path of our custom-built OpenSSL.

### shadow-plugin-bitcoin

Now we are ready to build the actual Shadow plug-in using cmake.

```bash
mkdir shadow-plugin-bitcoin; cd shadow-plugin-bitcoin
CC=`which clang` CXX=`which clang++` cmake ../..
make -jN
make install
```

Replace `N` with the number of cores you want to use for a parallel build.

## other potentially useful information

### cmake options

The `cmake` command above takes multiple options, specified as

```bash
cmake .. -DOPT=VAL
```

+ SHADOW_ROOT = "path/to/shadow/install/root" (default is "~/.shadow")  
  Specifies a custom path to the shadow installation root  
+ CMAKE_BUILD_TYPE = "Debug" or "Release" (default is "Debug")  
+ CMAKE_INSTALL_PREFIX = "path/to/install/root" (default is ${SHADOW_ROOT})  
  Specifies a custom path to install this package  
+ CMAKE_PREFIX_PATH = "custom/search/path" (default is ${SHADOW_ROOT})  
  Specifies a custom path to search for library dependencies  

For example, the following will fully specify the default options:

```bash
CC=`which clang` CXX=`which clang++` cmake .. -DSHADOW_ROOT=/home/rob/.shadow -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/home/rob/.shadow -DCMAKE_PREFIX_PATH=/home/rob/.shadow
```

### troubleshooting

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

### contributing

Please contribute by submitting pull requests via GitHub.

