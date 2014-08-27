# shadow-plugin-bitcoin

Shadow plugin for bitcoind (the Satoshi reference client)

This repository holds a Shadow plug-in that runs bitcoind. It can be used to run a private bitcoin network on a single machine using the Shadow discrete-event network simulator. For more information about Shadow, see https://shadow.github.io and https://github.com/shadow.

## dependencies

Fedora:

```bash
sudo yum install libstdc++ libstdc++-devel clang clang-devel llvm llvm-devel glib2 glib2-devel jansson jansson-devel
```

Ubuntu:

```bash
sudo apt-get install libstdc++ libstdc++-dev clang llvm llvm-dev libjansson libjansson-dev
```

## setup plug-in and custom build requirements

There are several custom build requirements which we will build from the `build` directory:

```bash
git clone git@github.com:amiller/shadow-plugin-bitcoin.git
cd shadow-plugin-bitcoin
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
./b2
cd ..
```

### bitcoin

We need to get the bitcoin source so we can compile it into our Shadow plug-in, and then configure it to obtain a proper `bitcoin-config.h` file.

```bash
git clone https://github.com/amiller/bitcoin.git -b 0.9.2-netmine
cd bitcoin
./autogen.sh
LD_LIBRARY_PATH=`pwd`/../boost_1_50_0/stage/lib PKG_CONFIG_PATH=/home/${USER}/.shadow/lib/pkgconfig LDFLAGS=-L/home/${USER}/.shadow/lib CFLAGS=-I/home/${USER}/.shadow/include CXXFLAGS=-I`pwd`/../boost_1_50_0 ./configure --prefix=/home/${USER}/.shadow --without-miniupnpc --without-gui --disable-wallet --disable-tests --with-boost-libdir=`pwd`/../boost_1_50_0/stage/lib
cd ..
```

Note that `PKG_CONFIG_PATH`, `LDFLAGS`, and `CFLAGS` need to be set to specify the install path of our custom-built OpenSSL.

The `0.9.2-netmine` branch contains a small number of changes to the Bitcoin 0.9.2 release that facilitate experiments.

+ The leveldb is modified not to use mmap, which reduces memory consumption
+ Command line parameters `-umd_createindexsnapshot` and `-umd_loadindexsnapshot` can be used to skip some expensive startup processing
+ Proof-of-work checking is disabled, to facilitate creating fake blocks
+ The ECDSA signature check routine is to hacked to accept fake signatures from a particular pubkey (the pubkey that received the second ever block reward).

### gnu pth

```bash
git clone git@github.com:amiller/gnu-pth.git -b shadow
cd gnu-pth
./configure --enable-epoll
cd ..
```

### picocoin

(Requires jannson as listed in the dependencies section above.)

```bash
git clone git@github.com:amiller/picocoin.git
cd picocoin
./autogen.sh
LDFLAGS=-L/home/${USER}/.shadow/lib ./configure
cd ..
```

### libev

```bash
wget http://pkgs.fedoraproject.org/lookaside/pkgs/libev/libev-4.15.tar.gz/3a73f247e790e2590c01f3492136ed31/libev-4.15.tar.gz
tar -zxf libev-4.15.tar.gz
cd libev-4.15
./configure
cd ..
```

### shadow-plugin-bitcoin

Now we are ready to build the actual Shadow plug-in using cmake.

```bash
mkdir shadow-plugin-bitcoin; cd shadow-plugin-bitcoin
CC=`which clang` CXX=`which clang++` cmake ../..
make -jN
make install
cd ..
```

Replace `N` with the number of cores you want to use for a parallel build.

## Running an experiment

The script that drives the experiment is at src/bitcoind/shadow-bitcoind.

Command line options:
+ `-t` prints the output to stdout as well as to data/shadow.log
+ `-r $N` initializes $N data directories, named .bitcoin1, .bitcoin2, ..., .bitcoin$N
+ `-T $template` if option `-r $N` is provided, this specifies the template directory that is copied over. If `-T` is not provided, then the initialized directories will be empty

### basic example

To run the most basic experiment, first generate the bitcoind data directories, then run the example:

```bash
mkdir run
cd run
../src/bitcoind/shadow-bitcoind -y -i ../resource/shadow.config.xml -r 2 -t | grep -e "received: getaddr" -e "received: verack"
```

### more realistic examples

In order to run a more realistic large scale example, we need to prepare some initialization blockchain datasets. It's useful to launch these experiments with Bitcoin nodes that have already processed the blockchain up to some point in history. To conserve memory, we can have multiple nodes share a single copy of most of the blockchain database files.

First create the dir structure:

```bash
mkdir initdata
cd initdata
mkdir pristine # will hold the single copy of the blockchain datasets
cp -R /storage/dotbitcoin_backing_120k pristine/.
mkdir dotbitcoin_template_120k
cd dotbitcoin_template_120k
```

The script `tools/make_symlinks.sh` is provided to build a dotbitcoin\_template directory that contains symlinks to an underlying dotbitcoin\_backing directory.

```
../../../tools/make_symlinks.sh ../pristine/dotbitcoin_backing_120k
cd ../..
```

Now we can run an experiment using the template we just created, where all nodes will share the backing datasets.

```bash
../src/bitcoind/shadow-bitcoind -y -i ../resource/shadow.config.xml -r 2 -t -T initdata/dotbitcoin_template_120k
```

### list of other provided examples

+ `resources/shadow.config-orphandos.xml` a cpu/memory exhaustion attack
+ `resources/shadow.config-6k.xml` a nearly-full-size experiment

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

