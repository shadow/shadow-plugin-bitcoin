# :bangbang: ARCHIVAL NOTICE - 2020-02-20 :bangbang:

Unfortunately, this project has not been properly maintained for a long time. This has resulted in users experiencing numerous bugs that we don't have the time to fix. Because we are prioritizing development effort elsewhere, we have decided to archive this repository: **no further development updates will be posted here**.

**Use at your own risk**; if it breaks, you get to keep both pieces.

-----


# Shadow-plugin-bitcoin

This repository holds a Shadow plug-in that runs the Bitcoin Satoshi reference client.
It can be used to run private Bitcoin networks of clients and servers on a single 
machine using the Shadow discrete-event network simulator.


By leveraging recent version of shadow, you can simplify the implementation of
Shadow plug-in for Bitcoin client. The detailed steps are summarized below.


# Dependencies

Please use Ubuntu 14.04.05 LTS. We confirmed the unresolved segmentation fault errors on Ubuntu 16.04 LTS.

You will need to install Shadow and its dependencies, using latest Shadow version (v1.12.0).
See https://github.com/shadow/shadow/wiki/1.1-Shadow.

Please install the glib manually before installing the shadow.
```
wget http://ftp.gnome.org/pub/gnome/sources/glib/2.42/glib-2.42.1.tar.xz
tar xaf glib-2.42.1.tar.xz
cd glib-2.42.1
./configure --prefix=~/.shadow
make
make install
```

# Setup plug-in and custom build requirements

After installing the shadow simulator, you will need to install Shadow plug-in for Bitcoin.
We will build from the `build` directory:

```
git clone https://github.com/shadow/shadow-plugin-bitcoin.git
cd shadow-plugin-bitcoin
mkdir build; cd build
```

You will also need to clone and customize the recent bitcoin sources (v0.16.0).

```
sudo apt-get install -y autoconf libtool libboost-all-dev libssl-dev libevent-dev
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
git checkout v0.16.0
./autogen.sh
./configure --disable-wallet
make -C src obj/build.h
make -C src/secp256k1 src/ecmult_static_context.h
git apply ../../DisableSanityCheck.patch
cd ..
```

Now we are ready to build the actual Shadow plug-in using cmake.

```
cmake ../
make -jN
make install
cd ..
```

Replace `N` with the number of cores you want to use for a parallel build.


# Running an experiment

To run the most basic experiment, run as follows.

```
mkdir run
cd run
mkdir -p data/bcdnode1
mkdir -p data/bcdnode2
shadow ../resource/example.xml
cd ..
```

To run a more large scale example (e.g. 1000 bitcoin nodes), run as follows.
Python script will automatically generate a necessary network config file of shadow at `../resource/example_multiple_generated.xml`.

```
mkdir run
cd run
python ../tools/run_multinode_experiment.py --nodenum 100 --workernum 5
cd ..
```


# Additional Links

Setup and Usage Instructions:
  + https://github.com/shadow/shadow-plugin-bitcoin/wiki

Shadow-Bitcoin: Scalable Simulation via Direct Execution of Multi-threaded Applications [(tech report)](https://cs.umd.edu/~amiller/shadow-bitcoin.pdf)

More Information about Shadow:
  + https://shadow.github.io
  + https://github.com/shadow/shadow

More Information about Bitcoin:
  + https://www.bitcoin.org
  + https://github.com/bitcoin/bitcoin

# Contributing

Contributions can be made by submitting pull requests via GitHub.
