#!/usr/bin/bash

OUTPUTPATH=$PWD
DATAPATH=$OUTPUTPATH/data

rm -r $DATAPATH
mkdir -p $DATAPATH

TEMPLATE=$1
N=$2
ln -s $OUTPUTPATH/initdata/pristine $DATAPATH/pristine
for x in `seq 1 $N`
do
    cp -r $TEMPLATE $DATAPATH/.bitcoin$x
done
X=$(for x in `seq 1 $N`; do echo -datadir=$DATAPATH/.bitcoin$x {} -port=$(dc -e "8332 $x + p"); done)
X="${X}"
echo "$X" > ./argsfile
xargs -a ./argsfile -t -d "\n" -P $N bitcoin/src/bitcoind -debug -printtoconsole
