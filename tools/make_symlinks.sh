#!/bin/bash -x

if [ "$#" != "1" ]; then 
    echo "Usage: make_shallow.sh <pristine_relative>"
    echo "Creates symlinks in the current directory"
    exit
fi
echo "FIXME: assuming there are exactly 144 block files in $1"
# TODO: find the actual number of block files
PRISTINE=$1
LASTBLK=$(echo $(ls -1 $PRISTINE/blocks/ | grep blk | wc -l) 1 - p | dc)
LASTBLKTXT=$(seq -f %05.0f $LASTBLK $LASTBLK) # Pad the last block
mkdir -p ./blocks

# Copy all the block/rev files up to lastblk-1
for i in $(seq -f %05.0f 0 $(echo $LASTBLK 1 - p | dc)); do ln -s ../$PRISTINE/blocks/blk$i.dat ../$PRISTINE/blocks/rev$i.dat ./blocks/; done
cp $PRISTINE/blocks/blk$LASTBLKTXT.dat $PRISTINE/blocks/rev$LASTBLKTXT.dat ./blocks/
cp $PRISTINE/bitcoin.conf ./

# Copy the block index files
#cp -r $PRISTINE/blocks/index ./blocks
mkdir -p ./blocks/index
for x in $(ls -1 $PRISTINE/blocks/index); do
    if [ $(cat $PRISTINE/blocks/index/$x | wc -c) -lt 2100000 ]; then
	cp $PRISTINE/blocks/index/$x ./blocks/index/
    else
	ln -s ../../$PRISTINE/blocks/index/$x ./blocks/index/
    fi
done

# Copy the chainstate files
mkdir -p ./chainstate
for x in $(ls -1 $PRISTINE/chainstate); do
    if [ $(cat $PRISTINE/chainstate/$x | wc -c) -lt 2100000 ]; then
	cp $PRISTINE/chainstate/$x ./chainstate/
    else
	ln -s ../$PRISTINE/chainstate/$x ./chainstate/
    fi
done
