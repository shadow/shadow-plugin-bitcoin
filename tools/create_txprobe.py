from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *

from test_createtx import Transaction, void_coinbase, k

def create_txprobe(input1, input2, n):
    """Creates several kinds of transactions:
      PARENT[i]:
         spends input1
         creates output p[i]
      ORPHAN[i]:
         spends input2, and p[i]
         creates output o[i] for recovery.
     
      FLOOD:
         spends input1, blocks parent[i]
    """
    PARENTS = []
    for i in range(n):
        tx = Transaction()
        tx
    pass


def make_experiment2(path='./experiment2_payload.dat'):
    # 1a. Add tx_setup to a block
    print 'Step 1a.'
    prevhash = "00000000000000005bac7c3c745d926451483e7a15ce7a76627861f19f756d22" # Block 302980 on main chain
    block = CBlock()
    block.hashPrevBlock = unhexlify(prevhash)[::-1]
    block.vtx.append(void_coinbase(height=302981))
    block.vtx.append(tx_setup._ctx)
    block.nBits = 409544770
    block.nNonce = 9999999 # Not a valid proof of work, but this is ok
    block.nTime = 1401257762
    block.nVersion = 2
    block.hashMerkleRoot = block.calc_merkle_root()
