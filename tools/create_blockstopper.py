# Create and sign a transaction with a bogus key
from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.net import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *
import struct

from txtools import Transaction, TxOut, TxIn, tx_from_CTransaction, tx_coinbase, get_txin_second, txpair_from_p2sh_one, txpair_from_pubkey, _ssl

def void_coinbase(height=0):    
    tx = CMutableTransaction()
    txin = CMutableTxIn()
    txin.scriptSig = chr(0x03) + struct.pack('<I', height)[:3]
    txout = CMutableTxOut()
    txout.nValue = 25*1e8
    txout.scriptPubKey = CScript(unhexlify('76a91427a1f12771de5cc3b73941664b2537c15316be4388ac'))
    tx.vin.append(txin)
    tx.vout.append(txout)
    return tx

def make_block():
    block = CBlock()
    prevhash = "0000000000004ba33ad245380d09ed2cf728753421550c23837ac3007ec4c25a" # height=120594
    nBits = 453031340
    height = 120594
    nTime = 1303964120
    ver = 1
    block.hashPrevBlock = unhexlify(prevhash)[::-1]
    block.vtx.append(void_coinbase(height=height))
    block.nBits = nBits
    block.nNonce = 9999991 # Not a valid proof of work, but this is ok
    block.nTime = nTime
    block.nVersion = ver;
    return block

def setup():
    _ssl.RAND_seed(b"hello", 5)
    # 1. Create a new block
    block = make_block()

    tx_setup = Transaction()
    tx_setup.vin = [get_txin_second()]
    _out,_in = txpair_from_pubkey(nValue=0.01*COIN)
    tx_setup.append_txout(_out)
    tx_setup.finalize()

    block.vtx.append(tx_setup._ctx)

    block.hashMerkleRoot = block.calc_merkle_root()


    # 2. 
    print 'writing to experiment_blockstop_block.dat'
    with open('experiment_blockstop_block.dat','wb') as f:
        m = msg_block()
        m.block = block
        f.write(m.serialize())

    print 'writing to experiment_blockstop_inv.dat'
    with open('experiment_blockstop_inv.dat','wb') as f:
        # First we create the actual inv
        inv = CInv()
        inv.type = 2 # block
        inv.hash = Hash(block.get_header().serialize())
        m = msg_inv()
        m.inv = [inv]
        f.write(m.serialize())

    print 'writing to experiment_blockstop_headers.dat'
    with open('experiment_blockstop_headers.dat','wb') as f:
        # Next we create a "headers" message
        # For version 0.9.2, this has no effect
        # For version 10.1+, this queues the header
        m = msg_headers()
        m.headers = [block.get_header()]
        print 'header len', len(block.get_header().serialize())
        f.write(m.serialize())

    return block, inv
