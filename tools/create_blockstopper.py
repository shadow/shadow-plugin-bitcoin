# Create and sign a transaction with a bogus key
from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *

from txtools import Transaction, TxOut, TxIn, tx_from_CTransaction, tx_coinbase, get_txin_second, txpair_from_p2sh_one

def void_coinbase(height=0):    
    tx = CTransaction()
    txin = CTxIn()
    txin.scriptSig = chr(0x03) + struct.pack('<I', height)[:3]
    txout = CTxOut()
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
    nTime = 1303963120
    ver = 2
    block.hashPrevBlock = unhexlify(prevhash)[::-1]
    block.vtx.append(void_coinbase(height=height))
    block.nBits = nBits
    block.nNonce = 9999999 # Not a valid proof of work, but this is ok
    block.nTime = nTime
    block.nVersion = ver;
    return block

def setup():
    tx_setup = Transaction()
    tx_setup.vin = [get_txin_second()]
    tx_setup_ins = []

    for _ in range(1):
        _out,_in = txpair_from_p2sh_one(nValue=0.02*COIN)
        tx_setup.append_txout(_out)
        tx_setup_ins.append(_in)
    tx_setup.finalize()


    # 1. Add tx_setup to a block
    block = make_block()
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
        inv = CInv()
        inv.type = 2 # block
        inv.hash = Hash(block.serialize())
        m = msg_inv()
        m.inv = [inv]
        f.write(m.serialize())

    return block, inv
