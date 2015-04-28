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
    if 0:
        #prevhash = "00000000000000005bac7c3c745d926451483e7a15ce7a76627861f19f756d22" # Block 302980 on main chain
        #nBits = 409544770
        #height = 302981
        #nTime = 1401257762
        #ver = 2
        pass
    else:
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

def setup(ntx=100):
    tx_setup = Transaction()
    tx_setup.vin = [get_txin_second()]
    tx_setup_ins = []
    
    for _ in range(ntx):
        _out,_in = txpair_from_p2sh_one(nValue=0.02*COIN)
        tx_setup.append_txout(_out)
        tx_setup_ins.append(_in)
    tx_setup.finalize()


    # 1a. Add tx_setup to a block
    block = make_block()
    block.vtx.append(tx_setup._ctx)
    block.hashMerkleRoot = block.calc_merkle_root()

    txes = []
    # 2. Create transactions to spend each of the outputs
    for inp in tx_setup_ins:
        _out,_in = txpair_from_p2sh_one(nValue=0.01*COIN)
        _tx = Transaction()
        _tx.vin = [inp]
        _tx.append_txout(_out)
        _tx.finalize()
        txes.append(_tx)

    print 'writing to experiment_t120_block.dat'
    with open('experiment_t120_block.dat','wb') as f:
        m = msg_block()
        m.block = block
        f.write(m.serialize())

    print 'writing to experiment_t120_tx.dat'
    with open('experiment_t120_tx.dat','wb') as f:
        for tx in txes:
            m = msg_tx()
            m.tx = tx._ctx
            f.write(m.serialize())

    return block, txes
