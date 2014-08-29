# Create and sign a transaction with a bogus key

from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *

class Transaction():
    def __init__(self):
        self.vin = [] # staged txin's only. Might be less than in _ctx
        self._vout = []
        self._ctx = CTransaction()

    def append_txout(self, txout):
        assert txout._tx is None and txout._idx is None
        txout._tx = self
        txout._idx = len(self._vout)
        self._vout.append(txout)
        self._ctx.vout.append(txout._ctxout)

    def finalize(self):
        assert self._ctx.vin == []
        for idx,txin in enumerate(self.vin):
            ctxin = CTxIn(txin.txout.prevout)
            self._ctx.vin.append(ctxin)
        for idx,txin in enumerate(self.vin):
            txfrom = txin.txout._tx._ctx
            self._ctx.vin[idx].scriptSig = txin._finalize(txfrom, self._ctx, idx)
        #self._ctx.calc_sha256()

class TxOut():
    def __init__(self, scriptPubKey, nValue):
        self._tx = None
        self._idx = None
        # a TxOut is "unhooked" until _tx and _idx are set
        self._ctxout = CTxOut()
        self._ctxout.nValue = nValue
        self._ctxout.scriptPubKey = scriptPubKey

    @property
    def prevout(self):
        assert self._tx is not None and self._idx is not None, "attempt to get prevout from an unhooked TxOut"
        return COutPoint(Hash(self._tx._ctx.serialize()), self._idx)

    @property
    def nValue(self):
        return self._ctxout.nValue

class TxIn():
    def __init__(self, txout, finalize):
        self.txout = txout
        self._finalize = finalize

def tx_from_CTransaction(ctx):
    """
    The base case (a Tx, TxIn, or TxOut with no predecessor) can only be a 
    transaction. It can't be a TxIn, since a signing a transaction requires
    loading the scriptPubKey from the underlying TxOut. It can't be a TxOut,
    since a TxOut is identified by the hash of the Tx it's contained in.
    """
    tx = Transaction()
    tx._ctx = ctx
    for idx,ctxout in enumerate(tx._ctx.vout):
        txout = TxOut(ctxout.scriptPubKey, ctxout.nValue)
        txout._idx = idx
        txout._tx = tx
        tx._vout.append(txout)
    return tx


def tx_coinbase(height):
    # Makes a coinbase transaction with a single input
    tx = Transaction()
    ctxin = CTxIn()
    ctxin.prevout.hash = 0L
    ctxin.prevout.n = 0xffffffff
    # after v2, coinbase scriptsig must begin with height
    ctxin.scriptSig = CScript(chr(0x03) + struct.pack('<I', height)[:3])
    tx._ctx.vin.append(txin)
    return tx

