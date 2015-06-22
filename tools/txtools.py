# Create and sign a transaction with a bogus key

from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *
import ctypes

_ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')

# ethalone keys
#ec_secret = 'a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e'
ec_secret = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'

def patched_set_pubkey(self, key):
    intercept = map(unhexlify, ['0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee'])
    cheat = unhexlify('04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a')
    if key in intercept:
        #print 'cheating!'
        key = cheat
    self.mb = ctypes.create_string_buffer(key)
    _ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

CECKey.set_pubkey = patched_set_pubkey

k = CECKey()
k.set_compressed(True)
k.set_secretbytes(ec_secret.decode('hex'))
#print 'get_privkey:', k.get_privkey().encode('hex')
#print 'get_pubkey:', k.get_pubkey().encode('hex')
# not sure this is needed any more: print k.get_secret().encode('hex')


class Transaction():
    def __init__(self):
        self.vin = [] # staged txin's only. Might be less than in _ctx
        self._vout = []
        self._ctx = CMutableTransaction()

    def append_txout(self, txout):
        assert txout._tx is None and txout._idx is None
        txout._tx = self
        txout._idx = len(self._vout)
        self._vout.append(txout)
        self._ctx.vout.append(txout._ctxout)

    def finalize(self):
        assert self._ctx.vin == []
        for idx,txin in enumerate(self.vin):
            ctxin = CMutableTxIn(txin.txout.prevout)
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
        self._ctxout = CMutableTxOut()
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
    ctxin = CMutableTxIn()
    ctxin.prevout.hash = 0L
    ctxin.prevout.n = 0xffffffff
    # after v2, coinbase scriptsig must begin with height
    ctxin.scriptSig = CScript(chr(0x03) + struct.pack('<I', height)[:3])
    tx._ctx.vin.append(txin)
    return tx

def txpair_from_pubkey(scriptPubKey=None,nValue=50*1e8):
    """
    returns:
       txout: a txout containing a standard pay-to-pubkey
       sign:  signs the transaction (using an interposed key)
    """
    if scriptPubKey is None:
        # default scriptPubKey, from coinbase #2
        scriptPubKey = CScript(unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'))
    txout = TxOut(scriptPubKey, nValue)
    def sign(txfrom, ctx, idx):
        sighash = SignatureHash(scriptPubKey, ctx, idx, SIGHASH_ALL)
        sig = k.sign(sighash) + chr(SIGHASH_ALL)
        assert len(sig) < OP_PUSHDATA1
        scriptSig = CScript(chr(len(sig)) + sig)
        # Go ahead and set the scriptSig in the transaction, so we can verify
        ctx.vin[idx].scriptSig = scriptSig
        try: 
            VerifySignature(txfrom, ctx, idx)
        except VerifySignatureError as e:
            print "Warning: signature did not verify"
        return scriptSig
    txin = TxIn(txout, sign)
    return txout, txin

def txpair_from_p2sh_one(nValue=50*1e8):
    """
    returns:
       txout: a txout containing a standard pay-to-scripthash
       sign:  signs the transaction (using an interposed key)
    """

    # Create a 15 (or 3) way multisig
    n_sigs = 3
    pk = k.get_pubkey()
    redeemscript = CScript(unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'))
    redeemscripthash = Hash160(redeemscript)
    scriptPubKey = CScript([OP_HASH160, redeemscripthash, OP_EQUAL])
    txout = TxOut(scriptPubKey, nValue)

    def sign(txfrom, ctx, idx):
        sighash = SignatureHash(redeemscript, ctx, idx, SIGHASH_ALL)
        sig = k.sign(sighash) + chr(SIGHASH_ALL)
        assert len(sig[0]) < OP_PUSHDATA1
        scriptSig = CScript([sig, redeemscript])
        assert len(scriptSig) <= 1650 # This is 1650 for 0.9.3+, but the 0.9.2 limit is 500.
        assert len(scriptSig) <= 500 
        # Go ahead and set the scriptSig in the transaction, so we can verify
        ctx.vin[idx].scriptSig = scriptSig
        try:
            VerifySignature(txfrom, ctx, idx)
            VerifyScript(scriptSig, scriptPubKey, ctx, idx, flags=(SCRIPT_VERIFY_P2SH,))
        except VerifySignatureError as e:
            print "Warning: signature did not verify"
            print e
        return scriptSig
    txin = TxIn(txout, sign)
    return txout, txin

def get_txin_second():
    """
    returns:
       txout: a txout representing the second coinbase
       sign:  signs a transaction spending this input
    """
    second_coinbase = CMutableTransaction.deserialize(unhexlify("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"))
    scriptPubKey = CScript(unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'))
    tx = tx_from_CTransaction(second_coinbase)
    def sign(txfrom, ctx, idx):
        sighash = SignatureHash(scriptPubKey, ctx, idx, SIGHASH_ALL)
        sig = k.sign(sighash) + chr(SIGHASH_ALL)
        assert len(sig) < OP_PUSHDATA1
        scriptSig = CScript(chr(len(sig)) + sig)
        # Go ahead and set the scriptSig in the transaction, so we can verify
        ctx.vin[idx].scriptSig = scriptSig
        try:
            VerifySignature(txfrom, ctx, idx)
        except VerifySignatureError as e:
            print "Warning: signature did not verify"
            print 'idx:', idx
            print '>', txfrom
            print '>', tx
            print
        return scriptSig
    txout = tx._vout[0]
    txin = TxIn(txout, sign)
    return txin
