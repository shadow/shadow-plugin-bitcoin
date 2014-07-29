# Create and sign a transaction with a bogus key



from bitcoin.core import *
from bitcoin.script import *
from bitcoin.scripteval import *
from bitcoin.key import *
from bitcoin import base58
from cStringIO import StringIO

# ethalone keys
#ec_secret = 'a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e'
ec_secret = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'

def patched_set_pubkey(self, key):
    intercept = map(unhexlify, ['0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee'])
    cheat = unhexlify('04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a')
    if key in intercept:
        print 'cheating!'
        key = cheat
    self.mb = ctypes.create_string_buffer(key)
    ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

CKey.set_pubkey = patched_set_pubkey

k = CKey()
k.generate (ec_secret.decode('hex'))
print(k.get_privkey().encode('hex'))
print(k.get_pubkey().encode('hex'))
# not sure this is needed any more: print k.get_secret().encode('hex')

class Transaction():
    def __init__(self):
        self.vin = [] # staged txin's only. Might be less than in _ctx
        self._vout = []
        self._ctx = CTransaction()

    def append_txout(self, txout):
        txout.tx = self
        txout.idx = len(self._vout)
        self._vout.append(txout)

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
        assert self._tx._ctx.sha256 is not None
        return self._tx._ctx.sha256, self._idx

    @property
    def nValue(self):
        return self._ctxout.nValue

class TxIn():
    def __init__(self, txout, finalize):
        self.txout = txout
        self._finalize = finalize

    def finalize(self):
        assert self.txout.tx is not None
        self._finalize()

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

def tx_second():
    second_coinbase = CTransaction()
    second_coinbase.deserialize(StringIO(unhexlify("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000")))
    second_coinbase.calc_sha256()
    tx = tx_from_CTransaction(second_coinbase)
    return tx

def tx_coinbase(height):
    # Makes a coinbase transaction with a single input
    tx = Transaction()
    ctxin = CTxIn()
    ctxin.prevout.hash = 0L
    ctxin.prevout.n = 0xffffffff
    # after v2, coinbase scriptsig must begin with height
    ctxin.scriptSig = chr(0x03) + struct.pack('<I', height)[:3] 
    tx._ctx.vin.append(txin)
    return tx

def txpair_from_pubkey():
    """
    returns:
       txout: a txout containing a standard pay-to-pubkey (from coinbase #2)
       sign:  signs the transaction (using an interposed key)
    """
    txout = TxOut()
    txout.scriptPubKey = CScript(unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'))
    def sign(txfrom, ctx, idx):
        sighash, = SignatureHash(txout.scriptPubKey, ctx, idx, SIGHASH_ALL)
        sighash = ser_uint256(sighash)
        sig = k.sign(sighash) + chr(SIGHASH_ALL)
        assert len(sig) < OP_PUSHDATA1
        scriptSig = chr(len(sig)) + sig
        # Go ahead and set the 
        ctx.vin[idx].scriptSig = scriptSig
        if not VerifySignature(txfrom, tx, idx, SIGHASH_ALL):
            print "Warning: signature did not verify"
        return scriptSig
    return txout, sign

def txin_from_second_coinbase():
    """
    returns:
       txin: An (unsigned) CTxIn corresponding to the second coinbase bonus
       sign(idx,tx): produces a signature on tx satisfying the scriptPubKey in txin
           assumes that tx[idx] is txin
    """
    # 
    second_coinbase = CTransaction()
    second_coinbase.deserialize(StringIO(unhexlify("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000")))
    second_coinbase.calc_sha256()
    txin = CTxIn()
    txin.prevout.hash = second_coinbase.sha256
    txin.prevout.n = 0
    def sign(idx, tx):
        assert tx.vin[idx] is txin, "Trying to sign wrong txinput"
        scriptPubKey = CScript(unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'))
        key = k # The default key we use to sign the transaction
        sighash, = SignatureHash(scriptPubKey, tx, idx, SIGHASH_ALL)
        sighash = ser_uint256(sighash)
        sig = key.sign(sighash) + chr(SIGHASH_ALL)
        assert len(sig) < OP_PUSHDATA1
        return chr(len(sig)) + sig
    return txin, sign

def sign_transaction(tx, scriptPubKey, key):
    # Signing logic
    for idx,txin in enumerate(tx.vin):
        sighash, = SignatureHash(scriptPubKey, tx, idx, SIGHASH_SINGLE)
        sighash = ser_uint256(sighash)
        sig = key.sign(sighash) + chr(SIGHASH_SINGLE)
        assert len(sig) < OP_PUSHDATA1
        txin.scriptSig = chr(len(sig)) + sig
        txfrom = CTransaction()
        txfrom.deserialize(StringIO(unhexlify('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')))
        print txfrom
        if not VerifySignature(txfrom, tx, idx, SIGHASH_SINGLE):
            print "Warning: signature did not verify"

spent_coinbase_134 = "c48b46883778003413636b23233ab90179f7d45a756960858c3f63db517762bb"
def spend_coinbase(txhash):
    tx = CTransaction()
    txin, sign = txin_from_second_coinbase()
    txout = CTxOut()
    txout.nValue = 50 * 1e8
    txout.scriptPubKey = unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac')
    tx.vin.append(txin)
    tx.vout.append(txout)
    tx.vin[0].scriptSig = sign(0,tx)    
    #sign_transaction(tx, scriptPubKey, k)
    return tx

def spend_second_coinbase():
    # Create a transaction that spends the second coinbase
    txhash = '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098'
    return spend_coinbase(txhash)

def void_coinbase(height=0):
    tx = CTransaction()
    txin = CTxIn()
    txin.prevout.hash = 0L
    txin.prevout.n = 0xffffffff
    txin.scriptSig = chr(0x03) + struct.pack('<I', height)[:3]
    txout = CTxOut()
    txout.nValue = 25*1e8
    txout.scriptPubKey = unhexlify('76a91427a1f12771de5cc3b73941664b2537c15316be4388ac')
    tx.vin.append(txin)
    tx.vout.append(txout)
    return tx

def spend_p2sh():
    # Create a 15 (or 5) way multisig
    n_sigs = 3
    k.set_compressed(True)
    pk = k.get_pubkey()
    def push_script(s):
        assert len(s) <= 520
        if len(s) < OP_PUSHDATA1: op = chr(len(s))
        elif len(s) <= 255: op = chr(OP_PUSHDATA1) + struct.pack('<I', len(s))[:1]
        else: op = chr(OP_PUSHDATA2) + struct.pack('<I', len(s))[:2]
        return op + s
    redeemscript = chr(OP_1+n_sigs-1) + n_sigs*(push_script(pk)) + chr(OP_1+n_sigs-1) + chr(OP_CHECKMULTISIG)
    redeemscripthash = ser_uint160(Hash160(redeemscript))
    scriptPubKey = chr(OP_HASH160) + push_script(redeemscripthash) + chr(OP_EQUAL)

    def spend_coinbase(new_scriptPubKey):
        # second coinbase transaction
        txhash = '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098'
        scriptPubKey = CScript(unhexlify('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'))
        tx = CTransaction()
        txin = CTxIn()
        txin.prevout.hash = uint256_from_str(unhexlify(txhash)[::-1])
        txin.prevout.n = 0
        txout = CTxOut()
        txout.nValue = 50 * 1e8
        txout.scriptPubKey = new_scriptPubKey
        tx.vin.append(txin)
        tx.vout.append(txout)
        sign_transaction(tx, scriptPubKey, k)
        tx.calc_sha256()
        return tx

    tx1 = spend_coinbase(scriptPubKey)
    tx = CTransaction()
    txin = CTxIn()
    txin.prevout.hash = tx1.sha256
    txin.prevout.n = 0
    sig = k.sign('') + chr(SIGHASH_ALL)
    assert len(sig) < OP_PUSHDATA1
    txin.scriptSig = chr(OP_0) + n_sigs * push_script(sig) + push_script(redeemscript)
    assert len(txin.scriptSig) <= 1650 # This is 1650 for 0.9.3+, but the 0.9.2 limit is 500.
    assert len(txin.scriptSig) <= 500 
    txout = CTxOut()
    txout.nValue = 50 * 1e8
    txout.scriptPubKey = scriptPubKey
    tx.vin.append(txin)
    tx.vout.append(txout)
    return tx1,tx

def block_and_p2sh():
    tx1, tx2 = spend_p2sh()
    prevhash = "00000000000000005bb3427edaf9b435967c90a490f2b32cfa51f7c32db2397f" # Block 330334 on main chain
    nBits = 409544770
    height = 303335
    nTime = 1401458326
    ver = 2
    block = CBlock()
    block.hashPrevBlock = uint256_from_str(unhexlify(prevhash)[::-1])
    block.vtx.append(void_coinbase(height=height))
    block.vtx.append(tx1)
    block.nBits = nBits
    block.nNonce = 9999999 # Not a valid proof of work, but this is ok
    block.nTime = nTime
    block.nVersion = ver;
    block.hashMerkleRoot = block.calc_merkle()
    block.calc_sha256()
    print 'block:', hexlify(block.serialize())
    print 'blockhash:', hexlify(ser_uint256(block.sha256)[::-1])
    print 'merkleroot:', hexlify(ser_uint256(block.hashMerkleRoot)[::-1])
    tx1.calc_sha256()
    print 'tx1:', hexlify(tx1.serialize())
    print 'tx1hash:', hexlify(ser_uint256(tx1.sha256)[::-1]);
    print 'tx2:', hexlify(tx2.serialize())
    tx2.calc_sha256()
    print 'tx2hash:', hexlify(ser_uint256(tx2.sha256)[::-1]);
    return block, tx2


def block_with_spend():
    tx = spend_second_coinbase()
    if 0: # Builds on block 120594 on main chain
        prevhash = "0000000000004ba33ad245380d09ed2cf728753421550c23837ac3007ec4c25a"
        nBits = 453031340
        height = 120495
        nTime = 1303963120
        ver = 1
    if 1: # Builds on block 303333 on main chain
        prevhash = "00000000000000005bb3427edaf9b435967c90a490f2b32cfa51f7c32db2397f" # Block 330334 on main chain
        nBits = 409544770
        height = 303335
        nTime = 1401458326
        ver = 2
    block = CBlock()
    block.hashPrevBlock = uint256_from_str(unhexlify(prevhash)[::-1])
    block.vtx.append(void_coinbase(height=height))
    block.vtx.append(tx)
    block.nBits = nBits
    block.nNonce = 9999999 # Not a valid proof of work, but this is ok
    block.nTime = nTime
    block.nVersion = ver;
    block.hashMerkleRoot = block.calc_merkle()
    return block

def address_from_key(key):
    p = k.get_pubkey()
    pkh = '\x00' + ser_uint160(Hash160(p))
    print 'pkh', pkh
    chk = ser_uint256(Hash(pkh))[:4]
    return base58.encode(pkh+chk)

def wif_from_key(key):
    p = k.prikey
    assert len(p) == 32
    p = '\x80' + p #+ '\x01'
    print '2:', hexlify(p)
    h = ser_uint256(Hash(p))
    print '3:', hexlify(h)
    chk = h[:4]
    print '5:', hexlify(chk)
    return base58.encode(p+chk)
    
addr = address_from_key(k)
print addr

hash = 'Hello, world!'
print(k.verify(hash, k.sign(hash)))

tx = spend_second_coinbase()
print 'tx:', tx
print 'tx:', hexlify(tx.serialize())

blk = block_with_spend()
print 'blk:', hexlify(blk.serialize())
