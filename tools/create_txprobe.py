from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *
import time
from cStringIO import StringIO
from test_createtx import Transaction, void_coinbase, k, txpair_from_p2sh, get_txin_second
import logger
from txtools import *
from connector import *

def do_send(sock, msg):
    written = 0
    while (written < len(msg)):
        rv = sock.send(msg[written:], 0)
        if rv > 0:
            written = written + rv
        if rv < 0:
            raise Exception("Error on write (this happens automatically in python?)");

def get_cxns():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #socket.create_connection
    sock.connect("/tmp/bitcoin_control")
    cmsg = command_msg(commands.COMMAND_GET_CXN, 0)
    ser = cmsg.serialize()
    do_send(sock, ser)

    length = sock.recv(4, socket.MSG_WAITALL)
    length, = unpack('>I', length)
    infos = sock.recv(length, socket.MSG_WAITALL)
    # Each info chunk should be 36 bytes

    cur = 0
    while(len(infos[cur:cur+36]) > 0):
        cinfo = connection_info.deserialize(infos[cur:cur+36])
        print "{0} {1}:{2} - {3}:{4}".format(cinfo.handle_id, cinfo.remote_addr, cinfo.remote_port, cinfo.local_addr, cinfo.local_port)
        yield cinfo.handle_id[0]
        cur = cur + 36

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
    ORPHANS = []
    for i in range(n):
        tx_parent = Transaction()
        tx_parent.vin = [input1]
        _tx_parent_out,tx_parent_in = txpair_from_p2sh(nValue=0.008*COIN)
        tx_parent.append_txout(_tx_parent_out)
        tx_parent.finalize()
        PARENTS.append(tx_parent)

        tx_orphan = Transaction()
        tx_orphan.vin = [input2, tx_parent_in]
        _tx_orphan_out,tx_orphan_in = txpair_from_p2sh(nValue=0.005*COIN)
        tx_orphan.append_txout(_tx_orphan_out)
        tx_orphan.finalize()
        ORPHANS.append(tx_orphan)

    FLOOD = Transaction()
    FLOOD.vin = [input1]
    _flood_out,tx_flood_in = txpair_from_p2sh(nValue=0.008*COIN)
    FLOOD.append_txout(_flood_out)
    FLOOD.finalize()
    return PARENTS, ORPHANS, FLOOD

def make_block():
    block = CBlock()
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

def schedule(elems):
    # Rows and columns
    import math
    n = len(elems)
    sn = int(math.ceil(math.sqrt(n)))
    s = range(n)
    sets = []
    # Rows
    for i in range(sn):
        tgt = elems[i*sn:(i+1)*sn]
        tst = set(elems).difference(set(tgt))
        if not tgt: continue
        sets.append((tgt,tst))
    # Columns
    for i in range(sn):
        tgt = elems[i::sn]
        tst = set(elems).difference(set(tgt))
        sets.append((tgt,tst))
    return sets

def make_experiment2(path='./experiment2_payload.dat'):
    import time
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #socket.create_connection
    sock.connect("/tmp/bitcoin_control")

    # Reset all the connections
    print 'Resetting connections'
    n = 79
    cmsg = command_msg(commands.COMMAND_DISCONNECT, 0, [targets.BROADCAST])
    ser = cmsg.serialize()
    do_send(sock, ser)
    for i in range(1,n+1):
        msg = connect_msg('127.0.0.1', 8332+i, '0.0.0.0', 0)
        ser = msg.serialize()
        do_send(sock, ser)
    print 'Connecting'
    time.sleep(2)

    nodes = list(get_cxns())
    print 'Nodes:', nodes

    import math
    sn = int(math.ceil(math.sqrt(n)))
    sched = schedule(range(n))
    print 'sqrt(n):', sn
    print 'schedule:', len(sched)

    # 1. Create a setup transaction with enough inputs for 2 boosters per trial
    tx_setup = Transaction()
    tx_setup.vin = [get_txin_second()]
    tx_setup_ins = []
    for _ in sched:
        for _ in range(2):
            _out,_in = txpair_from_p2sh(nValue=0.01*COIN)
            tx_setup.append_txout(_out)
            tx_setup_ins.append(_in)
    tx_setup.finalize()

    # 1a. Add tx_setup to a block
    block = make_block()
    block.vtx.append(tx_setup._ctx)
    block.hashMerkleRoot = block.calc_merkle_root()

    PAYLOADS = []
    for i,(tgt,tst) in enumerate(sched):
        PARENTS, ORPHANS, FLOOD = create_txprobe(tx_setup_ins[2*i+0], tx_setup_ins[2*i+1], len(tgt))
        PAYLOADS.append((PARENTS, ORPHANS, FLOOD))
    return nodes, block, PAYLOADS


def check_logs(nodes, PARENTS, ORPHANS, FLOOD, logs):
    orphan_hashes = [Hash(o._ctx.serialize()) for o in ORPHANS]
    d = dict(zip(orphan_hashes, nodes))
    edges = set()
    for log in logs:
        if log.is_sender: continue
        msg = MsgSerializable.stream_deserialize(StringIO('\xf9'+log.bitcoin_msg))
        if msg.command != 'getdata': continue
        print log.handle_id
        connected = set(nodes)
        connected.remove(log.handle_id) # Remove self
        for i in msg.inv:
            connected.remove(d[i.hash])
        for i in connected:
            edges.add(tuple(sorted((log.handle_id-min(nodes)+1,i-min(nodes)+1))))
    for i,j in sorted(edges):
        print i, '<->', j
        yield i,j

def check_all_logs(nodes, PAYLOADS, logs):
    sched = schedule(nodes)
    edges = set()

    # First determine the edges to pay attention to
    d = {}
    expected = dict((n,[]) for n in nodes)
    assert(len(PAYLOADS) == len(sched))
    for (tgt,tst),(PARENTS,ORPHANS,_) in zip(sched,PAYLOADS):
        orphan_hashes = [Hash(o._ctx.serialize()) for o in ORPHANS]
        assert(len(orphan_hashes) == len(tgt))
        d.update(dict(zip(orphan_hashes, tgt)))
        for n in tst: expected[n] += orphan_hashes
    for n in nodes: expected[n] = set(expected[n])

    actual = dict((n,[]) for n in nodes)
    for log in logs:
        if log.is_sender: continue
        msg = MsgSerializable.stream_deserialize(StringIO('\xf9'+log.bitcoin_msg))
        if msg.command != 'getdata': continue
        for i in msg.inv:
            if i.hash in expected[log.handle_id]: 
                actual[log.handle_id].append(i.hash)
                
    for n in nodes: actual[n] = set(actual[n])

    for i in nodes:
        for h in expected[i]:
            j = d[h]
            if h not in actual[i]:
                edges.add(tuple(sorted((j-min(nodes)+1,i-min(nodes)+1))))

    for i,j in sorted(edges):
        print i, '<->', j
        yield i,j

def run_experiment2(nodes, block, PAYLOADS):
    import time

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #socket.create_connection
    sock.connect("/tmp/bitcoin_control")

    # Set up a sending thread and queue
    from threading import Lock, Thread
    lock = Lock()

    # Helper functions
    def register_block(blk):
        m = msg_block()
        m.block = blk
        cmsg = bitcoin_msg(m.serialize())
        ser = cmsg.serialize()
        lock.acquire()
        do_send(sock, ser)
        rid = sock.recv(4)
        lock.release()
        rid, = unpack('>I', rid)  # message is now saved and can be sent to users with this id
        return rid

    def register_tx(tx):
        m = msg_tx()
        m.tx = tx._ctx
        cmsg = bitcoin_msg(m.serialize())
        ser = cmsg.serialize()
        lock.acquire()
        do_send(sock, ser)
        rid = sock.recv(4)
        lock.release()
        rid, = unpack('>I', rid)  # message is now saved and can be sent to users with this id
        return rid

    def register_inv(txs):
        m = msg_inv()
        for tx in txs:
            inv = CInv()
            inv.type = 1 # TX
            inv.hash = Hash(tx._ctx.serialize())
            m.inv.append(inv)
        cmsg = bitcoin_msg(m.serialize())
        ser = cmsg.serialize()
        lock.acquire()
        do_send(sock, ser)
        rid = sock.recv(4)
        lock.release()
        rid, = unpack('>I', rid)  # message is now saved and can be sent to users with this id
        return rid

    def broadcast(rid):
        cmsg = command_msg(commands.COMMAND_SEND_MSG, rid, (targets.BROADCAST,))
        ser = cmsg.serialize()
        lock.acquire()
        do_send(sock, ser)
        lock.release()

    def send_to_nodes(rid, nodes):
        cmsg = command_msg(commands.COMMAND_SEND_MSG, rid, nodes)
        ser = cmsg.serialize()
        lock.acquire()
        do_send(sock, ser)
        lock.release()

    # Run the experiment!
    print 'Setup'
    broadcast(register_block(block))

    sched = schedule(nodes)
    global logs, all_logs
    all_logs = []
    print 'Reading'
    logsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    logsock.connect("/tmp/logger/clients/bitcoin_msg")

    for (target_set, test_set), (PARENTS, ORPHANS, FLOOD) in zip(sched, PAYLOADS):
        def g((target_set, test_set), (PARENTS, ORPHANS, FLOOD)):
            print "Targets:", target_set

            print 'Step 1: inv locking'
            broadcast(register_inv(PARENTS + [FLOOD]))
            time.sleep(1)

            print 'Step 2: send the flood'
            send_to_nodes(register_tx(FLOOD), test_set)

            print 'Step 3: prime the orphans'
            for n,orphan in zip(target_set,ORPHANS):
                send_to_nodes(register_tx(orphan), (n,))

            time.sleep(3) # Make sure the flood propagates

            print 'Step 4: send parents'
            for n,parent in zip(target_set,PARENTS):
                send_to_nodes(register_tx(parent), (n,))
            time.sleep(10)

            print 'Step 5: read back'
            send_to_nodes(register_inv(ORPHANS), test_set)
        Thread(target=g,args=((target_set, test_set), (PARENTS, ORPHANS, FLOOD))).start()
        #g()

    logs = []
    deadline = time.time() + 20
    def _read_logs():
        while(True):
            logsock.settimeout(deadline - time.time())
            try:
                length = logsock.recv(4, socket.MSG_WAITALL);
                length, = unpack('>I', length)
                logsock.settimeout(deadline - time.time())
                record = logsock.recv(length, socket.MSG_WAITALL)
            except socket.timeout: break
            log_type, timestamp, rest = logger.log.deserialize_parts(record)
            log = logger.type_to_obj[log_type].deserialize(timestamp, rest)
            logs.append(log)
            logsock.settimeout(None)
        print 'Done'
    t = Thread(target=_read_logs)
    t.start()
    t.join()
        
