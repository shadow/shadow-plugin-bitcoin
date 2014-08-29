from binascii import hexlify, unhexlify
from bitcoin.core import *
from bitcoin.core.key import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin import base58
from bitcoin.messages import *
import time
from cStringIO import StringIO
from test_createtx import Transaction, void_coinbase, k

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

def make_experiment2(path='./experiment2_payload.dat'):
    import time
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #socket.create_connection
    sock.connect("/tmp/bitcoin_control")

    # Reset all the connections
    print 'Resetting connections'
    n = 100
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

    # 1. Create a setup transaction with enough inputs 2 boosters
    tx_setup = Transaction()
    tx_setup.vin = [get_txin_second()]
    tx_setup_ins = []
    for i in range(2):
        _out,_in = txpair_from_p2sh(nValue=0.01*COIN)
        tx_setup.append_txout(_out)
        tx_setup_ins.append(_in)
    tx_setup.finalize()

    # 1a. Add tx_setup to a block
    block = make_block()
    block.vtx.append(tx_setup._ctx)
    block.hashMerkleRoot = block.calc_merkle_root()

    PARENTS, ORPHANS, FLOOD = create_txprobe(tx_setup_ins[0], tx_setup_ins[1], len(nodes))
    return nodes, block, PARENTS, ORPHANS, FLOOD


def check_logs(nodes, block, PARENTS, ORPHANS, FLOOD, logs):
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


def run_experiment2(nodes, block, PARENTS, ORPHANS, FLOOD):
    import time

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #socket.create_connection
    sock.connect("/tmp/bitcoin_control")

    def register_block(blk):
        m = msg_block()
        m.block = blk
        cmsg = bitcoin_msg(m.serialize())
        ser = cmsg.serialize()
        do_send(sock, ser)
        rid = sock.recv(4)
        rid, = unpack('>I', rid)  # message is now saved and can be sent to users with this id
        return rid

    def register_tx(tx):
        m = msg_tx()
        m.tx = tx._ctx
        cmsg = bitcoin_msg(m.serialize())
        ser = cmsg.serialize()
        do_send(sock, ser)
        rid = sock.recv(4)
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
        do_send(sock, ser)
        rid = sock.recv(4)
        rid, = unpack('>I', rid)  # message is now saved and can be sent to users with this id
        return rid

    def broadcast(rid):
        cmsg = command_msg(commands.COMMAND_SEND_MSG, rid, (targets.BROADCAST,))
        ser = cmsg.serialize()
        do_send(sock, ser)

    def send_to_nodes(rid, nodes):
        cmsg = command_msg(commands.COMMAND_SEND_MSG, rid, nodes)
        ser = cmsg.serialize()
        do_send(sock, ser)

    target_set = (nodes[0],)
    test_set = nodes[1:]

    # Run the experiment!
    print 'Step 1: setup'
    broadcast(register_block(block))

    print 'Step 2: inv locking'
    broadcast(register_inv(PARENTS))
    time.sleep(0.5)

    print 'Step 3: prime the orphans'
    for n,orphan in zip(nodes,ORPHANS):
        send_to_nodes(register_tx(orphan), (n,))
    time.sleep(1)

    print 'Step 4: send parents'
    for n,parent in zip(nodes,PARENTS):
        send_to_nodes(register_tx(parent), (n,))
    time.sleep(10)

    print 'Step 5: read back'
    logsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    logsock.connect("/tmp/logger/clients/bitcoin_msg")

    broadcast(register_inv(ORPHANS))

    global logs
    logs = []
    while(True):
        length = logsock.recv(4, socket.MSG_WAITALL);
        length, = unpack('>I', length)
        record = logsock.recv(length, socket.MSG_WAITALL)
        log_type, timestamp, rest = logger.log.deserialize_parts(record)
        log = logger.type_to_obj[log_type].deserialize(timestamp, rest)
        logs.append(log)
        print log
