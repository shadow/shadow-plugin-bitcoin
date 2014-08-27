import socket
import os
import struct

class Connector():
    def __init__(self, path='/tmp/bitcoin_control'):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        self.s = s

class MSG():
    BITCOIN_PACKED_MESSAGE = 1
    COMMAND = 2
    REGISTER = 3
    CONNECT = 4
    types = [BITCOIN_PACKED_MESSAGE, COMMAND, REGISTER, CONNECT]
    

def make_message(msg_type, payload):
    assert msg_type in MSG.types
    struct.pack("c")
    

class GetNodes(Connector):
    def getnodes():
        """
struct sockaddr_in{
  short sin_family;
  unsigned short sin_port;
  IN_ADDR sin_addr;
  char sin_zero[8];
};
"""
        payload = struct.pack()
    


def make_ipv4():
    """
    struct in_addr:
        uint32_t s_addr

    struct sockaddr_in:
        unsigned short int sin_family
        uint16_t sin_port
        in_addr sin_addr
    """
    pass
