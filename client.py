#!/usr/bin/env python3

import socket
import hashlib
from datetime import datetime

HOST = '127.0.0.1'
PORT = 8080

# create an INET, STREAMing socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # now connect to the web server on port 80 - the normal http port
    s.connect((HOST, PORT))
    # get the current timestamp
    time = datetime.now()
    # make the hash string
    result = hashlib.md5(str(time).encode())
    # send the result
    s.sendall(result.digest())
    # now wait for the response and save it to data
    data = s.recv(1024)

print('Received', repr(data))