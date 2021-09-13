#!/usr/bin/env python3

import socket
import hashlib
from datetime import datetime

HOST = '192.168.56.2'
PORT = 8088

# create an INET, STREAMing socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # now connect to the web server on port 80 - the normal http port
    s.connect((HOST, PORT))
    # get the current timestamp
    time = datetime.now()
    # make the hash string
    result = hashlib.md5(str(time).encode()).digest()
    result1 = hashlib.sha256(str(time).encode()).digest()
    result2 = hashlib.sha512(str(time).encode()).digest()
    resultTotal = result + result1 + result2
    # send the result
    s.sendall(resultTotal)
    # now wait for the response and save it to data
    data = s.recv(1024)

print('Received', repr(data))