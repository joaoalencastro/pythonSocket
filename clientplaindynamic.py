#!/usr/bin/env python3

import socket
import hashlib
from datetime import datetime

### This script will send TCP requests to the HOST:PORT provided in chunks of BYTES

HOST = 'localhost'
PORT = 8088
FILE = 'Texts/rfc761.txt'

def utf8len(s):
    return len(s.encode('utf-8'))

# create an INET, STREAMing socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with open(FILE, 'r') as reader:
        s.connect((HOST, PORT))
        # get the current timestamp
        # time = datetime.now()

        text = reader.read()
        times = len(text) / 1024
        #if times < 1: times = 0
        times = int(times)

        for i in range(times+1):
            # send the result
            s.sendall(text[i*1024:(i+1)*1024].encode())
            # now wait for the response and save it to data
            data = s.recv(1024)

            print('Received', repr(data))

        # s.sendall(text[times*1024:].encode())
        # data = s.recv(1024)
        # print('Received', repr(data))