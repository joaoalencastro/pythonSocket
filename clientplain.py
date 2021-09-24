#!/usr/bin/env python3

import socket
import hashlib
from datetime import datetime

### This script will send TCP requests to the HOST:PORT provided in chunks of BYTES

HOST = 'localhost'
PORT = 8088
BYTES = 128
FILE = 'Texts/rfc761.txt'

# make the hash string
# result = hashlib.md5(str(time).encode()).digest()
# result1 = hashlib.sha256(str(time).encode()).digest()
# result2 = hashlib.sha512(str(time).encode()).digest()
# resultTotal = result + result1 + result2

def utf8len(s):
    return len(s.encode('utf-8'))

# create an INET, STREAMing socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with open(FILE, 'r') as reader:
        s.connect((HOST, PORT))
        # get the current timestamp
        # time = datetime.now()

        fullText = reader.readlines()

        text = ''
        for text in fullText:
            text += text

            if len(text) < BYTES:
              continue

            #make it divisible by number of desired bytes
            while (len(text) % BYTES != 0):
                text = text[:-1]

            for i in range(1,len(text)+1):
                if i % BYTES == 0:
                    # send the result
                    s.sendall((text[i-BYTES:i]).encode())
                    # now wait for the response and save it to data
                    data = s.recv(1024)
                    
                    print('Received', repr(data))
            text = ''