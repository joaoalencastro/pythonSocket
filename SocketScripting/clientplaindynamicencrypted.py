#!/usr/bin/env python3

import socket

from Crypto.Cipher import AES

### This script will send TCP requests to the HOST:PORT provided in chunks of BYTES

HOST = 'localhost'
PORT = 8088
FILE = 'Texts/rfc761.txt'
KEY = 'booRwoXXGGIzZdiG7qWv5t6M0gVW7YlO'.encode()

# create an INET, STREAMing socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with open(FILE, 'r') as reader:
        s.connect((HOST, PORT))

        text = reader.read()
        cipher = AES.new(KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())

        times = len(ciphertext) / 1024
        times = int(times)

        for i in range(times+1):
            # send the result
            s.sendall(ciphertext[i*1024:(i+1)*1024])
            # now wait for the response and save it to data
            data = s.recv(1024)

            print('Received', repr(data))

        # s.sendall(text[times*1024:].encode())
        # data = s.recv(1024)
        # print('Received', repr(data))