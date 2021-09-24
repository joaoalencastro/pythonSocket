#!/usr/bin/env python3

import socket
from Crypto.Cipher import AES

### This script will send TCP requests to the HOST:PORT provided in chunks of BYTES

HOST = 'localhost'
PORT = 8088
BYTES = 32
FILE = 'Texts/rfc761.txt'
key = 'booRwoXXGGIzZdiG7qWv5t6M0gVW7YlO'.encode()

def utf8len(s):
    return len(s.encode('utf-8'))

# create an INET, STREAMing socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with open(FILE, 'r') as reader:
        s.connect((HOST, PORT))
        # get the current timestamp
        # time = datetime.now()
        
        fullText = reader.readlines()

        ciphertextbytes = ''.encode()
        for text in fullText:
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(text.encode())
            ciphertextbytes += ciphertext

            if len(ciphertextbytes) < BYTES:           # if hash text is not big enough for bytes, accumulate
                continue

            #make it divisible by number of desired bytes
            while (len(ciphertextbytes) % BYTES != 0):
                ciphertextbytes = ciphertextbytes[:-1]

            for i in range(1,len(ciphertextbytes)+1):
                if i % BYTES == 0:
                    # send the result
                    s.sendall(ciphertextbytes[i-BYTES:i]) #.encode())
                    # now wait for the response and save it to data
                    data = s.recv(1024)
                    
                    print('Received', repr(data))
            ciphertextbytes = ''.encode()