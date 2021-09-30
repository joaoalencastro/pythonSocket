#!/usr/bin/env python3

import socket

host = '0.0.0.0'
port = 20001
bufferSize = 1024
msgFromServer = "Hello UDP Client"
bytesToSend = msgFromServer.encode()

# create an INET, STREAMing socket | Using with statement means we don't have to close the socket
with socket.socket(socket.AF_INET, type=socket.SOCK_DGRAM) as serversocket:
    # bind the socket to a public host, and a well-known port
    serversocket.bind((host, port))
    print("UDP server up and listening...")

    while True:
        # accept connections from outside
        bytesAddressPair = serversocket.recvfrom(bufferSize)
        
        # message = bytesAddressPair[0]
        # address = bytesAddressPair[1]

        # serversocket.sendto(bytesToSend, address)