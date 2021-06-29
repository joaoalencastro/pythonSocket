#!/usr/bin/env python3

import socket

'''
### Este código está sendo baseado na seguinte página web:
### https://docs.python.org/3/howto/sockets.html
'''

HOST = '127.0.0.1'
PORT = 8080

# create an INET, STREAMing socket | Using with statement means we don't have to close the socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
    # bind the socket to a public host, and a well-known port
    serversocket.bind((HOST, PORT))
    # become a server socket
    serversocket.listen(5)

    while True:
        # accept connections from outside
        (conn, addr) = serversocket.accept()
        # now do something with the clientsocket
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
        # in this case, we'll pretend this is a threaded server
        #ct = client_thread(clientsocket)
        #ct.run()
