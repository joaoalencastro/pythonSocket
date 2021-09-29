import socket
from time import sleep

file              = 'Texts/rfc761.txt'
serverAddressPort = ('127.0.0.1', 20001)
bufferSize        = 1024

# Create a UDP socket at client side
with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as UDPClientSocket:
  with open(file, 'r') as reader:
    text = reader.read()
    times = len(text) / 1024
    times = int(times)

    for i in range(times+1):
      chunk = text[i*1024:(i+1)*1024].encode()
      # Send to server using created UDP socket
      UDPClientSocket.sendto(chunk, serverAddressPort)
