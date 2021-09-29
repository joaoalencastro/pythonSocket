import socket
from Crypto.Cipher import AES

file              = 'Texts/rfc761.txt'
serverAddressPort = ('127.0.0.1', 20001)
bufferSize        = 1024
bytes             = 32
key               = 'booRwoXXGGIzZdiG7qWv5t6M0gVW7YlO'.encode()

# Create a UDP socket at client side
with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as UDPClientSocket:
  with open(file, 'r') as reader:
    text = reader.readlines()

    bytesToSend = ''.encode()
    for line in text:
      cipher = AES.new(key, AES.MODE_EAX)
      ciphertext, tag = cipher.encrypt_and_digest(line.encode())
      bytesToSend += ciphertext

      if len(bytesToSend) < bytes:
        continue

      #make it divisible by number of desired bytes
      while (len(bytesToSend) % bytes != 0):
        bytesToSend = bytesToSend[:-1]

      for i in range(1,len(bytesToSend)+1):
        if i % bytes == 0:
          chunk = bytesToSend[i-bytes:i]
          # Send to server using created UDP socket
          UDPClientSocket.sendto(chunk, serverAddressPort)
          # Receive msgs from client if you'd like:
          # msgFromServer = UDPClientSocket.recvfrom(bufferSize)
          # print(msgFromServer)
      bytesToSend = ''.encode()