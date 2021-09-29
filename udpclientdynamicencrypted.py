import socket
from time import sleep
from Crypto.Cipher import AES

file              = 'Texts/rfc761.txt'
serverAddressPort = ('127.0.0.1', 20001)
bufferSize        = 1024
key = 'booRwoXXGGIzZdiG7qWv5t6M0gVW7YlO'.encode()

# Create a UDP socket at client side
with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as UDPClientSocket:
  with open(file, 'r') as reader:
    text = reader.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    times = len(ciphertext) / 1024
    times = int(times)

    for i in range(times+1):
      chunk = ciphertext[i*1024:(i+1)*1024]
      # Send to server using created UDP socket
      UDPClientSocket.sendto(chunk, serverAddressPort)
