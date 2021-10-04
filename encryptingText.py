import elasticFetcher
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encryptbychunks():
  with open('udp_encrypted_test.txt','r') as reader:
    text = reader.getlines()
    for line in text:
      line = line.encode()
      key = get_random_bytes(16)
      cipher = AES.new(key, AES.MODE_EAX)
      ciphertext, tag = cipher.encrypt_and_digest(line)

      file_out = open("encrypted.bin", "wb")
      [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
      file_out.close()

      file_in = open("encrypted.bin", "rb")
      nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

      cipher = AES.new(key, AES.MODE_EAX, nonce)
      recoverdata = cipher.decrypt_and_verify(ciphertext, tag)
      print(recoverdata)

def process(file, key):
  with open(file, 'r') as reader:
    text = reader.read()
    print("RFC761 in plaintext:")
    print(" Shannon: {}".format(elasticFetcher.calculate_shannon_entropy(text.encode().hex())))
    print(" Bien: {}".format(elasticFetcher.sliding_window(elasticFetcher.truncate_hex(text.encode().hex(), 32), 'bien')))
    print(" TBien: {}".format(elasticFetcher.sliding_window(elasticFetcher.truncate_hex(text.encode().hex(), 32), 'tbien')))

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    print("RFC761 in AES 256")
    print(" Shannon: {}".format(elasticFetcher.calculate_shannon_entropy(ciphertext.hex())))
    print(" Bien: {}".format(elasticFetcher.sliding_window(elasticFetcher.truncate_hex(ciphertext.hex(), 32), 'bien')))
    print(" TBien: {}".format(elasticFetcher.sliding_window(elasticFetcher.truncate_hex(ciphertext.hex(), 32), 'tbien')))

def main():
  file = 'Texts/rfc761.txt'
  key = 'booRwoXXGGIzZdiG7qWv5t6M0gVW7YlO'.encode()
  process(file, key)

if __name__ == '__main__':
  main()