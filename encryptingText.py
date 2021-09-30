import elasticFetcher
from Crypto.Cipher import AES

file = 'Texts/rfc761.txt'
key = 'booRwoXXGGIzZdiG7qWv5t6M0gVW7YlO'.encode()



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