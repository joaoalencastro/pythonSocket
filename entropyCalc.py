# -*- coding: utf-8 -*-

import pandas as pd
import scipy.stats as st
from hashlib import md5, sha256, sha512
import argparse
from math import log2
import sys
import os
import codecs
from scapy.utils import *
from scapy.layers.l2 import Ether, Dot3
from scapy.layers.inet import IP, TCP

def listString(text):
  return [char for char in text]

def makeHash(text):
  """Returns a dict containing the original text, and then md5, sha256 and sha512 hashes hex values"""
  hashes = {}
  # hashes["Original"] = text
  # hashes["MD5"] = md5(text.encode()).digest().decode('UTF-8', 'replace')
  # hashes["SHA256"] = sha256(text.encode()).digest().decode('UTF-8', 'replace')
  # hashes["SHA512"] = sha512(text.encode()).digest().decode('UTF-8', 'replace')

  #hashes['originalHex'] = text
  hashes["Original"] = text.encode().hex()
  hashes["MD5"] = md5(text.encode()).hexdigest()
  hashes["SHA256"] = sha256(text.encode()).hexdigest()
  hashes["SHA512"] = sha512(text.encode()).hexdigest()
  return hashes

def calcEntropy(value):
  pd_series = pd.Series(listString(value))
  counts = pd_series.value_counts()
  # If only probabilities pk are given, the entropy is calculated as S = -sum(pk * log(pk), axis=axis)
  return st.entropy(counts)

def calculate_shannon_entropy(string):
    """
    Calculates the Shannon entropy for the given string. (modificada por mim)

    :param string: String to parse.
    :type string: str

    :returns: Shannon entropy (min bits per hex-character).
    :rtype: float
    """
    #Não é mais necessário fazer essa checagem, já que string não faz mais parte do tipo 'unicode'
    #if isinstance(string, unicode):
    #    string = string.encode("ascii")
    ent = 0.0
    alphabet = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    if len(string) < 2:
      return ent
    size = float(len(string)) 
    for b in range(15): # Para usar ASCII, troque para 127
      freq = string.count(alphabet[b])
      if freq > 0:
        freq = float(freq) / size
        ent = ent + freq * log2(freq)
    return -ent

def process_pcap(pcap_file):
  print('Opening {}...'.format(pcap_file))

  f = rdpcap(pcap_file)
  
  print('{} contains {} packets'.format(pcap_file, f))
  # Create list of dictionaries called connections
  connections = []

  for packet in f:
    if isinstance(packet, Dot3):
      # LLC packet's type is Dot3, not Ether. They do not matter.
      continue
    
    if packet.type == 34525:
      # Check if its IPv4: 2048 or IPv6: 34525. If it's IPv6, it doesn't matter
      continue

    ip_pkt = packet.getlayer(IP)
    if isinstance(ip_pkt, type(None)) or ip_pkt.proto != 6:
      # If it's not a TCP, it does not matter.
      continue

    # It's a valid packet 
    #packet.show()


def main():
  parser = argparse.ArgumentParser()
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("--text-file", metavar="<text file name>", \
                        help="Text file to parse, extract hashes, and calculate entropy.", dest="file")
  group.add_argument("--pcap-file", metavar="<pcap file name>", \
                        help="Pcap file to parse and calculate entropy", dest="file")
  args = parser.parse_args()

  file_name = args.file

  if not os.path.isfile(file_name):
    print('"{}" does not exist'.format(file_name), file=sys.stderr)
    sys.exit(-1)
  
  if '.txt' in file_name:
    with open(file_name, 'r') as f:
      # Slurp the whole file and efficiently convert it to hex all at once
      #hexdata = binascii.hexlify(f.read())
      data = f.read()

      print("\nTexto utilizado: {}".format(data))
      print("Todos os formatos são apresentados em hexadecimal\n")

      for key,value in makeHash(data).items():
        print("Formato {}: {}".format(key,value))
        print("   Sua entropia: {} bits.\n".format(calculate_shannon_entropy(value)))

      print('=================================================FIM=================================================\n')
  elif '.pcap' in file_name:
    process_pcap(file_name)
  else:
    print('"{}" does not correspond to the specified type'.format(file_name), file=sys.stderr)

if __name__ == '__main__':
  main()