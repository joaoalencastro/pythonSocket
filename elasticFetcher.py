# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
from math import log2

def connect_elasticsearch():
  es = None
  es = Elasticsearch([{'host':'192.168.0.142', 'port': 9200}])
  if es.ping():
    print('Yay Connected')
  else:
    print('Awww it could not connect!')
  return es

def get_packet_indices(es):
  packets_indices = []
  for index in es.indices.get('*'):
    if "packets-" in index:
      packets_indices.append(index)
  return packets_indices

def get_packets_from_index(es, index):
  # Me retorna uma lista de dicionarios, onde cada dicionário é um pacote
  response = es.search(index=index, body={"query":{"match_all":{}}})
  print("Querying {} packets from index '{}'...".format(response["hits"]["total"]["value"], index))
  return response["hits"]["hits"]

def get_ids_from_index(es, index):
  response = es.search(index=index, body={"query":{"match_all":{}},"stored_fields": []})
  print("============== IDs ==============")
  print(response)

def is_udp(packet):
  if "udp_raw" in packet["_source"]["layers"]:
    return packet["_source"]["layers"]["udp_raw"]
  else:
    return None

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

if __name__ == '__main__':
  es = connect_elasticsearch()

  packets = []
  for index in get_packet_indices(es):
    packets.append(get_packets_from_index(es, index))
    #get_ids_from_index(es, index)

  for packet in packets[1]:
    raw_data = is_udp(packet)
    if raw_data != None:
      print("""Packet '{}'
                Src IP: '{}'
                Dst IP: '{}'
                Src Port: '{}'
                Dst Port: '{}'
                Entropy: {} bits""".format(packet['_id'],
                                            packet['_source']['layers']['ip']['ip_ip_src'],
                                            packet['_source']['layers']['ip']['ip_ip_dst'],
                                            packet['_source']['layers']['udp']['udp_udp_srcport'],
                                            packet['_source']['layers']['udp']['udp_udp_dstport'],
                                            calculate_shannon_entropy(raw_data)))
      print("=============================================")