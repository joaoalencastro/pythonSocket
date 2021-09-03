# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
from bientropy import bien, tbien
from bitstring import Bits
from math import log2
from pandas import DataFrame

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
  response = es.search(index=index, body={"size":10000,"query":{"match_all":{}}}, scroll='1s')
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

def calculate_bien(string):
  return bien(Bits(string))

def calculate_tbien(string):
  return tbien(Bits(string))

if __name__ == '__main__':
  es = connect_elasticsearch()

  indices = get_packet_indices(es)
  print(indices)
  index = input("Chose from above which index to process: ")

  # packets is a list of dictionaries, with each dictinary being a packet
  packets = get_packets_from_index(es, index)

  # index_metadata will be the list of dictionaries of the processed data
  records = []

  for packet in packets:
    raw_data = is_udp(packet)
    if raw_data != None:
      new_doc = {}
      raw_data = '0x' + raw_data

      new_doc['id'] = packet['_id']
      new_doc['srcip'] = packet['_source']['layers']['ip']['ip_ip_src']
      new_doc['dstip'] = packet['_source']['layers']['ip']['ip_ip_dst']
      new_doc['srcport'] = packet['_source']['layers']['udp']['udp_udp_srcport']
      new_doc['dstport'] = packet['_source']['layers']['udp']['udp_udp_dstport']
      new_doc['shannon'] = float(calculate_shannon_entropy(raw_data[2:]))
      new_doc['bien'] = float(calculate_bien(raw_data))
      new_doc['tbien'] = float(calculate_tbien(raw_data))

      records.append(new_doc)

  index_metadata = DataFrame.from_records(records)
  
  request_body = {
    # "settings" : {
    #   "number_of_shards": 1,
    #   "number_of_replicas": 1
    # },
    'mappings': {
      'properties': {
        'id': {'type': 'keyword'},
        'srcip': { 'type': 'keyword'},
        'dstip': {'type': 'keyword'},
        'srcport': {'type': 'keyword'},
        'dstport': {'type': 'keyword'},
        'shannon': {'type': 'long'},
        'bien': {'type': 'long'},
        'tbien': {'type': 'long'}
      }}
  }
  new_index = index+'-processed'
  print("creating {} index...".format(new_index))
  es.indices.create(index=new_index, body = request_body)

  # preparing data to be sent to elastic
  bulk_data = []

  for index, row in index_metadata.iterrows():
    data_dict = {}
    for j in range(len(row)):
        data_dict[index_metadata.columns[j]] = row[j]
    op_dict = {
        "index": {
            "_index": new_index,
            "_type": '_doc',
            "_id": data_dict['id']
        }
    }
    bulk_data.append(op_dict)
    bulk_data.append(data_dict)

  print(bulk_data)
  res = es.bulk(index = new_index, body = bulk_data)

  # check data is in there, and structure in there
  #es.search(index = new_index, body={"query": {"match_all": {}}})
  #es_indices.get_mapping(index = new_index)
