# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
from bientropy import bien, tbien
from bitstring import Bits
from math import log2
from pandas import DataFrame

def connect_elasticsearch():
  host = input('Please, enter elastic host: ')

  es = None
  es = Elasticsearch([{'host':host, 'port': 9200}])
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

def get_transport_protocol(packet):
  if "udp" in packet["_source"]["layers"]:
    return "udp"
  elif "tls" in packet["_source"]["layers"]:
    return "tls"
  elif "tcp" in packet["_source"]["layers"]:
    return "tcp"
  else:
    return None

def get_payload(protocol, packet):
  # Returns the payload
  if protocol == 'udp':
    payload = packet["_source"]["layers"]["udp_raw"]                  # this data is in the hex format without :
  elif protocol == 'tcp' and "tcp_tcp_payload" in packet["_source"]["layers"]["tcp"]:
    payload = packet["_source"]["layers"]["tcp"]["tcp_tcp_payload"]   # this data is in the hex format with :
    payload = payload.split(':')
    payload = ''.join(payload)
  elif protocol == 'tls' and "tls_tls_app_data" in packet["_source"]["layers"]["tls"]:
    payload = packet["_source"]["layers"]["tls"]["tls_tls_app_data"]  # this data is in the hex format with :
    payload = payload.split(':')
    payload = ''.join(payload)
  else:
    payload = None
  return payload

def get_ports(protocol, packet):
  ports = []
  if protocol == 'udp': 
    ports.append(packet['_source']['layers']['udp']['udp_udp_srcport'])
    ports.append(packet['_source']['layers']['udp']['udp_udp_dstport'])
  else: 
    ports.append(packet['_source']['layers']['tcp']['tcp_tcp_srcport'])
    ports.append(packet['_source']['layers']['tcp']['tcp_tcp_dstport'])
  return ports

def get_payload_size(protocol, packet):
  # Returns the payload size of the Transport Layer
  if protocol == 'udp':
    size = packet["_source"]["layers"]["udp"]["udp_udp_length"]
  elif protocol == 'tcp' or protocol == 'tls' and "tcp_tcp_payload" in packet["_source"]["layers"]["tcp"]:
    size = packet["_source"]["layers"]["tcp"]["tcp_tcp_len"]
  else:
    size = None
  return size

def calculate_shannon_entropy(string):
    """
    Calculates the standardized Shannon entropy for the given string. (modificada por mim)

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
    return -ent/log2(size)

def calculate_bien(string):
  return bien(Bits(string))

def calculate_tbien(string):
  return tbien(Bits(string))

def write_df_to_csv(df, file):
  df.to_csv('Outputs/'+file, index=False)

def truncate_hex(data, bytes):
  '''
  Make it divisible by number of bytes provided
  This only works for hex strings
  '''
  # First, we need the first 256 bytes of our data in ASCII, which means 512 hex characters. The first 256bytes is arbitrary
  data = data[:512]
  # Then, we iterate it and chop the last char until is divisible by the number of bytes provided
  while (len(data) % bytes * 2 != 0):
      data = data[:-1]
  if len(data) < 64:
    return None
  return data

def sliding_window(data, test, n=32):
  '''
    Receives the data and the type of test it has to work (probably entropy) with and returns the mean/average of all windows of data entropy
    n is the size of the sliding window in bytes
    Returns the average of the vector formed by the results of the tests made in each chunk of string
  '''
  if len(data) < 64:
    if test == 'shannon': return float(calculate_shannon_entropy(data))
    elif test == 'bien': return float(calculate_bien('0x'+data))
    elif test == 'tbien': return float(calculate_tbien('0x'+data))
  else:
    data = truncate_hex(data, 32)  # this will make the hex raw data be divisible by 32 so we can use sliding window
  if test != 'shannon' and test != 'bien' and test != 'tbien':
    print("Non existing type of test or null data.")
    return None
  elif data == None or len(data) == 0: return None
  elif test == 'shannon':
    # We do not need a sliding window in this case.
    return float(calculate_shannon_entropy(data)) # for shannon's entropy we don't need the '0x'
  sum = 0
  windowsize = n * 2
  windowsnum = int(len(data)/windowsize)
  for i in range(1, windowsnum + 1):
    hex_data = '0x' + data[(i - 1) * windowsize : i * windowsize]
    if test == 'bien':
      sum += float(calculate_bien(hex_data))
    else:
      sum += float(calculate_tbien(hex_data))
  avg = sum/windowsnum
  return avg

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
    # Collect packet's intel
    tp = get_transport_protocol(packet)
    raw_data = get_payload(tp, packet)
    ports = get_ports(tp, packet) # ports is a two element vector with the source and destiny ports information
    payload_size = get_payload_size(tp, packet)

    if raw_data != None and payload_size != None and 'ip' in packet['_source']['layers']:
      new_doc = {}

      new_doc['id'] = packet['_id']
      new_doc['proto'] = tp
      new_doc['srcip'] = packet['_source']['layers']['ip']['ip_ip_src']
      new_doc['dstip'] = packet['_source']['layers']['ip']['ip_ip_dst']
      new_doc['srcport'] = ports[0]
      new_doc['dstport'] = ports[1]
      new_doc['payload_size'] = payload_size
      new_doc['shannon'] = sliding_window(raw_data, 'shannon')
      new_doc['bien'] = sliding_window(raw_data, 'bien')
      new_doc['tbien'] = sliding_window(raw_data, 'tbien')

      records.append(new_doc)

  index_metadata = DataFrame.from_records(records)
  
  request_body = {
    'mappings': {
      'properties': {
        'id': {'type': 'keyword'},
        'proto': {'type': 'keyword'},
        'srcip': { 'type': 'keyword'},
        'dstip': {'type': 'keyword'},
        'srcport': {'type': 'keyword'},
        'dstport': {'type': 'keyword'},
        'payload_size' : {'type': 'long'},
        'shannon': {'type': 'long'},
        'bien': {'type': 'long'},
        'tbien': {'type': 'long'}
      }
    }
  }
  new_index = index+'-processed'
  print("creating {} index...".format(new_index))

  # Before writing data in Elastic, write data to a csv
  write_df_to_csv(index_metadata, new_index) 

  # Now, create index pattern on Elastic
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
