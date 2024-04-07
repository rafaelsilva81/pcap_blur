import os
from scapy.all import rdpcap

def read_pcap(path):
  if os.path.exists(path):
    packets = rdpcap(path) # Função que le o arquivo PCAP e retorna um PacketList
    return packets
   