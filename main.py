from scapy.all import Packet, rdpcap, wrpcap

from steps.app_data import anon_app_data 
from steps.checksum import recalculate

def anonymize_pcap(packet: Packet) -> Packet:
  packet = anon_app_data(packet)
  packet = recalculate(packet)
  return packet
  
  
def main():
  packets = rdpcap("input.pcap")
  anonymized_packets = [anonymize_pcap(packet) for packet in packets]
  wrpcap("output.pcap", anonymized_packets)
  

if __name__ == "__main__":
  main()