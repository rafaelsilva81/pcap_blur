import logging
import os
import platform
from scapy.all import Packet, rdpcap, wrpcap

from steps.app_data import anon_app_data 
from steps.checksum import recalculate
from steps.timestamps import anon_timestamps
from steps.port_numbers import anon_port_numbers
from steps.mac_address import anon_mac_address
from steps.ip_address import anon_ip_address

def anonymize_pcap(packet: Packet, index: int) -> Packet:
  logging.info(f"Anonymizing packet {index + 1}")
  logging.debug(f"Packet summary: {packet.summary()}")
  packet = anon_app_data(packet)
  packet = anon_timestamps(packet)
  packet = anon_port_numbers(packet)
  packet = anon_mac_address(packet)
  packet = recalculate(packet)
  packet = anon_ip_address(packet)


  return packet
  
  
def main():
  logging.basicConfig(filename='log.txt',filemode='w', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d%H:%M:%S')
  
  path = "input.pcap"

  if os.path.exists(path):
    file_size = os.path.getsize(path)  # Size of packet trace in bytes
    packets = rdpcap(path)
    packet_count = len(packets)  # Amount of packets in the packet trace
        
    # Log the details
    logging.info(f"Path of the packet trace: {path}")
    logging.info(f"Size of the packet trace: {file_size} bytes")
    logging.info(f"Amount of packets in the packet trace: {packet_count}")
    logging.info(f"Operating system: {platform.system()} {platform.release()}")
    logging.info(f"Processor: {platform.processor()}")
    logging.info(f"Machine: {platform.machine()}")
    logging.info(f"Node/Host name: {platform.node()}")
        
    anonymized_packets = [anonymize_pcap(packet, index) for index, packet in enumerate(packets)]
    wrpcap("output.pcap", anonymized_packets)
  else:
    logging.error(f"File not found: {path}")

  

if __name__ == "__main__":
  main()