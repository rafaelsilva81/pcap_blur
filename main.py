import logging
import os
import platform
import sys
from scapy.all import Packet, rdpcap, wrpcap

from utils import check_checksum
from steps import anon_app_data, recalculate, anon_timestamps, anon_port_numbers, anon_mac_address, anon_ip_address

def anonymize_pcap(packet: Packet) -> Packet:


  packet = anon_app_data(packet)
  packet = anon_timestamps(packet)
  packet = anon_port_numbers(packet)
  packet = anon_mac_address(packet)
  packet = recalculate(packet)
  packet = anon_ip_address(packet)

  check_checksum(packet)


  return packet
  
  
def main(path):
    logging.basicConfig(filename='log.txt',filemode='w', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

    if os.path.exists(path):
        file_size = os.path.getsize(path)  # Size of packet trace in bytes
        packets = rdpcap(path)
        packet_count = len(packets)  # Amount of packets in the packet trace
            
        # Log the details
        logging.info(f"Original file: {os.path.basename(path)} - {file_size} bytes - {packet_count} packets")
        logging.info(f"Machine information: {platform.processor()} - {platform.platform()} - {platform.architecture()[0]}")
        logging.info(f"Node/Host name: {platform.node()}")
            
        anonymized_packets = [anonymize_pcap(packet) for packet in packets]
        file_name = path.replace(".pcap", "_out.pcap")
        wrpcap(file_name, anonymized_packets)
        print(f"Anonymized file saved to {file_name}")

    else:
        logging.error(f"File not found: {path} - Please check the file path and try again.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_pcap_file>")
    else:
        main(sys.argv[1])
