import logging
import os
import platform
import sys
from scapy.all import Packet, Raw, wrpcap, PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import time

from steps import anon_app_data, recalculate, anon_timestamps, anon_port_numbers, anon_mac_address, anon_ip_address
from utils import check_checksum, is_truncated, extract_metadata

def anonymize_pcap(packet: Packet, index: int) -> Packet:
  copy_packet = packet.copy()

  
  #packet.show2()
  # packet = anon_timestamps(packet)
  copy_packet = anon_port_numbers(packet)
  copy_packet = anon_mac_address(packet)
  copy_packet = anon_ip_address(packet)
  copy_packet = anon_app_data(packet)
  copy_packet = recalculate(packet, index)

  return copy_packet
   
def main(path):
    start_time = time.time()

    logging.basicConfig(filename='log.txt', filemode='w', level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    if os.path.exists(path):
      file_size = os.path.getsize(path)  # Size of packet trace in bytes
        
      # Initialize progress tracking
      packet_count = 0
 
      # Log initial details
      logging.info(f"Original file: {os.path.basename(path)} - {file_size} bytes")
      logging.info(f"Machine information: {platform.processor()} - {platform.platform()} - {platform.architecture()[0]}")
      logging.info(f"Node/Host name: {platform.node()}")

      
      anonymized_packets = []
      with PcapReader(path) as packets:
        for index, packet in enumerate(packets):
          if (index > 10):
             break
          # Anonymize and append packet
          print(f"Processing packet {packet.summary()}")
          
          modified_packet = anonymize_pcap(packet.copy(), index+1)
          # if is_truncated(modified_packet):
          #   logging.warning(f"Packet {index+1} was truncated")
          anonymized_packets.append(modified_packet)
          packet_count += 1

          # Progress update  logic here (adjust as needed)
          print(f"Processed {packet_count} packets")
      # Save the anonymized packets to a new file
      file_name = path.replace(".pcap", "_out.pcap")
      wrpcap(file_name, anonymized_packets)
      print(f"\nAnonymized file saved to {file_name}")

    else:
        logging.error(f"File not found: {path} - Please check the file path and try again.")

    end_time = time.time()
    logging.info(f"Time taken in seconds: {end_time - start_time}")

    
if __name__ == "__main__":
    file_path = sys.argv[1]
    # max_memory = int(sys.argv[2])

    if os.path.exists(file_path):
        main(file_path)
    else:
        logging.error(f"File not found: {file_path} - Please check the file path and try again.")
