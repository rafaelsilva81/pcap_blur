import logging
import os
import platform
import sys
from scapy.all import Packet, rdpcap, wrpcap, PcapReader
import time
from utils import check_checksum
from steps import anon_app_data, recalculate, anon_timestamps, anon_port_numbers, anon_mac_address, anon_ip_address

def anonymize_pcap(packet: Packet) -> Packet:

  packet = anon_app_data(packet)
  # packet = anon_timestamps(packet)
  packet = anon_port_numbers(packet)
  packet = anon_mac_address(packet)
  packet = recalculate(packet)
  packet = anon_ip_address(packet)

  check_checksum(packet)
  return packet
  
  
def main(path):

    if os.path.exists(path):
   
      
      anonymized_packets = []
      with PcapReader(path) as packets:
        for packet in packets:
          # Anonymize and append packet
          anonymized_packets.append(anonymize_pcap(packet))
          packet_count += 1

          # Progress update  logic here (adjust as needed)
          print(f"Processed {packet_count} packets")
      # Save the anonymized packets to a new file
      file_name = path.replace(".pcap", "_out.pcap")
      wrpcap(file_name, anonymized_packets)
      print(f"\nAnonymized file saved to {file_name}")



    
if __name__ == "__main__":
    file_path = sys.argv[1]
    # max_memory = int(sys.argv[2])

    if os.path.exists(file_path):
        main(file_path)

