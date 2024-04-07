import logging
import os
from scapy.all import rdpcap, wrpcap
import platform

def main(path):
    logging.basicConfig(filename='log.txt',filemode='w', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

    if os.path.exists(path):
        file_size = os.path.getsize(path) 
        packets = rdpcap(path)
        packet_count = len(packets)  
            
        logging.info(f"Original file: {os.path.basename(path)} - {file_size} bytes - {packet_count} packets")
        logging.info(f"Machine information: {platform.processor()} - {platform.platform()} - {platform.architecture()[0]}")
        logging.info(f"Node/Host name: {platform.node()}")
            
        anonymized_packets = [anonymize_pcap(packet) for packet in packets]
        file_name = path.replace(".pcap", "_out.pcap")
        wrpcap(file_name, anonymized_packets)
        print(f"Anonymized file saved to {file_name}")

    else:
        logging.error(f"File not found: {path} - Please check the file path and try again.")