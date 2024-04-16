from scapy.all import IP, TCP, Packet, UDP
import logging
from typing import Union, List, Dict
import pyshark

def check_checksum(packet: Packet):
    # Validar se o checksum do pacote é válido
    if packet.haslayer(IP):
        original_checksum = packet[IP].chksum
        del packet[IP].chksum
        new_checksum = packet[IP].chksum
        if original_checksum != new_checksum:
            logging.warning(f"IP Checksum Invalid for package {packet.summary()}")
       
    
    if packet.haslayer(TCP):
        original_checksum = packet[TCP].chksum
        del packet[TCP].chksum
        new_checksum = packet[TCP].chksum
        if original_checksum != new_checksum:
            logging.warning(f"TCP Checksum Invalid for package {packet.summary()}")

def is_truncated(packet: Packet) -> bool:

    # if IP in packet and UDP in packet:
    #     ip_len = packet[IP].len
    #     actual_len = len(packet[IP].payload)
    #     return ip_len > actual_len
    if IP in packet:
        ip_len = packet[IP].len
        actual_len = len(packet[IP].payload)
        return ip_len > actual_len
    if UDP in packet:
        ip_len = packet[UDP].len
        actual_len = len(packet[UDP].payload)
        return ip_len > actual_len
    return False

def extract_metadata(pcap_file: str, index: int) -> List[Dict[str,str]]:
    capture = pyshark.FileCapture(pcap_file, only_summaries=True)
    metadata_list: List[Dict[str,str]] = []
    # obter o pacote de acordo com o index
    packet = capture[index]

    print(f"packet: {packet}")
    print(f"info: {packet.info}")
    capture.close()
    return metadata_list