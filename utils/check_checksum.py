from scapy.all import IP, TCP, Packet
import logging
from typing import Union

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