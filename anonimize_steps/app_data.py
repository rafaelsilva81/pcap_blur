from scapy.all import *

def anonymize_app_data(packet):
    if Raw in packet:
        payload_length = len(packet[Raw].load)
        packet[Raw].load = b"\x00" * payload_length  
        if IP in packet:
            del packet[IP].chksum
        if TCP in packet:
            del packet[TCP].chksum
    return packet
