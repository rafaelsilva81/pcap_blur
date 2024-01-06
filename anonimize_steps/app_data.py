from scapy.all import Packet, Raw, IP, TCP

def anonymize_app_data(packet: Packet) -> Packet:
    if Raw in packet:
        payload_length = len(packet[Raw].load)
        packet[Raw].load = b"\x00" * payload_length  
        if IP in packet:
            del packet[IP].chksum
        if TCP in packet:
            del packet[TCP].chksum
    return packet
