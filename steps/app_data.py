from scapy.all import Packet, Raw

def anon_app_data(packet: Packet) -> Packet:
    if Raw in packet:
      payload_length = len(packet[Raw].load)
      packet[Raw].load = b"\x00" * payload_length  
    return packet
 