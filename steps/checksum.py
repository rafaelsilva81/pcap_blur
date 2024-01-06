
from scapy.all import Packet, IP, TCP


"""
  Esse passo recalcula os checksums dos pacotes.
"""
def recalculate(packet: Packet) -> Packet:
    if IP in packet:
      del packet[IP].chksum
    if TCP in packet:
      del packet[TCP].chksum
    return packet
