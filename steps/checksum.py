
from scapy.all import Packet, IP, TCP, UDP


"""
  Esse passo recalcula os checksums dos pacotes.
"""
def recalculate(packet: Packet) -> Packet:
    if packet.haslayer(IP):
      del packet[IP].chksum
    if packet.haslayer(TCP):
      del packet[TCP].chksum
    if packet.haslayer(UDP):
      del packet[UDP].chksum # pacotes UDP podem ter checksums
    return packet
