from scapy.all import Packet, IP, IPv6
from yacryptopan import CryptoPAn
import os

def gerar_chave_aes():
    return os.urandom(32)  # Gera 32 bytes (256 bits) de forma segura

cp = CryptoPAn(gerar_chave_aes())

def anon_ip_address(packet: Packet) -> Packet:
    if packet.haslayer(IP):
        packet[IP].src = cp.anonymize(packet[IP].src)
        packet[IP].dst = cp.anonymize(packet[IP].dst)
    if packet.haslayer(IPv6):
        packet[IPv6].src = cp.anonymize(packet[IPv6].src)
        packet[IPv6].dst = cp.anonymize(packet[IPv6].dst)
    return packet

