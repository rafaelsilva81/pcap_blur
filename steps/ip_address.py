from scapy.all import Packet, IP
from yacryptopan import CryptoPAn
import os

def gerar_chave_aes():
    return os.urandom(32)  # Gera 32 bytes (256 bits) de forma segura

cp = CryptoPAn(gerar_chave_aes())

def anon_ip_address(packet: Packet) -> Packet:
    if packet.haslayer(IP):
        packet[IP].src = cp.anonymize(packet[IP].src)
        packet[IP].dst = cp.anonymize(packet[IP].dst)
    return packet