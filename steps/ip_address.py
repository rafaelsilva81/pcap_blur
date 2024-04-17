import logging as log

from scapy.all import Packet
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from utils import cryptopan as cp


def anon_ip_address(packet: Packet) -> Packet:
    if cp is None:
        log.error("CryptoPAn not configured, cannot anonymize IP addresses")
        raise Exception("CryptoPAn not configured")

    if packet.haslayer(IP):
        packet[IP].src = cp.anonymize(packet[IP].src)
        packet[IP].dst = cp.anonymize(packet[IP].dst)
    if packet.haslayer(IPv6):
        packet[IPv6].src = cp.anonymize(packet[IPv6].src)
        packet[IPv6].dst = cp.anonymize(packet[IPv6].dst)
    return packet
