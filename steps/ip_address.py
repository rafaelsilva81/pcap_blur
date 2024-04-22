import logging as log

from scapy.all import Packet
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from utils import get_cryptopan


def anon_ip_address(packet: Packet) -> Packet | None:
    """
    Anonimize the IP address of a packet.
    This function also checks for ARP packets and anonymizes the source and destination IP addresses to avoid
    leaking original information on ARP packets.

    The anonymization process utilizes the CryptoPAn algorithm to generate a randomized IP address in a prefix-preserving manner.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """
    try:
        cp = get_cryptopan()
        if cp is None:
            log.error("CryptoPAn not configured, cannot anonymize IP addresses")
            raise Exception("CryptoPAn not configured")

        if packet.haslayer(IP):
            packet[IP].src = cp.anonymize(packet[IP].src)
            packet[IP].dst = cp.anonymize(packet[IP].dst)
        if packet.haslayer(IPv6):
            packet[IPv6].src = cp.anonymize(packet[IPv6].src)
            packet[IPv6].dst = cp.anonymize(packet[IPv6].dst)

        if packet.haslayer(ARP):
            packet[ARP].psrc = cp.anonymize(packet[ARP].psrc)
            packet[ARP].pdst = cp.anonymize(packet[ARP].pdst)
        return packet
    except Exception as e:
        log.error(f"Error anonymizing IP addresses: {e}")
