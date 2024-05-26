import picologging as log
from scapy.all import Packet
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from algorithms import prefix_preserving_cryptopan as anonymize_ip


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
        if packet.haslayer(IP):
            packet[IP].src = anonymize_ip(packet[IP].src)
            packet[IP].dst = anonymize_ip(packet[IP].dst)
        if packet.haslayer(IPv6):
            packet[IPv6].src = anonymize_ip(packet[IPv6].src)
            packet[IPv6].dst = anonymize_ip(packet[IPv6].dst)

        if packet.haslayer(ARP):
            packet[ARP].psrc = anonymize_ip(packet[ARP].psrc)
            packet[ARP].pdst = anonymize_ip(packet[ARP].pdst)
        return packet
    except Exception as e:
        log.error(f"Error anonymizing IP addresses: {e}")
