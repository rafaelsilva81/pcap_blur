import logging as log

from scapy.all import Packet
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from utils import get_cryptopan


def get_cryptopan_singleton():
    """Retrieve a singleton instance of CryptoPAn to avoid repeated initializations."""
    if not hasattr(get_cryptopan_singleton, "instance"):
        get_cryptopan_singleton.instance = get_cryptopan()
    return get_cryptopan_singleton.instance


def anon_ip_address(packet: Packet) -> Packet:
    """
    Anonymize the IP address of a packet. Handles IPv4, IPv6, and ARP packets.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet, or None if an error occurs.
    """
    cp = get_cryptopan_singleton()
    if cp is None:
        log.error("CryptoPAn not configured, cannot anonymize IP addresses")
        return packet

    try:
        for layer in (IP, IPv6):
            if packet.haslayer(layer):
                packet[layer].src = cp.anonymize(packet[layer].src)
                packet[layer].dst = cp.anonymize(packet[layer].dst)

        if packet.haslayer(ARP):
            packet[ARP].psrc = cp.anonymize(packet[ARP].psrc)
            packet[ARP].pdst = cp.anonymize(packet[ARP].pdst)

        return packet
    except Exception as e:
        log.error(f"Error anonymizing IP addresses: {e}")
        return packet
