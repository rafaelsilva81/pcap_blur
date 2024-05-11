import logging as log

from scapy.all import Packet
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import IPv6
from yacryptopan import CryptoPAn

from utils import get_cryptopan


def anon_icmp_v4(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
    if packet.haslayer(ICMP):
        log.warn(
            f"ICMP packet found at index {index}, truncating potential sensible data"
        )
        if packet[ICMP].gw is not None:
            packet[ICMP].gw = cp.anonymize(packet[ICMP].gw)
        if packet[ICMP].addr_mask is not None:
            packet[ICMP].addr_mask = cp.anonymize(packet[ICMP].addr_mask)
        if packet[ICMP].ts_ori is not None:
            packet[ICMP].ts_ori = 0
        if packet[ICMP].ts_rx is not None:
            packet[ICMP].ts_rx = 0
        if packet[ICMP].ts_tx is not None:
            packet[ICMP].ts_tx = 0
        del packet[ICMP].chksum
    return packet


def anon_icmp_v6(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
    if packet.haslayer(IPv6) and packet[IPv6].nh == 58:
        # Obter a próxima camada depois da layer IPv6
        log.warn(f"Truncation data for ICMPv6 packet layer at index {index}")
        packet.load = b""
        del packet[IPv6].cksum
    return packet


def anon_icmp(packet: Packet, index: int) -> Packet:
    cp = get_cryptopan()
    if cp is None:
        raise Exception("CryptoPAn not configured")

    packet = anon_icmp_v4(packet, index, cp)

    packet = anon_icmp_v6(packet, index, cp)
    return packet
