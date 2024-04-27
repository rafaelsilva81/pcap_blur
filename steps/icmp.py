import logging as log

from scapy.all import Packet
from scapy.layers.inet import ICMP

from utils import get_cryptopan


def anon_icmp(packet: Packet) -> Packet:
    cp = get_cryptopan()
    if cp is None:
        log.error("CryptoPAn not configured, cannot anonymize IP addresses")
        raise Exception("CryptoPAn not configured")

    if packet.haslayer(ICMP):
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


def anon_icmp_v6(packet: Packet) -> Packet:
    return packet  # TODO
