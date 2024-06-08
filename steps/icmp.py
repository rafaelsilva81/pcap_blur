import picologging as log
from scapy.all import Packet
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import IPv6
from yacryptopan import CryptoPAn

from utils import get_cryptopan


def anon_icmp_v4(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
    if packet.haslayer(ICMP):
        log.debug(f"Anonymizing ICMP packet at index {index}.")
        for field in ["gw", "addr_mask"]:
            if getattr(packet[ICMP], field, None) is not None:
                setattr(packet[ICMP], field, cp.anonymize(getattr(packet[ICMP], field)))

        for field in ["ts_ori", "ts_rx", "ts_tx"]:
            if getattr(packet[ICMP], field, None) is not None:
                setattr(packet[ICMP], field, 0)

        del packet[ICMP].chksum
    return packet


def anon_icmp_v6(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
    if packet.haslayer(IPv6) and packet[IPv6].nh == 58:
        log.debug(f"Handling ICMPv6 packet at index {index}.")
        # Assuming specific anonymization tasks for ICMPv6 could be defined here
        packet.load = b""  # Consider more granular handling than wiping payload
    return packet


def anon_icmp(packet: Packet, index: int) -> Packet:
    cp = get_cryptopan()
    if cp is None:
        raise Exception("CryptoPAn not configured")

    packet = anon_icmp_v4(packet, index, cp)
    packet = anon_icmp_v6(packet, index, cp)
    return packet
