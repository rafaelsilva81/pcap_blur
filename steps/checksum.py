import logging

import scapy.layers.inet6 as inet6
from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP

"""
  Esse passo recalcula os checksums dos pacotes.
"""


def recalculate_icmpv6_checksum(packet: Packet, index: int) -> Packet:
    pkt = packet.copy()
    if packet.haslayer(inet6.ICMPv6ND_RA):
        packet.show2()
        del pkt[inet6.ICMPv6ND_RA].chksum
    return pkt
    # for layer in pkt.layers():
    #     if issubclass(layer, inet6._ICMPv6):
    #         la = layer()
    #         del pkt[la].chksum
    #         # also tried: del layer.chksum

    # return pkt


def recalculate(packet: Packet, index: int) -> Packet:
    try:
        if packet.haslayer(IP):
            del packet[IP].chksum
            actual_len = len(packet[IP])
            if actual_len != packet[IP].len:
                logging.warning(
                    f"Incorrect IP length for packet {index}, probably truncated, recalculating length"
                )
                del packet[IP].len

        if packet.haslayer(inet6.IPv6):
            recalculate_icmpv6_checksum(packet, index)

        if packet.haslayer(TCP):
            del packet[TCP].chksum

        if packet.haslayer(UDP):
            del packet[UDP].chksum  # pacotes UDP podem ter checksums
            actual_len = len(packet[UDP])
            if actual_len != packet[UDP].len:
                logging.warning(
                    f"Incorrect UDP length for packet {index}, probably truncated, recalculating length"
                )
                del packet[UDP].len

        return packet
    except Exception as e:
        logging.error(f"Error while recalculating checksum for packet {index}: {e}")
        return packet
