import logging

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP

"""
  Esse passo recalcula os checksums dos pacotes.
"""


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
