import picologging as log
from scapy.all import Packet
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3
from scapy.layers.inet import IP, TCP, UDP


def recalculate(packet: Packet, index: int) -> Packet:
    """
    This function recalculates the checksums of the packets.

    :param packet: Scapy Packet to be processed.
    :param index: Index of the packet in the packet list (for logging purposes).
    :return: Anonymized packet.
    """
    try:
        if packet.haslayer(IP):
            del packet[IP].chksum

        if packet.haslayer(TCP):
            del packet[TCP].chksum

        if packet.haslayer(IGMP):
            del packet[IGMP].chksum

        if packet.haslayer(IGMPv3):
            del packet[IGMPv3].chksum

        if packet.haslayer(UDP):
            del packet[UDP].chksum

        return packet
    except Exception as e:
        log.error(f"Error while recalculating checksum for packet {index}: {e}")
        return packet
