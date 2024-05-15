from scapy.all import Packet, Raw

from algorithms import black_marker


def anon_app_data(packet: Packet) -> Packet:
    """
    This function anonymizes the application data of a packet.
    It replaces the payload of the packet with a black marker of bytes of zeroes.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """

    if packet.haslayer(Raw):
        payload_length = len(packet[Raw].load)
        packet[Raw].load = black_marker(payload_length)
    return packet
