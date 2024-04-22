from scapy.all import Packet, Raw


def black_marker(lenght: int) -> bytes:
    """
    This function returns a dull black marker of bytes of zeroes of the specified length.

    :param lenght: Length of the black marker.
    :return: Black marker of bytes of zeroes.
    """
    return b"\x00" * lenght


def anon_app_data(packet: Packet) -> Packet:
    """
    This function anonymizes the application data of a packet.
    It replaces the payload of the packet with a black marker of bytes of zeroes.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """
    if Raw in packet:
        payload_length = len(packet[Raw].load)
        packet[Raw].load = black_marker(payload_length)
    return packet
