from scapy.all import Packet, Padding, Raw

from algorithms import black_marker


def anon_app_data(packet: Packet) -> Packet:
    """
    This function anonymizes the application data of a packet.
    It replaces the payload of the packet with a black marker of bytes of zeroes.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """

    # Get the last layer of the packet
    last_layer = packet.getlayer(packet.layers()[-1])

    # Check if the last layer is a Raw layer
    if isinstance(last_layer, Raw):
        # Replace the payload of the Raw layer with a black marker of bytes of zeroes
        payload_length = len(last_layer.load)
        last_layer.load = black_marker(payload_length)

    # Check if the last layer is a Padding layer
    elif isinstance(last_layer, Padding):
        # Replace the payload of the Padding layer with a black marker of bytes of zeroes
        payload_length = len(last_layer.load)
        last_layer.load = black_marker(payload_length)

    return packet
