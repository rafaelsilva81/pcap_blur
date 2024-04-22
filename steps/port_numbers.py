import random
from typing import Dict

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP

# Original port number to permuted port number mapping
port_map: Dict[int, int] = {}


def create_port_permutation(port: int) -> int:
    """
    This function creates a permutation of a port, ensuring that each original port is mapped to a unique permuted port.

    :param port: Original port number.
    :return: Permuted port number.
    """

    # Check if the port has a permutation
    if port in port_map:
        return port_map[port]
    else:
        # Generate a random permutation for the port
        permuted_port = random.randint(0, 65535)
        while permuted_port in port_map.values():
            # If the permutation already exists, generate another
            permuted_port = random.randint(0, 65535)

        # Add the permutation to the dictionary
        port_map[port] = permuted_port

    return permuted_port


def anon_port_numbers(packet: Packet) -> Packet:
    """
    Processes a packet Scapy, applying port permutation if it is a TCP or UDP packet.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """

    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            # Aplicar permutação de porta
            packet[TCP].sport = create_port_permutation(packet[TCP].sport)
            packet[TCP].dport = create_port_permutation(packet[TCP].dport)
        if packet.haslayer("UDP"):
            # Aplicar permutação de porta
            packet[UDP].sport = create_port_permutation(packet[UDP].sport)
            packet[UDP].dport = create_port_permutation(packet[UDP].dport)
    return packet
