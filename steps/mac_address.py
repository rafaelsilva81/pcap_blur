import random
from typing import Dict

from scapy.all import Packet
from scapy.layers.l2 import ARP, Ether

# Mapeamentos para identificadores de fabricante e de dispositivo
manufacturer_map: Dict[str, str] = {}
device_map: Dict[str, str] = {}


def generate_permutation_mac(
    mac_part: str, mac_map: Dict[str, str], is_group_address: bool = False
) -> str:
    """
    Generates a permutation for a part of the MAC address, ensuring it retains group or individual characteristics.

    :param mac_part: Part of the MAC address to be permuted.
    :param mac_map: Dictionary for permutation mapping.
    :param is_group_address: Flag to ensure the resulting MAC is a group address.
    :return: Permuted part of the MAC address.
    """
    if mac_part in mac_map:
        return mac_map[mac_part]
    else:
        # Generate random permutation
        permuted_part = ":".join(["%02x" % random.randint(0, 255) for _ in range(3)])
        while permuted_part in mac_map.values():
            permuted_part = ":".join(
                ["%02x" % random.randint(0, 255) for _ in range(3)]
            )

        # Adjust the first byte to respect the group address property
        bytes = permuted_part.split(":")
        first_byte = int(bytes[0], 16)
        if is_group_address:
            first_byte |= 0x01  # Set LSB to 1
        else:
            first_byte &= 0xFE  # Set LSB to 0
        bytes[0] = "%02x" % first_byte
        permuted_part = ":".join(bytes)

        mac_map[mac_part] = permuted_part
        return permuted_part


def check_group_address(mac: str) -> bool:
    """
    Check if a MAC address is a group address.

    :param mac: MAC address as a string.
    :return: True if it's a group address, False otherwise.
    """
    # Get the first octet and convert it to integer
    first_octet = int(mac[:2], 16)
    # Check the least significant bit
    is_group_address = (first_octet & 0x01) == 0x01

    return is_group_address


def anonimize_mac(mac_addr: str, is_group_address=False) -> str:
    """
    Auxiliary function to anonymize a MAC address.

    :param mac_addr: MAC address as a string.
    :param is_group_address: True if the address is a group address, False otherwise.
    :return: Anonymized MAC address as a string.
    """

    manufacturer_addr, device_addr = mac_addr[:8], mac_addr[9:]

    mac_result = (
        generate_permutation_mac(manufacturer_addr, manufacturer_map, is_group_address)
        + ":"
        + generate_permutation_mac(device_addr, device_map, is_group_address)
    )

    return mac_result


def anon_mac_address(packet: Packet) -> Packet:
    """
    Anonimize the MAC address of a packet.
    This funtion also checks for ARP packets and anonymizes the source and destination MAC addresses to avoid
    leaking original information on ARP packets.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """
    if packet.haslayer(Ether):
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst

        # HERE i want to see if the mac address is a group address
        is_group_address_src = check_group_address(mac_src)
        is_group_address_dst = check_group_address(mac_dst)

        mac_src_anon = anonimize_mac(mac_src, is_group_address_src)
        mac_dst_anon = anonimize_mac(mac_dst, is_group_address_dst)

        # Definir endereços MAC anonimizados no pacote
        packet[Ether].src = mac_src_anon
        packet[Ether].dst = mac_dst_anon

        if packet.haslayer(ARP):
            packet[ARP].hwsrc = mac_src_anon
            packet[ARP].hwdst = mac_dst_anon
    return packet
