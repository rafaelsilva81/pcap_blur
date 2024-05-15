from scapy.all import Packet
from scapy.layers.l2 import ARP, Ether

from algorithms import generate_permutation_mac


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
        generate_permutation_mac(
            manufacturer_addr, is_group_address, is_device_address=False
        )
        + ":"
        + generate_permutation_mac(
            device_addr, is_group_address, is_device_address=True
        )
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
