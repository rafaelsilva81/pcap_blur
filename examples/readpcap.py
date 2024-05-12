from scapy.all import sniff

from steps import (
    anon_app_data,
    anon_icmp,
    anon_ip_address,
    anon_mac_address,
    anon_port_numbers,
    anon_timestamps,
    recalculate,
)

anonymized_packets = []


def anonymize_packet(packet, index):
    packet = anon_port_numbers(packet)
    packet = anon_mac_address(packet)
    packet = anon_ip_address(packet)
    packet = anon_icmp(packet, index)
    packet = anon_app_data(packet)
    packet = anon_timestamps(packet)
    packet = recalculate(packet, index)

    anonymized_packets.append(packet)
    return


def init_anonymization(path: str):
    sniff(offline=path, prn=anonymize_packet, store=0)
