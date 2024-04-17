import logging as log
import os
import platform
import sys

from scapy.all import Packet, PcapReader, wrpcap

from steps import (
    anon_app_data,
    anon_ip_address,
    anon_mac_address,
    anon_port_numbers,
    recalculate,
)
from utils import configure_cryptopan, configure_logging


def anonymize_pcap(packet: Packet, index: int) -> Packet:
    copy_packet = packet.copy()

    # packet.show2()
    # packet = anon_timestamps(packet)
    copy_packet = anon_port_numbers(packet)
    copy_packet = anon_mac_address(packet)
    copy_packet = anon_ip_address(packet)
    copy_packet = anon_app_data(packet)
    copy_packet = recalculate(packet, index)

    return copy_packet


def main(path):
    configure_logging(os.path.basename(path))
    key = os.urandom(32)
    configure_cryptopan(key)

    file_size = os.path.getsize(path)  # Size of packet trace in bytes

    # Initialize progress tracking
    packet_count = 0

    # Log initial details
    log.info(f"Original file: {os.path.basename(path)} - {file_size} bytes")
    log.info(
        f"Machine information: {platform.processor()} - {platform.platform()} - {platform.architecture()[0]}"
    )
    log.info(f"Node/Host name: {platform.node()}")

    anonymized_packets = []
    with PcapReader(path) as packets:
        for index, packet in enumerate(packets):
            # Anonymize and append packet
            print(f"Processing packet {packet.summary()}")

            modified_packet = anonymize_pcap(packet.copy(), index + 1)
            anonymized_packets.append(modified_packet)
            packet_count += 1

            # Progress update  logic here (adjust as needed)
            print(f"Processed {packet_count} packets")
            # Save the anonymized packets to a new file
            file_name = path.replace(".pcap", "_out.pcap")
            wrpcap(f"output/{file_name}", anonymized_packets)
            print(f"\nAnonymized file saved to {file_name}")


if __name__ == "__main__":
    file_path = sys.argv[1]

    if os.path.exists(file_path):
        main(file_path)
    else:
        print(
            f"File not found: {file_path} - Please check the file path and try again."
        )
