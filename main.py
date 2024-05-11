import argparse
import logging as log
import os
import platform

from scapy.all import Packet, PcapReader, wrpcap

from steps import (
    anon_app_data,
    anon_icmp,
    anon_ip_address,
    anon_mac_address,
    anon_port_numbers,
    anon_timestamps,
    recalculate,
)
from utils import configure_cryptopan, configure_logging, validate_anonymization


def anonymize_pcap(packet: Packet, index: int) -> Packet:
    pkt = packet.copy()

    pkt = anon_timestamps(pkt)
    pkt = anon_port_numbers(pkt)
    pkt = anon_mac_address(pkt)
    pkt = anon_ip_address(pkt)
    pkt = anon_icmp(pkt, index)
    pkt = anon_app_data(pkt)
    pkt = recalculate(pkt, index)

    return pkt


def init_anonimization(path: str, outDir: str, outName: str):
    configure_logging(os.path.basename(path), outDir, outName)
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
            modified_packet = anonymize_pcap(packet.copy(), index + 1)
            anonymized_packets.append(modified_packet)
            packet_count += 1

            # Save the anonymized packets to a new file
    # Make the output directory if it doesn't exist
    if not os.path.exists(outDir):
        os.makedirs(outDir)

    wrpcap(f"{outDir}/{outName}", anonymized_packets)
    print(f"\nAnonymized file saved to {outDir}/{outName}")


def main():
    parser = argparse.ArgumentParser(
        description="PcapBlur is a tool for anonymizing network traffic captured in .pcap files."
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "path", nargs="?", help="Path to the .pcap file to be anonymized."
    )

    parser.add_argument(
        "--outDir",
        "-o",
        help="Set the output directory for anonymized .pcap file. (OPTIONAL)",
    )

    parser.add_argument(
        "--outName",
        "-n",
        help="Set the filename of the anonymized .pcap file. (OPTIONAL)",
    )

    group.add_argument(
        "--validate",
        nargs=2,
        metavar=("ORIGINAL_PCAP", "ANONYMIZED_PCAP"),
        help="Provide paths to original and anonymized .pcap files for validation.",
    )

    args = parser.parse_args()

    if args.validate:
        original_pcap, anonymized_pcap = args.validate
        if not os.path.exists(original_pcap):
            print(f"File not found: {original_pcap}")
            exit(1)
        if not os.path.exists(anonymized_pcap):
            print(f"File not found: {anonymized_pcap}")
            exit(1)

        validate_anonymization(original_pcap, anonymized_pcap)
    else:
        path = args.path
        outDir = args.outDir if args.outDir else "output"
        outName = (
            f"{args.outName}"
            if args.outName
            else os.path.basename(path).replace(".pcap", "_out.pcap")
        )

        if os.path.exists(path):
            init_anonimization(path, outDir, outName)
        else:
            print(f"File not found: {path} - Please check the file path and try again.")


if __name__ == "__main__":
    main()
