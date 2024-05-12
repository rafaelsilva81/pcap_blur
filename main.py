import argparse
import logging as log
import os
import time

from scapy.all import sniff
from scapy.utils import PcapWriter

from steps import (
    anon_app_data,
    anon_icmp,
    anon_ip_address,
    anon_mac_address,
    anon_port_numbers,
    anon_timestamps,
    recalculate,
)
from utils import configure_cryptopan, configure_logging

anonymized_packets = []
pcap_writer: PcapWriter | None = None
index = 1


def anonymize_packet(pkt):
    global index
    global pcap_writer

    pkt = anon_timestamps(pkt)
    pkt = anon_port_numbers(pkt)
    pkt = anon_mac_address(pkt)
    pkt = anon_ip_address(pkt)
    pkt = anon_icmp(pkt, index)
    pkt = anon_app_data(pkt)
    pkt = recalculate(pkt, index)

    index += 1

    if pcap_writer is not None:
        pcap_writer.write(pkt)

    return pkt


def init_anonymization(path: str, outDir: str, outName: str, num_threads: int):
    global pcap_writer

    pcap_writer = PcapWriter(os.path.join(outDir, outName), append=False)

    start_time = time.time()
    print("Beginning anonymization process")
    configure_logging(os.path.basename(path), outDir, outName)
    key = os.urandom(32)
    configure_cryptopan(key)

    sniff(offline=path, prn=anonymize_packet, store=0)

    end_time = time.time()
    duration = (end_time - start_time) * 1000  # Duration in milliseconds
    log.info(f"Anonymization process completed in {duration:.2f} ms")
    print(f"\nAnonymized file saved to {outDir}/{outName}")


def main():
    parser = argparse.ArgumentParser(
        description="PcapBlur is a tool for anonymizing network traffic captured in .pcap files."
    )
    parser.add_argument("path", help="Path to the .pcap file to be anonymized.")
    parser.add_argument(
        "--outDir",
        "-o",
        help="Set the output directory for the anonymized .pcap file. (OPTIONAL)",
        default="output",
    )
    parser.add_argument(
        "--outName",
        "-n",
        help="Set the filename of the anonymized .pcap file. (OPTIONAL)",
    )
    parser.add_argument(
        "--threads",
        "-t",
        help="Set the number of threads to use for anonymization. (OPTIONAL)",
        default=os.cpu_count(),
        type=int,
    )
    args = parser.parse_args()

    if args.outName is None:
        args.outName = os.path.basename(args.path).replace(".pcap", "_anonymized.pcap")

    if not os.path.exists(args.outDir):
        os.makedirs(args.outDir)

    if not os.path.exists(args.path):
        print(f"Error: The file {args.path} does not exist.")
        return

    init_anonymization(args.path, args.outDir, args.outName, args.threads)


if __name__ == "__main__":
    main()
