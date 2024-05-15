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


class PcapAnonymizer:
    def __init__(self, path, outDir, outName):
        self.path = path
        self.outDir = outDir
        self.outName = outName
        self.pcap_writer = PcapWriter(
            os.path.join(self.outDir, self.outName), append=False
        )
        self.index = 1

    def anonymize_packet(self, pkt):
        pkt = anon_timestamps(pkt)
        pkt = anon_port_numbers(pkt)
        pkt = anon_mac_address(pkt)
        pkt = anon_ip_address(pkt)
        pkt = anon_icmp(pkt, self.index)
        pkt = anon_app_data(pkt)
        pkt = recalculate(pkt, self.index)

        self.index += 1

        if self.pcap_writer is not None:
            self.pcap_writer.write(pkt)
            self.pcap_writer.flush()

        return

    def single_file_anonymization(self):
        start_time = time.time()
        print("Beginning anonymization process ")

        configure_logging(self.outDir, self.outName)

        key = os.urandom(32)
        configure_cryptopan(key)

        sniff(offline=self.path, prn=self.anonymize_packet, store=0)

        end_time = time.time()
        duration = (end_time - start_time) * 1000  # Duration in milliseconds
        log.info(f"Anonymization process completed in {duration:.2f} ms")
        print(f"\nAnonymized file saved to {self.outDir}/{self.outName}")


def main():
    parser = argparse.ArgumentParser(
        description="PcapBlur is a tool for anonymizing network traffic captured in .pcap files."
    )

    # Create mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "path", nargs="?", help="Path to the .pcap file to be anonymized."
    )
    group.add_argument("--folder", help="Specify a folder for batch anonymization.")

    parser.add_argument(
        "--outDir",
        "-o",
        help="Set the output directory for the anonymized .pcap file(s).",
        default="output",
    )
    parser.add_argument(
        "--outName",
        "-n",
        help="Set the filename of the anonymized .pcap file. (OPTIONAL, works with path only)",
    )

    args = parser.parse_args()

    if args.folder:
        # Handling batch anonymization for a folder
        if args.outName:
            parser.error("--outName cannot be used with --folder")
        print(f"Batch anonymization for folder: {args.folder}")
        print(f"Output directory: {args.outDir}")
        # Add your batch anonymization code here
    else:
        # Handling single file anonymization
        if args.outName is None:
            args.outName = os.path.basename(args.path).replace(
                ".pcap", "_anonymized.pcap"
            )

        if not os.path.exists(args.outDir):
            os.makedirs(args.outDir)

        if not os.path.exists(args.path):
            print(f"Error: The file {args.path} does not exist.")
            return

        print(f"Single file anonymization for path: {args.path}")
        print(f"Output directory: {args.outDir}")
        print(f"Output filename: {args.outName}")
        pcap_anonymizer = PcapAnonymizer(args.path, args.outDir, args.outName)
        pcap_anonymizer.single_file_anonymization()
        # Add your single file anonymization code here


if __name__ == "__main__":
    main()
