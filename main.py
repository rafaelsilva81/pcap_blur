import argparse
import logging as log
import os
import time
from collections import deque
from threading import Event, Thread

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
    def __init__(self, path, outDir, outName, buffer_size=1000):
        self.path = path
        self.outDir = outDir
        self.outName = outName
        self.buffer_size = buffer_size
        self.pcap_writer = PcapWriter(
            os.path.join(self.outDir, self.outName), append=False
        )
        self.index = 1
        self.buffer = deque()
        self.stop_event = Event()

    def anonymize_packet(self, pkt):
        pkt = anon_timestamps(pkt)
        pkt = anon_port_numbers(pkt)
        pkt = anon_mac_address(pkt)
        pkt = anon_ip_address(pkt)
        pkt = anon_icmp(pkt, self.index)
        pkt = anon_app_data(pkt)
        pkt = recalculate(pkt, self.index)

        self.index += 1

        self.buffer.append(pkt)
        if len(self.buffer) >= self.buffer_size:
            self.flush_buffer()

    def flush_buffer(self):
        while self.buffer:
            pkt = self.buffer.popleft()
            self.pcap_writer.write(pkt)
        self.pcap_writer.flush()

    def progress_counter(self):
        start_time = time.time()
        while not self.stop_event.is_set():
            time.sleep(10)
            elapsed_time = time.time() - start_time
            print(f"Processed {self.index - 1} packets in {elapsed_time:.2f} seconds.")

    def init_anonymization(self):
        start_time = time.time()
        print("Beginning anonymization process")

        configure_logging(self.outDir, self.outName)

        key = os.urandom(32)
        configure_cryptopan(key)

        # Start the progress counter in a separate thread
        progress_thread = Thread(target=self.progress_counter)
        progress_thread.start()

        sniff(offline=self.path, prn=self.anonymize_packet, store=0)

        # Flush any remaining packets in the buffer
        self.flush_buffer()

        # Stop the progress counter
        self.stop_event.set()
        progress_thread.join()

        end_time = time.time()
        duration = (end_time - start_time) * 1000  # Duration in milliseconds
        log.info(f"Anonymization process completed in {duration:.2f} ms")
        print(f"\nAnonymized file saved to {self.outDir}/{self.outName}")


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
    args = parser.parse_args()

    if args.outName is None:
        args.outName = os.path.basename(args.path).replace(".pcap", "_anonymized.pcap")

    if not os.path.exists(args.outDir):
        os.makedirs(args.outDir)

    if not os.path.exists(args.path):
        print(f"Error: The file {args.path} does not exist.")
        return

    anonymizer = PcapAnonymizer(args.path, args.outDir, args.outName)
    anonymizer.init_anonymization()


if __name__ == "__main__":
    main()
