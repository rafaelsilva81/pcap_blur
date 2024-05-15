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

    def anonymize_file(self):
        start_time = time.time()
        print(f"Beginning anonymization process on {self.path}")

        configure_logging(self.outDir, self.outName)

        key = os.urandom(32)
        configure_cryptopan(key)

        sniff(offline=self.path, prn=self.anonymize_packet, store=0)

        end_time = time.time()
        duration = (end_time - start_time) * 1000  # Duration in milliseconds
        log.info(f"Anonymization process completed in {duration:.2f} ms")
        print(f"\nAnonymized file saved to {self.outDir}/{self.outName}")
