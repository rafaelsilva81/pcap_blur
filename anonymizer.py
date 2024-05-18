import math
import os
import platform
import time

import picologging as log
import psutil
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
from utils import configure_cryptopan


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
        """
        This function anonymizes a single packet and returns the anonymized packet.
        """
        pkt = anon_mac_address(pkt)
        pkt = anon_ip_address(pkt)
        pkt = anon_icmp(pkt, self.index)
        pkt = anon_port_numbers(pkt)
        pkt = anon_app_data(pkt)
        pkt = anon_timestamps(pkt)
        pkt = recalculate(pkt, self.index)

        self.index += 1

        if self.pcap_writer is not None:
            self.pcap_writer.write(pkt)
            self.pcap_writer.flush()

        return

    def log_system_info(self):
        """
        This function logs system information, the information logged is the following:
        - File name
        - OS information
        - Machine information (CPU, RAM, etc.)
        - Date and time of the start of the process
        - Original file size
        """

        log.info(f"Anonymization process started on {self.path}")
        log.info(
            f"OS: {platform.system()} version: {platform.version()} release: {platform.release()}"
        )
        log.info(
            f"Machine: {platform.processor()} - {math.ceil(psutil.virtual_memory().total / 1024**3)} GB"
        )
        log.info(f"Datetime: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        log.info(f"Original file size: {os.path.getsize(self.path)} bytes")

    def anonymize_file(self):
        """
        This is the main function that performs the anonymization process.
        It reads the file, anonymizes the packets, and writes the anonymized packets to a new file.
        It also logs system information such as the file name, the number of packets, and the duration of the anonymization process.
        """
        try:
            self.log_system_info()

            print(f"\nBeginning anonymization process on {self.path}")

            key = os.urandom(32)
            configure_cryptopan(key)

            start_time = time.time()

            sniff(offline=self.path, prn=self.anonymize_packet, store=0)

            end_time = time.time()
            duration = (end_time - start_time) * 1000  # Duration in milliseconds
            log.info(f"Anonymization process completed in {duration:.2f} ms")
            print(f"Anonymized file saved to {self.outDir}/{self.outName}")
        except Exception as e:
            log.error(f"Anonymization process failed: {e}")
