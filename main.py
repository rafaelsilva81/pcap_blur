import argparse
import logging as log
import os
import threading
import time
from queue import Queue

from scapy.all import PcapWriter, sniff

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

packet_queue = Queue()
index = 1
lock = threading.Lock()


def anonymize_packet(packet, index):
    pkt = packet.copy()
    packet = anon_timestamps(pkt)
    packet = anon_port_numbers(pkt)
    packet = anon_mac_address(pkt)
    packet = anon_ip_address(pkt)
    packet = anon_icmp(pkt, index)
    packet = anon_app_data(pkt)
    packet = recalculate(pkt, index)
    return pkt


def worker(pcap_writer):
    batch_size = 1000
    batch = []
    while True:
        item = packet_queue.get()
        if item is None:
            packet_queue.task_done()
            break  # Exit condition for the thread
        pkt, idx = item
        result = anonymize_packet(pkt, idx)
        batch.append(result)

        if len(batch) >= batch_size:
            with lock:
                for packet in batch:
                    pcap_writer.write(packet)
                    pcap_writer.flush()
            batch.clear()  # Clear the batch after writing

        packet_queue.task_done()

    # Handle remaining packets in the batch
    if batch:
        with lock:
            for packet in batch:
                pcap_writer.write(packet)
                pcap_writer.flush()


def init_anonymization(path: str, outDir: str, outName: str, num_threads: int):
    start_time = time.time()
    print("Beginning anonymization process")
    configure_logging(os.path.basename(path), outDir, outName)
    key = os.urandom(32)
    configure_cryptopan(key)

    pcap_writer = PcapWriter(os.path.join(outDir, outName))

    # Start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(pcap_writer,))
        t.start()
        threads.append(t)

    def packet_handler(pkt):
        global index
        with lock:
            index += 1
            print(f"Anonymizing packet {index}")

        packet_queue.put((pkt, index))

    sniff(offline=path, prn=packet_handler, store=0)

    # Block until all tasks are done
    packet_queue.join()

    # Stop workers
    for _ in range(num_threads):
        packet_queue.put(None)
    for t in threads:
        t.join()

    pcap_writer.close()

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
