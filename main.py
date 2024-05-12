import argparse
import logging as log
import os
import threading
import time
from queue import Queue

from scapy.all import sniff, wrpcap

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
index = 0
lock = threading.Lock()


def anonymize_packet(packet, index):
    packet = anon_port_numbers(packet)
    packet = anon_mac_address(packet)
    packet = anon_ip_address(packet)
    packet = anon_icmp(packet, index)
    packet = anon_app_data(packet)
    packet = anon_timestamps(packet)
    packet = recalculate(packet, index)
    return packet


def worker(out_path, batch_size=100):
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
            print(f"Anonymizing packet {index}")
            with lock:
                wrpcap(out_path, batch)  # Append packets to the output file
            batch.clear()  # Clear the batch after writing

        packet_queue.task_done()

    # Handle remaining packets in the batch
    if batch:
        with lock:
            print(f"Anonymizing packet {index}")
            wrpcap(out_path, batch)


def init_anonymization(path: str, outDir: str, outName: str, num_threads: int):
    start_time = time.time()
    print("Beginning anonymization process")
    configure_logging(os.path.basename(path), outDir, outName)
    key = os.urandom(32)
    configure_cryptopan(key)

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    out_path = os.path.join(outDir, outName)

    # Start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(out_path,))
        t.start()
        threads.append(t)

    global last_print_time
    last_print_time = time.time()

    def packet_handler(pkt):
        global index, last_print_time
        with lock:
            index += 1
        packet_queue.put((pkt, index))

    sniff(offline=path, prn=packet_handler, store=0)

    # Block until all tasks are done
    packet_queue.join()

    # Stop workers
    for _ in range(num_threads):
        packet_queue.put(None)
    for t in threads:
        t.join()

    end_time = time.time()
    duration = (end_time - start_time) * 1000  # Duration in milliseconds
    log.info(f"Anonymization process completed in {duration:.2f} ms")
    print(f"\nAnonymized file saved to {out_path}")


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

    if not os.path.isfile(args.path):
        print(
            f"Error: The file {args.path} does not exist. Please provide a valid .pcap or .pcapng file."
        )
        return

    init_anonymization(args.path, args.outDir, args.outName, args.threads)


if __name__ == "__main__":
    main()
