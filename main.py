import argparse
import logging as log
import os
import threading
import time
from queue import PriorityQueue, Queue

from scapy.all import PcapWriter, sniff

# Import your steps and utils functions here
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
write_queue = PriorityQueue()
index = 0
lock = threading.Lock()
completion_event = threading.Event()


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


def worker():
    while True:
        item = packet_queue.get()
        if item is None:  # Shutdown signal
            packet_queue.task_done()
            break
        pkt, idx = item
        result = anonymize_packet(pkt, idx)
        with lock:
            write_queue.put((idx, result))
        completion_event.set()
        packet_queue.task_done()


def write_packets_to_file(pcap_writer):
    current_index = 1
    while True:
        completion_event.wait()  # Wait until there is something to write or all threads are done
        while not write_queue.empty():
            with lock:
                idx, packet = write_queue.get()
                if idx == current_index:
                    pcap_writer.write(packet)
                    pcap_writer.flush()
                    current_index += 1
                else:
                    write_queue.put((idx, packet))
                    break
        if packet_queue.empty() and write_queue.empty():
            break  # Break if all packets have been processed
        completion_event.clear()  # Reset event for new data


def init_anonymization(path: str, outDir: str, outName: str, num_threads: int):
    print("Beginning anonymization process")
    start_time = time.time()

    configure_logging(os.path.basename(path), outDir, outName)
    key = os.urandom(32)
    configure_cryptopan(key)

    pcap_writer = PcapWriter(os.path.join(outDir, outName), append=False)

    # Start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    writer_thread = threading.Thread(target=write_packets_to_file, args=(pcap_writer,))
    writer_thread.start()

    def packet_handler(pkt):
        global index
        with lock:
            index += 1
        packet_queue.put((pkt, index))

    sniff(offline=path, prn=packet_handler, store=False)

    # Stop adding new packets
    for _ in range(num_threads):
        packet_queue.put(None)
    for t in threads:
        t.join()

    # Ensure all packets are written
    completion_event.set()
    writer_thread.join()
    pcap_writer.close()

    end_time = time.time()
    duration = (end_time - start_time) * 1000  # Duration in milliseconds (in seconds)
    log.info(f"Anonymization process completed in {duration:.2f} ms")

    print(f"Anonymized file saved to {outDir}/{outName}")


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
