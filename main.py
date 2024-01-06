from scapy.all import *
from anonimize_steps.app_data import anonymize_app_data 

def main():
    packets = rdpcap("input.pcap")
    anonymized_packets = [anonymize_app_data(packet) for packet in packets]
    wrpcap("output.pcap", anonymized_packets)

if __name__ == "__main__":
  main()