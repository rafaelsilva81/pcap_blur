from scapy.all import rdpcap, IP, IPv6, Ether
import sys
import logging
from datetime import datetime, timezone
import tzlocal


def validate_anonymization(original_pcap_path, anonymized_pcap_path):
    # Read packets from the provided pcap files
    original_packets = rdpcap(original_pcap_path)
    anonymized_packets = rdpcap(anonymized_pcap_path)

    # Check if the files have the same number of packets
    if len(original_packets) != len(anonymized_packets):
        logging.error("Validation Failed: The number of packets in the original and anonymized files does not match.")
        return False

    for orig_pkt, anon_pkt in zip(original_packets, anonymized_packets):
        # Check MAC addresses
        if Ether in orig_pkt and Ether in anon_pkt:
            if orig_pkt[Ether].src == anon_pkt[Ether].src or orig_pkt[Ether].dst == anon_pkt[Ether].dst:
                logging.error("Anonymization failure: Original MAC address found in the anonymized packet.")
                logging.info(f"Original MAC address: {orig_pkt[Ether].src} - {orig_pkt[Ether].dst}")
                return False
        
        # Check IPv4 addresses
        if IP in orig_pkt and IP in anon_pkt:
            if orig_pkt[IP].src == anon_pkt[IP].src or orig_pkt[IP].dst == anon_pkt[IP].dst:
                logging.error("Anonymization failure: Original IPV4 address found in the anonymized packet.")
                logging.info(f"Original IPV4 address: {orig_pkt[IP].src} - {orig_pkt[IP].dst}")
                return False
        
        # Check IPv6 addresses
        if IPv6 in orig_pkt and IPv6 in anon_pkt:
            if orig_pkt[IPv6].src == anon_pkt[IPv6].src or orig_pkt[IPv6].dst == anon_pkt[IPv6].dst:
                logging.error("Anonymization failure: Original IPV6 address found in the anonymized packet.")
                logging.info(f"Original IPV6 address: {orig_pkt[IPv6].src} - {orig_pkt[IPv6].dst}")
                return False

    print("Anonymization validation finished successfully.")
    logging.info("Anonymization validation successful. No original addresses were found in the anonymized packets.")
    return True

if __name__ == "__main__":
    logging.basicConfig(filename='validation_log.txt',filemode='w', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    if len(sys.argv) != 3:
        print("Usage: python validate_anonymization.py <original_pcap_path> <anonymized_pcap_path>")
    else:
        original_pcap_path = sys.argv[1]
        anonymized_pcap_path = sys.argv[2]
        logging.info(f"Validating anonymization for {original_pcap_path} and {anonymized_pcap_path}")
        validate_anonymization(original_pcap_path, anonymized_pcap_path)
