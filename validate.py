from scapy.all import rdpcap, IP, Ether, IPv6, TCP, UDP, Packet
import sys
import logging
from typing import List



def validate_anonymization(original_pcap_path, anonymized_pcap_path):
    hasError = False
    
    # Read packets from the provided pcap files
    original_packets: List[Packet] = rdpcap(original_pcap_path)
    anonymized_packets: List[Packet] = rdpcap(anonymized_pcap_path)

    # Check if the files have the same number of packets
    if len(original_packets) != len(anonymized_packets):
        logging.error("Validation Failed: The number of packets in the original and anonymized files does not match.")
        hasError = True
        return False

    for orig_pkt, anon_pkt, index in zip(original_packets, anonymized_packets, range(len(original_packets))):
        # Check MAC addresses
        if Ether in orig_pkt and Ether in anon_pkt:
            if orig_pkt[Ether].src == anon_pkt[Ether].src or orig_pkt[Ether].dst == anon_pkt[Ether].dst:
                logging.error(f"Original MAC address found in the anonymized packet: {orig_pkt[Ether].src} - {orig_pkt[Ether].dst} on packet #{index}")
                hasError = True

        # Check IPv4 addresses
        if IP in orig_pkt and IP in anon_pkt:
            if orig_pkt[IP].src == anon_pkt[IP].src or orig_pkt[IP].dst == anon_pkt[IP].dst:
                 logging.error(f"Original IPV4 address found in the anonymized packet: {orig_pkt[IP].src} - {orig_pkt[IP].dst} on packet #{index}")
                 hasError = True
      
        # Check IPv6 addresses
        if IPv6 in orig_pkt and IPv6 in anon_pkt:
            if orig_pkt[IPv6].src == anon_pkt[IPv6].src or orig_pkt[IPv6].dst == anon_pkt[IPv6].dst:
                 logging.error(f"Original IPV6 address found in the anonymized packet: {orig_pkt[IPv6].src} - {orig_pkt[IPv6].dst} on packet #{index}")
                 hasError = True
         
        # Check port numbers TCP
        if TCP in orig_pkt and TCP in anon_pkt:
            if orig_pkt[TCP].sport == anon_pkt[TCP].sport or orig_pkt[TCP].dport == anon_pkt[TCP].dport:
                logging.error(f"Original port number found in the anonymized packet: {orig_pkt[TCP].sport} - {orig_pkt[TCP].dport} on packet #{index}")
                hasError = True

        # Check port numbers UDP
        if UDP in orig_pkt and UDP in anon_pkt:
            if orig_pkt[UDP].sport == anon_pkt[UDP].sport or orig_pkt[UDP].dport == anon_pkt[UDP].dport:
                logging.error(f"Original port number found in the anonymized packet: {orig_pkt[UDP].sport} - {orig_pkt[UDP].dport} on packet #{index}")
                hasError = True
         
    print("Anonymization validation finished.")
    if hasError:
        logging.error("Anonymization failed. Some original information was found in the anonymized packets.")
    else:
        logging.info("Anonymization successful. No original information was found in the anonymized packets.")

if __name__ == "__main__":
 
    logging.basicConfig(filename='validation_log.txt',filemode='w', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    if len(sys.argv) != 3:
        print("Usage: python validate.py <original_pcap_path> <anonymized_pcap_path>")
    else:
        original_pcap_path = sys.argv[1]
        anonymized_pcap_path = sys.argv[2]
        logging.info(f"Validating anonymization for {original_pcap_path} and {anonymized_pcap_path}")
        validate_anonymization(original_pcap_path, anonymized_pcap_path)
