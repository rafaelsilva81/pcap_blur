import picologging as log
from scapy.all import Packet, PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

log.basicConfig(
    filename="validation_log.txt",
    filemode="w",
    level=log.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

hasError = False


def check_values(orig_pkt: Packet, anon_pkt: Packet, index: int):
    global hasError

    # Check MAC addresses
    if Ether in orig_pkt and Ether in anon_pkt:
        if (
            orig_pkt[Ether].src == anon_pkt[Ether].src
            or orig_pkt[Ether].dst == anon_pkt[Ether].dst
        ):
            log.error(
                f"Original MAC address found: {orig_pkt[Ether].src} - {orig_pkt[Ether].dst} on packet #{index}"
            )
            hasError = True

    # Check IPv4 addresses
    if IP in orig_pkt and IP in anon_pkt:
        if orig_pkt[IP].src == anon_pkt[IP].src or orig_pkt[IP].dst == anon_pkt[IP].dst:
            log.error(
                f"Original IPV4 address found: {orig_pkt[IP].src} - {orig_pkt[IP].dst} on packet #{index}"
            )
            hasError = True

    # Check IPv6 addresses
    if IPv6 in orig_pkt and IPv6 in anon_pkt:
        if (
            orig_pkt[IPv6].src == anon_pkt[IPv6].src
            or orig_pkt[IPv6].dst == anon_pkt[IPv6].dst
        ):
            log.error(
                f"Original IPV6 address found: {orig_pkt[IPv6].src} - {orig_pkt[IPv6].dst} on packet #{index}"
            )
            hasError = True

    # Check port numbers TCP
    if TCP in orig_pkt and TCP in anon_pkt:
        if (
            orig_pkt[TCP].sport == anon_pkt[TCP].sport
            or orig_pkt[TCP].dport == anon_pkt[TCP].dport
        ):
            log.error(
                f"Original port number found: {orig_pkt[TCP].sport} - {orig_pkt[TCP].dport} on packet #{index}"
            )
            hasError = True

    # Check port numbers UDP
    if UDP in orig_pkt and UDP in anon_pkt:
        if (
            orig_pkt[UDP].sport == anon_pkt[UDP].sport
            or orig_pkt[UDP].dport == anon_pkt[UDP].dport
        ):
            log.error(
                f"Original port number found: {orig_pkt[UDP].sport} - {orig_pkt[UDP].dport} on packet #{index}"
            )
            hasError = True


def validate_anonymization(original_pcap_path: str, anonymized_pcap_path: str):
    try:
        print("Validating anonymization. This might take a while...")
        with PcapReader(original_pcap_path) as original_reader, PcapReader(
            anonymized_pcap_path
        ) as anonymized_reader:
            for index, (original_pkt, anon_pkt) in enumerate(
                zip(original_reader, anonymized_reader)
            ):
                check_values(original_pkt, anon_pkt, index)

        if hasError:
            log.error(
                "Anonymization failed. Some original information was found in the anonymized packets."
            )
        else:
            log.info(
                "Anonymization successful. No original information was found in the anonymized packets."
            )

        print("Anonymization validation finished.")
        print("Check ./validation_log.txt for more information.")
    except Exception as e:
        print(f"Anonymization validation failed: {e}")
