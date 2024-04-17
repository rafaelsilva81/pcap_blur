import logging

from scapy.all import Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from yacryptopan import CryptoPAn

cryptopan: CryptoPAn | None = None


def check_checksum(packet: Packet):
    # Validar se o checksum do pacote é válido
    if packet.haslayer(IP):
        original_checksum = packet[IP].chksum
        del packet[IP].chksum
        new_checksum = packet[IP].chksum
        if original_checksum != new_checksum:
            logging.warning(f"IP Checksum Invalid for package {packet.summary()}")

    if packet.haslayer(IPv6):
        original_checksum = packet[IPv6].chksum
        del packet[IPv6].chksum
        new_checksum = packet[IPv6].chksum
        if original_checksum != new_checksum:
            logging.warning(f"IPv6 Checksum Invalid for package {packet.summary()}")

    if packet.haslayer(TCP):
        original_checksum = packet[TCP].chksum
        del packet[TCP].chksum
        new_checksum = packet[TCP].chksum
        if original_checksum != new_checksum:
            logging.warning(f"TCP Checksum Invalid for package {packet.summary()}")


def configure_cryptopan(key: bytes) -> None:
    global cryptopan
    cryptopan = CryptoPAn(key)


def configure_logging(original_filename: str) -> None:
    logging.basicConfig(
        filename=f"output/{original_filename}_log.txt",
        filemode="w",
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
