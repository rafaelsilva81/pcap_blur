import logging

from scapy.all import Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from yacryptopan import CryptoPAn

# Global cryptopan initialization
cryptopan: CryptoPAn | None = None


def check_checksum(packet: Packet):
    """
    This function checks if the checksum of a packet is valid.

    :param packet: Scapy Packet to be processed.
    :return: None
    """
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
    """
    This function configures the CryptoPAN algorithm with the provided key.

    :param key: Key to be used for the CryptoPAN algorithm.
    :return: None
    """
    global cryptopan
    cryptopan = CryptoPAn(key)


def configure_logging(original_filename: str) -> None:
    """
    This function configures the logging for the original file using the logging module.

    :param original_filename: Original file name.
    :return: None
    """
    logging.basicConfig(
        filename=f"output/{original_filename}_log.txt",
        filemode="w",
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_cryptopan() -> CryptoPAn:
    """
    This function returns the global CryptoPAn instance.

    :return: CryptoPAn instance.
    """
    if cryptopan is None:
        raise Exception("CryptoPAn not configured")
    return cryptopan


def safe_setattr(obj, attr_name, value):
    """
    This function sets an attribute of an object if it exists, otherwise it does nothing.

    :param obj: The object to set the attribute on.
    :param attr_name: The name of the attribute to set.
    :param value: The value to set the attribute to.
    """
    if hasattr(obj, attr_name):
        setattr(obj, attr_name, value)
