import os

from yacryptopan import CryptoPAn

cryptopan = CryptoPAn(os.urandom(32))


def configure_cryptopan(key: bytes) -> None:
    """
    This function configures the CryptoPAn algorithm with the provided key.

    :param key: Key to be used for the CryptoPAn algorithm.
    :return: None
    """
    global cryptopan
    cryptopan = CryptoPAn(key)


def prefix_preserving_cryptopan(address: str) -> str:
    """
    This function anonymizes an IP address using the prefix-preserving cryptopan algorithm.

    :param address: IP address to be anonymized.
    :return: Anonymized IP address.
    """

    return cryptopan.anonymize(address)
