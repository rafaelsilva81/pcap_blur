import random
from typing import Dict

port_map: Dict[int, int] = {}

manufacturer_map: Dict[str, str] = {}
device_map: Dict[str, str] = {}


def generate_permutation_mac(
    mac_part: str, is_group_address: bool = False, is_device_address: bool = False
) -> str:
    """
    Generates a permutation for a part of the MAC address, ensuring it retains group or individual characteristics.

    :param mac_part: Part of the MAC address to be permuted.
    :param mac_map: Dictionary for permutation mapping.
    :param is_group_address: Flag to ensure the resulting MAC is a group address.
    :return: Permuted part of the MAC address.
    """

    mac_map = device_map if is_device_address else manufacturer_map

    if mac_part in mac_map:
        return mac_map[mac_part]
    else:
        # Generate random permutation
        permuted_part = ":".join(["%02x" % random.randint(0, 255) for _ in range(3)])
        while permuted_part in mac_map.values():
            permuted_part = ":".join(
                ["%02x" % random.randint(0, 255) for _ in range(3)]
            )

        # Adjust the first byte to respect the group address property
        bytes = permuted_part.split(":")
        first_byte = int(bytes[0], 16)
        if is_group_address:
            first_byte |= 0x01  # Set LSB to 1
        else:
            first_byte &= 0xFE  # Set LSB to 0
        bytes[0] = "%02x" % first_byte
        permuted_part = ":".join(bytes)

        mac_map[mac_part] = permuted_part
        return permuted_part


def generate_permutation_port(port: int) -> int:
    """
    This function creates a permutation of a port, ensuring that each original port is mapped to a unique permuted port.

    :param port: Original port number.
    :return: Permuted port number.
    """

    # Check if the port has a permutation
    if port in port_map:
        return port_map[port]
    else:
        # Generate a random permutation for the port
        permuted_port = random.randint(0, 65535)
        while permuted_port in port_map.values():
            # If the permutation already exists, generate another
            permuted_port = random.randint(0, 65535)

        # Add the permutation to the dictionary
        port_map[port] = permuted_port

    return permuted_port
