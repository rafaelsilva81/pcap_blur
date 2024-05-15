def black_marker(length: int) -> bytes:
    """
    This function returns a dull black marker of bytes of zeroes of the specified length.

    :param lenght: Length of the black marker.
    :return: Black marker of bytes of zeroes.
    """
    return b"\x00" * length
