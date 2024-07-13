from datetime import datetime, timezone

import tzlocal
from scapy.all import Packet
from scapy.layers.inet import IP, TCP, IPOption_Timestamp
from scapy.utils import EDecimal


def degrade_edecimal_timestamp(timestamp: EDecimal) -> EDecimal:
    """
    Converts the timestamp EDecimal to a float and then degrades it to the nearest millisecond.

    :param timestamp: EDecimal timestamp to be converted and degraded.
    :return: Degraded timestamp.
    """
    timestamp_float = float(timestamp)

    local_tz = tzlocal.get_localzone()

    timestamp_datetime = datetime.fromtimestamp(timestamp_float, tz=timezone.utc)

    timestamp_datetime_local = timestamp_datetime.astimezone(local_tz)

    degraded_datetime_local = timestamp_datetime_local.replace(microsecond=0)

    degraded_datetime_utc = degraded_datetime_local.astimezone(timezone.utc)

    degraded_edecimal = EDecimal(degraded_datetime_utc.timestamp())
    return degraded_edecimal


def degrade_integer_timestamp(timestamp: int) -> int:
    """
    Degrades a TCP timestamp to the nearest millisecond.

    :param timestamp: The timestamp to be degraded.
    :return: The degraded timestamp.
    """
    return int(timestamp / 1000) * 1000


def anon_timestamps(packet: Packet) -> Packet:
    """
    Anonymizes the timestamps of a packet using the precision degradation function.
    This function will use the Precision Degradation algorithm to degrade the timestamps to the nearest millisecond.
    This function will degrade Timestamps present on the Packet Metadata as well as TCP Timestamp Options and IP (and IPv6) Timestamp Options.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """

    # Degrade the timestamp in the packet metadata
    degraded_packet_ts = degrade_edecimal_timestamp(packet.time)
    packet.time = degraded_packet_ts

    # Degrade the timestamps in the TCP options (if any)
    if packet.haslayer(TCP):
        # Get TCP timestamp option if it exists
        tcp_options = packet.getlayer(TCP).options

        # Options is a list of tuples
        # Find the option where the first element is "Timestamp"
        original_timestamp_option = next(
            (opt for opt in tcp_options if opt[0] == "Timestamp"), None
        )

        if original_timestamp_option is not None:
            # The timestamp option has the following format:
            # ("Timestamp", (TSval, Tsecr))
            timestamps = original_timestamp_option[1]

            # Iterate over the timestamps tuple
            degraded_timestamps = ()
            for ts in timestamps:
                degraded_ts = degrade_integer_timestamp(ts)
                degraded_timestamps += (degraded_ts,)

            # Set the degraded timestamps in the TCP option
            new_timestamp_option = ("Timestamp", degraded_timestamps)
            tcp_options.remove(original_timestamp_option)
            tcp_options.insert(0, new_timestamp_option)

        packet.getlayer(TCP).options = tcp_options

    # Degrade the timestamps in the IPv4 options (if any)
    if packet.haslayer(IP):
        # Get IP timestamp option if it exists
        ip_opt = packet.getlayer(IP).options

        print("original options", ip_opt)
        # Iterate the list of options
        for i, opt in enumerate(ip_opt):
            # Check if the option is of class IPOption_Timestamp
            if isinstance(opt, IPOption_Timestamp):
                # Degrade the timestamp
                degraded_timestamp = degrade_integer_timestamp(opt.timestamp)
                opt.timestamp = degraded_timestamp

                # Set the new timestamp in the IPOption_Timestamp object
                packet.getlayer(IP).options[i] = opt

    return packet
