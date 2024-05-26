from datetime import datetime, timezone

import tzlocal
from scapy.all import Packet
from scapy.utils import EDecimal


def precision_degradation(timestamp: EDecimal) -> EDecimal:
    """
    Converts the timestamp EDecimal to a float and then applies the precision degradation algorithm.

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


def anon_timestamps(packet: Packet) -> Packet:
    """
    Anonymizes the timestamps of a packet using the precision degradation function.

    :param packet: Scapy Packet to be processed.
    :return: Anonymized packet.
    """
    degraded_ts = precision_degradation(packet.time)
    packet.time = degraded_ts
    return packet
