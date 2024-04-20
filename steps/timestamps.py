from datetime import datetime, timezone

import tzlocal
from scapy.all import Packet
from scapy.utils import EDecimal


def precision_degradation(timestamp: EDecimal) -> EDecimal:
    # Converter o timestamp EDecimal para float
    timestamp_float = float(timestamp)

    local_tz = tzlocal.get_localzone()

    timestamp_datetime = datetime.fromtimestamp(timestamp_float, tz=timezone.utc)

    timestamp_datetime_local = timestamp_datetime.astimezone(local_tz)

    degraded_datetime_local = timestamp_datetime_local.replace(
        minute=0, second=0, microsecond=0
    )

    degraded_datetime_utc = degraded_datetime_local.astimezone(timezone.utc)

    degraded_edecimal = EDecimal(degraded_datetime_utc.timestamp())
    return degraded_edecimal


def anon_timestamps(packet: Packet) -> Packet:
    degraded_ts = precision_degradation(packet.time)
    packet.time = degraded_ts
    return packet
