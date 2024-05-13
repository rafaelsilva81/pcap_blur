from datetime import datetime, timezone
from decimal import Decimal as EDecimal

from scapy.all import Packet


def precision_degradation(timestamp: EDecimal) -> EDecimal:
    """
    Rounds down the timestamp to the nearest minute in UTC, improving performance by avoiding unnecessary conversions.
    """
    # Convert EDecimal directly to datetime in UTC
    timestamp_datetime = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
    # Degrade precision by rounding down to the nearest minute
    degraded_datetime = timestamp_datetime.replace(second=0, microsecond=0)
    # Convert back to EDecimal
    return EDecimal(degraded_datetime.timestamp())


def anon_timestamps(packet: Packet) -> Packet:
    """
    Anonymizes the timestamps of a packet by degrading its precision.
    """
    if hasattr(packet, "time"):
        degraded_ts = precision_degradation(EDecimal(packet.time))
        packet.time = degraded_ts
    return packet
