from scapy.all import Packet
from datetime import datetime, timezone
import tzlocal

def precision_degradation(timestamp: float) -> float:
    # Convert EDecimal to float
    timestamp_float = float(timestamp)

    # Get the local timezone from the OS
    local_tz = tzlocal.get_localzone()

    # Convert Unix timestamp to datetime object in UTC
    timestamp_datetime = datetime.utcfromtimestamp(timestamp_float).replace(tzinfo=timezone.utc)

    # Convert to local timezone
    timestamp_datetime = timestamp_datetime.astimezone(local_tz)

    # Zero out minutes and seconds
    degraded_datetime = timestamp_datetime.replace(minute=0, second=0, microsecond=0)

    # Convert back to Unix timestamp in UTC
    degraded_utc_datetime = degraded_datetime.astimezone(timezone.utc)
    return degraded_utc_datetime.timestamp()


def anon_timestamps(packet: Packet) -> Packet:
    if packet.haslayer('IP'):
        degraded_ts = precision_degradation(packet.time)
        packet.time = degraded_ts
    return packet
