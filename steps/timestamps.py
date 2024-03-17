from scapy.all import Packet
from datetime import datetime, timezone
import tzlocal

def precision_degradation(timestamp: float) -> float:
    # Não é necessário converter de EDecimal para float, assumindo que o input já é float

    # Obtém o fuso horário local do sistema operacional
    local_tz = tzlocal.get_localzone()

    # Converte o timestamp Unix para um objeto datetime em UTC
    timestamp_datetime = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    # Converte para o fuso horário local
    timestamp_datetime_local = timestamp_datetime.astimezone(local_tz)

    # Zera minutos e segundos
    degraded_datetime_local = timestamp_datetime_local.replace(minute=0, second=0, microsecond=0)

    # Converte de volta para UTC
    degraded_datetime_utc = degraded_datetime_local.astimezone(timezone.utc)

    # Retorna o timestamp Unix modificado
    return degraded_datetime_utc.timestamp()

def anon_timestamps(packet: Packet) -> Packet:
    degraded_ts = precision_degradation(packet.time)
    packet.time = degraded_ts
    return packet
