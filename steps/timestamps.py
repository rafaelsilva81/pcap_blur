from scapy.all import Packet
from algo.precision_degradation import precision_degradation

def anon_timestamps(packet: Packet) -> Packet:
    if packet.haslayer('IP'):
        degraded_ts = precision_degradation(packet.time)
        packet.time = degraded_ts
    return packet
