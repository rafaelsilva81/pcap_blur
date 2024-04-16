from scapy.all import Packet
from scapy.layers.l2 import Ether
import random
from typing import Dict, Tuple

# Mapeamentos para identificadores de fabricante e de dispositivo
fabricante_map: Dict[str, str] = {}
dispositivo_map: Dict[str, str] = {}

def gera_permutacao_mac(mac_part: str, mac_map: Dict[str, str]) -> str:
    """
    Gera uma permutação para uma parte do endereço MAC.

    :param mac_part: Parte do endereço MAC a ser permutada.
    :param mac_map: Dicionário de mapeamento para permutações.
    :return: Parte permutada do endereço MAC.
    """
    if mac_part in mac_map:
        return mac_map[mac_part]
    else:
        # Gerar permutação aleatória
        permuted_part = ':'.join(['%02x' % random.randint(0, 255) for _ in range(3)])
        while permuted_part in mac_map.values():
            permuted_part = ':'.join(['%02x' % random.randint(0, 255) for _ in range(3)])
        mac_map[mac_part] = permuted_part
        return permuted_part

def anon_mac_address(packet: Packet) -> Packet:
    """
    Anonimiza o endereço MAC de um pacote.

    :param packet: Pacote Scapy a ser processado.
    """
    if packet.haslayer(Ether):
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst

        # Dividir endereço MAC em fabricante e dispositivo
        fabricante_src, dispositivo_src = mac_src[:8], mac_src[9:]
        fabricante_dst, dispositivo_dst = mac_dst[:8], mac_dst[9:]

        # Aplicar permutação
        mac_src_anon = gera_permutacao_mac(fabricante_src, fabricante_map) + ":" + gera_permutacao_mac(dispositivo_src, dispositivo_map)
        mac_dst_anon = gera_permutacao_mac(fabricante_dst, fabricante_map) + ":" + gera_permutacao_mac(dispositivo_dst, dispositivo_map)

        # Definir endereços MAC anonimizados no pacote
        packet[Ether].src = mac_src_anon
        packet[Ether].dst = mac_dst_anon

    return packet
