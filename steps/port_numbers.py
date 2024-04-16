from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP
import random
from typing import Dict

# Mapeamento de portas originais para portas permutadas
port_map: Dict[int, int] = {}

def create_port_permutation(port: int) -> int:
    """
    Cria uma permutação de porta, garantindo que cada porta original seja mapeada 
    para uma única porta permutada.

    :param port: Porta original.
    :return: Porta permutada.
    """
    # Verificar se a porta já tem uma permutação
    if port in port_map:
        return port_map[port]
    else:
        # Gerar uma permutação aleatória para a porta
        permuted_port = random.randint(0, 65535)
        while permuted_port in port_map.values():
            # Se a permutação já existir, gerar outra
            permuted_port = random.randint(0, 65535)
        
        # Adicionar a permutação ao dicionário
        port_map[port] = permuted_port

    return permuted_port

def anon_port_numbers(packet: Packet) -> None:
    """
    Processa um pacote Scapy, aplicando permutação de porta se for um pacote TCP/IP.

    :param packet: Pacote a ser processado.
    """
    if packet.haslayer(IP):
      if packet.haslayer(TCP):
        # Aplicar permutação de porta
        packet[TCP].sport = create_port_permutation(packet[TCP].sport)
        packet[TCP].dport = create_port_permutation(packet[TCP].dport)
      if packet.haslayer('UDP'):
        # Aplicar permutação de porta
        packet[UDP].sport = create_port_permutation(packet[UDP].sport)
        packet[UDP].dport = create_port_permutation(packet[UDP].dport)  
    return packet
  
