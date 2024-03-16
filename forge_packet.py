from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import random

def create_packet():
    # Escolhe aleatoriamente entre TCP e UDP
    protocol = random.choice([TCP, UDP])
    
    # Define os endereços de IP de origem e destino de forma aleatória
    src_ip = f"192.168.1.{random.randint(1,254)}"
    dst_ip = f"192.168.1.{random.randint(1,254)}"
    
    # Define portas de origem e destino aleatoriamente
    src_port = random.randint(1024,65535)
    dst_port = random.randint(1024,65535)
    
    # Cria o cabeçalho IP
    ip = IP(src=src_ip, dst=dst_ip)
    
    # Cria o cabeçalho TCP ou UDP
    if protocol == TCP:
        pkt = ip / TCP(sport=src_port, dport=dst_port)
    else:
        pkt = ip / UDP(sport=src_port, dport=dst_port)
    
    # Adiciona dados de camada de aplicação
    data = "Hello, this is a test message!" * random.randint(1, 5)
    pkt = pkt / Raw(load=data)
    
    # Introduz erros aleatoriamente
    if random.choice([True, False]):
        if protocol == TCP:
            pkt[TCP].chksum = random.randint(0,65535)
        else:
            pkt[UDP].chksum = random.randint(0,65535)
    
    # Retorna o pacote criado
    return pkt

def create_packet_sequence(num_packets):
    return [create_packet() for _ in range(num_packets)]

def main():
    # Gera um número aleatório de pacotes, mas sempre no mínimo 100
    num_packets = random.randint(100, 200)
    
    # Gera a sequência de pacotes
    packets = create_packet_sequence(num_packets)
    
    # Salva os pacotes em um arquivo .pcap
    file_name = "forged.pcap"
    wrpcap(file_name, packets)
    
    print(f"Gerados e salvos {len(packets)} pacotes no arquivo {file_name}")

if __name__ == "__main__":
    main()
