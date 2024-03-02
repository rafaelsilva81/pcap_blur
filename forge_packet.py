from scapy.all import Ether, IP, TCP, wrpcap

# Função para gerar um pacote normal
def create_normal_packet():
    packet = Ether() / IP(dst="192.168.1.1") / TCP(dport=80)
    return packet

# Função para gerar um pacote com checksum IP incorreto
def create_ip_checksum_error_packet():
    packet = Ether() / IP(dst="192.168.1.2") / TCP(dport=80)
    packet[IP].chksum = 0x1234  # Atribui um valor de checksum incorreto
    return packet

# Função para gerar um pacote com checksum TCP incorreto
def create_tcp_checksum_error_packet():
    packet = Ether() / IP(dst="192.168.1.3") / TCP(dport=80)
    packet[TCP].chksum = 0x1234  # Atribui um valor de checksum incorreto
    return packet

# Adicione mais funções conforme necessário...

def save_packets_to_file(filename):
    # Gera os pacotes
    packets = [
        create_normal_packet(),
        create_ip_checksum_error_packet(),
        create_tcp_checksum_error_packet(),
        # Adicione mais chamadas de função conforme você criar mais tipos de pacotes
    ]
    
    # Salva os pacotes em um arquivo .pcap
    wrpcap(filename, packets)

# Chama a função para salvar os pacotes
save_packets_to_file("packets.pcap")
