from scapy.all import *


def forge_icmp():
    print("Forjando pacotes ICMP...")
    types_icmp = range(256)  # ICMP tem 8 bits para tipo, então varia de 0 a 255

    for type_icmp in types_icmp:
        packet = IP(dst="192.168.1.1") / ICMP(type=type_icmp)
        send(packet)
        print(f"Enviado ICMP tipo {type_icmp}")


def forge_icmp6():
    print("Forjando pacotes ICMP6...")
    types_icmp6 = range(256)  # Assumindo 8 bits para tipo no ICMP6 também

    for type_icmp6 in types_icmp6:
        packet = IPv6(dst="fe80::1") / ICMPv6Unknown(type=type_icmp6)
        send(packet)
        print(f"Enviado ICMP6 tipo {type_icmp6}")


if __name__ == "__main__":
    forge_icmp()
    forge_icmp6()
