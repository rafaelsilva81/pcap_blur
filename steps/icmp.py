import logging as log

from scapy.all import Packet
from scapy.layers.inet import ICMP
from yacryptopan import CryptoPAn

from utils import get_cryptopan


def anon_icmp_v4(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
    if packet.haslayer(ICMP):
        log.info(
            f"ICMP packet found at index {index}, truncating potential sensible data"
        )
        if packet[ICMP].gw is not None:
            packet[ICMP].gw = cp.anonymize(packet[ICMP].gw)
        if packet[ICMP].addr_mask is not None:
            packet[ICMP].addr_mask = cp.anonymize(packet[ICMP].addr_mask)
        if packet[ICMP].ts_ori is not None:
            packet[ICMP].ts_ori = 0
        if packet[ICMP].ts_rx is not None:
            packet[ICMP].ts_rx = 0
        if packet[ICMP].ts_tx is not None:
            packet[ICMP].ts_tx = 0
        del packet[ICMP].chksum
    return packet


# def anon_icmp_v6(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
#     if packet.haslayer(ICMPv6DestUnreach):
#         del packet[ICMPv6DestUnreach].cksum
#     if packet.haslayer(ICMPv6EchoReply):
#         log.info(f"ICMPv6 Echo Reply packet found at index {index}, truncating data")
#         packet[ICMPv6EchoReply].data = ""
#         del packet[ICMPv6EchoReply].cksum
#     if packet.haslayer(ICMPv6EchoRequest):
#         log.info(f"ICMPv6 Echo Request packet found at index {index}, truncating data")
#         packet[ICMPv6EchoRequest].data = ""
#         del packet[ICMPv6EchoRequest].cksum
#     if packet.haslayer(ICMPv6HAADReply):
#         log.info(
#             f"ICMPv6 HAAD Reply packet found at index {index}, truncating adresses"
#         )
#         packet[ICMPv6HAADReply].addresses = []
#         del packet[ICMPv6HAADReply].cksum
#     if packet.haslayer(ICMPv6HAADRequest):
#         del packet[ICMPv6HAADRequest].cksum
#     if packet.haslayer(ICMPv6MLDMultAddrRec):
#         log.info(
#             f"ICMPv6 MLD Multi-Address Record packet found at index {index}, anonymizing"
#         )
#         packet[ICMPv6MLDMultAddrRec].dst = cp.anonymize(
#             packet[ICMPv6MLDMultAddrRec].dst
#         )
#         packet[ICMPv6MLDMultAddrRec].sources = []
#     if packet.haslayer(ICMPv6MLDone):
#         log.info(f"ICMPv6 MLD Done packet found at index {index}, truncating data")
#         packet[ICMPv6MLDone].mladdr = ""
#         del packet[ICMPv6MLDone].cksum
#     if packet.haslayer(ICMPv6MLQuery):
#         log.info(f"ICMPv6 MLD Query packet found at index {index}, truncating data")
#         packet[ICMPv6MLQuery].mladdr = ""
#         del packet[ICMPv6MLQuery].cksum
#     if packet.haslayer(ICMPv6MLQuery2):
#         log.info(f"ICMPv6 MLD Query2 packet found at index {index}, truncating data")
#         packet[ICMPv6MLQuery2].mladdr = ""
#         packet[ICMPv6MLQuery2].sources = []
#         del packet[ICMPv6MLQuery2].cksum
#     if packet.haslayer(ICMPv6MLReport):
#         log.info(f"ICMPv6 MLD Report packet found at index {index}, truncating data")
#         packet[ICMPv6MLReport].mladdr = ""
#         del packet[ICMPv6MLReport].cksum
#     if packet.haslayer(ICMPv6MLReport2):
#         log.info(f"ICMPv6 MLD Report2 packet found at index {index}, truncating data")
#         packet[ICMPv6MLReport2].mladdr = ""
#         packet[ICMPv6MLReport2].records = []
#         del packet[ICMPv6MLReport2].cksum
#     if packet.haslayer(ICMPv6MPAdv):
#         log.info(
#             f"ICMPv6 MP Advertisement packet found at index {index}, truncating data"
#         )
#         del packet[ICMPv6MPAdv].cksum
#     if packet.haslayer(ICMPv6MRD_Advertisement):
#         log.info(
#             f"ICMPv6 MRD Advertisement packet found at index {index}, truncating data"
#         )
#         del packet[ICMPv6MRD_Advertisement].cksum
#     if packet.haslayer(ICMPv6MRD_Solicitation):
#         log.info(
#             f"ICMPv6 MRD Solicitation packet found at index {index}, truncating data"
#         )
#         del packet[ICMPv6MRD_Solicitation].cksum
#     if packet.haslayer(ICMPv6MRD_Termination):
#         log.info(
#             f"ICMPv6 MRD Termination packet found at index {index}, truncating data"
#         )
#         del packet[ICMPv6MRD_Termination].cksum
#     print(packet.show2())
#     return packet  # TODO


# def anon_icmp_v6(packet: Packet, index: int, cp: CryptoPAn) -> Packet:
#     if packet.haslayer(IPv6) and packet[IPv6].nh == 58:
#         # Obter a próxima camada depois da layer IPv6
#         load = packet.getlayer(IPv6).payload

#         for index, layer in enumerate(load.layers()):
#             log.info(f"Truncation data for {layer} layer at index {index}")

#             # Atributos provavelmente safe de mudar
#             safe_setattr(packet[layer], "data", b"")
#             safe_setattr(packet[layer], "addresses", [])
#             safe_setattr(packet[layer], "auxdata", b"")
#             safe_setattr(packet[layer], "sources", [])
#             safe_setattr(packet[layer], "URI", b"")
#             safe_setattr(packet[layer], "searchlist", [])

#             # OLHAR (ip6field)
#             safe_setattr(packet[layer], "dst", "::")
#             safe_setattr(packet[layer], "mladdr", "::")

#             # OLHAR MUITO (macfield)
#             safe_setattr(packet[layer], "lladdr", "00:00:00:00:00:00")

#             if hasattr(packet[layer], "cksum"):
#                 del packet[layer].cksum  # Recalculate checksums

#     return packet  # TODO


def anon_icmp(packet: Packet, index: int) -> Packet:
    cp = get_cryptopan()
    if cp is None:
        log.error("CryptoPAn not configured, cannot anonymize IP addresses")
        raise Exception("CryptoPAn not configured")

    packet = anon_icmp_v4(packet, index, cp)

    # packet = anon_icmp_v6(packet, index, cp)
    return packet
