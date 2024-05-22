from scapy.all import Packet, rdpcap
from scapy.layers.inet import TCP


class TcpInfo:
    def __init__(self):
        self.packets_info = []

    def analyze_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)

            # Packet information
            packet_info = {
                "flags": tcp_layer.flags,
                "seq": tcp_layer.seq,
                "ack": tcp_layer.ack,
                "history": [],
            }

            if tcp_layer.flags & 0x02:  # SYN
                packet_info["history"].append("SYN")
            if tcp_layer.flags & 0x12:  # SYN+ACK
                packet_info["history"].append("SYN+ACK")
            if tcp_layer.flags & 0x10:  # ACK
                packet_info["history"].append("ACK")
            if tcp_layer.flags & 0x01:  # FIN
                packet_info["history"].append("FIN")

            self.packets_info.append(packet_info)

    def read_pcap(self, filename):
        packets = rdpcap(filename)
        for packet in packets:
            self.analyze_packet(packet)

    def compare_packets(self, other):
        len_self = len(self.packets_info)
        len_other = len(other.packets_info)

        if len_self != len_other:
            print(
                f"Packet count mismatch: {len_self} packets in file 1, {len_other} packets in file 2."
            )

        for i in range(len_self):
            packet1 = self.packets_info[i]
            packet2 = other.packets_info[i]

            if packet1 != packet2:
                print(f"Difference in packet {i + 1}:")
                for key in packet1:
                    if packet1[key] != packet2[key]:
                        print(
                            f"  {key}: {packet1[key]} (file 1) != {packet2[key]} (file 2)"
                        )
                print(packet1)
                print(packet2)

        if len_self != len_other:
            print(
                f"Packet count mismatch: {len_self} packets in file 1, {len_other} packets in file 2."
            )
            if len_self > len_other:
                print(f"Extra packets in file 1 starting from index {len_other + 1}:")
                for i in range(len_other, len_self):
                    print(self.packets_info[i])
            else:
                print(f"Extra packets in file 2 starting from index {len_self + 1}:")
                for i in range(len_self, len_other):
                    print(other.packets_info[i])


def check_tcpinfo(file1, file2):
    tcpinfo1 = TcpInfo()
    tcpinfo2 = TcpInfo()

    tcpinfo1.read_pcap(file1)
    tcpinfo2.read_pcap(file2)

    tcpinfo1.compare_packets(tcpinfo2)

    print("TCP information check finished.")
