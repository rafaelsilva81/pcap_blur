from random import randint

from scapy.all import *


# Function to generate a random IPv4 address
def random_ipv4():
    return ".".join(str(randint(0, 255)) for _ in range(4))


# Function to generate a random IPv6 address
def random_ipv6():
    return "2001:" + ":".join(f"{randint(0, 65535):x}" for _ in range(7))


# Full range of standard ICMP types
icmp_types = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
    30: "Traceroute",
    31: "Datagram Conversion Error",
    32: "Mobile Host Redirect",
    33: "IPv6 Where-Are-You",
    34: "IPv6 I-Am-Here",
    35: "Mobile Registration Request",
    36: "Mobile Registration Reply",
    37: "Domain Name Request",
    38: "Domain Name Reply",
    39: "SKIP",
    40: "Photuris",
}

# Full range of standard ICMPv6 types
icmpv6_types = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect Message",
    138: "Router Renumbering",
    139: "ICMP Node Information Query",
    140: "ICMP Node Information Response",
    141: "Inverse Neighbor Discovery Solicitation Message",
    142: "Inverse Neighbor Discovery Advertisement Message",
    143: "Version 2 Multicast Listener Report",
    144: "Home Agent Address Discovery Request Message",
    145: "Home Agent Address Discovery Reply Message",
    146: "Mobile Prefix Solicitation",
    147: "Mobile Prefix Advertisement",
    148: "Certification Path Solicitation Message",
    149: "Certification Path Advertisement Message",
    151: "Multicast Router Advertisement",
    152: "Multicast Router Solicitation",
    153: "Multicast Router Termination",
    155: "RPL Control Message",
}

packets = []

# Create ICMP packets
for icmp_type in icmp_types:
    packet = (
        IP(dst=random_ipv4(), src=random_ipv4()) / ICMP(type=icmp_type) / b"Hello ICMP!"
    )
    packets.append(packet)

# Create ICMPv6 packets
for icmpv6_type in icmpv6_types:
    packet = (
        IPv6(dst=random_ipv6(), src=random_ipv6())
        / ICMPv6EchoRequest(type=icmpv6_type)
        / b"Hello ICMPv6!"
    )
    packets.append(packet)

# Save the crafted packets to a pcap file
wrpcap("combined_icmp_icmpv6_packets.pcap", packets)
