from scapy.all import rdpcap
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from parser.helpers import bytes_to_hex, bytes_to_ascii, get_payload

# Core parser function
def parse_pcap(file_path: str) -> list[dict]:
    packets = rdpcap(file_path)
    parsed_packets = []

    for pkt in packets:
        packet_data = {
            "time": float(pkt.time),
            "length": len(pkt),

            # Ethernet
            "eth_src": None,
            "eth_dst": None,
            "eth_type": None,

            # Network
            "src_ip": None,
            "dst_ip": None,

            # Transport
            "src_port": None,
            "dst_port": None,

            # Protocol info
            "protocol": None,

            # Payload
            "payload_len": 0,
            "payload_hex": "",
            "payload_ascii": ""
        }

        # Ethernet
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            packet_data["eth_src"] = eth.src
            packet_data["eth_dst"] = eth.dst
            packet_data["eth_type"] = eth.type

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            packet_data["protocol"] = "ARP"
            packet_data["src_ip"] = arp.psrc
            packet_data["dst_ip"] = arp.pdst

        # IP
        elif pkt.haslayer(IP):
            ip = pkt[IP]
            packet_data["src_ip"] = ip.src
            packet_data["dst_ip"] = ip.dst

            # TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                packet_data["protocol"] = "TCP"
                packet_data["src_port"] = tcp.sport
                packet_data["dst_port"] = tcp.dport

            # UDP
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                packet_data["protocol"] = "UDP"
                packet_data["src_port"] = udp.sport
                packet_data["dst_port"] = udp.dport

            else:
                packet_data["protocol"] = "IP"

        else:
            packet_data["protocol"] = "L2_UNKNOWN"

        # Payload
        payload = get_payload(pkt)
        packet_data["payload_len"] = len(payload)
        packet_data["payload_hex"] = bytes_to_hex(payload[:64])
        packet_data["payload_ascii"] = bytes_to_ascii(payload[:64])

        parsed_packets.append(packet_data)

    return parsed_packets