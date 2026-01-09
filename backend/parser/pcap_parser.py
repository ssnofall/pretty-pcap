from scapy.all import rdpcap, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# HTTP layers might not be available in all scapy versions
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False
    HTTPRequest = None
    HTTPResponse = None

from parser.helpers import bytes_to_hex, bytes_to_ascii, get_payload, format_time, generate_info_column, to_json_serializable

# Core parser function
def parse_pcap(file_path: str) -> dict:
    packets = rdpcap(file_path)
    parsed_packets = []
    
    first_packet_time = float(packets[0].time) if len(packets) > 0 else 0.0
    
    # Statistics
    protocol_counts = {}
    total_bytes = 0
    total_packets = len(packets)

    for idx, pkt in enumerate(packets):
        packet_data = {
            "no": idx + 1,
            "time": float(pkt.time),
            "time_relative": float(pkt.time) - first_packet_time,
            "time_delta": 0.0 if idx == 0 else float(pkt.time) - float(packets[idx-1].time),
            "length": len(pkt),
            "length_caplen": len(pkt) if hasattr(pkt, '__len__') else 0,

            # Ethernet
            "eth_src": None,
            "eth_dst": None,
            "eth_type": None,

            # Network
            "src_ip": None,
            "dst_ip": None,
            "ip_version": None,
            "ip_ttl": None,
            "ip_tos": None,
            "ip_id": None,
            "ip_flags": None,
            "ip_frag": None,

            # Transport
            "src_port": None,
            "dst_port": None,
            
            # TCP specific
            "tcp_flags": None,
            "tcp_flags_str": None,
            "tcp_seq": None,
            "tcp_ack": None,
            "tcp_window": None,
            "tcp_urgent": None,
            "tcp_options": None,
            
            # UDP specific
            "udp_length": None,
            "udp_checksum": None,
            
            # ICMP specific
            "icmp_type": None,
            "icmp_code": None,
            "icmp_id": None,
            "icmp_seq": None,
            
            # DNS specific
            "dns_qname": None,
            "dns_qtype": None,
            "dns_rcode": None,
            "dns_ancount": None,
            "dns_arcount": None,
            "dns_nscount": None,
            "dns_qdcount": None,
            "dns_response": None,
            
            # HTTP specific
            "http_method": None,
            "http_path": None,
            "http_version": None,
            "http_status": None,
            "http_reason": None,
            "http_headers": None,

            # Protocol info
            "protocol": None,
            "protocol_layers": [],

            # Payload
            "payload_len": 0,
            "payload_hex": "",
            "payload_ascii": "",
            "raw_hex": "",
            "raw_ascii": "",
            
            # Info column (like Wireshark)
            "info": ""
        }

        # Track protocol layers
        layer_names = []
        if pkt.haslayer(Ether):
            layer_names.append("Ethernet")
        if pkt.haslayer(IP):
            layer_names.append("IP")
        if pkt.haslayer(ARP):
            layer_names.append("ARP")
        if pkt.haslayer(TCP):
            layer_names.append("TCP")
        if pkt.haslayer(UDP):
            layer_names.append("UDP")
        if pkt.haslayer(ICMP):
            layer_names.append("ICMP")
        if pkt.haslayer(DNS):
            layer_names.append("DNS")
        if HTTP_AVAILABLE and (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)):
            layer_names.append("HTTP")
        if pkt.haslayer(Raw):
            layer_names.append("Raw")
        
        packet_data["protocol_layers"] = layer_names

        # Ethernet
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            packet_data["eth_src"] = str(eth.src) if eth.src else None
            packet_data["eth_dst"] = str(eth.dst) if eth.dst else None
            packet_data["eth_type"] = hex(eth.type) if eth.type else None

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            packet_data["protocol"] = "ARP"
            packet_data["src_ip"] = str(arp.psrc) if arp.psrc else None
            packet_data["dst_ip"] = str(arp.pdst) if arp.pdst else None
            protocol_counts["ARP"] = protocol_counts.get("ARP", 0) + 1

        # IP
        elif pkt.haslayer(IP):
            ip = pkt[IP]
            packet_data["src_ip"] = str(ip.src) if ip.src else None
            packet_data["dst_ip"] = str(ip.dst) if ip.dst else None
            packet_data["ip_version"] = to_json_serializable(ip.version)
            packet_data["ip_ttl"] = to_json_serializable(ip.ttl)
            packet_data["ip_tos"] = to_json_serializable(ip.tos)
            packet_data["ip_id"] = to_json_serializable(ip.id)
            packet_data["ip_flags"] = to_json_serializable(ip.flags)
            packet_data["ip_frag"] = to_json_serializable(ip.frag)

            # TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                packet_data["protocol"] = "TCP"
                packet_data["src_port"] = to_json_serializable(tcp.sport)
                packet_data["dst_port"] = to_json_serializable(tcp.dport)
                packet_data["tcp_seq"] = to_json_serializable(tcp.seq)
                packet_data["tcp_ack"] = to_json_serializable(tcp.ack)
                packet_data["tcp_window"] = to_json_serializable(tcp.window)
                packet_data["tcp_urgent"] = to_json_serializable(tcp.urgptr)
                
                # TCP Flags
                flags = []
                tcp_flags_int = int(tcp.flags) if hasattr(tcp.flags, '__int__') else tcp.flags
                if tcp_flags_int & 0x01: flags.append("FIN")
                if tcp_flags_int & 0x02: flags.append("SYN")
                if tcp_flags_int & 0x04: flags.append("RST")
                if tcp_flags_int & 0x08: flags.append("PSH")
                if tcp_flags_int & 0x10: flags.append("ACK")
                if tcp_flags_int & 0x20: flags.append("URG")
                if tcp_flags_int & 0x40: flags.append("ECE")
                if tcp_flags_int & 0x80: flags.append("CWR")
                
                packet_data["tcp_flags"] = to_json_serializable(tcp.flags)
                packet_data["tcp_flags_str"] = " ".join(flags) if flags else "None"
                
                # TCP Options
                if tcp.options:
                    packet_data["tcp_options"] = to_json_serializable(tcp.options)
                
                protocol_counts["TCP"] = protocol_counts.get("TCP", 0) + 1

            # UDP
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                packet_data["protocol"] = "UDP"
                packet_data["src_port"] = to_json_serializable(udp.sport)
                packet_data["dst_port"] = to_json_serializable(udp.dport)
                packet_data["udp_length"] = to_json_serializable(udp.len)
                packet_data["udp_checksum"] = hex(udp.chksum) if udp.chksum else None
                protocol_counts["UDP"] = protocol_counts.get("UDP", 0) + 1
                
                # DNS over UDP
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    packet_data["dns_rcode"] = to_json_serializable(dns.rcode)
                    packet_data["dns_ancount"] = to_json_serializable(dns.ancount)
                    packet_data["dns_arcount"] = to_json_serializable(dns.arcount)
                    packet_data["dns_nscount"] = to_json_serializable(dns.nscount)
                    packet_data["dns_qdcount"] = to_json_serializable(dns.qdcount)
                    packet_data["dns_response"] = bool(dns.qr == 1)
                    
                    # Get DNS query name
                    if dns.qdcount > 0 and dns.qd:
                        qr = dns.qd[0]  # First query
                        if hasattr(qr, 'qname'):
                            packet_data["dns_qname"] = qr.qname.decode('utf-8', errors='ignore') if isinstance(qr.qname, bytes) else str(qr.qname)
                        if hasattr(qr, 'qtype'):
                            packet_data["dns_qtype"] = to_json_serializable(qr.qtype)
                    protocol_counts["DNS"] = protocol_counts.get("DNS", 0) + 1

            # ICMP
            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                packet_data["protocol"] = "ICMP"
                packet_data["icmp_type"] = to_json_serializable(icmp.type)
                packet_data["icmp_code"] = to_json_serializable(icmp.code)
                if hasattr(icmp, 'id'):
                    packet_data["icmp_id"] = to_json_serializable(icmp.id)
                if hasattr(icmp, 'seq'):
                    packet_data["icmp_seq"] = to_json_serializable(icmp.seq)
                protocol_counts["ICMP"] = protocol_counts.get("ICMP", 0) + 1

            else:
                packet_data["protocol"] = "IP"
                protocol_counts["IP"] = protocol_counts.get("IP", 0) + 1

        else:
            packet_data["protocol"] = "L2_UNKNOWN"
            protocol_counts["L2_UNKNOWN"] = protocol_counts.get("L2_UNKNOWN", 0) + 1

        # HTTP
        if HTTP_AVAILABLE:
            if pkt.haslayer(HTTPRequest):
                http = pkt[HTTPRequest]
                packet_data["http_method"] = http.Method.decode('utf-8', errors='ignore') if isinstance(http.Method, bytes) else str(http.Method)
                packet_data["http_path"] = http.Path.decode('utf-8', errors='ignore') if isinstance(http.Path, bytes) else str(http.Path)
                packet_data["http_version"] = http.Http_Version.decode('utf-8', errors='ignore') if isinstance(http.Http_Version, bytes) else str(http.Http_Version)
                if hasattr(http, 'headers'):
                    headers_dict = dict(http.headers) if http.headers else None
                    packet_data["http_headers"] = to_json_serializable(headers_dict)
                protocol_counts["HTTP"] = protocol_counts.get("HTTP", 0) + 1
            elif pkt.haslayer(HTTPResponse):
                http = pkt[HTTPResponse]
                packet_data["http_version"] = http.Http_Version.decode('utf-8', errors='ignore') if isinstance(http.Http_Version, bytes) else str(http.Http_Version)
                packet_data["http_status"] = to_json_serializable(http.Status_Code) if hasattr(http, 'Status_Code') else None
                packet_data["http_reason"] = http.Reason_Phrase.decode('utf-8', errors='ignore') if isinstance(http.Reason_Phrase, bytes) else str(http.Reason_Phrase)
                if hasattr(http, 'headers'):
                    headers_dict = dict(http.headers) if http.headers else None
                    packet_data["http_headers"] = to_json_serializable(headers_dict)
                protocol_counts["HTTP"] = protocol_counts.get("HTTP", 0) + 1

        # Payload and Raw data
        payload = get_payload(pkt)
        packet_data["payload_len"] = len(payload)
        packet_data["payload_hex"] = bytes_to_hex(payload[:256])  # Show more bytes
        packet_data["payload_ascii"] = bytes_to_ascii(payload[:256])
        
        # Full raw packet hex
        raw_bytes = bytes(pkt)
        packet_data["raw_hex"] = bytes_to_hex(raw_bytes)
        packet_data["raw_ascii"] = bytes_to_ascii(raw_bytes)
        
        # Generate info column
        packet_data["info"] = generate_info_column(packet_data)
        
        # Ensure all values are JSON serializable
        packet_data = {k: to_json_serializable(v) for k, v in packet_data.items()}
        
        total_bytes += len(pkt)
        parsed_packets.append(packet_data)

    # Calculate statistics
    duration = parsed_packets[-1]["time_relative"] if parsed_packets else 0.0
    stats = {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration": duration,
        "protocol_counts": protocol_counts,
        "first_packet_time": first_packet_time,
        "last_packet_time": parsed_packets[-1]["time"] if parsed_packets else 0.0,
        "avg_packet_size": total_bytes / total_packets if total_packets > 0 else 0,
        "packets_per_second": total_packets / duration if duration > 0 else 0
    }

    return {
        "packets": parsed_packets,
        "statistics": stats
    }