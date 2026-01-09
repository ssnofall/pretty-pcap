# backend helper functions for the parser module

def bytes_to_hex(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)

def bytes_to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

def get_payload(pkt) -> bytes:
    if pkt.haslayer("Raw"):
        return bytes(pkt["Raw"].load)
    return b""

def to_json_serializable(value):
    """Convert scapy-specific types to JSON-serializable types"""
    if value is None:
        return None
    
    # Handle FlagValue and other scapy types
    type_name = type(value).__name__
    
    # FlagValue objects (like ip_flags)
    if type_name == "FlagValue":
        return str(value)
    
    # Try to convert to int if it's a numeric type
    try:
        if hasattr(value, '__int__'):
            return int(value)
    except (ValueError, TypeError):
        pass
    
    # Try to convert to string for other complex types
    if not isinstance(value, (str, int, float, bool, list, dict)):
        return str(value)
    
    # Handle dicts - recursively convert values
    if isinstance(value, dict):
        return {k: to_json_serializable(v) for k, v in value.items()}
    
    # Handle lists - recursively convert items
    if isinstance(value, list):
        return [to_json_serializable(item) for item in value]
    
    return value

def format_time(timestamp: float, relative: bool = False) -> str:
    """Format timestamp for display"""
    if relative:
        if timestamp < 1:
            return f"{timestamp * 1000:.3f} ms"
        elif timestamp < 60:
            return f"{timestamp:.6f} s"
        else:
            minutes = int(timestamp // 60)
            seconds = timestamp % 60
            return f"{minutes}m {seconds:.6f}s"
    else:
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def generate_info_column(packet_data: dict) -> str:
    """Generate Wireshark-like info column"""
    protocol = packet_data.get("protocol", "")
    info_parts = []
    
    if protocol == "TCP":
        flags = packet_data.get("tcp_flags_str", "")
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        
        if flags:
            info_parts.append(flags)
        
        if src_port and dst_port:
            info_parts.append(f"{src_port} → {dst_port}")
        
        # Add sequence/ack info for SYN/ACK packets
        if "SYN" in flags or "ACK" in flags:
            seq = packet_data.get("tcp_seq")
            ack = packet_data.get("tcp_ack")
            if seq is not None:
                info_parts.append(f"Seq={seq}")
            if ack is not None and ack > 0:
                info_parts.append(f"Ack={ack}")
        
        # HTTP over TCP
        if packet_data.get("http_method"):
            method = packet_data.get("http_method")
            path = packet_data.get("http_path", "")
            info_parts.append(f"{method} {path}")
        elif packet_data.get("http_status"):
            status = packet_data.get("http_status")
            reason = packet_data.get("http_reason", "")
            info_parts.append(f"{status} {reason}")
    
    elif protocol == "UDP":
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        if src_port and dst_port:
            info_parts.append(f"{src_port} → {dst_port}")
        
        # DNS over UDP
        if packet_data.get("dns_qname"):
            qname = packet_data.get("dns_qname")
            is_response = packet_data.get("dns_response", False)
            if is_response:
                info_parts.append(f"Standard query response {qname}")
            else:
                info_parts.append(f"Standard query {qname}")
    
    elif protocol == "ICMP":
        icmp_type = packet_data.get("icmp_type")
        icmp_code = packet_data.get("icmp_code")
        if icmp_type is not None:
            type_names = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                4: "Source Quench",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded",
                12: "Parameter Problem",
                13: "Timestamp Request",
                14: "Timestamp Reply"
            }
            type_name = type_names.get(icmp_type, f"Type {icmp_type}")
            if icmp_code is not None and icmp_code > 0:
                info_parts.append(f"{type_name} Code {icmp_code}")
            else:
                info_parts.append(type_name)
    
    elif protocol == "ARP":
        src_ip = packet_data.get("src_ip")
        dst_ip = packet_data.get("dst_ip")
        if src_ip and dst_ip:
            info_parts.append(f"Who has {dst_ip}? Tell {src_ip}")
    
    elif protocol == "DNS":
        qname = packet_data.get("dns_qname")
        is_response = packet_data.get("dns_response", False)
        if qname:
            if is_response:
                info_parts.append(f"Standard query response {qname}")
            else:
                info_parts.append(f"Standard query {qname}")
    
    elif protocol == "HTTP":
        method = packet_data.get("http_method")
        if method:
            path = packet_data.get("http_path", "")
            info_parts.append(f"{method} {path}")
        else:
            status = packet_data.get("http_status")
            if status:
                reason = packet_data.get("http_reason", "")
                info_parts.append(f"{status} {reason}")
    
    else:
        if protocol:
            info_parts.append(protocol)
    
    # Add length if no other info
    if not info_parts:
        length = packet_data.get("length", 0)
        info_parts.append(f"Length {length}")
    
    return " ".join(info_parts) if info_parts else ""