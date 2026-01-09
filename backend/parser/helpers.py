# backend helper functions for the parser module

def bytes_to_hex(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)

def bytes_to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

def get_payload(pkt) -> bytes:
    if pkt.haslayer("Raw"):
        return bytes(pkt["Raw"].load)
    return b""