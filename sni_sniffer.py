import datetime
from typing import Optional

from scapy.all import IP, Raw, sniff
from scapy.layers.inet6 import IPv6

from config import load_config
from db import insert_sni

_recent_sni_queries: dict[tuple[str, str], datetime.datetime] = {}


def _extract_sni_hostname(payload: bytes) -> Optional[str]:
    # Assumption: parse only a complete TLS ClientHello in the current TCP payload.
    if len(payload) < 6:
        return None

    if payload[0] != 0x16:
        return None

    if payload[5] != 0x01:
        return None

    if len(payload) < 9:
        return None

    record_length = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_length:
        return None

    offset = 9
    if offset + 2 + 32 > len(payload):
        return None

    # Skip legacy_version (2) and random (32).
    offset += 2 + 32

    if offset + 1 > len(payload):
        return None
    session_id_length = payload[offset]
    offset += 1
    if offset + session_id_length > len(payload):
        return None
    offset += session_id_length

    if offset + 2 > len(payload):
        return None
    cipher_suites_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    if offset + cipher_suites_length > len(payload):
        return None
    offset += cipher_suites_length

    if offset + 1 > len(payload):
        return None
    compression_methods_length = payload[offset]
    offset += 1
    if offset + compression_methods_length > len(payload):
        return None
    offset += compression_methods_length

    if offset + 2 > len(payload):
        return None
    extensions_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2

    extensions_end = offset + extensions_length
    if extensions_end > len(payload):
        return None

    while offset + 4 <= extensions_end:
        ext_type = int.from_bytes(payload[offset : offset + 2], "big")
        ext_length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4

        if offset + ext_length > extensions_end:
            return None

        if ext_type == 0x0000:
            ext_data = payload[offset : offset + ext_length]
            if len(ext_data) < 5:
                return None

            server_name_list_length = int.from_bytes(ext_data[0:2], "big")
            list_offset = 2
            list_end = min(2 + server_name_list_length, len(ext_data))

            while list_offset + 3 <= list_end:
                name_type = ext_data[list_offset]
                name_length = int.from_bytes(ext_data[list_offset + 1 : list_offset + 3], "big")
                list_offset += 3

                if list_offset + name_length > list_end:
                    return None

                hostname_bytes = ext_data[list_offset : list_offset + name_length]
                list_offset += name_length

                if name_type != 0:
                    continue

                try:
                    return hostname_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return hostname_bytes.decode("utf-8", errors="ignore")

            return None

        offset += ext_length

    return None


def start_sni_sniff(db_path: str) -> None:
    config = load_config()
    interface = config["interface"]

    def handle_packet(packet) -> None:
        if not packet.haslayer(Raw):
            return

        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
        else:
            return

        payload = bytes(packet[Raw].load)
        hostname = _extract_sni_hostname(payload)
        if not hostname:
            return

        now_utc = datetime.datetime.now(datetime.UTC)
        dedup_key = (src_ip, hostname.lower())
        last_seen = _recent_sni_queries.get(dedup_key)
        if last_seen is not None and (now_utc - last_seen) < datetime.timedelta(seconds=30):
            return
        _recent_sni_queries[dedup_key] = now_utc

        timestamp = now_utc.replace(microsecond=0).isoformat()
        print(f"[SNI] {src_ip} → {hostname}")
        insert_sni(db_path, src_ip, hostname, timestamp)

    sniff(
        iface=interface,
        filter="tcp port 443",
        store=False,
        prn=handle_packet,
    )
