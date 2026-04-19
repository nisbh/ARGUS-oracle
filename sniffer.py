import socket
from datetime import datetime, timedelta
from typing import Callable

from scapy.all import DNS, DNSQR, IP, sniff
from scapy.layers.inet6 import IPv6

from config import load_config
from db import log_dns_entry, update_device_hostname
from resolver import resolve_device_id

_recent_queries: dict[tuple[str, str], datetime] = {}
seen_devices: set[str] = set()


def start_sniff(conn, is_flagged_fn: Callable[[str], bool]) -> None:
    # Assumption: load_config centralizes validation and always provides a usable interface.
    config = load_config()
    interface = config["interface"]
    db_path = config["db_path"]

    def handle_packet(packet) -> None:
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return

        if packet[DNS].qr != 0:
            return

        # Assumption: DNS traffic may arrive over IPv4 or IPv6 (for example via VPN).
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
        else:
            return

        qname_value = packet[DNSQR].qname
        if isinstance(qname_value, bytes):
            domain = qname_value.decode("utf-8", errors="ignore")
        else:
            domain = str(qname_value)
        domain = domain.rstrip(".")

        # Assumption: deduplication is in-memory per process and resets on restart.
        now_utc = datetime.utcnow()
        dedup_key = (src_ip, domain)
        last_seen = _recent_queries.get(dedup_key)
        if last_seen is not None and (now_utc - last_seen) < timedelta(seconds=30):
            return
        _recent_queries[dedup_key] = now_utc

        timestamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")

        try:
            socket.setdefaulttimeout(1)
            hostname = socket.gethostbyaddr(src_ip)[0]
            if hostname:
                update_device_hostname(db_path, src_ip, hostname)
        except (socket.herror, socket.gaierror):
            pass

        device_id = resolve_device_id(conn, src_ip)
        flagged = 1 if bool(is_flagged_fn(domain)) else 0

        log_dns_entry(conn, device_id, domain, timestamp, flagged)

        if src_ip not in seen_devices:
            seen_devices.add(src_ip)
            print(f"--- New device: {src_ip} ---")

        status = "[FLAGGED]" if flagged else "[CLEAN]"
        display_time = timestamp.split(" ")[1]
        src_col = src_ip.ljust(15)
        domain_col = domain.ljust(24)
        print(f"[{display_time}] {src_col}  →  {domain_col} {status}")

    try:
        sniff(
            iface=interface,
            filter="udp port 53 or (ip6 and udp port 53)",
            store=False,
            prn=handle_packet,
        )
    except KeyboardInterrupt:
        print("Capture stopped. Logs saved.")
        return
