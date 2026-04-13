from datetime import datetime
from typing import Callable

from scapy.all import DNS, DNSQR, IP, sniff

from config import load_config
from db import log_dns_entry
from resolver import resolve_device_id


def start_sniff(conn, is_flagged_fn: Callable[[str], bool]) -> None:
    # Assumption: load_config centralizes validation and always provides a usable interface.
    config = load_config()
    interface = config["interface"]

    def handle_packet(packet) -> None:
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return

        if packet[DNS].qr != 0:
            return

        # Assumption: this module only tracks IPv4 source addresses via the IP layer.
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src

        qname_value = packet[DNSQR].qname
        if isinstance(qname_value, bytes):
            domain = qname_value.decode("utf-8", errors="ignore")
        else:
            domain = str(qname_value)
        domain = domain.rstrip(".")

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        device_id = resolve_device_id(conn, src_ip)
        flagged = 1 if bool(is_flagged_fn(domain)) else 0

        log_dns_entry(conn, device_id, domain, timestamp, flagged)

        status = "[FLAGGED]" if flagged else "[CLEAN]"
        display_time = timestamp.split(" ")[1]
        src_col = src_ip.ljust(15)
        domain_col = domain.ljust(24)
        print(f"[{display_time}] {src_col}  →  {domain_col} {status}")

    try:
        sniff(
            iface=interface,
            filter="udp port 53",
            store=False,
            prn=handle_packet,
        )
    except KeyboardInterrupt:
        print("Capture stopped. Logs saved.")
        return
