from sqlite3 import Connection

from db import get_device_id


def resolve_device_id(conn: Connection, ip: str) -> int | None:
    # Assumption: unknown IPs are normal on live networks and should not stop capture.
    device_id = get_device_id(conn, ip)
    if device_id is None:
        print(f"[RESOLVER] Unknown source IP: {ip} - logging anyway")
    return device_id
