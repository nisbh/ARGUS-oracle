import os
import sys
from datetime import datetime

from config import load_config
from db import init_db
from flagging import load_blocklist, make_is_flagged
from sniffer import start_sniff


def print_summary(conn, start_time: datetime) -> None:
    # Assumption: dns_logs timestamps are UTC strings in sortable YYYY-MM-DD HH:MM:SS format.
    start_time_iso = start_time.strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM dns_logs WHERE timestamp >= ?",
        (start_time_iso,),
    )
    total_queries = cursor.fetchone()[0] or 0

    cursor.execute(
        "SELECT COUNT(*) FROM dns_logs WHERE flagged = 1 AND timestamp >= ?",
        (start_time_iso,),
    )
    flagged_queries = cursor.fetchone()[0] or 0

    cursor.execute(
        "SELECT COUNT(DISTINCT domain) FROM dns_logs WHERE timestamp >= ?",
        (start_time_iso,),
    )
    unique_domains = cursor.fetchone()[0] or 0

    duration = datetime.utcnow() - start_time

    print("=" * 48)
    print("Session Summary")
    print(f"Duration  : {duration}")
    print(f"Queries   : {total_queries}")
    print(f"Flagged   : {flagged_queries}")
    print(f"Unique domains : {unique_domains}")
    print("=" * 48)


def main() -> None:
    config = load_config()
    conn = init_db(config["db_path"])

    # Assumption: blocklist.txt is colocated with main.py in repo root.
    blocklist_path = os.path.join(os.path.dirname(__file__), "blocklist.txt")
    blocklist = load_blocklist(blocklist_path)
    is_flagged_fn = make_is_flagged(blocklist)

    print("=" * 48)
    print("ARGUS-ORACLE - DNS Intelligence Module")
    print(f"Interface : {config['interface']}")
    print(f"Database  : {config['db_path']}")
    print(f"Blocklist : {len(blocklist)} entries loaded")
    print("=" * 48)
    print("Sniffing DNS traffic... (Ctrl+C to stop)")
    start_time = datetime.utcnow()

    try:
        start_sniff(conn, is_flagged_fn)
    except KeyboardInterrupt:
        # Safety net: this handles interrupt if it bypasses sniffer-level handling.
        print("Capture stopped. Logs saved.")
    finally:
        print_summary(conn, start_time)
        conn.close()
        print("Database connection closed.")

    sys.exit(0)


if __name__ == "__main__":
    main()
