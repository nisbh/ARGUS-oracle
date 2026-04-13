import os
import sys

from config import load_config
from db import init_db
from flagging import load_blocklist, make_is_flagged
from sniffer import start_sniff


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

    try:
        start_sniff(conn, is_flagged_fn)
    except KeyboardInterrupt:
        # Safety net: this handles interrupt if it bypasses sniffer-level handling.
        print("Capture stopped. Logs saved.")
    finally:
        conn.close()
        print("Database connection closed.")

    sys.exit(0)


if __name__ == "__main__":
    main()
