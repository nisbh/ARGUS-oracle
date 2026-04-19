import sqlite3
from typing import Optional


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_logs (
          id        INTEGER PRIMARY KEY AUTOINCREMENT,
          device_id INTEGER,
          domain    TEXT,
          timestamp TEXT,
          flagged   INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()
    return conn


def get_device_id(conn: sqlite3.Connection, ip: str) -> Optional[int]:
    # Assumption: the devices table is pre-created and maintained by recon.
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    return row[0] if row else None


def update_device_hostname(db_path: str, ip: str, hostname: str) -> None:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE devices
                SET hostname = ?
                WHERE ip = ?
                  AND (hostname IS NULL OR hostname = '')
                """,
                (hostname, ip),
            )
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
    except sqlite3.Error:
        pass


def log_dns_entry(
    conn: sqlite3.Connection,
    device_id: Optional[int],
    domain: str,
    timestamp: str,
    flagged: int,
) -> None:
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO dns_logs (device_id, domain, timestamp, flagged)
            VALUES (?, ?, ?, ?)
            """,
            (device_id, domain, timestamp, flagged),
        )
        conn.commit()
    except sqlite3.Error as exc:
        print(f"SQLite error while logging DNS entry: {exc}")


def init_sni_table(db_path: str) -> None:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sni_logs (
              id        INTEGER PRIMARY KEY AUTOINCREMENT,
              src_ip    TEXT,
              hostname  TEXT,
              timestamp TEXT
            )
            """
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        print(f"SQLite error while initializing sni_logs table: {exc}")


def insert_sni(db_path: str, src_ip: str, hostname: str, timestamp: str) -> None:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO sni_logs (src_ip, hostname, timestamp)
            VALUES (?, ?, ?)
            """,
            (src_ip, hostname, timestamp),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        print(f"SQLite error while logging SNI entry: {exc}")
