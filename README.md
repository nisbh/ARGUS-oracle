# ARGUS-ORACLE

ARGUS-ORACLE is the DNS intelligence module of the ARGUS Network Intelligence Framework.
It passively sniffs DNS query traffic, maps source IPs to known devices, logs activity to SQLite, and flags suspicious domains using a substring-based blocklist.

## Features

- Passive DNS query capture with Scapy (UDP/53 over IPv4 and IPv6)
- Source IP to device mapping through the shared `devices` table
- DNS logging to shared SQLite database (`dns_logs` table)
- Blocklist-based domain flagging via substring matching
- Query deduplication cooldown (30 seconds per `(src_ip, domain)` pair)
- Session summary on exit:
  - duration
  - total queries
  - flagged queries
  - unique queried domains

## Repository Files

- `main.py`: entry point and runtime wiring
- `sniffer.py`: packet capture and live DNS feed output
- `resolver.py`: device resolution from source IP
- `flagging.py`: blocklist loading and flag matcher closure
- `db.py`: database access layer
- `config.py`: config loader and validation
- `blocklist.txt`: sample blocklist entries
- `config.json`: local runtime config (not committed)

## Runtime Requirements

- Linux with packet capture support
- Python 3.11+
- Root privileges for sniffing (`sudo`)

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Configuration

Create `config.json` in the repo root:

```json
{
  "interface": "wlp2s0",
  "gateway_ip": "10.24.64.1",
  "subnet": "10.24.64.0/19",
  "db_path": "../argus.db"
}
```

Notes:

- `db_path` is resolved relative to the repo root.
- One-level parent traversal (for example `../argus.db`) is allowed.
- The path must resolve to a `.db` file.

## Run

```bash
sudo python main.py
```

Startup banner shows interface, DB path, and blocklist count.
Press `Ctrl+C` to stop capture and print the session summary.

## Database Behavior

ARGUS-ORACLE uses the shared database but has scoped responsibilities:

- Reads from `devices` to resolve `device_id`
- Writes to `dns_logs`
- Does not modify `devices`
- Does not touch `sessions`

## Flagging Behavior

- Matching is case-insensitive substring matching.
- Example:
  - entry `doubleclick.net`
  - query `ad.doubleclick.net` -> flagged
- Very short blocklist entries (`< 6` chars) are loaded but trigger startup warnings because they may cause false positives.

## Live Feed Format

Per captured query, output is aligned like:

```text
[HH:MM:SS] 10.24.64.55     ->  google.com               [CLEAN]
[HH:MM:SS] 10.24.64.12     ->  doubleclick.net          [FLAGGED]
```

## Notes and Assumptions

- Deduplication cache is in-memory and resets when the process restarts.
- Unknown source IPs are expected; resolver warnings are suppressed by default (`DEBUG = False` in `resolver.py`).
- DNS over encrypted transports (for example DoH/DoT) is not decoded by this module.
