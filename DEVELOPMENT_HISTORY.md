# ARGUS-ORACLE Development History

This document records decisions, fixes, and testing context that are not obvious from the source code alone. It is based on the retained Copilot session history and repository Git history. Details that were not preserved are called out explicitly rather than reconstructed by inference.

## Bugs and Errors

### Broad blocklist false positives

The original matcher treated every blocklist entry as an unrestricted substring. The short entry `c2` therefore matched unrelated domains containing those characters. The exact incorrectly flagged domain was not preserved in the available conversation or Git history.

The fix was committed as `05d1e21`:

- Removed `c2` from `blocklist.txt`.
- Kept exact matches and domain-boundary suffix matches.
- Restricted generic substring matching to entries containing a dot, making short keyword entries unable to match arbitrary text inside a domain.
- Removed the short-entry warning loop that had been added earlier, because the matcher now applies safer rules instead of merely warning about risky entries.

### Repeated DNS observations

High-volume DNS traffic could produce repeated records for the same source IP and domain. Commit `d86df80` added a 30-second, in-memory cooldown keyed by `(src_ip, domain)`. The cache is intentionally process-local and resets when the process restarts.

### Unknown-device resolver noise

Unknown source IPs are normal on a live network, but resolver diagnostics made normal operation noisy. Commit `d86df80` changed resolver warnings to be suppressed by default through `DEBUG = False`; enabling debug remains an explicit choice.

### Deprecated UTC timestamp usage

Commit `1c279dc` replaced deprecated naive UTC timestamp usage in `main.py` with timezone-aware UTC timestamps. The change was made to remove the deprecation warning and keep session timing explicit about its timezone.

### Missing IPv6 coverage

The initial capture path handled only IPv4. Commit `b3d7a96` added IPv6 source extraction and an IPv6-aware capture filter. The stated reason was that DNS traffic may arrive over IPv6, including when VPN networking is involved.

### Reverse DNS enrichment safety

Reverse DNS enrichment was added in commit `1ac6492` and refined in the later development conversation. The design constraints were driven by operational failure modes: reverse lookups must not stall packet processing, must not overwrite a hostname supplied by another system, and must not break databases that predate the `hostname` column.

The resulting decisions were:

- Set the socket timeout to one second before each lookup.
- Silently ignore `socket.herror` and `socket.gaierror`.
- Update only an empty hostname field.
- Catch SQLite `OperationalError` when the hostname column is unavailable.
- Do not print lookup diagnostics, since enrichment is auxiliary to capture.

## Network Interface: `proton0` to `wlp2s0`

The retained history does not record the original `proton0` configuration, the exact reason it was changed, or a dated troubleshooting exchange explaining the transition. The repository documentation and current configuration use `wlp2s0`, which is the wireless interface selected for the normal college-network run.

What to watch for if VPN is enabled again:

- A VPN may create a different interface, such as a tunnel interface, and traffic may no longer be visible on `wlp2s0`.
- Confirm the active interface with the host's network tools before starting capture.
- Check whether DNS is routed through the VPN and whether it uses IPv4, IPv6, DoH, or DoT.
- The code has IPv6 handling, but no VPN-specific interface selection or routing logic was recorded as a supported feature.
- The capture requires root privileges and the configured interface must actually carry the traffic of interest.

The exact `proton0` to `wlp2s0` rationale is therefore an undocumented historical detail, not something recoverable from the available session or Git history.

## Why SNI Sniffing Was Added

DNS logging was not sufficient as the sole visibility source. A connection can reach a TLS service without producing a useful DNS event at the point being observed, so the project added a parallel SNI capture path in commit `67c4606`.

The retained history says SNI was added to expose TLS hostnames that DNS logging missed. However, the specific hostname/domain observed during the college-network test was not preserved in the available conversation, commit messages, or repository files. No exact college-network example can be stated reliably from the surviving record.

The implementation choices that were recorded were:

- Run SNI capture in a daemon thread alongside DNS capture.
- Inspect TLS ClientHello traffic on TCP port 443.
- Keep SNI records in a separate table rather than mixing them with DNS logs.
- Deduplicate SNI observations independently with a 30-second in-memory cache.

## Design Decisions and Reasoning

### Passive packet capture

The project was built around passive Scapy capture rather than an active resolver or proxy. This preserves the ability to observe network behavior without changing client traffic, while requiring Linux packet-capture support and root privileges.

### Separate DNS and SNI data paths

DNS and SNI are different observations with different packet formats and timing. They were kept in separate capture handlers and database tables so one parser or logging failure would not redefine the other signal.

### In-memory cooldowns

Cooldowns were chosen to reduce duplicate live output and database writes without introducing persistent state or a cleanup job. The tradeoff is that deduplication does not survive a restart.

### Boundary-aware blocklist matching

The initial substring approach was simple but unsafe for short entries. The matcher was changed to prioritize exact and domain-boundary matches, and to permit unrestricted substring matching only for dotted entries. This retains useful domain-family matching while avoiding arbitrary character collisions.

### IPv4 and IPv6 support

IPv6 support was added after the initial IPv4-only capture path because real network traffic, including VPN-related traffic, may use either address family. The capture filter and source extraction were updated together so filtering and parsing remain consistent.

### Session summary and validation

A session summary was added in commit `7df0260` to make a run measurable at shutdown through duration, total queries, flagged queries, and unique domains. The same milestone added validation/warnings around short blocklist entries, although the warning mechanism was later removed when matching behavior was tightened.

### Database ownership boundaries

The module reads device identity information and writes its own DNS/SNI observations. It was deliberately kept from modifying unrelated session data. Reverse DNS is the one later enrichment exception, and even there it only fills an empty device hostname rather than replacing existing data.

### Configuration validation

The configuration loader validates required keys, resolves the database path relative to the repository, requires a `.db` target, and permits only one parent-directory traversal. This was chosen to support the shared database layout while preventing broad unsafe path traversal.

### Parameterized SQL

All database writes use parameterized values. This was retained for both ordinary logging and reverse DNS enrichment so observed domains, addresses, and hostnames are treated as data rather than SQL text.

## Known Limitations From Testing and Development

- The exact college-network test observations were not preserved in the available history.
- No VPN-specific configuration or automatic interface discovery was implemented.
- SNI parsing assumes a complete TLS ClientHello is present in the current TCP payload; TCP stream reassembly was not implemented.
- DNS over HTTPS and DNS over TLS are not decoded.
- DNS and SNI cooldown state is in memory only and resets on restart.
- Unknown devices are still logged with no device ID; only their warning output is suppressed by default.
- Reverse DNS can miss names, is intentionally limited to a one-second lookup timeout, and silently ignores lookup or legacy-schema failures.
- The README still contains historical wording that short blocklist entries trigger startup warnings, even though the warning loop was removed when false-positive matching was fixed.
- The repository documentation describes `config.json` as not committed, while a local `config.json` is present in the working tree.
- The available history contains no documented rejected-feature list beyond the limitations above; alternatives without recorded rationale have been omitted.
