from typing import Callable


def load_blocklist(blocklist_path: str) -> list[str]:
    # Assumption: entries are simple domain/keyword substrings, one per line.
    try:
        with open(blocklist_path, "r", encoding="utf-8") as file:
            entries: list[str] = []
            for raw_line in file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line.lower())

            for entry in entries:
                if len(entry) < 6:
                    print(
                        "[BLOCKLIST] Warning: entry "
                        f"'{entry}' is very short and may cause false positives "
                        "- consider making it more specific"
                    )

            return entries
    except FileNotFoundError:
        print(f"[FLAGGING] Warning: blocklist not found at {blocklist_path}. Running without flagging.")
        return []


def make_is_flagged(blocklist: list[str]) -> Callable[[str], bool]:
    def is_flagged(domain: str) -> bool:
        if not blocklist:
            return False

        domain_lower = (domain or "").lower()
        return any(entry in domain_lower for entry in blocklist)

    return is_flagged
