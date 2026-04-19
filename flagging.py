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
            return entries
    except FileNotFoundError:
        print(f"[FLAGGING] Warning: blocklist not found at {blocklist_path}. Running without flagging.")
        return []


def make_is_flagged(blocklist: list[str]) -> Callable[[str], bool]:
    """Build a domain matcher with ordered checks.

    Matching hierarchy (first hit wins):
    1. Exact match: domain == entry
    2. Suffix match: domain ends with "." + entry
    3. Subdomain match for dotted-leading entries: domain ends with entry
    4. Substring match only for entries containing at least one dot
    """

    def is_flagged(domain: str) -> bool:
        if not blocklist:
            return False

        domain_lower = (domain or "").lower()

        for entry in blocklist:
            if domain_lower == entry:
                return True

            if domain_lower.endswith("." + entry):
                return True

            if entry.startswith(".") and domain_lower.endswith(entry):
                return True

            if "." in entry and entry in domain_lower:
                return True

        return False

    return is_flagged
