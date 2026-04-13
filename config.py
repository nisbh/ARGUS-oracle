import json
import os
import sys
from typing import Any, Dict


def load_config() -> Dict[str, Any]:
    # Assumption: config.py and config.json are both in the repository root.
    config_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(config_dir, "config.json")
    required_keys = ("interface", "gateway_ip", "subnet", "db_path")

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)
    except FileNotFoundError:
        print(f"Error: Missing config.json at {config_path}.")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in {config_path}: {exc}")
        sys.exit(1)

    missing_keys = [key for key in required_keys if key not in config]
    if missing_keys:
        print(
            "Error: config.json is missing required key(s): "
            + ", ".join(missing_keys)
        )
        sys.exit(1)

    db_path_value = config["db_path"]
    if not isinstance(db_path_value, str):
        print("Error: config.json key 'db_path' must be a string.")
        sys.exit(1)

    # Assumption: db_path is typically relative to this repo, and one-level-up
    # traversal (../argus.db) is intentional for the shared database location.
    resolved_db_path = os.path.abspath(os.path.join(config_dir, db_path_value))

    if not resolved_db_path.lower().endswith(".db"):
        print("Error: db_path must resolve to a .db file.")
        sys.exit(1)

    # Assumption: traversal checks must use the configured value because an
    # absolute resolved path no longer preserves '..' segments.
    normalized_input_path = db_path_value.replace("\\", "/")
    input_parts = [part for part in normalized_input_path.split("/") if part not in ("", ".")]
    parent_refs = sum(1 for part in input_parts if part == "..")

    if parent_refs > 1:
        print(
            "Error: db_path contains unsafe traversal. Only one '../' level is allowed."
        )
        sys.exit(1)

    config["db_path"] = resolved_db_path
    return config
