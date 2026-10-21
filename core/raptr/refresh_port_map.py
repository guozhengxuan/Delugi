#!/usr/bin/env python3
"""Record the extracted core against immutable pinned source; never edits either."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIN = "a4c98047cf8aeae3571168d02fb7e343140d2948"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    baseline = ROOT / ".native-deps" / PIN / "raptr"
    rows = []
    for path in sorted((ROOT / "native").rglob("*")):
        if not path.is_file() or "target" in path.parts:
            continue
        relative = path.relative_to(ROOT / "native")
        original = baseline / relative
        original_hash = digest(original) if original.is_file() else None
        current_hash = digest(path)
        rows.append({"path": str(path.relative_to(ROOT)), "sha256": current_hash,
                     "pinned_sha256": original_hash, "unchanged": current_hash == original_hash})
    record = {"schema": 1, "source_commit": PIN,
              "scope": "native core extraction and explicit service/metadata seams; live QS acceptance pending",
              "historical_source_map": "source-map.json", "files": rows}
    (ROOT / "native-port-map.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
