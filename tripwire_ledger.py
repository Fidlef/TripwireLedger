"""TripwireLedger: local file-integrity snapshots with a hash-chained event log."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


STATE_DIR_NAME = ".tripwire-ledger"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def take_snapshot(root: Path) -> dict[str, dict]:
    root = root.resolve()
    snapshot = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or STATE_DIR_NAME in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        stat = path.stat()
        snapshot[relative] = {"sha256": sha256_file(path), "size": stat.st_size}
    return snapshot


def compare_snapshots(before: dict, after: dict) -> dict:
    before_names, after_names = set(before), set(after)
    return {
        "added": sorted(after_names - before_names),
        "removed": sorted(before_names - after_names),
        "modified": sorted(name for name in before_names & after_names if before[name]["sha256"] != after[name]["sha256"]),
    }


def canonical_hash(event_without_hash: dict) -> str:
    encoded = json.dumps(event_without_hash, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_events(ledger_path: Path) -> list[dict]:
    if not ledger_path.exists():
        return []
    return [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_event(ledger_path: Path, event_type: str, changes: dict) -> dict:
    events = read_events(ledger_path)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "changes": changes,
        "previous_hash": events[-1]["entry_hash"] if events else "GENESIS",
    }
    event["entry_hash"] = canonical_hash(event)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def initialize(root: Path) -> dict:
    root = root.resolve()
    state = root / STATE_DIR_NAME
    state.mkdir(parents=True, exist_ok=True)
    ledger = state / "ledger.jsonl"
    if ledger.exists():
        raise FileExistsError("A TripwireLedger already exists for this directory")
    snapshot = take_snapshot(root)
    (state / "snapshot.json").write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    append_event(ledger, "baseline", {"file_count": len(snapshot)})
    return snapshot


def scan(root: Path) -> dict:
    root = root.resolve()
    state = root / STATE_DIR_NAME
    snapshot_path, ledger_path = state / "snapshot.json", state / "ledger.jsonl"
    if not snapshot_path.exists() or not ledger_path.exists():
        raise FileNotFoundError("Run the init command first")
    before = json.loads(snapshot_path.read_text(encoding="utf-8"))
    after = take_snapshot(root)
    changes = compare_snapshots(before, after)
    append_event(ledger_path, "scan", changes)
    snapshot_path.write_text(json.dumps(after, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return changes


def verify_ledger(ledger_path: Path) -> tuple[bool, str]:
    events = read_events(ledger_path)
    previous = "GENESIS"
    for index, event in enumerate(events, start=1):
        entry_hash = event.get("entry_hash", "")
        body = {key: value for key, value in event.items() if key != "entry_hash"}
        if event.get("previous_hash") != previous:
            return False, f"Entry {index} does not point to the previous entry"
        if canonical_hash(body) != entry_hash:
            return False, f"Entry {index} content does not match its hash"
        previous = entry_hash
    return True, f"Verified {len(events)} ledger entries"


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor a lab folder with a tamper-evident local ledger.")
    parser.add_argument("command", choices=("init", "scan", "verify"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        result = {"baseline_files": len(initialize(args.directory))}
    elif args.command == "scan":
        result = scan(args.directory)
    else:
        valid, message = verify_ledger(args.directory / STATE_DIR_NAME / "ledger.jsonl")
        result = {"valid": valid, "message": message}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
