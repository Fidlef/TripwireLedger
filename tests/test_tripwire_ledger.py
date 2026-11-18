import json

import pytest

from tripwire_ledger import STATE_DIR_NAME, initialize, scan, verify_ledger


def test_detects_added_modified_and_removed_files(tmp_path):
    (tmp_path / "keep.txt").write_text("first")
    (tmp_path / "remove.txt").write_text("remove")
    initialize(tmp_path)
    (tmp_path / "keep.txt").write_text("changed")
    (tmp_path / "remove.txt").unlink()
    (tmp_path / "new.txt").write_text("new")
    changes = scan(tmp_path)
    assert changes == {"added": ["new.txt"], "removed": ["remove.txt"], "modified": ["keep.txt"]}


def test_ledger_verifies_after_normal_scans(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    initialize(tmp_path)
    (tmp_path / "a.txt").write_text("b")
    scan(tmp_path)
    valid, message = verify_ledger(tmp_path / STATE_DIR_NAME / "ledger.jsonl")
    assert valid
    assert "2 ledger entries" in message


def test_tampering_is_detected(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    initialize(tmp_path)
    ledger = tmp_path / STATE_DIR_NAME / "ledger.jsonl"
    event = json.loads(ledger.read_text())
    event["changes"]["file_count"] = 999
    ledger.write_text(json.dumps(event) + "\n")
    valid, message = verify_ledger(ledger)
    assert not valid
    assert "does not match" in message


def test_refuses_to_overwrite_existing_ledger(tmp_path):
    initialize(tmp_path)
    with pytest.raises(FileExistsError):
        initialize(tmp_path)
