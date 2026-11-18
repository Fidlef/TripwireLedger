# TripwireLedger

TripwireLedger monitors an authorized lab folder for added, removed, or modified
files. Unlike a basic checksum script, it stores scan events in a hash chain so
later edits to the history can be detected.

```bash
python tripwire_ledger.py init demo-folder
python tripwire_ledger.py scan demo-folder
python tripwire_ledger.py verify demo-folder
python -m pytest -q
```

The program is read-only toward monitored files. It writes its state inside
`.tripwire-ledger/`, which is excluded from snapshots. It does not monitor in
real time, upload results, identify malware, or prevent changes.

Use only on directories you own or are authorized to monitor. A local attacker
who can replace both the ledger and all trusted external copies can still forge
history; export the latest entry hash to a separately protected location for a
stronger design.

## AI-assisted authorship

OpenAI Codex generated the initial implementation, tests, and documentation.
The repository owner must review and understand it before describing personal
technical contributions.
