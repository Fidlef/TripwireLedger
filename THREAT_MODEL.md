# Threat model

## Protected property

TripwireLedger detects unexpected changes to files between manual scans and
detects edits to an existing event chain.

## In scope

- accidental or unauthorized file addition, removal, and modification;
- later editing of one ledger entry without recomputing all following entries;
- clear, reviewable evidence for a small lab directory.

## Out of scope

- real-time prevention;
- malware identification;
- a privileged attacker who can replace the snapshot, entire ledger, program,
  and any trusted copy of the latest hash;
- metadata-only changes such as permissions and ownership;
- highly dynamic or very large directory trees.
