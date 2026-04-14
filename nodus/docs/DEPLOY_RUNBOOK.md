# Nodus Deploy Runbook

Operational procedures for deploying and rolling back Nodus DHT nodes.

## Archive on-disk witness chain state

Before any chain-wipe deploy (e.g. multi-tx block refactor, witness chain format change), the existing on-disk witness state must be moved out of the way so the new binary starts from a clean DB.

**Procedure (run on each node before installing the new binary):**

```bash
cd /var/lib/nodus
mkdir -p archive/$(date +%s)
mv witness_* archive/$(date +%s)/
```

**Critical:** the glob is `witness_*` — **NOT** `witness_*.db`. The witness state lives in three sibling files for each chain:

- `witness_<chain_id>.db`     — main SQLite database
- `witness_<chain_id>.db-wal` — write-ahead log
- `witness_<chain_id>.db-shm` — shared memory index

Archiving only the `.db` file leaves `-wal` and `-shm` behind, which SQLite then merges back into a freshly-created database, producing a corrupted hybrid state. The bare-`witness_*` glob captures all three.

**Verification after archive:**

```bash
ls /var/lib/nodus/witness_* 2>/dev/null && echo "ARCHIVE INCOMPLETE — files remain" || echo "archive ok"
ls /var/lib/nodus/archive/$(date +%s)/
```

The first line must print `archive ok`. The second must list at least one `witness_*.db` plus its `-wal` and `-shm` siblings if the previous binary was running with WAL mode (default).
