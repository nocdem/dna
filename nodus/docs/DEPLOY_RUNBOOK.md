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

---

## Appendix B — Rollback state checklist

REVIEWED ___-___-___ (coordinator initials)

When **any** rollback trigger fires (see §6.5 of the multi-tx block refactor design doc for the 15-trigger list), the coordinator calls go/no-go and all operators execute the steps below **simultaneously** on every node in the cluster. Do not let nodes run mixed versions during a rollback — that is the failure mode the trigger detected in the first place.

### Stop everything

1. **Coordinator** announces "ROLLBACK STARTING — stop nodus on all nodes NOW" on the Signal bridge.
2. **Each operator** runs:
   ```bash
   sudo systemctl stop nodus
   ```
3. Confirm with `systemctl is-active nodus` → must print `inactive` on every node before continuing. **Coordinator collects ack from all 7 operators.**

### Archive the broken state

1. On each node, archive the current witness DB (the broken-deploy state) into a timestamped subdirectory so post-mortem can inspect it:
   ```bash
   cd /var/lib/nodus
   mkdir -p archive/rollback-$(date +%s)
   mv witness_* archive/rollback-$(date +%s)/
   ```
2. Verify the archive is complete (no `witness_*` files remain in `/var/lib/nodus`):
   ```bash
   ls /var/lib/nodus/witness_* 2>/dev/null \
       && echo "ARCHIVE INCOMPLETE — fix before restart" \
       || echo "archive ok"
   ```

### Restore the previous binary

1. Reinstall the previous-version `nodus-server` binary from the archived APT repo or the pre-deploy snapshot:
   ```bash
   sudo dpkg -i /var/cache/nodus/previous/nodus-server_<PREV_VERSION>.deb
   ```
2. Confirm version: `nodus-server --version` must print the previous version, **not** the half-deployed one.

### Restore the previous witness state

1. Restore the witness DB snapshot taken by the pre-deploy backup step. Snapshots live under `/var/lib/nodus/snapshots/pre-deploy-<TIMESTAMP>/`:
   ```bash
   cd /var/lib/nodus
   cp -a snapshots/pre-deploy-<TIMESTAMP>/witness_* .
   ```
2. Verify ownership and permissions match what nodus-server expects:
   ```bash
   chown nodus:nodus witness_*
   chmod 600 witness_*
   ```

### Restart the cluster

1. **Coordinator** announces "ROLLBACK READY — start nodus on all nodes NOW".
2. **Each operator** runs:
   ```bash
   sudo systemctl start nodus
   ```
3. Within 30 seconds confirm `systemctl is-active nodus` → `active` on every node.
4. Verify the cluster reformed:
   ```bash
   nodus-cli cluster-status nodus1:4001 nodus2:4001 ...
   ```
   - Every node must report the same `block_height` (the pre-deploy chain head).
   - No node may report `state_root_divergence` errors in `journalctl -u nodus -n 100`.
5. Run the post-deploy smoke test:
   ```bash
   ./nodus/tests/smoke_post_deploy.sh nodus1:4001 nodus2:4001 ...
   ```
   Must print `smoke: PASS`.

### Coordinator sign-off

The coordinator records on the Signal bridge:

> ROLLBACK COMPLETE at <ISO timestamp> — chain head <height>, all 7 nodes healthy, smoke test PASS.

If **any** of the steps above fails, the coordinator pages the on-call architect via the phone tree before retrying — **do not improvise mid-rollback**.

### Appendix B is reviewed pre-deploy

Before every deploy, the coordinator initials and dates the `REVIEWED` line at the top of this Appendix to confirm the procedure has been re-read in the current release context. An unsigned Appendix B blocks the deploy.
