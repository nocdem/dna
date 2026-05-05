# Witness Auto-Bootstrap

A fresh nodus-server node — no chain DB on disk, only an identity file and an operator-supplied seed list — discovers the running chain by exchanging four T3 messages with peers, validates a chain_def_blob via cdh quorum, fetches the genesis block via legacy sync replay, and converges to the cluster's state_root.

This document is the operator-facing reference for what happens, what each operator-facing log line means, and the two CLI escapes for unusual recovery scenarios.

Implemented in commit `a865733c` (PR 3 / Yol B), deployed to all 7 prod nodes 2026-05-05.

## State machine

```
INIT ──┬─► HAVE_CHAIN ─► (DONE)
       │   when local chain DB exists at startup
       │
       └─► DISCOVER ─► FETCH_GENESIS ─► BOOTSTRAP_CONFIG ─► DONE
           when local chain DB absent (fresh node)
```

| State | Meaning | Log line on entry |
|-------|---------|-------------------|
| `INIT` | Set during `nodus_witness_bootstrap_start` before branch decision. | (no log) |
| `HAVE_CHAIN` | Local DB has a chain DB with tip ≥ 1. Skip discovery, use existing chain. Transitions immediately to `DONE`. | `WITNESS-BOOTSTRAP: state=DONE branch=HAVE_CHAIN tip=N settle_until_ms=…` |
| `DISCOVER` | No local chain. Broadcast `w_chain_q` to seeded peers, collect `w_chain_r` echoes, group by (cid, cdh), wait for quorum (≥ ⌈2N/3⌉+1 agreeing). | `WITNESS-BOOTSTRAP: state=DISCOVER seed_count=N threshold=Q (= (2*N)/3 + 1)` |
| `FETCH_GENESIS` | Quorum reached on (cid, cdh). Pick the first agreeing peer, send `w_genesis_req` for the agreed cid. On valid `w_genesis_rsp` (cdh of received cdb matches quorum cdh): create chain DB, set chain_id, drop sentinel, transition to `DONE`. | `WITNESS-BOOTSTRAP: quorum reached (agree=N threshold=Q) — advancing to FETCH_GENESIS` |
| `BOOTSTRAP_CONFIG` | Transient (single tick). Refresh bft_config from on-chain committee + set settle window. | (folded into next state) |
| `DONE` | Bootstrap complete. The existing `nodus_witness_sync_check` + replay path catches the new node up to the cluster tip. | `WITNESS-BOOTSTRAP: state=DONE branch=DISCOVER cid_prefix=… cdb_len=… settle_until_ms=…` |

## Protocol messages (T3 types 16–19)

| Type | Constant | Direction | Purpose |
|------|----------|-----------|---------|
| 16 | `NODUS_T3_CHAIN_Q` | DISCOVER → all peers | "What chain are you on?" Carries 16-byte round nonce. |
| 17 | `NODUS_T3_CHAIN_R` | peer → DISCOVER | Echo: cid (32B), tip (uint64), cdh (SHA3-512 of chain_def_blob), nonce (echoed). C-2 cabal protection: peers in DISCOVER/FETCH_GENESIS state drop the request unless `--cold-bootstrap` is set on the responder. |
| 18 | `NODUS_T3_GENESIS_REQ` | FETCH_GENESIS → first agreeing peer | "Send me the chain_def_blob for the cid we agreed on." |
| 19 | `NODUS_T3_GENESIS_RSP` | peer → FETCH_GENESIS | cid + cdb (full chain_def_blob, ≤ 64 KB) + gth (genesis tx_hash) + gpid (proposer_id). Receiver validates `SHA3-512(rcv_cdb) == quorum_cdh`. |

After `w_genesis_rsp` is validated, the bootstrap path creates the chain DB and writes the `.witness_db_seen` marker. It does NOT write any block row — the existing `sync_check` path observes `MAX(height) = NULL → 0`, peer tip > 0, fetches block 1 via the regular `w_sync_req`/`w_sync_rsp` flow, and replays via `commit_genesis`.

## Hardenings (H-* numbering from the design doc)

| ID | Mitigation | Where it runs |
|----|-----------|---------------|
| H-1 | Per-source rate limit on incoming `w_chain_q` (1s min interval per peer; H-1 sign-amplification defense) | `handle_chain_q` before `nodus_t3_encode` |
| H-2 | Strict 64 KB cap on `chain_def_blob` decode | T3 decoder, defense in depth |
| H-3 | Domain-separated sig preimage `"nodus-t3-v1-bootstrap" \|\| method_str` | T3 encode/decode for types 16-19 |
| H-5 | Persist `current_view + last_prepared` across restart so VIEW_CHANGE post-restart carries highest prepared cert | `pbft_state` table (singleton CHECK id=1) loaded in `nodus_witness_init` |
| H-7 | Atomic chain DB write via sentinel `.bootstrap_in_progress` + cleanup on next boot if found stale (orphan recovery) | `nodus_witness_check_orphan_bootstrap_sentinel` in `nodus_witness_init` |
| H-9 | Mixed-version cluster fail-fast: if any peer reports an older `nodus_version` during DISCOVER, exit(3) | `nodus_witness_bootstrap_any_peer_older` in `bootstrap_tick` |
| H-10 | Partial-wipe XOR boot gate: 3 SQLite DBs (nodus.db, channels.db, witness_*.db) MUST be all-present or all-absent post-genesis | `nodus_server_check_partial_wipe` in `nodus_server_init` (marker-gated; sentinel-takes-precedence) |
| H-11 | systemd `RestartSec` envelope handles outer recovery after 10 attempts exhausted (exit 2) | `bootstrap_tick` |

## Cabal protections (C-* numbering)

| ID | Protection |
|----|-----------|
| C-1 | Startup gate: `seed_count ≥ DNAC_COMMITTEE_SIZE`. Refuses to start a fresh node with insufficient seeds. |
| C-2 | A node in `DISCOVER`/`FETCH_GENESIS` MUST NOT respond to `w_chain_q` — prevents two fresh nodes from agreeing on a fictitious chain_id. Bypass: `--cold-bootstrap`. |
| C-4 | Per-round random nonce in `w_chain_q`; `w_chain_r` must echo same nonce. Stale-nonce echoes from a captured prior round are silently dropped. |

## Operator CLI escapes

### `--cold-bootstrap` (no_argument)

Designed for cold-DR: when ALL nodes have lost their chain DB (chain_id mismatch, total disk wipe), the regular DISCOVER path can't form quorum because every node is in DISCOVER → C-2 drops every CHAIN_Q. The operator picks ONE node as the "cold seed" and starts it with this flag; that node bypasses C-2 and answers CHAIN_Q anyway.

**Operator must set this on EXACTLY ONE node**; multiple cold-bootstrap seeds re-introduce the cabal risk that C-2 protects against.

Currently shipped: the bypass + the operator-facing forensic log line `WITNESS-BOOTSTRAP: w_chain_q answered via --cold-bootstrap operator escape (C4); cabal protection bypassed`. The synthetic-cdb construction path (cold seed serves a chain_def from a config file rather than its own DB) is deferred to a follow-up — currently the `chain_tip_height < 1` short-circuit at the bottom of `handle_chain_q` returns before any reply is sent, so cold-bootstrap is fully usable only for nodes that have a backup chain DB.

### `--mock-nodus-version=N` (required_argument, dev only)

Override the packed version (`MAJOR<<16 | MINOR<<8 | PATCH`) advertised in `w_ident`. Used by the `test_bootstrap_mixed_version.sh` stagef test to simulate an older peer; H-9 detection fires on receivers who see the forged-old version. **Never set in production.**

## Recovery procedures

### Operator wiped one of the 3 SQLite DBs by accident

The H-10 partial-wipe XOR boot gate refuses start with:

```
NODUS_SRV: PARTIAL WIPE DETECTED at /var/lib/nodus/data — nodus.db=… channels.db=… witness_*.db=…
(genesis marker .witness_db_seen present). REFUSING START. After this node has crossed
genesis the 3 SQLite DBs MUST be all-present (normal boot) or all-absent (treated as
fresh-restart). Investigate the missing file(s); restore from backup, OR wipe ALL 3 DBs
(keep the marker) to trigger a clean re-bootstrap from peers, OR wipe ALL 3 DBs AND
the marker to force a fresh first-boot path.
```

Choose:
1. **Restore from backup** (preferred if you have a recent witness DB snapshot).
2. **Wipe ALL 3 DBs, keep the marker** — node enters DISCOVER, auto-bootstraps from peers via this PR's protocol. State_root reconverges via sync.
3. **Wipe ALL 3 DBs AND `.witness_db_seen`** — fresh first-boot path; works only if the cluster has a leader you can submit `genesis-create` against.

### Mid-bootstrap crash

If the FETCH_GENESIS path crashes between writing `.bootstrap_in_progress` and the chain DB landing, on next boot:

1. `nodus_server_init` → partial-wipe gate sees sentinel present, defers (option 2 above).
2. `nodus_witness_init` → orphan-sentinel cleanup detects the sentinel + any partial `witness_<hex>.db`, archives the partial DB to `archive/<timestamp>_witness_*`, removes the sentinel.
3. Logs `WITNESS: ORPHAN BOOTSTRAP SENTINEL detected at … (prior FETCH_GENESIS crashed) — archiving any partial witness_*.db files and clearing sentinel`, then `WITNESS: orphan-sentinel cleanup complete — DISCOVER will restart`.
4. DISCOVER restarts cleanly.

No manual operator intervention required.

### Fresh node started against an upgrade-in-progress cluster

If a peer reports an older `nodus_version` than the local binary, the fresh node logs `WITNESS-BOOTSTRAP: MIXED VERSION CLUSTER DETECTED local_nv=0x… peer_count=N — at least one peer reports an older nodus_version. Finish the rolling upgrade before starting fresh-node bootstrap. Exiting with code 3 (H-9).` and exits with code 3.

Recovery: finish the rolling upgrade on all peers, then restart the fresh node.

## Test coverage

| Test | What it covers |
|------|----------------|
| `tests/test_t3_bootstrap_wire.c` | encode/decode roundtrip + nonce echo invariant for types 16-19 |
| `tests/test_witness_pbft_state_persist.c` | H-5 schema (current_view + last_prepared persisted) |
| `tests/test_witness_bootstrap_state_machine.c` | HAVE_CHAIN branch transition |
| `tests/test_witness_bootstrap_orphan_sentinel.c` | E0 cleanup helper |
| `tests/test_witness_bootstrap_mixed_version.c` | H-9 helper detects older peer (8 cases) |
| `tests/test_witness_bootstrap_chain_q_rate_limit.c` | H-1 helper (7 cases) |
| `tests/test_witness_bootstrap_nonce_stale.c` | C-4 stale-nonce filter (5 cases including stale, fresh, mixed, dup-peer, non-DISCOVER) |
| `tests/test_server_partial_wipe_xor.c` | H-10 marker-gated XOR (13 cases) |
| `tests/integration/stagef/tests/test_bootstrap_join_live.sh` | F2 — full auto-bootstrap journey including orphan recovery (Phase A + B) |
| `tests/integration/stagef/tests/test_bootstrap_cold_dr.sh` | F3 — cold-bootstrap C-2 cabal-bypass log |
| `tests/integration/stagef/tests/test_bootstrap_mixed_version.sh` | F4 — H-9 exit 3 via `--mock-nodus-version` |
| `tests/integration/stagef/tests/test_bootstrap_partial_wipe.sh` | F5 — H-10 partial-wipe XOR refuse-start |
| `tests/integration/stagef/tests/test_bootstrap_replay_attack.sh` | F6 — wrapper around `test_witness_bootstrap_nonce_stale` |

ctest 128/128 PASS. Genesis Protocol harness 15/0/2 GREEN.
