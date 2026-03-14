# Nodus — Known Issues & Deferred Fixes

## FIXED: Channel Ring Heartbeat Spam

### MED: CH_RING "Node heartbeat timeout" Infinite Log Spam (FIXED)
- **Location**: `nodus/src/channel/nodus_channel_ring.c` — `nodus_ch_ring_handle_ack()`
- **Issue**: When `ring_ack` returns `agree=false`, `check_pending` was cleared but `last_heartbeat_recv` was not reset. Every 5s `ring_tick` re-detected the same stale timestamp → infinite log spam.
- **Fix**: On `disagree`, reset `last_heartbeat_recv = nodus_time_now_ms()` to give the node a fresh 45s grace period.

---

## Deferred: BFT/DNAC Witness (Lowest Priority)

These are real vulnerabilities but BFT consensus is **test-only** with **no real tokens**.
Revisit when DNAC goes to production.

### CRIT-4: IDENT Messages Bypass Signature Verification
- **Location**: `nodus_witness.c:241-258`, `nodus_witness_peer.c:291-376`
- **Issue**: IDENT messages skip wsig verification. Handler trusts all fields — can update roster entries with attacker-controlled pubkey, add new entries, create peer records.
- **Attack**: TCP connect → send `w_ident` with fabricated identity → added to roster → forge BFT votes → unilateral consensus.
- **Fix**: Verify wsig using pubkey embedded in IDENT (self-signed). Verify `witness_id == SHA3-512(pubkey)[0:32]`.

### CRIT-5: Roster Add Has No Authorization
- **Location**: `nodus_witness_bft.c:202-227`, `nodus_witness_peer.c:328-343`
- **Issue**: `nodus_witness_roster_add()` only checks capacity + duplicates. No allowlist, no quorum vote.
- **Attack**: Combine with CRIT-4 to add fake witnesses → control consensus.
- **Fix**: Roster from config file only. Reject `roster_add` for `witness_id` not in config.

### CRIT-6: COMMIT Skips TX Verification (Missed PROPOSE)
- **Location**: `nodus_witness_bft.c:1059-1089`
- **Issue**: When follower missed PROPOSE, `client_pubkey` is all-zeros → tx_hash re-verification skipped entirely.
- **Fix**: Include `client_pubkey` in COMMIT message. Require full verification.

### HIGH-6: Dangling pending_forward.client_conn Pointer
- **Location**: `nodus_witness_peer.c:734-748`
- **Issue**: `conn_closed()` clears `round_state.client_conn` but NOT `pending_forward.client_conn`. UAF if client disconnects after forwarding spend.
- **Fix**: `if (w->pending_forward.client_conn == conn) { w->pending_forward.client_conn = NULL; w->pending_forward.active = false; }`

### HIGH-7: UTXO Checksum Mismatch Only Logs Warning
- **Location**: `nodus_witness_bft.c:1121-1125`
- **Issue**: On UTXO checksum divergence, only QGP_LOG_WARN. Continues normal operation — silent state divergence.
- **Fix**: On mismatch: rollback TX, halt witness, log ERROR, initiate state sync.

### HIGH-14: DB Commit Failure Continues BFT Flow
- **Location**: `nodus_witness_bft.c:904-914`
- **Issue**: On `do_commit_db()` failure, still broadcasts COMMIT, sends success to client, updates `last_committed_round`.
- **Fix**: On DB failure: don't broadcast COMMIT, send error to client, halt or initiate view change.

### MED-24: View Change Drops Client Response
- **Location**: `nodus_witness_bft.c:1293, 1343`
- **Issue**: View change resets phase to IDLE without sending error to waiting client.

### MED-25: Follower Adopts Unverified Round/View from PROPOSE
- **Location**: `nodus_witness_bft.c:687-688`
- **Issue**: Sets `current_round` and `current_view` from leader's PROPOSE without validation.

### MED-26: Single pending_forward Slot
- **Location**: `nodus_witness_handlers.c:1013-1017`
- **Issue**: Concurrent `dnac_spend` from different clients overwrites first client's pending forward.

### LOW-6: Vote Signatures Not Stored
- **Location**: `nodus_witness_bft.c:842-844`
- **Issue**: COMMIT cannot include cryptographic proof of quorum.

### LOW-7: Genesis Requires Unanimous Vote
- **Location**: `nodus_witness_bft.c:858-860`
- **Issue**: N/N votes for genesis — any single offline witness blocks genesis.
