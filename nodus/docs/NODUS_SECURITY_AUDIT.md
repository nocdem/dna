# Nodus v5 Pre-Production Security Audit

**Date**: 2026-03-05
**Version Audited**: v0.5.3
**Methodology**: 6 parallel AI security agents + 4 parallel verification agents (line-by-line source code confirmation)
**Scope**: `/opt/dna/nodus/src/`, `/opt/dna/nodus/include/`, `/opt/dna/nodus/tools/`
**Status**: Pre-production — multiple critical issues require remediation before deployment
**Previous Audit**: `SECURITY_AUDIT_2026-03-04.md` (32 findings, **0 fixed**)

---

## Executive Summary

This audit consolidates findings from 6 independent security analysis passes across the entire Nodus v5 codebase (~17K lines of C, 29 source files, 17 headers). Every finding was then independently verified by reading the actual source code line-by-line, with confidence and exploitability scores assigned.

**None of the 32 findings from the 2026-03-04 audit have been fixed.**

| Severity | Count | Verified YES | Verified PARTIAL | False Positives |
|----------|-------|-------------|-----------------|----------------|
| CRITICAL | 9 | 8 | 1 | 0 |
| HIGH | 14 | 12 | 2 | 0 |
| MEDIUM | 17 | 15 | 1 | 0 |
| LOW | 2 | 2 | 0 | 0 |
| **Total** | **42** | **37** | **4** | **0** |

### Score Legend
- **Confidence %**: How likely the bug is real (verified against source code)
- **Exploitability %**: How likely this can be exploited in a real 3-node production deployment

---

## CRITICAL — Must Fix Before Production

| ID | Title | Conf. | Expl. | Agents | Previous |
|----|-------|-------|-------|--------|----------|
| CRIT-1 | CBOR Recursive Depth Bomb | 95% | 40% | 3/6 | CRIT-2 |
| CRIT-2 | Unauthenticated Inter-Node Replication | 95% | 60% | 3/6 | CRIT-1 |
| CRIT-3 | Epoll Use-After-Free | 90% | 30% | 2/6 | CRIT-5 |
| CRIT-4 | TCP Frame Size Not Validated | 100% | 70% | 2/6 | CRIT-4 |
| CRIT-5 | No DHT Value Size Validation on Deserialize | 95% | 40% | 2/6 | CRIT-3 |
| CRIT-6 | TTL Expiry Never Runs | 100% | 50% | 1/6 | CRIT-6 |
| CRIT-7 | IDENT Bypasses Sig Verification (Roster Poisoning) | 95% | 70% | 2/6 | **NEW** |
| CRIT-8 | Roster Add Has No Authorization | 95% | 65% | 1/6 | **NEW** |
| CRIT-9 | COMMIT Skips TX Verification (missed PROPOSE) | 75% | 35% | 1/6 | **NEW** (PARTIAL) |

---

### CRIT-1: CBOR Recursive Depth Bomb (Pre-Auth Remote Crash)
**Location**: `nodus_cbor.c:274-288` | **Confidence**: 95% | **Exploitability**: 40%

`cbor_decode_skip()` recurses into nested CBOR containers with no depth limit. Reachable pre-auth via `hello` message parsing.

```c
// nodus_cbor.c:280-286
if (item.type == CBOR_ITEM_MAP) {
    for (size_t i = 0; i < item.count * 2 && !dec->error; i++)
        cbor_decode_skip(dec);  // UNBOUNDED RECURSION
}
```

**Attack**: 5KB crafted CBOR -> all 3 nodes SIGSEGV -> cluster-wide DoS. No auth required.

**Verification note**: Recursion depth bounded by frame size (1 byte/level minimum). With CRIT-4 unfixed, up to ~4M levels. Even with fixed frames (~1MB), still overflows 8MB stack.

**Fix**: Add depth parameter (max 32) or rewrite iteratively.

---

### CRIT-2: Unauthenticated Inter-Node Replication
**Location**: `nodus_server.c:580-637` | **Confidence**: 95% | **Exploitability**: 60%

| Method | Line | Source Check | Data Check | Risk |
|--------|------|-------------|-----------|------|
| `sv` | 580 | None | Dilithium5 value sig ✓ | Storage exhaustion (valid sig needed for forgery) |
| `p_sync` | 593 | IP vs PBFT peers | None | Presence poisoning (requires peer IP) |
| `ch_rep` | 611 | **None** | **None** | **Full channel post injection from any TCP client** |

**Verification note**: `sv` has partial mitigation (value signature check). `p_sync` has weak IP check (line 598-604). `ch_rep` is fully open — any TCP connection can inject channel posts.

**Fix**: IP whitelist for all three. Verify `ch_rep` post signatures. Long-term: mutual Dilithium5 auth.

---

### CRIT-3: Epoll Use-After-Free
**Location**: `nodus_tcp.c:614-620` | **Confidence**: 90% | **Exploitability**: 30%

```c
if (events[i].events & EPOLLOUT)
    handle_write(tcp, conn);       // May free conn on error
if (events[i].events & EPOLLIN)
    handle_read(tcp, conn);        // USE-AFTER-FREE
```

**Verification note**: handle_write() calls conn_free() on write error (line 238). No slot check between EPOLLOUT and EPOLLIN. Windows select() path correctly checks `pool[i] == NULL` but Linux epoll does not. Requires both events firing simultaneously — specific timing needed.

**Fix**: `int slot = conn->slot;` before handle_write, then `if (tcp->pool[slot] == NULL) continue;` after.

---

### CRIT-4: TCP Frame Size Not Validated
**Location**: `nodus_tcp.c:159-183` | **Confidence**: 100% | **Exploitability**: 70%

`try_parse_frames()` calls `nodus_frame_decode()` but never `nodus_frame_validate()`. The validate function exists (wire.c:67) but is only called in UDP path.

**Verification note**: `buf_ensure()` caps at `NODUS_MAX_FRAME_TCP + header + 4096` (~4MB), so allocation is bounded. But connection slot is held while waiting for impossible data -> pool exhaustion.

**Fix**: One-line: `if (rc > 0 && !nodus_frame_validate(&frame, false)) { conn_free(tcp, conn); return; }`

---

### CRIT-5: No DHT Value Size Validation on Deserialize
**Location**: `nodus_value.c:268-273` | **Confidence**: 95% | **Exploitability**: 40%

```c
if (v.type == CBOR_ITEM_BSTR && v.bstr.len > 0) {
    val->data = malloc(v.bstr.len);  // No NODUS_MAX_VALUE_SIZE check
```

**Verification note**: `v.bstr.ptr` bounded by frame size. If CRIT-4 is fixed, practical max ~4MB. Defense-in-depth demands the check.

**Fix**: `if (v.bstr.len > NODUS_MAX_VALUE_SIZE) { dec.error = true; break; }`

---

### CRIT-6: TTL Expiry Never Runs — Unbounded DB Growth — FIXED (Replication Redesign Phase 5)
**Location**: `nodus_storage.c:271` (function), `nodus_server.c` run loop (never called)
**Confidence**: 100% | **Exploitability**: 50%

`nodus_storage_cleanup()` exists, tested in unit tests, but grep confirms zero calls from server code.

**Fix**: Add to server run loop every 60s (timer-gated like presence tick).

**Resolution**: `dht_storage_cleanup()` now calls `nodus_storage_cleanup()` every `NODUS_CLEANUP_SEC` (3600s) from the server main loop. Unit test: `test_storage_cleanup`.

---

### CRIT-7: IDENT Messages Bypass Signature Verification — Roster Poisoning [NEW]
**Location**: `nodus_witness.c:241-259`, `nodus_witness_peer.c:291-376`
**Confidence**: 95% | **Exploitability**: 70%

```c
if (msg.type != NODUS_T3_IDENT) {
    // roster lookup + nodus_t3_verify() — ONLY for non-IDENT
}
```

IDENT handler trusts all fields. At `peer.c:328-343`, unknown senders added to roster with self-declared pubkey. The `w_` prefix check at `server.c:570` allows this pre-auth.

**Attack**: TCP connect -> send `w_ident` with fabricated identity -> added to roster -> quorum altered -> forge BFT votes.

**Fix**: Verify wsig using claimed pubkey. Verify `witness_id == SHA3-512(pubkey)[0:32]`. Lock roster to file only.

---

### CRIT-8: Roster Add Has No Authorization [NEW]
**Location**: `nodus_witness_bft.c:202-227`, `nodus_witness_peer.c:329-343`
**Confidence**: 95% | **Exploitability**: 65%

`nodus_witness_roster_add` only checks capacity + duplicates. No allowlist, no quorum vote.

**Attack**: n=3, quorum=2. Add 3 fake witnesses via CRIT-7 (n=6). Attacker has 3 fake votes = unilateral consensus.

**Fix**: Roster from config file only. No dynamic adds from network.

---

### CRIT-9: COMMIT Handler Skips TX Verification [NEW] (PARTIAL)
**Location**: `nodus_witness_bft.c:1059-1089` | **Confidence**: 75% | **Exploitability**: 35%

```c
} else {
    QGP_LOG_DEBUG(LOG_TAG, "COMMIT: no client_pubkey available, "
                  "skipping tx_hash re-verification (missed PROPOSE)");
}
```

**Verification note**: COMMIT IS authenticated via wsig (sender must be in roster). But there is NO check that sender is the expected leader. Combined with CRIT-7/8, a rogue witness could send forged commits. Without roster poisoning, requires compromising an existing witness. Replay check (line 1040) + round check (line 1048) add further barriers.

**Fix**: Include client pubkey/sig in COMMIT. Verify sender is current leader.

---

## HIGH — Fix Before or Shortly After Launch

| ID | Title | Conf. | Expl. | Previous |
|----|-------|-------|-------|----------|
| HIGH-1 | Session Token Check is Optional | 95% | 30% | HIGH-7 |
| HIGH-2 | Timing Side-Channels on Token/Key Comparison | 90% | 10% | HIGH-1 |
| HIGH-3 | No Per-IP Connection Rate Limiting | 95% | 70% | HIGH-2 |
| HIGH-4 | Shared Static resp_buf[65536] | 95% | 5% | HIGH-3 |
| HIGH-5 | Blocking Replication I/O on Event Loop | 95% | 50% | HIGH-4 |
| HIGH-6 | Routing Table Poisoning (No Ping-Before-Evict) | 85% | 40% | HIGH-5 |
| HIGH-7 | Secret Key File Permissions (0644) | 95% | 35% | HIGH-6 |
| HIGH-8 | No TTL/Permanent Value Enforcement | 95% | 70% | HIGH-8 |
| HIGH-9 | 128KB Stack Buffers in Witness Functions | 100% | 30% | HIGH-9 |
| HIGH-10 | Presence Sync Leaks TCP Connections | 75% | 50% | HIGH-10 (PARTIAL) |
| HIGH-11 | Dangling pending_forward.client_conn | 100% | 40% | HIGH-11 |
| HIGH-12 | No TLS — All Traffic Plaintext | 100% | 60% | HIGH-12 |
| HIGH-13 | CBOR Array Counts Trusted for Heap Alloc | 95% | 55% | **NEW** |
| HIGH-14 | UTXO Checksum Mismatch Not Acted Upon | 100% | 25% | **NEW** |

### HIGH-1: Session Token Check is Optional
**Location**: `nodus_server.c:649` | **Confidence**: 95% | **Exploitability**: 30%

`if (msg.has_token && !session_check_token(...))` — omitting token bypasses check entirely.

**Verification note**: Requires prior Dilithium5 auth (line 568). Token is secondary session binding. Narrow attack window (must be on authenticated connection).

**Fix**: `if (!msg.has_token || !session_check_token(sess, msg.token)) { /* reject */ }`

### HIGH-2: Timing Side-Channels on Token/Key Comparison
**Location**: `nodus_server.c:47`, `nodus_types.h:338`, `nodus_witness_verify.c:244`
**Confidence**: 90% | **Exploitability**: 10%

`memcmp()`/`__builtin_memcmp()` for session token, fingerprint, tx_hash.

**Verification note**: Fingerprint comparison is on public data (attacker knows pubkey -> fp). tx_hash comparison is against client-provided value. Network jitter makes remote timing extremely difficult. Session token is the most sensitive but still hard to exploit.

**Fix**: Constant-time `ct_equal()` for security-critical comparisons.

### HIGH-3: No Per-IP Connection Rate Limiting
**Location**: `nodus_tcp.c:283-316` | **Confidence**: 95% | **Exploitability**: 70%

Only global `NODUS_TCP_MAX_CONNS` (1024). No per-IP tracking. Straightforward DoS.

**Fix**: Per-IP limit (10), auth failure throttle (3 -> 5min ban), idle timeout.

### HIGH-4: Shared Static resp_buf[65536]
**Location**: `nodus_server.c:30`, `nodus_auth.c:18` | **Confidence**: 95% | **Exploitability**: 5%

**Verification note**: Single-threaded epoll = no concurrent access. Comment says "shared, single-threaded". Latent vulnerability if threading added. Currently NOT exploitable.

### HIGH-5: Blocking Replication I/O on Event Loop — PARTIALLY FIXED (Replication Redesign Phase 5)
**Location**: `nodus_server.c:155-216`, `nodus_replication.c:31-95`
**Confidence**: 95% | **Exploitability**: 50%

Synchronous `connect()` + `select()` with 2s timeout per peer. Called from `handle_t2_put`. 2 unreachable peers = 4s stall for ALL clients.

**Resolution**: Periodic republish now uses fully non-blocking `dht_republish_send_async()` via separate epoll fd (zero blocking). `replicate_value()` on PUT path still uses synchronous `send_frame_to_peer()` but targets K-closest nodes via routing table (dead nodes filtered out).

### HIGH-6: Routing Table Poisoning
**Location**: `nodus_routing.c:69-83`, `nodus_server.c:803-808`
**Confidence**: 85% | **Exploitability**: 40%

Unconditional LRU eviction. `fn_r` peers inserted without verification.

**Verification note**: Only from UDP Kademlia messages (not TCP clients). Attacker must be a Kademlia peer.

### HIGH-7: Secret Key File Permissions
**Location**: `nodus_identity.c:91-98` | **Confidence**: 95% | **Exploitability**: 35%

`fopen("wb")` -> umask 022 -> 0644. 4896-byte Dilithium5 secret key world-readable.

**Verification note**: Single-user VPS = lower risk. Multi-user/container = higher.

### HIGH-8: No TTL/Permanent Value Enforcement
**Location**: `nodus_value.c:113-117`, `nodus_server.c:240-244`
**Confidence**: 95% | **Exploitability**: 70%

Any authenticated client stores `NODUS_VALUE_PERMANENT` (expires_at=0). No max TTL, no quota.

### HIGH-9: 128KB Stack Buffers in Witness Functions
**Location**: `nodus_witness_bft.c:255,1011,1174`, `peer.c:277,557`, `handlers.c:1076`, `tier3.c:915`
**Confidence**: 100% | **Exploitability**: 30%

131072-byte stack allocations in 6+ functions. `tier3.c:915` uses `static` (not reentrant). Default 8MB stack can hold ~62 such buffers, but nested calls compound.

### HIGH-10: Presence Sync Leaks TCP Connections (PARTIAL)
**Location**: `nodus_presence.c:234-239` | **Confidence**: 75% | **Exploitability**: 50%

**Verification note**: Remote peer may close after processing (triggering conn_free via handle_read returning 0). Timing-dependent. If remote keeps open: pool exhausted in ~4.3 hours.

### HIGH-11: Dangling pending_forward.client_conn
**Location**: `nodus_witness_peer.c:734-748` | **Confidence**: 100% | **Exploitability**: 40%

`conn_closed()` clears `round_state.client_conn` (line 746-747) but NOT `pending_forward.client_conn`. Classic use-after-free.

**Fix**: Add to conn_closed: `if (w->pending_forward.client_conn == conn) { ... = NULL; }`

### HIGH-12: No TLS — All Traffic Plaintext
**Location**: `nodus_tcp.c` (entire file) | **Confidence**: 100% | **Exploitability**: 60%

Zero TLS/SSL. PQ signatures for integrity/authenticity but NO confidentiality. Session tokens visible to network observers.

### HIGH-13: CBOR Array/Map Counts Trusted for Heap Allocation [NEW]
**Location**: `nodus_tier2.c:816,871,895` | **Confidence**: 95% | **Exploitability**: 55%

```c
msg->pq_fps = calloc(arr.count, sizeof(nodus_key_t));  // arr.count from wire
```

**Verification note**: calloc returns NULL for absurd values (handled). fps path has partial server-side mitigation (PRESENCE_SYNC_MAX_FPS=256). values and posts paths have none.

### HIGH-14: UTXO Checksum Mismatch Not Acted Upon [NEW]
**Location**: `nodus_witness_bft.c:1121-1125` | **Confidence**: 100% | **Exploitability**: 25%

`QGP_LOG_WARN` only. No halt, no rollback, no view change. Silent state divergence continues.

---

## MEDIUM — Should Fix

| ID | Title | Conf. | Expl. | Previous |
|----|-------|-------|-------|----------|
| MED-1 | No Idle Connection Timeout | 95% | 40% | MED-1 |
| MED-2 | CBOR Map/Array Count Unbounded | 90% | 30% | MED-2 |
| MED-3 | Presence Query pq_count Not Capped | 95% | 50% | MED-3 |
| MED-4 | 128+ fprintf(stderr) in Production | 100% | 5% | MED-4 |
| MED-5 | No T1 UDP Replay Protection | 95% | 35% | MED-5 |
| MED-6 | nodus_t3_verify() Static 128KB Buffer | 100% | 10% | MED-6 |
| MED-7 | Signal Handler Not Async-Safe | 95% | 5% | MED-7 |
| MED-8 | Channel seq_id TOCTOU Race | 90% | 15% | MED-8 |
| MED-10 | nodus_identity_clear() Volatile Loop | 85% | 5% | MED-10 |
| MED-11 | FD_SET Overflow in replicate_to_peer | 90% | 15% | MED-11 |
| MED-12 | Nonce Hash Table Memory Leak | 95% | 5% | MED-12 |
| MED-13 | Presence Table O(N) Linear Scan | 100% | 0% | MED-13 |
| MED-14 | ~73 Lines Dead Code | 80% | 0% | MED-14 (PARTIAL) |
| MED-15 | No Rate Limiting on Auth Attempts | 95% | 40% | **NEW** |
| MED-16 | Leader Election Clock-Dependent | 100% | 20% | **NEW** |
| MED-17 | SQLite synchronous=NORMAL for Witness | 100% | 10% | **NEW** |

### MED-1: No Idle Connection Timeout
`last_activity` tracked in 4 places but never checked. TCP keepalive (30s) detects dead hosts, not live-but-idle attackers.

### MED-2: CBOR Map/Array Count Unbounded
`item.count` from header not checked against remaining buffer. Each element read fails individually via `dec_has()`, but callers allocate based on count.

### MED-3: Presence Query pq_count Not Capped Server-Side
`NODUS_PRESENCE_MAX_QUERY` (128) enforced on CLIENT side only. Server does `calloc(msg.pq_count, ...)` without cap. Handles NULL gracefully but allows memory pressure.

### MED-4: fprintf(stderr) in Production Code
128 occurrences across 13 files. 46 in nodus_witness_bft.c alone. All use controlled format strings (no log injection). Violates QGP_LOG convention.

### MED-5: No T1 UDP Replay Protection
T1 messages (ping, store_value, find_node) have zero replay protection. Mitigated by Kademlia semantics (replayed stores with same seq don't change state if seq isn't higher).

### MED-6: nodus_t3_verify() Static 128KB Buffer
`static uint8_t sign_buf[131072]` at tier3.c:915. Safe in current single-threaded design. Breaks if threading added.

### MED-7: Signal Handler Not Async-Safe
`running` is plain `bool`, not `volatile sig_atomic_t`. Uses `signal()`. In practice, 100ms epoll_wait timeout forces re-read, so exploitation near-zero.

### MED-8: Channel seq_id TOCTOU Race
Three separate SQLite ops without transaction. Single-threaded server makes concurrent calls impossible. Theoretical risk.

### MED-10: nodus_identity_clear() Volatile Loop
Volatile loop is commonly accepted alternative to `explicit_bzero()`. Functionally correct. Minor hygiene.

### MED-11: FD_SET Overflow in replicate_to_peer
`FD_SET(fd, &wfds)` with no `fd >= FD_SETSIZE` check. Requires 1024+ open fds. Unlikely under normal operation.

### MED-12: Nonce Hash Table Memory Leak
Static table, never freed on shutdown. Entries freed on TTL expiry per-bucket. OS reclaims on process exit. Pedantic leak.

### MED-13: Presence Table O(N) Linear Scan
Linear scan up to 2048 entries. Performance issue, not security. Fine for <1000 clients.

### MED-14: Dead Code (~73 Lines) (PARTIAL)
`nodus_hash_hex`, `nodus_t1_subscribe/unsubscribe/notify` confirmed dead. `nodus_republish_reset` has caller in `dna_engine.c` (NOT dead).

### MED-15: No Rate Limiting on Auth Attempts [NEW]
No rate limit on hello/auth. Dilithium5 verification ~1ms each. CPU exhaustion DoS vector.

### MED-16: Leader Election Clock-Dependent [NEW]
`epoch = time(NULL) / EPOCH_DURATION`. Clock skew > epoch causes different leaders -> consensus stall (not incorrect results). Mitigated by view-change mechanism.

### MED-17: SQLite synchronous=NORMAL for Witness [NEW]
`PRAGMA synchronous=NORMAL` with WAL. Power failure -> last transactions lost -> UTXO inconsistency -> possible double-spend after crash.

---

## LOW — Minor Issues

| ID | Title | Conf. | Expl. |
|----|-------|-------|-------|
| LOW-1 | Nonce Replay Window Lost on Restart | 100% | 25% |
| LOW-2 | session_clear Uses Non-Secure memset | 100% | 3% |

### LOW-1: Nonce Replay Window Lost on Restart
Static memory-only nonce table. After restart, replayed BFT messages within 5-min window succeed. Requires capturing valid signed messages AND triggering restart.

### LOW-2: session_clear Uses Non-Secure memset
Plain `memset` for session token/nonce. Session struct reused (not freed), so compiler unlikely to optimize away.

---

## Positive Findings

1. **Post-quantum crypto**: Dilithium5 (ML-DSA-87) + SHA3-512 throughout. No deprecated algorithms.
2. **Secure RNG**: `getrandom()` via `qgp_platform_random()`. BFT nonce generation aborts on failure.
3. **No hardcoded secrets**: Zero API keys, passwords, tokens, or seeds in source.
4. **DHT value signatures**: All values Dilithium5-verified. Sign payload covers key_hash, data, type, ttl, value_id, seq.
5. **BFT message signatures**: All non-IDENT T3 messages wsig-verified against roster pubkeys.
6. **BFT replay prevention**: Nonce + timestamp hash table with 5-minute window.
7. **Chain ID validation**: Prevents cross-zone replay on all BFT messages.
8. **Transaction verification**: 6 independent checks (nullifiers, hash, sig, balance, fee, double-spend).
9. **Fail-closed nullifier checks**: DB error returns "spent" (safe default).
10. **Atomic DB transactions**: `do_commit_db` uses BEGIN/COMMIT/ROLLBACK.
11. **Identity cleanup on shutdown**: `nodus_identity_clear()` with volatile writes.
12. **Minimal dependencies**: Only SQLite (static) + shared crypto.
13. **PUT rate limiting**: 60/minute per session.
14. **Listen/subscribe limits**: 128 listen keys, 32 channel subscriptions per session.
15. **Parameterized SQL**: Bound parameters throughout. Channel UUIDs hex-validated.
16. **CBOR decoder bounds checking**: `dec_has()` validates at every read.
17. **UDP frame size validation**: Against `NODUS_MAX_FRAME_UDP = 1400`.
18. **Connection pool cap**: `NODUS_TCP_MAX_CONNS = 1024`.
19. **Overflow protection**: uint64 overflow checks in witness_verify amount calculations.
20. **Leader verification in PROPOSE**: Followers verify sender matches expected leader.
21. **SIGPIPE ignored**: Prevents server kill from writes to closed sockets.
22. **WAL mode**: All SQLite databases use WAL.

---

## Recommended Fix Order (by Exploitability)

### Phase 1: Exploitability >= 60% (Week 1)

| # | ID | Expl. | Effort | Description |
|---|------|-------|--------|-------------|
| 1 | CRIT-4 | 70% | Trivial | Frame size validation (one-line fix) |
| 2 | CRIT-7 | 70% | Small | IDENT sig verification + roster lockdown |
| 3 | HIGH-3 | 70% | Small | Per-IP connection limits |
| 4 | HIGH-8 | 70% | Small | Max TTL enforcement |
| 5 | CRIT-8 | 65% | Small | Roster from config file only |
| 6 | CRIT-2 | 60% | Medium | Auth for inter-node replication |
| 7 | HIGH-12 | 60% | Large | TLS (long-term, start design) |

### Phase 2: Exploitability 40-55% (Week 2)

| # | ID | Expl. | Effort | Description |
|---|------|-------|--------|-------------|
| 8 | HIGH-13 | 55% | Small | Cap CBOR array counts |
| 9 | CRIT-6 | 50% | Trivial | Wire storage_cleanup into server loop |
| 10 | HIGH-5 | 50% | Medium | Non-blocking replication |
| 11 | HIGH-10 | 50% | Small | Fix presence sync connection leak |
| 12 | MED-3 | 50% | Trivial | Cap pq_count server-side |
| 13 | CRIT-1 | 40% | Small | Iterative cbor_decode_skip with depth limit |
| 14 | CRIT-5 | 40% | Trivial | Value size check in deserialize |
| 15 | HIGH-11 | 40% | Trivial | Clear pending_forward.client_conn |
| 16 | HIGH-6 | 40% | Medium | Ping-before-evict |
| 17 | MED-1 | 40% | Small | Idle connection timeout |
| 18 | MED-15 | 40% | Small | Auth attempt rate limiting |

### Phase 3: Exploitability 25-35% (Week 3)

| # | ID | Expl. | Effort |
|---|------|-------|--------|
| 19 | HIGH-7 | 35% | Trivial |
| 20 | CRIT-9 | 35% | Medium |
| 21 | MED-5 | 35% | Small |
| 22 | CRIT-3 | 30% | Small |
| 23 | HIGH-1 | 30% | Trivial |
| 24 | HIGH-9 | 30% | Small |
| 25 | MED-2 | 30% | Trivial |
| 26 | HIGH-14 | 25% | Medium |
| 27 | LOW-1 | 25% | Small |

### Phase 4: Exploitability < 25% (Week 4+)

| # | ID | Expl. |
|---|------|-------|
| 28 | MED-16 | 20% |
| 29 | MED-8 | 15% |
| 30 | MED-11 | 15% |
| 31 | HIGH-2 | 10% |
| 32 | MED-6 | 10% |
| 33 | MED-17 | 10% |
| 34-42 | Remaining | 0-5% |

---

## Cross-Reference: Previous Audit (2026-03-04)

All 32 findings from the previous audit remain **OPEN**:

| Previous ID | This Audit ID | Status |
|------------|---------------|--------|
| CRIT-1 | CRIT-2 | OPEN |
| CRIT-2 | CRIT-1 | OPEN |
| CRIT-3 | CRIT-5 | OPEN |
| CRIT-4 | CRIT-4 | OPEN |
| CRIT-5 | CRIT-3 | OPEN |
| CRIT-6 | CRIT-6 | OPEN |
| HIGH-1 | HIGH-2 | OPEN |
| HIGH-2 | HIGH-3 | OPEN |
| HIGH-3 | HIGH-4 | OPEN |
| HIGH-4 | HIGH-5 | OPEN |
| HIGH-5 | HIGH-6 | OPEN |
| HIGH-6 | HIGH-7 | OPEN |
| HIGH-7 | HIGH-1 | OPEN |
| HIGH-8 | HIGH-8 | OPEN |
| HIGH-9 | HIGH-9 | OPEN |
| HIGH-10 | HIGH-10 | OPEN |
| HIGH-11 | HIGH-11 | OPEN |
| HIGH-12 | HIGH-12 | OPEN |
| MED-1 | MED-1 | OPEN |
| MED-2 | MED-2 | OPEN |
| MED-3 | MED-3 | OPEN |
| MED-4 | MED-4 | OPEN |
| MED-5 | MED-5 | OPEN |
| MED-6 | MED-6 | OPEN |
| MED-7 | MED-7 | OPEN |
| MED-8 | MED-8 | OPEN |
| MED-9 | CRIT-7 (escalated) | OPEN |
| MED-10 | MED-10 | OPEN |
| MED-11 | MED-11 | OPEN |
| MED-12 | MED-12 | OPEN |
| MED-13 | MED-13 | OPEN |
| MED-14 | MED-14 | OPEN |

**New findings**: CRIT-7, CRIT-8, CRIT-9, HIGH-13, HIGH-14, MED-15, MED-16, MED-17, LOW-1, LOW-2 (10 new, including 3 CRITICAL in BFT protocol).
