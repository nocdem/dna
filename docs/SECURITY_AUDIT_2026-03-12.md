# DNA / Nodus Full-Stack Security Audit Report

**Date:** 2026-03-12
**Scope:** Nodus DHT server (`nodus/`), DNA Connect messenger (`messenger/`), shared crypto (`shared/crypto/`)
**Version:** Nodus v0.6.8 (commit e18f569e)
**Method:** 8 parallel automated agents — memory safety, protocol, auth, crypto, DHT/consensus, messenger, network/DoS, input validation
**Remediation:** Nodus v0.6.9–v0.6.11 — separate inter-node TCP port (CRIT-1 FIXED, HIGH-1/HIGH-2/HIGH-10 MITIGATED, CRIT-4/CRIT-5 MITIGATED)

## Executive Summary

**88 raw findings** across 8 audit domains, deduplicated to **61 unique findings**:

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 13 |
| MEDIUM | 27 |
| LOW | 16 |

14 of 18 findings have been FIXED or MITIGATED as of v0.6.11. The codebase has strong fundamentals — parameterized SQL everywhere, proper AES-GCM nonce generation, CSPRNG on all platforms, constant-time token comparison, CBOR depth limits, and solid Dilithium5/Kyber1024 usage. The primary systemic weakness is **lack of inter-node authentication** — both UDP Tier 1 and TCP inter-node messages are accepted without peer identity verification, enabling routing table poisoning, presence spoofing, and replication DoS. The second major theme is **connection exhaustion** — no idle timeouts or per-IP limits on the TCP pool.

---

## CRITICAL Findings (5)

### CRIT-1: Unauthenticated STORE_VALUE via T1 Fallback Path (Auth Bypass)
- **Component:** `nodus/src/server/nodus_server.c:dispatch_t2()` lines 1587-1603
- **Description:** When T2 CBOR decode fails, dispatch falls back to T1 decode. If the T1 message is a STORE_VALUE, it's stored via `put_if_newer()` with **no authentication check** — this path runs before the `if (!sess->authenticated)` gate. Any TCP connection can inject signed values without completing HELLO/AUTH.
- **Attack:** Connect to TCP 4001, send a wire-framed T1 STORE_VALUE. Bypasses rate limiting, storage quotas, and session tracking entirely.
- **Impact:** Arbitrary DHT writes from unauthenticated connections.
- **Fix:** Remove the T1 fallback in `dispatch_t2()` or gate it behind `sess->authenticated`. ~5 lines.
- **Status:** FIXED in v0.6.9 — T1 fallback removed from `dispatch_t2()`. Client port (4001) now only accepts hello/auth before authentication. Inter-node messages (sv, fv, p_sync, ch_rep, w_*) moved to dedicated peer port 4002 via `dispatch_inter()`.

### CRIT-2: No Authentication on Tier 1 UDP Messages (Sybil/Eclipse)
- **Component:** `nodus/src/server/nodus_server.c:handle_udp_message()` line 1882; `nodus/src/protocol/nodus_tier1.c`
- **Description:** All UDP Kademlia messages (PING, PONG, FIND_NODE, NODES_FOUND, STORE_VALUE) are processed from any IP with no signatures or identity proof. PING/PONG carry a `node_id` with no proof of ownership.
- **Attack:** Send PINGs from many IPs with crafted node_ids near a target key. Victim's routing table fills with attacker nodes → eclipse attack. Spoofed PONGs keep dead nodes "alive" in routing table and hashring.
- **Impact:** Complete DHT routing compromise. Enables Sybil attacks, eclipse attacks, data interception.
- **Fix:** Sign PING/PONG with sender's Dilithium5 key, verify `node_id == SHA3-512(pk)`. ~300-500 lines, protocol version bump.

### CRIT-3: Routing Table Poisoning via Unauthenticated FIND_NODE Responses
- **Component:** `nodus/src/server/nodus_server.c:handle_udp_message()` line 1944; `nodus/src/core/nodus_routing.c:nodus_routing_insert()` line 39
- **Description:** NODES_FOUND responses insert all peer entries directly into the routing table with no validation. Node_ids aren't verified against keypairs; IPs are taken at face value. LRU eviction means fresh attacker entries can evict legitimate long-lived peers.
- **Attack:** Combined with CRIT-2 for full eclipse — attacker controls all routing entries, intercepts all DHT operations.
- **Impact:** Victim node isolated from legitimate network.
- **Fix:** Require PING verification before inserting FIND_NODE results. ~100-150 lines.

### CRIT-4: No TCP Idle Timeout — Slowloris Connection Exhaustion
- **Component:** `nodus/src/server/nodus_server.c`, `nodus/src/transport/nodus_tcp.c`
- **Description:** No idle timeout for TCP connections. `last_activity` field is set on read but never checked. TCP keepalive (30s) can be defeated by sending 1 byte per 25s. An attacker can hold all 1024 slots indefinitely.
- **Attack:** Open 1024 TCP connections, never send data (or send 1 byte periodically). All legitimate clients locked out. 6 nodes × 1024 = 6144 connections exhausts entire cluster.
- **Impact:** Complete TCP DoS for all clients on targeted node(s).
- **Fix:** Sweep pool every 10-30s, disconnect stale connections. Use shorter timeout (15s) for unauthenticated connections. ~30 lines.
- **Status:** FIXED in v0.6.11 — TCP idle timeout sweep added (60s authenticated, 15s unauthenticated). Previously MITIGATED in v0.6.9 (separate pools).

### CRIT-5: No Per-IP Connection Limit
- **Component:** `nodus/src/transport/nodus_tcp.c:handle_accept()` line 299
- **Description:** `handle_accept` checks `count >= MAX_CONNS` but has no per-IP limit. A single IP can consume all 1024 slots.
- **Attack:** Single attacker machine opens 1024 connections. Even with idle timeout (CRIT-4), active connections holding all slots blocks everyone.
- **Impact:** Single-machine DoS against any Nodus node.
- **Fix:** Count connections per IP in `handle_accept`, reject if >10-20. ~15 lines.
- **Status:** FIXED in v0.6.11 — Per-IP connection limit (max 20). Previously MITIGATED in v0.6.9 (separate pools).

---

## HIGH Findings (13)

### HIGH-1: No Authentication for Inter-Node TCP Messages
- **Component:** `nodus/src/server/nodus_server.c:dispatch_t2()` lines 1619-1678
- **Description:** `sv`, `fv`, `p_sync`, `ch_rep`, and `w_*` messages processed without authentication on TCP. `p_sync` has no signature verification at all — any TCP client can inject arbitrary presence data.
- **Attack:** Connect without auth, send `p_sync` with fabricated fingerprints → presence table poisoned. Send `fv` to enumerate DHT keys. Send `sv` to bypass per-session rate limits.
- **Impact:** Presence spoofing, storage flooding, key enumeration.
- **Fix:** Require mutual auth for inter-node TCP, or whitelist known PBFT peer IPs. ~100-200 lines.
- **Status:** MITIGATED in v0.6.9 — inter-node messages isolated to peer port 4002. Can be firewalled to cluster IPs only. Client port 4001 rejects all inter-node message types.

### HIGH-2: Global Static Rate Limits for sv/fv (Cross-Session DoS)
- **Component:** `nodus/src/server/nodus_server.c:dispatch_t2()` lines 1621-1654
- **Description:** Rate limits for inter-node `sv` (200/sec) and `fv` use `static` local variables shared across ALL connections. One attacker connection exhausts the limit, blocking all legitimate replication.
- **Attack:** Open one unauthenticated TCP connection, send 200 `sv`/sec. All peer replication silently dropped. Sustained attack prevents DHT value propagation.
- **Impact:** Replication DoS — cluster data diverges.
- **Fix:** Move to per-session fields in `nodus_session_t` (like `p_sync`/`ch_rep` already are). ~20 lines.
- **Status:** FIXED in v0.6.9 — all inter-node message types (sv, fv, p_sync, ch_rep, w_*) use per-session rate limiting in `nodus_inter_session_t` on peer port 4002. Global static rate limiters removed.

### HIGH-3: PBFT Is Heartbeat-Only — No Write Consensus
- **Component:** `nodus/src/consensus/nodus_pbft.c`
- **Description:** Despite the name, PBFT implements only heartbeat-based health tracking and leader election. No pre-prepare/prepare/commit phases. PUTs succeed on a single node, replicated asynchronously.
- **Attack:** Compromised node accepts arbitrary PUTs without cluster agreement, serves manipulated GET results.
- **Impact:** No Byzantine fault tolerance. Single compromised node = data integrity loss.
- **Fix:** Read-repair (~200 lines client-side) as pragmatic intermediate step. Full PBFT: 1000+ lines.

### HIGH-4: Stack Overflow in `nodus_presence_tick()` (~576KB)
- **Component:** `nodus/src/server/nodus_presence.c:nodus_presence_tick()`
- **Description:** Stack-allocates `nodus_peer_t peers[4096]` (4096 × 144B = ~576KB). Dangerous on threads with limited stacks.
- **Impact:** Stack overflow → server crash.
- **Fix:** Heap-allocate or iterate routing table directly. ~20 lines.
- **Status:** FIXED in v0.6.11 — Stack array replaced with heap allocation.

### HIGH-5: Shared Static `resp_buf` Reentrancy Risk
- **Component:** `nodus/src/server/nodus_server.c` line 33
- **Description:** Single 1.1MB static buffer for all response encoding. `notify_listeners()` reuses it while iterating sessions. Currently safe due to single-threaded design, but fragile.
- **Impact:** Latent data corruption risk. Currently mitigated by single-threaded model.
- **Fix:** Per-operation heap buffers for notifications. ~20 lines.
- **Status:** FIXED in v0.6.11 — Per-operation heap buffers in notify_listeners().

### HIGH-6: Unbounded Allocation in Value Deserialization
- **Component:** `nodus/src/core/nodus_value.c:nodus_value_deserialize()` line 269
- **Description:** `malloc(v.bstr.len)` where `bstr.len` comes from untrusted CBOR. No check against `NODUS_MAX_VALUE_SIZE` before allocation.
- **Impact:** Memory exhaustion (64-bit), heap overflow (32-bit).
- **Fix:** Add `if (v.bstr.len > NODUS_MAX_VALUE_SIZE) return NULL;`. ~3 lines.
- **Status:** FIXED in v0.6.11 — Added size check before allocation (max NODUS_MAX_VALUE_SIZE).

### HIGH-7: Contact Request Auto-Approval Bypass
- **Component:** `messenger/src/api/engine/dna_engine_contacts.c:dna_handle_get_contact_requests()` line 409
- **Description:** Auto-approves incoming contact requests where `message == "Contact request accepted"`. An attacker can send a contact request with this exact message text to bypass the approval flow entirely.
- **Attack:** Mallory sends contact request to Alice with message `"Contact request accepted"`. Alice's client auto-approves on next fetch.
- **Impact:** Unauthorized contact addition, unsolicited message delivery.
- **Fix:** Verify reciprocal outgoing request exists before auto-approving. ~15 lines.
- **Status:** FIXED in v0.6.11 — Auto-approval requires matching outgoing pending request.

### HIGH-8: Detached Backup Threads Use-After-Free
- **Component:** `messenger/src/api/engine/dna_engine_backup.c:backup_thread_func()` line 52
- **Description:** Backup/restore spawn `pthread_detach`'d threads holding raw `dna_engine_t*`. If engine is destroyed while backup runs, the thread accesses freed memory.
- **Impact:** Use-after-free → crash or heap corruption.
- **Fix:** Track threads in engine struct, join with timeout on destroy. ~30 lines.
- **Status:** FIXED in v0.6.11 — Threads tracked and joined with timeout on engine destroy.

### HIGH-9: UDP Amplification Factor (~10x)
- **Component:** `nodus/src/server/nodus_server.c:handle_udp_message()` FIND_NODE/FIND_VALUE handlers
- **Description:** Small UDP request (~72 bytes) generates response with 8 peers (~700 bytes) = ~10x amplification. Source IP is not verified.
- **Impact:** Reflected DDoS using Nodus nodes as amplifiers.
- **Fix:** Per-IP UDP rate limiting or cookie exchange. ~60-80 lines.
- **Status:** FIXED in v0.6.11 — Per-IP UDP rate limiting (max 10 fn/fv per second).

### HIGH-10: Unauthenticated Dilithium5 Verification CPU Exhaustion
- **Component:** `nodus/src/server/nodus_server.c:dispatch_t2()` pre-auth path
- **Description:** `sv` and `ch_rep` trigger Dilithium5 verification (~2ms each) from unauthenticated connections. Multiple connections × 200 msg/sec saturates CPU.
- **Impact:** CPU exhaustion, all clients experience latency.
- **Fix:** Global cap on total unauthenticated crypto ops/sec, or restrict pre-auth `sv`/`fv` to known peers. ~30-50 lines.
- **Status:** MITIGATED in v0.6.9 — Dilithium5 verification only reachable on peer port 4002 (firewallable). Per-session rate limits cap sv (200/sec) and fv (100/sec) per connection.

### HIGH-11: GEK — Removed Members Retain Old Keys
- **Component:** `messenger/messenger/gek.c:gek_rotate_on_member_remove()` line 783
- **Description:** On member removal, GEK rotates but old versions remain on removed member's device. Historical messages (up to 7-day TTL) still decryptable.
- **Impact:** Removed members can decrypt all messages sent before removal.
- **Fix:** Design limitation (same as Signal/WhatsApp groups). Document clearly.

### HIGH-12: FIND_VALUE Cache Stores Unverified Values
- **Component:** `nodus/src/server/nodus_server.c:dht_find_value_handle_event()` line 1127
- **Description:** FIND_VALUE results cached via `put_if_newer()` without calling `nodus_value_verify()`. Malicious node can return forged data that gets cached.
- **Impact:** Cache poisoning — forged values served to subsequent clients.
- **Fix:** Add `nodus_value_verify()` before `put_if_newer` at line 1127. ~5 lines.
- **Status:** FIXED in v0.6.11 — nodus_value_verify() called before put_if_newer() in cache path.

### HIGH-13: Blocking TCP in Replication Stalls Main Event Loop
- **Component:** `nodus/src/server/nodus_server.c:send_frame_to_peer()` lines 294-353
- **Description:** DHT and channel replication use blocking TCP with 2s connect + 2s send timeouts. Synchronous from main event loop. With K=8 slow peers, a PUT blocks 16+ seconds.
- **Impact:** All clients experience latency during replication to slow/dead peers.
- **Fix:** Use async sends (like `dht_republish_send_async` already does). ~30 lines.
- **Status:** FIXED in v0.6.11 — Blocking send_frame_to_peer() replaced with dht_republish_send_async().

---

## MEDIUM Findings (27)

| ID | Component | Description |
|----|-----------|-------------|
| MED-1 | `nodus_server.c:verify_channel_post_sig` | `body_len * 6` integer overflow risk on 32-bit |
| MED-2 | `nodus_ops.c:nodus_ops_cancel_all` | ~80KB stack allocation |
| MED-3 | `dht_groups.c:serialize_metadata` | `sprintf` (not `snprintf`) buffer overflow risk |
| MED-4 | `nodus_client.c:client_on_frame` | Unchecked malloc, slot marked ready with NULL data |
| MED-5 | `nodus_cbor.c:cbor_decode_next` | Map/array count truncation on 32-bit |
| MED-6 | `nodus_value.c:nodus_value_serialize` | Buffer size overflow on 32-bit |
| MED-7 | `nodus_auth.c:handle_hello` | Nonce not invalidated on re-HELLO |
| MED-8 | `nodus_server.c:handle_t2_ch_*` | No channel membership enforcement (by design) |
| MED-9 | `nodus_tcp.c` | No transport encryption (plaintext TCP) |
| MED-10 | `nodus_storage.c` | Sequence rollback not prevented on client PUT |
| MED-11 | `nodus_storage.c` | Permanent values cannot be deleted |
| MED-12 | `nodus_storage.c:check_quota` | Sybil attack bypasses per-owner quotas |
| MED-13 | `nodus_pbft.c:on_pong` | Hashring membership from unverified PONG |
| MED-14 | `nodus_auth.c` | No rate limiting on auth attempts |
| MED-15 | `qgp_dilithium.c` | Seed + secret polyvec material not wiped from stack |
| MED-16 | `nodus_identity.c:save` | Secret key file permissions not restricted (0644) |
| MED-17 | `qgp_key.c:qgp_key_save` | Unencrypted key save lacks chmod 0600 |
| MED-18 | `messages.c:encrypt_multi_recipient` | Signature covers plaintext only, not timestamp/fingerprint |
| MED-19 | `dna_engine.c:task_queue_push` | MPSC queue not actually lock-free (mitigated by mutex) |
| MED-20 | `gek.c` | GEK static KEM keys have no thread safety |
| MED-21 | `nodus_init.c` | Global init state has no thread safety |
| MED-22 | `dna_engine_wallet.c` | Master seed on stack, not mlock'd (swappable) |
| MED-23 | `dna_engine_internal.h` | Session password stored as plaintext in heap |
| MED-24 | `dna_engine.c:dispatch_event` | Event dispatch race during engine destroy |
| MED-25 | `nodus_presence.c` | p_sync consumes client pool slots; linear O(N×M) scans |
| MED-26 | `nodus_server.c:dispatch_t2` | No rate limit on presence queries |
| MED-27 | `nodus_cbor.c:cbor_decode_skip` | Map count × 2 overflow → near-infinite loop |

---

## LOW Findings (16)

| ID | Component | Description |
|----|-----------|-------------|
| LOW-1 | `nodus_server.h:session_t` | Session tokens never expire |
| LOW-2 | `seed_storage.c`, `gek.c` | AES-GCM without AAD (no context binding) |
| LOW-3 | `nodus_identity.c` + `keygen.c` | `dht_identity.bin` stored unencrypted on disk |
| LOW-4 | `qgp_signature.c:free` | Signature data not wiped before free |
| LOW-5 | `qgp_platform_linux.c` | `getrandom()` partial read not retried |
| LOW-6 | `dht_profile.c` | No domain separation prefix in signed payloads |
| LOW-7 | `nodus_wire.c:frame_decode` | `int` return truncation for large payload_len |
| LOW-8 | `nodus_tcp.c:buf_ensure` | TCP read buffer grows to 4MB per conn (×1024 = 4GB) |
| LOW-9 | `nodus_tier1.c:decode_peers` | Port value uint64→uint16 truncation without range check |
| LOW-10 | `nodus_tier2.c` | Unchecked calloc returns in presence decode |
| LOW-11 | `nodus_witness_peer.c:handle_fwd_rsp` | Stale connection pointer use-after-free |
| LOW-12 | `nodus_witness_db.c:utxo_lookup` | Off-by-one in owner_out strncpy |
| LOW-13 | `base58.c` | Unchecked malloc returns (3 sites) |
| LOW-14 | `bip39_pbkdf2.c` | Unchecked malloc returns (3 sites) |
| LOW-15 | `nodus_client.c:try_reconnect` | No jitter in reconnection backoff |
| LOW-16 | Engine modules / profile data | Unicode bidi override chars not stripped from display names |

---

## Cross-Reference with Already-Fixed Issues

| Fixed Issue | Status | Conflicts? |
|-------------|--------|------------|
| CRIT-1 (ch_post sig verify) | Fixed in v0.6.7 | No conflict. Verified: `verify_channel_post_sig()` called on both direct and replication paths. |
| HIGH-5 (per-session rate limits for p_sync/ch_rep) | Fixed in v0.6.8 | **Partial fix** — `sv` and `fv` still use global static rate limits (HIGH-2 above). |
| HIGH-7, HIGH-8 | Fixed | No conflict |

---

## Top 10 Priority Fixes

Ordered by impact × ease:

| # | ID | Fix | Effort | Impact |
|---|-----|-----|--------|--------|
| 1 | **CRIT-1** | Remove T1 fallback in `dispatch_t2` or gate behind auth | ~5 lines | Auth bypass → arbitrary DHT writes |
| 2 | **HIGH-12** | Add `nodus_value_verify()` before fv cache store | ~5 lines | Cache poisoning prevention |
| 3 | **HIGH-2** | Move sv/fv rate limits to per-session | ~20 lines | Replication DoS prevention |
| 4 | **CRIT-4** | Add idle timeout sweep in main loop | ~30 lines | Slowloris prevention |
| 5 | **CRIT-5** | Add per-IP connection limit in `handle_accept` | ~15 lines | Single-IP DoS prevention |
| 6 | **HIGH-7** | Verify outgoing request exists before auto-approving contact | ~15 lines | Contact spoofing prevention |
| 7 | **HIGH-6** | Add `NODUS_MAX_VALUE_SIZE` check before malloc in deserialize | ~3 lines | Memory exhaustion / heap overflow |
| 8 | **HIGH-4** | Heap-allocate presence tick peer array | ~20 lines | Stack overflow prevention |
| 9 | **MED-16/17** | `chmod 0600` on secret key files | ~6 lines | Key exposure on multi-user systems |
| 10 | **HIGH-1** | Restrict inter-node TCP to known PBFT peer IPs | ~50 lines | Presence/replication poisoning |

**Fixes 1-7 are all under 20 lines each and close the most dangerous attack vectors.**

---

## Positive Findings (Well-Defended Areas)

- All SQLite queries use parameterized statements — zero SQL injection
- AES-256-GCM nonces generated fresh via CSPRNG — no nonce reuse possible
- PBKDF2 at 210,000 iterations with 32-byte random salt
- `qgp_secure_memzero()` correct on all platforms
- BIP39 seed derivation uses domain-separated SHAKE256
- CBOR decoder has depth limit (32) preventing stack exhaustion
- Constant-time session token comparison
- DHT values are Dilithium5-signed with owner verification on PUT
- Path traversal prevention in contacts_db uses strict character whitelist
- AES-GCM wipes partial plaintext on auth failure
- Per-message DEK with per-recipient KEM wrapping is sound design
