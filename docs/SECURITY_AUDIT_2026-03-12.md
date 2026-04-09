# DNA / Nodus Security Audit Report — Open Issues

**Date:** 2026-03-12 (updated 2026-03-15)
**Scope:** Nodus DHT server, DNA Connect messenger, shared crypto
**Original findings:** 61 unique (5 CRITICAL, 13 HIGH, 27 MEDIUM, 16 LOW)
**Resolved:** 17/18 CRITICAL+HIGH fixed/mitigated
**Remaining:** 1 CRITICAL+HIGH open

---

## Open CRITICAL

### CRIT-2: No Authentication on Tier 1 UDP Messages (Sybil/Eclipse)
- **Component:** `nodus/src/server/nodus_server.c:handle_udp_message()`
- **Description:** All UDP Kademlia messages (PING, PONG, FIND_NODE, NODES_FOUND) processed without signatures or identity proof. PING/PONG carry `node_id` with no proof of ownership.
- **Attack:** Sybil/eclipse — send PINGs from many IPs with crafted node_ids, fill victim routing table with attacker nodes.
- **Impact:** Complete DHT routing compromise.
- **Fix:** Sign PING/PONG with Dilithium5, verify `node_id == SHA3-512(pk)`. ~300-500 lines, protocol version bump.
- **Mitigation:** All 6 nodes under operator control, no public node participation yet.

### CRIT-3: Routing Table Poisoning via Unauthenticated FIND_NODE Responses
- **Component:** `nodus/src/core/nodus_routing.c:nodus_routing_insert()`
- **Description:** NODES_FOUND responses insert peer entries into routing table without validation. Combined with CRIT-2 for full eclipse.
- **Impact:** Victim node isolated from legitimate network.
- **Fix:** Require PING verification before inserting FIND_NODE results. ~100-150 lines. Depends on CRIT-2.

## Open HIGH

### HIGH-3: PBFT Is Heartbeat-Only — No Write Consensus
- **Component:** `nodus/src/consensus/nodus_pbft.c`
- **Description:** PBFT implements only heartbeat-based health tracking and leader election. PUTs succeed on a single node, replicated asynchronously.
- **Impact:** Single compromised node = data integrity loss.
- **Fix:** Read-repair (~200 lines) as intermediate step. Full PBFT: 1000+ lines.
- **Status: RESOLVED** — Full BFT write consensus implemented with PROPOSE/PREVOTE/PRECOMMIT/COMMIT phases. 7 witnesses with 5-of-7 quorum requirement. Used by DNAC witness system for transaction attestation.

---

## Open MEDIUM (26)

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
| MED-9 | `nodus_tcp.c` | ~~No transport encryption~~ **RESOLVED** — Kyber1024 channel encryption on all TCP (v0.9.169/nodus v0.10.2) |
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

## Open LOW (16)

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

## Resolved (for reference)

| ID | Description | Resolution |
|----|-------------|------------|
| CRIT-1 | T1 fallback auth bypass | FIXED v0.6.9 |
| CRIT-4 | TCP idle timeout | FIXED v0.6.11 |
| CRIT-5 | Per-IP connection limit | FIXED v0.6.11 |
| HIGH-1 | Inter-node TCP auth | MITIGATED v0.6.9 (separate port) |
| HIGH-2 | Per-session rate limits | FIXED v0.6.9 |
| HIGH-4 | Stack overflow 576KB | FIXED v0.6.11 |
| HIGH-5 | Static resp_buf | FIXED v0.6.11 |
| HIGH-6 | Unbounded allocation | FIXED v0.6.11 |
| HIGH-7 | Contact auto-approve bypass | FIXED v0.6.11 |
| HIGH-8 | Detached thread UAF | FIXED v0.6.11 |
| HIGH-9 | UDP amplification | FIXED v0.6.11 |
| HIGH-10 | Dilithium CPU exhaust | MITIGATED v0.6.9 |
| HIGH-11 | GEK removed members | FIXED v0.6.11 (HKDF ratchet) |
| HIGH-12 | Cache unverified values | FIXED v0.6.11 |
| HIGH-13 | Blocking replication | FIXED v0.6.11 |
| HIGH-3 | PBFT heartbeat-only, no write consensus | RESOLVED — Full BFT write consensus (PROPOSE/PREVOTE/PRECOMMIT/COMMIT, 5-of-7 quorum) |
| MED-9 | No transport encryption (plaintext TCP) | RESOLVED — Kyber1024 channel encryption on all TCP connections (v0.9.169/nodus v0.10.2) |
