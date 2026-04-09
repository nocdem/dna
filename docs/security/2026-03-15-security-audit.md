# DNA Security Audit v2 — 2026-03-15

**Scope:** Nodus v0.9.x | Messenger v0.9.x | DNAC v0.11.x
**Method:** 6 parallel domain agents + 1 cross-domain consolidation
**Prior Audit:** 2026-03-14 (v1 assessment — 88 findings across 6 domains)

---

## Executive Summary

**82 unique findings** (after deduplication) across 6 domains, forming **6 cross-domain attack chains.**
**As of 2026-04-10: 35 RESOLVED, 0 IN PROGRESS, 47 remaining.**

| Severity | Total | Resolved | In Progress | Open |
|----------|-------|----------|-------------|------|
| CRITICAL | 6 | 6 | 0 | 0 |
| HIGH | 17 | 13 | 0 | 4 |
| MEDIUM | 35 | 16 | 0 | 19 |
| LOW | 24 | 0 | 0 | 24 |

**Top 3 systemic risks:**
1. **No transport-level authentication on inter-node and witness ports** — TCP 4002 (inter-node) and TCP 4004 (witness BFT) accept connections from any source. Combined with DHT routing table poisoning, this enables full consensus hijack (Chain 1) and DHT data corruption (Chain 3).
2. **Client-side witness verification trusts embedded public keys** — DNAC wallets verify witness attestations using the public key carried inside the attestation itself, with no pinning to a trusted roster. Any Dilithium5 keypair can forge valid-looking attestations (Chain 2).
3. **Unauthenticated UDP Kademlia enables Sybil/Eclipse attacks** — No cryptographic binding between node IDs and identity, no ping-before-evict on routing table insertions, and a trivially bypassable rate limiter create a cascading failure path from routing table poisoning to witness discovery manipulation.

### Positive Findings
- **Strong algorithm choices**: Dilithium5 (ML-DSA-87), Kyber1024 (ML-KEM-1024), SHA3-512, AES-256-GCM — all NIST Category 5
- **Proper PBKDF2**: 210,000 iterations for key encryption (OWASP 2023 compliant)
- **AES-GCM nonce handling**: Fresh CSPRNG 12-byte nonces per operation, authentication tags verified before returning plaintext
- **Consistent secure memzero**: Platform-abstracted via `explicit_bzero` / `SecureZeroMemory`
- **KEM-based seed storage**: Kyber1024 encapsulation for post-quantum forward secrecy
- **BIP39/BIP32 standards compliance**: Correct PBKDF2-HMAC-SHA512 seed derivation
- **Vendored reference implementations**: pq-crystals Dilithium5 and Kyber1024
- **Fail-closed nullifier check**: DB error treated as "already spent"
- **Atomic DB transactions in witness**: Rollback on failure for core UTXO operations
- **Path traversal prevention**: `qgp_platform_sanitize_filename()` blocks directory traversal
- **DHT values are Dilithium5-signed** with owner verification (when verification is called)
- **Channel UUID SQL injection mitigated**: hex-only validation on table names


## Resolution Status (Updated 2026-03-16)

**35 findings RESOLVED** | **0 IN PROGRESS** | **47 remaining**

### Resolved Items
| ID | Severity | Resolution |
|----|----------|------------|
| C-04 | CRITICAL | RESOLVED (commit 49397352 — nodus_value_verify in storage PUT) |
| C-05 | CRITICAL | RESOLVED (commit 49397352 — encrypted channel member check) |
| H-05 | HIGH | RESOLVED (udp_rate_check before STORE_VALUE) |
| H-07 | HIGH | RESOLVED (commit 49397352 — channel member update owner auth) |
| H-08 | HIGH | RESOLVED (repl_verify_post_sig on BACKUP nodes) |
| H-11 | HIGH | RESOLVED (commit 49397352 — owner_fp == SHA3-512(owner_pk)) |
| H-12 | HIGH | RESOLVED (all sprintf replaced with snprintf) |
| H-13 | HIGH | RESOLVED (SIZE_MAX overflow guard in sign_payload) |
| H-14 | HIGH | RESOLVED (DNAC_GENESIS_WITNESSES_REQUIRED check) |
| H-15 | HIGH | RESOLVED (started_at + 30s timeout + disconnect cleanup) |
| H-16 | HIGH | RESOLVED (ledger entry inside atomic transaction) |
| H-17 | HIGH | RESOLVED (fee = total_input/1000 aligned client/witness) |
| M-01 | MEDIUM | RESOLVED (NODUS_CBOR_MAX_ITEMS bound) |
| M-02 | MEDIUM | RESOLVED (NODUS_MAX_FRAME_TCP guard in tcp_send + frame_encode) |
| M-09 | MEDIUM | RESOLVED (getrandom loop until full len) |
| M-10 | MEDIUM | RESOLVED (qgp_secure_memzero on entropy) |
| M-11 | MEDIUM | RESOLVED (qgp_secure_memzero on SHA-256 hash) |
| M-12 | MEDIUM | RESOLVED (chmod 0600 on nodus.sk) |
| M-13 | MEDIUM | RESOLVED (qgp_secure_memzero replaces volatile loop) |
| M-14 | MEDIUM | RESOLVED (chmod 0600 in qgp_key_save) |
| M-32 | MEDIUM | RESOLVED (tx_type range validation in deserialize) |
| M-35 | MEDIUM | RESOLVED (NONCE_MAX_TOTAL 10000 cap + eviction) |
| C-03 | CRITICAL | RESOLVED (ping-before-evict: routing_insert_or_ping + pending evictions + UDP PING + PONG cancel) |
| M-20 | MEDIUM | RESOLVED (group member add ownership check) |
| M-25 | MEDIUM | RESOLVED (CLOCK_MONOTONIC in nodus_time_now) |
| M-28 | MEDIUM | RESOLVED (heap-allocate in nodus_ops_cancel_all) |
| M-30 | MEDIUM | RESOLVED (pthread_mutex on witness discovery cache) |
| C-06 | CRITICAL | RESOLVED (verify_witnesses pins pubkey against DHT roster cache) |
| C-01 | CRITICAL | RESOLVED (server-side enforcement + config flag require_peer_auth, witness client auth done, inter-node FV deferred) |
| C-02 | CRITICAL | RESOLVED (server-side enforcement + witness peer auth with PEER_AUTH_NONE/HELLO_SENT/OK state machine) |
| H-01 | HIGH | RESOLVED (v0.9.169/nodus v0.10.2) — Kyber1024 channel encryption on all TCP connections (4001, 4002). Post-quantum transport encryption. |
| H-02 | HIGH | RESOLVED — UDP response size limits added, preventing amplification attacks. |
| H-06 | HIGH | RESOLVED (nodus v0.10.4+) — Mutual Dilithium5 auth on TCP 4002 blocks unauthenticated presence injection. |
| H-10 | HIGH | RESOLVED (nodus v0.10.4+) — Inter-node auth prevents heartbeat spoofing from unauthenticated sources. |
| M-09 | MEDIUM | RESOLVED (v0.9.169/nodus v0.10.2) — getrandom loop fixed; also transport encryption now in place. |

### Remaining Open (by priority)
| Severity | Count | Key Items |
|----------|-------|-----------|
| CRITICAL | 0 | — all resolved |
| HIGH | 4 | H-03 (static resp_buf), H-04 (inter-node quota), H-09 (ring eviction) |
| MEDIUM | 19 | See detailed findings below |
| LOW | 24 | See detailed findings below |

---
## Attack Chains

### CHAIN 1: "Witness Takeover via Unauthenticated BFT Port"
**Severity: CRITICAL | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | NET-CRIT-2 (Agent 1) | Connect to TCP 4004 — no connection-level authentication |
| 2 | DNAC-CRIT-1 (Agent 5) | Client trusts any Dilithium5 key in attestation — no roster pinning |
| 3 | NET-CRIT-1 (Agent 1) | Connect to TCP 4002 — inject presence / STORE_VALUE without auth |
| 4 | DHT-HIGH-1 (Agent 3) | Submit forged channel member updates (no authorization check) |
| 5 | Result | **Attacker forges witness attestations accepted by wallets, enabling fake UTXO crediting** |

**Remediation:** Authenticate TCP 4004 connections with challenge-response. Pin witness public keys on client side against discovered roster. Authenticate TCP 4002 with mutual Dilithium5.

---

### CHAIN 2: "DHT Eclipse to Witness Discovery Poison"
**Severity: CRITICAL | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | DHT-CRIT-1 (Agent 3) | Flood routing table via unconditional LRU eviction (no ping-before-evict) |
| 2 | NET-MEDIUM-2 (Agent 1) | Inject fake peers via unauthenticated NODES_FOUND responses |
| 3 | DHT-HIGH-4 (Agent 3) | Spoof cluster heartbeat PONG to hijack peer identity mapping |
| 4 | DHT-MEDIUM-6 (Agent 3) | No node_id validation — attacker chooses IDs targeting specific buckets |
| 5 | DNAC-CRIT-1 (Agent 5) | Client accepts unverified witness pubkeys from poisoned DHT |
| 6 | Result | **Client's witness discovery returns attacker-controlled nodes; all transactions go to fake witnesses** |

**Remediation:** Implement ping-before-evict. Authenticate T1 UDP (verify `node_id = SHA3-512(pubkey)`). Pin witness pubkeys.

---

### CHAIN 3: "Unauthenticated Inter-Node Data Injection"
**Severity: HIGH | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | NET-CRIT-1 (Agent 1) | Connect to TCP 4002 — zero authentication |
| 2 | DHT-CRIT-2 (Agent 3) | Submit STORE_VALUE — storage layer does not call `nodus_value_verify()` |
| 3 | NET-HIGH-4 (Agent 1) | Bypass client port rate limits (60 PUT/min) via inter-node port (200 SV/sec) |
| 4 | NET-HIGH-6 (Agent 1) | Inject false presence via unauthenticated `p_sync` |
| 5 | Result | **Unsigned values stored and served to messenger clients; false presence data** |

**Remediation:** Authenticate TCP 4002. Call `nodus_value_verify()` in storage PUT path. Add per-session quota on inter-node STORE_VALUE.

---

### CHAIN 4: "Key Material Harvest to Node Impersonation"
**Severity: HIGH | Confidence: MEDIUM**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | CRYPTO-MEDIUM-4 (Agent 2) | Read nodus.sk from disk — default permissions 0644, world-readable |
| 2 | CRYPTO-MEDIUM-6 (Agent 2) | Or read messenger private keys via `qgp_key_save()` — also 0644 |
| 3 | NET-HIGH-1 (Agent 1) | All TCP is plaintext — impersonate node on any port |
| 4 | Result | **Full node impersonation; forge DHT values, disrupt BFT consensus** |

**Remediation:** `chmod 0600` on all secret key files. Encrypt identity at rest. Implement TLS on all transports.

---

### CHAIN 5: "Messenger Metadata Surveillance"
**Severity: MEDIUM | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | DHT-MEDIUM-4 (Agent 3) / MSG-MEDIUM-4 (Agent 4) | Compute deterministic inbox keys from public fingerprints |
| 2 | MSG-MEDIUM-5 (Agent 4) | Compute deterministic outbox keys from public fingerprints |
| 3 | NET-HIGH-1 (Agent 1) | Monitor plaintext DHT traffic for GET/PUT patterns |
| 4 | Result | **Full communication graph reconstruction without breaking encryption** |

**Remediation:** Use per-contact shared secrets (from Kyber key exchange) in DHT key derivation. Implement transport encryption.

---

### CHAIN 6: "Encrypted Channel Spam and Disruption"
**Severity: HIGH | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | DHT-CRIT-3 (Agent 3) | Encrypted channel posts skip server-side signature verification entirely |
| 2 | DHT-HIGH-1 (Agent 3) | Add attacker as push target (no authorization on member update) |
| 3 | DHT-HIGH-2 (Agent 3) | Backup nodes store replicated posts without verification |
| 4 | Result | **Any authenticated client floods any encrypted channel with garbage; receives metadata via push notifications** |

**Remediation:** Verify `author_fp` matches session `client_fp` even for encrypted channels. Add channel membership ACL for member updates. Verify signatures on backup nodes.

---

## All Findings by Severity

### CRITICAL (6)

| ID | Description | Component | File:Line | Confidence | Prior Audit Status |
|----|-------------|-----------|-----------|------------|-------------------|
| C-01 | No authentication on inter-node TCP port 4002 — any source can connect and inject STORE_VALUE, FIND_VALUE, and presence data | Nodus Server | `nodus_server.c:1428-1444` | HIGH | KNOWN (was NET-3 / HIGH-1; mitigated by port separation but auth still absent) |
| C-02 | No authentication on witness BFT TCP port 4004 — any peer can connect and flood expensive Dilithium5 verifications or attempt consensus disruption | Nodus Server | `nodus_server.c:1460-1480` | HIGH | KNOWN (was NET-4 / CRIT-4; confirmed still open) |
| C-03 | Routing table LRU eviction without liveness check — `nodus_routing_insert()` bypasses ping-before-evict, enabling Eclipse attacks | Nodus DHT | `nodus_routing.c:72-86` | HIGH | KNOWN (was DHT-02/03 / CRIT-2/3; still open) |
| C-04 | No signature verification on DHT storage PUT path — `nodus_storage_put()` never calls `nodus_value_verify()`, accepting forged values | Nodus Storage | `nodus_storage.c:262-282` | HIGH | KNOWN (was DHT-01 / HIGH-12; still open, re-confirmed at storage layer) |
| C-05 | Encrypted channel posts skip signature verification entirely — any authenticated client can post to any encrypted channel | Nodus Channel | `nodus_channel_primary.c:317-327` | HIGH | NEW |
| C-06 | Client-side witness verification trusts embedded public key — no pinning against known roster, attacker can forge attestations with any Dilithium5 keypair | DNAC Verify | `verify.c:63-101`, `builder.c:309-327` | HIGH | KNOWN (was BFT-02; confirmed still open) |

### HIGH (17)

| ID | Description | Component | File:Line | Confidence | Prior Audit Status |
|----|-------------|-----------|-----------|------------|-------------------|
| H-01 | ~~No TLS/encryption on any transport~~ **RESOLVED (v0.9.169/nodus v0.10.2)** — Kyber1024 channel encryption on all TCP connections | Nodus Transport | `nodus_tcp.c`, `nodus_udp.c` | HIGH | RESOLVED |
| H-02 | ~~UDP amplification attack~~ **RESOLVED** — Response size limits added | Nodus Server | `nodus_server.c:1729-1786` | HIGH | RESOLVED |
| H-03 | Static response buffer `resp_buf` shared across operations — fragile reentrancy, data corruption risk if code evolves | Nodus Server | `nodus_server.c:36` | HIGH | KNOWN (was MEM-02 / HIGH-5; still open) |
| H-04 | Inter-node port accepts arbitrary STORE_VALUE — bypasses client port rate limits (200 SV/sec vs 60 PUT/min) | Nodus Server | `nodus_server.c:1402-1423` | HIGH | KNOWN (was DHT-07; confirmed) |
| H-05 | UDP STORE_VALUE has no rate limiting — unlike FIND_NODE/FIND_VALUE which have `udp_rate_check` | Nodus Server | `nodus_server.c:1751-1762` | HIGH | NEW |
| H-06 | ~~Presence sync injection via unauthenticated inter-node port~~ **RESOLVED (nodus v0.10.4+)** — Mutual Dilithium5 auth on TCP 4002 | Nodus Server | `nodus_server.c:1375-1393` | HIGH | RESOLVED |
| H-07 | Channel member update has no authorization check — any client can add/remove push targets for any encrypted channel | Nodus Channel | `nodus_channel_server.c:298-374` | HIGH | NEW |
| H-08 | Replicated channel posts not verified on BACKUP nodes — compromised PRIMARY injects forged posts into all replicas | Nodus Channel | `nodus_channel_replication.c:114-143` | HIGH | NEW |
| H-09 | Unilateral ring eviction without peer confirmation — network partition causes legitimate node eviction from hashring | Nodus Channel | `nodus_channel_ring.c:240-251` | HIGH | NEW |
| H-10 | ~~Cluster heartbeat spoofing via IP matching~~ **RESOLVED (nodus v0.10.4+)** — Inter-node auth prevents unauthenticated heartbeat spoofing | Nodus Cluster | `nodus_cluster.c:189-210` | HIGH | RESOLVED |
| H-11 | DHT value `owner_fp` not verified against `owner_pk` — enables per-owner quota bypass via mismatched fingerprints | Nodus Value | `nodus_value.c:291-293` | HIGH | NEW |
| H-12 | `sprintf` in `dht_groups.c` `serialize_metadata` — heap buffer overflow if `group_uuid` exceeds expectations | Messenger DHT | `dht_groups.c:158-173` | HIGH | KNOWN (was MEM-05 / MED-3; still open) |
| H-13 | Integer overflow in `nodus_value_sign_payload` on 32-bit — `size_t` wraps, undersized malloc, memcpy overflow | Nodus Value | `nodus_value.c:31` | HIGH | KNOWN (was MEM-10 / MED-6; still open) |
| H-14 | Genesis broadcast does not verify witness count matches unanimous requirement — trusts server-side BFT without client-side check | DNAC Genesis | `genesis.c:246-255` | HIGH | NEW |
| H-15 | Pending forward lifetime has no timeout — stale `client_conn` pointer causes use-after-free; single slot blocks all non-leader requests | Nodus Witness | `nodus_witness.h:223-228`, `nodus_witness_peer.c:515-576` | HIGH | KNOWN (was BFT-H6; confirmed) |
| H-16 | Ledger entry added outside atomic transaction — crash between COMMIT and ledger add creates non-auditable chain state | Nodus Witness | `nodus_witness_bft.c:594-601` | HIGH | NEW |
| H-17 | Fee calculation inconsistency between client and witness — different formulas can cause valid transactions to be rejected | DNAC TX | `builder.c:123`, `nodus_witness_verify.c:344-354` | HIGH | NEW |

### MEDIUM (35)

| ID | Description | Component | File:Line | Confidence | Prior Audit Status |
|----|-------------|-----------|-----------|------------|-------------------|
| M-01 | CBOR map/array count not bounded before processing — CPU-bound DoS via crafted count field | Nodus Protocol | `nodus_cbor.c:216-222`, `nodus_tier2.c:951` | HIGH | KNOWN (was MEM-01 / MED-27; confirmed) |
| M-02 | Integer overflow in `nodus_frame_encode` — `size_t` to `uint32_t` truncation on `nodus_tcp_send` | Nodus Wire | `nodus_wire.c:12`, `nodus_tcp.c:521` | HIGH | NEW |
| M-03 | Peer IP:port accepted from untrusted CBOR in NODES_FOUND — routing table poisoning, SSRF-like | Nodus Server | `nodus_server.c:1744-1749` | HIGH | KNOWN (was DHT-14; confirmed) |
| M-04 | Session token not cryptographically bound to client identity | Nodus Auth | `nodus_server.c:69-76`, `nodus_auth.c:79-86` | HIGH | NEW |
| M-05 | No version negotiation on wire protocol — complicates security upgrades | Nodus Wire | `nodus_wire.c:67-78` | HIGH | NEW |
| M-06 | UDP rate limiter table: 64 entries, linear search, trivially bypassable | Nodus Server | `nodus_server.c:1602-1673` | HIGH | KNOWN (confirmed) |
| M-07 | Channel node_hello without nonce — no challenge-response on port 4003 | Nodus Channel | `nodus_tier2.h:233-241` | MEDIUM | NEW |
| M-08 | TCP connection limit 1024 with per-IP=20 — 52 IPs exhaust all slots | Nodus Transport | `nodus_tcp.c:308-311` | MEDIUM | KNOWN (was NET-1/NET-2; confirmed) |
| M-09 | `getrandom()` partial read silently falls through to `/dev/urandom` | Shared Crypto | `qgp_platform_linux.c:33-36` | HIGH | KNOWN (was CRYPTO-02 / LOW-5; upgraded) |
| M-10 | BIP39 entropy not wiped after mnemonic generation | Shared Crypto | `bip39.c:134-141` | HIGH | KNOWN (was CRYPTO-07; confirmed) |
| M-11 | BIP39 SHA-256 hash not wiped after checksum calculation | Shared Crypto | `bip39.c:56,237` | HIGH | NEW |
| M-12 | Nodus secret key saved to disk without encryption or restrictive permissions (0644) | Nodus Crypto | `nodus_identity.c:90-98` | HIGH | KNOWN (was CRYPTO-03; confirmed) |
| M-13 | Nodus identity clear uses custom volatile loop instead of `qgp_secure_memzero()` | Nodus Crypto | `nodus_identity.c:192-198` | MEDIUM | NEW |
| M-14 | `qgp_key_save()` does not set restrictive file permissions | Shared Crypto | `qgp_key.c:108-148` | HIGH | KNOWN (was CRYPTO-04 / MED-16/17; confirmed) |
| M-15 | Session password stored in plaintext in engine struct for entire session | Messenger Engine | `dna_engine_internal.h:659` | HIGH | KNOWN (was MSG-15; confirmed) |
| M-16 | Backup thread `backup_thread_running` flag not protected by mutex — data race | Messenger Engine | `dna_engine_backup.c:67,115,191,280` | HIGH | KNOWN (was MSG-02 / HIGH-8; confirmed at lower severity for race specifically) |
| M-17 | DHT inbox key derivation publicly predictable — social graph metadata leakage | Messenger DHT | `dht_contact_request.c:33-43` | HIGH | KNOWN (was MSG-08; confirmed) |
| M-18 | Outbox DHT keys publicly enumerable — communication pattern metadata leakage | Messenger DHT | `dht_offline_queue.c:143-145` | HIGH | KNOWN (was MSG-08 partial; confirmed) |
| M-19 | Mnemonic exposed in memory during wallet derivation — copies may persist in callees | Messenger Engine | `dna_engine_wallet.c:57-79` | HIGH | KNOWN (was CRYPTO-05 / MED-22; confirmed) |
| M-20 | Group member addition has no ownership check (unlike removal which does) | Messenger Engine | `dna_engine_groups.c:346-391` | HIGH | NEW |
| M-21 | Detached background fetch threads can access freed engine — use-after-free | Messenger Engine | `dna_engine.c:827-868` | MEDIUM | KNOWN (was MSG-09 / MED-24; confirmed) |
| M-22 | Hardcoded bootstrap node IPs — single point of failure, Eclipse vector for new clients | Messenger DHT | `nodus_init.c:70-77` | HIGH | KNOWN (confirmed) |
| M-23 | No rate limiting on hinted handoff insertions — unbounded disk growth | Nodus Channel | `nodus_channel_store.c:491-508` | HIGH | NEW |
| M-24 | Channel SQL table name construction fragile — validated but not centralized | Nodus Channel | `nodus_channel_store.c:206-261` | MEDIUM | NEW |
| M-25 | Cluster dead node detection uses wall clock (not monotonic) — clock jump causes false dead | Nodus Cluster | `nodus_cluster.c:149-157` | MEDIUM | NEW |
| M-26 | No node_id validation in routing table — no `node_id = SHA3-512(pubkey)` binding | Nodus Routing | `nodus_routing.c:39-87` | HIGH | KNOWN (was DHT-02; part of Sybil attack surface) |
| M-27 | Ring rejoin accepts any authenticated node without membership verification | Nodus Channel | `nodus_channel_ring.c:377-428` | HIGH | NEW |
| M-28 | `nodus_ops_cancel_all` ~80KB stack allocation | Messenger DHT | `nodus_ops.c:451` | HIGH | KNOWN (was MEM-04 / MED-2; confirmed) |
| M-29 | Nullifier derivation uses variable-length fingerprint without domain separation | DNAC TX | `nullifier.c:34-64` | MEDIUM | NEW |
| M-30 | Global mutable state in witness discovery cache — no thread safety | DNAC Client | `client.c:34-37`, `discovery.c:32-35` | MEDIUM | NEW |
| M-31 | View change does not verify new leader differs from timed-out leader | Nodus Witness | `nodus_witness_bft.c` | MEDIUM | KNOWN (was BFT-M24 area; related) |
| M-32 | Transaction deserialization does not validate `tx_type` range | DNAC TX | `serialize.c:144-146` | HIGH | NEW |
| M-33 | SQLite `int64` storage for `uint64` amounts — safe now but implicit constraint | DNAC DB | `db.c:204`, `nodus_witness_db.c:129` | HIGH | NEW |
| M-34 | Wallet sync clears all UTXOs before recovery — zero balance during network outage | DNAC Wallet | `wallet.c:332-334` | HIGH | NEW |
| M-35 | Unbounded nonce allocation in BFT replay prevention — memory exhaustion DoS | Nodus Witness | `nodus_witness_bft.c:52-85` | HIGH | KNOWN (was MEM-08; confirmed) |

### LOW (24)

| ID | Description | Component | Confidence | Prior Audit Status |
|----|-------------|-----------|------------|-------------------|
| L-01 | Nonce not invalidated after failed auth (but 256-bit entropy makes brute force infeasible) | Nodus Auth | HIGH | NEW |
| L-02 | Wire frame 32-bit length field allows 4MB allocation before rejection | Nodus Wire | HIGH | KNOWN (was MEM-12 / LOW-7) |
| L-03 | CBOR text strings not validated as UTF-8 | Nodus Protocol | HIGH | NEW |
| L-04 | TCP port derivation uses hardcoded offset convention | Nodus Server | HIGH | NEW |
| L-05 | Integer truncation in CBOR decoder on 32-bit platforms | Nodus Protocol | MEDIUM | NEW |
| L-06 | Dilithium5 deterministic signing (no randomized nonce hedging) | Shared Crypto | HIGH | NEW |
| L-07 | Keccak-256 uses `memset` instead of `qgp_secure_memzero` for state cleanup | Shared Crypto | HIGH | KNOWN (was CRYPTO-10) |
| L-08 | secp256k1 context created per-call (performance, not security) | Shared Crypto | HIGH | NEW |
| L-09 | `key_verify_password` 8KB stack buffer for key material | Shared Crypto | MEDIUM | KNOWN (was MEM-05 area) |
| L-10 | BIP32 global secp256k1 context not thread-safe (lazy init race) | Shared Crypto | HIGH | KNOWN (was CRYPTO-16) |
| L-11 | Windows HANDLE truncation in identity lock (64-bit Windows) | Shared Crypto | MEDIUM | NEW |
| L-12 | `qgp_key_load` does not validate key sizes from file header | Shared Crypto | HIGH | NEW |
| L-13 | HMAC-SHA512 silently returns zeros on malloc failure | Shared Crypto | HIGH | KNOWN (was MEM-19 / LOW-14) |
| L-14 | Static buffers in `armor.c` and `qgp_key.c` not thread-safe | Shared Crypto | HIGH | NEW |
| L-15 | `dna_engine_get_global()` returns pointer without reference counting — use-after-free window | Messenger Engine | HIGH | NEW |
| L-16 | Wall/channel post body size not validated at engine API layer | Messenger Engine | MEDIUM | NEW |
| L-17 | `nodus_ops_dispatch` snapshot limited to 32 matches — excess silently dropped | Messenger DHT | HIGH | NEW |
| L-18 | Identity lock file descriptor leak on error path | Messenger Engine | MEDIUM | NEW |
| L-19 | Contact request replay within TTL window after device restore | Messenger DHT | HIGH | NEW |
| L-20 | `strtok` usage in log tag parsing is not thread-safe | Messenger Engine | HIGH | NEW |
| L-21 | DHT hinted handoff table dropped on server restart (data loss) | Nodus Storage | HIGH | NEW |
| L-22 | Stale entry filtering in `find_closest` uses wall clock (not monotonic) | Nodus Routing | MEDIUM | NEW |
| L-23 | `fprintf(stderr)` used throughout nodus server instead of structured logging | Nodus Server | HIGH | KNOWN (was MEM-17) |
| L-24 | `strtoull` without error checking in DNAC CLI amount parsing | DNAC CLI | HIGH | NEW |

---

## Comparison with Prior Audit (2026-03-14)

### Findings Confirmed by Both Audits (KNOWN)

| v2 ID | v1 ID(s) | Description | Status Change |
|-------|----------|-------------|---------------|
| C-01 | NET-3 / HIGH-1 | TCP 4002 unauthenticated | Still open; mitigated by port separation only |
| C-02 | NET-4 / CRIT-4 | TCP 4004 unauthenticated | Still open |
| C-03 | DHT-02/03 / CRIT-2/3 | Routing table Eclipse attack | Still open |
| C-04 | DHT-01 / HIGH-12 | DHT values served without signature verification | Still open; v2 pinpoints storage layer |
| C-06 | BFT-02 | Witness pubkey not pinned | Still open |
| H-01 | NET-6 / MED-9 | All ports plaintext | Upgraded to HIGH |
| H-02 | NET-7 | UDP amplification | Confirmed |
| H-03 | MEM-02 / HIGH-5 | Static resp_buf reentrancy | Still open |
| H-04 | DHT-07 | Inter-node STORE_VALUE no quota | Confirmed |
| H-06 | NET-9 | Presence sync injection | Confirmed |
| H-10 | DHT-15 | Heartbeat PONG spoofing | Confirmed |
| H-12 | MEM-05 / MED-3 | sprintf buffer overflow in groups | Still open |
| H-13 | MEM-10 / MED-6 | Integer overflow in value sign_payload | Still open |
| H-15 | BFT-H6 | Pending forward UAF | Still open |
| M-12 | CRYPTO-03 | Nodus SK world-readable | Confirmed |
| M-14 | CRYPTO-04 / MED-16/17 | qgp_key_save no chmod | Confirmed |

### New Findings in v2 (Not in v1)

| v2 ID | Description |
|-------|-------------|
| C-05 | Encrypted channel posts skip signature verification entirely |
| H-05 | UDP STORE_VALUE no rate limiting |
| H-07 | Channel member update no authorization check |
| H-08 | Replicated channel posts not verified on BACKUP nodes |
| H-09 | Unilateral ring eviction without peer confirmation |
| H-11 | DHT value owner_fp not verified against owner_pk |
| H-14 | Genesis broadcast doesn't verify witness count |
| H-16 | Ledger entry outside atomic transaction |
| H-17 | Fee calculation inconsistency client vs witness |
| M-02 | Integer overflow in frame_encode (size_t to uint32_t) |
| M-04 | Session token not bound to client identity |
| M-05 | No version negotiation |
| M-07 | Channel node_hello without nonce |
| M-11 | BIP39 SHA-256 hash not wiped |
| M-13 | Nodus identity clear custom volatile loop |
| M-20 | Group member add no ownership check |
| M-23 | Unbounded hinted handoff insertions |
| M-24 | Channel SQL table name construction fragile |
| M-25 | Wall clock for dead node detection |
| M-27 | Ring rejoin no membership verification |
| M-29 | Nullifier derivation no domain separation |
| M-30 | Witness discovery cache no thread safety |
| M-32 | tx_type range not validated on deserialization |
| M-33 | SQLite int64 for uint64 amounts |
| M-34 | Wallet sync clears UTXOs before recovery |

### Findings in v1 Not Found by v2

| v1 ID | Description | Assessment |
|-------|-------------|------------|
| CRIT-1 | T1 fallback vulnerability | **FIXED** — confirmed in v1 |
| HIGH-2 | Missing per-session rate limits | **FIXED** — per-session rate limits now present |
| HIGH-13 | Wire array count caps missing | **FIXED** — `NODUS_MAX_WIRE_*` caps now defined |
| HIGH-4 | Stack allocation in presence | **FIXED** — reduced |
| CRIT-5 (v1) | Roster add no authorization | Not specifically re-tested in v2; v1 finding still relevant if code unchanged |
| CRIT-6 (v1) | COMMIT skips TX verification | Not specifically re-tested in v2; v1 finding still relevant if code unchanged |
| MEM-09 (v1) | fv_fd_table OOB on fd >= 4096 | Not re-tested by v2 agents |
| BFT-H7 (v1) | UTXO checksum mismatch only logs | Not re-tested by v2 agents |
| BFT-H14 (v1) | DB commit failure continues BFT | Not re-tested by v2 agents |
| MSG-01 (v1) | Contact request auto-approval bypass | Not re-tested by v2 agents |
| MSG-03 (v1) | GEK removed members retain old keys | Not re-tested by v2 agents; architectural issue |
| MSG-04 (v1) | GEK static KEM keys no thread safety | Not re-tested by v2 agents |

**Note:** Several v1 HIGH/CRITICAL findings in the witness BFT and messenger domains were not explicitly re-audited by v2 agents. These should be assumed STILL OPEN unless code changes can be verified.

### Regressions

No regressions identified. All fixed issues from v1 remain fixed.

---

## Remediation Priority

### Phase 1: Before Production (MUST FIX)

| Priority | IDs | Description | Effort |
|----------|-----|-------------|--------|
| P1 | C-01, C-02 | Authenticate TCP 4002 (inter-node) and TCP 4004 (witness) with mutual Dilithium5 challenge-response | 3-5 days |
| P2 | C-06, H-14 | Pin witness public keys against trusted roster on client side; verify witness count for genesis | 1-2 days |
| P3 | C-04, H-11 | Call `nodus_value_verify()` in storage PUT path; verify `owner_fp = SHA3-512(owner_pk)` | 2-4 hours |
| P4 | C-05, H-07 | Verify `author_fp` matches session for encrypted channels; add authorization check on member updates | 1-2 days |
| P5 | C-03, M-26 | Enforce ping-before-evict; validate `node_id = SHA3-512(pubkey)` in routing | 2-3 days |
| P6 | H-12 | Replace `sprintf` with `snprintf` in `dht_groups.c` | 30 min |
| P7 | H-13, M-02 | Add overflow checks in `nodus_value_sign_payload` and `nodus_tcp_send` | 1 hour |
| P8 | M-12, M-14 | `chmod 0600` on nodus.sk and `qgp_key_save()` output files | 30 min |
| P9 | H-16 | Move ledger entry inside atomic transaction in witness BFT | 1-2 hours |
| P10 | H-05 | Add rate limiting for UDP STORE_VALUE | 1 hour |

### Phase 2: Near-Term (within 30 days)

| Priority | IDs | Description | Effort |
|----------|-----|-------------|--------|
| P11 | ~~H-01~~ | ~~Implement TLS 1.3 on all TCP transports~~ **RESOLVED** — Kyber1024 channel encryption (v0.9.169) | ~~1-2 weeks~~ |
| P12 | ~~H-02~~, M-06 | ~~UDP amplification~~ **RESOLVED** (response size limits); Scalable rate limiter still open | 2-3 days |
| P13 | H-08 | Verify post signatures on BACKUP nodes before storing | 1 day |
| P14 | H-09, M-27 | Require peer confirmation for eviction; membership verification for ring rejoin | 2-3 days |
| P15 | H-10, M-25 | Authenticate PONG responses; use monotonic clock for heartbeat | 1-2 days |
| P16 | H-15 | Add timeout and cleanup for pending_forward; clear on client disconnect | 2-4 hours |
| P17 | H-17 | Align fee calculation between client and witness | 2-4 hours |
| P18 | M-01, M-35 | Bound CBOR map/array counts; cap nonce table entries | 1 day |
| P19 | M-10, M-11, M-19 | Wipe BIP39 entropy, SHA-256 hash, and mnemonic copies from stack | 2 hours |
| P20 | M-15, M-16, M-21 | Session password mlock; backup thread mutex; shutdown-check in detached threads | 1-2 days |
| P21 | M-17, M-18 | Use per-contact shared secret in DHT key derivation for inbox/outbox | 3-5 days |
| P22 | M-20 | Add ownership check to group member addition | 1 hour |
| P23 | M-34 | Reconciliation-based wallet sync instead of clear-then-recover | 1-2 days |

### Phase 3: Backlog

- M-04: Bind session token to client fingerprint
- M-05: Wire protocol version negotiation
- M-07: Channel node_hello challenge-response
- M-08: Reduce per-IP connection limits for unauthenticated connections
- M-09: Loop `getrandom()` on partial reads
- M-13: Replace custom volatile loop with `qgp_secure_memzero()`
- M-22: Supplement hardcoded bootstrap with signed DNS/HTTPS discovery
- M-23: Cap hinted handoff entries per target
- M-24: Centralize UUID-to-table-name conversion
- M-28: Heap-allocate `nodus_ops_cancel_all` buffer
- M-29: Domain separation in nullifier derivation
- M-30: Add mutex to witness discovery cache
- M-31: Skip views that re-elect same leader
- M-32: Validate tx_type range during deserialization
- M-33: Compile-time assertion `DNAC_DEFAULT_TOTAL_SUPPLY < INT64_MAX`
- All LOW findings (L-01 through L-24)

---

## Methodology Notes

### Agent Coverage

| Agent | Domain | Files Audited | Key Focus Areas |
|-------|--------|---------------|-----------------|
| Agent 1 | Network/Transport | 18 files | TCP/UDP transports, wire protocol, server accept/dispatch, auth |
| Agent 2 | Cryptography | 35 files | Dilithium5, Kyber1024, AES-GCM, BIP39/32, key storage, RNG |
| Agent 3 | DHT/Kademlia | 27 files | Routing, storage, values, channels, hashring, cluster, messenger DHT integration |
| Agent 4 | Messenger (DNA Connect) | 42 files | Engine API, all 17 engine modules, DHT client layer, keyserver |
| Agent 5 | DNAC/Witness BFT | 30 files | Transactions, wallet, witness BFT consensus, genesis, verification, DB |
| Agent 6 | Memory Safety/Input Validation | 24 files | Wire parsing, CBOR decoder, buffer allocations, integer overflow, input validation |

### Methodology
- **STRIDE** threat model applied per component (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **Cross-domain analysis** identified 6 attack chains where findings from different agents combine into multi-step exploits
- **Deduplication**: 14 findings were merged where multiple agents identified the same root cause (e.g., Agent 1 NET-CRIT-1 + Agent 3 DHT-CRIT-2 on routing table poisoning; Agent 1 HIGH-3 + Agent 6 HIGH-4 on static resp_buf)
- **Confidence levels**: HIGH = verified in source code with file:line citation; MEDIUM = likely based on code patterns and architecture; LOW = theoretical
- **Static analysis only** — no dynamic testing, fuzzing, or runtime verification performed
- **Comparison baseline**: All findings cross-referenced against the 2026-03-14 v1 audit (88 findings)

---

*Generated by Claude Opus 4.6 automated security assessment, 2026-03-15*
