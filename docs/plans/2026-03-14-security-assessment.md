# DNA / Nodus / DNAC Full-Stack Security Assessment

**Date:** 2026-03-14
**Scope:** Full stack -- Network, Crypto, DHT/Consensus, Messenger, DNAC/Witness BFT, Input Validation/Memory Safety
**Version:** Nodus v0.9.1 | Messenger v0.9.78 | DNAC v0.11.1
**Method:** 6 parallel domain agents + 1 cross-domain consolidation agent
**Prior Audit:** v0.6.8 (2026-03-12) -- 61 findings
**Threat Model:** STRIDE per component + cross-domain attack chain analysis

---

## Executive Summary

**88 unique findings** across 6 domains, forming **7 cross-domain attack chains:**

| Severity | Count |
|----------|-------|
| CRITICAL | 6 |
| HIGH | 16 |
| MEDIUM | 40 |
| LOW | 26 |

**Top 3 systemic risks:**
1. **Witness BFT has no authentication** -- A single TCP connection to port 4004 can inject fake witnesses and take over consensus (Chain 1: "Witness Takeover")
2. **Inter-node port 4002 has no authentication** -- Any host can inject DHT values, corrupt presence, and enumerate stored data (Chain 3)
3. **UDP Kademlia has no authentication** -- Trivial Sybil/Eclipse attacks poison routing tables, cascading into witness discovery (Chain 2)

**Since v0.6.8 audit:** CRIT-1 fixed, HIGH-2 fixed. But CRIT-2, CRIT-3, CRIT-4, CRIT-5 remain open. 6 new CRITICAL-chain-worthy findings discovered.

### Positive Findings
- All SQLite uses parameterized queries (zero SQL injection)
- AES-256-GCM nonce generation correct (CSPRNG)
- PBKDF2 at 210,000 iterations
- `qgp_secure_memzero` correctly uses `explicit_bzero`
- DHT values are Dilithium5-signed with owner verification
- Fail-closed nullifier check (DB error = assume spent)
- TX hash integrity verified before DB commit
- Chain ID validation prevents cross-zone replay
- Atomic DB transactions in witness with rollback

---

## Attack Chains

### CHAIN 1: "Witness Takeover" -- Complete BFT Consensus Hijack
**Severity: CRITICAL | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | NET-4 / CRIT-4 | Connect to TCP 4004, send `w_ident` (no signature verification) |
| 2 | CRIT-5 | Roster add has no authorization -- attacker added as witness |
| 3 | Repeat | Register enough fake witnesses for quorum (2f+1) |
| 4 | CRIT-6 | Forge COMMIT -- followers skip TX verification if they missed PROPOSE |
| 5 | Result | **Arbitrary DNAC minting, double-spend, ledger corruption** |

**Remediation:** Verify `w_ident` signatures. Restrict roster to config allowlist. Include `client_pubkey` in COMMIT.

### CHAIN 2: "DHT Eclipse to Witness Discovery Poison"
**Severity: CRITICAL | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | DHT-02/03 | Flood UDP 4000 with fake PING/fn_r to poison routing table |
| 2 | DHT-04 | Poisoned routing entries enter hashring |
| 3 | DHT-15 | Bootstrap by spoofing seed node PONG |
| 4 | BFT-02 | Client accepts unverified witness pubkeys from DHT |
| 5 | Result | **Client talks to attacker-controlled witnesses** |

**Remediation:** Authenticate T1 UDP (`node_id == SHA3-512(pubkey)`). Separate hashring from routing. Pin witness pubkeys.

### CHAIN 3: "Unauthenticated Inter-Node Value Injection"
**Severity: HIGH | Confidence: HIGH**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | NET-3 | Connect to TCP 4002 (zero auth) |
| 2 | DHT-07 | Send STORE_VALUE -- no quota enforcement |
| 3 | DHT-01/08 | Values cached and served without signature verification |
| 4 | NET-9 | Inject fake presence via p_sync |
| 5 | Result | **Corrupted DHT data served to messenger users** |

**Remediation:** Authenticate TCP 4002 (mutual Dilithium5). Add quota on replication. Verify values before caching/serving.

### CHAIN 4: "Key Material Harvest"
**Severity: HIGH | Confidence: MEDIUM**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | CRYPTO-03 | Read nodus SK from disk (world-readable 0644) |
| 2 | CRYPTO-17 | Or call `nodus_identity_export()` (returns raw SK) |
| 3 | NET-6 | All TCP is plaintext -- impersonate node |
| 4 | Result | **Full node impersonation** |

**Remediation:** chmod 0600 on SK files. Encrypt identity export. Implement TLS.

### CHAIN 5: "Memory Corruption Pipeline"
**Severity: HIGH | Confidence: MEDIUM**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | NET-1/2 | Open persistent connections (no idle timeout, no per-IP limit) |
| 2 | MEM-03 | Trigger unbounded allocation via crafted value deserialization |
| 3 | MEM-09 | Trigger OOB write in fv_fd_table (fd >= 4096) |
| 4 | MEM-05 | Trigger sprintf overflow via malformed group metadata |
| 5 | Result | **Server crash or potential RCE on 32-bit** |

**Remediation:** Add idle timeout. Per-IP limits. Bounds check on all allocations.

### CHAIN 6: "Messenger Forward Secrecy Breach"
**Severity: HIGH | Confidence: MEDIUM**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | MSG-03 | Removed member keeps old GEK |
| 2 | MSG-08 | Monitor deterministic DHT key for group messages |
| 3 | MSG-05 | Replay messages (signature doesn't cover timestamp) |
| 4 | Result | **Persistent read access after group removal** |

### CHAIN 7: "Contact Hijack to MitM"
**Severity: HIGH | Confidence: MEDIUM**

| Step | Vulnerability | Action |
|------|--------------|--------|
| 1 | Chain 3 | Inject malicious contact record into DHT |
| 2 | MSG-01 | Auto-approval bypass adds attacker as contact |
| 3 | Result | **Attacker becomes trusted contact without consent** |

---

## All Findings by Severity

### CRITICAL (6)

| ID | Description | Component | Confidence | Status |
|----|-------------|-----------|------------|--------|
| CRIT-4 | IDENT messages bypass signature verification | `nodus_witness_peer.c:351` | HIGH | Known/Confirmed |
| CRIT-5 | Roster add has no authorization | `nodus_witness_bft.c:209` | HIGH | Known/Confirmed |
| CRIT-6 | COMMIT skips TX verification (missed PROPOSE) | `nodus_witness_bft.c:1082` | HIGH | Known/Confirmed |
| DHT-02 | No auth on T1 UDP -- Sybil/Eclipse | `nodus_server.c:1545` | HIGH | Known (CRIT-2) |
| DHT-03 | Routing table poisoning via unauthenticated fn_r | `nodus_server.c:1607` | HIGH | Known (CRIT-3) |
| NET-3 | TCP 4002 completely unauthenticated | `nodus_server.c:1276` | HIGH | Known (HIGH-1) |

### HIGH (16)

| ID | Description | Component | Confidence | Status |
|----|-------------|-----------|------------|--------|
| NET-4 | Witness port 4004 no auth, IDENT bypass | `nodus_server.c:1403` | HIGH | NEW |
| NET-6 | Plaintext TCP on all ports | `nodus_tcp.c` | HIGH | Known (MED-9 upgraded) |
| DHT-01 | FIND_VALUE cache stores unverified values | `nodus_server.c:970` | HIGH | Known (HIGH-12) |
| DHT-04 | Hashring from unauthenticated routing | `nodus_server.c:1196` | HIGH | Known (MED-13 upgraded) |
| DHT-08 | FIND_VALUE sends unverified values to clients | `nodus_server.c:954` | HIGH | NEW |
| BFT-02 | Missing witness pubkey pinning | `dnac/src/transaction/builder.c:308` | HIGH | NEW |
| BFT-H6 | Dangling pending_forward.client_conn (UAF) | `nodus_witness_peer.c:863` | HIGH | Known/Confirmed |
| BFT-H7 | UTXO checksum mismatch only logs warning | `nodus_witness_bft.c:1144` | HIGH | Known/Confirmed |
| BFT-H14 | DB commit failure continues BFT flow | `nodus_witness_bft.c:927` | HIGH | Known/Confirmed |
| MSG-01 | Contact request auto-approval bypass | `dna_engine_contacts.c:409` | HIGH | Known (HIGH-7) |
| MSG-02 | Detached backup threads use-after-free | `dna_engine_backup.c:270` | HIGH | Known (HIGH-8) |
| MSG-03 | GEK removed members retain old keys | `gek.c:604` | HIGH | Known (HIGH-11) |
| MSG-04 | GEK static KEM keys no thread safety | `gek.c:49` | HIGH | Known (MED-20 upgraded) |
| MEM-02 | Shared static resp_buf reentrancy risk | `nodus_server.c:36` | HIGH | Known (HIGH-5) |
| MEM-03 | Unbounded allocation in value deserialization | `nodus_value.c:268` | HIGH | Known (HIGH-6) |
| CRYPTO-03 | Nodus identity SK files world-readable | `nodus_identity.c:73` | HIGH | NEW (nodus path) |

### MEDIUM (40)

| ID | Description | Confidence | Status |
|----|-------------|------------|--------|
| NET-1 | No application-level idle timeout | HIGH | Known (CRIT-4 partial) |
| NET-2 | No per-IP connection limit | HIGH | Known (CRIT-5 partial) |
| NET-5 | No auth attempt rate limiting | HIGH | Known (MED-14) |
| NET-7 | UDP Kademlia no rate limit | HIGH | NEW |
| NET-9 | p_sync presence injection | HIGH | NEW |
| NET-11 | Session token replay without TLS | HIGH | NEW |
| DHT-05 | Sequence rollback on client PUT | HIGH | Known (MED-10) |
| DHT-06 | Per-owner quota bypass via Sybil | HIGH | Known (MED-12) |
| DHT-07 | No quota on inter-node STORE_VALUE | HIGH | NEW |
| DHT-10 | Leader election uses unauth node_ids | HIGH | NEW |
| DHT-14 | FIND_VALUE candidates not verified (SSRF) | HIGH | NEW |
| DHT-15 | Seed discovery trusts first PONG | HIGH | NEW |
| BFT-01 | Supply summation overflow in genesis | HIGH | NEW |
| BFT-03 | Nullifier uses public data only | HIGH | NEW |
| BFT-06 | Genesis supply re-derivation no safe math | HIGH | NEW |
| BFT-07 | UTXO query lacks owner verification | MEDIUM | NEW |
| BFT-M24 | View change drops client response | HIGH | Known/Confirmed |
| BFT-M25 | Follower adopts unverified round/view | HIGH | Known/Confirmed |
| BFT-M26 | Single pending_forward slot | HIGH | Known/Confirmed |
| MSG-05 | Signature covers plaintext only | HIGH | Known (MED-18) |
| MSG-06 | MPSC queue not actually lock-free | HIGH | Known (MED-19) |
| MSG-07 | nodus_init global state no thread safety | MEDIUM | Known (MED-21) |
| MSG-08 | DHT key derivation leaks metadata | HIGH | Known (partial) |
| MSG-09 | Event dispatch race during destroy | MEDIUM | Known (MED-24) |
| MSG-10 | Signing key without password in flush | HIGH | NEW |
| MSG-11 | Outbox cache not thread-safe | HIGH | NEW |
| MEM-01 | CBOR map*2 overflow on 32-bit | HIGH | Known (MED-27) |
| MEM-04 | nodus_ops_cancel_all ~80KB stack | HIGH | Known (MED-2) |
| MEM-05 | dht_groups.c sprintf buffer overflow | HIGH | Known (MED-3) |
| MEM-06 | Unchecked malloc in nodus_client.c | HIGH | Known (MED-4) |
| MEM-07 | nonce_buckets no thread safety | MEDIUM | NEW |
| MEM-08 | nonce hash table unbounded growth | HIGH | NEW |
| MEM-09 | fv_fd_table OOB on fd >= 4096 | HIGH | NEW |
| MEM-10 | Integer overflow in value sign_payload (32-bit) | MEDIUM | Known (MED-6) |
| MEM-11 | Value serialize buffer overflow (32-bit) | MEDIUM | Known (MED-6) |
| MEM-13 | JSON sscanf format mismatch | HIGH | NEW |
| MEM-14 | member_count unbounded allocation | HIGH | NEW |
| MEM-16 | Unchecked mallocs in witness handlers | HIGH | NEW |
| MEM-18 | base58_decode no output size param | HIGH | NEW |
| CRYPTO-01 | Dilithium5 keypair secret not wiped | HIGH | Known (MED-15) |
| CRYPTO-02 | getrandom() partial read | HIGH | Known (LOW-5) |
| CRYPTO-04 | qgp_key_save() no chmod | HIGH | Known (MED-16/17) |
| CRYPTO-05 | Master seed on stack not mlock'd | HIGH | Known (MED-22) |
| CRYPTO-17 | nodus_identity_export unencrypted SK | HIGH | NEW |

### LOW (26)

| ID | Description | Status |
|----|-------------|--------|
| NET-8 | Shared static resp_buf (duplicate of MEM-02) | NEW |
| NET-10 | Channel notification buffer size | NEW |
| CRYPTO-06 | Seed/mnemonic AES-GCM without AAD | Known (LOW-2) |
| CRYPTO-07 | BIP39 entropy not wiped from stack | NEW |
| CRYPTO-10 | Keccak-256 memset not secure | NEW |
| CRYPTO-11 | TOCTOU between file creation and chmod | NEW |
| CRYPTO-12 | qgp_platform_write_file no permissions | NEW |
| CRYPTO-13 | Windows no ACL for key files | NEW |
| CRYPTO-16 | BIP32 secp256k1 context lazy init race | NEW |
| MSG-12 | No Unicode bidi stripping | Known (LOW-16) |
| MSG-13 | No domain separation in signed payloads | Known (LOW-6) |
| MSG-14 | GEK database handle not protected | NEW |
| MSG-15 | Session password plaintext in struct | NEW |
| MSG-16 | Path traversal validation is dead code | NEW |
| BFT-04 | Builder fee no overflow check | NEW |
| BFT-05 | Witness spend result timestamp discrepancy | NEW |
| BFT-08 | Key material not zeroed on free | NEW |
| BFT-L6 | Vote signatures not stored | Known/Confirmed |
| BFT-L7 | Genesis requires unanimous vote | Known/Confirmed |
| DHT-13 | Permanent values never cleaned up | NEW |
| MEM-12 | frame_decode int truncation | Known (LOW-7) |
| MEM-15 | Stale witness peer connection pointer | Known (LOW-11) |
| MEM-17 | fprintf instead of QGP_LOG | NEW |
| MEM-19 | HMAC-SHA512 silent failure | Known (LOW-14) |
| MEM-20 | CBOR decoder no depth tracking | NEW |
| MEM-21 | Payload length overflow messages.c | NEW |
| MEM-22 | witness_db utxo_lookup off-by-one | Known (LOW-12) |

---

## Prior Audit (v0.6.8) Status Tracking

| Prior ID | Severity | Status |
|----------|----------|--------|
| CRIT-1 | CRITICAL | **FIXED** (T1 fallback removed) |
| CRIT-2 | CRITICAL | **STILL OPEN** (UDP auth) |
| CRIT-3 | CRITICAL | **STILL OPEN** (routing poisoning) |
| CRIT-4 | CRITICAL | **MITIGATED** (separate pools, not fixed) |
| CRIT-5 | CRITICAL | **MITIGATED** (separate pools, not fixed) |
| HIGH-1 | HIGH | **MITIGATED** (port 4002 separation, no auth) |
| HIGH-2 | HIGH | **FIXED** (per-session rate limits) |
| HIGH-3 | HIGH | **STILL OPEN** (PBFT heartbeat-only) |
| HIGH-4 | HIGH | **FIXED** (stack allocation reduced) |
| HIGH-5 | HIGH | **STILL OPEN** (resp_buf) |
| HIGH-6 | HIGH | **STILL OPEN** (unbounded alloc) |
| HIGH-7 | HIGH | **STILL OPEN** (contact auto-approve) |
| HIGH-8 | HIGH | **STILL OPEN** (backup UAF) |
| HIGH-9 | HIGH | Not verified in this audit |
| HIGH-10 | HIGH | **MITIGATED** (restricted to 4002) |
| HIGH-11 | HIGH | **STILL OPEN** (GEK architectural) |
| HIGH-12 | HIGH | **STILL OPEN** (FV cache unverified) |
| HIGH-13 | HIGH | **FIXED** (wire array count caps) |
| MED-1..27 | MEDIUM | Most **STILL OPEN** (see findings) |
| LOW-1..16 | LOW | Most **STILL OPEN** (see findings) |

**Summary:** 4 fixed, 4 mitigated, ~53 still open from v0.6.8.

---

## Remediation Priority

### Phase 1: Before Production (MUST FIX)

| Priority | IDs | Description | Effort |
|----------|-----|-------------|--------|
| P1 | CRIT-4, CRIT-5, NET-4 | Witness IDENT auth + roster allowlist | 2-3 days |
| P2 | CRIT-6 | Include client_pubkey in COMMIT | 1 day |
| P3 | NET-3 | Authenticate TCP 4002 (mutual Dilithium5) | 2-3 days |
| P4 | DHT-01, DHT-08 | Add `nodus_value_verify()` before cache/serve | 1 hour |
| P5 | MEM-03 | Add MAX_VALUE_SIZE check before malloc | 10 min |
| P6 | MEM-09 | Add bounds check on fv_fd_table write | 10 min |
| P7 | CRYPTO-03 | chmod 0600 on nodus SK files | 15 min |
| P8 | MSG-01 | Verify outgoing request before auto-approve | 2-4 hours |
| P9 | NET-1, NET-2 | Idle timeout + per-IP connection limit | 1-2 days |
| P10 | DHT-07 | Add quota on inter-node STORE_VALUE | 2 hours |

### Phase 2: Near-Term (within 30 days)

| Priority | IDs | Description | Effort |
|----------|-----|-------------|--------|
| P11 | DHT-02, DHT-03 | Authenticate T1 UDP protocol | 1-2 weeks |
| P12 | NET-6 | Transport encryption (TLS or Noise) | 1-2 weeks |
| P13 | BFT-02 | Witness pubkey pinning | 1 day |
| P14 | BFT-H6 | Fix pending_forward.client_conn UAF | 30 min |
| P15 | BFT-H7 | Halt witness on UTXO checksum mismatch | 2 hours |
| P16 | BFT-H14 | Don't broadcast COMMIT on DB failure | 2 hours |
| P17 | MSG-02 | Convert backup threads to joinable | 4-8 hours |
| P18 | MSG-04 | Add rwlock on GEK KEM keys | 4 hours |
| P19 | CRYPTO-01 | Wipe Dilithium5 secret material | 30 min |

### Phase 3: Backlog

All MEDIUM and LOW findings not listed above. See individual finding descriptions for effort estimates.

---

## Methodology Notes

- **6 parallel agents** each read source code independently, citing file:line numbers
- **STRIDE threat model** applied per component
- **Cross-domain analysis** identified 7 attack chains where findings from different domains combine
- **Confidence levels** reflect how certain the auditor is that the finding is real (HIGH = verified in code, MEDIUM = likely based on patterns, LOW = theoretical)
- **No dynamic testing** was performed -- this is a static code review
- **No fuzzing** was performed -- see `messenger/docs/FUZZING.md` for fuzzing recommendations

---

*Generated by Claude Opus 4.6 automated security assessment, 2026-03-14*
