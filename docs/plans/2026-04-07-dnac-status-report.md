# DNAC Post-Quantum Blockchain — Status Report

**Date:** April 7, 2026
**Version:** DNAC v0.12.0 / Nodus v0.10.9
**Phase:** Development (pre-alpha)
**Cluster:** 7 nodes (6 EU + 1 US)

---

## Executive Summary

DNAC is a post-quantum UTXO blockchain running on the Nodus BFT witness network. Today's session removed the DHT dependency, added block hash linking (prev_hash), commit certificates (2f+1 Dilithium5 signatures per block), and performed a live genesis with real token transfers.

**Key finding:** A node that misses a single BFT round ends up with a diverged chain, broken supply invariant, and a double-spend vulnerability. State sync is the highest priority missing feature.

---

## Chain State (Live Data)

| Metric | Value |
|--------|-------|
| Genesis supply | 100,000,000,000,000 raw (1,000,000 tokens) |
| Block height | 4 |
| Transactions committed | 4 (1 genesis + 3 spend) |
| Active UTXOs | 4 |
| Spent nullifiers | 3 |
| UTXO total value | 99,700,799,900,002 raw |
| Burned (fees) | 299,200,099,998 raw (2,992.00099998 tokens) |
| Supply invariant | ✅ Holds on 6/7 nodes, ❌ broken on EU-6 |

## Block Chain (from EU-2, authoritative)

| Height | TX Hash (8B prefix) | Type | Time (UTC) | prev_hash (8B) | Certs |
|--------|-------------------|------|------------|----------------|-------|
| 1 | `EAF6D019` | GENESIS | 10:42:54 | `00000000` | 7/7 |
| 2 | `5A1ED7A1` | SPEND | 11:07:46 | `0BC33113` | 5/7 |
| 3 | `D8CE64D4` | SPEND | 11:20:21 | `029A72AE` | 5/7 |
| 4 | `7F22D128` | SPEND | 11:26:44 | `14DE523B` | 5/7 |

- Block 1: 7/7 unanimous (genesis requires N/N)
- Blocks 2-4: 5/7 quorum (PBFT 2f+1, f=2)
- All blocks hash-linked via SHA3-512 prev_hash

## Wallet Balances

| Identity | Name | Balance (tokens) | UTXOs |
|----------|------|-----------------|-------|
| `3f4443..43a0` | punk | 992,006.99899002 | 1 |
| `324453..a807` | chip | 5,001.00001 | 3 |
| — | burned | 2,992.00099998 | — |

## Transaction History

| Block | From | To | Amount (tokens) | Fee (tokens) |
|-------|------|----|----------------|-------------|
| 1 | genesis | punk | 1,000,000 | 0 |
| 2 | punk | chip | 0.00001 (1000 raw) | 0.00000001 |
| 3 | punk | chip | 5,000 | 5 |
| 4 | punk | chip | 1 | 0.001 |

## Cross-Witness Consistency

### Block hash agreement (7 nodes)

| Block | EU-6 | EU-5 | EU-4 | EU-3 | EU-2 | EU-1 | US-1 |
|-------|------|------|------|------|------|------|------|
| 1 | `EAF6` ✅ | `EAF6` ✅ | `EAF6` ✅ | `EAF6` ✅ | `EAF6` ✅ | `EAF6` ✅ | `EAF6` ✅ |
| 2 | `D8CE` ❌ | `5A1E` ✅ | `5A1E` ✅ | `5A1E` ✅ | `5A1E` ✅ | `5A1E` ✅ | `5A1E` ✅ |
| 3 | `7F22` ❌ | `D8CE` ✅ | `D8CE` ✅ | `D8CE` ✅ | `D8CE` ✅ | `D8CE` ✅ | `D8CE` ✅ |
| 4 | — ❌ | `7F22` ✅ | `7F22` ✅ | `7F22` ✅ | `7F22` ✅ | `7F22` ✅ | `7F22` ✅ |

**EU-6 diverged.** It missed block 2 (the first spend TX) during a cluster restart. Subsequent blocks were written at wrong heights with wrong prev_hashes.

### EU-6 Divergence Impact

| Metric | EU-6 (broken) | Other 6 nodes (correct) |
|--------|--------------|------------------------|
| Block count | 3 | 4 |
| UTXO count | 4 | 4 |
| UTXO total | 199,700,799,899,002 | 99,700,799,900,002 |
| Genesis UTXO spent? | ❌ NO (still unspent) | ✅ YES |
| Nullifiers | 2 | 3 |
| Supply invariant | ❌ BROKEN (2x genesis) | ✅ Holds |
| Double-spend risk | ⚠️ YES | No |

**Root cause:** No state sync mechanism. When a node misses a BFT round (due to restart, network issue, or slow mesh formation), it never receives the missed block. The missed nullifier is never recorded, leaving the original UTXO unspent. All subsequent blocks are written at shifted heights with different prev_hashes.

---

## What Was Built Today

### 1. Witness-Only Architecture (DHT Removed)
- Removed all DHT inbox write from `builder.c` and `genesis.c`
- Removed DHT inbox read from `wallet.c` (sync now queries witnesses)
- Removed dead code: `dnac_build_inbox_key()`, inbox listener, `derive_value_id()`
- Net: -254 lines of code. Simpler, more reliable, no "money disappears if DHT write fails" bug.

### 2. Block Hash Linking (prev_hash)
- Added `prev_hash BLOB` column to `blocks` table
- `prev_hash = SHA3-512(height || tx_hash || timestamp || prev_hash)` of previous block
- Genesis block: prev_hash = all zeros
- Block query API returns prev_hash to clients

### 3. Commit Certificates (2f+1 Signatures)
- New `commit_certificates` table: `(block_height, voter_id, vote, signature)`
- Leader stores all PRECOMMIT approve signatures after BFT commit
- **Certificate replication:** Leader includes precommit signatures in COMMIT broadcast message (new `cer` CBOR field). All witnesses decode and store locally.
- Every node independently holds cryptographic proof that consensus happened.

### 4. Witness Peer Mesh Auth Fix
- **Bug:** `require_peer_auth=true` broke witness TCP 4004 connections. `on_witness_connect` didn't send T2 hello. Auth gate blocked challenge/auth_ok responses.
- **Fix:** Send T2 hello on outbound connect. Handle challenge/auth_ok inside auth gate. Send `w_ident` immediately after auth completes (not deferred to peer_tick which skipped zero-id seed peers).

### 5. Genesis Attestation Fix
- **Bug:** Client required `DNAC_GENESIS_WITNESSES_REQUIRED=3` attestations but BFT mode returns 1 (leader represents full quorum).
- **Fix:** Require 1 attestation. Server-side enforces unanimous N/N.

### 6. CLI Integration
- DNAC commands integrated into `dna-connect-cli dna <command>` (separate session)
- `genesis-create`, `genesis-submit`, `balance`, `send`, `sync`, `history`, `witnesses`

---

## Known Issues

### CRITICAL: State Sync Missing (Roadmap #3)
**Proven by EU-6 divergence.** When a node misses a BFT round, it has no way to recover the missed block. This causes:
- Chain divergence (different block heights, wrong prev_hashes)
- Supply invariant violation (spent UTXOs reappear as unspent)
- Double-spend vulnerability (nullifier not recorded)
- No self-healing — the divergence is permanent until manual DB reset

### HIGH: Leader Election Instability After Restart (Roadmap #2)
Observed during testing: after full cluster restart, some nodes computed different leaders and forwarded spend requests in circles (A→B→A). Resolved after mesh stabilization (~60s). Root cause: `current_view` may differ across nodes during mesh formation. Not a permanent divergence but causes temporary TX timeouts.

### MEDIUM: EU-6 Has 3 Blocks, Others Have 4
EU-6 needs manual intervention: stop nodus, delete `witness_*.db`, restart, wait for state sync (which doesn't exist yet). Currently a manual `genesis` re-run would be needed — but genesis can only happen once. **This node is permanently diverged until state sync is implemented.**

---

## Roadmap Status

| # | Item | Status | Priority | Notes |
|---|------|--------|----------|-------|
| 1 | prev_hash block linking | ✅ DONE v0.12.0 | — | SHA3-512, verified on live chain |
| 2 | View change (leader failure) | ⚠️ Code exists, not battle-tested | HIGH | Leader election instability seen |
| 3 | **State sync** | ❌ NOT STARTED | **CRITICAL** | EU-6 proves this is mandatory |
| 4 | Mempool / TX batching | ❌ | MEDIUM | Still 1 TX = 1 block |
| 5 | Block time | ❌ | MEDIUM | Blocks only on TX arrival |
| 6 | **Partition recovery** | ❌ | **CRITICAL** | EU-6 = permanent divergence |
| 7 | Stake requirement | ❌ | LOW | Needs working ledger first |
| 8 | Witness incentives | ❌ | LOW | Fees burned, witnesses earn nothing |
| 9 | Slashing / eviction | ❌ | LOW | No misbehavior detection |
| 10 | CLI integration | ✅ DONE | — | `dna-connect-cli dna` |
| 11 | Flutter wallet UI | ❌ | MEDIUM | |
| 12 | Client chain sync | ✅ DONE v0.12.0 | — | Witness-only polling |
| 13 | Merkle state root | ❌ | MEDIUM | Needed for state proofs |
| 14 | Light client (SPV) | ❌ | LOW | Depends on #13 |
| 15 | Commit certificates | ✅ DONE v0.12.0 | — | 2f+1 sigs, replicated to all nodes |

### Next Priority: State Sync (#3)

Without state sync, any node that misses a single BFT round is permanently corrupted. The blockchain cannot tolerate node restarts, network blips, or slow mesh formation. This must be solved before any further feature work.

**Proposed approach:**
1. Node detects it missed blocks (local height < peer's height)
2. Requests missing blocks + committed TX data from peers
3. Replays missed commits locally (including nullifiers, UTXO updates)
4. Verifies prev_hash chain continuity
5. Verifies commit certificates for each missed block

---

## Cryptographic Primitives

| Algorithm | Usage | Security Level |
|-----------|-------|---------------|
| Dilithium5 (ML-DSA-87) | TX signing, witness attestation, BFT voting, commit certificates | NIST Category 5 (256-bit quantum) |
| SHA3-512 | TX hash, block prev_hash, nullifiers, UTXO keys | 256-bit collision resistance |
| SHA3-256 | Chain ID derivation | 128-bit collision resistance |

## Network

| Node | Location | IP | Roster Index | Chain OK? |
|------|----------|-----|-------------|-----------|
| EU-6 | Germany | 75.119.141.51 | 3 | ❌ Diverged |
| EU-5 | Germany | 164.68.116.180 | 5 | ✅ |
| EU-4 | Germany | 164.68.105.227 | 4 | ✅ |
| EU-3 | Germany | 156.67.25.251 | 1 | ✅ |
| EU-2 | Germany | 156.67.24.125 | 2 | ✅ |
| EU-1 | Germany | 161.97.85.25 | 6 | ✅ |
| US-1 | USA | 154.38.182.161 | 0 | ✅ |
