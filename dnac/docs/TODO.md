> **⚠️ HISTORICAL — DO NOT USE FOR CURRENT STATE**
>
> This file is frozen at **v0.7.1 / 2026-01-22** and refers to the
> pre-blockchain DHT cash architecture. Many "shipped" items below
> have since been removed or replaced (DHT transport removed in v0.12.0,
> 2-of-3 nodus replaced by 2f+1 BFT, multi-tx blocks added in v0.14.0,
> Merkle state_root added in v0.11.0).
>
> **For the current open-gaps list, see [`STATUS.md`](STATUS.md).**
>
> Keep this file only for phase history.

---

# DNAC TODO (HISTORICAL — frozen at v0.7.1)

**Current Phase:** Phase 23 Complete - BFT-Anchored Proofs (v0.7.1)
**Protocol Version:** v1 (Transparent amounts)
**Updated:** 2026-01-22 (FROZEN — see STATUS.md for current state)

---

## Protocol Decision

**v1 (Current):** Transparent amounts - amounts are plaintext in transactions.
**ZK (STARKs, PQ-safe):** verify-only stack + range/balance AIR BUILT + audited
(Plonky3 C ports, parked/not-in-consensus); prover [MISSING]; confidential/hidden
amounts deferred to v4. See Phase 4 + `shared/crypto/zk/RESUME.md`.

Phase 4 (Range Proofs) — verification done, generation (prover) pending.

---

## Completed: Phase 14 - Testing & Hardening

- [x] Integration tests (send/receive flow) - `test_send_receive` EXISTS
- [ ] Multi-party tests (Alice → Bob → Charlie)
- [x] Double-spend attempt tests - `test_double_spend` EXISTS
- [x] Multi-input double-spend tests (v0.4.0)
- [~] Nodus failure/timeout tests - PARTIAL (graceful SKIP when unavailable)
- [ ] Fuzz testing for parsing
- [ ] Wallet recovery tests
- [x] Genesis mechanism - Implemented in v0.5.0 (unanimous 3-of-3 authorization)

### ⚠️ TEST WARNING: Synthetic Funds

Some unit tests inject fake UTXOs directly via `dnac_db_store_utxo()`:
- `test_utxo_store`: 1000 coins
- `test_utxo_select`: 1500 coins (5 UTXOs)
- `test_db_*`: 350 coins

**Note:** Genesis system (v0.5.0) provides production-realistic token creation.

---

## Phase 4 - PQ Zero-Knowledge (STARKs) — IN PROGRESS (verify-only; confidential = v4)
Authoritative status: `shared/crypto/zk/RESUME.md` (top block).

- [x] STARK library chosen: **Plonky3-grounded C ports** (pin `82cfad73`), not winterfell/stone/ethSTARK
- [x] Design + implement STARK **range proofs** (range_air 52-bit + sum_balance) — soundness-audited, 2 mints fixed
- [x] Implement range proof **verification** (full STARK verifier stack, `make test` GREEN 36 gates)
- [ ] Implement range proof **generation** — **prover [MISSING]** (~2–4 months)
- [ ] **B1 trace↔TX binding [OPEN]**, full FRI param pin, consensus integration (before-consensus MUST-FIX)
- [ ] Wallet auto-split for outputs > 2^52 (`dnac/BUGS.md` P3)
- [ ] **Confidential / hidden amounts (v4)** — Poseidon2 in-AIR commitment, deferred
- Proof size ~100 KB acceptable (chunked DHT)

---

## Completed

### Phase 1: Project Setup ✅
- [x] GitHub repo created
- [x] Directory structure
- [x] CMakeLists.txt with libdna
- [x] Headers defined
- [x] Builds and links

### Phase 2: Database Schema ✅
- [x] SQLite schema designed
- [x] Schema versioning/migration support
- [x] UTXO storage functions
- [x] Transaction storage functions
- [x] Pending spend functions
- [x] Debug UTXO lookup

### Phase 3: v1 Transparent Mode ✅
- [x] Protocol versioning (v1 transparent, v2 PQ ZK)
- [x] UTXO and transaction structures for v1
- [x] v1 balance verification (plaintext sum)
- [x] Clean slate for future PQ ZK (STARKs)

### Phase 5: Wallet Core ✅
- [x] Database header (db.h) with function declarations
- [x] Wallet initialization with DNA engine integration
- [x] Balance calculation from UTXOs
- [x] UTXO storage, retrieval, and marking spent
- [x] UTXO selection algorithm (smallest-first greedy)

### Phase 6: Transaction Building ✅
- [x] v1 wire format serialization/deserialization
- [x] Transaction builder with UTXO selection
- [x] Dilithium5 signing via DNA engine
- [x] Change output handling

### Phase 7: Nodus Client ✅
- [x] Define Nodus protocol (SpendRequest/SpendResponse)
- [x] Implement Nodus client (DHT-based)
- [x] Implement attestation request flow
- [x] Implement 2-of-3 signature collection
- [x] Handle timeouts and retries

### Phase 8: Send Flow ✅
- [x] Integrate: UTXO selection → TX build → attest → broadcast
- [x] Implement fee calculation
- [x] Implement pending spend tracking
- [x] Implement payment message creation (DHT-based)

### Phase 9: Receive Flow ✅
- [x] Implement payment inbox (DHT-based discovery)
- [x] Implement dnac_sync_wallet() to fetch payments
- [x] Extract UTXO data from transactions
- [x] Store received UTXOs in wallet database
- [x] Call payment callback on receive

### Phase 10: Transaction History ✅
- [x] Connect dnac_get_history() to database queries
- [x] Store received transactions in history during sync
- [x] CLI deferred to Phase 12

### Phase 11: Nodus Fee Implementation ✅
- [x] Add fingerprint field to dnac_nodus_info_t
- [x] Derive fingerprint from Nodus pubkey (SHA3-512)
- [x] Add fee output to transactions (addressed to Nodus)
- [x] Nodus can extract fee UTXO via their fingerprint
- [x] Updated balance verification (sum(in) == sum(out))

### Phase 12: dnac-cli ✅
- [x] Create standalone CLI executable
- [x] Implement `balance` command
- [x] Implement `utxos` command
- [x] Implement `send` command
- [x] Implement `sync` command
- [x] Implement `history` command
- [x] Implement `tx` command
- [x] Implement `nodus-list` command
- [x] Flutter integration deferred to release

### Phase 13: Wallet Recovery ✅
- [x] Implement DHT payment scan for recovery
- [x] Implement `dnac_wallet_recover()` function
- [x] CLI: `dnac-cli recover` (scan and restore from seed)
- [x] Note: Deterministic blinding derivation deferred to v2

### Phase 15: Epoch-Based DHT Keys ✅
- [x] Create `include/dnac/epoch.h` with epoch helper functions
- [x] Add epoch constants to `src/witness/config.h`
- [x] Define `dnac_witness_announcement_t` structure
- [x] Implement announcement serialization/deserialization
- [x] Implement `witness_publish_announcement()` server function
- [x] Implement epoch-based request key building
- [x] Server: Publish announcement on startup and epoch change
- [x] Server: Listen on current AND previous epoch keys (event-driven)
- [x] Client: Fetch announcement to discover current epoch
- [x] Client: Build epoch-based request keys

### Phase 16: CLI Query Commands (v0.1.28) ✅
- [x] `dnac-cli info` - Show wallet info, address, DHT status, balance
- [x] `dnac-cli address` - Output fingerprint only (for scripting)
- [x] `dnac-cli query <name|fp>` - Lookup identity by name or fingerprint
- [x] Auto-detect name vs fingerprint (128 hex = fingerprint)
- [x] Documentation: `docs/archive/CLI_COMMANDS.md` (archived 2026-04-24 — CLI now in `dna-connect-cli dna <verb>`)

### Phase 17: Permanent DHT Storage (v0.1.29) ✅
- [x] All DHT data stored permanently (cash doesn't expire)
- [x] Payments now permanent
- [x] Witness attestations permanent
- [x] Nullifier replication permanent
- [x] Removed unused TTL defines from config.h
- **Note:** Originally used `dht_put_signed_permanent()`. Now uses Nodus via `nodus_ops` API (OpenDHT removed).

### Phase 18: BFT Consensus (v0.2.0) ✅
- [x] PBFT-like consensus protocol
- [x] Leader election: `(epoch + view) % n_witnesses`
- [x] TCP mesh networking between witnesses
- [x] Systemd service deployment

### Phase 19: Multi-Input Double-Spend Fix (v0.4.0) ✅
- [x] Fixed multi-input double-spend vulnerability
- [x] Atomic nullifier validation in single BFT round

### Phase 20: Genesis System (v0.5.0) ✅
- [x] Genesis transaction type for initial token creation
- [x] Unanimous 3-of-3 witness authorization required
- [x] `genesis` CLI command (with `mint` kept as alias)

### Phase 21: Security Gap Fixes (v0.6.0) ✅
- [x] Gaps 1-6: BFT message signing with real Dilithium5
- [x] Gaps 8-9: Integer overflow protection
- [x] Gap 12: Public key validation
- [x] Gaps 23-24: Replay prevention (nonce/timestamp)
- [x] Gap 25: Memo support (up to 255 bytes)
- [x] 18 unit tests in `tests/test_gaps.c`

### Phase 22: P0 Infrastructure (v0.7.0) ✅
- [x] Chain synchronization infrastructure
- [x] Merkle tree for transaction inclusion proofs
- [x] Ledger confirmation tracking

### Phase 23: BFT-Anchored Proofs (v0.7.1) ✅
- [x] Epoch roots signed by BFT consensus
- [x] Merkle proofs anchored to BFT-signed state
- [x] Trust verification for transaction inclusion

---

## Implementation Notes

### v1 Transaction Verification
- Balance: sum(input_amounts) == sum(output_amounts)
- Witnesses: 2+ Dilithium5 attestations required
- Sender: Dilithium5 signature on tx_hash

### v2 PQ ZK (Future)
- STARKs for range proofs (hash-based, PQ-safe)
- Proof size ~50-200 KB (acceptable with chunked DHT)
- No trusted setup required
