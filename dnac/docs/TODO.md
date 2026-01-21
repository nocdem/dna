# DNAC TODO

**Current Phase:** Phase 14 - Testing & Hardening
**Protocol Version:** v1 (Transparent amounts)
**Updated:** 2026-01-21

---

## Protocol Decision

**v1 (Current):** Transparent amounts - amounts are plaintext in transactions.
**v2 (Future):** ZK amounts - STARKs (PQ-safe).

Phase 4 (Range Proofs) is deferred until v2 implementation.

---

## Next Up: Phase 14 - Testing & Hardening

- [ ] Integration tests (send/receive flow)
- [ ] Multi-party tests (Alice → Bob → Charlie)
- [ ] Double-spend attempt tests
- [ ] Nodus failure/timeout tests
- [ ] Fuzz testing for parsing
- [ ] Wallet recovery tests

---

## Deferred: Phase 4 - PQ Zero-Knowledge (v2 only)

- [ ] Evaluate STARK libraries (winterfell, stone, ethSTARK)
- [ ] Design STARK-based range proofs
- [ ] Implement range proof generation
- [ ] Implement range proof verification
- [ ] Benchmark proof size (~50-200 KB, OK for chunked DHT)

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
