# DNAC Implementation Roadmap

**Project:** DNAC - Post-Quantum Digital Cash over DHT
**Version:** v0.1.13
**Status:** Phase 13 Complete (Wallet Recovery)

---

## Overview

DNAC is a post-quantum digital cash system that integrates with DNA Messenger:
- **UTXO model** for transactions
- **DHT** for transport (payments as messages)
- **Nodus servers** for nullifier anchoring (2-of-3 consensus)
- **Fee model** where Nodus servers earn commission
- **Dilithium5** (Post-Quantum) signatures for authorization

### Protocol Versions

| Version | Status | Amounts | Commitments | Range Proofs |
|---------|--------|---------|-------------|--------------|
| **v1** | Active | Transparent | None | None |
| **v2** | Future | Hidden | Pedersen | Bulletproofs |

**Current Implementation: Protocol v1 (Transparent)**
- Amounts are plaintext in transactions
- Verification: sum(inputs) == sum(outputs) + fee
- Pedersen commitments implemented but not used
- v2 ZK can be added later without breaking v1

---

## Implementation Phases

### Phase 1: Project Setup ✅ COMPLETE
- [x] Create GitHub repo `nocdem/dnac`
- [x] Clone to `/opt/dnac/`
- [x] Create directory structure
- [x] Setup CMakeLists.txt with libdna dependency
- [x] Create CLAUDE.md with project guidelines
- [x] Create include/dnac/dnac.h with API stubs
- [x] Create include/dnac/version.h (v0.1.0)
- [x] Verify builds and links against libdna

### Phase 2: Database Schema ✅ COMPLETE
- [x] Design SQLite schema for:
  - `dnac_utxos` table
  - `dnac_transactions` table
  - `dnac_pending_spends` table
- [x] Add schema versioning/migration support
- [x] Implement transaction storage functions
- [x] Implement pending spend functions
- [x] Implement debug UTXO lookup by commitment

### Phase 3: v1 Transparent Mode ✅ COMPLETE
- [x] Define protocol versioning (v1 transparent, v2 PQ ZK)
- [x] Update UTXO and transaction structures for v1
- [x] Implement v1 balance verification (plaintext sum)
- [x] Remove classical ZK code (Pedersen) to maintain full PQ

**Note:** Pedersen commitments were implemented but removed to keep
the entire system post-quantum safe. v2 will use PQ ZK (STARKs).

### Phase 4: PQ Zero-Knowledge (STARKs) - DEFERRED TO v2
- [ ] Evaluate STARK libraries (winterfell, stone, ethSTARK)
- [ ] Design STARK-based range proofs for amounts
- [ ] Implement range proof generation
- [ ] Implement range proof verification
- [ ] Benchmark proof size (~50-200 KB expected)
- [ ] Evaluate proof aggregation for multi-output transactions

**v2 ZK Design (PQ-safe):**
- STARKs: Hash-based, no trusted setup, post-quantum secure
- Proof size (~100KB) acceptable - DHT uses chunked storage
- Alternative: Lattice-based ZK when mature

### Phase 5: Wallet Core ✅ COMPLETE
- [x] Create db.h header for database functions
- [x] Implement wallet init/shutdown with DNA engine
- [x] Implement balance calculation from UTXOs
- [x] Implement UTXO storage, retrieval, mark spent
- [x] Implement UTXO selection (smallest-first greedy)
- [ ] CLI: `dnac balance` (Phase 12)
- [ ] CLI: `dnac utxos` (Phase 12)

### Phase 6: Transaction Building ✅ COMPLETE
- [x] Define v1 wire format (transparent amounts)
- [x] Implement transaction serialization
- [x] Implement transaction deserialization
- [x] Implement transaction builder with UTXO selection
- [x] Implement Dilithium5 signing via DNA engine
- [ ] Unit tests for transactions (deferred)

### Phase 7: Nodus Client ✅ COMPLETE
- [x] Define Nodus protocol (SpendRequest/SpendResponse)
- [x] Implement Nodus client (DHT-based)
- [x] Implement anchor request flow
- [x] Implement 2-of-3 signature collection
- [x] Handle timeouts and retries
- [ ] CLI: `dnac nodus-list` (deferred to Phase 12)

### Phase 8: Send Flow ✅ COMPLETE
- [x] Integrate: UTXO selection → TX build → anchor → broadcast
- [x] Implement fee calculation
- [x] Implement pending spend tracking
- [x] Implement payment message creation (DHT-based)
- [ ] CLI: `dnac send <recipient> <amount> [memo]` (deferred to Phase 12)
- [ ] End-to-end test with real Nodus (deferred to Phase 14)

### Phase 9: Receive Flow ✅ COMPLETE
- [x] Implement payment inbox (DHT-based discovery)
- [x] Implement dnac_sync_wallet() to fetch payments
- [x] Extract UTXO data from transactions
- [x] Store received UTXOs in wallet database
- [x] Call payment callback on receive
- [ ] CLI: `dnac sync` (deferred to Phase 12)

### Phase 10: Transaction History ✅ COMPLETE
- [x] Connect dnac_get_history() to database queries
- [x] Connect dnac_debug_get_utxo() to database
- [x] Store received transactions in history during sync
- [ ] CLI: `dnac history` (deferred to Phase 12)
- [ ] CLI: `dnac tx <hash>` (deferred to Phase 12)

### Phase 11: Nodus Fee Implementation ✅ COMPLETE
- [x] Add fingerprint field to dnac_nodus_info_t
- [x] Derive fingerprint from Nodus pubkey (SHA3-512)
- [x] Add fee output to transactions (addressed to Nodus)
- [x] Nodus can extract fee UTXO via their fingerprint
- [x] Updated balance verification (sum(in) == sum(out))

### Phase 12: dnac-cli ✅ COMPLETE
- [x] Create standalone CLI executable (src/cli/)
- [x] Implement balance, utxos, send, sync commands
- [x] Implement history, tx, nodus-list commands
- [x] CMake integration with DNAC_BUILD_CLI option
- [x] Flutter integration deferred to release

### Phase 12b: Flutter Integration (RELEASE ONLY)
- [ ] Create FFI bindings (dnac_bindings.dart)
- [ ] Create DnacProvider
- [ ] Add wallet balance widget
- [ ] Add send payment screen
- [ ] Add payment message bubble in chat
- [ ] Add transaction history screen

### Phase 13: Wallet Recovery ✅ COMPLETE
- [x] Implement DHT payment scan for recovery
- [x] Implement `dnac_wallet_recover()` function
- [x] CLI: `dnac recover` (scan and restore from seed)
- [ ] Deterministic blinding derivation (deferred to v2)

### Phase 14: Testing & Hardening
- [ ] Integration tests (send/receive flow)
- [ ] Multi-party tests (Alice → Bob → Charlie)
- [ ] Double-spend attempt tests
- [ ] Nodus failure/timeout tests
- [ ] Fuzz testing for parsing
- [ ] Wallet recovery tests

---

## Transaction Format

```
DNAC TRANSACTION:
┌─────────────────────────────────────────────────────────────┐
│ HEADER                                                      │
│   version: u8 = 1                                           │
│   type: u8 = TX_SPEND                                       │
│   timestamp: u64                                            │
│   tx_hash: bytes[64]                                        │
├─────────────────────────────────────────────────────────────┤
│ INPUTS                                                      │
│   nullifier: bytes[64]                                      │
│   key_image: bytes[32]                                      │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS (per output)                                        │
│   commitment: bytes[33]         Pedersen commitment         │
│   owner_pubkey: bytes[32]       Encrypted to recipient      │
│   encrypted_data: bytes[~100]   Amount + blind + secret     │
│   range_proof: bytes[~700]      Bulletproof                 │
├─────────────────────────────────────────────────────────────┤
│ BALANCE PROOF                                               │
│   excess_commitment: bytes[33]                              │
│   excess_signature: bytes[64]                               │
├─────────────────────────────────────────────────────────────┤
│ ANCHOR PROOF (2 required)                                   │
│   nodus_id: bytes[32]                                       │
│   signature: bytes[~2400]       Dilithium                   │
├─────────────────────────────────────────────────────────────┤
│ SENDER AUTHORIZATION                                        │
│   sender_signature: bytes[~2400] Dilithium                  │
└─────────────────────────────────────────────────────────────┘

Typical size: ~8-10 KB (mostly Dilithium signatures)
```

---

## Nodus 2-of-3 Protocol

```
1. Client sends SpendRequest to ALL Nodus servers
2. Each Nodus checks nullifier not in DB
3. If new: APPROVE + Dilithium sign + replicate to peers
4. If exists: REJECT (already spent)
5. Client collects 2+ signatures → AnchorProof
6. Transaction with AnchorProof is valid
7. Conflicts resolved by timestamp (first wins)
```

---

## CLI Commands (to be added to dna-messenger-cli)

```bash
dnac balance                     # Show wallet balance
dnac utxos                       # List UTXOs
dnac send <fp|name> <amount> [memo]  # Send payment
dnac history                     # Transaction history
dnac sync                        # Sync wallet from network
dnac recover                     # Recover wallet from seed (DHT scan)
dnac nodus-list                  # Show Nodus servers
dnac debug utxo <commitment>     # Debug UTXO
dnac debug nullifier <null>      # Check if spent
```

---

## Database Schema

```sql
CREATE TABLE dnac_utxos (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    commitment          BLOB NOT NULL UNIQUE,
    tx_hash             BLOB NOT NULL,
    output_index        INTEGER NOT NULL,
    amount              INTEGER NOT NULL,
    blinding_factor     BLOB NOT NULL,
    spend_secret        BLOB NOT NULL,
    nullifier           BLOB NOT NULL UNIQUE,
    owner_fingerprint   TEXT NOT NULL,
    status              INTEGER NOT NULL DEFAULT 0,
    received_at         INTEGER NOT NULL,
    spent_at            INTEGER,
    spent_in_tx         BLOB
);

CREATE TABLE dnac_transactions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash             BLOB NOT NULL UNIQUE,
    raw_tx              BLOB NOT NULL,
    type                INTEGER NOT NULL,
    counterparty_fp     TEXT,
    created_at          INTEGER NOT NULL,
    confirmed_at        INTEGER,
    amount_in           INTEGER NOT NULL DEFAULT 0,
    amount_out          INTEGER NOT NULL DEFAULT 0,
    amount_fee          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE dnac_pending_spends (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash             BLOB NOT NULL,
    nullifier           BLOB NOT NULL,
    anchors_needed      INTEGER NOT NULL DEFAULT 2,
    anchors_received    INTEGER NOT NULL DEFAULT 0,
    anchor_signatures   BLOB,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    status              INTEGER NOT NULL DEFAULT 0
);
```

---

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DNAC_COMMITMENT_SIZE` | 33 | Pedersen commitment (compressed) |
| `DNAC_BLINDING_SIZE` | 32 | Blinding factor |
| `DNAC_NULLIFIER_SIZE` | 64 | SHA3-512 nullifier |
| `DNAC_SIGNATURE_SIZE` | 4627 | Dilithium5 signature |
| `DNAC_RANGE_PROOF_MAX_SIZE` | 800 | Bulletproof max size |
| `DNAC_ANCHORS_REQUIRED` | 2 | Anchors needed for valid TX |
| `DNAC_FEE_RATE_BPS` | 10 | Fee rate (0.1%) |

---

## Deterministic Blinding Design

Blinding factors are derived deterministically from the master seed, enabling wallet recovery without backups.

### Derivation

```
blinding = SHAKE256(
    master_seed ||           // 64 bytes from BIP39
    "dnac:blind:" ||         // domain separator
    tx_hash ||               // 64 bytes
    output_index             // 4 bytes, little-endian
)[0:32]                      // first 32 bytes
```

### Recovery Process

1. Restore identity from BIP39 mnemonic
2. Scan DHT for payments to your fingerprint
3. For each payment, re-derive blinding factor
4. Verify: `commitment == Pedersen(amount, derived_blinding)`
5. If match, restore UTXO to local wallet

### Benefits

- Always recoverable from seed phrase alone
- No DHT backup infrastructure needed
- Works even after extended offline periods

---

## Dependencies

- **libdna** - DNA Messenger library (identity, DHT, crypto primitives)
- **OpenSSL** - SHA3, AES, SHAKE256
- **SQLite3** - Database
- **secp256k1-zkp** - Bulletproofs (optional, or implement from scratch)
