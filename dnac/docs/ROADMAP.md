# DNAC Implementation Roadmap

**Project:** DNAC - Post-Quantum Zero-Knowledge Cash over DHT
**Version:** v0.1.0
**Status:** Phase 1 Complete

---

## Overview

DNAC is a post-quantum ZK cash system that integrates with DNA Messenger:
- **UTXO model** for transactions
- **Hybrid ZK** (classical Pedersen + Bulletproofs for commitments, PQ Dilithium for signatures)
- **DHT** for transport (payments as messages)
- **Nodus servers** for nullifier anchoring (2-of-3 consensus)
- **Fee model** where Nodus servers earn commission

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

### Phase 2: Database Schema (~70% done)
- [x] Design SQLite schema for:
  - `dnac_utxos` table
  - `dnac_transactions` table
  - `dnac_pending_spends` table
- [ ] Add schema versioning/migration support
- [ ] Implement transaction storage functions
- [ ] Implement pending spend functions
- [ ] Integrate database with dnac_context

### Phase 3: Pedersen Commitments
- [ ] Implement Pedersen commitment: `C = g^v · h^r`
- [ ] Implement commitment addition (homomorphic)
- [ ] Implement blinding factor arithmetic
- [ ] Unit tests for commitments

### Phase 4: Range Proofs (Bulletproofs)
- [ ] Evaluate libraries: secp256k1-zkp or implement
- [ ] Implement range proof generation
- [ ] Implement range proof verification
- [ ] Unit tests for range proofs
- [ ] Benchmark proof size (~700 bytes target)

### Phase 5: Wallet Core
- [ ] Implement UTXO structure and storage
- [ ] Implement balance calculation
- [ ] Implement UTXO selection algorithms
- [ ] Implement wallet sync from DB
- [ ] CLI: `dnac balance`
- [ ] CLI: `dnac utxos`

### Phase 6: Transaction Building
- [ ] Define transaction wire format
- [ ] Implement transaction builder
- [ ] Implement commitment creation for outputs
- [ ] Implement balance proof (inputs = outputs)
- [ ] Implement serialization/deserialization
- [ ] Unit tests for transactions

### Phase 7: Nodus Client
- [ ] Define Nodus protocol (SpendRequest/SpendResponse)
- [ ] Implement Nodus client (TCP or DHT-based)
- [ ] Implement anchor request flow
- [ ] Implement 2-of-3 signature collection
- [ ] Handle timeouts and retries
- [ ] CLI: `dnac nodus-list`

### Phase 8: Send Flow
- [ ] Integrate: UTXO selection → TX build → anchor → broadcast
- [ ] Implement fee calculation
- [ ] Implement pending spend tracking
- [ ] Implement payment message creation
- [ ] CLI: `dnac send <recipient> <amount> [memo]`
- [ ] End-to-end test with real Nodus

### Phase 9: Receive Flow
- [ ] Add MESSAGE_TYPE_PAYMENT to libdna
- [ ] Implement payment message handler
- [ ] Decrypt and extract UTXO data
- [ ] Store received UTXO in wallet
- [ ] Update balance on receive
- [ ] CLI: `dnac sync`

### Phase 10: Transaction History
- [ ] Implement transaction history storage
- [ ] Implement history queries
- [ ] CLI: `dnac history`
- [ ] CLI: `dnac tx <hash>` (details)

### Phase 11: Nodus Fee Implementation
- [ ] Add fee output to transactions
- [ ] Nodus extracts fee UTXO
- [ ] Fee goes to anchoring Nodus

### Phase 12: Flutter Integration
- [ ] Create FFI bindings (dnac_bindings.dart)
- [ ] Create DnacProvider
- [ ] Add wallet balance widget
- [ ] Add send payment screen
- [ ] Add payment message bubble in chat
- [ ] Add transaction history screen

### Phase 13: Testing & Hardening
- [ ] Integration tests (send/receive flow)
- [ ] Multi-party tests (Alice → Bob → Charlie)
- [ ] Double-spend attempt tests
- [ ] Nodus failure/timeout tests
- [ ] Fuzz testing for parsing

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

## Dependencies

- **libdna** - DNA Messenger library (identity, DHT, crypto primitives)
- **OpenSSL** - SHA3, AES
- **SQLite3** - Database
- **secp256k1-zkp** - Bulletproofs (optional, or implement from scratch)
