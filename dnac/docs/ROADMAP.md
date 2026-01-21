# DNAC Implementation Roadmap

**Project:** DNAC - Post-Quantum Digital Cash over DHT
**Version:** v0.1.22
**Status:** Phase 15 Complete (Epoch-Based DHT Keys)

---

## Overview

DNAC is a post-quantum digital cash system that integrates with DNA Messenger:
- **UTXO model** for transactions
- **DHT** for transport (payments as messages)
- **Nodus servers** for nullifier witnessing (2-of-3 consensus)
- **Fee model** where Nodus servers earn commission
- **Dilithium5** (Post-Quantum) signatures for authorization

### Protocol Versions

| Version | Status | Amounts | ZK System |
|---------|--------|---------|-----------|
| **v1** | Active | Transparent | None |
| **v2** | Future | Hidden | PQ ZK (STARKs) |

**Current Implementation: Protocol v1 (Transparent)**
- Amounts are plaintext in transactions
- Verification: sum(inputs) == sum(outputs)
- v2 will add PQ ZK (STARKs) when mature

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
- [x] Clean slate for future PQ ZK integration

**Note:** v2 will use PQ ZK (STARKs) for hidden amounts.

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
- [x] Implement attestation request flow
- [x] Implement 2-of-3 signature collection
- [x] Handle timeouts and retries
- [ ] CLI: `dnac nodus-list` (deferred to Phase 12)

### Phase 8: Send Flow ✅ COMPLETE
- [x] Integrate: UTXO selection → TX build → attest → broadcast
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

### Phase 15: Epoch-Based DHT Keys ✅ COMPLETE
- [x] Create `include/dnac/epoch.h` with epoch helper functions
- [x] Add epoch constants to `src/witness/config.h`
- [x] Define `dnac_witness_announcement_t` structure
- [x] Implement announcement serialization/deserialization
- [x] Implement `witness_publish_announcement()` server function
- [x] Implement epoch-based request key building
- [x] Server: Publish announcement on startup and epoch change
- [x] Server: Listen on current AND previous epoch keys
- [x] Client: Fetch announcement to discover current epoch
- [x] Client: Build epoch-based request keys

**Purpose:** Prevent unbounded DHT key accumulation by rotating request keys hourly.

**Key Files:**
| File | Change |
|------|--------|
| `include/dnac/epoch.h` | NEW - Epoch helpers |
| `include/dnac/witness.h` | Announcement struct/functions |
| `src/witness/config.h` | Epoch constants |
| `src/witness/server.c` | Announcement publishing, epoch listeners |
| `src/witness/main.c` | Epoch tracking, listener rotation |
| `src/nodus/client.c` | Fetch announcement, epoch keys |
| `src/nodus/attestation.c` | Announcement serialize/deserialize |

---

## Transaction Format (v1)

```
DNAC TRANSACTION (v1 Transparent):
┌─────────────────────────────────────────────────────────────┐
│ HEADER                                                      │
│   version: u8 = 1                                           │
│   type: u8 = TX_SPEND                                       │
│   timestamp: u64                                            │
│   tx_hash: bytes[64]                                        │
├─────────────────────────────────────────────────────────────┤
│ INPUTS                                                      │
│   nullifier: bytes[64]                                      │
│   amount: u64                   Plaintext amount            │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS (per output)                                        │
│   version: u8                                               │
│   owner_fingerprint: string     Recipient fingerprint       │
│   amount: u64                   Plaintext amount            │
│   nullifier_seed: bytes[32]     For recipient               │
├─────────────────────────────────────────────────────────────┤
│ WITNESS PROOF (2 required)                                  │
│   witness_id: bytes[32]                                     │
│   signature: bytes[4627]        Dilithium5                  │
│   server_pubkey: bytes[2592]    Dilithium5                  │
│   timestamp: u64                                            │
├─────────────────────────────────────────────────────────────┤
│ SENDER AUTHORIZATION                                        │
│   sender_pubkey: bytes[2592]    Dilithium5                  │
│   sender_signature: bytes[4627] Dilithium5                  │
└─────────────────────────────────────────────────────────────┘

Typical size: ~20-25 KB (mostly Dilithium5 signatures)
```

---

## Nodus 2-of-3 Protocol

```
1. Client fetches witness announcement from permanent DHT key
2. Client extracts current_epoch from announcement
3. Client sends SpendRequest to epoch-based DHT key for each witness
4. Each Nodus checks nullifier not in DB
5. If new: APPROVE + Dilithium sign + replicate to peers
6. If exists: REJECT (already spent)
7. Client collects 2+ signatures → WitnessProof
8. Transaction with WitnessProof is valid
9. Conflicts resolved by timestamp (first wins)
```

### DHT Key Structure

```
Announcement Key: SHA3-512("dnac:witness:announce:" + witness_fp)
  - Published by witness on startup and epoch change
  - Contains: current_epoch, witness_pubkey, signature

Request Key: SHA3-512("dnac:nodus:epoch:request:" + witness_fp + ":" + epoch)
  - Epoch = time(NULL) / 3600 (hourly rotation)
  - Client PUTs SpendRequest here
  - Witness listens on current AND previous epoch
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
    tx_hash             BLOB NOT NULL,
    output_index        INTEGER NOT NULL,
    amount              INTEGER NOT NULL,
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
    witnesses_needed    INTEGER NOT NULL DEFAULT 2,
    witnesses_received  INTEGER NOT NULL DEFAULT 0,
    witness_signatures  BLOB,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    status              INTEGER NOT NULL DEFAULT 0
);
```

---

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DNAC_NULLIFIER_SIZE` | 64 | SHA3-512 nullifier |
| `DNAC_TX_HASH_SIZE` | 64 | SHA3-512 transaction hash |
| `DNAC_SIGNATURE_SIZE` | 4627 | Dilithium5 signature |
| `DNAC_PUBKEY_SIZE` | 2592 | Dilithium5 public key |
| `DNAC_WITNESSES_REQUIRED` | 2 | Witnesses needed for valid TX |
| `DNAC_FEE_RATE_BPS` | 10 | Fee rate (0.1%) |
| `DNAC_EPOCH_DURATION_SEC` | 3600 | Epoch duration (1 hour) |
| `WITNESS_EPOCH_ANNOUNCE_TTL_SEC` | 3600 | Announcement TTL |
| `WITNESS_EPOCH_REQUEST_TTL_SEC` | 300 | Request TTL (5 min) |

---

## Dependencies

- **libdna** - DNA Messenger library (identity, DHT, crypto primitives)
- **OpenSSL** - SHA3, AES, SHAKE256
- **SQLite3** - Database
