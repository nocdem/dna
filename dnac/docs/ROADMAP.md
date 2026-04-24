> **⚠️ HISTORICAL — DO NOT USE FOR CURRENT STATE**
>
> This roadmap is frozen at **v0.10.2** and reflects the pre-blockchain
> "DHT cash" architecture that no longer exists. The standalone DHT
> transport was removed in v0.12.0; DNAC is now a witness-only PQ
> blockchain on Nodus BFT.
>
> **For current component status, see [`STATUS.md`](STATUS.md).**
>
> Keep this file only for phase history (Phases 1–24).

---

# DNAC Implementation Roadmap (HISTORICAL — frozen at v0.10.2)

**Project:** DNAC - Post-Quantum Digital Cash over DHT
**Version:** v0.10.2 (FROZEN — current is v0.14.3, see STATUS.md)
**Status:** Phase 24 Complete (P0 Security Audit)

---

## Overview

DNAC is a post-quantum digital cash system that integrates with DNA Connect:
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

### Phase 16: CLI Query Commands ✅ COMPLETE (v0.1.28)
- [x] `dnac-cli info` - Show wallet info, address, DHT status, balance
- [x] `dnac-cli address` - Output fingerprint only (for scripting)
- [x] `dnac-cli query <name|fp>` - Lookup identity by name or fingerprint
- [x] Auto-detect name vs fingerprint (128 hex = fingerprint)
- [x] Documentation: `docs/archive/CLI_COMMANDS.md` (archived 2026-04-24 — CLI now in `dna-connect-cli dna <verb>`)

### Phase 17: Permanent DHT Storage ✅ COMPLETE (v0.1.29)
- [x] All DHT data stored permanently (cash doesn't expire)
- [x] Payments now permanent
- [x] Witness attestations permanent
- [x] Nullifier replication permanent
- [x] Removed unused TTL defines from config.h
- **Note:** Originally used `dht_put_signed_permanent()`. Now uses Nodus via `nodus_ops` API (OpenDHT removed).

### Phase 18: BFT Consensus ✅ COMPLETE (v0.2.0)
- [x] PBFT-like consensus protocol (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- [x] Leader election: `(epoch + view) % n_witnesses`
- [x] Quorum requirement: 2 for 3 witnesses
- [x] TCP mesh networking between witnesses
- [x] Request forwarding (non-leader → leader)
- [x] Systemd service deployment on 3 nodes

### Phase 19: Multi-Input Double-Spend Fix ✅ COMPLETE (v0.4.0)
- [x] Fixed vulnerability where multi-input transactions could double-spend
- [x] All input nullifiers now validated atomically in single BFT round
- [x] Added `test_double_spend` test case

### Phase 20: Genesis System ✅ COMPLETE (v0.5.0)
- [x] Genesis transaction type for initial token creation
- [x] Unanimous 3-of-3 witness authorization required
- [x] `genesis` CLI command (with `mint` kept as alias)
- [x] One-time bootstrap mechanism for token supply

### Phase 21: Security Gap Fixes ✅ COMPLETE (v0.6.0)
- [x] Gaps 1-6: BFT message signing with real Dilithium5
- [x] Gaps 8-9: Integer overflow protection
- [x] Gap 12: Public key validation
- [x] Gaps 23-24: Replay prevention (nonce/timestamp)
- [x] Gap 25: Memo support (up to 255 bytes)
- [x] 18 unit tests in `tests/test_gaps.c`

### Phase 22: P0 Infrastructure ✅ COMPLETE (v0.7.0)
- [x] Chain synchronization infrastructure
- [x] Merkle tree for transaction inclusion proofs
- [x] Ledger confirmation tracking
- [x] `test_remote.c` for cross-machine testing

### Phase 23: BFT-Anchored Proofs ✅ COMPLETE (v0.7.1)
- [x] Epoch roots signed by BFT consensus
- [x] Merkle proofs anchored to BFT-signed state
- [x] Trust verification for transaction inclusion

### Phase 24: P0 Security Audit ✅ COMPLETE (v0.10.2)
- [x] UTXO ownership verification — sender fingerprint checked against UTXO owner (CRITICAL-4)
- [x] Nullifier fail-closed — DB errors default to "spent" to prevent double-spend (HIGH-10)
- [x] Chain ID validation — all 10 BFT handlers validate chain_id (CRITICAL-2)
- [x] Secure nonce generation — abort() on RNG failure instead of weak fallback (CRITICAL-3)
- [x] Overflow protection — safe_add_u64 in genesis supply + balance calculation (HIGH-3, HIGH-8)
- [x] COMMIT signature verification — Dilithium5 sig required on all COMMIT messages (CRITICAL-1)
- [x] Test fixes — witness verify tests updated for ownership check

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

## CLI Commands (to be added to dna-connect-cli)

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

- **libdna** - DNA Connect library (identity, crypto primitives) - built at `messenger/build/`
- **Nodus** - DHT transport via `nodus_ops` API (OpenDHT has been completely removed)
- **OpenSSL** - SHA3, AES, SHAKE256
- **SQLite3** - Database
