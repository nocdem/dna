# DNAC (DNA Cash) - Comprehensive Audit Documentation

**Version:** 0.10.3
**Audit Date:** 2026-03-01 | **P0 Fixes Applied:** 2026-03-02 | **Dead Code Cleanup:** 2026-03-02
**Audit Depth:** Exhaustive (all source files verified)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Structure](#2-project-structure)
3. [Public API](#3-public-api)
4. [UTXO System](#4-utxo-system)
5. [Transaction System](#5-transaction-system)
6. [BFT Consensus](#6-bft-consensus)
7. [Witness System](#7-witness-system)
8. [Build System](#8-build-system)
9. [Tests](#9-tests)
10. [CLI Tool](#10-cli-tool)
11. [Integration with Messenger](#11-integration-with-messenger)
12. [Integration with Nodus DHT](#12-integration-with-nodus-dht)
13. [Cryptography Usage](#13-cryptography-usage)
14. [Known Issues & Status](#14-known-issues--status)

---

## 1. Executive Summary

DNAC (DNA Cash) is a UTXO-based digital cash system with BFT witness consensus, built on post-quantum cryptography and the Nodus v5 DHT for transport.

| Metric | Value |
|--------|-------|
| Total source lines | ~6,900 (after v0.10.3 cleanup) |
| Public headers | 6 files |
| Test files | 3 (test_real, test_gaps, test_remote) |
| Test cases | 17 unit + 6 integration + cross-machine |
| Version | 0.10.3 |
| Build system | CMake 3.16+ |

---

## 2. Project Structure

```
/opt/dna/dnac/
├── CMakeLists.txt              Build system
├── README.md                   Main documentation
├── include/dnac/               Public headers (6 files)
│   ├── dnac.h                  Main public API
│   ├── version.h               Version 0.10.3
│   ├── bft.h                   BFT types, serialization, roster
│   ├── nodus.h                 Nodus client + witness announcements
│   ├── wallet.h                Wallet internals
│   └── transaction.h           Transaction types
├── src/
│   ├── bft/                    BFT support (3 files)
│   │   ├── serialize.c         Message serialization
│   │   ├── roster.c            Witness roster + config/leader election
│   │   └── replay.c            Nonce-based replay prevention
│   ├── transaction/            Transaction handling (6 files)
│   │   ├── genesis.c           Genesis TX
│   │   ├── builder.c           TX builder
│   │   ├── serialize.c         Binary serialization
│   │   ├── verify.c            TX verification
│   │   ├── nullifier.c         Nullifier derivation
│   │   └── transaction.c       Core TX functions
│   ├── wallet/                 Wallet management (4 files)
│   │   ├── wallet.c            Core wallet operations
│   │   ├── utxo.c              UTXO storage
│   │   ├── balance.c           Balance calculation
│   │   └── selection.c         Coin selection
│   ├── nodus/                  Nodus/DHT client (4 files)
│   │   ├── attestation.c       Witness request handling
│   │   ├── client.c            Witness client (Nodus SDK)
│   │   ├── discovery.c         Witness discovery
│   │   └── tcp_client.c        Direct TCP client
│   ├── db/                     Database (1 file)
│   │   └── db.c                SQLite schema, queries
│   └── cli/                    CLI tool (2 files)
│       ├── main.c              Argument parsing
│       └── commands.c          Command implementations
├── tests/
│   ├── test_real.c             End-to-end integration
│   ├── test_gaps.c             17 security gap tests
│   └── test_remote.c           Cross-machine testing
├── docs/                       Documentation
└── plans/                      BFT design docs
```

### Module Breakdown (Lines of Code)

| Module | Files | Lines | Purpose |
|--------|-------|-------|---------|
| Transaction | 6 | ~2,073 | Building, signing, verification |
| Nodus/DHT Client | 4 | ~1,978 | Witness discovery, requests |
| Wallet | 4 | ~1,454 | UTXO management, balance |
| BFT Support | 3 | ~2,000 | Serialization, roster, replay |
| Database | 1 | ~898 | SQLite schema, queries |
| CLI | 2 | ~898 | Command-line tool |
| **Total** | **~20** | **~6,900** | |

**v0.10.3 cleanup removed ~10K lines:** Old standalone witness server (src/witness/), TCP mesh (bft/tcp.c), peer management (bft/peer.c), consensus state machine (bft/consensus.c), and associated headers (witness.h, tcp.h, zone.h). Witness functionality now lives in Nodus v5 (`nodus/src/witness/`).

---

## 3. Public API

### dnac.h - Main Interface

#### Initialization

```c
dnac_context_t* dnac_init(void *dna_engine);
void dnac_shutdown(dnac_context_t *ctx);
```

#### Error Codes (24 total)

```c
DNAC_SUCCESS            (0)
DNAC_ERROR_INVALID_PARAM    (-1)
DNAC_ERROR_INSUFFICIENT_FUNDS (-2)
DNAC_ERROR_DOUBLE_SPEND     (-3)
DNAC_ERROR_WITNESS_FAILED   (-4)
DNAC_ERROR_GENESIS_EXISTS   (-5)
DNAC_ERROR_NO_GENESIS       (-6)
// ... through DNAC_ERROR_* (-22)
```

#### Data Structures

**dnac_utxo_t:**
```c
struct dnac_utxo {
    uint8_t version;
    uint8_t tx_hash[64];               // Creating TX hash
    uint32_t output_index;
    uint64_t amount;                   // Transparent (v1)
    uint8_t nullifier[64];            // SHA3-512(owner_fp || seed)
    char owner_fingerprint[129];
    dnac_utxo_status_t status;        // UNSPENT, PENDING, SPENT
    uint64_t received_at, spent_at;
};
```

**dnac_transaction_t:**
```c
struct dnac_transaction {
    uint8_t version;                   // = 1
    dnac_tx_type_t type;              // GENESIS, SPEND, BURN
    uint64_t timestamp;
    struct { uint8_t nullifier[64]; uint64_t amount; } inputs[16];
    struct {
        uint8_t version;
        char owner_fingerprint[129];
        uint64_t amount;
        uint8_t nullifier_seed[32];
        char memo[256]; uint8_t memo_len;
    } outputs[16];
    struct {
        uint8_t witness_id[32];
        uint8_t signature[4627];
        uint8_t pubkey[2592];
        uint64_t timestamp;
    } witnesses[3];                    // 2-of-3 quorum (3-of-3 for genesis)
    uint8_t sender_pubkey[2592];
    uint8_t sender_signature[4627];
};
```

**dnac_balance_t:**
```c
struct dnac_balance {
    uint64_t confirmed;
    uint64_t pending;
    uint64_t locked;
    uint32_t utxo_count;
};
```

#### Public Functions (50+)

| Category | Functions |
|----------|-----------|
| Lifecycle | dnac_init, dnac_shutdown, dnac_set_payment_callback |
| Wallet | dnac_get_balance, dnac_get_utxos, dnac_sync_wallet, dnac_start_listening, dnac_stop_listening, dnac_wallet_recover |
| Send | dnac_send, dnac_estimate_fee, dnac_tx_builder_create, dnac_tx_builder_add_output, dnac_tx_builder_build, dnac_tx_broadcast, dnac_tx_builder_free |
| History | dnac_get_history, dnac_get_confirmation, dnac_free_history |
| Witnesses | dnac_get_witness_list, dnac_check_nullifier, dnac_free_witness_list |
| Utilities | dnac_error_string, dnac_free_transaction |

---

## 4. UTXO System

### UTXO Status States

```
DNAC_UTXO_UNSPENT (0) — Available for spending
DNAC_UTXO_PENDING (1) — Spend in progress, awaiting attestations
DNAC_UTXO_SPENT   (2) — Already spent
```

### Coin Selection Algorithm (`selection.c`, 110 lines)

**Strategy:** Smallest-first greedy selection
1. Get all unspent UTXOs
2. Sort by amount (smallest first)
3. Select until target_amount is reached
4. Calculate change = accumulated - target_amount

Privacy benefit: Minimizes change output.

### Nullifier System (`nullifier.c`, 52 lines)

```
Nullifier = SHA3-512(owner_fingerprint || nullifier_seed)
```

- Each output includes random nullifier_seed[32]
- Deterministic: same owner + seed = same nullifier
- Witnesses track nullifiers for double-spend prevention

### Balance Calculation

- Confirmed: Sum of UNSPENT UTXOs
- Pending: Sum of PENDING UTXOs
- Locked: UTXOs in active spend transactions
- Invariant: sum(all UTXOs) = genesis_supply - burned_fees

---

## 5. Transaction System

### Transaction Types

```c
DNAC_TX_GENESIS = 0  // One-time token creation (3-of-3 witness)
DNAC_TX_SPEND   = 1  // Standard spend (2-of-3 witness)
DNAC_TX_BURN    = 2  // Destroy coins
```

### Transaction Format (v1 Transparent)

- Max 16 inputs per transaction
- Max 16 outputs per transaction
- Memo up to 255 bytes per output (v0.6.0+)
- TX hash: SHA3-512 of serialized body

### Core Functions

| Function | Purpose |
|----------|---------|
| `dnac_tx_create()` | Create new transaction |
| `dnac_tx_add_input()` | Add UTXO being spent |
| `dnac_tx_add_output()` | Add payment output |
| `dnac_tx_add_output_with_memo()` | Add output with memo (v0.6.0) |
| `dnac_tx_finalize()` | Sign & compute hash |
| `dnac_tx_add_witness()` | Add witness signature |
| `dnac_tx_verify()` | Validate structure, signatures, quorum |
| `dnac_tx_serialize()` | Convert to bytes |
| `dnac_tx_deserialize()` | Parse from bytes |

### TX Builder (`builder.c`, 421 lines)

```c
dnac_tx_builder_t *dnac_tx_builder_create(ctx);
int dnac_tx_builder_add_output(builder, recipient, amount);
int dnac_tx_builder_build(builder, tx_out);  // Coin selection + sign
void dnac_tx_builder_free(builder);
```

### Verification (`verify.c`, 145 lines)

- Validates input/output counts
- Checks sum(inputs) == sum(outputs) (no inflation)
- Verifies sender Dilithium5 signature
- Counts witness signatures (>=2 for SPEND, =3 for GENESIS)

---

## 6. BFT Consensus

### Protocol: PBFT-like (embedded in Nodus v5)

**Participants:** 3 witness servers (running inside nodus-server)
**Quorum:** 2-of-3 (SPEND), 3-of-3 (GENESIS)
**Byzantine tolerance:** f=1
**Leader:** (epoch + view) % N

### 4-Phase Flow

```
Client Request -> Leader -> PROPOSE -> PREVOTE -> PRECOMMIT -> COMMIT
```

### Message Types (11)

| Type | Purpose |
|------|---------|
| BFT_MSG_PROPOSAL (1) | Leader proposes nullifiers + TX data |
| BFT_MSG_PREVOTE (2) | Witness votes on proposal |
| BFT_MSG_PRECOMMIT (3) | Vote after prevote quorum |
| BFT_MSG_COMMIT (4) | Final commit |
| BFT_MSG_VIEW_CHANGE (5) | Request view change |
| BFT_MSG_NEW_VIEW (6) | New leader announces |
| BFT_MSG_FORWARD_REQ (7) | Non-leader forwards to leader |
| BFT_MSG_FORWARD_RSP (8) | Leader response via forwarder |
| BFT_MSG_ROSTER_REQUEST (9) | Request witness list |
| BFT_MSG_ROSTER_RESPONSE (10) | Roster response |
| BFT_MSG_IDENTIFY (11) | Identity exchange |

### Key Features

- Multi-input atomic: All nullifiers in one round (v0.4.0)
- Genesis unanimous: 3-of-3 required (v0.5.0)
- Full TX in PROPOSE, replayed in COMMIT (v0.8.0)
- Deterministic timestamps from PROPOSE (v0.9.0)
- Replay prevention: Nonce + timestamp (v0.6.0)
- Zone isolation: chain_id field (v0.10.0)

---

## 7. Witness System

### Architecture (embedded in Nodus v5 since v0.10.0)

Witness logic now lives in `nodus/src/witness/` and runs inside the nodus-server process:

| Component | Location | Purpose |
|-----------|----------|---------|
| nodus_witness.c | nodus/src/witness/ | Witness server main, message dispatch |
| nodus_witness_bft.c | nodus/src/witness/ | BFT consensus (PROPOSE/PREVOTE/PRECOMMIT/COMMIT) |
| nodus_witness_db.c | nodus/src/witness/ | Nullifier DB, UTXO set, block storage |
| nodus_witness_verify.c | nodus/src/witness/ | TX verification, UTXO ownership |
| nodus_witness_handlers.c | nodus/src/witness/ | Hub/spoke query handlers |

The old standalone `dnac/src/witness/` directory was removed in v0.10.3 (~5,600 lines of dead code).

### Block Structure (v0.9.0)

```c
struct dnac_block {
    uint64_t block_height;          // 0, 1, 2, ...
    uint8_t prev_block_hash[64];   // SHA3-512 of prev
    uint8_t state_root[64];        // UTXO set root
    uint8_t tx_hash[64];           // Transaction
    uint16_t tx_count;             // 1 (batching later)
    uint64_t epoch;
    uint64_t timestamp;            // From PROPOSE
    uint8_t proposer_id[32];
    uint8_t block_hash[64];        // Computed hash
};
```

### Witness Announcement (DHT Discovery)

```c
struct dnac_witness_announcement {
    uint8_t version;                    // = 2
    uint8_t witness_id[32];
    uint64_t current_epoch, epoch_duration;
    uint64_t timestamp;
    uint8_t software_version[3];
    uint8_t witness_pubkey[2592];      // Dilithium5
    uint8_t signature[4627];
};  // Serialized: 7,279 bytes
```

### Epoch System

- Duration: 60 seconds (DNAC_EPOCH_DURATION_SEC)
- Leader rotation: Hourly
- Data bucketed by epoch for DHT storage

---

## 8. Build System

### CMakeLists.txt

**Dependencies:**
- libdna_lib.a/so (DNA Messenger) - REQUIRED
- OpenSSL (libssl, libcrypto)
- SQLite3
- POSIX pthreads, libm

**Targets:**
- libdnac.a (static, default) / libdnac.so (optional)
- dnac-cli (executable)
- test_real, test_gaps, test_remote (test executables)

**Build Order (Critical):**
```bash
cd messenger/build && cmake .. && make -j$(nproc)   # Must build first
cd dnac/build && cmake .. && make -j$(nproc)        # Links against libdna_lib
```

**Compiler Flags:**
- Debug: `-g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer`
- Release: Default optimizations

---

## 9. Tests

### test_real.c (427 lines) - End-to-End Integration

Flow: MINT -> Verify -> SEND -> Verify -> Double-Spend Check -> Receive

Requires: 2+ real witness servers, network connectivity

### test_gaps.c (750 lines) - 18 Security Gap Tests

| Gaps | Coverage |
|------|----------|
| 1-6 | BFT message signing (real Dilithium5) |
| 8-9 | Integer overflow protection |
| 12 | Public key validation |
| 23-24 | Replay prevention (nonce/timestamp) |
| 25 | Memo support (255 bytes) |

### test_remote.c (1,000+ lines) - Cross-Machine Testing

Send/receive across different machines via DHT.

---

## 10. CLI Tool

### Commands (`dnac-cli`)

| Command | Purpose |
|---------|---------|
| `info` | Wallet info, address, DHT status, balance |
| `address` | Fingerprint only (for scripting) |
| `query <name\|fp>` | Lookup identity |
| `balance` | Confirmed/pending/locked balance |
| `utxos` | List all UTXOs |
| `send <fp> <amount>` | Send payment |
| `genesis <fp> <amount>` | Create genesis transaction |
| `mint <fp> <amount>` | Alias for genesis |
| `sync` | Sync wallet from DHT |
| `recover` | Recover wallet from seed phrase |
| `history [limit]` | Transaction history |
| `tx <hash>` | Transaction details |
| `nodus-list` | Available witness servers |

---

## 11. Integration with Messenger

### Dependency Chain

```
dnac-cli / libdnac.a
     |
DNA Engine (dna_engine_t)
     |
Nodus DHT Client (nodus_ops)
     |
Nodus v5 Server Cluster
```

### Functions Used from DNA Engine

1. **Identity:** dna_engine_create, dna_engine_has_identity, dna_engine_load_identity, dna_engine_get_fingerprint
2. **Crypto:** dna_engine_get_signing_public_key, dna_engine_sign_data
3. **DHT:** nodus_ops_put, nodus_ops_get, nodus_ops_listen, nodus_ops_is_ready

---

## 12. Integration with Nodus DHT

### DHT Keys (Epoch-Based)

| Data | DHT Key Pattern |
|------|----------------|
| Payments | `dnac:inbox:<epoch>:<recipient_fp>` |
| Witness announcements | `dnac:witnesses:<epoch>` |
| Nullifiers | `dnac:nullifiers:<epoch>` |
| Ledger | `dnac:ledger:<epoch>` |

### Witness Discovery Flow

1. Query `dnac:witnesses:<current_epoch>` on DHT
2. Collect witness announcements
3. Extract address, pubkey, fingerprint
4. TCP connect to witnesses

---

## 13. Cryptography Usage

| Algorithm | Purpose | Sizes |
|-----------|---------|-------|
| Dilithium5 (ML-DSA-87) | TX signing, witness consensus | pk=2592B, sk=4896B, sig=4627B |
| SHA3-512 | Nullifiers, TX hash, block hash, Merkle | 64 bytes |
| BIP39 | Seed phrase recovery | 12-24 words |

### Signature Budget Per Transaction

- Sender signature: 4,627 bytes
- 3 witness signatures: 3 x (4,627 + 2,592 + 8) = 21,681 bytes
- Total TX with 3 inputs, 2 outputs, 3 witnesses: ~14 KB

---

## 14. Known Issues & Status

### Phase Completion

- Phases 1-24: Complete (v0.10.2)
- Dead code cleanup: Complete (v0.10.3) — removed ~10K lines of old standalone witness code
- Phase 4 (PQ Zero-Knowledge): Deferred to v2

### Deferred Features

- View change protocol (leader failure recovery)
- Dynamic witness roster management
- STARK-based zero-knowledge proofs
- Fuzz testing for parsing
- Multi-party tests (Alice -> Bob -> Charlie)

### Completed Security Gaps (v0.6.0)

All 18 security gaps resolved and tested:
- BFT message signing with real Dilithium5
- Integer overflow protection
- Public key validation
- Replay prevention (nonce/timestamp)
- Memo support

### P0 Security Audit Fixes (v0.10.2)

6 critical/high vulnerabilities resolved:
- UTXO ownership verification — sender fingerprint vs UTXO owner (CRITICAL-4)
- Nullifier fail-closed — DB errors return true/spent (HIGH-10)
- Chain ID validation — 10 BFT handlers check chain_id (CRITICAL-2)
- Secure nonce generation — abort() on RNG failure (CRITICAL-3)
- Overflow protection — safe_add_u64 for genesis supply and balance (HIGH-3, HIGH-8)
- COMMIT signature verification — Dilithium5 sig check on COMMIT messages (CRITICAL-1)

See `docs/SECURITY_AUDIT_2026-03-02.md` for full audit report and fix details.

### Quality Assessment

| Aspect | Rating | Evidence |
|--------|--------|---------|
| Architecture | EXCELLENT | Modular: wallet, TX, consensus, witness |
| Security | STRONG | 18 gap tests + 6 P0 audit fixes, real crypto operations |
| Atomicity | VERIFIED | Database transactions for multi-nullifier |
| Determinism | VERIFIED | Identical results across witnesses |
| Testing | GOOD | Unit + integration + cross-machine |
