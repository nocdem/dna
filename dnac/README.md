# DNAC - Post-Quantum Zero-Knowledge Cash over DHT

**Version:** v0.13.0 | **Protocol:** v1 (Transparent Amounts)

DNAC is a privacy-preserving digital cash system built on top of [DNA Connect](https://github.com/nocdem/dna). It lives in the DNA monorepo at `/opt/dna/dnac/`.

## Features

- **UTXO Model** - Unspent Transaction Output model for privacy
- **Dilithium5 Signatures** - Post-quantum digital signatures (NIST Category 5)
- **Witness-Only Architecture** - All state stored on BFT witnesses, no DHT dependency (v0.12.0)
- **BFT Consensus** - Byzantine Fault Tolerant witness consensus (PBFT-like)
- **PBFT Witnessing** - Transactions require PBFT quorum (2f+1) witness attestations
- **Memo Support** - Optional transaction memos up to 255 bytes (v0.6.0)
- **Replay Prevention** - Nonce and timestamp-based replay attack prevention (v0.6.0)
- **Merkle Proofs** - Transaction inclusion proofs via Merkle tree (v0.7.0)
- **BFT-Signed Epochs** - Epoch roots signed by BFT consensus (v0.7.1)
- **Block Hash Linking** - Blocks chained via prev_hash (SHA3-512) for chain integrity (v0.12.0)
- **Commit Certificates** - 2f+1 PRECOMMIT signatures stored per block for trustless verification (v0.12.0)
- **Shared UTXO Set** - Validators maintain shared UTXO state, preventing counterfeiting (v0.8.0)
- **Cross-Identity Sends** - Full TX data through BFT consensus for multi-party transfers (v0.8.0)
- **Fee Burn Model** - Fees burned (removed from circulation) instead of sent to witnesses (v0.8.1)
- **Genesis System** - Unanimous witness authorization for token creation (v0.5.0)
- **Hub/Spoke TX Storage** - Witnesses store full serialized transactions during BFT commit (v0.10.0)
- **TX Query Protocol** - Clients retrieve full transaction data by hash from witnesses (v0.10.0)
- **Block Query Protocol** - Clients query blocks by height or range from witnesses (v0.10.0)
- **Multi-Token Support** - Custom token creation with per-token UTXO tracking (v0.13.0)
- **Token Creation** - TX_TOKEN_CREATE transaction type with 1 DNAC fee burn (v0.13.0)
- **Per-Token Balances** - Wallet tracks separate UTXO sets per token_id (v0.13.0)
- **Name Resolution** - CLI send accepts DNA name, auto-resolves to fingerprint (v0.13.0)

## Protocol Versions

| Version | Amounts | ZK Technology | Status |
|---------|---------|---------------|--------|
| **v1** | Transparent (plaintext) | None | **Current** |
| **v2** | Hidden | STARKs (PQ-safe) | Future |

v1 uses transparent amounts for simplicity. v2 will add STARK-based zero-knowledge proofs for amount privacy while maintaining post-quantum security.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        dnac-cli                             │
│              (standalone CLI application)                   │
└─────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
┌─────────────────────┐        ┌─────────────────────┐
│      libdna         │◀───────│      libdnac        │
│  (identity, crypto, │ links  │  (cash + tokens)    │
│   transport)        │        │                     │
└─────────────────────┘        └─────────────────────┘
                                         │
                                    TCP 4004
                                         ▼
                               ┌─────────────────────┐
                               │  WITNESS SERVERS    │
                               │ (dynamic roster)    │
                               │ (PBFT 2f+1 quorum)  │
                               │ (authoritative UTXO │
                               │  + block storage)   │
                               └─────────────────────┘
```

## Building

### Prerequisites

1. Build DNA Connect first (DNAC links against `libdna.so`):
```bash
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)
```

2. Install dependencies:
```bash
# Debian/Ubuntu
sudo apt install libssl-dev libsqlite3-dev pkg-config cmake
```

### Build DNAC

```bash
cd /opt/dna/dnac/build
cmake .. && make -j$(nproc)
```

This builds:
- `libdnac.a` - Static library
- `dnac-cli` - Command-line wallet

## CLI Commands

```bash
# Identity & Info
dnac-cli info                    # Show wallet info, address, DHT status, balance
dnac-cli address                 # Show wallet address (fingerprint only)
dnac-cli query <name|fp>         # Lookup identity by name or fingerprint

# Wallet
dnac-cli balance                 # Show wallet balance
dnac-cli utxos                   # List UTXOs
dnac-cli send <name|fp> <amount> [memo]  # Send payment (accepts DNA name or fingerprint)
dnac-cli genesis <fp> <amount>   # Create genesis TX (3-of-3 witness auth)
dnac-cli sync                    # Sync wallet from network
dnac-cli recover                 # Recover wallet from seed

# History
dnac-cli history [n]             # Transaction history (optional: last n)
dnac-cli tx <hash>               # Show transaction details

# Token Management
dnac-cli token-create <name> <symbol> <supply>  # Create new token (burns 1 DNAC fee)
dnac-cli token-list                              # List all known tokens
dnac-cli token-info <token_id|symbol>            # Show token details

# Token-Aware Operations
dnac-cli balance --token <token_id>              # Show balance for a specific token
dnac-cli send --token <token_id> <name|fp> <amount> [memo]  # Send token payment

# Network
dnac-cli nodus-list              # Show witness servers
```

## Hub/Spoke Query API (v0.10.0)

Clients trust witnesses and can query the full blockchain view via the hub/spoke model:

### Transaction Query
```c
// Retrieve full serialized TX by hash (caller frees tx_data)
int dnac_query_transaction(dnac_context_t *ctx,
                            const uint8_t *tx_hash,
                            uint8_t **tx_data_out,
                            uint32_t *tx_len_out,
                            uint8_t *tx_type_out,
                            uint64_t *block_height_out);
```

### Block Query
```c
// Query single block by height
int dnac_query_block(dnac_context_t *ctx,
                      uint64_t height,
                      uint8_t *tx_hash_out,
                      uint8_t *tx_type_out,
                      uint64_t *timestamp_out,
                      uint8_t *proposer_out);

// Query block range (max 100 per request)
int dnac_query_block_range(dnac_context_t *ctx,
                            uint64_t from_height,
                            uint64_t to_height,
                            int *count_out,
                            uint64_t *total_out);
```

### Wire Protocol (CBOR over Nodus Tier 2)

| Message Type | ID | Direction | Description |
|---|---|---|---|
| `DNAC_NODUS_MSG_TX_QUERY` | 144 | Client→Witness | Query TX by hash |
| `DNAC_NODUS_MSG_TX_RESPONSE` | 145 | Witness→Client | Full TX data blob |
| `DNAC_NODUS_MSG_BLOCK_QUERY` | 146 | Client→Witness | Query block by height |
| `DNAC_NODUS_MSG_BLOCK_RESPONSE` | 147 | Witness→Client | Block fields |
| `DNAC_NODUS_MSG_BLOCK_RANGE_QUERY` | 148 | Client→Witness | Query block range |
| `DNAC_NODUS_MSG_BLOCK_RANGE_RESPONSE` | 149 | Witness→Client | Array of blocks |

### Witness-Side Storage

Witnesses store full serialized `tx_data` in the `committed_transactions` table during BFT commit. Schema:
```sql
CREATE TABLE committed_transactions (
    tx_hash BLOB PRIMARY KEY,
    tx_type INTEGER NOT NULL,
    tx_data BLOB NOT NULL,
    tx_len  INTEGER NOT NULL,
    block_height INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX idx_ctx_height ON committed_transactions(block_height);
```

### Wallet Address

The wallet address is a **SHA3-512 hash of the Dilithium5 public key**:
- 64 bytes = 128 hexadecimal characters
- Same as DNA Connect identity fingerprint

## Transaction Format (v1)

```
DNAC TRANSACTION v1:
┌─────────────────────────────────────────────────────────────┐
│ HEADER                                                      │
│   version: u8 = 1                                           │
│   type: u8 = TX_SPEND | TX_TOKEN_CREATE                     │
│   timestamp: u64                                            │
│   tx_hash: bytes[64] (SHA3-512)                             │
├─────────────────────────────────────────────────────────────┤
│ INPUTS: nullifier[64] + amount + token_id[64]               │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS: recipient_fingerprint[64] + amount + token_id[64]  │
│   (token_id = zeros for native DNAC)                        │
├─────────────────────────────────────────────────────────────┤
│ BALANCE: sum(inputs) >= sum(outputs), difference = burned fee│
├─────────────────────────────────────────────────────────────┤
│ WITNESS ATTESTATIONS (2+ required): Dilithium5 signatures   │
├─────────────────────────────────────────────────────────────┤
│ SENDER AUTHORIZATION: Dilithium5 signature                  │
└─────────────────────────────────────────────────────────────┘
```

## Witness Infrastructure

DNAC uses a dynamic BFT witness roster for double-spend prevention. Witnesses are nodus-server nodes with witness capability, discovered at runtime:

### BFT Consensus Protocol

```
Client Request → Any Witness → Forward to Leader → Consensus Round → Response

PROPOSE → PREVOTE → PRECOMMIT → COMMIT
   │         │          │          │
   └─ Leader broadcasts proposal
             └─ All witnesses vote
                       └─ Quorum (2/3) reached
                                  └─ Nullifier committed, response sent
```

### Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| Witnesses | Dynamic | Discovered at runtime via announcements |
| Quorum | 2f+1 | PBFT quorum for N = 3f+1 witnesses |
| Leader Election | `(epoch + view) % N` | Rotates hourly |

### Features

- **Embedded in Nodus** - Witness logic runs inside nodus-server process
- **Nullifier Database** - SQLite-based persistent storage
- **Request Forwarding** - Non-leaders forward to current leader

### Witness-Only Storage (v0.12.0)

All blockchain state is stored on BFT witnesses. DHT inbox delivery was removed in v0.12.0 — witnesses are the authoritative source for all data:
- **UTXO set** — maintained by witnesses, clients poll via `dnac_sync_wallet()`
- **Blocks** — hash-linked chain with commit certificates
- **Nullifiers** — double-spend prevention
- **Transaction data** — full serialized TX for client queries

## Security

- **Post-Quantum Signatures**: Dilithium5 for all signatures (NIST Category 5)
- **Nullifiers**: SHA3-512 hash prevents UTXO tracking
- **Linkability Prevention**: Nullifiers prevent transaction graph analysis
- **Double-Spend Prevention**: PBFT quorum (2f+1) witness attestation required
- **UTXO Validation**: Witnesses verify UTXO legitimacy before voting (v0.8.0)
- **Fee Burn**: Transaction fees are permanently removed from circulation (v0.8.1)
- **UTXO Ownership Verification**: Sender fingerprint must match UTXO owner (v0.10.2)
- **Nullifier Fail-Closed**: DB errors assume nullifier exists to prevent double-spend (v0.10.2)
- **Chain ID Validation**: All BFT messages validated against zone chain_id to prevent cross-zone replay (v0.10.2)
- **Secure Nonce Generation**: RNG failure aborts instead of falling back to weak source (v0.10.2)
- **Overflow Protection**: Safe integer arithmetic for genesis supply and balance calculation (v0.10.2)
- **COMMIT Signature Verification**: All BFT COMMIT messages require valid Dilithium5 signature (v0.10.2)

## Status

**Development Phase** - v0.13.0. Not for production use.

### Implemented

- [x] Core wallet functionality (UTXO management, balance tracking)
- [x] Send/receive transactions via DHT
- [x] BFT consensus protocol (PBFT-like, embedded in Nodus)
- [x] Dynamic witness roster (discovered at runtime)
- [x] Leader election and request forwarding
- [x] Double-spend prevention via nullifiers
- [x] End-to-end integration tests
- [x] Multi-input double-spend fix (v0.4.0)
- [x] Genesis transaction with 3-of-3 unanimous authorization (v0.5.0)
- [x] BFT message signing with Dilithium5 (v0.6.0)
- [x] Integer overflow protection (v0.6.0)
- [x] Replay prevention via nonce/timestamp (v0.6.0)
- [x] Memo support up to 255 bytes (v0.6.0)
- [x] Merkle tree for transaction inclusion proofs (v0.7.0)
- [x] Chain synchronization infrastructure (v0.7.0)
- [x] Ledger confirmation tracking (v0.7.0)
- [x] BFT-anchored epoch roots (v0.7.1)
- [x] Shared UTXO set — validators verify UTXO legitimacy before consensus (v0.8.0)
- [x] Cross-identity sends with full TX data through BFT (v0.8.0)
- [x] Fee burn model — fees permanently removed from circulation (v0.8.1)
- [x] Genesis TX verification fix (v0.8.1)
- [x] Hub/spoke TX storage — witnesses persist full tx_data during BFT commit (v0.10.0)
- [x] TX query protocol — clients retrieve full transaction by hash (v0.10.0)
- [x] Block query protocol — clients query blocks by height or range (v0.10.0)
- [x] P0 Security audit fixes — 3 CRITICAL + 3 HIGH vulnerabilities resolved (v0.10.2)
- [x] Dead code cleanup — removed ~10K lines of old standalone witness code (v0.10.3)
- [x] BFT cleanup — removed client-side BFT code (serialize/roster/replay), dynamic witness discovery (v0.11.1)
- [x] Witness-only architecture — removed DHT inbox dependency, wallet syncs from witnesses (v0.12.0)
- [x] Block hash linking — prev_hash chain integrity via SHA3-512 (v0.12.0)
- [x] Commit certificates — 2f+1 PRECOMMIT signatures stored per block (v0.12.0)
- [x] Remote transaction history via witnesses (v0.12.1)
- [x] Multi-token UTXO tracking — per-token balances and UTXO sets (v0.13.0)
- [x] TX_TOKEN_CREATE — custom token creation with 1 DNAC fee burn (v0.13.0)
- [x] Token-aware TX builder — UTXO selection by token_id (v0.13.0)
- [x] CLI send by DNA name — auto-resolve to fingerprint (v0.13.0)

### Tested

- [x] GENESIS transaction flow (3-of-3 unanimous)
- [x] SEND transaction flow
- [x] Double-spend rejection
- [x] Multi-input double-spend rejection
- [x] Service auto-restart on reboot
- [x] Witness mesh reconnection
- [x] Security gap fixes (18 test cases in test_gaps.c)
- [x] Cross-machine send/receive (test_remote.c)
- [x] Cross-identity supply invariant (4 identities, 10000 supply = 9995.5 UTXOs + 4.5 burned)

### Deferred to v2

- [ ] STARK-based zero-knowledge proofs for amount privacy
- [ ] View change protocol (leader failure recovery)

## License

MIT

## Related Projects

- [DNA Connect](https://github.com/nocdem/dna) - Post-quantum encrypted messenger (monorepo: `/opt/dna/messenger/`)
- [Nodus](../nodus/) - Post-quantum Kademlia DHT with PBFT consensus (monorepo: `/opt/dna/nodus/`)
