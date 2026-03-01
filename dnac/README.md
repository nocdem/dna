# DNAC - Post-Quantum Zero-Knowledge Cash over DHT

**Version:** v0.8.1 | **Protocol:** v1 (Transparent Amounts)

DNAC is a privacy-preserving digital cash system built on top of [DNA Messenger](https://github.com/nocdem/dna-messenger). It lives in the DNA monorepo at `/opt/dna/dnac/`.

## Features

- **UTXO Model** - Unspent Transaction Output model for privacy
- **Dilithium5 Signatures** - Post-quantum digital signatures (NIST Category 5)
- **Nodus v5 DHT Transport** - Payments delivered via Nodus v5 DHT network (nodus_ops API)
- **Permanent Storage** - All data stored permanently on DHT
- **BFT Consensus** - Byzantine Fault Tolerant witness consensus (PBFT-like)
- **2-of-3 Witnessing** - Transactions require 2 witness attestations
- **TCP Mesh Network** - Witnesses communicate via TCP for consensus
- **Memo Support** - Optional transaction memos up to 255 bytes (v0.6.0)
- **Replay Prevention** - Nonce and timestamp-based replay attack prevention (v0.6.0)
- **Merkle Proofs** - Transaction inclusion proofs via Merkle tree (v0.7.0)
- **BFT-Signed Epochs** - Epoch roots signed by BFT consensus (v0.7.1)
- **Shared UTXO Set** - Validators maintain shared UTXO state, preventing counterfeiting (v0.8.0)
- **Cross-Identity Sends** - Full TX data through BFT consensus for multi-party transfers (v0.8.0)
- **Fee Burn Model** - Fees burned (removed from circulation) instead of sent to witnesses (v0.8.1)
- **Genesis System** - Unanimous 3-of-3 witness authorization for token creation (v0.5.0)

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
│  (identity, DHT,    │ links  │  (cash system)      │
│   crypto, transport)│        │                     │
└─────────────────────┘        └─────────────────────┘
                                         │
                                         ▼
                               ┌─────────────────────┐
                               │  WITNESS SERVERS    │
                               │ (3-node cluster)    │
                               │ (2-of-3 required)   │
                               └─────────────────────┘
```

## Building

### Prerequisites

1. Build DNA Messenger first (DNAC links against `libdna_lib.so`):
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
- `dnac-witness` - Witness server (for infrastructure operators)

## CLI Commands

```bash
# Identity & Info
dnac-cli info                    # Show wallet info, address, DHT status, balance
dnac-cli address                 # Show wallet address (fingerprint only)
dnac-cli query <name|fp>         # Lookup identity by name or fingerprint

# Wallet
dnac-cli balance                 # Show wallet balance
dnac-cli utxos                   # List UTXOs
dnac-cli send <fp> <amount>      # Send payment
dnac-cli genesis <fp> <amount>   # Create genesis TX (3-of-3 witness auth)
dnac-cli sync                    # Sync wallet from network
dnac-cli recover                 # Recover wallet from seed

# History
dnac-cli history [n]             # Transaction history (optional: last n)
dnac-cli tx <hash>               # Show transaction details

# Network
dnac-cli nodus-list              # Show witness servers
```

### Wallet Address

The wallet address is a **SHA3-512 hash of the Dilithium5 public key**:
- 64 bytes = 128 hexadecimal characters
- Same as DNA Messenger identity fingerprint

## Transaction Format (v1)

```
DNAC TRANSACTION v1:
┌─────────────────────────────────────────────────────────────┐
│ HEADER                                                      │
│   version: u8 = 1                                           │
│   type: u8 = TX_SPEND                                       │
│   timestamp: u64                                            │
│   tx_hash: bytes[64] (SHA3-512)                             │
├─────────────────────────────────────────────────────────────┤
│ INPUTS: nullifier[64] + amount (plaintext)                  │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS: recipient_fingerprint[64] + amount (plaintext)     │
├─────────────────────────────────────────────────────────────┤
│ BALANCE: sum(inputs) >= sum(outputs), difference = burned fee│
├─────────────────────────────────────────────────────────────┤
│ WITNESS ATTESTATIONS (2+ required): Dilithium5 signatures   │
├─────────────────────────────────────────────────────────────┤
│ SENDER AUTHORIZATION: Dilithium5 signature                  │
└─────────────────────────────────────────────────────────────┘
```

## Witness Infrastructure

DNAC uses a 3-node BFT witness cluster for double-spend prevention:

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
| Witnesses | 3 | Total nodes in cluster |
| Quorum | 2 | Required for consensus |
| Leader Election | `(epoch + view) % N` | Rotates hourly |
| TCP Port | 4200 | Inter-witness communication |

### Features

- **Auto-start on boot** - systemd service with `Restart=always`
- **Nullifier Database** - SQLite-based persistent storage
- **TCP Mesh** - Full mesh connectivity between witnesses
- **Request Forwarding** - Non-leaders forward to current leader

### DHT Storage via Nodus v5

All DHT data is stored via Nodus v5 (the `nodus_ops` convenience API). OpenDHT has been completely removed from the codebase. Data is stored permanently on the Nodus network:
- **Payments**
- **Witness attestations**
- **Nullifier replication**
- **Witness announcements**

## Security

- **Post-Quantum Signatures**: Dilithium5 for all signatures (NIST Category 5)
- **Nullifiers**: SHA3-512 hash prevents UTXO tracking
- **Linkability Prevention**: Nullifiers prevent transaction graph analysis
- **Double-Spend Prevention**: 2-of-3 witness attestation required
- **UTXO Validation**: Witnesses verify UTXO legitimacy before voting (v0.8.0)
- **Fee Burn**: Transaction fees are permanently removed from circulation (v0.8.1)

## Status

**Development Phase** - v0.8.1. Not for production use.

### Implemented (v0.8.1)

- [x] Core wallet functionality (UTXO management, balance tracking)
- [x] Send/receive transactions via DHT
- [x] BFT consensus protocol (PBFT-like)
- [x] 3-node witness cluster with systemd deployment
- [x] TCP mesh networking between witnesses
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
- [ ] Dynamic witness roster management

## License

MIT

## Related Projects

- [DNA Messenger](https://github.com/nocdem/dna-messenger) - Post-quantum encrypted messenger (monorepo: `/opt/dna/messenger/`)
- [Nodus v5](../nodus/) - Post-quantum Kademlia DHT with PBFT consensus (monorepo: `/opt/dna/nodus/`)
