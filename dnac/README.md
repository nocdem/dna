# DNAC - Post-Quantum Zero-Knowledge Cash over DHT

**Version:** v0.1.29 | **Protocol:** v1 (Transparent Amounts)

DNAC is a privacy-preserving digital cash system built on top of [DNA Messenger](https://github.com/nocdem/dna-messenger).

## Features

- **UTXO Model** - Unspent Transaction Output model for privacy
- **Dilithium5 Signatures** - Post-quantum digital signatures (NIST Category 5)
- **DHT Transport** - Payments delivered via DNA Messenger's DHT network
- **Permanent Storage** - All data stored permanently (cash doesn't expire)
- **Nodus 2-of-3 Witnessing** - Fast double-spend prevention
- **Epoch-Based Discovery** - Witness servers discovered via epoch keys

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

1. Build DNA Messenger first:
```bash
cd /opt/dna-messenger
mkdir build && cd build
cmake .. && make -j$(nproc)
```

2. Install dependencies:
```bash
# Debian/Ubuntu
sudo apt install libssl-dev libsqlite3-dev pkg-config cmake
```

### Build DNAC

```bash
cd /opt/dnac
mkdir build && cd build
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
dnac-cli mint <fp> <amount>      # Mint new coins (requires witness auth)
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
│ BALANCE: sum(inputs) == sum(outputs)                        │
├─────────────────────────────────────────────────────────────┤
│ WITNESS ATTESTATIONS (2+ required): Dilithium5 signatures   │
├─────────────────────────────────────────────────────────────┤
│ SENDER AUTHORIZATION: Dilithium5 signature                  │
└─────────────────────────────────────────────────────────────┘
```

## Witness Infrastructure

DNAC uses a 3-node witness cluster for double-spend prevention:

- **2-of-3 Threshold** - Transactions require 2 witness attestations
- **Nullifier Database** - Each witness tracks spent UTXOs
- **Cross-Replication** - Nullifiers replicated across all witnesses
- **Epoch-Based Discovery** - Witnesses announce on epoch-based DHT keys

### Permanent DHT Storage

All DHT data is stored permanently:
- **Payments** - Never expire (cash doesn't expire)
- **Witness attestations** - Permanent record
- **Nullifier replication** - Permanent cross-witness sync
- **Witness announcements** - Permanent identity publication

## Security

- **Post-Quantum Signatures**: Dilithium5 for all signatures (NIST Category 5)
- **Nullifiers**: SHA3-512 hash prevents UTXO tracking
- **Linkability Prevention**: Nullifiers prevent transaction graph analysis
- **Double-Spend Prevention**: 2-of-3 witness attestation required

## Status

**Design Phase** - v0.1.29. Not for production use.

- Core wallet functionality: Working
- Send/receive: Working
- Witness infrastructure: Deployed (3 nodes)
- CLI: Implemented
- ZK amounts: Deferred to v2

## License

MIT

## Related Projects

- [DNA Messenger](https://github.com/nocdem/dna-messenger) - Post-quantum encrypted messenger
