# DNAC - Post-Quantum Zero-Knowledge Cash over DHT

DNAC is a privacy-preserving digital cash system built on top of [DNA Messenger](https://github.com/nocdem/dna-messenger).

## Features

- **UTXO Model** - Unspent Transaction Output model for privacy
- **Pedersen Commitments** - Hide transaction amounts cryptographically
- **Bulletproofs** - Compact zero-knowledge range proofs
- **Dilithium5 Signatures** - Post-quantum digital signatures (NIST Category 5)
- **DHT Transport** - Payments delivered via DNA Messenger's DHT network
- **Nodus 2-of-3 Witnessing** - Fast double-spend prevention

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     dna-messenger-cli                       │
│         (existing commands + new "dnac" subcommands)        │
└─────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
┌─────────────────────┐        ┌─────────────────────┐
│      libdna         │◀───────│      libdnac        │
│  (identity, DHT,    │ links  │  (ZK cash system)   │
│   crypto, transport)│        │                     │
└─────────────────────┘        └─────────────────────┘
                                         │
                                         ▼
                               ┌─────────────────────┐
                               │  WITNESS SERVERS    │
                               │ (nullifier witness) │
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

## CLI Commands (Planned)

```bash
dnac balance                     # Show wallet balance
dnac utxos                       # List UTXOs
dnac send <fp|name> <amount>     # Send payment
dnac history                     # Transaction history
dnac sync                        # Sync wallet from network
dnac nodus-list                  # Show Nodus servers
```

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
│ INPUTS: nullifier + key_image                               │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS: commitment + encrypted_data + range_proof          │
├─────────────────────────────────────────────────────────────┤
│ BALANCE PROOF: excess_commitment + excess_signature         │
├─────────────────────────────────────────────────────────────┤
│ WITNESS PROOF (2 required): Dilithium attestations          │
├─────────────────────────────────────────────────────────────┤
│ SENDER AUTHORIZATION: Dilithium signature                   │
└─────────────────────────────────────────────────────────────┘
```

## Security

- **Hybrid ZK**: Classical Pedersen commitments + Bulletproofs for ZK proofs
- **Post-Quantum Signatures**: Dilithium5 for all signatures (quantum-resistant)
- **Amount Privacy**: Transaction amounts hidden in Pedersen commitments
- **Linkability Prevention**: Nullifiers prevent UTXO tracking

## Status

**Alpha** - API under development. Not for production use.

## License

MIT

## Related Projects

- [DNA Messenger](https://github.com/nocdem/dna-messenger) - Post-quantum encrypted messenger
