# DNAC Witness Nodes - Alpha/Beta Testing

**Created:** 2026-01-21 | **Version:** v0.1.18

---

## Overview

This document describes the witness node infrastructure for DNAC alpha/beta testing. These nodes provide the 2-of-3 witnessing mechanism required for double-spend prevention.

---

## Node Inventory

| Name | IP Address | Hostname | Role | Status |
|------|------------|----------|------|--------|
| node1 | 192.168.0.195 | chat1 | Witness Server #1 | Pending Setup |
| treasury | 192.168.0.196 | treasury | Witness Server #2 | Pending Setup |
| cpunkroot2 | 192.168.0.199 | cpunkroot2 | Witness Server #3 | Pending Setup |

**SSH Access:** `nocdem@<ip>`

---

## Network Topology

```
                    ┌─────────────────────┐
                    │    Test Clients     │
                    │  (DNAC Wallets)     │
                    └──────────┬──────────┘
                               │
                               │ DHT
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Witness #1     │  │  Witness #2     │  │  Witness #3     │
│  node1          │  │  treasury       │  │  cpunkroot2     │
│  192.168.0.195  │  │  192.168.0.196  │  │  192.168.0.199  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## Witness Node Requirements

Each witness node requires:

1. **libdna** - DNA Messenger library (DHT connectivity)
2. **libdnac** - DNAC library
3. **dnac-witness** - Witness server binary
4. **SQLite3** - Nullifier storage
5. **Dilithium5 keypair** - For signing attestations

---

## Setup Checklist

### Per-Node Setup

- [ ] Install dependencies (OpenSSL, SQLite3)
- [ ] Build and install libdna
- [ ] Build and install libdnac
- [ ] Build dnac-witness server
- [ ] Generate witness keypair
- [ ] Configure witness identity
- [ ] Start dnac-witness service
- [ ] Verify DHT connectivity

### Network Setup

- [ ] All nodes connected to DHT network
- [ ] Firewall rules allow DHT port (default: 4222)
- [ ] Nodes can reach each other
- [ ] Bootstrap node configured

---

## Configuration

### Witness Server Config (`/etc/dnac/witness.conf`)

```
# Witness node configuration
witness_id = "<32-byte-hex-id>"
listen_port = 4222
data_dir = /var/lib/dnac
nullifier_db = /var/lib/dnac/nullifiers.db

# Peer witnesses for nullifier replication
peers = [
    "192.168.0.195:4222",
    "192.168.0.196:4222",
    "192.168.0.199:4222"
]
```

---

## Witnessing Protocol

1. Client sends `SpendRequest` to all 3 witnesses via DHT
2. Each witness checks nullifier table
3. If nullifier is new: APPROVE + sign + replicate to peers
4. If nullifier exists: REJECT (double-spend)
5. Client collects 2+ attestations
6. Transaction with 2+ attestations is valid

---

## Testing Phases

### Alpha (Current)
- Local network testing
- Manual witness startup
- Basic transaction flow validation

### Beta (Planned)
- Extended network testing
- Automated witness management
- Stress testing / load testing
- Nullifier replication verification

---

## Commands

### SSH to nodes
```bash
ssh nocdem@192.168.0.195  # node1
ssh nocdem@192.168.0.196  # treasury
ssh nocdem@192.168.0.199  # cpunkroot2
```

### Check node status (once deployed)
```bash
ssh nocdem@192.168.0.195 "systemctl status dnac-witness"
```

---

## Known Issues

1. `src/witness/config.h:32-36` - `WITNESS_PEERS[]` array is empty
2. `src/nodus/discovery.c:118-119` - Bootstrap server pubkeys are zeros
3. Witness server not yet built by default (requires `-DDNAC_BUILD_WITNESS=ON`)

---

## Next Steps

1. Build dnac-witness on each node
2. Generate Dilithium5 keypairs for each witness
3. Configure peer list with real fingerprints
4. Start services and verify DHT connectivity
5. Test transaction flow between wallets

---

## Contact

Repository: `github.com/nocdem/dnac`
