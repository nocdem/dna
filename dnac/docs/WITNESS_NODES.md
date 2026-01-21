# DNAC Witness Nodes - Alpha/Beta Testing

**Created:** 2026-01-21 | **Version:** v0.1.23

---

## Overview

This document describes the witness node infrastructure for DNAC alpha/beta testing. These nodes provide the 2-of-3 witnessing mechanism required for double-spend prevention.

---

## Node Inventory

| Name | IP Address | Hostname | Role | Status |
|------|------------|----------|------|--------|
| node1 | 192.168.0.195 | chat1 | Witness Server #1 | Active |
| treasury | 192.168.0.196 | treasury | Witness Server #2 | Active |
| cpunkroot2 | 192.168.0.199 | cpunkroot2 | Witness Server #3 | Active |

### Node Fingerprints

| Node | Fingerprint |
|------|-------------|
| node1 | `46de00d4e2ac54bdb70f3867498707ebaca58c65ca7713569fe183ffeeea46bdf380804405430d4684d8fc17b4702003d46d013151749a43fdc6b84d7472709d` |
| treasury | `d43514f121b508ca304ce741edca0bd1fbe661fe5fbd6f188b6831d0794179977083e9fbae4aa40e7d16ee73918b6e26f9c29011914415732322a2b129303634` |
| cpunkroot2 | `7dea0967abe22f720be1b1c0f68131eb1e39d93a5bb58039836fe842a10fefec1db52df710238edcb90216f232da5c621e4a2e92b6c42508b64baf43594935e7` |

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

## Epoch-Based DHT Keys (v0.1.21+)

To prevent unbounded DHT key accumulation, witness requests use epoch-based rotating keys.

### Epoch Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| Epoch Duration | 3600 sec (1 hour) | Time-based rotation |
| Announcement TTL | 3600 sec | Refreshed each epoch |
| Request TTL | 300 sec (5 min) | Short-lived requests |

### Key Structure

```
PERMANENT ANNOUNCEMENT KEY (per witness):
  SHA3-512("dnac:witness:announce:" + witness_fingerprint)

EPOCH REQUEST KEY (rotates hourly):
  SHA3-512("dnac:nodus:epoch:request:" + witness_fingerprint + ":" + epoch_number)

Epoch Number = time(NULL) / 3600
```

### Witness Announcement

Each witness publishes an announcement to its permanent key:

```c
typedef struct {
    uint8_t  version;                    /* = 1 */
    uint8_t  witness_id[32];             /* First 32 bytes of fingerprint */
    uint64_t current_epoch;              /* Current epoch number */
    uint64_t epoch_duration;             /* 3600 seconds */
    uint64_t timestamp;                  /* Announcement time */
    uint8_t  witness_pubkey[2592];       /* Dilithium5 public key */
    uint8_t  signature[4627];            /* Dilithium5 signature */
} dnac_witness_announcement_t;
```

### Client Flow

```
1. Client discovers witness fingerprints
2. Client fetches announcement from permanent key:
   GET SHA3-512("dnac:witness:announce:" + witness_fp)
3. Client extracts current_epoch from announcement
4. Client builds epoch request key:
   SHA3-512("dnac:nodus:epoch:request:" + witness_fp + ":" + epoch)
5. Client PUTs SpendRequest to epoch key
6. Fallback: If announcement unavailable, use local time(NULL)/3600
```

### Server Flow

```
1. Server publishes announcement on startup
2. Server listens on current epoch key AND previous epoch key
3. On epoch change:
   a. Publish new announcement
   b. Stop listener on (epoch - 2)
   c. Start listener on new epoch
4. Process requests from both current and previous epoch keys
```

### Epoch Boundary Handling

```
Time:   |-------- Epoch N --------|-------- Epoch N+1 --------|

Client: Sends to epoch N          | Sends to epoch N+1
        at 00:59:59               | at 01:00:01

Server: Listens on epoch N        | Listens on epoch N+1
        Listens on epoch N-1      | Listens on epoch N

Result: Request found in N        | Request found in N+1
```

The server always listens on current AND previous epoch, ensuring no requests are missed at boundaries.

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

1. ~~`src/witness/config.h:32-36` - `WITNESS_PEERS[]` array is empty~~ **RESOLVED** - All 3 witnesses configured
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
