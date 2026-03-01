# DNAC Witness Nodes - BFT Consensus Cluster

**Created:** 2026-01-21 | **Updated:** 2026-01-24 | **Version:** v0.7.1

---

## Overview

This document describes the witness node infrastructure for DNAC. These nodes provide double-spend prevention through BFT (Byzantine Fault Tolerant) consensus using TCP communication.

---

## Node Inventory

| Name | IP Address | Hostname | TCP Port | Status |
|------|------------|----------|----------|--------|
| node1 | 192.168.0.195 | chat1 | 4200 | Active |
| treasury | 192.168.0.196 | treasury | 4200 | Active |
| cpunkroot2 | 192.168.0.199 | cpunkroot2 | 4200 | Active |

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
                               │ TCP (port 4200)
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Witness #1     │  │  Witness #2     │  │  Witness #3     │
│  node1          │◀▶│  treasury       │◀▶│  cpunkroot2     │
│  192.168.0.195  │  │  192.168.0.196  │  │  192.168.0.199  │
│  :4200          │  │  :4200          │  │  :4200          │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                     │                     │
         └─────────────────────┴─────────────────────┘
                    BFT Consensus (TCP)
```

---

## BFT Consensus Protocol

### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Cluster Size | 3 (N=3f+1, f=0) | Byzantine fault tolerance |
| Quorum | 2 (2f+1) | Votes needed for consensus |
| Leader Election | `(epoch + view) % N` | Rotates hourly |
| Round Timeout | 5000ms | Triggers view change |
| Max View Changes | 3 | Per request before error |

### Consensus Flow

```
1. Client → Any Witness: SPEND_REQUEST
2. If not leader → Forward to leader
3. Leader → All: PROPOSE (nullifier + tx_hash)
4. All → All: PREVOTE (validate + vote)
5. On 2f+1 prevotes → All: PRECOMMIT
6. On 2f+1 precommits → COMMIT (record nullifier)
7. Leader → Client: SPEND_RESPONSE (approved/rejected)
```

### Phases

```
IDLE → PROPOSE → PREVOTE → PRECOMMIT → COMMIT → IDLE
                    │
                    └──► VIEW_CHANGE (on timeout)
```

---

## Witness Node Requirements

Each witness node requires:

1. **libdna** - DNA Messenger library (for identity/crypto)
2. **libdnac** - DNAC library
3. **dnac-witness** - Witness server binary
4. **SQLite3** - Nullifier storage
5. **Dilithium5 keypair** - For signing attestations
6. **TCP port 4200** - Open for inter-witness and client connections

---

## Setup

### Starting a Witness

```bash
# Using roster file
./dnac-witness -d ~/.dna -p 4200 -a "192.168.0.195:4200" -r roster.txt

# Options:
#   -d <dir>    Data directory (default: ~/.dna)
#   -p <port>   TCP port (default: 4200)
#   -a <addr>   My address for roster (IP:port)
#   -r <file>   Initial roster file
```

### Roster File Format

```
# roster.txt - one address per line
192.168.0.195:4200
192.168.0.196:4200
192.168.0.199:4200
```

### Systemd Service

```ini
# /etc/systemd/system/dnac-witness.service
[Unit]
Description=DNAC Witness Server
After=network.target

[Service]
Type=simple
User=nocdem
ExecStart=/opt/dna/dnac/build/dnac-witness -d /home/nocdem/.dna -p 4200 -a "192.168.0.195:4200" -r /etc/dnac/roster.txt
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Witnessing Protocol

1. Client sends `SpendRequest` to any witness via TCP
2. If witness is not leader, it forwards request to leader
3. Leader broadcasts `PROPOSE` to all witnesses
4. Witnesses validate and send `PREVOTE`
5. On quorum (2 votes): witnesses send `PRECOMMIT`
6. On quorum: all witnesses record nullifier (`COMMIT`)
7. Client receives signed `SpendResponse`

### Double-Spend Prevention

- **Consensus ensures atomicity**: No nullifier can be recorded without 2f+1 agreement
- **No race conditions**: Unlike DHT mode, BFT prevents concurrent conflicting approvals
- **Byzantine tolerance**: Can tolerate up to f malicious witnesses (f=0 for N=3)

---

## Commands

### SSH to nodes
```bash
ssh nocdem@192.168.0.195  # node1
ssh nocdem@192.168.0.196  # treasury
ssh nocdem@192.168.0.199  # cpunkroot2
```

### Check node status
```bash
ssh nocdem@192.168.0.195 "systemctl status dnac-witness"
```

### View logs
```bash
ssh nocdem@192.168.0.195 "journalctl -u dnac-witness -f"
```

### Check peer connectivity
```bash
# From any witness, check TCP connections
ss -tnp | grep 4200
```

---

## Features (v0.7.1)

### Version Announcements

Witnesses broadcast their software version in announcements:
- Response includes: `software_version[3]` - [major, minor, patch]
- Announcement includes: `software_version[3]` - [major, minor, patch]
- Logs show: `witness %.8s... v%d.%d.%d VERIFIED`

### Replay Prevention (v0.6.0)

Transactions include nonce and timestamp to prevent replay attacks:
- Nonce: Unique per-transaction random value
- Timestamp: Must be within acceptable window
- Combined with nullifiers for complete replay protection

### Merkle Tree Ledger (v0.7.0)

Transaction inclusion proofs via Merkle tree:
- Transactions stored in Merkle tree structure
- Inclusion proofs available for any confirmed transaction
- Chain synchronization for new nodes

### BFT-Signed Epoch Roots (v0.7.1)

Epoch state anchored by BFT consensus:
- Each epoch produces a signed state root
- Merkle proofs anchored to BFT-signed roots
- Trust verification for transaction inclusion

---

## Troubleshooting

### Witness not connecting to peers
1. Check firewall: `sudo ufw status`
2. Verify port is open: `nc -zv 192.168.0.196 4200`
3. Check roster file has correct addresses

### Leader election issues
- Leader = `(epoch + view) % N` where epoch = `time(NULL) / 3600`
- View changes on consensus timeout (5s)
- Check logs for `VIEW_CHANGE` messages

### Consensus stalled
- Ensure at least 2 witnesses are running (quorum = 2)
- Check for network partitions between witnesses
- Verify all witnesses have same roster

---

## Contact

Repository: `github.com/nocdem/dna-messenger` (monorepo, DNAC at `dnac/`)
