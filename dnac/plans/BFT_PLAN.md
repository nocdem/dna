# BFT Implementation Plan for DNAC

**Date:** 2026-01-22
**Status:** COMPLETED
**Completed In:** v0.2.0
**Completion Date:** 2026-01-22

> **Note:** This plan has been fully implemented. All phases completed successfully.

---

## Executive Summary

Implement Byzantine Fault Tolerance (BFT) for DNAC's witness system to handle **malicious** witnesses, not just failed ones.

**Implementation Strategy:** Start with 3 witnesses (local testing), add 4th witness for production BFT.

---

## Test Infrastructure

### Local Witness Nodes

| Name | IP Address | TCP Port | Role |
|------|------------|----------|------|
| node1 | 192.168.0.195 | 4200 | Witness #1 (initial leader) |
| treasury | 192.168.0.196 | 4200 | Witness #2 |
| cpunkroot2 | 192.168.0.199 | 4200 | Witness #3 |
| (future) | TBD | 4200 | Witness #4 (production BFT) |

### Quorum Requirements

| Witnesses | f | Quorum (2f+1) | Notes |
|-----------|---|---------------|-------|
| 3 | 0 | 2 | Testing (same as current 2-of-3) |
| 4 | 1 | 3 | Production minimum |

---

## Protocol Design

### Consensus Round for Spend Request

```
Phase 1: PROPOSE   - Leader receives request, broadcasts Proposal
Phase 2: PREVOTE   - Witnesses validate, broadcast Prevote
Phase 3: PRECOMMIT - Wait for quorum Prevotes, broadcast Precommit
Phase 4: COMMIT    - Wait for quorum Precommits, commit + respond
```

### Communication Architecture

```
TCP FOR COMMUNICATION, DHT FOR STORAGE

Clients ──TCP──▶ Leader Witness ◀──TCP──▶ Other Witnesses
                       │
                       ▼
                 DHT (Storage Only)
                 - Attestations
                 - Nullifiers
                 - Roster
```

---

## Implementation Phases

### Phase 1: Foundation (v0.2.0-alpha)

| Task | Files | Description |
|------|-------|-------------|
| Define BFT structures | `include/dnac/bft.h` | Message types, config, state |
| BFT serialization | `src/bft/serialize.c` | Proposal, vote, roster encoding |
| TCP networking | `src/bft/tcp.c` | TCP server/client for witness mesh |
| Peer management | `src/bft/peer.c` | Connect/disconnect, reconnect |
| Consensus state machine | `src/bft/consensus.c` | Round state, vote counting |

### Phase 2: Witness BFT Mode (v0.2.0-beta)

| Task | Files | Description |
|------|-------|-------------|
| BFT main loop | `src/witness/bft_main.c` | BFT-enabled witness server |
| Proposal handling | `src/witness/proposer.c` | Leader creates proposals |
| Vote handling | `src/witness/voter.c` | Prevote/precommit logic |
| View change | `src/witness/viewchange.c` | Leader failure recovery |

### Phase 3: Client Integration (v0.2.0-rc)

| Task | Files | Description |
|------|-------|-------------|
| Client TCP layer | `src/nodus/tcp_client.c` | TCP connection to witnesses |
| Roster discovery | `src/nodus/roster.c` | Fetch roster from DHT |
| Update client API | `include/dnac/nodus.h` | TCP-based request/response |

### Phase 4: Testing & Deployment (v0.2.0)

| Task | Description |
|------|-------------|
| Deploy to 3 local witnesses | 192.168.0.195/196/199 |
| Test basic consensus | All 3 witnesses agree |
| Test leader failure | View change to new leader |
| Add 4th witness | Enable true BFT (f=1) |

---

## File Summary

### New Files (12)

| File | Purpose |
|------|---------|
| `include/dnac/bft.h` | BFT public API and structures |
| `include/dnac/tcp.h` | TCP protocol definitions |
| `src/bft/consensus.c` | Consensus state machine |
| `src/bft/serialize.c` | BFT message serialization |
| `src/bft/tcp.c` | TCP server/client networking |
| `src/bft/peer.c` | Peer connection management |
| `src/witness/bft_main.c` | BFT witness entry point |
| `src/witness/proposer.c` | Leader proposal logic |
| `src/witness/voter.c` | Voting (prevote/precommit) |
| `src/witness/viewchange.c` | View change protocol |
| `src/nodus/tcp_client.c` | Client TCP connection |
| `src/nodus/roster.c` | Witness roster discovery |

### Modified Files (4)

| File | Change |
|------|--------|
| `include/dnac/nodus.h` | Add BFT attestation type |
| `src/nodus/client.c` | Add TCP-based requests |
| `src/witness/main.c` | Add --bft mode flag |
| `CMakeLists.txt` | Add bft source files |

---

## Configuration

### Local Testing (3 witnesses)

```c
dnac_bft_config_t config = {
    .n_witnesses = 3,
    .f_tolerance = 0,
    .quorum = 2,
    .round_timeout_ms = 5000,
    .view_change_timeout_ms = 10000
};

static const char *LOCAL_WITNESS_HOSTS[] = {
    "192.168.0.195",  /* node1 */
    "192.168.0.196",  /* treasury */
    "192.168.0.199"   /* cpunkroot2 */
};
```

---

## Decisions Made

1. **Cluster size**: 3 witnesses for testing, 4th for production BFT
2. **Test network**: Local IPs (192.168.0.195/196/199)
3. **Communication**: TCP for messaging, DHT for storage only
4. **Migration**: Hard cutover (no backward compatibility needed)
