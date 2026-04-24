> **ARCHIVED 2026-04-24** — RESOLVED (DHT removed + burn address supply invariant). See MEMORY: `project_dnac_permanent_utxo`. Kept for history; the "Status: OPEN" below is stale.

# Problem: UTXO Persistence and Recovery

**Status:** OPEN
**Severity:** Critical
**Date:** 2026-01-23

---

## Summary

UTXOs are stored only in local SQLite databases. There is no shared ledger or persistent global state. If a user loses their local database and DHT data expires, their coins are permanently lost.

---

## Current Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│   SENDER    │────▶│  WITNESS (BFT)  │────▶│  RECIPIENT  │
│             │     │                 │     │             │
│ Local DB    │     │ Nullifier DB    │     │ Local DB    │
│ (SQLite)    │     │ (double-spend)  │     │ (SQLite)    │
└─────────────┘     └─────────────────┘     └─────────────┘
      │                                            ▲
      │              ┌─────────────┐               │
      └─────────────▶│     DHT     │───────────────┘
                     │ (temporary) │
                     └─────────────┘
```

### Data Flow

1. **Sender** creates transaction, gets witness signatures
2. **Witness** records nullifier (prevents double-spend)
3. **Sender** publishes TX to recipient's DHT inbox
4. **Sender** stores change UTXO in local SQLite
5. **Recipient** syncs from DHT, stores UTXO in local SQLite

### Where Data Lives

| Data | Location | Persistence |
|------|----------|-------------|
| UTXOs (unspent) | Local SQLite only | Until DB deleted |
| UTXOs (change) | Local SQLite only | Until DB deleted |
| Transactions | DHT + local history | DHT may expire |
| Nullifiers | Witness servers | Permanent (prevents reuse) |

---

## Problems

### 1. No Shared Ledger

Unlike Bitcoin where all nodes maintain the UTXO set, DNAC has no shared state:

- Each wallet only knows about its own UTXOs
- No way to query "what UTXOs exist for address X" globally
- Witnesses only track nullifiers (spent coins), not UTXOs (unspent coins)

### 2. DHT Data Expiration

**Note:** OpenDHT has been completely removed from the codebase. DNAC now uses Nodus for all DHT operations via the `nodus_ops` API. Nodus provides 7-day TTL with server-side persistence, which mitigates some of the original concerns below. However, the fundamental issue remains:

- DHT data has limited lifetime (7-day TTL on Nodus)
- If sender goes offline and data expires, recipient may never receive payment
- Network partitions can cause data loss

### 3. Single Point of Failure

Local SQLite database is the only source of truth:

```
User loses ~/.dna/dnac.db
        ↓
All UTXOs lost
        ↓
No recovery possible (if DHT data expired)
        ↓
Coins permanently destroyed
```

### 4. No Proof of Ownership

Without a shared ledger, there's no way to prove:

- That a UTXO exists and is valid
- That you own a certain balance
- Historical transaction validity

### 5. Inconsistent State

Race conditions can cause state divergence:

- Sender marks UTXO spent, but DHT put fails
- Recipient never receives, sender lost the coins
- No mechanism for rollback or dispute resolution

---

## Comparison with Real Payment Systems

| Feature | Bitcoin | Lightning | DNAC (current) |
|---------|---------|-----------|----------------|
| UTXO storage | Blockchain (all nodes) | Channel state (2 parties) | Local DB only |
| Persistence | Permanent (proof-of-work) | Until channel close | Until DB deleted |
| Recovery | Re-sync from any node | Channel backups | Hope DHT has it |
| Proof of balance | Merkle proof from chain | Channel signatures | None |
| Double-spend prevention | Blockchain consensus | Channel penalties | Witness nullifiers |
| Offline receiving | Yes (on-chain) | No (need online) | No (need DHT sync) |

---

## Potential Solutions

### Option A: Witnesses Store Full UTXO Set

```
┌─────────────┐     ┌─────────────────────────┐     ┌─────────────┐
│   SENDER    │────▶│    WITNESS CLUSTER      │────▶│  RECIPIENT  │
│             │     │                         │     │             │
│ Local cache │     │ Nullifier DB            │     │ Local cache │
│             │     │ UTXO DB (full state)    │     │             │
│             │     │ TX History              │     │             │
└─────────────┘     └─────────────────────────┘     └─────────────┘
```

**Pros:**
- Authoritative source of truth
- Clients can query balance from witnesses
- Recovery by re-syncing from witnesses
- No DHT dependency for core functionality

**Cons:**
- Witnesses become centralized storage
- Increased witness storage requirements
- Need BFT replication of UTXO state

**Implementation:**
1. Add UTXO table to witness servers
2. Witnesses store outputs when signing TX
3. Client queries witnesses for balance
4. Local DB becomes cache, not source of truth

### Option B: Append-Only Transaction Log

```
┌─────────────┐     ┌─────────────────────────┐
│   CLIENT    │────▶│    WITNESS CLUSTER      │
│             │     │                         │
│             │     │ TX Log (append-only)    │
│             │     │ ┌─────────────────────┐ │
│             │     │ │ TX1 │ TX2 │ TX3 │...│ │
│             │     │ └─────────────────────┘ │
│             │     │ Derived UTXO Set        │
└─────────────┘     └─────────────────────────┘
```

**Pros:**
- Simple append-only structure
- Full audit trail
- UTXO set derived from log
- Easy BFT replication

**Cons:**
- Growing storage over time
- Need log compaction strategy
- Slower queries (need to scan log)

**Implementation:**
1. Witnesses store all signed TXs in order
2. UTXO set computed from TX log
3. Periodic snapshots for faster queries
4. Clients sync from witnesses, not DHT

### Option C: Hybrid DHT + Witness Backup

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   SENDER    │────▶│     DHT     │────▶│  RECIPIENT  │
│             │     │ (primary)   │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │ Witness1 │  │ Witness2 │
              │ (backup) │  │ (backup) │
              └──────────┘  └──────────┘
```

**Pros:**
- DHT for fast delivery (existing code)
- Witnesses as backup storage
- Gradual migration path

**Cons:**
- Two systems to maintain
- Complexity in sync logic
- DHT still unreliable

---

## Recommended Solution

**Option A (Witnesses Store Full UTXO Set)** is recommended because:

1. Witnesses already have BFT consensus
2. Witnesses already sign every transaction
3. Natural extension of existing trust model
4. Eliminates DHT reliability issues
5. Enables proper balance queries and proofs

### Migration Path

1. **Phase 1:** Witnesses store TXs they sign (read-only backup)
2. **Phase 2:** Add UTXO tracking to witnesses
3. **Phase 3:** Client balance queries from witnesses
4. **Phase 4:** Deprecate DHT for TX delivery
5. **Phase 5:** Local DB becomes cache only

---

## Action Items

- [ ] Design witness UTXO storage schema
- [ ] Implement BFT-replicated UTXO state
- [ ] Add client API for balance/UTXO queries
- [ ] Add TX delivery via witnesses (not DHT)
- [ ] Implement wallet recovery from witnesses
- [ ] Update documentation

---

## References

- Current UTXO storage: `src/db/db.c` (dnac_utxos table)
- Witness nullifier DB: `src/witness/nullifier.c`
- DHT sync: `src/wallet/wallet.c` (dnac_wallet_sync)
- BFT consensus: `src/bft/consensus.c`
