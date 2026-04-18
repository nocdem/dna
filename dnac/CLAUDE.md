# DNAC - Development Guidelines

**Last Updated:** 2026-04-17 | **Status:** DESIGN | **Version:** v0.17.0-stake.wip (feature branch `stake-delegation-v1`)

**Note:** Framework rules (checkpoints, identity override, protocol mode, violations) are in root `/opt/dna/CLAUDE.md`. This file contains DNAC-specific guidelines only.

**Active feature branch:** `stake-delegation-v1` — stake-weighted top-7 committee, delegation, per-block reward accrual, pull-based claim. Design doc: `dnac/docs/plans/2026-04-17-witness-stake-delegation-design.md`. Implementation plan: `dnac/docs/plans/2026-04-17-witness-stake-delegation-implementation.md`. Not yet merged to `main`; chain wipe required at deploy time.

---

## Project Overview

DNAC is a **Post-Quantum Zero-Knowledge Cash** system built on top of DNA Connect.

| Component | Technology |
|-----------|------------|
| Token Model | UTXO |
| Signatures | Dilithium5 (Post-Quantum) |
| Transport | DHT via Nodus (nodus_ops API) |
| Double-Spend Prevention | Nodus PBFT Witnessing (dynamic roster) |
| Database | SQLite |
| ZK (v2 future) | STARKs (Post-Quantum) |

```
┌─────────────────────────────────────────────────────────────┐
│                     dna-connect-cli                       │
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
                               │ (embedded in nodus) │
                               └─────────────────────┘
```

---

## Directory Structure

```
/opt/dna/dnac/
├── include/dnac/
│   ├── dnac.h             # Main API
│   ├── version.h          # Version info
│   ├── wallet.h           # Wallet internals
│   ├── transaction.h      # Transaction types
│   ├── nodus.h            # Nodus client + witness
│   ├── ledger.h           # Ledger/chain
│   ├── block.h            # Block types
│   ├── epoch.h            # Epoch management
│   ├── genesis.h          # Genesis config
│   ├── utxo_set.h         # UTXO set tracking
│   ├── safe_math.h        # Overflow-safe arithmetic
│   ├── commitment.h       # Commitments
│   ├── crypto_helpers.h   # Crypto utilities
│   ├── db.h               # Database layer
│   └── cli.h              # CLI interface
├── src/
│   ├── wallet/            # UTXO management, coin selection, balance
│   ├── transaction/       # TX building, verification, nullifiers, genesis
│   ├── nodus/             # Witness client, discovery, attestation
│   ├── db/                # SQLite operations
│   ├── cli/               # CLI tool
│   ├── utils/             # Crypto helpers
│   └── version.c          # Version info
└── tests/                 # Unit tests
```

---

## Build

**Prerequisites:** libdna must be built first at `/opt/dna/messenger/build`

```bash
cd /opt/dna/dnac/build
cmake .. && make -j$(nproc)
```

**Debug Build with ASAN:**
```bash
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" ..
make -j$(nproc)
```

**Check if libdna has ASAN:** `nm /opt/dna/messenger/build/libdna.so | grep -i asan`

---

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DNAC_NULLIFIER_SIZE` | 64 | SHA3-512 nullifier |
| `DNAC_TX_HASH_SIZE` | 64 | SHA3-512 transaction hash |
| `DNAC_SIGNATURE_SIZE` | 4627 | Dilithium5 signature |
| `DNAC_PUBKEY_SIZE` | 2592 | Dilithium5 public key |
| `DNAC_WITNESSES_REQUIRED` | 2 | Witnesses needed for valid TX |

---

## Witness System (Embedded in Nodus)

The standalone `dnac-witness` binary was removed in v0.10.3. Witness logic runs inside `nodus-server` via `nodus/src/witness/`. The witness roster is dynamic — nodus-server nodes with witness capability announce themselves and are discovered at runtime via `dnac_discover_witnesses()`.

### BFT Consensus

| Parameter | Value | Description |
|-----------|-------|-------------|
| Leader Election | `(epoch + view) % N` | Rotates each hour |
| Quorum | `2f+1` | For `N = 3f+1` witnesses |
| Round Timeout | 5000ms | Triggers view change |
| Max View Changes | 3 | Per request before error |

**Phases:** PROPOSE → PREVOTE → PRECOMMIT → COMMIT

---

## Committee, Stake & Delegation (feature branch `stake-delegation-v1`)

The witness roster in `main` is *dynamic* — every online nodus node automatically participates as a witness. On the `stake-delegation-v1` branch this is replaced with a **stake-weighted deterministic top-7 committee** whose membership is derived entirely from on-chain state. Witness discovery and BFT roster both consult chain state — not DHT registrations, not TCP 4002 peer lists.

**Key properties (v1):**

| Property | Value |
|----------|-------|
| Committee size | 7 (top by total stake; self + delegations) |
| Self-stake | Fixed exactly 10,000,000 DNAC per witness |
| Delegator stake | Unbounded (any holder may delegate any amount) |
| Rotation | Per-epoch (deterministic re-rank from chain snapshot) |
| Rewards | Per-block fee-pool accrual, pull-based `CLAIM_REWARD` TX |
| Commission | Per-validator bps (set via `VALIDATOR_UPDATE`) |
| Slashing | Not in v1 (deferred to v2 with sortition) |

**New TX types (v0.17):** `STAKE`, `UNSTAKE`, `DELEGATE`, `UNDELEGATE`, `CLAIM_REWARD`, `VALIDATOR_UPDATE`. Existing BFT (PBFT, `N = 3f+1`), multi-signer TX infrastructure (v0.11 `signers[]` array), and Merkle `state_root` are preserved. Roster authority moves from DHT/routing-based auto-join to chain-derived top-7 by total stake, which replaces the paths documented in `nodus/docs/DYNAMIC_WITNESS_DESIGN.md` (now superseded).

See `dnac/docs/plans/2026-04-17-witness-stake-delegation-design.md` for the full design + red-team audit.

---

## Hard-Fork Mechanism v1 (`DNAC_TX_CHAIN_CONFIG`, 2026-04-19)

Committee-voted consensus parameter changes without chain wipe. A 5-of-7
committee signs a proposal preimage and a `DNAC_TX_CHAIN_CONFIG` TX is
broadcast carrying the votes; on commit the override is stored in
`chain_config_history` and contributes to `state_root` via
`chain_config_root`. Consumer sites read active overrides via
`nodus_chain_config_get_u64(param_id, current_block, default)`.

**Supported parameters (v1):**

| param_id | Constant | Range | Consumer |
|----------|----------|-------|----------|
| 1 | `DNAC_CFG_MAX_TXS_PER_BLOCK` | `[1, 10]` | BFT batch cap |
| 2 | `DNAC_CFG_BLOCK_INTERVAL_SEC` | `[1, 15]` | Proposer timer (future) |
| 3 | `DNAC_CFG_INFLATION_START_BLOCK` | `[0, 2^48]` | Inflation mint |

**Consensus rules** (enforced in `nodus_chain_config_apply`):
- Min 5-of-7 Dilithium5 signatures from CURRENT committee at
  `commit_block - 1`
- Grace: `effective_block >= commit_block + EPOCH_LENGTH` (ergonomic
  params) / `12 × EPOCH_LENGTH` (safety-critical: block_interval,
  inflation)
- Freshness: `commit_block <= valid_before_block`
- `INFLATION_START_BLOCK` monotonicity: once non-zero committed, cannot
  be disabled (set to 0) or moved past current_block
- PK `(param_id, effective_block)` replay rejection

**state_root composition (post-activation):**
```
state_root = SHA3-512( 0x02 || utxo_root || validator_root ||
                        delegation_root || reward_root || chain_config_root )
```
The `0x02` version byte is domain separation from the legacy 4-input
formula (`nodus_merkle_combine_state_root_v1_legacy`, retained
`__attribute__((cold))` for archive-replay).

**Design doc:** `dnac/docs/plans/2026-04-19-hard-fork-mechanism-design.md`
(contains full 29-finding red-team audit).

**Shipped:**
- Stage A — TX wire format + client verify (commit `69c4e44e`)
- Stage B — witness apply + DB schema + 5-input state_root (`ca628df1`)
- Stage C — vote primitives (digest / sign / verify) (`fd1e194e`)
- Stage D — finalize_block consumer wiring (`08baa4d1`)

**Pending:**
- Stage C.2 — tier-2 vote-collect RPC wire format + peer handler +
  rate-limit
- Stage E — CLI verbs (`dna chain-config propose/list/history`)
- Stage F — local 3-node integration test harness

These three land together once the tier-2 RPC is designed — shipping E
without C.2 would require the CLI to drive collection via ad-hoc TCP
calls, which is brittle.

---

## Security Considerations

1. **Nullifiers** — SHA3-512(secret || UTXO data) to prevent linking
2. **Nodus Witnessing** — PBFT quorum (2f+1) for double-spend prevention
3. **Key Storage** — libdna's secure key storage
4. **Dilithium5** — Post-quantum secure signatures
5. **UTXO Ownership** — Sender fingerprint verified before PREVOTE (v0.10.2)
6. **Nullifier Fail-Closed** — DB errors assume nullifier exists (v0.10.2)
7. **Chain ID Validation** — Prevents cross-zone replay (v0.10.2)
8. **Secure Nonce** — RNG failure aborts, no weak fallback (v0.10.2)
9. **Overflow Protection** — safe_add_u64 for supply/balance (v0.10.2)
10. **COMMIT Signatures** — Valid Dilithium5 required (v0.10.2)
11. **COMMIT TX Integrity** — tx_hash recomputed before DB commit (v0.11.0)
12. **Nonce Hash Table** — O(1) replay prevention with TTL (v0.11.0)
13. **BFT Code Removal** — Client-side BFT removed; all BFT logic server-side in nodus (v0.11.1)

---

## Development Phase Policy

**Current Phase:** DESIGN (pre-alpha)

**Breaking Changes:** ALLOWED — no backward compatibility required. Clean implementations preferred. Legacy code/protocols can be removed without deprecation.

---

**Priority:** Security, correctness, simplicity. When in doubt, ask.
