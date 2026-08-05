# DNAC - Development Guidelines

**Last Updated:** 2026-08-05 | **Status:** TESTNET (live 7-witness production cluster) | **Version:** v0.18.0-ledgerv2-s3

**Note:** Framework rules (ORCHESTRATOR CYCLE O1-O10, agent classes, identity override, protocol mode, violations) are in root `/opt/dna/CLAUDE.md`. This file contains DNAC-specific guidelines only.

**Stake/delegation v1:** SHIPPED — `stake-delegation-v1` merged to `main` and deployed (stake-ranked committee, delegation, per-block reward accrual, pull-based claim). Ledger V2 S3 (2026-08-05) made the committee size governance-driven (`DNAC_CFG_TARGET_ACTIVE_COUNT`, 7 initial → 128 ceiling) and per-epoch snapshots the membership authority. Design doc: `dnac/docs/plans/2026-04-17-witness-stake-delegation-design.md` (local-only, gitignored). Sortition v2 (weighted random) is a future follow-up.

**Active workstream:** v3 ZK (STARK range proofs) — see "v3 ZK Workstream" section below.

---

## HARD RULE: NO FLAKY BEHAVIOR

**DNAC is the consensus core. Flaky / non-deterministic code is the single fastest path to a chain split.** See root `/opt/dna/CLAUDE.md` (`PRIMARY OBJECTIVE: DETERMINISM`) and memory `feedback_no_flaky_blockchain.md` for the full rule.

**DNAC-specific examples (all forbidden):**
- UTXO selection / coin selection that depends on iteration order of an unordered set — must sort by deterministic key (e.g., outpoint hash) before selection.
- Nullifier insert/check order that depends on map traversal — explicit sorted ordering required.
- `state_root` divergence between witnesses on the same block: any difference is a P0 chain-split bug. Genesis Protocol harness 7/7 enforcement catches this; never bypass or weaken the harness.
- Double-spend detection that "rarely misses a race" — the rare case ships and burns money.
- Committee selection / sortition without a seeded, on-chain-derived PRNG (block hash + epoch, never `rand()`).
- Fee calculation order-dependent on input ordering — must be commutative or explicitly ordered.
- Per-block reward accrual that depends on local node clock — must be derived from block height / on-chain state only.
- TX validation that passes locally but fails on a peer — the validator disagreement is the bug; the deploy is blocked until reproduced and fixed.
- Tests that pass with `ctest -j1` but fail with `ctest -j$(nproc)` — race in production code, not flakiness in tests.

**Stake/delegation feature:** every code path that affects committee membership, reward accrual, or claim must be reviewed against this rule before merge. Sortition v2 (memory: `project_dnac_stake_v2_sortition`) MUST use deterministic seeded PRNG.

If a Genesis Protocol harness run is not 7/7 identical `state_root`, that is a deploy-blocker, not a "let's investigate later." **No production deploy on a flaky harness.**

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
| ZK (v3, in progress) | STARK range proofs (Plonky3-grounded C ports in `shared/crypto/zk/`) |

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
| `DNAC_TX_HEADER_SIZE` | 82 | v0.17.1 TX wire header (see below) |
| `DNAC_MIN_FEE_RAW` | 1,000,000 | 0.01 DNAC minimum fee for non-GENESIS |
| `DNAC_PROTOCOL_VERSION` | 2 (`V2`) | Current TX wire version |

---

## TX Wire Format (v2 — since v0.17.1)

Canonical layout from `dnac/src/transaction/serialize.c`. Offsets in the
82-byte header are fixed constants exposed in `dnac/include/dnac/transaction.h`
(`DNAC_TX_HEADER_SIZE`, `DNAC_TX_COMMITTED_FEE_OFF`, `DNAC_TX_BODY_OFF`).

```
offset  size  field
------  ----  -----
     0     1  version            (u8, DNAC_PROTOCOL_VERSION = 2)
     1     1  type               (u8, DNAC_TX_*)
     2     8  timestamp          (u64 LE on wire, BE in preimage)
    10    64  tx_hash            (SHA3-512 over preimage below)
    74     8  committed_fee     (u64 BE, v0.17.1+ — fee the TX pays)
    82     1  input_count
    83   ...  inputs             each: nullifier(64) + amount(u64 LE) + token_id(64) = 136B
    ...    1  output_count
    ...  ...  outputs            each: version(1) + fp(129) + amount(u64 LE) + token_id(64)
                                       + seed(32) + memo_len(1) + memo[memo_len]
    ...    1  witness_count
    ...  ...  witnesses          each: witness_id(32) + sig(4627) + ts(8) + pk(2592)
    ...    1  signer_count
    ...  ...  signers            each: pubkey(2592) + sig(4627)
    ...  ...  type-specific appended fields (STAKE/DELEGATE/etc.)
    ...    1  has_chain_def      (u8, genesis TX only — optional trailer)
    ...  ...  chain_def blob     (if has_chain_def)
```

**Preimage** (ONE shared implementation since Ledger V2 S1, 2026-08-05:
`shared/dnac/tx_wire.c::dnac_txw_legacy_tx_hash` — `dnac_tx_compute_hash`
serializes-then-delegates and `nodus_witness_recompute_tx_hash` is a thin
wrapper; the witness's independent hand-written mirror is RETIRED. Byte
identity pinned by `nodus/tests/test_tx_hash_kat.c` literals captured from
the pre-S1 algorithm. All multi-byte integers BIG-ENDIAN):
```
"DNAC_TX_V2\0" (11B domain separator, SEC-06) ||
version || type || timestamp_BE || chain_id[32] || committed_fee_BE ||
inputs (nullifier + amount_BE + token_id)... ||
outputs (version + fp + amount_BE + token_id + seed + memo_len + memo)... ||
signer_count || signer_pubkeys... ||
type_specific_appended_fields
```

**Min-fee gate:** non-GENESIS TXs must have `committed_fee >= DNAC_MIN_FEE_RAW`.
Witness `verify.c::Check 0` rejects before expensive Dilithium5 sig verify.

### Shielded TX (type 11, dual-mode V4 — Phase-C, NOT live)

`DNAC_TX_SHIELDED = 11` (S5, 2026-07-17) keeps the 82-byte header but: the
tx-hash preimage uses its OWN domain tag `"DNAC_TX_V4\0"`; transparent
`input_count`/`output_count` MUST be 0 (D7.1); `signer_count` MUST be 0 (spend
authority is the STARK proof's ak/nk binding); the body carries a shielded
section after the (empty) signers section: `anchor[4] ‖ num_input ‖
nf_set[4][4] ‖ num_output ‖ output_commit[4][4] ‖ fee ‖ tx_binding[4]` (330 B,
all lanes u64 **BIG-ENDIAN**, canonical `< p`, unused slots zero) +
`fri_proof_len(u32 BE)` + the opaque proof blob (blob is NOT in the tx-hash
preimage). `fee` MUST equal header `committed_fee@74` (D7.2). Statement
binding: `tx_binding = conf_txbind_map(sighash_v4)` where `sighash_v4 =
SHA3-512("DNAC_SIGHASH_V4\0" ‖ chain_id ‖ counts/slots ‖ fee ‖ anchor)`
(`dnac_tx_shielded_sighash`, serialize.c). Verify entry (C2.1, consensus-
linked): `dnac_shielded_verify_statement` (`shared/crypto/zk/shielded_verify.h`).
**Admission: the witness REJECTS type-11 unconditionally through all of C2**
(`nodus_witness_verify.c::verify_shielded_tx`) — the accept-flip lands at C3
atomically with the shielded apply case + state_root v4. Full design:
`dnac/docs/plans/2026-07-17-dm-s5-v4-wire-design.md` + `2026-07-22-c2-*.md`
(local-only).

**When bumping header size again:** grep every `\b<old_size>\b` and
`tx_len [<>] <old_size>` literal across `dnac/src/transaction/` AND
`nodus/src/witness/`. The v1→v2 migration missed ~10 sites in nodus
witness code (handlers, peer, bft, db, sync, chain_config, verify) and
cost hours of debugging. Consolidate via `DNAC_TX_HEADER_SIZE` and
`dnac_tx_read_committed_fee()` (static inline in `transaction.h` so
`libnodus` standalone builds link without `libdna`).

---

## Witness System (Embedded in Nodus)

The standalone `dnac-witness` binary was removed in v0.10.3. Witness logic runs inside `nodus-server` via `nodus/src/witness/`.

Since nodus v0.15.0 (F17 committee enforcement), the BFT **voting authority** is the chain-derived committee — leader election, quorum, and vote counting all consult `nodus_committee_get_for_block()`, not the gossip roster. Since Ledger V2 S3 (nodus v0.19.0) that function serves the epoch's committed validator-set snapshot when one exists. The **gossip roster** is now transport-only: it serves peer discovery (`dnac_discover_witnesses()`, TCP 4004 handshake) and a `witness_id → pubkey` lookup table, but does not gate consensus participation.

### BFT Consensus

| Parameter | Value | Description |
|-----------|-------|-------------|
| Leader Election | `(epoch + view) % N` | `N` = the active set governing the height; rotates each hour |
| Quorum | `dna_bft_quorum(n) = (2n)/3+1` | `shared/dnac/ledger_ids.h`; `n` from the epoch's validator-set snapshot, never a compile-time size (n=7 ⇒ 5) |
| Round Timeout | 5000ms | Triggers view change |
| Max View Changes | 3 | Per request before error |

**Phases:** PROPOSE → PREVOTE → PRECOMMIT → COMMIT

---

## Committee, Stake & Delegation

The BFT voting authority is a **stake-ranked top-N active validator set** derived entirely from on-chain state. Witness discovery and BFT roster both consult chain state — not DHT registrations, not TCP 4002 peer lists.

Since Ledger V2 S3 the set size `N` is **governance-driven, not a constant**: it is the chain-config parameter `DNAC_CFG_TARGET_ACTIVE_COUNT` (param_id 4), sampled at the **epoch start height** (`nodus_witness_committee.c::committee_target_for_epoch`), defaulting to `DNAC_COMMITTEE_SIZE` = 7 and capped at `DNAC_MAX_ACTIVE_VALIDATORS` = 128. Sampling at the epoch start is what makes the parameter epoch-boundary-effective by construction — a mid-epoch `effective_block` cannot resize a live committee.

**Key properties:**

| Property | Value |
|----------|-------|
| Committee size | Governance target, top-N by total stake (self + delegations). 7 initial/floor (`DNAC_COMMITTEE_SIZE`), 128 release ceiling (`DNAC_MAX_ACTIVE_VALIDATORS`) |
| Self-bond | `>= DNAC_SELF_STAKE_AMOUNT` (10,000,000 DNAC). Extra self-bond is allowed (S3 O-3) |
| Delegator stake | Unbounded (any holder may delegate any amount) |
| Rotation | Per-epoch, 1 hour (720 blocks × 5 s); membership changes ONLY at epoch boundaries |
| Authority | The per-epoch validator-set **snapshot**, frozen one epoch ahead |
| Rewards | Per-block fee-pool accrual, pull-based `CLAIM_REWARD` TX |
| Commission | Per-validator bps (set via `VALIDATOR_UPDATE`) |
| Slashing | Not in v1 (deferred to v2 with sortition) |

**Snapshot is the authority (S3).** At each boundary the witness freezes the set for the epoch **one ahead** into `validator_set_snapshots` (canonical codec `shared/dnac/vset_wire.h`, tag `"DNA.VSET.v1"`, 78-byte header + 2642 bytes/entry); genesis seeds epochs `0` and `DNAC_EPOCH_LENGTH`. Committee lookup, the boundary status flips, and historical QC verification all consume that one committed set — never a live recomputation, which would drift from the frozen set after any mid-epoch `DELEGATE`/`UNSTAKE`. A snapshot row that fails integrity is a fault: the lookup fails closed.

**Validator status (`dnac/include/dnac/validator.h`).** S3 added `DNAC_VALIDATOR_ELIGIBLE = 4` — bonded and tenured, but **not seated this epoch**; the bond stays locked and the row stays a candidate for the next boundary. Boundary flips move `ACTIVE ↔ ELIGIBLE` per the epoch's snapshot. `DELEGATE`, `UNSTAKE` and `VALIDATOR_UPDATE` accept `ELIGIBLE` targets (both are BONDED states); committee-scoped rules — Rule N liveness / auto-retire, attendance, reward settlement — stay `ACTIVE`-scoped. Values 0-3 (`ACTIVE`, `RETIRING`, `UNSTAKED`, `AUTO_RETIRED`) are unchanged and wire-stable; 4 is appended.

**Self-bond derivation (S3 O-3).** `apply_stake` stores what the STAKE TX actually locked — `bond = Σnative_in − Σnative_out − committed_fee` — into `validators.self_stake`, requiring `bond >= DNAC_SELF_STAKE_AMOUNT` rather than exact equality. Ranking mechanics (self + external delegated) are unchanged. `UNSTAKE` graduation pays back the record's **actual** bond and zeroes `self_stake`, so the supply invariant sees the value in exactly one place.

**TX types (v0.17):** `STAKE`, `UNSTAKE`, `DELEGATE`, `UNDELEGATE`, `CLAIM_REWARD`, `VALIDATOR_UPDATE`. Existing BFT (PBFT, `N = 3f+1`), multi-signer TX infrastructure (v0.11 `signers[]` array), and Merkle `state_root` are preserved. Roster authority is chain-derived, which replaces the paths documented in `nodus/docs/DYNAMIC_WITNESS_DESIGN.md` (now superseded).

See `dnac/docs/plans/2026-04-17-witness-stake-delegation-design.md` for the full design + red-team audit.

---

## Hard-Fork Mechanism v1 (`DNAC_TX_CHAIN_CONFIG`, 2026-04-19)

Committee-voted consensus parameter changes without chain wipe. A quorum of
the committee signs a proposal preimage and a `DNAC_TX_CHAIN_CONFIG` TX is
broadcast carrying the votes; on commit the override is stored in
`chain_config_history` and contributes to `state_root` via
`chain_config_root`. Consumer sites read active overrides via
`nodus_chain_config_get_u64(param_id, current_block, default)`.

**Supported parameters:**

| param_id | Constant | Range | Consumer |
|----------|----------|-------|----------|
| 1 | `DNAC_CFG_MAX_TXS_PER_BLOCK` | `[1, 10]` | BFT batch cap |
| 2 | `DNAC_CFG_BLOCK_INTERVAL_SEC` | `[1, 15]` | Proposer timer (future) |
| 3 | `DNAC_CFG_INFLATION_START_BLOCK` | `[0, 2^48]` | Inflation mint |
| 4 | `DNAC_CFG_TARGET_ACTIVE_COUNT` | `[7, 128]` | committee selection (epoch-start sampled) |

**Consensus rules** (enforced in `nodus_chain_config_apply`):
- `dna_bft_quorum(committee_count)` = `(2n)/3+1` Dilithium5 signatures from
  the committee governing the signing height (`commit_block - 1`). At the
  DNA chain's 7 seats that is exactly 5, so live behaviour is unchanged;
  the fixed `[5, 7]` threshold is gone because the set size is dynamic.
  `DNAC_CHAIN_CONFIG_MIN_SIGS` = 5 / `DNAC_CHAIN_CONFIG_MAX_SIGS` = 128
  remain *shape* bounds on the wire, not the quorum rule
- Grace: `effective_block >= commit_block +
  DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS` (720 blocks = 1 h; ergonomic
  params) / `DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS` (17280 blocks = 24 h;
  safety-critical: block_interval, inflation_start, target_active_count).
  Both are `#ifndef`-guarded so the Genesis Protocol short-epoch harness
  can override them at compile time; production builds never define them
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

**Shipped (all stages, 2026-04-19):**
- Stage A — TX wire format + client verify (commit `69c4e44e`)
- Stage B — witness apply + DB schema + 5-input state_root (`ca628df1`)
- Stage C — vote primitives (digest / sign / verify) (`fd1e194e`)
- Stage D — finalize_block consumer wiring (`08baa4d1`)
- Stages C.2 / C.3 / E.1-E.3 — tier-2 vote-collect RPC + CLI verbs
  (`dna chain-config propose/list/history`), 16 commits total, last
  `6f1b36ab`
- Stage F (local 3-node harness) — skipped; covered by the 7-node
  Genesis Protocol harness + deploy-runbook smoke test instead

---

## v3 ZK Workstream (STARK Range Proofs)

**Architectural identity LOCKED 2026-05-21** (Bitcoin-style v3.0): uniform
SHA3-512 everywhere, Goldilocks field, within-TX aggregation scope, 1 TPS,
full-history storage model.

- **Code:** `shared/crypto/zk/` — Plonky3-grounded C ports (Goldilocks field,
  NTT, Keccak AIR, sponge, transcript, Merkle SMT, FRI fold/verify, STARK
  transcript priming, proof codecs). Own Makefile: `cd shared/crypto/zk && make test`.
- **Status / handoff:** `shared/crypto/zk/RESUME.md` — read this FIRST before
  any ZK work.
- **HARD RULE:** every cryptographic construct MUST cite a pinned reference
  (Plonky3 commit `file:line`, FIPS-202, NIST KAT). See root CLAUDE.md
  `ANA HEDEF: KAFADAN KRİPTO YASAK`. Same-day self-audit is circular and
  forbidden — crypto audits require 10+ parallel independent subagents.
- **Design docs:** `dnac/docs/plans/` (local-only, gitignored — never `git add`).

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

**Current Phase:** TESTNET — live 7-witness production cluster with real tester balances.

**Breaking Changes:** ALLOWED but require a **chain wipe** bundled with a stop-all deploy (memory: `feedback_consensus_deploy_stop_all`) — never a rolling deploy for consensus/block-format changes. Clean implementations preferred; legacy code/protocols can be removed without deprecation.

---

**Priority:** Security, correctness, simplicity. When in doubt, ask.
