# DNAC - Development Guidelines

**Last Updated:** 2026-08-27 | **Status:** DEVNET (live 7-witness cluster; will be wiped — no real user data) | **Version:** v0.18.6

**Note:** Framework rules (ORCHESTRATOR CYCLE O1-O10, agent classes, identity override, protocol mode, violations) are in root `/opt/dna/CLAUDE.md`. This file contains DNAC-specific guidelines only.

**Stake/delegation v1:** SHIPPED — `stake-delegation-v1` merged to `main` and deployed (stake-ranked committee, delegation, per-block reward accrual, pull-based claim). Ledger V2 S3 (2026-08-05) made the committee size governance-driven (`DNAC_CFG_TARGET_ACTIVE_COUNT`, 7 initial → 128 ceiling) and per-epoch snapshots the membership authority. Design doc: `dnac/docs/plans/2026-04-17-witness-stake-delegation-design.md` (local-only, gitignored). Sortition v2 (weighted random) is a future follow-up. Ledger V2 S4 (2026-08-05) added the INACTIVE domain registry: canonical DomainManifest/registry/readiness codec (`shared/dnac/domain_wire.{h,c}`), the compiled NATIVE_BUILTIN runtime table + fail-closed exact-tuple lookup (`nodus/src/witness/nodus_witness_runtime.{h,c}`), the staged activation scheduler (`nodus_witness_domreg.{h,c}` — quorum schedules, all-active activates, 2-epoch deadline, non-slashing unready exclusion via the ordinary S3 transition, set-change/ruleset boundaries never shared) and inactive V2 semantic admission (Type 11 still REJECT; 12-14 unavailable). No live consensus path touched. Ledger V2 S5 (2026-08-05) added the INACTIVE persistence + atomic-apply foundation: versioned schema (PRAGMA user_version = 5, atomic fail-closed migration, `utxo_set.domain_id` ownership backfill → DNA_CORE), canonical `DomainUpdate v1` (368 B, tags `DNA.DUPD/DUNODE/E.DUPD/DTXB/E.DUPDPRV.v1`), the single-transaction global-block apply engine (`nodus_witness_v2_apply.{h,c}` — 15 deterministic fault points, full-DB-digest rollback proof, replay/idempotency matrix, untouched-domain guard, per-domain + global resource enforcement), the V2 supply gate (1B/70M carve-out, shielded balance structurally zero) and the genesis-root cycle break (`DNA.SYSPAYL.v1` payload root: manifest.genesis_state_root = runtime-owned payload root, final head root = full 8-leg system root — a DAG, no fixed point). Ledger V2 S6 (2026-08-05) added the INACTIVE generic genesis/distribution manifest + claim layer: GenesisManifest v1 (`shared/dnac/manifest_wire.{h,c}`, tag `DNA.GMAN.v1` — versioned, presence-byte distribution section, fail-closed enums, consumer-neutral; NO chain_id field since chain_id derives from a hash over the manifest bytes), generic snapshot leaves + shape-derived inclusion proofs (`DNA.DSLEAF/DSNODE.v1`), DNA-native claims with committed-leaf-context nullifiers (`DNA.CLAIM/CLNUL/CLUTXO.v1`), REAL manifest_root/claims_root legs (empty = the frozen S2 placeholders byte-identically), schema v6 (`v2_manifests`/`v2_dist_state`/`v2_claims_spent`), claims inside the ONE S5 apply transaction (3 new fault points), and the supply equation's single new owner `unclaimed_distribution` (a claim moves value, never mints). Post-deadline v1 = RETAIN only; types 12-14 still unassigned; no live consensus path touched. A Ledger V2 **genericity correction pass** (2026-08-06) then removed every domain default from the generic layer: distributions commit an EXPLICIT `target_domain_id` + bounded opaque `target_asset_ref`; claims reference the manifest BY HASH (`manifest_seq` demoted to an internal DB locator) and their nullifiers bind chain ‖ manifest_hash ‖ target domain ‖ target asset ‖ leaf hash; the claim engine routes through the registered TARGET runtime's `claim_apply` hook (never creating an output or picking a domain itself); `utxo_set.domain_id` lost its schema default (explicit ownership, legacy → CORE as a one-time migration literal); `v2_blocks` dropped its named `system_root`/`core_root` columns; the supply gate became a runtime-owned invariant dispatcher (the DNAC equation lives in the CORE runtime hook and never sums another domain's asset); the S5 apply engine + V2 genesis are registry-driven for any registered domain set. Correction pass 2 (2026-08-06) locked two owner decisions: **native supply ownership → DNA_CORE** (`supply_root` moved out of `system_state_root` — now 7 legs — into `core_state_root` — now 6 legs; `DNA.SYSPAYL.v1` is 5 legs; issuance mutations move only the CORE root, SYSTEM↔CORE native moves are generic cross-domain ops, fee burn is CORE-local) and the **canonical DomainHead lifecycle** (no synthesized heads: one activation constructor creates the height-0 head in the exact activation block, root bound to the registry-committed `genesis_state_root` via the optional `payload_root` runtime hook; ACTIVE requires persisted head + resolvable runtime else consensus failure; PAUSED/RETIRED heads carried byte-unchanged without the runtime; RETIRED terminal; unknown states fail closed). Ledger V2 S7 (2026-08-06) added the INACTIVE **D=24 production pool state**: canonical pool-state commitments (`shared/dnac/pool_wire.{h,c}` — tags `DNA.POOLCFG/POOLLEAF/POOLNODE/PNUL/PHIST.v1`, empty `DNA.E.PNUL/E.PHIST.v1`, zero-pool domain = frozen S2 `DNA.E.POOLS.v1` byte-identical; note roots/commitments/nullifiers = 4 canonical Goldilocks lanes u64 BE, the shielded-wire encoding), the witness pool module (`nodus_witness_v2_pools.{h,c}` — O(D) frontier persistence appending THROUGH the shipped `shielded_tree`, fail-closed frontier↔count↔root mutual verification, derived `v2_pool_notes` path-serving list, canonical `(tx index, slot)` mutation order, devnet **R=720** finalized-root history with single-oldest eviction + retained-window anchor authority + reappearance fail-close, O(1) incremental nullifier accumulator with strict inserts, checked u64 balance), schema **v7** (`v2_pools`/`v2_pool_notes`/`v2_pool_nullifiers`/`v2_pool_roots`, atomic 6→7, exact column-shape verify, stage faults, v8+ fail-closed), apply phase 6p + fault points **F19-F25** (S1-S6 ids frozen), the REAL per-domain `pools_root` leg, the supply equation's `shielded ≡ 0` placeholder REPLACED by real committed native-asset pool balances (foreign asset/domain excluded), and the generic OPTIONAL `state_init` activation hook through which the CORE runtime instantiates its configured native pool (`DNAC_SHIELDED_POOL_V1`, D=24, R=720) at genesis/activation — before the registry commits `genesis_state_root`, idempotent inside `head_activate`. Mainnet R remains OPEN. Type 11 still REJECT; 12-14 unassigned; no live consensus path calls any pool mutation; the S3 live-shrink/crash activation gate is unchanged. Ledger V2 **S9 Gate 2** (2026-08-06, slices W0-W5) added the INACTIVE **SHIELD/UNSHIELD V3 wire + native stateless verification substrate**: tx types `DNAC_TX_SHIELD = 12` / `DNAC_TX_UNSHIELD = 13` appended to `dnac_tx_type_t` (`dnac/include/dnac/dnac.h`), mirrored as `NODUS_W_TX_SHIELD`/`NODUS_W_TX_UNSHIELD` (`nodus/src/witness/nodus_witness.h`) and OWNED by `DNA_DOMAIN_CORE` via new `dna_tx_type_owner()` rows (`shared/dnac/ledger_ids.h`) — type 14 stays UNASSIGNED, type 8 stays retired, and the legacy V2 deserialize type gate (`dnac/src/transaction/serialize.c`) became the LITERAL `11` rather than the enum tail so the frozen V2 acceptance set can never widen when the enum grows; the S8 V3 shielded-body codec's test debt closed (`dnac_txw3_shielded_encode`/`_decode`/`_check_header` shipped with zero callers and zero tests — `nodus/tests/test_tx_wire_v3.c` now carries round-trips, a byte-exact offset KAT and the full negative matrix, plus a fail-close repair to `dnac_txw3_shielded_decode` whose two early length rejects returned without zeroing `*out`); the canonical **transparent-leg section v1** (`shared/dnac/tx_wire.{h,c}` §6 — `tleg_version(1)=0x01 ‖ num_tin ‖ nullifier[64]×num_tin` STRICTLY ASCENDING `‖ num_tout ‖ (fp[129] ‖ amount u64 BE ≥1 ‖ seed[32])×num_tout ‖ num_signers ‖ (pubkey[2592] ‖ signature[4627])×num_signers`, `LEG_LEN = 4 + 64·num_tin + 169·num_tout + 7219·num_signers`, worst legal leg 32,608 B; a PREFIX decode reporting `consumed` — the caller hands the remainder to the shielded decoder — and POLICY-NEUTRAL by construction: no tx_type/domain/pool branch, the per-type count windows are native rules) with its commitment `dnac_tleg_commit` = SHA3-512 over the 16-byte tag `"DNA.TLEG.v1"`+5×0x00 ‖ counts ‖ inputs ‖ outputs ‖ signer PUBKEYS — signatures deliberately EXCLUDED (a signature cannot cover itself, and the commitment must be computable before signing), `tleg_version` and `tx_type` excluded too (framing; tx_type is bound once by `sighash_v5`'s ExecutionContext) — filling the frozen `sighash_v5` slot at preimage **offset 453** so **no offset, length, tag or field of `sighash_v5` moves and no vector moves**, with the empty form `"DNA.E.TLEG.v1"` a distinct domain; the **native stateless verifier** `dnac_v3_native_verify_stateless` (`shared/crypto/zk/native_verify_v3.{c,h}`, ZERO production callers) with its frozen check order and per-type policy (11: priv 1..4/1..4, boundary_in 0, boundary_out == committed_fee · 12 SHIELD: priv_in 0 with all-zero anchor and nullifier slots, priv_out 1..4, num_tin ≥1, num_signers ≥1, boundary_out 0, boundary_in ≥1 · 13 UNSHIELD: priv_in 1..4, priv_out 0..1, num_tin 0, num_signers 0, exactly one transparent output, boundary_in 0, boundary_out == recipient_amount + committed_fee, checked add) and seven APPENDED status classes (values 0..17 UNMOVED; 18 `ERR_TLEG_DECODE`, 19 `ERR_TLEG_ORDER` RESERVED-never-assigned, 20 `ERR_TYPE_RULE`, 21 `ERR_TLEG_ARITH`, 22 `ERR_SIG`, 23 `ERR_NF_DUP`, 24 `ERR_TIMESTAMP`); and the CORE runtime descriptor (`nodus/src/witness/nodus_witness_runtime.c`) now owning `{1,2,3,11,12,13}` with rule ids 5/6 appended (`DNA_CORERULE_SHIELD_C3_REJECT`, `DNA_CORERULE_UNSHIELD_C3_REJECT`), `rt_admit_common` hard-stopping 11, 12 AND 13 unconditionally BEFORE the pool rule so `DNAC_SHIELDED_POOL_V1` can never become an admit path, declared work units 12=101 / 13=100 (unreachable while admission rejects), and `CORE_RULESET_HASH` consequently RE-DERIVED (`13bc5fa9…669ada` → `e0a0bc43…6ee77429`; the SYSTEM digest is UNCHANGED). **Nothing is activated:** Type 11 still terminates in an unconditional REJECT, 12/13 are defined and owned but REJECT-unconditional, the V3 wire is still rejected by every live admission path (all gate on wire version byte 2), and no consensus path calls any of it. The Ledger V2 **execution season** (2026-08-12, `feat/ledger-v2-s1-s3` line) then replaced the S5 raw-SQL op scaffold with the typed/mediated/metered execution path and made `RulesetDescriptor` **v2** (appending the committed `meter_policy_digest`), so BOTH compiled ruleset hashes were re-derived again — SYSTEM `f2dcdefa…4cce` → `89362213…7896c2`, CORE `e0a0bc43…6ee77429` → `ad98a036…88a8e6f3` (the S9 values above are historical); the layer stays INACTIVE end to end. Details: the header contracts in `nodus/src/witness/nodus_witness_v2_apply.h` (engine flow, FAULT-vs-VERDICT return contract, honest labels), `nodus/src/witness/nodus_witness_runtime.h` (execution hooks + metering authority) and `shared/dnac/res_meter.h` (policy identity digest). Ledger V2 **O15C** (2026-08-19) appended the COMPILE-GATED (CMake `NODUS_V2_ACTIVATION`, default OFF — production builds reject both) legacy-lane governance tx types **15 `DNAC_TX_V2_SCHEDULE` / 16 `DNAC_TX_V2_READY`** (type 14 stays UNASSIGNED; 12/13 stay V3-only and undeserializable on the legacy wire) with the shared activation codec `shared/dnac/activation_wire.{h,c}` (target digest D, schedule/cancel/readiness, terminal source binding `DNA.LEGACY.TERM.v1`) and the legacy state_root **v4/0x04** 6-leg composition (…‖ activation_root); the migration seam derives the successor V2 chain deterministically from the committed terminal state — see nodus/CLAUDE.md "Committed V2 Activation Authority + Migration Seam".

**Ledger V2 burn season (2026-08-13):** the transparent DNA_CORE runtime set is COMPLETE on the (still INACTIVE) V2 boundary — BURN (runtime_op 2) and TOKEN_CREATE (runtime_op 3) joined SPEND, under **CORE ruleset_version 2** (v1 retired, resolves nothing; `CORE_RULESET_HASH` re-derived `ad98a036…e6f3` → `746f584a…67a1`). BURN = SPEND surface + explicit `burn_amount` (everything destroyed lands in the ONE legacy `supply_tracking.total_burned` bucket; token burns fail closed). TOKEN_CREATE = opaque caller-chosen token_id + client-rule metadata bounds, output[0] is the registry-committed genesis output, `NODUS_W_TOKEN_CREATE_FEE` floor + exact native conservation, duplicate ids HARD-rejected (legacy INSERT OR IGNORE retired on the V2 lane), registry timestamp pinned 0. Worst legal envelope re-derived 813,904 → 813,947 B (CC + maximal TOKEN_CREATE leg); ceiling 2^20 unchanged. No live consensus path touched; types 11/12/13 stay REJECT. Details: nodus/CLAUDE.md burn-season section.

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

DNAC = **DNA Chain** — a post-quantum UTXO chain (with a ZK/shielded track under development) built on top of DNA Connect.

| Component | Technology |
|-----------|------------|
| Token Model | UTXO |
| Signatures | Dilithium5 (Post-Quantum) |
| Transport | Nodus TCP witness client (nodus SDK) — DHT storage removed v0.12.0 |
| Double-Spend Prevention | Witness BFT — chain-derived committee (F17/v0.15.0+; roster is transport-only) |
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

### Shielded TX — two frozen lanes, NEITHER live

There are **two independent shielded lanes** and they must never be conflated:
lane A is the legacy V2 carrier (below, frozen byte-for-byte), lane B is the
Wire V3 carrier the Ledger V2 work builds on. Both are consensus-DEAD today.

#### Lane A — legacy V2 wire, type 11, dual-mode V4 (Phase-C, frozen)

**SCOPE: this paragraph describes ONLY the legacy V2 carrier** (`version` byte
2, 82-byte header, `DNAC_TX_V4` preimage tag). It is frozen and permanently
REJECTED for type 11; the S8/S9 V3 objects in lane B do not replace or modify
any of it.

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

#### Lane B — Wire V3 shielded body + transparent leg (Ledger V2 S8 + S9, INACTIVE)

**Wire V3 is a different carrier, not a new version of lane A** — its own
header and codec live in `shared/dnac/tx_wire.{h,c}` (Ledger V2 S1), and
"Wire V3" is not "Ledger V3". Its objects:

- **V3 shielded body (S8)** — a **359-byte** fixed section, section version
  `0x02` (`DNAC_TXW3_SECT_VERSION`), codec `dnac_txw3_shielded_encode` /
  `_decode` / `_check_header` in `shared/dnac/tx_wire.{h,c}` §4. It shipped
  with **zero callers and zero tests**; S9 W1 closed that debt in
  `nodus/tests/test_tx_wire_v3.c` (round-trips for the transfer shape, the
  zero-input SHIELD shape and 4-in/4-out at the canonical lane maximum `p−1`;
  a byte-exact offset KAT against hand-written literals; the full
  encode/decode negative matrix) and repaired a fail-close hole: the decoder's
  two early length rejects returned without zeroing `*out`, contradicting the
  header's "zeroed on any rejection" contract.
- **Statement binding = `sighash_v5`** (`dnac_sighash_v5`), NOT lane A's
  `sighash_v4`. Its layout is FROZEN and S9 moved nothing in it: the
  transparent-leg commitment fills the already-reserved slot at preimage
  **offset 453**, so no offset, length, tag or field of `sighash_v5` moves and
  **no vector moves**. `tx_type` is bound once, by `sighash_v5`'s
  ExecutionContext.
- **Transparent-leg section v1 (S9 W2)** — `shared/dnac/tx_wire.{h,c}` §6:
  `tleg_version(1)=0x01 ‖ num_tin(1) ‖ nullifier[64]×num_tin` (**strictly
  ascending**) `‖ num_tout(1) ‖ (fp[129] ‖ amount u64 BE ≥1 ‖ seed[32])×num_tout
  ‖ num_signers(1) ‖ (pubkey[2592] ‖ signature[4627])×num_signers`;
  `LEG_LEN = 4 + 64·num_tin + 169·num_tout + 7219·num_signers`, worst legal leg
  **32,608 B**. Unlike §2/§4 this is a **PREFIX** decode: it walks ONE leg and
  reports `consumed`, and the caller hands the remainder to the shielded
  decoder. It is **policy-neutral** — no tx_type/domain/pool branch lives in
  the codec; the per-type count windows are native rules. Commitment
  `dnac_tleg_commit` = SHA3-512 over the 16-byte tag `"DNA.TLEG.v1"`+5×`0x00`
  ‖ counts ‖ inputs ‖ outputs ‖ signer **PUBKEYS** — signatures deliberately
  EXCLUDED (a signature cannot cover itself, and the commitment must be
  computable before signing); `tleg_version` and `tx_type` excluded as framing.
  The empty form `"DNA.E.TLEG.v1"` is a distinct domain.
- **Types 12/13 (S9 W0)** — `DNAC_TX_SHIELD = 12`, `DNAC_TX_UNSHIELD = 13`
  appended to `dnac_tx_type_t` (`dnac/include/dnac/dnac.h`), mirrored as
  `NODUS_W_TX_SHIELD`/`NODUS_W_TX_UNSHIELD` and owned by `DNA_DOMAIN_CORE`
  (`dna_tx_type_owner()`, `shared/dnac/ledger_ids.h`). **Type 14 stays
  UNASSIGNED; type 8 stays retired.** The legacy V2 deserialize type gate in
  `serialize.c` is now the LITERAL `11`, deliberately **not** the enum tail, so
  the frozen V2 acceptance set (0..11, with 11 rejected downstream) cannot
  widen when the enum grows. `nodus_witness_verify.c` gained a NAMED reject
  branch for 12/13 in the same position as the type-11 dispatch — the verdict
  is unchanged (both already died as a fallthrough), only the diagnosis is new.
- **Native stateless verifier (S9 W3)** —
  `dnac_v3_native_verify_stateless(tx_bytes, tx_len, nctx, out)` in
  `shared/crypto/zk/native_verify_v3.{c,h}`, **zero production callers**.
  Frozen check order: generic decode → type gate `{11,12,13}` → body split
  (leg for 12/13) → ExecutionContext/context match → fee+expiry mirrors +
  min-fee floor → per-type count windows and boundary equalities →
  transparent-leg commitment → `sighash_v5` → `tx_binding` equality → type-12
  signature verification → in-TX private nullifier distinctness → proof →
  exported deferred-state expectations. Per-type policy — **11**: `priv_in`
  1..4, `priv_out` 1..4, `boundary_in == 0`, `boundary_out == committed_fee`;
  **12 (SHIELD)**: `priv_in == 0` (all-zero anchor, all-zero nullifier slots),
  `priv_out` 1..4, `num_tin ≥ 1`, `num_signers ≥ 1`, `boundary_out == 0`,
  `boundary_in ≥ 1`; **13 (UNSHIELD)**: `priv_in` 1..4, `priv_out` 0..1,
  `num_tin == 0`, `num_signers == 0`, exactly one transparent output,
  `boundary_in == 0`, `boundary_out == recipient_amount + committed_fee`
  (checked add). All transparent sums are checked; overflow rejects. Seven
  status classes APPENDED to `dnac_shielded_verify_status_t` (0..17 UNMOVED):
  18 `ERR_TLEG_DECODE`, 19 `ERR_TLEG_ORDER` (reserved), 20 `ERR_TYPE_RULE`, 21
  `ERR_TLEG_ARITH`, 22 `ERR_SIG`, 23 `ERR_NF_DUP`, 24 `ERR_TIMESTAMP`.

**Seams — one closed by the correction pass, two open:**
1. Type-12 Dilithium5 verification is a **caller-supplied function pointer**
   (the standalone zk build cannot link `qgp_dsa87_verify` without dragging in
   the vendored dsa library and its circular `randombytes` dependency). A NULL
   verifier on type 12 yields `ERR_SIG` — **never a skip**. Still open
   (`OBL-S9-SIGFN-PIN`): the wiring slice must pin the real symbol.
2. ✔ **CLOSED by the S9 CORRECTION PASS (2026-08-06).** Types 12/13 used to get
   no proof verification at all, because `dnac_shielded_verify_statement`
   derived the leg commitment itself (always tagged-empty) and a populated leg
   therefore mis-bound. The commitment moved into
   `dnac_shielded_verify_ctx_t.tleg_commit`, so the native verifier computes it
   once — tagged-empty for 11, real `DNA.TLEG.v1` for 12/13 — and **all three
   types now run the same real aggregate verifier**. `ERR_PROOF_DEFERRED` is
   DELETED and value 24 now carries `ERR_TIMESTAMP`. Proven with runtime-
   generated real proofs in `test_native_verify_v3_proofs` (11, 12, 13-with-
   change and 13-without-change all reach OK; leg substitution, boundary
   substitution, an empty-leg-on-populated-statement and an all-zero
   `tleg_commit` all reject). The frozen 581-byte `sighash_v5`, the 45 publics,
   D, the width, the FRI params and every vector are UNCHANGED.
3. `ERR_TLEG_ORDER` (19) is **RESERVED — declared, never assigned**: the shared
   codec folds ordering and duplicate rejects into a single `-1`, so the native
   layer cannot distinguish them. Reserved rather than reused so a future codec
   that reports ordering separately can take the value without renumbering.

**Timestamp rule (S9 correction, closes `OBL-S9-TS-BIND`):** for types 11/12/13
the V3 header `timestamp` is **consensus-inert and pinned to 0**; a non-zero
value is `ERR_TIMESTAMP` (24), returned before any proof work. `sighash_v5`
excludes consensus-time fields and type-12 signers sign `sighash_v5`, so a free
timestamp would be a wire byte nothing binds — a relayer could re-stamp a signed
transaction into a different txid for the same statement. The preimage is NOT
enlarged; the generic codec stays policy-neutral; `expiry_height` is untouched.

⚠ **`OBL-S9-CARRIER-CAP` (measured, blocks activation):** a production aggregate
proof is **2,474,998 B**; a type-11 V3 body would need 2,475,357 B against
`DNAC_TXW3_MAX_BODY_LEN = 65,426` — **37.8× over**. No production shielded
transaction can be framed as a V3 transaction today. This is a pre-existing
carrier constraint (raising the cap is a consensus-relevant wire change owned by
the activation season), and it is a further independent reason 11/12/13 cannot
be admitted. Pinned by cases C-1/C-2 of the real-proof gate.

**Admission (S9 W4):** the compiled CORE runtime descriptor owns
`{1,2,3,11,12,13}` with rule ids 5/6 appended (`DNA_CORERULE_SHIELD_C3_REJECT`,
`DNA_CORERULE_UNSHIELD_C3_REJECT`); `rt_admit_common` hard-stops 11, 12 AND 13
unconditionally and that stop sits **BEFORE** the pool rule, so
`DNAC_SHIELDED_POOL_V1` can never become an admit path. Declared work units are
12 = 101 / 13 = 100 (unreachable while admission rejects). Because the
RulesetDescriptor digest commits the rule and type lists, `CORE_RULESET_HASH`
was RE-DERIVED (`13bc5fa9…669ada` → `e0a0bc43…6ee77429`); the **SYSTEM digest is
UNCHANGED**. The V3 wire itself is still rejected by every live admission path
(all gate on wire version byte 2).

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
  forbidden — crypto audits use parallel independent subagents, scaled per
  root CLAUDE.md `RED-TEAM ÖLÇEĞİ` (8-13 agents ONLY for consensus/shipped
  crypto with live consumers; zero-consumer design = 1-2).
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

**Current Phase:** DEVNET — live 7-witness cluster with tester balances; the chain will be wiped (no real user data to protect). Public messaging may say "live testnet" (`project_cpunk_dna_announcement`), but for engineering decisions this is a devnet — the messenger RC rule does NOT apply here (`feedback_no_derived_requirements`).

**Breaking Changes:** ALLOWED but require a **chain wipe** bundled with a stop-all deploy (memory: `feedback_consensus_deploy_stop_all`) — never a rolling deploy for consensus/block-format changes. Clean implementations preferred; legacy code/protocols can be removed without deprecation.

---

**Priority:** Security, correctness, simplicity. When in doubt, ask.
