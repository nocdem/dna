# Witness Stake & Delegation — v1 Design

**Date:** 2026-04-17
**Status:** DESIGN APPROVED (red-team audit in §7 complete; mitigations folded into §2–§6)
**Scope:** DNAC + Nodus — messenger unaffected
**Phase:** DESIGN (pre-alpha, breaking changes allowed, chain wipe required)

---

## 1. Goal & Scope

### 1.1 Goal

Replace the currently-permissioned witness roster with **stake-weighted deterministic top-7 committee**, with delegation, per-block reward accrual, pull-based claim, and market-driven validator commission — while preserving existing BFT consensus (PBFT, `N=3f+1`), multi-signer TX infrastructure (v0.11 signers[] array), and Merkle `state_root` committed to chain.

### 1.2 Non-goals (v1)

- Slashing (v2 with sortition).
- Weighted random sortition (v2).
- Committee rotation mid-epoch.
- Delegator-driven slashing remediation / insurance.
- Validator endpoint on-chain (stays in DHT).
- Committee size expansion beyond 7 (v2 with sortition).
- Commission markets beyond simple per-validator % (no compound schedules, no voting).
- Cross-chain stake / liquid staking tokens.
- Delegator-side commission cap (`max_accepted_bps`) — accepted risk, v2.

### 1.3 What this unlocks

- Economic security for DNAC consensus — every witness has 10M DNAC at risk.
- Validator competition on commission + uptime + delegation attraction.
- Reward distribution with clean supply invariance (no new-mint, only claim-materialization from existing fee pool).
- Foundation for v2 sortition and slashing without re-architecting state.
- Foundation for client-side committee proof verification (Merkle).

### 1.4 Locked decisions (from brainstorming)

| # | Decision | Choice |
|---|----------|--------|
| 1 | TX shape | Three+ dedicated TX types (STAKE, DELEGATE, UNSTAKE, UNDELEGATE, CLAIM_REWARD, VALIDATOR_UPDATE) |
| 2 | State location | Hybrid: witness DB hot index + Merkle commitment |
| 3 | Fee distribution | Pure state accumulator + pull-based CLAIM_REWARD (Cosmos F1 style) |
| 4 | Cooldown | Validator 24h (17,280 blocks). Delegator instant (after 1-epoch min hold, Rule O) |
| 5 | Genesis bootstrap | Pre-allocated 70M from 1B supply, 7 validators seeded in chain_def |
| 6 | Committee timing | 120-block epoch, 1-epoch lookback (post-commit snapshot), fixed committee size = 7, MIN_TENURE 2 epochs |
| 7 | Commission | Per-validator, market-driven, 0–10000 bps, increase ≥ full epoch notice; decrease immediate + clears pending |
| 8 | Misc | Min delegation **100 DNAC** (raised from 1 per F-DOS-02), max 64 delegations/delegator, dynamic dust threshold (§2.4 Rule L), endpoint stays on DHT, MAX_VALIDATORS = 128 |
| 9 | Security (post-audit) | Tree-tag domain separation (0x01–0x04), u128 BE accumulator, self-delegation ban (Rule S), liveness gate 80% (Rule N), unstake_destination_fp bound to STAKE preimage (immutable post-STAKE) |

---

## 2. TX Format Changes

### 2.1 New `dnac_tx_type_t` enum values

```c
typedef enum {
    DNAC_TX_GENESIS          = 0,   /* existing */
    DNAC_TX_SPEND            = 1,   /* existing */
    DNAC_TX_BURN             = 2,   /* existing */
    DNAC_TX_TOKEN_CREATE     = 3,   /* existing */
    DNAC_TX_STAKE            = 4,   /* new */
    DNAC_TX_DELEGATE         = 5,   /* new */
    DNAC_TX_UNSTAKE          = 6,   /* new */
    DNAC_TX_UNDELEGATE       = 7,   /* new */
    DNAC_TX_CLAIM_REWARD     = 8,   /* new */
    DNAC_TX_VALIDATOR_UPDATE = 9    /* new */
} dnac_tx_type_t;
```

### 2.2 Per-TX semantics

| Type | Inputs | Outputs | Signer | Appended fields |
|------|--------|---------|--------|-----------------|
| `STAKE` | DNAC UTXOs ≥ 10M + fee | change → signer | 1 (validator pubkey) | `commission_bps: u16`, `unstake_destination_fp[64]` |
| `DELEGATE` | DNAC UTXOs ≥ amount + fee (amount ≥ 100 DNAC) | change → signer | 1 (delegator pubkey) | `validator_pubkey: 2592B` |
| `UNSTAKE` | fee input + change | — | 1 (validator pubkey) | (none) |
| `UNDELEGATE` | fee input + change | principal + pending-reward (auto-claim) | 1 (delegator pubkey) | `validator_pubkey: 2592B`, `amount: u64` |
| `CLAIM_REWARD` | fee input + change | 1 fresh reward UTXO | 1 (claimant pubkey) | `target_validator: 2592B`, `max_pending_amount: u64`, `valid_before_block: u64` |
| `VALIDATOR_UPDATE` | fee input + change | — | 1 (validator pubkey) | `new_commission_bps: u16`, `signed_at_block: u64` |

Notes:
- `STAKE` / `DELEGATE` consume real DNAC UTXOs. Staked amount becomes Merkle state; UTXOs are marked spent via nullifier. Supply invariance: stake locked in state == UTXO set reduction.
- `UNSTAKE` / `UNDELEGATE` / `CLAIM_REWARD` produce fresh UTXOs without consuming existing stake UTXOs (state → materialize). Still carry fee input + change (uniform fee policy).
- Fee = standard dynamic DNAC fee from `dnac_get_current_fee()`.

### 2.3 Wire format

**Canonical TX hash preimage base** (all types):

```
version (u8) || type (u8) || timestamp (u64 BE) || chain_id[32] ||
inputs[0..input_count] || outputs[0..output_count] ||
signers[0..signer_count]                      /* truncated — NOT fixed 4 slots */ ||
type_specific_appended_fields
```

`chain_id` is explicitly bound into the preimage for all new TX types (prevents cross-chain replay per `F-CRYPTO-10`). Signer array is **truncated to `signer_count`** in the hash preimage — unused slots of the in-memory fixed array are NOT hashed (prevents trailing-garbage malleability per `F-CRYPTO-06`).

**Type-specific appended fields** (post-signer bytes):

```
if tx.type == STAKE:
    uint16_t commission_bps                      (big-endian)
    uint8_t  unstake_destination_fp[64]
    uint8_t  purpose_tag[17]                     = "DNAC_VALIDATOR_v1"  (exact ASCII, no padding, no NUL terminator)
if tx.type == DELEGATE:
    uint8_t  validator_pubkey[2592]
if tx.type == UNDELEGATE:
    uint8_t  validator_pubkey[2592]
    uint64_t amount                              (big-endian)
if tx.type == CLAIM_REWARD:
    uint8_t  target_validator[2592]
    uint64_t max_pending_amount                  (big-endian)
    uint64_t valid_before_block                  (big-endian)
if tx.type == VALIDATOR_UPDATE:
    uint16_t new_commission_bps                  (big-endian)
    uint64_t signed_at_block                     (big-endian)
```

All multi-byte integers are **big-endian**. All appended fields are included in the TX hash preimage — signers sign over the complete preimage.

**Purpose tag on STAKE** prevents cross-protocol signature reuse (`F-CRYPTO-05`): a Dilithium5 signature over a SPEND preimage cannot be reinterpreted as a STAKE signature because the purpose tag is absent from SPEND. The tag is the exact 17-byte ASCII string `"DNAC_VALIDATOR_v1"` — no NUL terminator and no padding, so its full byte length is 17 (not 16). An earlier revision of this spec listed `[16]`; the implementation is and has always been 17 (`DNAC_STAKE_PURPOSE_TAG_LEN = 17` in `dnac/include/dnac/transaction.h`).

### 2.4 Verify rules (per type)

```
STAKE:
  require signer_count == 1
  require purpose_tag == "DNAC_VALIDATOR_v1"                       [cross-protocol defense]
  require Σ input.amount (DNAC) >= 10_000_000 × 10^8 + fee
  require sum(outputs, DNAC) == Σ inputs − 10_000_000 × 10^8 − fee
  require NO record exists in validator_tree with signer[0].pubkey  [Rule I — literal]
  require commission_bps <= 10000
  require |validator_tree| < MAX_VALIDATORS (128)                  [Rule M]

DELEGATE:
  require signer_count == 1
  require validator_pubkey IN validator_tree
  require validator.status == ACTIVE                                [Rule B — not RETIRING/UNSTAKED/AUTO_RETIRED]
  require amount >= 100 × 10^8   (100 DNAC min)                   [Rule J — raised from 1]
  require Σ DNAC inputs >= amount + fee
  require Σ DNAC outputs == Σ inputs − amount − fee
  require count(delegations where delegator==signer[0]) < 64       [Rule G]
  require signer[0].pubkey != validator_pubkey                     [Rule S — no self-delegation gaming ranking]

UNSTAKE:
  require signer_count == 1
  require signer[0].pubkey IN validator_tree AND status == ACTIVE
  require NO delegation records exist with validator=signer[0]     [Rule A — literal, not counter]
  require fee paid (standard)
  // Mid-epoch behavior [Rule H]: status := RETIRING immediately;
  // graduation to UNSTAKED + cooldown UTXO emission deferred to next epoch boundary
  // (keeps BFT peer set stable until epoch end)

UNDELEGATE:
  require signer_count == 1
  require delegation(signer[0], validator_pubkey) exists
  require amount <= delegation.amount
  require amount > 0
  require current_block − delegation.delegated_at_block >= EPOCH_LENGTH    [Rule O — 1 epoch min hold]
  // Auto-claim [Rule C]: emit principal UTXO + pending-reward UTXO
  //                      always emit pending even if < dust [Rule Q — supply preservation]

CLAIM_REWARD:
  require signer_count == 1
  require current_block <= valid_before_block                      [freshness gate]
  if signer == target_validator:
      pending = validator.validator_unclaimed
  else:
      pending = ((validator.accumulator − delegation.reward_snapshot) × delegation.amount) >> 64
  require pending <= max_pending_amount                            [cap prevents delayed-replay over-claim]
  dust_threshold = max(10^6, 10 × current_fee)                     [Rule L — dynamic]
  require pending >= dust_threshold

VALIDATOR_UPDATE:
  require signer_count == 1
  require signer[0].pubkey IN validator_tree AND status ∈ {ACTIVE, RETIRING}
  require current_block − signed_at_block < SIGN_FRESHNESS_WINDOW (32 blocks)  [Rule K — freshness]
  require new_commission_bps <= 10000
  require last_validator_update_block(signer[0]) + EPOCH_LENGTH <= current_block  [per-epoch cooldown vs spam]
  if new_commission_bps > current_commission_bps:
      pending_commission_bps = new_commission_bps
      pending_effective_block = max(
          next_epoch_boundary(current_block),
          current_block + EPOCH_LENGTH                             [Rule K — always ≥1 full epoch notice]
      )
  else:
      current_commission_bps = new_commission_bps
      pending_commission_bps = 0                                   [Rule K — decrease clears pending]
      pending_effective_block = 0

GENESIS (additional invariant):
  require initial_validator_count == 7                             [Rule P]
  require Σ outputs.amount + Σ initial_validators[i].self_stake == DNAC_TOTAL_SUPPLY  [Rule P]
```

**Verify rules catalog:**

| ID | Rule | Rationale / finding |
|----|------|---------------------|
| A | UNSTAKE rejected if any delegation records for target validator exist (literal, not counter) | `F-STATE-12` — prevents stale-ghost replay |
| B | DELEGATE rejected if validator not ACTIVE | `F-DOS-07` partial; prevents attaching to retiring validator |
| C | UNDELEGATE auto-claims pending (2 UTXOs, always emit even sub-dust) | `F-STATE-01` supply preservation |
| D | UTXO records gain `unlock_block: u64` | Cooldown semantics |
| E | Reward accumulator = u128 18-decimal fixed-point, **big-endian** 16B serialization | `F-CRYPTO-08` determinism |
| F | Commission: increase delayed to max(next_epoch, +1 epoch); decrease immediate and clears pending | `F-ECON-01`, `F-CONS-04`, `F-ECON-07` |
| G | Per-delegator cap 64 delegations | Bounded Merkle state |
| H | Mid-epoch UNSTAKE → `status = RETIRING`; graduate at next epoch boundary | `F-CONS-03` BFT peer set stability |
| I | "NOT IN validator_tree" is literal — any record blocks (including UNSTAKED/AUTO_RETIRED) | `F-STATE-07` pubkey reuse |
| J | Min delegation = 100 DNAC | `F-DOS-02` Merkle bloat; `F-DOS-07` grief minimum |
| K | VALIDATOR_UPDATE freshness (signed_at_block) + ≥1 full epoch delegator-exit window on increase + decrease clears pending + per-epoch cooldown | `F-CRYPTO-02`, `F-CONS-04`, `F-DOS-06` |
| L | CLAIM dust threshold dynamic: `max(10^6 raw, 10 × current_fee)` | `F-DOS-03` fee > reward trap |
| M | `MAX_VALIDATORS = 128` (pending pool cap) | `F-DOS-01` |
| N | Liveness ejection: validator missing all blocks in 3 consecutive epochs → `status = AUTO_RETIRED`, excluded from future committees (NO stake loss — no slashing in v1) | `F-DOS-11` |
| O | Min delegation hold duration = 1 epoch before UNDELEGATE | `F-ECON-06`, `F-ECON-05` drive-by flash |
| P | Genesis: `initial_validator_count == 7` AND supply sum invariant | `F-STATE-04` |
| Q | Auto-claim paths (UNDELEGATE, UNSTAKE) ALWAYS emit reward UTXO regardless of dust; user-initiated CLAIM keeps dust threshold | `F-STATE-01`, `F-ECON-10` supply preservation |
| R | `MIN_TENURE = 2 × EPOCH_LENGTH` (240 blocks) — validator's `active_since_block + MIN_TENURE ≤ snapshot_block` required for committee eligibility | `F-CONS-08` drive-by committee |
| S | DELEGATE where `delegator_pubkey == validator_pubkey` rejected (self-delegation ban in v1) | `F-ECON-03` ranking manipulation |
| T | `unstake_destination_fp` is IMMUTABLE post-STAKE — no TX type updates it | `F-STATE-05` destination hijack |

### 2.5 Fee policy

DNAC-only fees (unchanged from v0.11.0). Fee previously burned to `0x00…00`; **now routes to reward accumulator** — fee collection redirects in the same commit as this feature lands.

### 2.6 No in-memory struct ABI changes

Existing `dnac_transaction_t` (up to 4 signers, 16 inputs/outputs, 3 witness sigs) is sufficient. Per-type appended fields stored in a small union or `extra[]` byte buffer attached to the struct; serialize/deserialize routines handle type-specific layout.

---

## 3. Merkle State Schema + Committee Election

### 3.1 Extended state_root

```
state_root = SHA3-512(
    utxo_tree_root       ||   /* existing v0.11.0, tree_tag = 0x01 */
    validator_tree_root  ||   /* new, tree_tag = 0x02 */
    delegation_tree_root ||   /* new, tree_tag = 0x03 */
    reward_tree_root          /* new, tree_tag = 0x04 */
)
```

4 independent Merkle trees, atomically updated per block commit. **Concatenation order is fixed** (utxo, validator, delegation, reward) — any deviation across witnesses is a consensus bug.

**Domain separation** (`F-CRYPTO-04`, `F-STATE-08`):
- Every leaf key is constructed as `SHA3-512(tree_tag || raw_key_data)`.
- Every leaf value is hashed as `SHA3-512(tree_tag || cbor_serialized_record)`.
- Tree tag is a 1-byte prefix: `0x01=utxo, 0x02=validator, 0x03=delegation, 0x04=reward`.
- **Empty-tree root** (when tree has no leaves): `SHA3-512(tree_tag || 0x00)`. Explicit so all witnesses agree on the initial state root (e.g., delegation_tree before any DELEGATE).

### 3.2 Validator tree

Key: `SHA3-512(0x02 || validator_pubkey)` (64 bytes)
Value (CBOR-serialized, leaf-hashed as `SHA3-512(0x02 || cbor)`):

```c
struct validator_record {
    uint8_t  pubkey[2592];                 /* Dilithium5 */
    uint64_t self_stake;                   /* always 10M × 10^8 */
    uint64_t total_delegated;              /* Σ of ALL delegations (incl. self if allowed; v1 bans) */
    uint64_t external_delegated;           /* Σ of delegations where delegator != validator;
                                              used for committee ranking to avoid self-delegation
                                              ranking manipulation. v1 Rule S makes this == total_delegated */
    uint16_t commission_bps;               /* 0–10000 */
    uint16_t pending_commission_bps;       /* 0 = no pending */
    uint64_t pending_effective_block;      /* 0 = no pending */
    uint8_t  status;                       /* 0=ACTIVE 1=RETIRING 2=UNSTAKED 3=AUTO_RETIRED */
    uint64_t active_since_block;
    uint64_t unstake_commit_block;         /* 0 = not yet unstaked */
    uint8_t  unstake_destination_fp[64];   /* IMMUTABLE post-STAKE (Rule T) */
    uint8_t  unstake_destination_pubkey[2592]; /* Dilithium5 pubkey corresponding to fp,
                                                  enables SPEND verify of unlocked UTXO */
    uint64_t last_validator_update_block;  /* cooldown tracker for Rule K */
    uint64_t consecutive_missed_epochs;    /* liveness tracker for Rule N */
    uint64_t last_signed_block;            /* last block this validator signed PRECOMMIT */
};
```

### 3.3 Delegation tree

Key: `SHA3-512(0x03 || delegator_pubkey || validator_pubkey)` (64 bytes)
Value (leaf hash `SHA3-512(0x03 || cbor)`):

```c
struct delegation_record {
    uint8_t  delegator_pubkey[2592];
    uint8_t  validator_pubkey[2592];
    uint64_t amount;
    uint64_t delegated_at_block;           /* Rule O: amount locked until +EPOCH_LENGTH */
    uint8_t  reward_snapshot[16];          /* u128 BE fixed-point, last CLAIM accumulator */
};
```

### 3.4 Reward tree

Key: `SHA3-512(0x04 || validator_pubkey)` (64 bytes)
Value (leaf hash `SHA3-512(0x04 || cbor)`):

```c
struct reward_record {
    uint8_t  validator_pubkey[2592];
    uint8_t  accumulator[16];              /* u128, 18-decimal fixed-point, BIG-ENDIAN serialization */
    uint64_t validator_unclaimed;          /* self-stake portion + commission skim + liveness redistribution */
    uint64_t last_update_block;
    uint64_t residual_dust;                /* accumulator-division truncation carry, folded into next block's pool */
};
```

**Accumulator serialization** (`F-CRYPTO-08`):
- u128 is serialized as **16 bytes big-endian** (high limb first, low limb second).
- Implementations MUST use a portable bigint routine (vendored library), NOT compiler-native `__uint128_t` — heterogeneous toolchains (gcc/clang/MSVC) produce divergent results for edge values otherwise.
- Test vectors required in `test_accumulator_math.c`: `u128(1) = 00 00 .. 00 01`, `u128(2^64) = 00 .. 01 00 .. 00`, etc. Every witness binary MUST match.

### 3.5 Accumulator math (per block, block commit phase)

**Liveness gate** (`F-ECON-11`, Rule N): only validators that signed ≥ `LIVENESS_THRESHOLD` (80%) of blocks in this epoch receive this block's share. Non-signers' share is redistributed pro-rata to the active signers in the same committee. Attendance is tracked via `last_signed_block` + per-epoch counters.

```
block_fee_pool = Σ block_txs.fee

// Determine attending committee for THIS block
attending = [V for V in committee if
             epoch_blocks_signed(V) / epoch_blocks_elapsed >= LIVENESS_THRESHOLD]

if len(attending) == 0:
    // Pathological case — all committee members offline. Pool rolls forward.
    global_unallocated_pool += block_fee_pool
    return

per_member_share = (block_fee_pool + global_unallocated_pool) / len(attending)
global_unallocated_pool = 0

for each V in attending:
    // Committee ranking uses external_delegated (F-ECON-03); reward math uses full total_delegated
    total_stake = V.self_stake + V.total_delegated

    if V.total_delegated > 0:
        // Compute pieces such that pieces-sum == per_member_share exactly (F-ECON-04)
        delegator_share_raw = (per_member_share × V.total_delegated) / total_stake
        commission_skim     = (delegator_share_raw × V.commission_bps) / 10000
        delegator_pool      = delegator_share_raw − commission_skim
        validator_share     = per_member_share − delegator_pool   // absorbs all truncation

        V.validator_unclaimed += validator_share

        // Residual-dust carry: truncation remainder carried into next block
        acc_increment_num   = (delegator_pool << 64) + V.residual_dust
        acc_increment       = acc_increment_num / V.total_delegated
        V.residual_dust     = acc_increment_num − (acc_increment × V.total_delegated)
        V.accumulator       = u128_add(V.accumulator, acc_increment)
    else:
        V.validator_unclaimed += per_member_share
```

**Invariant test** (added to `test_accumulator_math.c`):
```
assert(validator_share + delegator_pool == per_member_share)
assert(Σ V.validator_unclaimed_delta + Σ (V.accumulator_delta × V.total_delegated >> 64) + Σ V.residual_dust_delta == block_fee_pool)
```
Per-block supply should always balance exactly.

### 3.6 Committee election (at epoch boundary, block `E_start`)

```
lookback_block   = E_start − EPOCH_LENGTH − 1        /* POST-COMMIT snapshot of this block */
snapshot_root    = block_at(lookback_block).validator_tree_root
state_seed       = block_at(lookback_block).state_root

// Bootstrap — first epoch after genesis
if E_start < EPOCH_LENGTH:
    committee_next_epoch = chain_def.initial_validators  /* sorted by tiebreak rule below */
    return

validator_snapshot = read_validator_tree_at(snapshot_root)
eligible = [
    v for v in validator_snapshot
    if v.status == ACTIVE
    AND v.active_since_block + MIN_TENURE <= lookback_block      /* Rule R: 240 blocks */
]

// Ranking uses external_delegated (self-delegation excluded, Rule S)
// Tiebreak uses epoch-specific seed to prevent pubkey grinding (F-CRYPTO-11)
eligible.sort(
    key       = λ v: (v.self_stake + v.external_delegated),
    reverse   = True,
    tiebreak  = λ v: SHA3-512(0x02 || v.pubkey || state_seed)  /* bytes compared lexicographically */
)
committee_next_epoch = eligible[:7]
```

**Determinism**:
- `lookback_block` uses **post-commit** state: the block is fully committed, state_root fixed, no race between PREVOTE/PRECOMMIT phases (`F-CONS-01`).
- Tiebreak is epoch-specific (mixes state_root as seed), so grinding one-time-cheap pubkey can't grant permanent priority (`F-CRYPTO-11`).
- All 7 nodes compute the same committee from the same state.

**MIN_TENURE = 240 blocks** (2 × EPOCH_LENGTH) prevents "drive-by" committee seats: stake N blocks before boundary → must serve ≥2 full epochs in pending pool before eligible (`F-CONS-08`).

### 3.7 Witness DB hot index (SQLite)

```sql
CREATE TABLE validators (
    pubkey_hash BLOB PRIMARY KEY,
    pubkey BLOB NOT NULL,
    self_stake INTEGER NOT NULL,
    total_delegated INTEGER NOT NULL DEFAULT 0,
    external_delegated INTEGER NOT NULL DEFAULT 0,    -- for committee ranking
    commission_bps INTEGER NOT NULL,
    pending_commission_bps INTEGER NOT NULL DEFAULT 0,
    pending_effective_block INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL,                          -- 0=ACTIVE 1=RETIRING 2=UNSTAKED 3=AUTO_RETIRED
    active_since_block INTEGER NOT NULL,
    unstake_commit_block INTEGER NOT NULL DEFAULT 0,
    unstake_destination_fp TEXT NOT NULL,
    unstake_destination_pubkey BLOB NOT NULL,         -- 2592 bytes, enables SPEND verify
    last_validator_update_block INTEGER NOT NULL DEFAULT 0,
    consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,
    last_signed_block INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_validator_rank ON validators ((self_stake + external_delegated) DESC);

CREATE TABLE delegations (
    delegator_hash BLOB,
    validator_hash BLOB,
    delegator_pubkey BLOB NOT NULL,
    validator_pubkey BLOB NOT NULL,
    amount INTEGER NOT NULL,
    delegated_at_block INTEGER NOT NULL,
    reward_snapshot BLOB NOT NULL,          -- 16 bytes, big-endian u128
    PRIMARY KEY (delegator_hash, validator_hash)
);
CREATE INDEX idx_delegator ON delegations (delegator_hash);
CREATE INDEX idx_validator ON delegations (validator_hash);

CREATE TABLE rewards (
    validator_hash BLOB PRIMARY KEY,
    accumulator BLOB NOT NULL,              -- 16 bytes big-endian u128
    validator_unclaimed INTEGER NOT NULL,
    last_update_block INTEGER NOT NULL,
    residual_dust INTEGER NOT NULL DEFAULT 0
);

-- Global meta for MAX_VALIDATORS cap (Rule M)
CREATE TABLE validator_stats (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT INTO validator_stats (key, value) VALUES ('active_count', 0);

-- UTXO table existing — ADD unlock_block column
ALTER TABLE utxos ADD COLUMN unlock_block INTEGER NOT NULL DEFAULT 0;
```

Committee election query (v1 fixed top-7):
```sql
SELECT pubkey FROM validators
WHERE status = 0                                           -- ACTIVE only
  AND active_since_block + 240 <= :lookback_block          -- Rule R MIN_TENURE
ORDER BY (self_stake + external_delegated) DESC, pubkey ASC
LIMIT 7;
```

DB rebuilds from chain scan on startup; **Merkle commitment is authoritative** — if DB and Merkle ever diverge, rebuild DB. Every state mutation runs inside a single SQLite transaction (`F-STATE-03`), which commits only after state_root recompute + BFT 5-of-7 PRECOMMIT.

### 3.8 Locked UTXO support

UTXO tree leaf gains `unlock_block: u64` (existing UTXOs = 0, immediately spendable).

SPEND verify:
```
for each input in tx.inputs:
    utxo = lookup(input.nullifier)
    if utxo.unlock_block > current_block:
        return ERROR_UTXO_LOCKED
```

UNSTAKE commit produces a locked UTXO (`unlock_block = commit_block + 17280`).

### 3.9 State update atomicity matrix

| TX type | utxo | validator | delegation | reward |
|---------|------|-----------|------------|--------|
| STAKE | ✓ (inputs spent + change) | ✓ (new record) | — | ✓ (new empty record) |
| DELEGATE | ✓ (inputs spent + change) | ✓ (total_delegated += amount) | ✓ (new record, snapshot = current acc) | — |
| UNSTAKE | ✓ (locked UTXO out) | ✓ (status=UNSTAKED) | — | ✓ (validator_unclaimed drain) |
| UNDELEGATE | ✓ (principal + reward UTXOs) | ✓ (total_delegated −= amount) | ✓ (amount update or delete) | — |
| CLAIM_REWARD | ✓ (reward UTXO) | — | ✓ (snapshot advance) OR — | ✓ (validator_unclaimed = 0 if validator-claim) |
| VALIDATOR_UPDATE | — | ✓ (pending fields or immediate) | — | — |

---

## 4. Fee Flow + Reward Lifecycle

### 4.1 Fee collection flow (per block)

Previously: every TX fee produced a burn UTXO (owner = `0x00…00`). Now fees bypass UTXO creation and flow directly to the accumulator.

**Block commit order** (strictly pinned — `F-STATE-02`, `F-ECON-08`):

```
1. VERIFY: verify all TXs including type-specific rules (§2.4); collect block_fee_pool = Σ fee
2. MUTATE STATE: apply ALL TX state mutations in order:
     - UTXO tree: inputs spent (nullifiers added) + outputs created
     - validator tree: STAKE inserts, UNSTAKE status→RETIRING, VALIDATOR_UPDATE fields
     - delegation tree: DELEGATE inserts (reward_snapshot := accumulator BEFORE step 3),
                        UNDELEGATE deletes/updates
     - reward tree: CLAIM_REWARD advances snapshots, zeros validator_unclaimed on validator-claim
3. LIVENESS ATTENDANCE: record which committee members signed PREVOTE this block
4. ACCUMULATOR UPDATE (§3.5): distribute block_fee_pool among attending committee members,
    using POST-mutation total_delegated for each validator
5. EPOCH BOUNDARY ACTIONS (only if current_block is an epoch boundary):
     - Apply pending_commission_bps where pending_effective_block == current_block
     - Graduate RETIRING validators → UNSTAKED + emit locked 10M UTXO
     - Update consecutive_missed_epochs; flag AUTO_RETIRED where > 3
     - Compute committee for NEXT epoch (§3.6)
6. MERKLE RECOMPUTE: state_root = SHA3-512(utxo_root || validator_root || delegation_root || reward_root)
7. BFT PREVOTE: every witness independently repeats steps 1–6 and compares state_root byte-for-byte
8. BFT PRECOMMIT: 5-of-7 signatures over state_root
9. SQLITE COMMIT: the entire DB transaction wrapping steps 2–6 commits only after step 8 succeeds

Any view-change abort during steps 7–8 rolls back the SQLite transaction entirely — no partial state persists.
```

**DELEGATE snapshot rule** (`F-ECON-08`): when DELEGATE TX creates a new delegation_record in step 2, `reward_snapshot` is set to `V.accumulator` as-of-step-2-entry — i.e., **before** step 4's accumulator bump for this block. This ensures the new delegator does NOT earn from fees collected in the same block their DELEGATE landed; they start earning from the NEXT block.

**Atomicity** (`F-STATE-03`, `F-CONS-06`): every witness must independently recompute `state_root` in step 6 before signing PREVOTE (step 7). No fast-path / trust-leader shortcut is permitted. SQLite mutations in step 2 occur inside a transaction that only commits after step 8; view-change abort triggers rollback.

### 4.2 Pending-reward query (wallet UX)

Wallet displays "Pending rewards: X DNAC" via a new Tier-2 RPC:

```c
int dnac_get_pending_rewards(dnac_context_t *ctx,
                             uint64_t *total_pending_out);
```

Server-side computation:
```
pending = 0
for each delegation D owned by claimant:
    V = D.validator
    pending += ((V.accumulator − D.reward_snapshot) × D.amount) >> 64
if claimant is a validator:
    pending += V.validator_unclaimed
```

O(delegation_count), max 64 per delegator — cheap.

### 4.3 CLAIM_REWARD materialization

Delegator claim (one validator at a time):
```
1. verify: signer owns delegation(signer, target_validator)
2. pending = ((V.accumulator − D.reward_snapshot) × D.amount) >> 64
3. require pending >= 10^6 (0.01 DNAC)
4. state:
   - UTXO: new {owner=claimant, amount=pending, token=DNAC, unlock_block=0}
   - delegation.reward_snapshot = V.accumulator
```

Validator self-claim:
```
1. verify: signer == target_validator (self)
2. pending = V.validator_unclaimed
3. require pending >= 10^6
4. state:
   - UTXO: new {owner=validator, amount=pending, ...}
   - V.validator_unclaimed = 0
```

### 4.4 Auto-claim on UNDELEGATE (Rule C + Rule Q)

```
1. verify delegation exists, amount <= D.amount, hold duration satisfied (Rule O)
2. pending = ((V.accumulator − D.reward_snapshot) × D.amount) >> 64
3. state mutations (applied in step 2 of block commit order per §4.1):
   - UTXO A: {owner=delegator_fp, amount=undelegate_amount, unlock_block=0}
   - UTXO B: {owner=delegator_fp, amount=pending, unlock_block=0}
     /* ALWAYS emit even if pending < dust (Rule Q — supply preservation) */
   - delegation.amount −= undelegate_amount; delete record if amount reaches 0
   - D.reward_snapshot := V.accumulator (locks in all earnings up to this block)
   - validator.total_delegated −= undelegate_amount
   - validator.external_delegated −= undelegate_amount (v1: same as total since Rule S bans self-delegation)
```

### 4.5 UNSTAKE lifecycle (Rule A + Rule H + §3.9 locked-UTXO)

UNSTAKE is a **two-phase** process (mid-epoch → RETIRING → graduation at epoch boundary → UNSTAKED + UTXO):

```
# Phase 1: UNSTAKE TX commits (anywhere in epoch)
1. verify signer matches validator.pubkey
2. verify status == ACTIVE
3. verify NO delegation records exist with validator=signer.pubkey (Rule A, literal)
4. state mutations:
   - validator.status := RETIRING
   - validator.unstake_commit_block := current_block
   /* BFT peer set stays stable: committee snapshot for current epoch
      was frozen at lookback, so RETIRING validator continues serving */

# Phase 2: graduation at next epoch boundary (§4.1 step 5)
when current_block == next_epoch_boundary_after(validator.unstake_commit_block):
   - pending = V.validator_unclaimed
   - UTXO A: {owner=validator.unstake_destination_fp, amount=10M × 10^8,
              unlock_block = current_block + 17280}
   - UTXO B: {owner=validator.unstake_destination_fp, amount=pending, unlock_block=0}
     /* ALWAYS emit even if pending < dust (Rule Q) */
   - validator.status := UNSTAKED
   - V.validator_unclaimed := 0
   - validator_stats.active_count -= 1
```

**UTXO owner format** (`F-STATE-11`): UTXO `owner` is a 64-byte fingerprint, consistent across the UTXO table. SPEND verify resolves fp→pubkey via `unstake_destination_pubkey` stored in validator_record, ensuring the unlocked UTXO is spendable by the operator.

**Accumulator isolation during RETIRING** (`F-STATE-10`): a RETIRING validator is still in the frozen committee snapshot, so §3.5 accumulator math still considers them. However, the attendance-liveness gate (Rule N, §3.5) will naturally exclude them if they stop signing. If they continue signing, they earn legitimately during their retirement epoch — this is the intended behavior (they're still doing consensus work).

### 4.6 Supply invariance — formal balance sheet

Total supply is an invariant:

```
DNAC_TOTAL_SUPPLY ≡ 10^17 raw (1B DNAC)

Σ UTXO.amount (all trees, all states, including locked)
+ Σ validator.self_stake (over validator_tree)
+ Σ delegation.amount (over delegation_tree)
+ Σ validator.validator_unclaimed (over reward_tree)
+ Σ delegator pending rewards [(accumulator − snapshot) × amount >> 64]
+ Σ validator.residual_dust
≡ DNAC_TOTAL_SUPPLY
```

**Per-TX-type supply conservation:**

| TX type | UTXO Δ | validator Δ | delegation Δ | reward-state Δ | Net |
|---------|:-----:|:-----------:|:------------:|:--------------:|:---:|
| SPEND / BURN | `−fee (input) + 0 (no burn UTXO)` | 0 | 0 | `+fee → pool → accumulators & validator_unclaimed` | 0 |
| STAKE | `−10M − fee` | `+10M` | 0 | `+fee → pool` | 0 |
| DELEGATE | `−amount − fee` | `+amount (total_delegated)` | `+amount` (new record, zero pending) | `+fee → pool` | 0 |
| UNSTAKE (phase 1) | `−fee` | `status change only` | 0 | `+fee → pool` | 0 |
| UNSTAKE (phase 2, at epoch boundary) | `+10M + pending` | `−10M (self_stake removed)` | 0 | `−validator_unclaimed` | 0 |
| UNDELEGATE | `+amount + pending − fee` | `−amount` | `−amount (record mutation)` | `+fee → pool, pending re-materialized` | 0 |
| CLAIM_REWARD | `+pending − fee` | 0 | snapshot advance (no Δ in amount) | `−pending drained from accumulator/unclaimed` | 0 |
| VALIDATOR_UPDATE | `−fee` | field change | 0 | `+fee → pool` | 0 |
| GENESIS | `+Σ outputs` | `+7×10M self_stake` | 0 | 0 | supply created once; genesis verify ensures `Σ = 10^17` (Rule P) |

**Debug-build invariant check** (test gate): per-block assertion that total supply deviation across all state is zero. Implemented in `test_accumulator_math.c` and `test_commit_atomicity.c`; optionally compiled into production witness behind `#ifdef DNAC_DEBUG_SUPPLY_INVARIANT` for canary runs.

**Truncation handling** (`F-ECON-04`, `F-STATE-09`): `residual_dust` field on reward_record carries integer-division remainder to next block, preventing sub-unit truncation leak. Supply stays exact, not just bounded.

**Auto-claim dust emission** (`F-STATE-01`, Rule Q): UNDELEGATE/UNSTAKE ALWAYS emit reward UTXO regardless of amount (even if < dust threshold). Only user-initiated CLAIM_REWARD enforces the dust threshold (as economic spam protection, not supply preservation).

---

## 5. Genesis Bootstrap + Migration

### 5.1 chain_def extension

```c
typedef struct {
    uint8_t  pubkey[2592];                  /* Dilithium5 validator public key */
    char     endpoint[128];                 /* IP:port (informational only, zero-filled beyond NUL) */
    uint16_t commission_bps;                /* initial rate */
    char     unstake_destination_fp[129];   /* 128 hex + NUL, zero-filled beyond NUL */
    uint8_t  unstake_destination_pubkey[2592]; /* Dilithium5 pubkey matching fp — enables SPEND verify
                                                  when locked UTXO unlocks (F-STATE-11) */
} dnac_genesis_validator_t;

typedef struct {
    /* existing fields ... */
    dnac_genesis_validator_t initial_validators[7];
    uint8_t                  initial_validator_count;  /* MUST == 7, Rule P */
} dnac_chain_definition_t;
```

**Canonical serialization** (`F-CRYPTO-07`):
- All multi-byte integers: **big-endian** explicit encoding.
- All fixed-length byte arrays: full buffer, zero-filled beyond any NUL terminator — the full buffer participates in hash preimage.
- No native struct memcpy; every field serialized explicitly with length discipline.
- `test_genesis_validators.c` asserts: mutating any post-NUL byte changes the genesis hash (prevents second-preimage via trailing-garbage).

chain_def is part of genesis TX hash preimage (existing `has_chain_def` field) → the initial validator set is authenticated by the hardcoded `chain_id` the client ships with.

### 5.2 Genesis TX

```
type = DNAC_TX_GENESIS
inputs = []
outputs = [
    { owner = punk_fp, amount = 930_000_000 × 10^8, token = DNAC, unlock_block = 0 }
]
witness_sigs = 7/7 (unanimous)
chain_def.initial_validators = [ <7 production node records> ]
chain_def.initial_validator_count = 7
```

**Genesis verify rule (Rule P):**
```
require chain_def.initial_validator_count == 7
require (Σ outputs.amount) + (Σ chain_def.initial_validators[i].self_stake [=10M each]) == DNAC_TOTAL_SUPPLY
require all 7 chain_def.initial_validators[i].pubkey are distinct
```

Post-commit Merkle state:
- utxo_tree: 1 UTXO (punk 930M)
- validator_tree: 7 records (self_stake=10M, external_delegated=0, status=ACTIVE, active_since_block=1, commission_bps=500, all fp/pubkey populated from chain_def)
- delegation_tree: empty (root = `SHA3-512(0x03 || 0x00)`)
- reward_tree: 7 empty records (accumulator=0, validator_unclaimed=0, residual_dust=0)

Supply: 930M + 7×10M = 1B ✓

### 5.3 Initial validator parameters (production)

7 production nodus nodes: US-1, EU-1, EU-2, EU-3, EU-4, EU-5, EU-6. Each contributes one `initial_validators[i]`:
- `pubkey` = node's witness Dilithium5 pubkey
- `endpoint` = node's public IP:4004
- `commission_bps` = 500 (5% starting, per-validator adjustable post-genesis via VALIDATOR_UPDATE)
- `unstake_destination_fp` = `3f444357467a3a68...` (punk) — all 7 destinations initially point to single-operator fingerprint. Future operator distribution happens off-protocol (UNSTAKE + new operator STAKE).
- `unstake_destination_pubkey` = punk's Dilithium5 pubkey (2592B) — enables SPEND verify when locked UTXO unlocks.

**Accepted risk** (`F-CONS-02`, `F-ECON-02`): all 7 destinations identical = single point of failure for key custody. Documented as pre-mainnet operator-diversification milestone; v2 parse rules MAY enforce destination diversity.

### 5.4 Post-genesis distribution (unchanged protocol)

Per `project_genesis_protocol` memory: 8 testers × (1M PUNK + 100 DNAC). Fees from these distribution TXs feed the reward accumulator from block 1 onward.

### 5.5 Chain wipe + deploy

Per `feedback_consensus_deploy_stop_all`:
```
1. Stop-all: halt nodus on all 7 production nodes
2. Archive: /var/lib/nodus/*.db snapshot, timestamped
3. Deploy: new nodus + dnac binaries on all 7 nodes (rolling prohibited)
4. Prepare chain_def: 7 production witness pubkeys + punk as unstake_destination
5. Genesis re-mint: `dna dnac genesis ...` produces genesis TX with chain_def;
   unanimous 7/7 BFT signature collection
6. Start-all: witnesses boot, commit genesis block
7. Post-genesis distribution: 8 testers × 1M PUNK + 100 DNAC
8. Messenger regression test: chip+punk → nocdem message round-trip
```

### 5.6 Version bumps

- Nodus: `NODUS_VERSION_*` major bump (schema change)
- DNAC: `DNAC_VERSION_*` major bump (TX type expansion)
- Messenger: unaffected (libdna API unchanged)
- Commit tags: none (DNAC + nodus only, per `feedback_dnac_no_build_tag` + `feedback_nodus_only_no_build_tag`)

### 5.7 Backwards compatibility

None. DESIGN phase; users re-receive test allocations via genesis distribution. Production cluster starts fresh with new schema from block 1.

---

## 6. Files Touched + Testing

### 6.1 DNAC files

| File | Change |
|------|--------|
| `dnac/include/dnac/dnac.h` | 6 new enum values + 9 new API functions |
| `dnac/include/dnac/transaction.h` | Type-specific extra-field encoding, helper prototypes |
| `dnac/include/dnac/block.h` | `chain_definition_t.initial_validators[7]` |
| `dnac/include/dnac/validator.h` | **NEW** — validator/delegation/reward record structs |
| `dnac/include/dnac/version.h` | Major bump |
| `dnac/src/transaction/serialize.c` | Type-specific appended-field serialization |
| `dnac/src/transaction/verify.c` | Per-type verify rules + locked-UTXO spend check |
| `dnac/src/transaction/stake.c` | **NEW** — STAKE/UNSTAKE builders |
| `dnac/src/transaction/delegate.c` | **NEW** — DELEGATE/UNDELEGATE builders |
| `dnac/src/transaction/claim.c` | **NEW** — CLAIM_REWARD builder |
| `dnac/src/transaction/validator_update.c` | **NEW** — VALIDATOR_UPDATE builder |
| `dnac/src/transaction/genesis.c` | chain_def.initial_validators handling, validator tree seeding |
| `dnac/src/wallet/balance.c` | Pending-reward aggregation API |
| `dnac/src/nodus/discovery.c` | Committee-filtered witness discovery (chain state, not just DHT) |

### 6.2 Nodus files

| File | Change |
|------|--------|
| `nodus/include/nodus/nodus_types.h` | `NODUS_VERSION_*` bump, committee/epoch/cooldown constants |
| `nodus/src/witness/nodus_witness_verify.c` | TX-type dispatch for 6 new types |
| `nodus/src/witness/nodus_witness_merkle.c` | 4-subtree state_root |
| `nodus/src/witness/nodus_witness_validator.c` | **NEW** — validator tree CRUD, committee election |
| `nodus/src/witness/nodus_witness_delegation.c` | **NEW** — delegation tree CRUD, prefix-scan cap check |
| `nodus/src/witness/nodus_witness_reward.c` | **NEW** — accumulator math, per-block commit step |
| `nodus/src/witness/nodus_witness_db.c` | 3 new SQLite tables + UTXO.unlock_block column |
| `nodus/src/witness/nodus_witness_handlers.c` | `dnac_pending_rewards_query`, `dnac_committee_query`, `dnac_validator_list_query` |
| `nodus/src/witness/nodus_witness_peer.c` | Roster from committee snapshot (chain-authoritative) |
| `nodus/src/witness/nodus_witness_bft.c` | BFT peer set from committee snapshot, re-read at epoch boundary |
| `nodus/src/witness/nodus_witness.c` | Accumulator update step at block commit |

### 6.3 Messenger files

| File | Change |
|------|--------|
| `messenger/cli/cli_dna_chain*.c` | New CLI verbs: `stake`, `delegate`, `unstake`, `undelegate`, `claim`, `validator-update`, `validator-list`, `committee`, `pending-rewards` |
| `messenger/dna_messenger_flutter/lib/...` | Stake dashboard, delegation screen, rewards screen, validator control panel |
| `messenger/dna_messenger_flutter/lib/l10n/app_{en,tr}.arb` | New strings (non-technical UI per CLAUDE.md) |

### 6.4 Docs

| File | Change |
|------|--------|
| `dnac/CLAUDE.md` | Version bump, witness section updated |
| `messenger/docs/ARCHITECTURE_DETAILED.md` | Chain-state-authoritative witness roster |
| `nodus/docs/DYNAMIC_WITNESS_DESIGN.md` | Superseded notice + pointer to this doc |

### 6.5 Unit tests (new)

- `test_stake.c` — exact 10M, commission ≤ 10000, literal "NOT IN tree" (UNSTAKED record blocks), purpose_tag required, MAX_VALIDATORS cap, unstake_destination_fp bound into hash
- `test_delegate.c` — min 100 DNAC, RETIRING reject, 65th reject, self-delegation reject (Rule S), 1-epoch hold before UNDELEGATE
- `test_unstake.c` — wrong signer reject, literal "no delegation record for target" (Rule A), RETIRING status transition, graduation at epoch boundary produces locked UTXO with correct `unlock_block`
- `test_undelegate.c` — amount bounds, hold duration enforced, auto-claim ALWAYS emits reward UTXO (Rule Q), accumulator snapshot advance
- `test_claim.c` — dynamic dust threshold, `max_pending_amount` cap, `valid_before_block` freshness, validator-claim vs delegator-claim distinction, double-claim (snapshot advance)
- `test_validator_update.c` — increase delay = max(epoch_boundary, +1 epoch), decrease clears pending, `signed_at_block` freshness, per-epoch cooldown
- `test_accumulator_math.c` — u128 big-endian KAT, residual_dust carry, invariant sum check per block
- `test_locked_utxo.c` — SPEND reject when `unlock_block > current_block`, spend succeeds after unlock
- `test_genesis_validators.c` — chain_def seeding → validator_tree, supply invariant verify (Rule P), canonical serialization (post-NUL byte mutation changes hash)
- `test_preimage_binding.c` — STAKE/UPDATE/CLAIM signature covers all appended fields + chain_id binding (no cross-chain replay)
- `test_signer_canonical.c` — signer_count truncation: hash identical whether signers[1..3] are zero or garbage
- `test_tree_tags.c` — cross-tree leaf-key collision rejection (validator vs reward trees); empty-tree root determinism
- `test_liveness_gate.c` — non-attending validator share redistributed pro-rata to attenders; AUTO_RETIRED after 3 consecutive missed epochs
- `test_commit_atomicity.c` — SQLite transaction rollback on simulated view-change abort, no partial state visible
- `test_min_tenure.c` — stake at block N → first eligible epoch = ceil((N + 240) / 120)
- `test_dust_dynamic.c` — user CLAIM rejected when `pending < max(10^6, 10 × current_fee)`
- `test_self_delegation_exclusion.c` — self-delegation rejected at TX verify; committee ranking uses external_delegated
- `test_state_root_determinism.c` — compile two witness binaries with different compilers/flags; verify bit-identical state_root on same input stream

### 6.6 Nodus integration tests (new)

- `test_committee_election.c` — top-7 selection, tiebreak determinism, lookback window
- `test_fee_pool_distribution.c` — 7-way split, commission skim, delegator accumulator update
- `test_epoch_rotation.c` — pending validator graduation, BFT peer set sync

### 6.7 Manual integration test (post-chain-wipe)

1. Fresh genesis with chain_def seeded from 7 production nodes
2. Post-genesis distribution (8 testers × 1M PUNK + 100 DNAC)
3. 8th validator stakes → pending pool (not in committee while size = 7 fixed)
4. Delegation: `bios → one (validator), 5M DNAC`
5. Commission update: `one` sets 5%; bios pending-reward verifiable at epoch end
6. `bios` claims: accumulator → new UTXO
7. Unstake flow: `one` UNSTAKE while `bios` delegated → reject; `bios` UNDELEGATE first; `one` UNSTAKE → locked UTXO
8. Wait cooldown (24h simulated); SPEND reject before unlock, succeed after
9. Messenger regression (chip+punk → nocdem)
10. 7/7 state_root consistency check across cluster

Success criteria:
1. Unit tests all pass
2. 7/7 witnesses commit on new genesis
3. STAKE/DELEGATE/UNSTAKE/CLAIM lifecycle consistent in manual scenario
4. Pending-reward math bit-exact across 7 witnesses
5. Messenger regression passes
6. ~100 blocks BFT stable

### 6.8 Migration checklist

```
[ ] chain_def.initial_validators list prepared (7 production pubkeys + punk destination)
[ ] Messenger C lib builds clean (zero warnings)
[ ] Flutter Linux + APK build clean
[ ] Nodus builds clean
[ ] DNAC unit tests pass
[ ] Nodus unit tests pass
[ ] Local integration test pass (single-node simulation)
[ ] Stop-all production cluster
[ ] DB archive
[ ] Deploy new binaries (7/7)
[ ] Genesis re-mint (7/7 unanimous)
[ ] Start-all
[ ] Post-genesis distribution (8 testers)
[ ] Messenger regression (chip+punk → nocdem)
[ ] Monitor 100 blocks consistency
```

---

## 7. Red-Team Security Audit

Multi-agent red-team audit executed 2026-04-17. Five parallel sub-agents attacked the design independently from different angles (economic, consensus/BFT, cryptographic/PQ, DoS/griefing, state-integrity). Total: **58 findings** — 6 Critical, 19 High, 27 Medium, 6 Low.

### 7.1 Finding tally

| Surface | Critical | High | Medium | Low | Total |
|---------|:--------:|:----:|:------:|:---:|:-----:|
| Economic / incentives | 1 | 3 | 6 | 1 | 11 |
| Consensus / BFT | 3 | 3 | 4 | 0 | 10 |
| Crypto / PQ | 0 | 5 | 6 | 1 | 12 |
| DoS / griefing | 1 | 4 | 5 | 3 | 13 |
| State integrity / supply | 1 | 4 | 6 | 1 | 12 |
| **Total** | **6** | **19** | **27** | **6** | **58** |

### 7.2 Critical findings (must mitigate before implementation)

#### C-1 — `F-STATE-03`: CLAIM_REWARD non-atomicity = money printer under view change
Reward UTXO emission and `reward_snapshot` advance are separate mutations. Under BFT view-change mid-block, one can persist without the other → repeat claim printing DNAC. **Mitigation:** single SQLite transaction wrapping all state mutations (UTXO insert + 4 Merkle subtree updates + snapshot advance). `state_root` computed after all mutations; any partial apply fails root check and rolls back.

#### C-2 — `F-CONS-01`: Epoch-boundary committee read race = chain halt at every epoch
Implementations may read validator_tree at different points of block `E_start − 120`'s lifecycle → different committees → BFT peer set mismatch. **Mitigation:** spec pins "committee for epoch E is computed from post-commit validator_tree_root of block `E_start − EPOCH_LENGTH − 1`." Enforce in `nodus_witness_validator.c`; covered by `test_committee_election.c`.

#### C-3 — `F-CONS-06`: Fake state_root via fast-path PREVOTE skip
A byzantine leader can propose a block with forged `state_root`. If any witness accepts without independently recomputing, the 5-of-7 barrier collapses. **Mitigation:** mandatory independent Merkle recompute on every PREVOTE before signing. No "trust-leader fast path" allowed. Mutation-test `nodus_witness_verify.c` to prove no code path signs without recompute.

#### C-4 — `F-CONS-02` / `F-ECON-02`: Single-operator Byzantine assumption violated
All 7 initial validators operated by one entity → BFT's `f < N/3` assumption is theatrical until operator diversity exists. **Mitigation (accepted risk, v1):** documented as pre-mainnet gate. Hard controls: (a) chain_def rejects if all 7 `unstake_destination_fp` identical (enforce destination diversity at parse time — v2 requirement, NOT v1 since v1 all-punk is intentional); (b) operator diversification is a tracked pre-mainnet milestone; (c) HSM-per-node key custody with operator-separation documented in a genesis ceremony doc before mainnet.

#### C-5 — `F-DOS-04`: Targeted committee DDoS = cheap full chain halt
7-member committee, 5/7 quorum → DDoS 3 nodes halts chain. Endpoints public in DHT. **Mitigation (accepted risk, v1):** v2 sortition rotates committee unpredictably. v1 interim: front-end proxies / DNS-based endpoint rotation, documented operational playbook for DDoS response.

#### C-6 — `F-ECON-02`: Single-operator cartel
Same root cause as C-4. Mitigation covered there.

### 7.3 High findings — mitigations to bake in

**TX format / preimage integrity** (must fix in §2.3):
- **`F-CRYPTO-12` (Design gap)** — `unstake_destination_fp` missing from TX_STAKE appended fields. **Fix §2.3:** STAKE appended = `commission_bps: u16 || unstake_destination_fp[64]`. Bound into signature, immutable post-STAKE (`F-STATE-05`).
- **`F-CRYPTO-01`** — CLAIM_REWARD timing replay (signed but delayed). **Fix §2.3:** CLAIM_REWARD appended = `target_validator[2592] || max_pending_amount: u64 || valid_before_block: u64`. Verify rejects if current pending > max OR current_block > valid_before_block.
- **`F-CRYPTO-02`** — VALIDATOR_UPDATE commission race via reordering. **Fix §2.3:** VALIDATOR_UPDATE appended = `new_commission_bps: u16 || signed_at_block: u64`. Verify rejects if stale (`current_block > signed_at_block + N`). Newer-signed update supersedes older pending.
- **`F-CRYPTO-06`** — Signer trailing-garbage malleability. **Fix §2.3:** TX hash preimage includes exactly `signer_count` signers, not fixed-length `signers[4]` array. Serialize truncates to `signer_count`.
- **`F-CRYPTO-08`** — u128 accumulator endianness drift across platforms. **Fix §3.4:** accumulator serializes as 16 bytes **big-endian** explicitly. Vendored bigint lib, not `__uint128_t`. KAT tests in `test_accumulator_math.c`.
- **`F-CRYPTO-04`** — Cross-tree Merkle leaf collision (validator_tree vs reward_tree same key). **Fix §3.2–§3.4:** leaf key = `SHA3-512(tree_tag_byte || data)`; `0x01=utxo`, `0x02=validator`, `0x03=delegation`, `0x04=reward`. Leaf value hash = `SHA3-512(tree_tag || record_cbor)`.

**Economic / incentive** (must fix in §2.4, §3.5, §3.6):
- **`F-ECON-11`** — No-liveness fee collection. Idle committee member still gets 1/7 share. **Fix §3.5:** only credit validators that signed ≥ `LIVENESS_THRESHOLD` (proposal: 80%) of blocks in this epoch. Non-signers' share redistributes pro-rata to active signers. Add `signature_attendance` tracking per committee member per epoch.
- **`F-ECON-03`** — Self-delegation ranking manipulation. Validator delegates to self to boost ranking. **Fix §3.6:** committee ranking uses `self_stake + external_delegated` where `external_delegated = total_delegated − self_delegation_amount`. Tracks self-delegation as a separate field on delegation record, or excludes delegations where `delegator_pubkey == validator_pubkey`.
- **`F-ECON-01`** — Commission front-run via VALIDATOR_UPDATE bait-and-switch (`F-CONS-04` same root). **Fix §2.4 + Rule F:** (a) commission **decrease** ALSO clears `pending_commission_bps` and `pending_effective_block` (prevents stale pending mis-applying). (b) Minimum exit window: increase takes effect at `pending_effective_block` only if `current_block + EPOCH_LENGTH ≤ pending_effective_block` at submission (always full epoch notice).

**DoS** (must fix in §2.4):
- **`F-DOS-07`** — 1 DNAC delegation holds validator UNSTAKE hostage indefinitely. **Fix Rule A:** UNSTAKE with active delegations triggers **automatic cascade-undelegate** — state step synthesizes one UTXO per delegator (principal + pending auto-claim), then validator enters RETIRING/cooldown. OR raise min delegation to 100 DNAC and keep Rule A as-is (latter simpler).
- **`F-DOS-02`** — Dust delegation Merkle bloat (10K DNAC sunk = 5GB state). **Fix §2.4:** raise min delegation to 100 DNAC (not 1 DNAC). Min UTXO output for DELEGATE = 100 × 10^8 raw.
- **`F-DOS-11`** — Offline validator never UNSTAKEs → chronic liveness drain. **Fix §3.6:** liveness gate — if validator misses all blocks in `LIVENESS_EJECTION_EPOCHS` (proposal: 3 consecutive epochs), validator_tree status auto-flips to `AUTO_RETIRED`, excluded from future committees. No slashing (no stake loss), just ejection. Validator can re-stake after cooldown.
- **`F-DOS-03`** — Dust threshold ≤ fee → rewards unclaimable. **Fix §2.4:** dust threshold dynamic: `max(10^6 raw, 10 × current_fee)`. Ensures claiming is always profitable.

**Consensus/BFT** (must fix in §3.6, §2.4):
- **`F-CONS-03`** — Mid-epoch UNSTAKE ambiguates BFT peer set. **Fix Rule H (new):** UNSTAKE mid-epoch sets `status = RETIRING`; graduation to `UNSTAKED` + cooldown-UTXO emission happens at next epoch boundary. BFT peer set always reads from frozen epoch snapshot.
- **`F-CONS-08`** — Drive-by committee seats (stake just before lookback snapshot, leave right after). **Fix §3.6:** `MIN_TENURE = 2 × EPOCH_LENGTH` (240 blocks). Validator's `active_since_block + MIN_TENURE ≤ snapshot_block` required for committee eligibility.

**State integrity** (must fix in §3.5, §3.9):
- **`F-STATE-02`** — Accumulator-vs-UNDELEGATE ordering causes over-distribution. **Fix §4.1:** commit step order — (1) verify TXs, (2) apply all state mutations FIRST, (3) THEN update accumulators using POST-mutation `total_delegated`. OR snapshot `(acc, total_delegated)` pre-mutation and use those values for auto-claim computation. Spec pins the order explicitly.
- **`F-STATE-07`** — STAKE re-entry after UNSTAKED. **Fix §2.4:** "NOT IN validator_tree" is literal — any record blocks. Retired validator must re-stake with NEW pubkey.
- **`F-STATE-11`** — UNSTAKE UTXO owner format ambiguity (fp vs pubkey). **Fix §4.5:** UTXO owner field format is consistent across UTXO tree (always fingerprint). Add genesis chain_def field: `initial_validators[i].unstake_destination_pubkey[2592]` alongside fp so SPEND can verify fp↔pubkey binding without out-of-band lookup.
- **`F-STATE-04`** — Genesis 70M supply-invariance not defensively checked. **Fix §5.2 genesis verify:** `require Σ outputs + Σ initial_validators[i].self_stake == DNAC_TOTAL_SUPPLY` AND `require initial_validator_count == 7`.

### 7.4 Medium/Low findings — absorb or defer

Medium findings are baked into the implementation test matrix (§6.5–6.7) with specific test cases. Low findings are accepted or documented. Full list in audit logs; highlights:

- Auto-claim dust skip on UNDELEGATE/UNSTAKE silently burns (`F-STATE-01`, `F-ECON-10`). **Fix:** always emit UTXO regardless of dust threshold on auto-claim paths (user-initiated CLAIM keeps dust threshold as spam protection; auto-claim must not lose supply).
- Empty-subtree Merkle root ambiguity (`F-STATE-08`). **Fix:** empty-tree root = `SHA3-512(single zero byte)`, specified explicitly.
- Accumulator integer division truncation (`F-ECON-04`, `F-STATE-09`). **Fix:** carry `residual_dust: u64` per validator to next block's delegator_pool; prove `Σ pieces == committee_share` per block.
- Pending validator pool unbounded (`F-DOS-01`). **Fix:** cap `MAX_VALIDATORS = 128`. STAKE rejects above cap. v2 sortition removes cap.
- Committee ranking tiebreak grindable (`F-CRYPTO-11`). **Fix:** tiebreak = `SHA3-512(tree_tag || pubkey || state_root_at_lookback)` — per-epoch re-mix prevents permanent grind advantage.
- VALIDATOR_UPDATE spam (`F-DOS-06`). **Fix:** per-validator cooldown — max 1 VALIDATOR_UPDATE per epoch.
- Pending-rewards query amplification (`F-DOS-05`). **Fix:** per-client read-RPC rate limit (10 QPS) and per-block result cache.
- Dust-delegation spam via short DELEGATE/UNDELEGATE loops (`F-ECON-06`). **Fix:** min delegation hold duration = 1 epoch before UNDELEGATE accepted.
- Validator identity hijacking via pubkey reuse (`F-CRYPTO-05`). **Fix:** STAKE preimage includes purpose tag `"DNAC_VALIDATOR_v1"` — prevents cross-protocol key reuse.
- Balance query locked-UTXO divergence (`F-STATE-06`). **Fix:** balance API returns `{confirmed, pending_unlock}` split, deterministic.
- DELEGATE snapshot race (`F-ECON-08`). **Fix:** DELEGATE's `reward_snapshot` = accumulator AFTER this block's update (§4.1 step order).
- Chain_def serialization canonical (`F-CRYPTO-07`). **Fix:** length-prefixed strings, explicit BE, zero unused bytes before hashing.
- Chain_id preimage binding for all new TX types (`F-CRYPTO-10`). **Fix:** explicit spec — TX hash preimage base = `version || type || timestamp || chain_id || inputs || outputs || signers[0..signer_count] || type-specific`.
- UNSTAKED validator still earns fees mid-epoch via lookback residency (`F-STATE-10`). **Fix:** RETIRING status (new Rule H) stops accumulator allocation at UNSTAKE-commit block even though BFT membership stays until epoch end.
- Epoch-boundary mass UNDELEGATE churn (`F-DOS-08`). **Accept:** 1-epoch lookback already mitigates.
- Delegation tree key ordering / domain separation (`F-CRYPTO-03`). **Fix:** applied via tree_tag bytes in `F-CRYPTO-04` mitigation.
- Locked UTXO SPEND overhead (`F-DOS-09`). **Accept:** read `unlock_block` in same row as nullifier.
- Genesis chain_def size (`F-DOS-12`). **Accept:** ~20KB, trivial.
- Epoch boundary compute spike (`F-DOS-13`). **Accept:** bounded by `MAX_VALIDATORS` cap; SQL index makes top-7 O(log N).
- Stale-delegation ghost (`F-STATE-12`). **Fix:** UNSTAKE verify asserts no delegation records with `validator=target` exist (not just counter==0). Delete transactional with decrement.

### 7.5 Accepted risks (documented, not mitigated in v1)

| ID | Description | Rationale |
|----|-------------|-----------|
| A-1 | Single-operator cluster (F-CONS-02 / F-ECON-02) | Pre-mainnet; operator diversification is a tracked milestone. |
| A-2 | Targeted committee DDoS (F-DOS-04) | v2 sortition mitigates via unpredictable rotation; interim = operational mitigation. |
| A-3 | Commission 100% griefing — one epoch of yield loss | Market-driven commission implies operator flexibility; delegator has instant undelegate escape. `max_accepted_bps` deferred to v2. |
| A-4 | No slashing → various griefing costs (F-ECON-11 mitigated by liveness gate, others absorbed) | v2 feature; liveness ejection gate covers most-damaging case (F-DOS-11) without requiring stake destruction. |
| A-5 | Accumulator truncation sub-unit rounding | F-STATE-09 mitigation via residual carry; monotonically bounded supply deviation. |
| A-6 | ~20KB chain_def size increase (F-DOS-12) | Negligible relative to block size. |

### 7.6 Design changes required before implementation

The following are concrete deltas folded back into Sections 2–6:

1. **§2.3 wire format additions** (F-CRYPTO-01, -02, -06, -12):
   - STAKE: `commission_bps: u16 || unstake_destination_fp[64]`
   - CLAIM_REWARD: `target_validator[2592] || max_pending_amount: u64 || valid_before_block: u64`
   - VALIDATOR_UPDATE: `new_commission_bps: u16 || signed_at_block: u64`
   - TX preimage rule: exactly `signer_count` signers, not fixed-length array.
   - TX preimage base explicitly includes `chain_id`.

2. **§2.4 verify rules additions**:
   - Rule H (new): mid-epoch UNSTAKE → `status = RETIRING`; graduation at next epoch boundary.
   - Rule I (new): `MIN_TENURE = 2 × EPOCH_LENGTH` for committee eligibility.
   - Rule J (new): UNSTAKE with active delegations auto-cascade-undelegates OR require 100 DNAC min delegation (pick one; design decision = raise min).
   - Rule K (new): VALIDATOR_UPDATE `signed_at_block` freshness; increase always has full-epoch exit window; decrease clears pending fields.
   - Rule L (new): dust threshold = `max(10^6 raw, 10 × current_fee)`.
   - Rule M (new): `MAX_VALIDATORS = 128` (pending pool cap).
   - Rule N (new): liveness ejection after 3 missed epochs → `AUTO_RETIRED`.
   - Rule O (new): min delegation 100 DNAC; min hold duration 1 epoch before UNDELEGATE.
   - Rule P (new): genesis verify asserts supply invariant + `initial_validator_count == 7`.
   - STAKE: "NOT IN validator_tree" is literal (any record blocks, including UNSTAKED); purpose tag in preimage.
   - STAKE: `unstake_destination_fp` immutable post-STAKE.
   - UNSTAKE verify: assert no delegation records exist with `validator=target`, not just counter==0.

3. **§3.1–§3.4 Merkle tree hashing**:
   - Tree-tag byte prefix on all leaf keys: `0x01=utxo, 0x02=validator, 0x03=delegation, 0x04=reward`.
   - Leaf value hash = `SHA3-512(tree_tag || record_cbor)`.
   - Empty-tree root = `SHA3-512(0x00)`.

4. **§3.4 accumulator serialization**:
   - Accumulator stored as 16 bytes **big-endian**. Vendored bigint, not `__uint128_t`. KAT test required.
   - Per-validator `residual_dust: u64` field added to reward_record; carried per block to avoid truncation loss.

5. **§3.5 accumulator math**:
   - Only credit validators with `signature_attendance ≥ LIVENESS_THRESHOLD` (80%) this epoch. Non-signer share redistributes pro-rata to signers.
   - Committee ranking = `self_stake + external_delegated` (excludes self-delegation from ranking math).

6. **§3.6 committee election**:
   - Snapshot = post-commit validator_tree_root of block `E_start − EPOCH_LENGTH − 1`.
   - Tiebreak = `SHA3-512(tree_tag || pubkey || state_root_at_lookback)`.
   - Bootstrap: if `E_start < EPOCH_LENGTH`, committee = `chain_def.initial_validators` sorted by tiebreak.

7. **§4.1 commit step order (explicit)**:
   ```
   1. verify all TXs, collect block_fee_pool
   2. apply ALL TX state mutations (UTXO, validator, delegation, reward records)
   3. update accumulators for committee using POST-mutation total_delegated;
      skip non-attending validators; redistribute skip share pro-rata
   4. recompute state_root
   5. BFT commit (single SQLite transaction wrapping 2–4)
   ```
   `reward_snapshot` at DELEGATE = accumulator AFTER step 3.

8. **§4.4/§4.5 auto-claim dust rule**:
   - On UNDELEGATE/UNSTAKE auto-claim: ALWAYS emit UTXO regardless of dust (supply preservation). User-initiated CLAIM keeps dust threshold.

9. **§5.1 chain_def additions**:
   - `initial_validators[i].unstake_destination_pubkey[2592]` added alongside fp.
   - Canonical serialization: length-prefixed strings, explicit BE ints, zero-fill tail.

10. **PBFT atomicity**:
    - All state mutations occur ONLY at COMMIT phase, after 5-of-7 PRECOMMIT signatures. Single SQLite transaction.
    - Every witness independently recomputes `state_root` on every PREVOTE before signing. No fast path.

### 7.7 Tests added to §6.5–6.7

New/updated unit tests for each mitigation:
- `test_preimage_binding.c` — STAKE/UPDATE/CLAIM signature covers all appended fields; chain_id binding
- `test_signer_canonical.c` — signer_count truncation hash behavior
- `test_accumulator_endianness.c` — KAT tests for u128 BE serialization
- `test_tree_tags.c` — cross-tree leaf-key collision rejection, empty-tree root determinism
- `test_liveness_gate.c` — non-attending validator share redistribution
- `test_cascade_undelegate.c` — UNSTAKE with delegators (if we pick cascade path) OR rejection (if we pick min-100-DNAC path)
- `test_commit_atomicity.c` — SQLite transaction rollback on partial state apply
- `test_min_tenure.c` — stake at block N, first epoch with eligibility = `ceil((N + 240) / 120)`
- `test_dust_dynamic.c` — claim reject when `pending < 10 × current_fee`
- `test_self_delegation_exclusion.c` — validator self-delegation excluded from ranking
- `test_validator_update_cooldown.c` — max 1 VALIDATOR_UPDATE per epoch
- `test_state_root_determinism.c` — compile two witnesses with different compilers/flags; verify bit-identical state_root

### 7.8 Audit verdict

**FOLDED (2026-04-17)**: all mitigations from §7.6 applied to §2–§6 body. Design doc is now self-consistent and ready for implementation planning.

Concrete changes applied to body (cross-reference to §7.6):
- §2.3 wire format extended: `unstake_destination_fp` + `purpose_tag` on STAKE, `max_pending_amount + valid_before_block` on CLAIM_REWARD, `signed_at_block` on VALIDATOR_UPDATE. Canonical preimage with chain_id binding and signer-count truncation explicit.
- §2.4 verify rules expanded from A–G (7 rules) to A–T (20 rules) covering every audit mitigation.
- §3.1–§3.4 Merkle leaves use tree_tag domain separators; empty-tree root specified; accumulator is big-endian 16-byte u128 via vendored bigint; `residual_dust`, `external_delegated`, `unstake_destination_pubkey`, liveness tracking fields added to records.
- §3.5 accumulator math includes liveness gate, residual-dust carry, exact-sum invariant.
- §3.6 committee election uses post-commit lookback snapshot, state_root-seeded tiebreak, MIN_TENURE gate, bootstrap path for block < EPOCH_LENGTH.
- §3.7 SQLite schema covers all new fields + UTXO.unlock_block.
- §4.1 commit step order pinned (9 steps) with explicit atomicity, state-before-accumulator ordering, and DELEGATE-snapshot-before-accumulator-bump rule.
- §4.4/§4.5 auto-claim always emits UTXO (Rule Q); UNSTAKE two-phase RETIRING→UNSTAKED.
- §4.6 formal supply invariance balance sheet with per-TX Δ table.
- §5.1 chain_def adds `unstake_destination_pubkey`, canonical-serialization discipline.
- §5.2 genesis verify rule asserts `initial_validator_count == 7` and supply invariant.
- §6.5 unit tests expanded from 9 to 21 tests covering every mitigation.

**No attacks remain open** that fundamentally break the architecture. Residual accepted risks (single-operator v1, v2-deferred slashing, commission griefing 1-epoch skim, targeted DDoS) are documented in §7.5 with operational/v2 mitigations.

The design is now ready for the `superpowers:writing-plans` handoff.

---

## 8. Open Questions (Deferred to v2)

- Slashing — BFT equivocation, downtime, double-signing penalties.
- Weighted random sortition (Algorand-style) replacing top-7 deterministic.
- Delegator-side `max_accepted_bps` cap with auto-undelegate on violation.
- Committee size growth beyond 7 (targeted: 10 → 13 → 19 as stake diversity grows).
- Validator endpoint on-chain (remove DHT dependency).
- Operator diversification: protocol-native operator-key rotation without UNSTAKE+restake dance.
