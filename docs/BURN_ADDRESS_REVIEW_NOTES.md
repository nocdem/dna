# Burn Address Implementation — Review Notes

Review performed 2026-04-08 across 4 rounds of parallel agent audits.

## Non-Bug Observations (Pre-existing or By-Design)

### 1. Output truncation uses `break` not `return -1`
**Location:** `nodus_witness_bft.c`, `update_utxo_set()` output loop
**Details:** If an output is truncated mid-parse, the loop `break`s and continues
with partial `total_output`. The input loop was hardened to `return -1`.
**Why not a bug:** `nodus_witness_verify_transaction()` rejects truncated tx_data
before it reaches `update_utxo_set`. Remote COMMIT also verifies tx_hash integrity.
**Recommendation:** Consider changing output truncation to `return -1` for consistency.

### 2. Input amounts read from tx_data, not UTXO DB
**Location:** `update_utxo_set()` input parsing loop
**Details:** Fee is computed from wire tx_data input amounts, not by re-fetching
from the UTXO DB (which is what `nodus_witness_verify.c` does).
**Why not a bug:** tx_hash integrity check at COMMIT time ensures tx_data matches
what was verified. A mismatch would fail the hash recompute.
**Recommendation:** Document this trust assumption.

### 3. No overflow guard in `update_utxo_set` input summation
**Location:** `update_utxo_set()`, `total_input += in_amt`
**Details:** No `if (total_input + in_amt < total_input)` overflow check, unlike
`nodus_witness_verify.c` which has explicit overflow protection.
**Why not a bug:** Verify rejects overflow before commit. tx_hash integrity prevents
modified amounts from reaching this path.
**Recommendation:** Add defensive overflow check for defense-in-depth.

### 4. `current_supply == genesis_supply - total_burned` not verified
**Location:** Supply invariant check in `commit_block_inner()`
**Details:** The invariant check only verifies `genesis_supply == utxo_sum`. The
`supply_tracking.current_supply` field is tracked but never independently validated.
**Why not a bug:** The UTXO sum invariant is the primary correctness check. The
`current_supply` field is for informational queries (`dnac_supply` command).
**Recommendation:** Add a secondary check: `current_supply == genesis - burned`.

### 5. Two separate DNAC_BURN_ADDRESS definitions
**Location:** `nodus/include/nodus/nodus_types.h` and `dnac/include/dnac/dnac.h`
**Details:** Same constant defined in two files. Could theoretically diverge.
**Why not a bug:** Nodus and DNAC are independent build targets — neither includes
the other's headers. Duplication is architecturally necessary.
**Recommendation:** Both have matching comments. Consider a build-time assertion.

### 6. `round_state.fee_amount` passed as `total_supply` parameter
**Location:** Legacy single-TX path calling `nodus_witness_commit_block()`
**Details:** The 6th argument is semantically `total_supply` but receives `fee_amount`.
**Why not a bug:** `total_supply` is only consumed for GENESIS TXs. Genesis always
has `fee_amount == 0`, and the function re-parses supply from tx_data when 0.
**Recommendation:** Rename parameter or add clarifying comment.

### 7. Pre-existing chain supply invariant will fail
**Details:** Old TXs committed before burn address didn't create burn UTXOs. After
upgrade, `genesis_supply > utxo_sum` by the sum of all historical fees.
**Mitigation:** A one-time migration burn UTXO can reconcile the delta:
`genesis_supply - utxo_sum = accumulated_lost_fees`. Create a single burn UTXO
for this amount to restore the invariant.

## Bugs Found and Fixed

| Round | Bug | Commit |
|-------|-----|--------|
| 2 | `supply_tracking` table never created (supply_init not called) | fc6b9b71 |
| 3 | Burn UTXO hash/insert failure silently swallowed | fda6f94d |
| 3 | `total_burned`/`current_supply` never updated | fda6f94d |
| 3 | `supply_init` failure non-fatal | fda6f94d |
| 4 | `supply_add_burned` failure non-fatal | 1d577105 |
| 5 | `tx_hash` NULL guard missing in `supply_add_burned` | 8d90d740 |
| 6 | Output truncation `break` → `return -1` (inflated fee) | f218a6b7 |
| 6 | `utxo_sum` returns 0 on step failure with uninitialized output | f218a6b7 |
| 6 | `supply_add_burned` silent no-op when row missing (sqlite3_changes) | f218a6b7 |
| 7 | Output nullifier hash failure `continue` → `return -1` (coins lost) | pending |
