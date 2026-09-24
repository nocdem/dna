/**
 * @file nodus_witness_v2_econ.h
 * @brief The version-3 chain's economics: the committed economic
 *        parameters, the epoch reward distribution, the payday and the
 *        frozen balance copy (tokenomics-v3 P2).
 *
 * ── WHAT THIS FILE WAS, AND WHAT IT IS NOW ─────────────────────────
 * O15J Faz 2 ported V1's economics onto this lane verbatim: a PER-BLOCK
 * MINT on the 32 → 1 halving curve (nodus_witness_v2_emission_apply,
 * apply phase 6f), accumulated per epoch in `epoch_state`, and an EQUAL
 * per-seat settlement at every boundary that BURNED every remainder and
 * every missed share, while every transaction fee was burned too.
 *
 * tokenomics-v3 P2 replaces all of it. The governing record is
 * docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md (§1
 * "Ödüller ve ücretler", "Katılım ve cezalar"; §3 "P2 tasarım
 * soruları") and the contract is design
 * docs/plans/2026-09-23-tokenomics-v3-consensus-binding-design.md §7
 * (P2-1 … P2-9):
 *
 *   NO MINT. The total supply is fixed at genesis ("Yeni token
 *   basılmayacak"). The per-block mint, its halving curve and apply phase
 *   6f are DELETED; chain-config parameter id 3 (INFLATION_START_BLOCK)
 *   is RETIRED exactly as id 1 was.
 *
 *   A REWARD POOL. `supply_tracking.reward_pool` is seeded at genesis
 *   with the version-3 document's `reward_pool_initial` (carved OUT of
 *   the fixed total supply — genesis Rule P.2), grows by EVERY
 *   transaction fee (nodus_witness_rt_native.c, P2-3) and shrinks ONLY
 *   by the distribution below.
 *
 *   DISTRIBUTION at every boundary H over the epoch (H−E, H]
 *   (nodus_witness_v2_settlement_apply; design §7.1 "P2-6 rev 2",
 *   decision file §3 2026-09-24 "DELEGATOR = VALIDATOR GİBİ"): payout =
 *   reward_pool >> 16, split among the members of the snapshot that
 *   GOVERNED the epoch by that snapshot's own voting power; a member
 *   that failed the shared participation predicate forfeits its WHOLE
 *   share, delegators included; inside a member the split is by the
 *   frozen balance copy that snapshot was built from (src(H) = H−3E since
 *   tokenomics-v3 P3-2, 0 below 3E), checked against the snapshot entry
 *   first; every share is ACCRUED per recipient in `v2_reward_accrual`;
 *   every rounding remainder and every forfeited share stays in the
 *   pool. Nothing is burned. A stake withdrawn during the epoch is still
 *   in the governing snapshot and in the source copy, so it is paid for
 *   the epoch — and its release UTXO stays LOCKED until 12 epochs after
 *   it leaves the voting power (P2-10, nodus_witness_rt_native.c), which
 *   is what makes paying the governing set safe (no coin earns while it
 *   is spendable).
 *
 *   PAYDAY every `payout_interval_epochs` boundaries
 *   (nodus_witness_v2_payday_apply): every accrual row becomes one CORE
 *   UTXO and is deleted. An owner that left (UNDELEGATE deletes the
 *   delegation row; a validator graduates) is still paid — the accrual is
 *   keyed by the RECIPIENT, never by a stake row.
 *
 *   THE FROZEN BALANCE COPY (nodus_witness_v2_balance_copy_write): at
 *   every boundary (and at genesis) the bonded balances are copied into
 *   `v2_balance_copy`, out of every root; the H−2E, H−E and H copies are
 *   kept (tokenomics-v3 P3-2). The selection at H + E ranks by copy(H)
 *   (P3-1 "okuma B") and the distribution at H + 3E splits by it.
 *
 * ── FAULT/VERDICT CLASSIFICATION ────────────────────────────────────
 * Every entry point takes committed state and a height as its ONLY
 * inputs. None of them can be wrong about a block the way a signature
 * check can: there is no verdict class here. Every failure is therefore
 * -2, a NODE-LOCAL FAULT — the caller rolls the block back and does not
 * vote (nodus/CLAUDE.md "A DB failure is never a value"; approved record
 * atlas-dec-fb1307d36a5af51accfc9950174986bc).
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_ECON_H
#define NODUS_WITNESS_V2_ECON_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_epoch.h"   /* nodus_v2_epoch_fault_fn */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The economic parameters a PURE-V2 chain committed at its own genesis.
 *
 * ── THE DEFECT THIS CLOSES (O15J Faz 2 Block 2C) ────────────────────
 * DNAC_BLOCKS_PER_YEAR, DNAC_DECIMAL_UNIT (nodus_witness_emission.h) and
 * DNAC_EPOCH_LENGTH (dnac.h) are all `#ifndef`-guarded, so `-D` at
 * compile time changes a node's build identity. Before Block 2C none of
 * them appeared in any committed field: a differently-built node derived
 * the SAME chain id, joined cleanly, and then diverged at some later
 * height.
 *
 * The pure-V2 builder commits all three, at genesis, into the reserved
 * chain_config_history econ band (nodus_chain_config.h). Two independent
 * bindings result: the values are hashed into `source_commit` (so a
 * config change is a DIFFERENT CHAIN ID), and they are committed ROWS
 * the runtime can READ BACK — which is what catches a mismatched build
 * that arrived by syncing rather than by deriving.
 *
 * tokenomics-v3 P2: blocks_per_year has NO consumer any more (its one
 * consumer was the deleted per-block mint); the band stays committed
 * build identity. decimal_unit is still the voting-power unit (power =
 * total_stake / DNAC_DECIMAL_UNIT — the cometbft ValidatorUpdate, Rule
 * N's weight floor). The refusals of epoch_length AND decimal_unit
 * (below) are enforced on EVERY block — the apply engine calls this
 * loader once per block (nodus_witness_v2_apply.c phase 6f, "per-block
 * build-identity check"), relocated from the deleted mint so the check
 * did not vanish with it.
 *
 * `present == 0` is the honest answer for every chain built before
 * Block 2C: the compiled constants stand. A READ FAULT is never
 * `present == 0`.
 */
typedef struct {
    int      present;          /* 1 the chain committed a band; 0 it did
                                * not (compiled constants apply)         */
    uint64_t blocks_per_year;  /* valid only when present                */
    uint64_t decimal_unit;     /* valid only when present                */
    uint64_t epoch_length;     /* valid only when present                */
} nodus_v2_econ_params_t;

/**
 * Load the committed econ band, and VALIDATE it against this build.
 *
 * Three-valued by construction:
 *   0  either all three rows are present and usable (`out->present == 1`)
 *      or NONE of them is (`out->present == 0`, compiled constants apply)
 *  -1  a fault: the table is unreadable, the band is PARTIAL (some rows
 *      present, some absent — a chain in that state has no defined
 *      economics), a committed value is 0 or stored negative, the
 *      committed epoch_length disagrees with the compiled
 *      DNAC_EPOCH_LENGTH, or the committed decimal_unit disagrees with
 *      the compiled DNAC_DECIMAL_UNIT.
 *
 * WHY decimal_unit IS CHECKED TOO. DNAC_DECIMAL_UNIT is read as a macro
 * wherever voting power is derived (the cometbft ValidatorUpdate, Rule
 * N's weight floor). The genesis builder refuses a config that disagrees
 * with it, but a node that SYNCED never ran the builder; this refusal is
 * what stops it from reporting every power scaled differently from its
 * peers. Same detection-not-parameterisation stance as epoch_length.
 *
 * WHY epoch_length IS CHECKED RATHER THAN USED. DNAC_EPOCH_LENGTH is read
 * as a macro by the vset snapshot builder, the committee selector, the
 * boundary gate, the reward distribution and the payday rule. Rewiring
 * every one of those is a different change. The honest guarantee is
 * REFUSAL — a build whose epoch length disagrees with the chain's
 * committed one stops, rather than quietly keying its epochs differently
 * from its peers. That is DETECTION, and it is labelled as such.
 *
 * Pure read; opens no transaction and writes nothing.
 *
 * @param w    witness handle (open DB).
 * @param out  required; always fully initialised, including on -1.
 * @return 0 / -1 (the reason is logged).
 */
int nodus_witness_v2_econ_params_load(nodus_witness_t *w,
                                      nodus_v2_econ_params_t *out);

/**
 * THE FROZEN BALANCE COPY (tokenomics-v3 P2, design §7 P2-5).
 *
 * Writes `v2_balance_copy` rows for `epoch_start`:
 *   - one row per `validators` row with self_stake != 0:
 *       (epoch_start, fp(pubkey), fp(pubkey), self_stake)
 *   - one row per `delegations` row:
 *       (epoch_start, fp(validator_pubkey), fp(delegator_pubkey), amount)
 * where fp = the raw 64-byte SHA3-512(pubkey) (the recipient identity the
 * accrual and the payday UTXO owner use). Then DELETES every row whose
 * epoch_start is below `epoch_start − 2·DNAC_EPOCH_LENGTH` — the H−2E,
 * H−E and H copies are kept, nothing older (tokenomics-v3 P3-2; P2 kept
 * two).
 *
 * TWO READERS (tokenomics-v3 P3-1, P3-2):
 *   - SELECTION ("okuma B"): the commit_next of boundary B ranks the set
 *     it stores for B+E by the frozen totals of copy(B−E)
 *     (nodus_witness_v2_balance_copy_frozen below, called by
 *     nodus_committee_compute_for_epoch) and writes them into the
 *     snapshot entries;
 *   - DISTRIBUTION: boundary H reads copy(H−3E) — the copy the governing
 *     snapshot(H−E) was built from at boundary H−2E (src(H) = 0 while
 *     H < 3E: the genesis snapshots 0 and E come from the genesis rows =
 *     copy(0), and snapshot(2E) is built at E from copy(0)). The copy
 *     kept at boundary H as "H−2E" is read by the distribution at H + E,
 *     which runs before that boundary's own prune.
 *
 * OUT OF EVERY ROOT, deliberately: every row is a pure function of
 * `validators` and `delegations`, which ARE rooted, taken at a
 * boundary. The distribution CHECKS each governing member's copy rows
 * against its snapshot entry (self row == self_bond, Σ delegator rows ==
 * total_stake − self_bond) and FAULTS on a mismatch, so a node whose
 * copy diverged stops at the boundary that reads it instead of paying a
 * different accrual; a divergence the check cannot see (a delegator row
 * moved between two delegators of one member, sums intact) pays a
 * different accrual, and accrual_root (core_state_root) catches it at
 * that boundary.
 *
 * A stored-negative stake or amount, a malformed pubkey, a row that
 * already exists for (epoch_start, validator, owner) — every one is a
 * FAULT, never skipped.
 *
 * MUST run inside the caller's transaction; opens/commits nothing.
 * Called by the engine genesis (epoch 0) and at the END of every epoch
 * boundary (nodus_witness_v2_epoch_boundary_apply, after the graduation
 * so the copy reflects the bonded state the next epoch starts from).
 *
 * @return 0 / -2.
 */
int nodus_witness_v2_balance_copy_write(nodus_witness_t *w,
                                        uint64_t epoch_start);

/**
 * tokenomics-v3 P3-1 — one validator's FROZEN totals in copy(epoch_start):
 *   *self_out  = the amount of its own row (owner_fp == validator_fp),
 *                0 when that row is absent;
 *   *total_out = its own row + Σ every delegator row of that validator,
 *                0 when it has no row at all ("absent means 0").
 * validator_fp = the raw 64-byte SHA3-512(pubkey) — the copy's key, NOT
 * the validators table's pubkey_hash (SHA3-512(0x02 ‖ pubkey)).
 *
 * The selection core (nodus_committee_compute_for_epoch) ranks candidates
 * by *total_out and writes *total_out / *self_out as the snapshot entry's
 * total_stake / self_bond; the reward distribution later checks that
 * entry against the same copy through the same row reader.
 *
 * Pure read. Query-lane convention: 0 read (including "absent" = 0/0),
 * -1 fault (bad argument, hash failure, DB error, a stored-negative
 * amount, a sum that overflows 64 bits). A fault is never a zero.
 */
int nodus_witness_v2_balance_copy_frozen(nodus_witness_t *w,
                                         uint64_t epoch_start,
                                         const uint8_t *pubkey,
                                         uint64_t *self_out,
                                         uint64_t *total_out);

/**
 * The chain's payout interval, in epochs (tokenomics-v3 P2, P2-7):
 *   - a chain with a stored version-3 genesis document: the document's
 *     `payout_interval_epochs`, read through the canonical-strict
 *     accessor (nodus_witness_v2_gen_stored_doc) — a document that does
 *     not read back, or carries 0, is a FAULT;
 *   - a version-3 successor chain (w->v2_successor) WITHOUT its document:
 *     FAULT — every such chain stores its document at derivation;
 *   - any other chain (no document: the pre-document fixture lane that
 *     builds its genesis through nodus_witness_v2_genesis_ex): the
 *     version-3 default NODUS_V2_GEN_PAYOUT_INTERVAL_EPOCHS_DEFAULT (24),
 *     the same "nothing committed -> compiled constant" rule
 *     nodus_witness_v2_econ_params_load applies to a chain with no band.
 *
 * @param out  required; written only on 0.
 * @return 0 / -2.
 */
int nodus_witness_v2_payout_interval(nodus_witness_t *w, uint64_t *out);

/**
 * THE EPOCH REWARD DISTRIBUTION (tokenomics-v3 P2, design §7 P2-6 as
 * REVISED by §7.1 "P2-6 rev 2"; decision file §3 2026-09-24 "DELEGATOR =
 * VALIDATOR GİBİ") — replaces the O15J equal-per-seat, burning
 * settlement. Runs at boundary H for the epoch (H−E, H] that just ended:
 *
 *   payout   = reward_pool >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2 (16)
 *   members  = snapshot(H−E) (nodus_witness_v2_epoch_authority_for_epoch;
 *              the set that GOVERNED the epoch, in its committed order)
 *   src      = H−3E when H >= 3E, else 0 — the frozen balance copy that
 *              snapshot was built from (tokenomics-v3 P3-2: the
 *              commit_next of boundary H−2E ranked it by copy(H−3E) —
 *              P3-1 "okuma B"; the genesis snapshots 0 and E and copy(0)
 *              all come from the genesis rows, and snapshot(2E) is built
 *              at E from copy(0))
 *   PASS 1, for EVERY member v (snapshot order):
 *     CONSISTENCY GATE: copy(src)'s self row of v (absent = 0) must equal
 *                 the entry's self_bond, and Σ copy(src) delegator rows
 *                 of v must equal total_stake − self_bond; otherwise
 *                 FAULT -2 before anything is paid (the two structures
 *                 were built from one state — a mismatch is local
 *                 corruption or a broken external_delegated writer)
 *     power_v   = entry.total_stake / DNAC_DECIMAL_UNIT
 *   Σpower over ALL members — including a member with no row and one
 *   that misses the bar below, so a forfeited share is never
 *   redistributed to the members that attended (§3 "P2 tasarım
 *   soruları" (2)). Σpower == 0 -> nothing is paid, the pool stays.
 *   PASS 2, for each member v (snapshot order):
 *     share_v   = floor(payout × power_v / Σpower)       (128-bit)
 *     share_v == 0, no validators row, or the shared participation
 *     predicate (nodus_witness_v2_attendance_meets_bar at H) fails
 *                -> share_v STAYS IN THE POOL, delegators included
 *     base      = floor(share × self_bond / total_stake)  (the entry's)
 *     gross     = share − base
 *     commission= floor(gross × commission_bps / 10000), commission_bps
 *                 from the snapshot(H−E) ENTRY (frozen with the set)
 *     net       = gross − commission
 *     x_d       = floor(net × a_d / Σa_d), a_d = the delegator's
 *                 copy(src) amount, delegators in owner_fp ASC order
 *                 (Σa_d == 0 with net > 0: net stays in the pool)
 *     accrue    base + commission to fp(v), x_d to each delegator's fp
 *   reward_pool −= Σ accrued (checked; bound to the observed value)
 *
 * There is no "left mid-epoch" stake any more: a delegator that
 * withdraws during (H−E, H] is still in snapshot(H−E) and in copy(src),
 * so it is paid for the epoch it was counted in — and its release UTXO
 * is locked until L(h) + 12 epochs (P2-10, nodus_witness_rt_native.c;
 * nodus_v2_power_exit_boundary), so no counted coin is spendable while
 * it earns. A flash delegation into the governing set is locked the
 * same way, so it is no lever.
 *
 * Every rounding remainder stays in the pool (share − base − commission
 * − Σx_d, and payout − Σshare). `has_row` (a validators row exists) is
 * read at H BEFORE this boundary's own transitions: the distribution
 * runs ahead of the graduation (boundary order, header of
 * nodus_witness_v2_epoch.h), so a leaving validator that kept signing
 * through its last seated epoch is paid for it — the decision file §3
 * (graduation deferral) states it must keep signing that epoch and
 * loses the epoch's share only if it stops (the bar). It also runs
 * ahead of step 6's prune, which deletes copy(src).
 *
 * TOUCHED-DOMAIN OBLIGATION OF THE CALLER. A nonzero *accrued_out moved
 * `v2_reward_accrual` and `supply_tracking.reward_pool` — both CORE
 * state-root legs — so CORE is declared touched exactly when it is > 0.
 *
 * MUST run inside the caller's transaction, BEFORE the attendance reset
 * (it reads the ended epoch's attendance through the shared predicate)
 * and BEFORE the boundary's balance-copy write (whose prune deletes
 * copy(src)). Fault stages NODUS_V2_EPST_DIST_ACCRUED /
 * NODUS_V2_EPST_DIST_APPLIED.
 *
 * @param boundary_height  H — a positive multiple of DNAC_EPOCH_LENGTH.
 * @param accrued_out      required; Σ credited this boundary.
 * @return 0 (including "nothing to pay": an empty pool, a zero payout,
 *         a zero total power); -2 NODE-LOCAL FAULT (a DB or allocation
 *         failure, or the consistency gate refusing a member).
 */
int nodus_witness_v2_settlement_apply(nodus_witness_t *w,
                                      uint64_t boundary_height,
                                      nodus_v2_epoch_fault_fn fault,
                                      void *fault_ud,
                                      uint64_t *accrued_out);

/**
 * PAYDAY (tokenomics-v3 P2, design §7 P2-7). At boundary H with
 * (H / DNAC_EPOCH_LENGTH) % payout_interval_epochs == 0, every
 * `v2_reward_accrual` row (owner_fp ASC) becomes ONE CORE UTXO — owner =
 * lowercase-hex(owner_fp), amount = the accrual, native token, unlock 0,
 * block_height = H, tx_hash = nodus_witness_v2_settlement_tx_hash(H),
 * nullifier = nodus_witness_v2_settlement_nullifier(tx_hash,
 * NODUS_V2_SETTLE_KIND_ACCRUAL, NODUS_V2_SETTLE_OUT_IDX_BASE + i) with i
 * the row's rank — written through the typed CORE effect path — and
 * then every accrual row is deleted. Any other height is a no-op.
 *
 * TOUCHED-DOMAIN OBLIGATION: CORE, exactly when *n_utxos_out > 0.
 * Fault stages NODUS_V2_EPST_PAYDAY_EMITTED / NODUS_V2_EPST_PAYDAY_APPLIED.
 *
 * @param interval  payout_interval_epochs (nodus_witness_v2_payout_
 *                  interval); 0 is a FAULT.
 * @return 0 / -2.
 */
int nodus_witness_v2_payday_apply(nodus_witness_t *w,
                                  uint64_t boundary_height,
                                  uint64_t interval,
                                  nodus_v2_epoch_fault_fn fault,
                                  void *fault_ud,
                                  uint32_t *n_utxos_out);

/**
 * The payday UTXO batch's canonical tx_hash — SHA3-512("settlement" ‖
 * u64be(key)), the V1 derivation at nodus_witness_bft.c:2977-2986 with a
 * BYTE-IDENTICAL preimage (the 10-byte ASCII tag carries no NUL). Since
 * tokenomics-v3 P2 the key is the PAYDAY BOUNDARY HEIGHT H.
 *
 * EXPORTED so a test can recompute the identity of a payday row
 * independently instead of reading it back out of the row it checks.
 *
 * @return 0 / -2 on a NULL argument or a hash-backend fault.
 */
int nodus_witness_v2_settlement_tx_hash(uint64_t key, uint8_t out[64]);

/**
 * The payday UTXO's nullifier — SHA3-512(tx_hash ‖ kind ‖
 * u32be(output_index)), the V1 synthetic derivation at
 * nodus_witness_bft.c:3041-3052.
 *
 * @return 0 / -2 on a NULL argument or a hash-backend fault.
 */
int nodus_witness_v2_settlement_nullifier(const uint8_t tx_hash[64],
                                          uint8_t kind,
                                          uint32_t output_index,
                                          uint8_t out[64]);

/* The payout kind bytes. 0x20 (validator) and 0x21 (delegator) were the
 * O15J per-boundary settlement's (bft.c:3261 / :3314); that settlement
 * is gone and the two values are RETIRED — never reused. The P2 payday
 * pays ONE kind, the accrual, APPENDED. */
#define NODUS_V2_SETTLE_KIND_ACCRUAL   ((uint8_t)0x22)

/** V1's settlement output-index base (bft.c NODUS_EPOCH_SETTLE_
 *  OUTPUT_INDEX_BASE, :3025): clear of the UNDELEGATE range (100-101)
 *  and of the graduation range (200..327). */
#define NODUS_V2_SETTLE_OUT_IDX_BASE   ((uint32_t)400)

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_ECON_H */
