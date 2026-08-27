/**
 * @file nodus_witness_v2_econ.h
 * @brief O15J Faz 2 — V1's economics, ported verbatim onto the Ledger V2
 *        lane: per-block inflation emission and epoch settlement.
 *
 * ── WHY THIS FILE EXISTS ────────────────────────────────────────────
 * A pure-V2 chain (one born without a legacy ancestor) never executes
 * `finalize_block`, and `finalize_block` is where V1 keeps its entire
 * issuance and reward machinery: the emission block
 * (nodus_witness_bft.c:3640-3700) and the settlement trigger
 * (nodus_witness_bft.c:3730-3743 calling apply_epoch_settlement at
 * :3085). With neither running, a V2 chain mints nothing and — because
 * both lanes already burn every transaction fee — pays validators
 * exactly zero. That is the O15J red-team's L2-F5, recorded in
 * docs/plans/2026-08-26-pure-v2-genesis-design.md §3.4.
 *
 * The user's decision (2026-08-26, §5 of that document) is "V1'in
 * aynısı": the specification of this port is the SHIPPED V1
 * implementation, not a new design. Every rule below is cited to the
 * bft.c line that defines it, and where this port cannot be literal the
 * divergence is named at the point where it happens — never smoothed
 * over.
 *
 * ── THE THREE PARTS, AND WHERE EACH ONE LIVES ───────────────────────
 *   Fee     — already identical on both lanes: the CORE runtime's SPEND
 *             and BURN legs add every destroyed value to
 *             supply_tracking.total_burned regardless of leg kind
 *             (nodus_witness_rt_native.c rtn_supply_burn_eff), which is
 *             V1's route_tx_fee rule (bft.c:731-733). NOTHING HERE.
 *   Emission— nodus_witness_v2_emission_apply, below. A PER-BLOCK hook.
 *   Settle  — nodus_witness_v2_settlement_apply, below. A phase of
 *             nodus_witness_v2_epoch_boundary_apply.
 *
 * ── TWO MORE DIVERGENCES, FOUND BY REVIEW R1 AND NAMED HERE ─────────
 * The four divergences documented at their own sites are not the whole
 * list. Review R1 found two more; both are recorded rather than
 * silently carried.
 *
 * 5. AN ACTIVE CORE RUNTIME IS A PRECONDITION FOR PAYING OUT.
 *    nodus_witness_v2_settlement_apply resolves the CORE runtime with
 *    require_active = 1 and FAULTS if it does not resolve. V1 has no
 *    such precondition — it writes the payout row with raw SQL and does
 *    not care whether a runtime exists. So on a chain whose CORE is
 *    registered but not ACTIVE, V1 pays and this lane halts the block.
 *    Deliberate: paying out through a runtime that is not active would
 *    mean writing domain state with no owner, which is exactly what the
 *    typed effect boundary exists to prevent. Named because "four
 *    divergences" was an undercount, not because the choice is doubted.
 *
 * 6. THE PER-EPOCH COUNTER RESET IS UNCONDITIONAL HERE, CONDITIONAL IN
 *    V1 — a REAL committed-state difference between the lanes.
 *    V1's two whole-pool exits (no usable snapshot; committee_count 0)
 *    `return 0` BEFORE its counter reset, so on those two paths V1 does
 *    NOT clear signed_blocks_this_epoch and the counts carry into the
 *    next epoch. On this lane the reset belongs to Rule N step (d)
 *    (O15C) and runs unconditionally after settlement returns.
 *    `signed_blocks_this_epoch` IS a validator merkle-leaf field
 *    (nodus_witness_merkle.c), so the two lanes commit different state
 *    on those paths.
 *    NOT a fork risk — the lanes never run on one chain — and arguably
 *    the better behaviour, since V1's carry-over inflates the next
 *    epoch's attendance and hides downtime. But it is a divergence from
 *    "V1'in aynısı" and it was nowhere in writing until now.
 *
 * ── FAULT/VERDICT CLASSIFICATION ────────────────────────────────────
 * Both entry points take committed state and a height as their ONLY
 * inputs. Neither can be wrong about a block the way a signature check
 * can: there is no verdict class here. Every failure is therefore -2, a
 * NODE-LOCAL FAULT — the caller rolls the block back and does not vote.
 * This is the same convention nodus_witness_v2_epoch.h states for the
 * boundary, and the reason neither function returns -1.
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
 * PER-BLOCK INFLATION EMISSION — the port of nodus_witness_bft.c
 * :3640-3700.
 *
 * Rule, verbatim:
 *   inflation_start = chain_config(DNAC_CFG_INFLATION_START_BLOCK,
 *                                  at height, DEFAULT 1)
 *   emission = (inflation_start != 0 && height >= inflation_start)
 *              ? nodus_emission_per_block(height) : 0
 *   if emission > 0:
 *       supply_tracking.total_minted += emission        (bft.c:3666)
 *       epoch_state[floor(h/E)*E].epoch_pool_accum += emission
 *                                                       (bft.c:3679)
 *       and, when that row did not exist, seed it and capture the
 *       epoch-start committee+delegation snapshot
 *       (nodus_witness_epoch_snapshot_apply, bft.c:3709)
 *
 * THE 1ULL DEFAULT IS LOAD-BEARING, not a convenience: an override that
 * cannot be fetched must not silently disable emission on one node and
 * leave it on for another. Two nodes disagreeing about whether a block
 * minted is a state_root split. bft.c:3652-3654 says exactly this, and
 * the value is copied from there rather than chosen here.
 *
 * TOUCHED-DOMAIN OBLIGATION OF THE CALLER. A non-zero mint moves
 * supply_tracking — a leg of the CORE state root
 * (nodus_witness_roots_v2.c:342-345) — and epoch_state — a leg of the
 * SYSTEM state root (:283-284). The caller MUST declare BOTH domains
 * touched when *minted_out > 0, and NEITHER when it is 0: the apply
 * engine rejects an undeclared mutation (nodus_witness_v2_apply.c
 * :2888-2901) AND a declared no-op (:2912-2919). That is why this
 * function reports what it minted.
 *
 * MUST run inside the caller's transaction and BEFORE any root
 * computation. Opens, commits and rolls back nothing.
 *
 * @param w             witness handle (open DB).
 * @param global_height the block's GLOBAL height.
 * @param minted_out    required; receives the raw amount minted (0 when
 *                      emission is off, or before the start block).
 * @return 0 applied (including a legitimate zero-mint height);
 *         -2 NODE-LOCAL FAULT.
 */
int nodus_witness_v2_emission_apply(nodus_witness_t *w,
                                    uint64_t global_height,
                                    uint64_t *minted_out);

/**
 * EPOCH SETTLEMENT — the port of apply_epoch_settlement
 * (nodus_witness_bft.c:3085-3378; contract comment at :2917-2957).
 *
 * Drains epoch_state[settling_epoch_start].epoch_pool_accum into CORE
 * UTXOs and burn, per the V1 rule:
 *
 *   per_slot   = pool / committee_count
 *   outer_dust = pool - per_slot * committee_count          -> BURN
 *   for each committee validator V (snapshot order):
 *       if V missed the liveness bar this epoch: per_slot    -> BURN
 *       else if V has no delegations:  emit_utxo(V, per_slot)
 *       else:
 *           validator_base  = per_slot * self_stake / total_stake
 *           delegator_gross = per_slot - validator_base
 *           commission      = delegator_gross * commission_bps / 10000
 *           validator_total = validator_base + commission
 *           delegator_net   = delegator_gross - commission
 *           emit_utxo(each D, delegator_net * D.amount / total_delegated)
 *           inner_dust      = delegator_net - SUM(shares)    -> BURN
 *           emit_utxo(V, validator_total)
 *   delete epoch_state[settling_epoch_start]
 *
 * THE THREE BURN LEGS ARE ONE COUNTER. outer_dust (bft.c:3147), the
 * absent validator's per_slot (:3250) and inner_dust (:3326) accumulate
 * into one total and reach supply_tracking through ONE call (:3369).
 * Two whole-pool burn branches exist beside them: no usable snapshot
 * (:3103) and an empty committee (:3134). A port that drops any leg does
 * not balance at the first boundary, because dust is MINTED value that
 * could not be distributed — see the design document §5.3.
 *
 * TOUCHED-DOMAIN OBLIGATION OF THE CALLER. Emitted UTXOs and the burn
 * both move the CORE state root; the epoch_state deletion moves the
 * SYSTEM root (which a fired boundary already declares). The caller MUST
 * declare CORE touched exactly when (*n_utxos_out > 0 || *burned_out >
 * 0). Both outputs exist for that decision.
 *
 * MUST run inside the caller's transaction, and BEFORE the per-epoch
 * signed-block counters are reset — see the ordering note in
 * nodus_witness_v2_epoch.c, and the report of this port.
 *
 * @param w                    witness handle (open DB).
 * @param settling_epoch_start canonical epoch key of the epoch that just
 *                             ENDED (block_height - DNAC_EPOCH_LENGTH).
 * @param fault                optional stage-fault callback (NULL = none).
 * @param fault_ud             opaque cookie for `fault`.
 * @param n_utxos_out          required; settlement UTXOs emitted.
 * @param burned_out           required; the ONE accumulated burn.
 * @return 0 applied (including "no row for that epoch — nothing to
 *         settle", which is the honest state of a chain whose first
 *         epoch predates emission);
 *         -2 NODE-LOCAL FAULT.
 */
int nodus_witness_v2_settlement_apply(nodus_witness_t *w,
                                      uint64_t settling_epoch_start,
                                      nodus_v2_epoch_fault_fn fault,
                                      void *fault_ud,
                                      uint32_t *n_utxos_out,
                                      uint64_t *burned_out);

/**
 * The settlement UTXO batch's canonical tx_hash — SHA3-512("settlement"
 * ‖ u64be(settling_epoch_start)), the V1 derivation at
 * nodus_witness_bft.c:2977-2986 with a BYTE-IDENTICAL preimage (the
 * 10-byte ASCII tag carries no NUL).
 *
 * EXPORTED so a test can recompute the identity of a settlement row
 * independently instead of reading it back out of the row it is meant to
 * be checking.
 *
 * @return 0 / -2 on a NULL argument or a hash-backend fault.
 */
int nodus_witness_v2_settlement_tx_hash(uint64_t settling_epoch_start,
                                        uint8_t out[64]);

/**
 * The settlement UTXO's nullifier — SHA3-512(tx_hash ‖ kind ‖
 * u32be(output_index)), the V1 synthetic derivation at
 * nodus_witness_bft.c:3041-3052. `kind` is 0x20 for a validator payout
 * and 0x21 for a delegator payout (bft.c:3261 and :3333 / bft.c:3314).
 *
 * EXPORTED for the same reason as the tx_hash above.
 *
 * @return 0 / -2 on a NULL argument or a hash-backend fault.
 */
int nodus_witness_v2_settlement_nullifier(const uint8_t tx_hash[64],
                                          uint8_t kind,
                                          uint32_t output_index,
                                          uint8_t out[64]);

/** V1's settlement payout kind bytes (bft.c:3261 / :3314). */
#define NODUS_V2_SETTLE_KIND_VALIDATOR ((uint8_t)0x20)
#define NODUS_V2_SETTLE_KIND_DELEGATOR ((uint8_t)0x21)

/** V1's settlement output-index base (bft.c NODUS_EPOCH_SETTLE_
 *  OUTPUT_INDEX_BASE, :3025): clear of the UNDELEGATE range (100-101)
 *  and of the graduation range (200..327). */
#define NODUS_V2_SETTLE_OUT_IDX_BASE   ((uint32_t)400)

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_ECON_H */
