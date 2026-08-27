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
 * The economic parameters a PURE-V2 chain committed at its own genesis.
 *
 * ── THE DEFECT THIS CLOSES (O15J Faz 2 Block 2C) ────────────────────
 * DNAC_BLOCKS_PER_YEAR, DNAC_DECIMAL_UNIT (nodus_witness_emission.h) and
 * DNAC_EPOCH_LENGTH (dnac.h) are all `#ifndef`-guarded, so `-D` at
 * compile time changes how much a node mints and where its epoch
 * boundaries fall. Before this change none of them appeared in any
 * committed field: a differently-built node derived the SAME chain id,
 * joined cleanly, and then credited a different amount at some later
 * height — a CORE root divergence with nothing visible on the wire.
 *
 * The pure-V2 builder now commits all three, at genesis, into the
 * reserved chain_config_history econ band (nodus_chain_config.h). Two
 * independent bindings result, and they are NOT the same property:
 *   1. the values are hashed into `source_commit`, which the manifest
 *      carries into dna_bh2_genesis_block_id (nodus_witness_v2_apply.c
 *      :865) — so a config change is a DIFFERENT CHAIN ID;
 *   2. the values are committed ROWS, so they reach chain_config_root →
 *      SYSTEM root (nodus_witness_roots_v2.c:266, :285), they travel to
 *      joiners in the genesis bundle (nodus_witness_v2_bundle.c:47), and
 *      — the point — the runtime can READ THEM BACK. Binding alone would
 *      be decorative: a joiner never runs the builder, so only a readable
 *      committed value can catch a mismatched build that arrived by
 *      syncing rather than by deriving.
 *
 * `present == 0` is the honest answer for every chain built before this
 * change (and for every seam successor, which has no operator config to
 * express these values): the compiled constants stand, and behaviour is
 * byte-identical to what it was. A READ FAULT is never `present == 0`.
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
 * Three-valued by construction — the shape nodus/CLAUDE.md demands of a
 * read whose answer reaches consensus:
 *   0  either all three rows are present and usable (`out->present == 1`)
 *      or NONE of them is (`out->present == 0`, compiled constants apply)
 *  -1  a fault: the table is unreadable, the band is PARTIAL (some rows
 *      present, some absent — a chain in that state has no defined
 *      economics), a committed value is 0 or stored negative, or the
 *      committed epoch_length disagrees with the compiled
 *      DNAC_EPOCH_LENGTH.
 *
 * WHY epoch_length IS CHECKED RATHER THAN USED. blocks_per_year and
 * decimal_unit have exactly one production consumer on this lane
 * (nodus_witness_v2_emission_apply), so the committed value can simply be
 * USED. DNAC_EPOCH_LENGTH cannot: it is read as a macro by the vset
 * snapshot builder (nodus_witness_vset.c:721-722), the committee
 * selector, the graduation boundary and this module's own settlement
 * arithmetic. Rewiring every one of those is a different change. Until
 * then the only honest guarantee is REFUSAL — a build whose epoch length
 * disagrees with the chain's committed one stops, rather than quietly
 * keying its epochs differently from its peers. That is DETECTION, and it
 * is labelled as such rather than sold as parameterisation.
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
 * PER-BLOCK INFLATION EMISSION — the port of nodus_witness_bft.c
 * :3640-3700.
 *
 * Rule, as IMPLEMENTED (the V1 rule with Block 2C's committed inputs —
 * the two differ only in where the parameters come from, never in the
 * arithmetic):
 *   econ            = econ_params_load()        ← Block 2C, and a FAULT
 *                                                 here fails the block
 *   BY, DU          = econ.present ? the chain's COMMITTED values
 *                                  : DNAC_BLOCKS_PER_YEAR /
 *                                    DNAC_DECIMAL_UNIT
 *   inflation_start = chain_config(DNAC_CFG_INFLATION_START_BLOCK,
 *                                  at height, DEFAULT 1)
 *   emission = (inflation_start != 0 && height >= inflation_start)
 *              ? nodus_emission_per_block_ex(height, BY, DU) : 0
 *   if emission > 0:
 *       supply_tracking.total_minted += emission        (bft.c:3666)
 *       epoch_state[floor(h/E)*E].epoch_pool_accum += emission
 *                                                       (bft.c:3679)
 *       and, when that row did not exist, seed it and capture the
 *       epoch-start committee+delegation snapshot
 *       (nodus_witness_epoch_snapshot_apply, bft.c:3709)
 *
 * THE 1ULL DEFAULT APPLIES ONLY WHEN THERE IS GENUINELY NO ROW.
 *
 * ⚠ CORRECTED, O15J Block 2 (A2). This paragraph used to read: "THE 1ULL
 * DEFAULT IS LOAD-BEARING, not a convenience: an override that cannot be
 * fetched must not silently disable emission on one node and leave it on
 * for another." That justification did not hold. Substituting 1ULL only
 * covers the direction where the real override would DELAY emission; when
 * the peers' override starts emission LATER than 1, or is an explicit 0,
 * the node that could not read it mints blocks its peers do not — the
 * same state_root split, in the other direction. A default cannot close a
 * hole whose nature is not knowing which side of it you are on.
 *
 * The lookup is three-valued now: rc 1 (no governance row — every chain
 * today) still yields 1ULL and the historical behaviour byte-for-byte;
 * rc -1 is a NODE-LOCAL FAULT and this function returns -2 rather than
 * minting on a schedule it cannot read. The V1 lane's gate
 * (nodus_witness_bft.c, finalize_block) carries the identical rule.
 *
 * Block 2C narrowed WHEN that default is reached without changing it: a
 * chain this builder derives commits its own inflation start at genesis,
 * so the lookup returns a committed row and the 1ULL is reached only by a
 * chain that committed nothing — which is every chain built before 2C,
 * and is exactly the behaviour those chains already had.
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
