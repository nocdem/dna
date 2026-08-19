/**
 * @file nodus_witness_v2_activation.h
 * @brief Ledger V2 O15C — the committed activation authority: record,
 *        readiness, activation_root, type-15/16 apply, boundary state
 *        machine and the terminal-height refusal predicate.
 *
 * ═══ WHAT THIS IS ═════════════════════════════════════════════════════
 * The ONE committed authority that can ever select Ledger V2
 * (nodus_witness_v2_gate.c:46-50 named this module's season). It is a
 * singleton record + a readiness table in the legacy chain's witness
 * database, committed under the legacy state root as its 6th leg
 * (activation_root, state_root v4 — nodus_witness_merkle.h), driven by
 * two quorum/validator-signed legacy transaction types (15/16) and an
 * engine-mandatory epoch-boundary transition. Byte layouts and digests:
 * shared/dnac/activation_wire.h.
 *
 * ═══ STATE MACHINE (O15C-A §D.3, the approved design) ═════════════════
 *   (no row) UNSCHEDULED
 *     ──type-15 SCHEDULE (quorum of the committee at commit−1)──▶ SCHEDULED
 *   SCHEDULED ──every boundary, readiness complete over snap(h)──▶ READY
 *   READY     ──boundary, readiness broken (membership churn)───▶ SCHEDULED
 *   SCHEDULED ──type-15 CANCEL (quorum, anytime)───────────────▶ CANCELLED
 *   READY     ──type-15 CANCEL (quorum, commit < H_act − E)────▶ CANCELLED
 *   READY     ──boundary at H_act: complete(snap(H_act)) AND
 *               members(snap(H_act)) == members(snap(H_act−E))─▶ ACTIVE
 *   any live  ──boundary at H_act, recheck fails──▶ SCHEDULED with
 *               H_act += E, postpone_count += 1; past
 *               DNA_ACT_MAX_POSTPONES ──▶ CANCELLED (auto)
 *   ACTIVE is TERMINAL: the legacy chain refuses every height > H_act.
 *
 * Readiness collection stays OPEN across postponements (signals bind the
 * schedule digest, not the mutable height) — that is what makes the
 * postpone loop converge, matching how the S4 domreg policy converges
 * through continued op_signal collection.
 *
 * ═══ WHAT CANNOT DRIVE IT ═════════════════════════════════════════════
 * No environment variable, flag, file, clock, peer claim or mutable
 * current set: every transition reads committed rows, committed
 * snapshots (nodus_witness_vset_get / nodus_committee_get_for_block for
 * the committee governing the SIGNING height) and the block height.
 *
 * ═══ PRODUCTION DORMANCY ══════════════════════════════════════════════
 * The module is always compiled (unit-testable), but every CALL SITE
 * that could admit a type-15/16 transaction, run the boundary machine,
 * refuse a height, compute state_root v4 or derive the successor chain
 * is compiled ONLY under NODUS_V2_ACTIVATION_AUTHORITY — a CMake option
 * (-DNODUS_V2_ACTIVATION=ON) that is OFF by default and set on no
 * production target. A production binary therefore cannot commit a
 * record, and nodus_witness_v2_gate_authority_present() keeps returning
 * 0 exactly as O15B shipped it.
 *
 * TRANSACTIONS: apply/boundary functions issue no BEGIN/COMMIT — they
 * run inside the caller's block transaction (the chain_config pattern).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_ACTIVATION_H
#define NODUS_WITNESS_V2_ACTIVATION_H

#include "witness/nodus_witness.h"
#include "dnac/activation_wire.h"
#include "dnac/vset_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The committed activation record (decoded row). */
typedef struct {
    uint32_t record_version;
    uint8_t  state;                          /* DNA_ACT_STATE_* */
    uint8_t  chain_id[DNA_ACT_CHAIN_ID_LEN];
    uint8_t  target[DNA_ACT_HASH_LEN];       /* D */
    uint64_t activation_height;              /* CURRENT (postponable) H_act */
    uint64_t original_height;                /* as scheduled (digest-bound) */
    uint64_t deadline_height;                /* original − 2E: Stage-C one-shot */
    uint8_t  schedule_digest[DNA_ACT_HASH_LEN];
    uint64_t proposal_nonce;
    uint64_t commit_height;
    uint32_t postpone_count;
} nodus_v2_act_record_t;

/** Idempotent CREATE TABLE IF NOT EXISTS for the two activation tables
 *  (the nodus_chain_config_db_migrate pattern). Also invoked by the v2
 *  ladder's S10 migration so both creation paths share one DDL.
 *  @return 0 / -1. */
int nodus_witness_v2_activation_db_migrate(nodus_witness_t *w);

/** Load the singleton record. @return 0 found, 1 no record, -1 fault
 *  (malformed row, wrong widths, unknown state/version → FAULT, never
 *  silently "no record"). */
int nodus_witness_v2_activation_get(nodus_witness_t *w,
                                    nodus_v2_act_record_t *out);

/** activation_root: record leaf + readiness leaves (voter_id ASC) under
 *  the local RFC6962 shape (0x00/0x01, the chain_config tree pattern);
 *  no record → nodus_merkle_empty_root(NODUS_TREE_TAG_ACTIVATION).
 *  @return 0 / -1. */
int nodus_witness_v2_activation_root(nodus_witness_t *w, uint8_t out[64]);

/** This build's compiled ActivationTarget digest D — over the compiled
 *  runtime table (domain_id ASC), DNA_BH2_VERSION and the v2 schema
 *  version this build requires. @return 0 / -1. */
int nodus_witness_v2_activation_compiled_target(uint8_t out[DNA_ACT_HASH_LEN]);

/** Number of stored readiness signals for `schedule_digest` whose voter
 *  is a member of `snap` (one validator = one vote). @return 0 / -1. */
int nodus_witness_v2_activation_readiness_count(nodus_witness_t *w,
        const uint8_t schedule_digest[DNA_ACT_HASH_LEN],
        const dna_vset_snapshot_t *snap, uint32_t *count_out);

/** Apply one type-15 SCHEDULE/CANCEL transaction (full consensus rule
 *  set — the nodus_chain_config_apply mirror). Runs inside the caller's
 *  block transaction. @return 0 applied / -1 rejected. */
int nodus_witness_v2_activation_apply(nodus_witness_t *w,
                                      const uint8_t *tx_data,
                                      uint32_t tx_len,
                                      uint64_t block_height);

/** Apply one type-16 READY transaction. @return 0 applied (or exact
 *  byte-identical duplicate no-op) / -1 rejected. */
int nodus_witness_v2_activation_apply_ready(nodus_witness_t *w,
                                            const uint8_t *tx_data,
                                            uint32_t tx_len,
                                            uint64_t block_height);

/** The engine-mandatory boundary transition. Call ONLY at epoch
 *  boundaries (h > 0, h % E == 0), AFTER vset flips + commit_next, still
 *  inside the block transaction and BEFORE any root computation.
 *  @param activated_out optional: set 1 when this boundary flipped the
 *  record ACTIVE (the terminal legacy block). @return 0 / -1 fault. */
int nodus_witness_v2_activation_on_boundary(nodus_witness_t *w,
                                            uint64_t boundary_height,
                                            int *activated_out);

/** Terminal refusal: 1 = a committed ACTIVE record forbids `height`
 *  (height > H_act) or the record could not be read (fail closed);
 *  0 = height permitted. */
int nodus_witness_v2_activation_refuses_height(nodus_witness_t *w,
                                               uint64_t height);

/**
 * Stage C — the one-shot unready-exclusion list for the ordinary
 * snapshot build (O15C-A §D.3, transplanting domreg_exclusions_at):
 * fires only when a SCHEDULED record's deadline_height equals
 * `boundary_height`. Floor-guarded: if excluding every unready member
 * would leave fewer than `min_count`, NO exclusion happens (*n_out = 0,
 * return 2) — the old rules continue and the schedule postpones.
 * @return 0 list valid, 1 not applicable (no record / wrong boundary),
 *         2 floor-guard, -1 fault.
 */
int nodus_witness_v2_activation_exclusions(nodus_witness_t *w,
        uint64_t boundary_height,
        const dna_vset_snapshot_t *candidate,
        uint16_t min_count,
        uint8_t (*excl_out)[DNA_ACT_VOTER_ID_LEN],
        size_t cap, size_t *n_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_ACTIVATION_H */
