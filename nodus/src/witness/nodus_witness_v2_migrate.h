/**
 * @file nodus_witness_v2_migrate.h
 * @brief HF-6 sub-slice 3b — the one-shot generation-4 validator
 *        migration (design docs/plans/2026-10-03-hf5-validator-owner-
 *        stake-design.md rev 6 §7; plan tasks/hf6-slice3-plan.md §1
 *        "Migration step placement" and §2 "3b").
 *
 * Run ONCE, by the engine's generation-4 edge phase (nodus_witness_v2_
 * apply.c phase_6b_gen4_edge) at the end of block H−1, inside the block's
 * transaction, right after the registry switch 3 → 4. It re-values the
 * keys of the committed staking tables in place (plan decision D1 (i)) and
 * fills the side table v2_validator_roles:
 *
 *   validators.pubkey_hash        SHA3-512(0x02‖pk) → validator_id =
 *                                 dna_validator_id_migrated(chain32, pk)
 *   v2_validator_roles            one row (validator_id, owner_fp,
 *                                 2592 × 0x00, 0) per validator
 *   owner_fp                      foundation_fp for a row with
 *                                 active_since_block <= 1 (decision D2
 *                                 (a)), else SHA3-512(pk) (untagged)
 *   bonded rows (ACTIVE/ELIGIBLE) self_stake must be EXACTLY
 *                                 DNAC_SELF_STAKE_AMOUNT; it becomes
 *                                 DNAC_HF6_STAKE_MIN_DEFAULT and
 *                                 total_delegated / external_delegated
 *                                 both grow by the difference, which is the
 *                                 self-delegation (owner_fp, validator_id):
 *                                 a top-up of that row if it exists after
 *                                 the re-key (delegated_at_block unchanged),
 *                                 else a new row with delegated_at_block =
 *                                 h_next (= H)
 *   RETIRING / AUTO_RETIRED /     amounts untouched (re-keyed + roles row)
 *   UNSTAKED rows
 *   v2_consensus_keys (slice 4,   one role-1 row (SHA3-512(pk) untagged,
 *   design §4; khan decision      validator_id, 1) per validator of ANY
 *   2026-10-13-kurultay-18-       status, UNSTAKED included (the index is
 *   summary.md items 1, 4)        permanent: a key once used is never
 *                                 STAKEd again), in SHA3-512(pk) ASC
 *   delegations                   (SHA3-512(0x03‖dpk), SHA3-512(0x03‖vpk))
 *                                 → (SHA3-512(dpk), validator_id(vpk));
 *                                 amount, delegated_at_block and both
 *                                 *_pubkey columns kept
 *   v2_balance_copy (every epoch) validator_fp SHA3-512(pk) → validator_id,
 *                                 the kind-0 row's owner_fp → validator_id,
 *                                 amounts untouched; a row whose
 *                                 validator_fp names no validator is a FAULT
 *   v2_reward_accrual (K4)        each Foundation row's accrual
 *                                 [SHA3-512(pk)] is added (checked, ≤
 *                                 INT64_MAX) to accrual[foundation_fp] and
 *                                 the source row deleted; every other row
 *                                 untouched
 *
 * Shape: READ every input → COMPUTE the whole result in memory → WRITE.
 * Nothing is looked up in a half-re-keyed table. Every collection is read
 * and written in an explicit total order (ORDER BY on key columns, the
 * computed sets sorted by their new primary key), so two nodes with the
 * same committed tables write the same rows. Σself_stake +
 * Σtotal_delegated and Σaccrual are unchanged by construction and are
 * re-checked in memory before any write (the engine's phase-7 supply gate
 * re-checks the committed state).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_MIGRATE_H
#define NODUS_WITNESS_V2_MIGRATE_H

#include "witness/nodus_witness.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The generation-4 validator migration (contract above).
 *
 * Runs INSIDE THE CALLER'S TRANSACTION and opens none; called in
 * autocommit mode it refuses before reading. On -2 some tables may
 * already be written: the caller rolls the whole transaction back (the
 * host does so on every block fault), which is what makes the edge
 * atomic and a replay of H−1 identical.
 *
 * Preconditions, each a FAULT when false: v2_validator_roles and
 * v2_consensus_keys are empty;
 * every validators / delegations key equals the tagged hash of its stored
 * pubkey (a re-keyed or foreign row means the migration already ran or
 * the table is corrupt); every bonded row holds exactly
 * DNAC_SELF_STAKE_AMOUNT; every delegation's validator pubkey and every
 * balance-copy validator_fp names a validators row; no amount leaves
 * [0, INT64_MAX]; no two computed rows share a primary key.
 *
 * @param h_next         H, the first height judged under generation 4 —
 *                       delegated_at_block of a NEW self-delegation row;
 *                       must be in [1, INT64_MAX].
 * @param chain32        the chain's derived 32-byte id
 *                       (nodus_witness_v2_chain_id) — validator_id input.
 * @param foundation_fp  the 64-byte Foundation owner address
 *                       (dnac.h DNAC_HF6_FOUNDATION_OWNER in production).
 * @return 0 migrated / -2 node FAULT (reason logged) — never a verdict.
 */
int nodus_witness_v2_roles_migrate(nodus_witness_t *w, uint64_t h_next,
                                   const uint8_t chain32[32],
                                   const uint8_t foundation_fp[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_MIGRATE_H */
