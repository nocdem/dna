/**
 * @file nodus_witness_roots_v2.h
 * @brief Ledger V2 Season 2 — witness-side loaders for the INACTIVE V2
 *        state-root hierarchy.
 *
 * These functions read REAL current witness state (tokens table, epoch
 * table, supply_tracking, and the existing exported subtree roots) and
 * assemble the tagged V2 hierarchy defined in shared/dnac/ledger_roots_v2.h.
 *
 * ACTIVATION: called by tests and the S2 determinism harness ONLY — no
 * consensus path (PREVOTE/COMMIT/finalize) consults any V2 root. The
 * active chain keeps combine_v3 (nodus_witness_merkle.c) byte-identical.
 *
 * Fail-closed discipline (v0.18.19 rule): any DB prepare/step error, NULL
 * or short blob, or subtree failure fails the WHOLE computation — no
 * sentinel, no fallback, no partial root.
 *
 * S2 DomainHead fixture inputs (real head persistence is Season 5):
 *   SYSTEM = { id 0, system_state_root, height 0, last_updated 0,
 *              ruleset_version 1, status 0 }
 *   CORE   = { id 1, core_state_root,   height 0, last_updated 0,
 *              ruleset_version 1, status 0 }
 * documented placeholders — heights/status carry no state until S5.
 *
 * @file nodus_witness_roots_v2.h
 */

#ifndef NODUS_WITNESS_ROOTS_V2_H
#define NODUS_WITNESS_ROOTS_V2_H

#include "witness/nodus_witness.h"
#include "dnac/ledger_roots_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

/** token_root over the tokens table (ORDER BY token_id ASC; the local
 *  wall-clock `timestamp` column is EXCLUDED — node-divergent). */
int nodus_witness_token_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** epoch_state_root_v2 — v2 leaves WITHOUT the supply counters (they are
 *  committed exactly once, in supply_root). */
int nodus_witness_epoch_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** supply_root from supply_tracking (three-valued read honored: absent
 *  row = honest pre-genesis zeros; DB error = fail). */
int nodus_witness_supply_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** system_state_root per the V2 composition. The validator-set leg is now
 *  REAL (S3): nodus_witness_vset_root over the validator_set_snapshots
 *  table. That table is empty until a later wave wires the genesis /
 *  epoch-boundary snapshot writes, and an empty table returns exactly the
 *  DNA_V2_EMPTY_VSET tagged root the S2 placeholder returned — so this
 *  root is byte-unchanged for every pre-snapshot chain. The S4/S6 legs
 *  (domain_registry, manifest) are still tagged-empty placeholders. */
int nodus_witness_system_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** core_state_root per the V2 composition (S6/S7/O-7 legs tagged-empty). */
int nodus_witness_core_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** Full assembly: SYSTEM + CORE DomainHeads → domains_root →
 *  global_state_root. Optional component outputs (any may be NULL). */
int nodus_witness_global_root_v2(nodus_witness_t *w,
                                 uint8_t out_global[64],
                                 uint8_t out_domains[64],
                                 uint8_t out_system[64],
                                 uint8_t out_core[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_ROOTS_V2_H */
