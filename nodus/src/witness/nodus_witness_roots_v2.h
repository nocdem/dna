/**
 * @file nodus_witness_roots_v2.h
 * @brief Ledger V2 — witness-side loaders for the V2 state-root hierarchy.
 *
 * These functions read REAL current witness state (tokens table,
 * supply_tracking, the attendance / accrual tables and the exported
 * subtree roots) and assemble the tagged V2 hierarchy defined in
 * shared/dnac/ledger_roots_v2.h.
 *
 * ACTIVATION: this is the version-3 chain's state root — the SYSTEM and
 * CORE runtimes return nodus_witness_system_root_v2 / _core_root_v2 as
 * their domain state roots (nodus_witness_v2_claims.c), and the global
 * root over them is the block app_hash. The legacy five-input root
 * (combine_v3) and the epoch_state leg are DELETED (root-layout round,
 * docs/plans/decisions/2026-09-25-root-layout-round.md K2/K3).
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

/* Root-layout round (K2): nodus_witness_epoch_root_v2 (the epoch_state
 * leg) is DELETED with the `epoch_state` table. */

/** supply_root from supply_tracking (three-valued read honored: absent
 *  row = honest pre-genesis zeros; DB error = fail). tokenomics-v3 P2:
 *  the leaf commits genesis/minted/burned AND reward_pool
 *  ("DNA.SUPPLY.v2"). */
int nodus_witness_supply_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** accrual_root (tokenomics-v3 P2, P2-8) over `v2_reward_accrual`
 *  (owner_fp ASC) — the 7th leg of core_state_root. A malformed row
 *  (owner_fp not 64 bytes, amount <= 0) or a scan fault fails the whole
 *  computation; the table is in the base schema, so an absent table is
 *  a fault, never the empty state. @return 0 / -1. */
int nodus_witness_accrual_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** attendance_root (tokenomics-v3 P1, D-4 / S-2) over `v2_attendance_epoch`
 *  rows, epoch_start ASC. Fail-closed: a
 *  missing table is the honest empty state (a pre-P1 database, or before
 *  the chain's first epoch boundary), a probe fault is never reported as
 *  empty, and a malformed row fails the whole computation. */
int nodus_witness_attendance_root(nodus_witness_t *w, uint8_t out[64]);

/** system_state_root per the V2 composition — 7 legs under "DNA.SYS.v3"
 *  (root-layout round K2 removed the epoch_state leg). The validator-set leg is now
 *  REAL (S3): nodus_witness_vset_root over the validator_set_snapshots
 *  table. That table is empty until a later wave wires the genesis /
 *  epoch-boundary snapshot writes, and an empty table returns exactly the
 *  DNA_V2_EMPTY_VSET tagged root the S2 placeholder returned — so this
 *  root is byte-unchanged for every pre-snapshot chain. The
 *  domain-registry leg is REAL since S4 (nodus_witness_domreg_root; an
 *  empty registry table returns exactly the old tagged-empty root, so
 *  pre-registry chains are byte-unchanged). Only the S6 manifest leg is
 *  still a tagged-empty placeholder. */
int nodus_witness_system_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** core_state_root per the V2 composition (S6/S7/O-7 legs tagged-empty;
 *  tokenomics-v3 P2: 7 legs incl. accrual_root, tag "DNA.CORE.v2"). */
int nodus_witness_core_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** S5 — SYSTEM runtime-owned genesis PAYLOAD root ("DNA.SYSPAYL.v2",
 *  root-layout round K2): the four runtime legs validator ‖ delegation ‖
 *  chain_config ‖ validator_set, WITHOUT the container-lifetime legs
 *  domain_registry_root / manifest_root / attendance_root. The
 *  genesis-cycle break: DomainManifest.genesis_state_root is THIS value
 *  for SYSTEM (dna_v2_system_payload_root in shared/dnac). */
int nodus_witness_system_payload_root_v2(nodus_witness_t *w,
                                         uint8_t out[64]);

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
