/**
 * @file nodus_witness_v2_seam.h
 * @brief Ledger V2 O15C — the activation seam: deterministic derivation
 *        of the successor V2 chain from a terminal legacy chain.
 *
 * ═══ THE SEAM (approved decision O15C-B §1.3) ═════════════════════════
 * Activation is a deterministic MIGRATION to a NEW V2 chain, not a
 * continuous-height hard fork. When the legacy chain's committed
 * activation record flips ACTIVE at H_act (the terminal boundary block),
 * every node derives — from committed legacy state alone — the SAME:
 *
 *   - terminal source commitment (chain id ‖ terminal BlockID ‖ terminal
 *     state root ‖ H_act — dna_act_source_commit, bound into the V2
 *     genesis manifest's source_tag/source_commit fields);
 *   - S6 GenesisManifest v1 whose distribution snapshot carries every
 *     spendable native legacy UTXO as a claim leaf (source_id = the
 *     UTXO's nullifier, dest_binding = the owner fingerprint bytes,
 *     conversion 1/1 FLOOR) — the claim reserve. Legacy UTXOs are NEVER
 *     copied as spendable V2 rows: value enters the reserve exactly
 *     once, and a claim moves it out through the shipped S6 machinery;
 *   - the successor witness database: carried committed SYSTEM state
 *     (validators — attendance counters reset to the new chain's height
 *     domain — delegations, validator_stats, epoch_state,
 *     supply_tracking, chain_config_history), fresh epoch-0/E validator
 *     snapshots frozen from the carried set, schema v10, and the V2
 *     genesis (nodus_witness_v2_genesis_ex) whose engine-derived
 *     BlockID IS the V2 chain id.
 *
 * The V2 supply gate inside genesis_ex is the equation proof the season
 * demands: genesis + minted − burned == Σstakes + Σdelegations + pool +
 * unclaimed_distribution (the reserve), with ΣV2 utxo == 0 — which
 * balances exactly when reserve == the legacy migratable value, because
 * the legacy invariant (check_supply_invariant_v016) held at terminal.
 *
 * FAIL-CLOSED classification: any custom token registry row, any token
 * UTXO, a malformed owner fingerprint, a leaf-count overflow, or any
 * derivation/commit failure ABORTS the derivation — nothing partial is
 * ever left behind (the provisional database is removed).
 *
 * Everything here compiles always (unit-testable); production call
 * sites are NODUS_V2_ACTIVATION_AUTHORITY-gated.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_SEAM_H
#define NODUS_WITNESS_V2_SEAM_H

#include "witness/nodus_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Probe: is the chain database at `db_path` a seam SUCCESSOR (a
 *  committed height-0 genesis manifest carrying the
 *  "DNA.LEGACY.TERM.v1" source binding)? Read-only, opens its own
 *  connection. @return 1 yes, 0 no, -1 unreadable (treated as no by
 *  callers that only PREFER successors). */
int nodus_witness_v2_seam_is_successor(const char *db_path);

/**
 * Derive the successor V2 chain from `w` (the legacy handle) if and only
 * if its committed activation record is ACTIVE and no successor database
 * exists yet in w->data_path. Idempotent across restarts and crashes:
 * a completed successor short-circuits; a partial one (provisional
 * filename) is removed and re-derived.
 *
 * @param out_chain32 optional: the derived V2 chain id.
 * @return 0 derived-or-already-present-or-not-applicable, -1 fault
 *         (nothing partial left behind).
 */
int nodus_witness_v2_seam_maybe_derive(nodus_witness_t *w,
                                       uint8_t out_chain32[32]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_SEAM_H */
