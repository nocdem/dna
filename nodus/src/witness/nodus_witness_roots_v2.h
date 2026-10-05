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
 *  ("NDS.SUPPLY.v2"). */
int nodus_witness_supply_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** accrual_root (tokenomics-v3 P2, P2-8) over `v2_reward_accrual`
 *  (owner_fp ASC) — the 7th leg of core_state_root. A malformed row
 *  (owner_fp not 64 bytes, amount <= 0) or a scan fault fails the whole
 *  computation; the table is in the base schema, so an absent table is
 *  a fault, never the empty state. @return 0 / -1. */
int nodus_witness_accrual_root_v2(nodus_witness_t *w, uint8_t out[64]);

/* ── The keyless, locked treasury pools (final pre-testnet wipe, W-A) ──
 * decision 2026-09-28-treasury-pools-and-exact-self-stake.md (answers
 * 7, 9, 11, 12, 13). `v2_treasury(pool_id INTEGER PRIMARY KEY, balance
 * INTEGER NOT NULL)` holds one balance per pool; nobody holds a key to
 * it. Pool ids follow the tokenomics §1 table order (answer 11):
 *   1 Storage · 2 Compute · 3 VPN/Bandwidth · 4 Future services ·
 *   5 Security/bug bounty · 6 Liquidity · 7 Ecosystem grants ·
 *   8 Foundation · 9 Community airdrop.
 * The table is seeded ONCE, from the genesis document
 * (nodus_witness_v2_gen.c gen_seed_state). There is NO exit rule in this
 * build (the exit rule is PARKED by the operator, 2026-09-28) and NO
 * writer after genesis: general multisig (decision 2026-09-29-general-
 * multisig.md) moved the Foundation's funds to a multisig ADDRESS and
 * withdrew W-A's genesis-validator graduation refund into pool 8 (and
 * the credit primitive only it used) — a genesis seat now releases a
 * UTXO to its unstake destination, the Foundation multisig address.
 * The nine-row table and the root layout stay as approved; on a chain
 * whose Foundation funds are genesis outputs, pools 5-9 hold 0. */
#define NODUS_TREASURY_POOL_MIN         1u
#define NODUS_TREASURY_POOL_MAX         9u
#define NODUS_TREASURY_POOL_COUNT       9u

/** treasury_root (W-A) over `v2_treasury` (pool_id ASC) — the 8th leg of
 *  system_state_root and the 5th of system_payload_root. The table is in
 *  the base schema, so an absent table is a FAULT, never the empty
 *  state (no sqlite_master probe — the accrual leg's shape). A malformed
 *  row (pool_id outside [NODUS_TREASURY_POOL_MIN, _MAX], a negative
 *  balance, a non-INTEGER column) or a scan fault fails the whole
 *  computation. An EMPTY table (pre-genesis) is DNA_V2_EMPTY_TREASURY.
 *  @return 0 / -1. */
int nodus_witness_treasury_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** Σ v2_treasury.balance with the loader's row checks and a checked
 *  add — the supply equation's treasury term
 *  (nodus_witness_v2_claims.c). @return 0 / -1 (never a partial sum). */
int nodus_witness_treasury_total(nodus_witness_t *w, uint64_t *out);

/* ── Storage reward v1 — the storage registry (package B1) ─────────────
 * Decision docs/plans/decisions/2026-10-04-storage-reward-approved.md;
 * design docs/plans/2026-10-04-storage-reward-v1-design.md rev 2.2 §1;
 * leaf bytes docs/plans/2026-10-04-storage-reward-bytes.md item 1.
 * `v2_storage_nodes` (nodus_witness.h NODUS_V2_STORAGE_DDL, base schema)
 * holds one row per node_fp = SHA3-512(node_pk). Written ONLY by the
 * GEN_STORAGE SYSTEM ops STORAGE_REGISTER / STORAGE_EXIT and the storage
 * epoch boundary (archive reward, package B2a — exit release and the
 * fail_streak update, nodus_witness_v2_storage.c); empty on every chain
 * before the storage activation. The leaf is v2 ("NDS.STLEAF.v2",
 * fail_streak appended — bytes doc docs/plans/2026-10-05-archive-reward-
 * bytes.md item 4). */

/** The storage set cap (design rev 2.2 F3) — the ONE number the cap
 *  admission (STORAGE_REGISTER) and the frozen set share. */
#define NODUS_STORAGE_SET_MAX           DNA_V2_STORAGE_SET_MAX

/** registry_root (bytes doc item 1) over `v2_storage_nodes`, node_fp
 *  ASC, every row through dna_v2_storage_registry_root. The table is in
 *  the base schema, so an absent table is a FAULT (prepare fails), never
 *  the empty state; a malformed row (non-BLOB fp / pk, a length other
 *  than 64 / DNAC_PUBKEY_SIZE, node_fp != SHA3-512(node_pk), a negative
 *  integer, a fail_streak above UINT32_MAX, a status outside 1..3) or a
 *  scan fault fails the whole computation. An empty table is
 *  DNA_V2_EMPTY_STORAGE_REG.
 *  @return 0 / -1. */
int nodus_witness_storage_registry_root(nodus_witness_t *w,
                                        uint8_t out[64]);

/** Every `v2_storage_nodes` row, node_fp ASC, through the SAME scan and
 *  row checks as the registry root (one loader for the root, the supply
 *  term and the storage boundary — they can never disagree on which rows
 *  are well-formed). *rows is malloc'd (NULL when *n_out == 0); the
 *  caller frees it. @return 0 / -1. */
int nodus_witness_storage_registry_load(nodus_witness_t *w,
                                        dna_v2_storage_node_row_t **rows,
                                        size_t *n_out);

/** Σ bond over the ACTIVE + EXITING rows of `v2_storage_nodes`, with the
 *  registry root's own row checks (ONE scan for both — the treasury
 *  pattern) and a checked add: the supply equation's storage-bond term
 *  (nodus_witness_v2_claims.c nodus_rt_core_invariant). RELEASED rows
 *  are excluded: their bond already left as the release UTXO (the
 *  storage boundary, nodus_witness_v2_storage.c).
 *  @return 0 / -1 (never a partial sum). */
int nodus_witness_storage_bond_total(nodus_witness_t *w, uint64_t *out);

/** storage_root = dna_v2_storage_root(registry_root, sets_root,
 *  reports_root, segments_root) — "NDS.STOR.v2" (archive bytes item 5),
 *  each leg from its own table (sets / reports / segments loaders:
 *  nodus_witness_v2_storage.h). @return 0 / -1. */
int nodus_witness_storage_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** system_state_root v5 ("NDS.SYS.v5", bytes doc item 4): the 8 legs of
 *  nodus_witness_system_root_v2 in the same order + storage_root. The
 *  SYSTEM state-root hook selects it when the resolved runtime is
 *  GEN_STORAGE or later (nodus_rt_system_state_root) — before the
 *  storage activation the v4 composition above, unchanged. */
int nodus_witness_system_root_v5(nodus_witness_t *w, uint8_t out[64]);

/** attendance_root (tokenomics-v3 P1, D-4 / S-2) over `v2_attendance_epoch`
 *  rows, epoch_start ASC. Fail-closed: a
 *  missing table is the honest empty state (a pre-P1 database, or before
 *  the chain's first epoch boundary), a probe fault is never reported as
 *  empty, and a malformed row fails the whole computation. */
int nodus_witness_attendance_root(nodus_witness_t *w, uint8_t out[64]);

/** system_state_root per the V2 composition — 8 legs under "NDS.SYS.v4"
 *  (root-layout round K2 removed the epoch_state leg; W-A appended
 *  treasury_root as the last leg). The validator-set leg is now
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
 *  tokenomics-v3 P2: 7 legs incl. accrual_root, tag "NDS.CORE.v2"). */
int nodus_witness_core_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** S5 — SYSTEM runtime-owned genesis PAYLOAD root ("NDS.SYSPAYL.v3",
 *  W-A): the five runtime legs validator ‖ delegation ‖ chain_config ‖
 *  validator_set ‖ treasury, WITHOUT the container-lifetime legs
 *  domain_registry_root / manifest_root / attendance_root. The
 *  genesis-cycle break: DomainManifest.genesis_state_root is THIS value
 *  for SYSTEM (dna_v2_system_payload_root in shared/dnac). */
int nodus_witness_system_payload_root_v2(nodus_witness_t *w,
                                         uint8_t out[64]);

/** Full assembly: SYSTEM + CORE DomainHeads → domains_root →
 *  global_state_root. Optional component outputs (any may be NULL).
 *  ⚠ Storage reward v1: out_system is ALWAYS the v4 composition
 *  (nodus_witness_system_root_v2) — this assembly does not resolve the
 *  registry's generation. On a chain past the storage activation it is
 *  therefore NOT the committed SYSTEM root; the committed one comes from
 *  the runtime hook (nodus_rt_system_state_root). No consensus path calls
 *  this function (tests compare it on pre-activation chains). */
int nodus_witness_global_root_v2(nodus_witness_t *w,
                                 uint8_t out_global[64],
                                 uint8_t out_domains[64],
                                 uint8_t out_system[64],
                                 uint8_t out_core[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_ROOTS_V2_H */
