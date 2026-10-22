/**
 * Nodus — Witness Database Layer
 *
 * SQLite operations for DNAC witness state: nullifiers, ledger,
 * UTXO set, blocks, genesis, supply tracking.
 * All functions take nodus_witness_t* (use witness->db).
 *
 * Ported from dnac/src/witness/{nullifier,ledger,utxo_set,block}.c
 *
 * @file nodus_witness_db.h
 */

#ifndef NODUS_WITNESS_DB_H
#define NODUS_WITNESS_DB_H

#include "witness/nodus_witness.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Nullifier operations ────────────────────────────────────────── */

bool nodus_witness_nullifier_exists(nodus_witness_t *w, const uint8_t *nullifier);

/* ── UTXO set operations ─────────────────────────────────────────── */

int  nodus_witness_utxo_lookup(nodus_witness_t *w, const uint8_t *nullifier,
                                uint64_t *amount_out, char *owner_out,
                                uint8_t *token_id_out);

/**
 * Lookup a UTXO, also returning its unlock_block (v15 schema column).
 *
 * unlock_block > current_block ⇒ UTXO is locked (post-UNSTAKE cooldown).
 * Caller (witness SPEND verify) uses this to enforce Rule D — reject
 * SPEND TXs that consume still-locked UTXOs.
 *
 * Behaves identically to nodus_witness_utxo_lookup() for the existing
 * out-parameters; unlock_block_out is the sole addition. Pass NULL for
 * any *_out you don't care about.
 */
int  nodus_witness_utxo_lookup_ex(nodus_witness_t *w, const uint8_t *nullifier,
                                    uint64_t *amount_out, char *owner_out,
                                    uint8_t *token_id_out,
                                    uint64_t *unlock_block_out);

int  nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height,
                              const uint8_t *token_id);

/**
 * Add a UTXO with an explicit unlock_block (locked UTXO helper).
 *
 * unlock_block == 0 ⇒ already spendable (same as nodus_witness_utxo_add).
 * unlock_block > 0  ⇒ UTXO is locked until chain height > unlock_block.
 *
 * Written by the legacy UNSTAKE commit for its time-locked return UTXO.
 * (The version-3 lane writes its locked releases through its own adapters:
 * a graduation's bond at H_grad + DNAC_VALIDATOR_UNBOND_EPOCHS × E and its
 * delegations at H_grad + DNAC_UNDELEGATE_LOCK_EPOCHS × E —
 * nodus_witness_v2_epoch.c; the DNAC_UNSTAKE_COOLDOWN_BLOCKS constant this
 * comment used to name was deleted by tokenomics-v3 P3-3.)
 */
int  nodus_witness_utxo_add_locked(nodus_witness_t *w, const uint8_t *nullifier,
                                     const char *owner, uint64_t amount,
                                     const uint8_t *tx_hash, uint32_t index,
                                     uint64_t block_height,
                                     const uint8_t *token_id,
                                     uint64_t unlock_block);

/**
 * Sum UTXO amounts for a specific token_id.
 * @param token_id  64-byte token ID (zeros = native DNAC, NULL = same as zeros)
 * @param sum_out   [out] Total amount for this token
 * @return 0 on success, -1 on error
 */
int  nodus_witness_utxo_sum_by_token(nodus_witness_t *w,
                                       const uint8_t *token_id,
                                       uint64_t *sum_out);

/* Phase 10 / Task 10.2 — nodus_witness_utxo_checksum DELETED.
 * State root computation now lives in nodus_witness_merkle.c as
 * nodus_witness_merkle_compute_utxo_root (RFC 6962 Merkle tree). */

/* Query UTXOs by owner fingerprint */
typedef struct {
    uint8_t     nullifier[NODUS_T3_NULLIFIER_LEN];
    char        owner[129];     /* fingerprint */
    uint64_t    amount;
    uint8_t     token_id[64];   /* 64 bytes — zeros = native DNAC */
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint32_t    output_index;
    uint64_t    block_height;
    /* O15B §7 — the height at or after which this coin becomes spendable.
     * 0 = spendable now (every ordinary output). Non-zero only for a
     * locked release: a graduation's bond (DNAC_VALIDATOR_UNBOND_EPOCHS
     * epochs), an UNDELEGATE release or a graduation's delegation
     * release (DNAC_UNDELEGATE_LOCK_EPOCHS epochs) — tokenomics-v3 P3-3;
     * the older DNAC_UNSTAKE_COOLDOWN_BLOCKS is deleted.
     *
     * This field exists because consensus REJECTS a spend of a locked coin
     * (Rule D, nodus_witness_verify.c:730) while the wallet that chose it
     * had no way to know it was locked: the column was never selected here,
     * never carried on the dnac_utxo wire, and has no counterpart in the
     * client's own UTXO table. Coin selection therefore built transactions
     * that all seven validators were guaranteed to reject, and the submitter
     * observed only a 60 s timeout. */
    uint64_t    unlock_block;
} nodus_witness_utxo_entry_t;

int  nodus_witness_utxo_by_owner(nodus_witness_t *w, const char *owner,
                                   nodus_witness_utxo_entry_t *out,
                                   int max_entries, int *count_out);

/* nodus_witness_utxo_by_owner restricted to coins whose token_id equals
 * `token_id` (64 bytes; all-zero = native). Same order, cap, domain
 * filter and fail-closed read as the unfiltered query. 0 / -1 (fault). */
int  nodus_witness_utxo_by_owner_token(nodus_witness_t *w, const char *owner,
                                       const uint8_t token_id[64],
                                       nodus_witness_utxo_entry_t *out,
                                       int max_entries, int *count_out);

/* scan-v3 (decision docs/plans/decisions/2026-09-28-scan-v3-query.md,
 * item 3a) — one owner's TRANSPARENT balance, per token. */
typedef struct {
    uint8_t  token_id[64];   /* all-zero = native                          */
    uint64_t total;          /* Σ amount of every CORE coin of the token   */
    uint64_t spendable;      /* Σ amount of those with unlock < spend_h    */
    uint64_t coins;          /* number of those coins (>= 1)               */
} nodus_witness_balance_entry_t;

#define NODUS_WITNESS_BALANCE_TOO_MANY  (-2)

/**
 * Per-token totals of `owner`'s unspent coins in `utxo_set`, CORE domain
 * only (DNA_DOMAIN_CORE — the transparent coins; a shielded pool's notes
 * live in v2_pools, never in utxo_set, and are never read here). Rows are
 * read ordered by (token_id, nullifier) and summed in C with checked
 * addition (dna_ck_add_u64): an overflow is a fault, never a wrap.
 *
 * `spend_h` is the height the spend rule is judged at: a coin counts as
 * spendable iff unlock_block < spend_h — the native exec's lock gate
 * (nodus_witness_rt_native.c rtn_xfer_exec, "unlock >= ctx->global_height
 * rejects") at global_height = spend_h.
 *
 * Fail-closed ("A DB failure is never a value", nodus/CLAUDE.md): a
 * non-integer / NULL / NEGATIVE amount or unlock_block, a token id that
 * is not a 64-byte blob, an overflow, or a step error mid-scan answers -1
 * with *count_out = 0 — never a partial or guessed total.
 *
 * Output is token_id-ascending (memcmp order), deterministic.
 *
 * @return 0 (count_out = tokens written, 0 = the owner holds nothing);
 *         NODUS_WITNESS_BALANCE_TOO_MANY when the owner holds more than
 *         max_entries distinct tokens (nothing usable written);
 *         -1 on a fault or bad arguments.
 */
int  nodus_witness_utxo_balance_by_owner(nodus_witness_t *w,
                                         const char *owner,
                                         uint64_t spend_h,
                                         nodus_witness_balance_entry_t *out,
                                         int max_entries, int *count_out);

/* ── Token registry operations ──────────────────────────────────── */

int  nodus_witness_token_get(nodus_witness_t *w, const uint8_t *token_id,
                               char *name_out, char *symbol_out,
                               uint8_t *decimals_out, uint64_t *supply_out,
                               char *creator_fp_out);

/** Token list entry for query results */
typedef struct {
    uint8_t  token_id[64];
    char     name[64];
    char     symbol[16];
    uint8_t  decimals;
    uint64_t supply;
    char     creator_fp[129];
} nodus_witness_token_entry_t;

/**
 * List all registered tokens.
 *
 * @param w           Witness context
 * @param out         Output array (caller-allocated)
 * @param max_entries Array capacity
 * @param count_out   [out] Number of entries written
 * @return 0 on success, -1 on error
 */
int  nodus_witness_token_list(nodus_witness_t *w,
                                nodus_witness_token_entry_t *out,
                                int max_entries, int *count_out);

/* ── Block operations ────────────────────────────────────────────── */

typedef struct {
    uint64_t    height;
    uint8_t     tx_root[NODUS_T3_TX_HASH_LEN];     /* RFC 6962 Merkle root over the block's TX hashes */
    uint32_t    tx_count;                          /* Number of TXs the block carries */
    uint64_t    timestamp;
    uint8_t     proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     prev_hash[NODUS_T3_TX_HASH_LEN];   /* SHA3-512 of previous block header */
    uint8_t     state_root[NODUS_T3_TX_HASH_LEN];  /* SHA3-512 over the UTXO set after this block */
} nodus_witness_block_t;

/* R3 W4 — nodus_witness_block_add (the legacy commit path's block-row
 * writer) is DELETED with the closed consensus lane: zero surviving
 * callers. block_get below stays, reading whatever row this build's
 * active writer populated (committee lookback / genesis read,
 * nodus_witness_committee.c). block_get_latest had no caller and is
 * deleted; block_get_range and block_get_genesis are deleted with the
 * dnac_block_range / dnac_genesis client RPCs they served. */
int  nodus_witness_block_get(nodus_witness_t *w, uint64_t height,
                               nodus_witness_block_t *out);
/**
 * The chain height, WITH the DB fault kept distinguishable from it.
 *
 * TWO-VALUED (O15O Faz 1). `nodus_witness_block_height` below cannot
 * report a fault at all: it answers 0 for "the chain is empty" and 0 for
 * "the query did not run", and 0 is a legitimate height. Every consumer
 * that decides something — the round anchor, the committee resolved at
 * height+1, leader election, the signed VIEW_OK preimage — therefore
 * treated a transient sqlite failure as "this chain is at genesis", which
 * is the fail-open nodus/CLAUDE.md forbids in one line: A DB FAILURE IS
 * NEVER A VALUE. Bug ref: nodus/BUGS.md O15N-L2.
 *
 * Same discipline, and the same shape, as nodus_witness_supply_get above.
 *
 * @param w    witness. NULL is a fault. A NULL w->db is TWO different
 *             states and is split along the O15L DG-1 matrix:
 *               chain_id all zeros — GENUINE PRE-GENESIS. Success, *out 0.
 *                 There is no chain, so 0 is a true committed answer, and
 *                 this is the window the F17 A5 gossip-roster bootstrap
 *                 runs in. A node in the genesis round is here by
 *                 construction — the chain database does not exist yet —
 *                 so refusing it would stop a fresh cluster from ever
 *                 producing genesis.
 *               chain_id non-zero — DG-1 ROW 2. Fault, -1. This node
 *                 holds a chain and cannot read it; 0 would be the
 *                 fail-open.
 *             R3 W4 — this used to be one of two gates required to agree
 *             (the other being nodus_witness_bft.c's load_committee_at_
 *             height); that sibling is deleted with the closed consensus
 *             lane and this function's own two-armed answer now stands
 *             alone.
 * @param out  receives the height on success. UNTOUCHED on -1, so a
 *             caller that pre-seeded it cannot mistake a fault for data.
 *
 * @return  0  success. *out is the committed tip: the MAX(global_height)
 *             of v2_blocks on a successor chain (w->v2_successor), the
 *             MAX(height) of `blocks` on a legacy one, or 0 for a
 *             genuinely pre-genesis node with no database. A GENUINELY
 *             EMPTY chain is this case with *out == 0 — that is the whole
 *             point of separating the two returns.
 *         -1  NULL w, NULL out, DG-1 row 2 (above), or a sqlite fault on
 *             either branch: prepare failure (which INCLUDES "no such
 *             table", the shape a half-migrated or corrupt DB produces),
 *             or a sqlite3_step return other than SQLITE_ROW /
 *             SQLITE_DONE. *out is untouched.
 */
int nodus_witness_block_height_checked(nodus_witness_t *w, uint64_t *out);

/**
 * THE FAIL-OPEN FORM. Answers 0 both for an empty chain and for a DB
 * fault; prefer nodus_witness_block_height_checked in anything that
 * decides. Kept for the display / advisory callers listed in the block
 * comment on its definition (nodus_witness_db.c), and loud on stderr
 * when the underlying read faults so the fault is never silent.
 */
uint64_t nodus_witness_block_height(nodus_witness_t *w);

/* ── Genesis state ───────────────────────────────────────────────── */

/* R3 W4 — nodus_witness_genesis_exists and nodus_witness_genesis_set
 * (the legacy genesis-row writer and its existence guard) are DELETED
 * with the closed consensus lane: zero surviving callers. The reader
 * nodus_witness_genesis_get and its nodus_witness_genesis_t had no
 * caller either and are deleted (dead-code pruning 2026-10-15); the
 * genesis_state table schema is unchanged. */

/* ── Supply tracking ─────────────────────────────────────────────── */

typedef struct {
    uint64_t    genesis_supply;
    uint64_t    total_burned;
    uint64_t    total_minted;    /* v0.16 stage B.2 — cumulative inflation
                                  * mint. tokenomics-v3 P2: NOTHING writes
                                  * it any more (decision §1 "Yeni token
                                  * basılmayacak"); it reads 0 on every
                                  * chain this build derives and stays in
                                  * the supply leaf and the equation as a
                                  * term that is always 0. */
    uint64_t    current_supply;
    uint64_t    last_sequence;
    uint64_t    reward_pool;     /* tokenomics-v3 P2 (P2-1): the reward
                                  * reserve. Seeded at genesis with the
                                  * document's reward_pool_initial, grows
                                  * by every transaction fee, shrinks only
                                  * by the epoch distribution. */
} nodus_witness_supply_t;

/**
 * Create the singleton supply_tracking row (id = 1).
 *
 * tokenomics-v3 P2 (P2-1): `reward_pool` is the genesis reward reserve
 * (the version-3 document's `reward_pool_initial`; 0 for every chain that
 * has none). It is part of `genesis_supply` — total_supply is FIXED and
 * the reserve is carved out of it, never added to it — so the row starts
 * with genesis_supply = current_supply = total_supply and reward_pool =
 * `reward_pool`, and the caller guarantees reward_pool <= total_supply
 * (the genesis Rule P.2, nodus_witness_v2_gen.c).
 *
 * @return 0 created; -2 a row already exists (untouched); -1 fault or
 *         reward_pool > total_supply.
 */
int  nodus_witness_supply_init(nodus_witness_t *w, uint64_t total_supply,
                                 uint64_t reward_pool,
                                 const uint8_t *genesis_tx_hash);

/**
 * Read the singleton supply_tracking row (id = 1).
 *
 * THREE-VALUED (D1, 2026-07-31). Callers MUST distinguish the two
 * non-success codes; a blanket `!= 0` is a fail-open, because the
 * counters this row carries are hashed into supply_root
 * (nodus_witness_supply_root_v2, "NDS.SUPPLY.v2") and therefore into
 * the chain's state root.
 *
 * @return  0  row present, *out populated
 *          1  row genuinely absent — the table exists but holds no
 *             id = 1 row (sqlite3_step returned SQLITE_DONE). This is
 *             the pre-genesis state; *out is untouched, so the caller
 *             must have zeroed it if it intends to use it.
 *         -1  real error: NULL argument, prepare failure (which
 *             INCLUDES "no such table: supply_tracking", since the
 *             table is created lazily by nodus_witness_supply_init),
 *             or any sqlite3_step return code other than SQLITE_ROW /
 *             SQLITE_DONE. *out is untouched.
 */
int  nodus_witness_supply_get(nodus_witness_t *w,
                                nodus_witness_supply_t *out);

/* ── Supply buckets (scan, decision 2026-09-30-scan-supply-buckets.md) ─ */

/* The fixed treasury pool set 1..9 (nodus_witness_roots_v2.h
 * NODUS_TREASURY_POOL_COUNT; a _Static_assert in nodus_witness_db.c keeps
 * the two equal). */
#define NODUS_WITNESS_SUPPLY_TREASURY_POOLS 9u

typedef struct {
    int      has_supply;      /* 1: the supply_tracking row is present;
                               * 0: genuinely absent (pre-genesis) —
                               * `supply` is then all zero and carries no
                               * reward_pool */
    nodus_witness_supply_t supply;
    uint64_t tip;             /* nodus_witness_v2_tip_height */
    uint64_t treasury[NODUS_WITNESS_SUPPLY_TREASURY_POOLS];
                              /* v2_treasury.balance, pool 1..9 in order;
                               * a pool with no row reads 0 */
    uint64_t unclaimed;       /* Σ v2_dist_state.remaining of the
                               * distributions targeting the CORE
                               * domain's native asset —
                               * nodus_witness_v2_unclaimed_total, the
                               * term the CORE conservation invariant
                               * sums (nodus_witness_v2_claims.c
                               * nodus_rt_core_invariant) */
} nodus_witness_supply_view_t;

/**
 * One read of everything the version-3 dnac_supply reply reports: the
 * supply_tracking row (reward_pool included), the committed tip, the
 * nine treasury balances and the unclaimed distribution total.
 *
 * SUCCESSOR CHAINS ONLY (w->v2_successor): the tip and the two bucket
 * reads are version-3 tables.
 *
 * ONE READING MOMENT. The witness has one sqlite connection (w->db),
 * used from one thread (the p2p worker threads run handshake / signature
 * jobs only), so no commit can interleave between the reads of one call.
 * What could make two of the figures disagree is a ledger transaction
 * left OPEN on that connection (the host's FinalizeBlock..Commit
 * bracket): the reads would then see an uncommitted block. That state is
 * refused (-1), the same check nodus_witness_v3_block_build makes. No
 * BEGIN is issued here: a read transaction left open by a fault path
 * would make the host's next BEGIN IMMEDIATE fail and stop the node.
 *
 * Fail-closed: a DB fault is never a value. A malformed treasury row
 * (pool_id outside 1..9, a negative balance, a non-INTEGER column, more
 * than nine rows) and a negative reward_pool fail the read.
 *
 * Read-only. No consensus caller: this feeds a client RPC answer, never
 * state_root, a block or a vote.
 *
 * @return  0  *out populated (has_supply tells the pre-genesis case)
 *         -1  NULL argument, an open ledger transaction, or any read
 *             fault; *out is unspecified
 */
int  nodus_witness_supply_view_get(nodus_witness_t *w,
                                   nodus_witness_supply_view_t *out);
/* tokenomics-v3 P2 — nodus_witness_supply_add_burned and
 * nodus_witness_supply_add_minted are DELETED: their only production
 * callers were the per-block mint and the burning epoch settlement
 * (nodus_witness_v2_econ.c), both removed by P2-4/P2-6. Every surviving
 * writer of supply_tracking is the CORE adapter's EXISTS_VERSION-bound
 * absolute SET (nodus_witness_rt_native.c) and the distribution's own
 * bound pool update (nodus_witness_v2_econ.c). */

/* The legacy-table query readers (tx_by_owner, tx_get,
 * get_committed_coords, cert_get) and the uncalled tx_output_add writer
 * are deleted with the dnac_history / dnac_tx / dnac_spend_replay /
 * dnac_block client RPCs — see nodus_witness_db.c. */

/* ── DB transaction wrappers ─────────────────────────────────────── */

int  nodus_witness_db_begin(nodus_witness_t *w);
int  nodus_witness_db_commit(nodus_witness_t *w);
int  nodus_witness_db_rollback(nodus_witness_t *w);

/* Savepoint wrappers (Phase 0 / Task 0.15).
 *
 * Required by Phase 6 commit_batch attribution replay (Task 6.2): when a
 * multi-tx batch's finalize_block fails, the attribution loop replays each
 * TX in isolation under a savepoint to identify which one violated the
 * supply invariant.
 *
 * Caller is responsible for ensuring `name` is a valid SQL identifier
 * (alphanumeric + underscores). Names are inlined into the generated SQL —
 * SQLite SAVEPOINT does not accept parameter binding.
 */
int  nodus_witness_db_savepoint(nodus_witness_t *w, const char *name);
int  nodus_witness_db_rollback_to_savepoint(nodus_witness_t *w, const char *name);

/* R3 W4 — nodus_witness_compute_block_hash / _ex (the block-hash
 * preimage shared by the legacy block_add writer and the legacy sync
 * verifier) are DELETED with the closed consensus lane: both callers
 * are gone. */

/* Schema migration umbrella (Phase 1 / Task 1.1, originally named v12).
 *
 * Runs all additive schema migrations in order:
 *   - v12: tx_index column + composite idx_ctx_block index on
 *          committed_transactions (multi-tx block refactor)
 *   - v13: client_pubkey + client_sig columns on committed_transactions
 *          (Phase 11 client binding)
 *   - v14: chain_def_blob column on blocks (Phase 2 / Task 7 — anchored
 *          merkle proofs; NULL on non-genesis blocks)
 *   - v15: unlock_block column on utxo_set (Task 11 — stake delegation
 *          unbonding cooldown; 0 = already spendable)
 *
 * Idempotent: safe to run on a fresh DB or on a DB that already has any
 * of the above shapes. Returns 0 on success. On unrecoverable SQLite
 * error the function triggers WITNESS_DB_MIGRATION_FATAL (logs
 * MIGRATION FAILURE then abort()), so callers can assume success on
 * return.
 */
int  nodus_witness_db_migrate_v12(nodus_witness_t *w);

/* R3 W4 — nodus_witness_db_save_pbft_state and _load_pbft_state (the PR 3
 * Yol B / H-5 persistence pair for the legacy BFT view counter and
 * PREVOTE-prepared certificate) are DELETED with the closed consensus
 * lane: `w->current_view` and `w->last_prepared` no longer exist on
 * nodus_witness_t and their only caller is gone. */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DB_H */
