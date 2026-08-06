/**
 * @file nodus_witness_v2_pools.h
 * @brief Ledger V2 Season 7 — persistent per-domain/per-pool shielded
 *        pool state: the D=24 note-commitment tree frontier, finalized
 *        root history + authoritative anchor lookup, the nullifier set,
 *        the public aggregate pool balance and the REAL pools_root
 *        (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. Tests (and later the
 * Ledger V2 devnet reset) drive it. Type 11 admission remains an
 * unconditional consensus REJECT (C3 stop); tx types 12-14 stay
 * UNASSIGNED; no proof result, no transaction-supplied anchor and no
 * wallet/delivery path reaches any mutation below. S7 is state
 * infrastructure only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── Ownership / genericity ────────────────────────────────────────────
 * Pool state is namespaced (domain_id, pool_id) — a pool id is unique
 * only inside its owning domain. This module is domain-agnostic: it
 * never knows the native token, the first pool's number, or how a
 * runtime interprets its asset_ref. Pool POLICY belongs to the owning
 * runtime: the DNA_CORE runtime instantiates its configured native
 * D=24 pool through its own activation path (nodus_rt_core_state_init,
 * dispatched through the generic optional state_init runtime hook) and
 * commits its pools_root as one leg of core_state_root. The global
 * layer continues to consume only opaque DomainUpdates and state roots.
 *
 * ── Tree primitive ────────────────────────────────────────────────────
 * The authoritative D=24 tree is the shipped shielded_tree
 * (shared/crypto/zk/shielded_tree.{h,c}) — Poseidon2
 * note_merkle_compress, E_0 = zero leaf, capacity 2^24, append refuses
 * at FULL before any mutation. This module persists exactly the O(D)
 * consensus state (filled-subtree frontier + count + current root) and
 * appends THROUGH shielded_tree_append on a frontier-restored tree —
 * the struct is transparent for exactly this purpose
 * (shielded_tree.h:71-73). The O(count) commitment list
 * (v2_pool_notes) is DERIVED/rebuildable path-serving storage and is
 * never independently committed by pools_root.
 *
 * The persisted frontier blob is CANONICAL: level i's 32 bytes are the
 * 4 u64 BE lanes of filled[i] when bit i of note_count is 1, and ZERO
 * otherwise — two witnesses with the same appends hold byte-identical
 * rows. On load the frontier, count and root are MUTUALLY verified
 * (root recomputed from the frontier must equal the stored root; the
 * derived tables' counts must match) — disagreement fails closed;
 * ordinary startup never rebuilds or repairs consensus state.
 *
 * ── Deterministic mutation order ──────────────────────────────────────
 * Canonical output append order is (global block tx index, output slot
 * inside that transaction); nullifier insertion order is (global block
 * tx index, input slot). A batch must be strictly ascending on that
 * key with contiguous slots per transaction — duplicates, skipped or
 * ambiguous ordering and non-canonical slots reject before any write.
 * Only the FINAL note root a committed block produces for a pool
 * enters the root history; intermediate roots never do; a
 * transaction-supplied root never becomes authoritative.
 *
 * ── Root history (devnet R = 720) ─────────────────────────────────────
 * The retained window counts DISTINCT finalized note-root updates —
 * not blocks, not time. A created pool's history starts with the
 * canonical empty D=24 root; a quiet block adds nothing; a block whose
 * final root equals the current root adds nothing; a changed final
 * root adds exactly one entry and evicts the single oldest entry once
 * the consensus-committed history_limit is exceeded. A NON-CURRENT
 * retained root reappearing as the new root is corruption/collision
 * and fails closed. Anchor acceptance requires membership in the
 * retained window of (chain, domain, pool). The limit is committed
 * through the pool's versioned configuration (config_hash → pool leaf
 * → pools_root); the MAINNET value remains OPEN.
 *
 * EVICTION SEMANTICS (exact consensus rule): reappearance detection
 * and the v2_pool_roots uniqueness constraint cover the RETAINED
 * window ONLY — once evicted, a root is no longer stored for anchor
 * acceptance OR duplicate detection, and NO unbounded seen-roots
 * table exists. In an append-only D=24 commitment tree, reproducing
 * an evicted earlier root after additional leaves would require
 * breaking the tree hash's collision/preimage resistance — a
 * CRYPTOGRAPHIC assumption, not a database-enforced permanent-history
 * rule.
 *
 * @file nodus_witness_v2_pools.h
 */

#ifndef NODUS_WITNESS_V2_POOLS_H
#define NODUS_WITNESS_V2_POOLS_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"
#include "dnac/pool_wire.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── In-memory pool state (one v2_pools row, verified) ──────────────── */

typedef struct {
    dna_pool_config_t cfg;
    uint64_t note_count;
    uint8_t  note_root[DNA_POOL_NOTE_LEN];
    uint8_t  frontier[DNA_POOL_TREE_DEPTH_V1][DNA_POOL_NOTE_LEN];
    uint64_t nul_count;
    uint8_t  nul_root[DNA_POOL_ROOT_LEN];
    uint64_t balance;
    uint64_t hist_count;
    uint64_t hist_next_seq;
} nodus_v2_pool_state_t;

/**
 * Create one pool with its canonical initial state (INSIDE the
 * caller's transaction — never commits on its own): note_count 0,
 * note_root = the canonical empty D=24 root, zeroed frontier,
 * nul_count 0, empty nullifier root, balance 0, and a root history
 * initialized with exactly the empty-root entry (seq 0, at
 * `global_height`), hist_next_seq 1. v1 accepts tree_depth 24 only.
 * Idempotent-or-conflict: an existing (domain, pool) row whose
 * CONFIGURATION columns byte-match `cfg` is a no-op (0); any
 * difference is a conflict (-1).
 */
int nodus_witness_v2_pool_create(nodus_witness_t *w,
                                 const dna_pool_config_t *cfg,
                                 uint64_t global_height);

/**
 * Load + fully verify one pool. Mutual verification (all fail-closed):
 * canonical shapes; the root recomputed from the frontier equals the
 * stored root; the derived append-only tables' TIPS agree with the
 * committed counters (MAX(position)+1 == note_count / nul_count, a
 * zero counter tolerates no row — the derived bodies are
 * recovery-tooling scope, never an ordinary-startup rebuild); the
 * retained history is the contiguous newest-hist_count window ending
 * at hist_next_seq-1 whose newest entry IS the current root;
 * hist_count within [1, history_limit].
 * @return 0 found+valid, 1 absent, -1 fault or corruption (never a
 *         silent rebuild).
 */
int nodus_witness_v2_pool_load(nodus_witness_t *w, uint32_t domain_id,
                               uint32_t pool_id,
                               nodus_v2_pool_state_t *out);

/* ── Canonical mutation batch (INACTIVE — test/fixture-driven only;
 *    future S9 transaction semantics will construct these) ──────────── */

typedef struct {
    uint8_t  commitment[DNA_POOL_NOTE_LEN];  /* canonical 4×u64 BE      */
    uint32_t tx_index;                       /* global block tx index   */
    uint16_t output_slot;                    /* slot inside that tx     */
} nodus_v2_pool_out_t;

typedef struct {
    uint8_t  nullifier[DNA_POOL_NULLIFIER_LEN];
    uint32_t tx_index;
    uint16_t input_slot;
} nodus_v2_pool_in_t;

typedef struct {
    uint32_t domain_id;
    uint32_t pool_id;
    const nodus_v2_pool_out_t *outs;   /* strictly ascending (tx, slot),
                                        * slots contiguous from 0 per tx */
    size_t n_outs;
    const nodus_v2_pool_in_t *ins;     /* same canonical ordering rule   */
    size_t n_ins;
    uint64_t balance_add;              /* checked; overflow rejects      */
    uint64_t balance_sub;              /* checked; underflow rejects     */
} nodus_v2_pool_mut_t;

/** Shape-validate one batch (pure): canonical ordering + contiguous
 *  slots, canonical lanes, in-batch duplicate nullifiers, at least one
 *  actual change. @return 0 / -1. */
int nodus_witness_v2_pool_mut_validate(const nodus_v2_pool_mut_t *m);

/* Mutation stages, in execution order — the stage callback receives
 * each value AFTER that stage's writes; a nonzero return aborts the
 * batch (the apply engine maps these to its S7 fault points). */
typedef enum {
    NODUS_V2_POOL_STAGE_COMMITS = 1,   /* v2_pool_notes rows inserted   */
    NODUS_V2_POOL_STAGE_FRONTIER,      /* frontier/root/count updated   */
    NODUS_V2_POOL_STAGE_NULLS,         /* nullifier rows inserted       */
    NODUS_V2_POOL_STAGE_NULROOT,       /* nullifier root/count updated  */
    NODUS_V2_POOL_STAGE_BALANCE,       /* balance updated               */
    NODUS_V2_POOL_STAGE_HISTORY,       /* history entry appended        */
    NODUS_V2_POOL_STAGE_EVICT          /* oldest entry evicted          */
} nodus_v2_pool_stage_t;

typedef int (*nodus_v2_pool_stage_cb)(void *ud, nodus_v2_pool_stage_t s);

/**
 * Apply one canonical batch to one pool (INSIDE the caller's
 * transaction — never commits on its own). Fail-closed pre-checks
 * BEFORE any write: batch shape, pool load+verify, total capacity
 * (note_count + n_outs ≤ 2^24 — a batch crossing capacity rejects
 * atomically), every nullifier absent from the committed set. Then the
 * stages above in order; the final changed root (if any) is the ONE
 * history entry this batch contributes. `cb` (optional) fires after
 * each stage; nonzero aborts with -1 (the enclosing transaction is the
 * rollback boundary). @return 0 / -1.
 */
int nodus_witness_v2_pool_apply(nodus_witness_t *w,
                                const nodus_v2_pool_mut_t *m,
                                uint64_t global_height,
                                nodus_v2_pool_stage_cb cb, void *ud);

/* ── Roots / lookups (read-only, fail-closed) ───────────────────────── */

/**
 * S7 correction — ONE production-reachable startup verification pass.
 *
 * Called from the witness DB open path
 * (nodus_witness_create_chain_db, nodus_witness.c) AFTER the database
 * opens, ONCE per database startup — before the witness may validate
 * or apply any Ledger V2 block. A pre-v7 database (user_version != 7)
 * has no pool state and passes vacuously. Runs inside one read
 * transaction (consistent snapshot); NEVER repairs, deletes, reorders
 * or rebuilds anything — any mismatch fails closed (the caller
 * refuses the database).
 *
 * Per pool, in (domain_id, pool_id) order:
 *   NULLIFIER LOG (the committed (nul_root, nul_count) covers the
 *   ORDERED log; the SQL table serves spent lookups — a tip-only
 *   check cannot see an interior deletion/modification, so the FULL
 *   chain is replayed here):
 *     rows strictly by position ASC; first position 0; every position
 *     == the next expected value; every nullifier exactly 32 canonical
 *     bytes; every DNA.PNUL.v1 step recomputed in order; processed
 *     rows == stored nul_count; recomputed root == stored nul_root;
 *     zero rows ⇒ count 0 AND the canonical empty root.
 *   DERIVED NOTE TABLE (structural shape only — v2_pool_notes stays
 *   derived/path-serving and is never independently committed twice):
 *     COUNT(*) == note_count; zero count ⇒ no rows; else MIN(position)
 *     == 0 and MAX(position) == note_count-1 (positions unique via the
 *     PK); every commitment exactly 32 canonical bytes. An interior
 *     commitment-byte corruption does NOT redefine consensus state —
 *     the persisted frontier/root remains authoritative and any
 *     generated path must still verify against that root; the
 *     frontier is never rebuilt from this table.
 *
 * The per-block insertion path stays O(1) per nullifier; this O(n)
 * scan runs only at startup. @return 0 healthy / -1 fail closed.
 */
int nodus_witness_v2_pools_startup_check(nodus_witness_t *w);

/**
 * The REAL per-domain pools_root: every v2_pools row of `domain_id`
 * (strictly ascending pool_id), each pool fully load-verified, its
 * history commitment recomputed from the retained window, leaves
 * hashed per pool_wire.h and rooted with "DNA.POOLNODE.v1". An absent
 * v2_pools table (pre-S7 database) or a domain with zero pools returns
 * the frozen S2 tagged-empty pools_root byte-identically.
 */
int nodus_witness_pools_root_v2(nodus_witness_t *w, uint32_t domain_id,
                                uint8_t out[64]);

/**
 * Authoritative anchor lookup: accept exactly
 *   anchor ∈ retained_finalized_roots(chain_id, domain_id, pool_id).
 * `chain_id` must equal this database's derived chain id
 * (nodus_witness_v2_chain_id). Unknown, forged, expired (evicted),
 * wrong-chain, wrong-domain, wrong-pool and non-canonical anchors all
 * reject. Read-only; NO live caller exists in S7 and a
 * transaction-supplied anchor gains no authority from this check.
 * @return 0 accepted, -1 rejected/fault.
 */
int nodus_witness_v2_pool_anchor_check(nodus_witness_t *w,
                                       const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                       uint32_t domain_id,
                                       uint32_t pool_id,
                                       const uint8_t note_root[DNA_POOL_NOTE_LEN]);

/** Checked Σ balance over the pools of (domain_id, asset_ref) — the
 *  bucket a runtime's OWN conservation invariant consumes. Never a
 *  cross-domain or cross-asset sum. Absent v2_pools table (pre-S7 DB)
 *  = honest 0. DB fault = -1 (never a value). */
int nodus_witness_v2_pool_balance_total(nodus_witness_t *w,
                                        uint32_t domain_id,
                                        const uint8_t *asset_ref,
                                        uint16_t asset_ref_len,
                                        uint64_t *out);

/* ── DNA_CORE runtime pool policy (the ONLY place that knows the
 *    native pool's concrete configuration) ─────────────────────────── */

/** The generic activation-time state_init hook, CORE implementation:
 *  creates the configured native D=24 pool (symbolic IDs
 *  DNA_DOMAIN_CORE / DNAC_SHIELDED_POOL_V1, native 64-zero-byte
 *  token_id asset_ref, devnet history limit 720) — idempotent inside
 *  one activation. Requires schema v7 (fails closed earlier). */
int nodus_rt_core_state_init(const nodus_domain_runtime_t *rt,
                             struct nodus_witness *w,
                             uint64_t activation_global_height);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_POOLS_H */
