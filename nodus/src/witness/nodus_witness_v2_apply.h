/**
 * @file nodus_witness_v2_apply.h
 * @brief Ledger V2 Season 5 — the INACTIVE atomic global-block apply
 *        engine, V2 genesis, and the V2 supply-conservation gate.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. Tests (and later the V2
 * devnet reset) drive it. Real transaction SEMANTICS are Season-9 work:
 * this engine executes CONTROLLED TEST-ONLY state transitions
 * (nodus_v2_op_t.sql) to prove the persistence, ordering, atomicity,
 * rollback, resource and supply machinery — exactly the S5 charter.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── One atomic SQLite transaction per global block ────────────────────
 * nodus_witness_v2_apply_block OWNS the single BEGIN IMMEDIATE. Every
 * helper below it runs inside that transaction and never commits on its
 * own. Phase order (prompt §9/§10):
 *
 *   0.  replay/linkage checks against v2_blocks (read-only, pre-BEGIN)
 *   1.  BEGIN IMMEDIATE                                   [F1]
 *   2.  supply gate (pre-apply)
 *   3.  resource pre-scan + quota enforcement (BEFORE any mutation)
 *   4.  SYSTEM-phase ops (touched == {SYSTEM})            [F2]
 *   5.  cross-domain ops (touched_n > 1)                  [F3]
 *   6.  domain-local batches, EVERY registered domain, domain_id ASC
 *                                                         [F4 per batch]
 *       (all op SQL has now run)                          [F5 "UTXO"]
 *   6b. S6 generic claims: admit (committed manifest names the TARGET
 *       domain + asset; the registered target runtime is resolved
 *       through the generic registry path) → target-runtime output
 *       [F16] → spent-claim insert [F17] → distribution-state
 *       decrement [F18]; fault points fire after the named stage of
 *       claim `fail_claim_index`. The engine never creates an output
 *       or picks a domain itself.
 *   6c. LIFECYCLE re-scan (canonical DomainHead lifecycle): re-read the
 *       registry; a domain whose status became ACTIVE with no committed
 *       head gets its ONE deterministic activation head HERE (height 0,
 *       root = runtime state root bound to the registry-committed
 *       genesis_state_root, last_updated = this block, status ACTIVE,
 *       height-0 history row) — atomic with the SYSTEM registry
 *       transition, entering domains_root in this same block. A resume
 *       (PAUSED→ACTIVE) fails closed unless the exact runtime tuple
 *       resolves; a vanished registry row rejects; heads are NEVER
 *       synthesized anywhere else. Execution authority remains the
 *       BLOCK-ENTRY status: nothing executes in its own activation
 *       block.
 *   7.  supply gate (post-stage)                          [F6 "supply"]
 *   8.  domain state roots — dispatched through each REGISTERED
 *       runtime's state_root hook — + the UNTOUCHED-DOMAIN GUARD:
 *       an untouched domain's recomputed root MUST equal its persisted
 *       head root — an op that mutated a domain it did not declare
 *       (cross-domain substitution) rejects the whole block  [F7]
 *   9.  DomainUpdate build + verify + persist (touched only)  [F8]
 *   10. DomainHead write                                   [F9]
 *   11. root history append                                [F10]
 *   12. global + local transaction indices                 [F11]
 *   13. domain_updates_root + domains_root + global root; compare every
 *       caller-expected root; v2_blocks metadata insert    [F12]
 *   14. supply gate (pre-commit)                           [F13]
 *   15. COMMIT                                             [F14 simulated
 *       commit failure → ROLLBACK]                         [F15 = crash
 *       window AFTER commit, BEFORE cache publication → rc 2; restart
 *       reconstructs from the tables]
 *
 * Any failure before COMMIT rolls back EVERYTHING (UTXOs, supply
 * counters, registry, updates, heads, history, indices, metadata) — the
 * tests prove it by byte-comparing table dumps and roots, not by return
 * codes. There are no authoritative V2 in-memory caches to un-publish;
 * the reconstruct-on-restart path is the table state itself.
 *
 * ── Replay / idempotency (checked BEFORE the transaction) ─────────────
 *   same height, byte-identical BlockID already committed → rc 1, NO
 *     writes of any kind;
 *   same height, different BlockID → reject;
 *   same BlockID at another height → reject;
 *   height gap (height != max_committed + 1) → reject;
 *   wrong prev_block_id (must equal the previous row's block_id) → reject.
 *
 * ── Touched-domain definition ─────────────────────────────────────────
 * touched(block) = the UNION of the DECLARED touched lists of the block's
 * ops. A rejected transaction never reaches the op list; an op that
 * declares a domain but does not change its state still touches it (its
 * update carries the unchanged-root transition post == pre is REJECTED —
 * see below); an op that CHANGES a domain it did not declare is caught by
 * the untouched-domain guard. An untouched domain gets NO update, NO
 * head write, NO history row and its domain_height does not move —
 * SYSTEM does not advance merely because the global height advanced.
 * (A touched domain whose recomputed root equals its head root is a
 * DECLARED no-op: the engine rejects the block — no fake empty updates.)
 *
 * ── Resources (S4 quotas; weights stay S4 placeholders — OPEN) ────────
 * An op's verify_cost is charged to EVERY domain it touches (each domain
 * accounts the verification work imposed on it) — the one canonical
 * cross-domain rule. res_tx_count increments likewise. Checked
 * arithmetic throughout; per-domain quotas from the S4 registry
 * manifests (0 = the global cap/budget governs — never "unlimited");
 * global caps: chain-config MAX_TXS_PER_BLOCK and
 * NODUS_V2_GLOBAL_VERIFY_BUDGET (test-level JUDGMENT constant; the
 * consensus value is OPEN until S9 pins real weights).
 *
 * ── Supply gate (V2) — runtime-owned invariant DISPATCH ───────────────
 * nodus_witness_v2_supply_check is a DISPATCHER, not an equation: it
 * iterates the registered domains (falling back to the compiled native
 * runtime table on a pre-registry database) and calls each runtime's
 * OWN invariant hook. Heterogeneous domain assets are NEVER summed into
 * one global equation:
 *   - SYSTEM declares no asset state (NULL hook);
 *   - the native CORE runtime enforces the DNAC conservation equation
 *     (genesis + minted − burned == Σ CORE utxo + Σ self_stake +
 *     Σ delegated + Σ epoch_pool + unclaimed CORE-NATIVE distribution +
 *     shielded ≡ 0), including a fail-closed guard that no foreign
 *     domain owns a utxo_set row and no shielded/pool table exists —
 *     see nodus_rt_core_invariant (nodus_witness_v2_claims.c);
 *   - a registered ACTIVE domain whose runtime this build cannot
 *     resolve FAILS the gate (unknown state is never "conserved");
 *   - future runtimes enforce their own assets through the same hook.
 * A claim MOVES value between two owners of the SAME target-domain
 * asset (unclaimed distribution → target-runtime output) — it never
 * mints or burns. The gate runs at V2 genesis, pre-apply, post-stage,
 * pre-commit, and is re-runnable after restart.
 *
 * @file nodus_witness_v2_apply.h
 */

#ifndef NODUS_WITNESS_V2_APPLY_H
#define NODUS_WITNESS_V2_APPLY_H

#include "witness/nodus_witness.h"
#include "dnac/domain_wire.h"
#include "dnac/manifest_wire.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Global verify-work budget per block — TEST-LEVEL JUDGMENT constant;
 *  the consensus value is OPEN until S9 pins real cost weights. */
#define NODUS_V2_GLOBAL_VERIFY_BUDGET  1000u

/** Deterministic fault-injection points (prompt §11, 15 points). */
typedef enum {
    V2AP_FAIL_NONE = 0,
    V2AP_FAIL_AFTER_BEGIN = 1,
    V2AP_FAIL_AFTER_SYSTEM = 2,
    V2AP_FAIL_AFTER_CROSS = 3,
    V2AP_FAIL_AFTER_DOMAIN_BATCH = 4,   /* + blk->fail_domain_batch      */
    V2AP_FAIL_AFTER_UTXO = 5,
    V2AP_FAIL_AFTER_SUPPLY_MUT = 6,
    V2AP_FAIL_AFTER_DOMAIN_ROOTS = 7,
    V2AP_FAIL_AFTER_UPDATES = 8,
    V2AP_FAIL_AFTER_HEADS = 9,
    V2AP_FAIL_AFTER_HISTORY = 10,
    V2AP_FAIL_AFTER_TX_INDEX = 11,
    V2AP_FAIL_AFTER_BLOCK_META = 12,
    V2AP_FAIL_BEFORE_COMMIT = 13,
    V2AP_FAIL_COMMIT = 14,              /* simulated COMMIT failure      */
    V2AP_FAIL_AFTER_COMMIT = 15,        /* pre-cache crash window → rc 2 */
    /* S6 claim stages (fire after the named stage of the claim at
     * index blk->fail_claim_index) */
    V2AP_FAIL_AFTER_CLAIM_OUTPUT = 16,  /* target-runtime output created */
    V2AP_FAIL_AFTER_CLAIM_SPEND = 17,   /* spent-claim insert done       */
    V2AP_FAIL_AFTER_CLAIM_STATE = 18    /* remaining decremented         */
} nodus_v2_apply_fail_t;

/** One controlled test-only state transition ("transaction"). */
typedef struct {
    uint8_t  tx_id[64];                 /* global transaction identity   */
    uint32_t touched[DNA_TOUCHED_MAX];  /* DECLARED touched domains, ASC */
    uint16_t touched_n;                 /* 1..DNA_TOUCHED_MAX            */
    const char *sql;                    /* executed inside THE txn; NULL
                                         * = pure declaration            */
    uint32_t verify_cost;               /* declared work units           */
} nodus_v2_op_t;

/** One V2 global block for the engine. */
typedef struct {
    uint64_t global_height;
    uint64_t epoch;
    uint8_t  block_id[64];
    uint8_t  prev_block_id[64];
    uint8_t  vset_hash[64];
    const nodus_v2_op_t *ops;
    size_t   n_ops;
    /* S6 generic claims (routed to each claim's COMMITTED target
     * runtime; processed INSIDE the one block transaction, phase 6b).
     * NULL/0 = none. */
    const dna_claim_t *claims;
    size_t   n_claims;
    /* Follower-mode expected roots — any NULL = leader mode (fill). A
     * non-NULL expectation that mismatches the recomputation rejects the
     * whole block. */
    const uint8_t *expect_tx_root;
    const uint8_t *expect_dupd_root;
    const uint8_t *expect_domains_root;
    const uint8_t *expect_global_root;
    /* Fault injection */
    nodus_v2_apply_fail_t fail_at;
    uint32_t fail_domain_batch;         /* domain_id for point 4         */
    uint32_t fail_claim_index;          /* claim index for points 16-18  */
    /* Outputs (valid on rc 0/2) */
    uint8_t  out_tx_root[64];
    uint8_t  out_dupd_root[64];
    uint8_t  out_domains_root[64];
    uint8_t  out_global_root[64];
} nodus_v2_block_t;

/** V2 supply-conservation gate (header equation). @return 0 / -1. */
int nodus_witness_v2_supply_check(nodus_witness_t *w);

/**
 * V2 genesis: requires schema version 6; one atomic transaction seeding
 * the domain registry (REAL payload-root manifests — the S5 cycle
 * break), then ONE canonical ACTIVATION DomainHead per registered
 * domain whose status is ACTIVE (the genesis block IS those domains'
 * activation block: height 0, root = the runtime's state root — whose
 * activation payload form must equal the registry-committed
 * genesis_state_root — last_updated 0, status ACTIVE, height-0 history
 * row; SYSTEM's head root is the FULL 7-leg system root computed AFTER
 * the registry rows exist). A registered-but-not-ACTIVE domain exists
 * only in the registry: no head, absent from domains_root. Then the
 * height-0 v2_blocks row (empty tx/update roots) and the supply gate.
 * The domain count is whatever the registry holds — never a fixed two.
 * Idempotent-or-conflict (byte-identical re-run 0 / diverging -2 / -1).
 */
int nodus_witness_v2_genesis(nodus_witness_t *w,
                             const uint8_t genesis_block_id[64],
                             const uint8_t vset_hash[64],
                             uint64_t epoch);

/**
 * S6 variant: additionally commits ONE canonical GenesisManifest v1
 * (manifest_seq 0, height 0) inside the same genesis transaction,
 * BEFORE the root computation — so the genesis SYSTEM head root
 * commits the REAL manifest_root. `manifest_bytes` NULL/0 keeps the
 * legacy no-manifest genesis (manifest_root stays the tagged-empty
 * leg). The manifest's domain set is cross-checked against the domain
 * registry and its genesis supply against supply_tracking; a present
 * distribution section seeds the unclaimed-distribution state
 * (v2_dist_state) that the supply gate then owns. Same return contract
 * as nodus_witness_v2_genesis.
 */
int nodus_witness_v2_genesis_ex(nodus_witness_t *w,
                                const uint8_t genesis_block_id[64],
                                const uint8_t vset_hash[64],
                                uint64_t epoch,
                                const uint8_t *manifest_bytes,
                                size_t manifest_len);

/**
 * Apply one V2 global block (header contract).
 * @return 0 committed; 1 idempotent replay (no writes); 2 committed but
 *         the post-commit/pre-cache crash window fired (state IS
 *         committed; restart reconstructs it); -1 rejected + rolled back.
 */
int nodus_witness_v2_apply_block(nodus_witness_t *w, nodus_v2_block_t *blk);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_APPLY_H */
