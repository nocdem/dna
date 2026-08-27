/**
 * @file nodus_witness_v2_apply.h
 * @brief Ledger V2 Season 5 — the INACTIVE atomic global-block apply
 *        engine, V2 genesis, and the V2 supply-conservation gate.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. Tests (and later the V2
 * devnet reset) drive it. The caller-shaped raw-SQL op scaffold
 * (nodus_v2_op_t.sql) is RETIRED: a block carries ENVELOPES
 * (nodus_v2_envelope_t — bytes and length, nothing else), and every
 * state transition they cause runs through ONE typed, mediated, metered
 * path:
 *
 *   envelope bytes → canonical preflight (dna_env_preflight) →
 *   ENGINE-DERIVED transaction identity → exact five-axis runtime
 *   resolution from the FROZEN block-start snapshot → deterministic
 *   reservation (res_meter) → mediated reads (adapter `read`, engine-
 *   charged) → native compiled runtime execution (nodus_rt_exec_fn) →
 *   canonical "DNA.EFFRES.v1" typed result → strict decode + adapter
 *   validation → deterministic charging → storage-adapter application →
 *   domain/global roots → persistence → ONE outer COMMIT.
 *
 * There is NO second execution path and NO raw-SQL fallback inside this
 * engine boundary: no V2 request, runtime result or effect can carry
 * SQL text, a table name, a schema string, an SQLite handle or a
 * callback address — the envelope and effect codecs cannot represent
 * them. The only SQL in this file is the ENGINE'S OWN persistence
 * (heads/updates/history/indices/metadata and BEGIN/COMMIT/ROLLBACK),
 * compiled into the engine, never accepted from a caller or a runtime.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── One atomic SQLite transaction per global block ────────────────────
 * nodus_witness_v2_apply_block OWNS the single BEGIN IMMEDIATE. Every
 * helper below it runs inside that transaction and never commits on its
 * own. Phase order:
 *
 *   0.  replay/linkage checks against v2_blocks (read-only, pre-BEGIN)
 *   0a. FROZEN BLOCK-START EXECUTION SNAPSHOT (read-only, pre-BEGIN):
 *       registered-domain working set (strict ACTIVE preconditions),
 *       per-domain contextual ruleset table, derived chain id, epoch
 *       DERIVED FROM GLOBAL BLOCK COUNT (blk->epoch must equal
 *       global_height / DNAC_EPOCH_LENGTH — never a clock), the block
 *       metering policy from the resolved SYSTEM runtime (seal +
 *       descriptor-committed identity digest verified), and the
 *       global/per-domain unit budgets. EVERY transaction in the block
 *       resolves against this one snapshot: no mid-block mutation can
 *       change a later transaction's ruleset, price or authority, and
 *       the caller can neither supply nor override any of it.
 *   0b. envelope preflight + RESERVATION of the whole canonical batch
 *       (nodus_witness_v2_env_preflight_reserve_batch — BOTH derived
 *       identities per envelope, batch dedup at wire AND intent level,
 *       deterministic sequential reservation)                   [F26]
 *       + COMMITTED-IDENTITY REPLAY GUARD (intent season): each
 *       envelope's intent_id then wire_id checked read-only against
 *       v2_intent_index / v2_tx_index — a hit is a deterministic
 *       VERDICT (a committed intent may commit ONCE per chain, under
 *       exactly one wire realization; matching intent is never
 *       evidence of authorization). Budget restored byte-identically
 *       on rejection.                                           [F35]
 *       + per-leg execution admission: block-entry ACTIVE domain,
 *       resolvable runtime WITH an exec hook, INVOKE access (READ legs
 *       are rejected this season — an admission rule for a later
 *       season, honest label below), runtime_op OWNED by the domain's
 *       committed ruleset (descriptor rule_ids), per-domain tx quota.
 *   1.  BEGIN IMMEDIATE                                   [F1]
 *   2.  supply gate (pre-apply)
 *   4.  SYSTEM-phase envelopes (single leg, SYSTEM)       [F2]
 *   5.  cross-domain envelopes (leg_count > 1)            [F3]
 *   6.  domain-local envelopes, EVERY registered domain, domain_id ASC
 *                                                         [F4 per batch]
 *       Each envelope executes as: meter activate → per leg (ascending
 *       domain_id by envelope construction): mediated read plan +
 *       engine-charged reads → native exec → strict result decode →
 *       adapter validation → effect charge → adapter application
 *       [F37 mid-effect-list, F38 BETWEEN legs of the same envelope] →
 *       meter finalize                          [F27 after the envelope
 *       at fail_env_index]                                [F5 "UTXO"]
 *   6b. S6 generic claims: admit (committed manifest names the TARGET
 *       domain + asset; the registered target runtime is resolved
 *       through the generic registry path) → target-runtime output
 *       [F16] → spent-claim insert [F17] → distribution-state
 *       decrement [F18]; fault points fire after the named stage of
 *       claim `fail_claim_index`. The engine never creates an output
 *       or picks a domain itself.
 *   6p. S7 pool-state batches (INACTIVE test/fixture surface — future
 *       S9 transaction semantics will construct these): each batch is
 *       one pool's canonical mutations for this block, processed in
 *       strictly ascending (domain_id, pool_id) order through
 *       nodus_witness_v2_pool_apply — commitment inserts [F19] →
 *       frontier/root/count update [F20] → nullifier inserts [F21] →
 *       nullifier-root update [F22] → balance update [F23] → history
 *       append [F24] → history eviction [F25]; fault points fire
 *       after the named stage of batch `fail_pool_index`. Carrying a
 *       batch declares its (already ACTIVE, runtime-backed) owning
 *       domain touched. The engine knows no pool internals — ordering,
 *       capacity, canonicity, duplicate and collision rules live in
 *       the pool module. pools_root recomputation rides the existing
 *       domain-root phase [F7]; DomainHead/history/global metadata
 *       persistence ride [F9]/[F10]/[F12].
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
 *   12. transaction indices: SEMANTIC first (v2_intent_index —
 *       intent_id PK + its ONE accepted wire realization)  [F36]
 *       then WIRE (v2_tx_index + v2_tx_local_index)        [F11]
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
 * the reconstruct-on-restart path is the table state itself. The
 * IN-MEMORY meter/budget state rolls back too: on every rejection the
 * engine aborts every non-terminal meter, which restores the engine-
 * owned budget byte-identically — no reservation is ever stranded and
 * no meter is left RESERVED or ACTIVE.
 *
 * ── FAULT vs VERDICT vs DEFERRAL (the return-code contract) ───────────
 * The named values are nodus_v2_result_t (nodus_witness_v2_result.h).
 *
 * -1 CONSENSUS_INVALID is a VERDICT: a deterministic function of
 * (committed state, block bytes) — every honest node computes the same
 * rejection.
 * -2 INTERNAL_FAULT is a NODE-LOCAL FAULT: this node could not compute
 * (storage fault, hash-backend failure, allocation failure, broken
 * compiled table, meter accounting FAULT).
 * -3 NOT_YET_LINKABLE is a DEFERRAL, added by O15A: the block's height is
 * beyond the next expected one, or no genesis is committed here, so the
 * required predecessor state is absent and NOTHING was judged. It is not
 * a rejection and must never be reported as one — a node that is merely
 * behind produces it for bytes that synced peers accept. Note the
 * boundary: a block AT or BELOW the head is evaluable now and gets a
 * verdict; only a block ahead of the chain is deferred.
 *
 * All three roll back completely. A consensus caller MUST fail its own
 * operation on -2 and -3 (do not vote), and never convert either into a
 * transaction/block rejection — the env_preflight.h ERR_HASH rule,
 * engine-wide.
 *
 * CONSERVATIVE CLASSIFICATION SEAM: nodus_witness_v2_runtime_for
 * conflates "tuple not carried by this build" with a node-local domreg
 * read fault (one -1). Everywhere the engine re-resolves a runtime
 * INSIDE the block (the 6c lifecycle re-scan, the phase-8 root pass) a
 * NULL result is therefore classified -2 — the SAFE direction: the
 * deterministic unsupported-tuple case also reads as "do not vote"
 * rather than risking one starved witness voting reject. The
 * deterministic VERDICTS about resolvability live in the pre-BEGIN
 * admission scan (strict doms_load + per-leg checks).
 *
 * ── HONEST LABELS (what this engine still does NOT do) ────────────────
 *   (DRIFT REPAIR, intent season: the former "authorization stays with a
 *   later season" label was stale — the native-auth season shipped the
 *   verified boundary. Authorization is now verified pre-BEGIN into the
 *   engine-owned verdict array; the exec context hands runtimes BOTH
 *   derived identities — wire_id, intent_id — plus the commitments and
 *   the verified verdict, and consensus-state provenance binds
 *   intent_id only.)
 *   - READ-access legs: DNA_ENV_ACCESS_READ legs are REJECTED at the
 *     execution boundary this season (fail-closed); their admission
 *     semantics are a later season's rule. Metering already prices them
 *     (res_meter.h honest label), so no pricing question is left open.
 *   - PER-DOMAIN UNIT QUOTAS: manifest v1 commits quota_verify_cost
 *     (u32). Where non-zero it is used as that domain's per-block unit
 *     budget; 0 = the global unit budget governs. Denominating committed
 *     quotas in envelope-lane units (rather than the legacy tx_cost work
 *     units, which the envelope lane never consults) is the documented
 *     interim rule until the devnet reset pins real economics.
 *
 * ── Replay / idempotency (checked BEFORE the transaction) ─────────────
 *   same height, byte-identical BlockID already committed → rc 1, NO
 *     writes of any kind;
 *   same height, different BlockID → reject;
 *   same BlockID at another height → reject;
 *   height gap (height != max_committed + 1) → reject;
 *   wrong prev_block_id (must equal the previous row's block_id) → reject.
 *   TRANSACTION-LEVEL (intent season, after the whole-block matrix —
 *   exact committed-block replay therefore stays idempotent, rc 1):
 *   an envelope whose intent_id is already committed → reject (semantic
 *     replay — including under a DIFFERENT valid authorization witness,
 *     and in ANY later block);
 *   an envelope whose wire_id is already committed → reject (the intent
 *     guard subsumes this for byte-identical envelopes; the wire check
 *     is the independent second leg);
 *   both backstopped by the v2_intent_index / v2_tx_index UNIQUE
 *     constraints inside the block transaction.
 *
 * ── Touched-domain definition ─────────────────────────────────────────
 * touched(block) = the UNION of the LEG DOMAINS of the block's included
 * envelopes (an envelope's legs are strictly ascending by domain_id —
 * the DECLARED touched set IS the leg list) ∪ the claims' committed
 * TARGET domains ∪ the pool batches' owning domains. A domain a leg
 * addresses without changing its state still touches it (post == pre is
 * REJECTED — a DECLARED no-op, no fake empty updates); a runtime that
 * CHANGES a domain its leg did not address is caught by the
 * untouched-domain guard (cross-domain substitution rejects the block).
 * An untouched domain gets NO update, NO head write, NO history row and
 * its domain_height does not move — SYSTEM does not advance merely
 * because the global height advanced.
 *
 * ── Resources (deterministic metering — res_meter.h authority model) ──
 * Every included envelope is priced EXCLUSIVELY by the frozen block-
 * start policy snapshot (the SYSTEM ruleset's committed policy): plan →
 * reserve (full declared ceiling from the global unit budget, per-leg
 * static units from each leg domain's budget) → activate → per-read and
 * per-result charges → finalize (unused units released) — abort on any
 * rejection restores everything. No caller, envelope, runtime or legacy
 * tx_cost hook can feed or override a price; no domain borrows from
 * another. Checked u64 arithmetic throughout. Global caps: chain-config
 * MAX_TXS_PER_BLOCK and NODUS_V2_GLOBAL_UNIT_BUDGET (JUDGMENT constant;
 * the consensus value is OPEN until the devnet reset pins economics);
 * per-domain budgets from the committed manifest quota (honest label
 * above).
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
#include "witness/nodus_witness_v2_result.h"
#include "witness/nodus_witness_v2_pools.h"
#include "witness/nodus_witness_v2_env.h"   /* nodus_v2_envelope_t + the
                                             * preflight/reserve seam    */
#include "dnac/domain_wire.h"
#include "dnac/manifest_wire.h"
#include "dnac/block_v2.h"                  /* O14: the engine OWNS the
                                             * canonical header v3 and
                                             * the BlockID it persists   */
#include "dnac/dnac.h"                      /* DNAC_EPOCH_LENGTH         */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Global per-block unit budget for the envelope lane — JUDGMENT
 *  constant sized so placeholder-weight envelopes (Dilithium5-scale
 *  auth blobs at w_authbyte 1) fit comfortably; the consensus value is
 *  OPEN until the devnet reset pins real economics. Never a price: it
 *  bounds what a block may reserve, the policy alone prices. */
#define NODUS_V2_GLOBAL_UNIT_BUDGET  1000000u

/**
 * Bound on the engine's refusal-reason string (`nodus_v2_block_t
 * .out_reason`), NUL included. 256 is the size the witness layer already
 * uses for the same job — nodus_witness.h:236 `char reason[256]` and the
 * `char *reject_reason, size_t reason_size` pair at
 * nodus_witness_verify.h:125 — so one convention governs both.
 */
#define NODUS_V2_APPLY_REASON_MAX 256

/**
 * The canonical epoch of a global block height — GLOBAL BLOCK COUNT
 * divided by the compile-time epoch length, the SAME convention the
 * shipped consensus surfaces use (leader election
 * nodus_witness_bft.c:492 `epoch = next_bh / DNAC_EPOCH_LENGTH`; epoch
 * start = floor multiple, boundary at height % LEN == 0 — genesis
 * height 0 is epoch 0, the first boundary is DNAC_EPOCH_LENGTH itself).
 * No clock, no timestamp, no domain_height enters this function — a
 * machine's clock cannot move its epoch. (The ledger_entries surface
 * carries a DIVERGENT legacy convention, (h-1)/LEN at
 * nodus_witness_db.c:369-370; it is NOT adopted here and unifying it is
 * that surface's own migration.)
 */
static inline uint64_t nodus_v2_epoch_for_height(uint64_t global_height) {
    return global_height / (uint64_t)DNAC_EPOCH_LENGTH;
}

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
    V2AP_FAIL_AFTER_CLAIM_STATE = 18,   /* remaining decremented         */
    /* S7 pool stages (fire after the named stage of the pool batch at
     * index blk->fail_pool_index; S1-S6 ids above are FROZEN) */
    V2AP_FAIL_AFTER_POOL_COMMITS = 19,  /* v2_pool_notes rows inserted   */
    V2AP_FAIL_AFTER_POOL_FRONTIER = 20, /* frontier/root/count updated   */
    V2AP_FAIL_AFTER_POOL_NULLS = 21,    /* nullifier rows inserted       */
    V2AP_FAIL_AFTER_POOL_NULROOT = 22,  /* nullifier root/count updated  */
    V2AP_FAIL_AFTER_POOL_BALANCE = 23,  /* pool balance updated          */
    V2AP_FAIL_AFTER_POOL_HISTORY = 24,  /* history entry appended        */
    V2AP_FAIL_AFTER_POOL_EVICT = 25,    /* oldest history entry evicted  */
    /* Execution-season stages (S1-S7 ids above are FROZEN) */
    V2AP_FAIL_AFTER_ENV_RESERVE = 26,   /* whole batch preflighted +
                                         * reserved (pre-BEGIN; proves
                                         * meter abort + budget restore) */
    V2AP_FAIL_AFTER_ENV_EXEC = 27,      /* the envelope at
                                         * blk->fail_env_index fully
                                         * executed + finalized          */
    /* Native-auth-season stages (26/27 above are FROZEN). 28 fires
     * pre-BEGIN after the WHOLE batch's authorization verdicts were
     * verified; 29-33 fire INSIDE the transaction after the named
     * per-leg stage of the envelope at blk->fail_env_index. */
    V2AP_FAIL_AFTER_AUTH = 28,          /* all auth verdicts verified    */
    V2AP_FAIL_AFTER_READ_PLAN = 29,     /* read plan emitted + validated */
    V2AP_FAIL_AFTER_READS = 30,         /* mediated reads done + charged */
    V2AP_FAIL_AFTER_EXEC_HOOK = 31,     /* native exec returned          */
    V2AP_FAIL_AFTER_EFFECT_DECODE = 32, /* strict result decode done     */
    V2AP_FAIL_AFTER_EFFECT_CHARGE = 33, /* effect charge done            */
    /* Capacity-season stage (28-33 above are FROZEN). Fires pre-BEGIN
     * after the governing committee snapshot was resolved, hashed and
     * fixed into the engine-owned view — proves that a block failing
     * right after snapshot resolution leaves the database digest, the
     * unit budget and every index byte-identical. */
    V2AP_FAIL_AFTER_CC_SNAPSHOT = 34,
    /* Intent-season stages (34 above is FROZEN). 35 fires pre-BEGIN
     * after the committed-identity replay guard passed (both identities
     * of every envelope checked against v2_intent_index / v2_tx_index)
     * — proves the guard's rejection path releases the batch
     * reservation and restores the budget byte-identically. 36 fires
     * INSIDE the transaction after the v2_intent_index rows were
     * inserted and BEFORE the wire indices — proves an interrupted
     * block commits NEITHER identity index. */
    V2AP_FAIL_AFTER_INTENT_GUARD = 35,
    V2AP_FAIL_AFTER_INTENT_INDEX = 36,
    /* Burn-season stage (35/36 above are FROZEN). Fires INSIDE the
     * transaction after the adapter APPLIED the effect at index
     * blk->fail_effect_index of a leg of the envelope at
     * blk->fail_env_index (the first leg with that many effects) —
     * mid-effect-list injection, so a block interrupted BETWEEN a leg's
     * mutations (after the UTXO deletes but before the burned-counter
     * SET, after the token-registry insert but before the fee burn, …)
     * provably leaves the database digest byte-identical. */
    V2AP_FAIL_AFTER_EFFECT_APPLY = 37,
    /* O11 stake-lifecycle stage (37 above is FROZEN). Fires INSIDE the
     * transaction after the leg at blk->fail_leg_index of the envelope
     * at blk->fail_env_index has FULLY applied its effects and BEFORE
     * the next leg of the same envelope runs. Where F37 interrupts one
     * leg MID-mutation, this interrupts BETWEEN legs — the
     * HALF-ENVELOPE point that only exists for a cross-domain envelope.
     * A staking envelope injected at leg 0 has written its SYSTEM
     * record rows (validator / delegation / counter) and has NOT yet
     * consumed the CORE funding inputs; the proof obligation is that
     * neither half survives: a validator row without its bond, or a
     * spent input without its record, would be a torn cross-domain
     * transition. */
    V2AP_FAIL_AFTER_LEG_APPLY = 38,
    /* O12 S2 epoch-boundary stages (38 above is FROZEN). All seven fire
     * INSIDE the transaction, from the boundary module's stage callback
     * (nodus_witness_v2_epoch.h nodus_v2_epoch_stage_t) — the module owns
     * the stages, this enum owns the numbering, exactly as F19-F25 map
     * the S7 pool stages. They only ever fire on a block whose height IS
     * an epoch boundary; on any other height the boundary is a no-op and
     * none of them is reachable.
     *
     * F40/F41 fire on the FIRST graduate (candidate index 0) — the
     * boundary allocates no per-graduate index field on the block because
     * its write order is fixed by the ORDER BY pubkey ASC candidate scan
     * and the first graduate is the point where an interrupt can leave a
     * release UTXO without its record transition.
     *
     * F44/F45 straddle the next-epoch snapshot: F44 fires with every
     * build INPUT final and NOTHING built or persisted, F45 after the
     * source function built AND persisted it (the source builds and
     * persists atomically — the honest label is in
     * nodus_witness_v2_epoch.h). */
    V2AP_FAIL_AFTER_EPOCH_COMMISSIONS  = 39, /* pending commissions in   */
    V2AP_FAIL_AFTER_FIRST_GRAD_RELEASE = 40, /* graduate 0 release UTXO  */
    V2AP_FAIL_AFTER_FIRST_GRAD_APPLIED = 41, /* graduate 0 row + counter */
    V2AP_FAIL_AFTER_GRAD_BATCH         = 42, /* every graduate applied   */
    V2AP_FAIL_AFTER_BOUNDARY_FLIPS     = 43, /* membership flips applied */
    V2AP_FAIL_AFTER_SNAPSHOT_BUILD     = 44, /* build inputs final       */
    V2AP_FAIL_AFTER_SNAPSHOT_PERSIST   = 45, /* snapshot row written     */

    /* O14 — the identity seam inside phase 13. F46 fires with the
     * canonical header v3 fully reconstructed from locally derived
     * results and NOTHING hashed or written; F47 after the final
     * BlockID has been recomputed and checked against the caller's
     * assertion, still before the v2_blocks row exists. Together they
     * bracket the exact window in which an interrupt could otherwise
     * leave a persisted id that no execution result produced. */
    V2AP_FAIL_AFTER_HEADER_BUILD       = 46, /* header bytes final       */
    V2AP_FAIL_AFTER_BLOCK_ID           = 47, /* BlockID recomputed       */

    /* O15E Faz B — fires with every canonical envelope byte record of
     * the block written (phase 12b, S11 schema) and nothing of phase 13
     * (roots/header/identity/metadata) started. Brackets the envelope
     * persist so an interrupt can never leave byte rows for a block
     * that was not committed, or a committed block missing its bytes. */
    V2AP_FAIL_AFTER_ENV_BYTES          = 48, /* envelope bytes persisted */

    /* O15F Task 4 — fires with every canonical claim byte record of the
     * block written (phase 12c, S12 schema) and nothing of phase 13
     * (roots/header/identity/metadata) started. Brackets the claim-bytes
     * persist so an interrupt can never leave claim rows for a block that
     * was not committed, or a committed block missing its claim bytes.
     * The count row and the claim rows are one transaction with the
     * block, so both roll back together. */
    V2AP_FAIL_AFTER_CLAIM_BYTES        = 49, /* claim bytes persisted    */

    /* O15J Faz 2 — the economics hooks. APPENDED; 39-49 are pinned by
     * shipped tests and are never renumbered.
     *
     * 50 fires with every settlement payout UTXO written and NOTHING
     * burned or retired: the proof obligation is that an interrupt there
     * leaves no payout row AND no supply movement. 51 fires with the
     * burn recorded and the settled epoch row retired, one step before
     * Rule N — the second rollback window. 52 brackets the per-block
     * mint: total_minted and epoch_pool_accum move together or not at
     * all, which is the conservation equation's own precondition. */
    V2AP_FAIL_AFTER_SETTLE_EMITTED     = 50, /* payout UTXOs written     */
    V2AP_FAIL_AFTER_SETTLE_APPLIED     = 51, /* burn + epoch row retired */
    V2AP_FAIL_AFTER_EMISSION           = 52  /* per-block mint accrued   */
} nodus_v2_apply_fail_t;

/*
 * The caller-shaped raw-SQL operation type (nodus_v2_op_t: tx_id / sql /
 * verify_cost) is RETIRED. A block carries nodus_v2_envelope_t — bytes
 * and length, NOTHING else: no identity field, no SQL, no cost, no
 * touched list. Identity is DERIVED, the touched set is the leg list,
 * and the price comes from the frozen policy snapshot.
 */

/**
 * One V2 global block for the engine.
 *
 * ── O14: THE ENGINE OWNS THE BLOCK IDENTITY ───────────────────────────
 * There is NO caller-supplied `block_id`, `prev_block_id` or `vset_hash`
 * input any more. The engine DERIVES every canonical header-v3 field and
 * computes the BlockID it persists; a caller may only ASSERT what it
 * expects, through the `expect_*` pointers, and a mismatch rejects the
 * block BEFORE commit. No field has two authoritative producers.
 *
 * Field authority classification (prompt §9):
 *   header_version      fixed protocol value  (DNA_BH2_VERSION)
 *   chain_id            committed pre-state   (nodus_witness_v2_chain_id)
 *   block_height        block input           (global_height)
 *   epoch               committed pre-state   (nodus_v2_epoch_for_height,
 *                                              VERIFIED against `epoch`)
 *   prev_block_id       committed pre-state   (the previous v2_blocks row)
 *   global_state_root   execution             (out_global_root)
 *   tx_root             execution             (out_tx_root)
 *   domain_updates_root execution             (out_dupd_root)
 *   validator_set_hash  committed pre-state   (the block-start authority
 *                                              snapshot, re-hashed here)
 *   tx_count            execution             (the derived batch size)
 *   proposer_id         block input           (below)
 *   timestamp           block input           (below; EXCLUDED from the
 *                                              BlockID — PR2 discipline)
 *
 * The only two header fields a caller still supplies are the two the
 * engine cannot possibly derive: `proposer_id` and `timestamp`.
 */
typedef struct {
    uint64_t global_height;
    uint64_t epoch;                     /* MUST equal
                                         * nodus_v2_epoch_for_height(
                                         *   global_height) — verified,
                                         * never trusted               */
    /* ── Header material the engine CANNOT derive ─────────────────── */
    uint8_t  proposer_id[32];
    uint64_t timestamp;                 /* informational; NOT in BlockID */

    /* ── Equality ASSERTIONS — never authority. NULL = derive only.
     * A non-NULL pointer that disagrees with the locally derived result
     * REJECTS the block before any commit (the follower/verification
     * mode; NULL throughout is leader/derivation mode). */
    const uint8_t *expect_prev_block_id;
    const uint8_t *expect_vset_hash;
    const uint8_t *expect_block_id;
    /* ── HOW THE THREE CONTENT CHANNELS REACH THE BLOCK IDENTITY ──────
     * O15A §10 mapped this, because the three below are NOT bound the
     * same way and a reader could easily assume they are:
     *
     *   envs      DOUBLY bound — `tx_root` is built from envelope
     *             wire_ids, so the exact canonical bytes are committed
     *             in the header directly, AND their effects move the
     *             state roots.
     *   claims    bound TRANSITIVELY ONLY. A claim's canonical semantic
     *             identity is its nullifier (DNA.CLNUL.v1 over chain,
     *             manifest hash, target domain, target asset and leaf —
     *             all committed values), and claims_root is a leg of the
     *             target domain's state root. Claims are not
     *             transactions and never enter tx_root.
     *   pool_muts bound TRANSITIVELY ONLY, through pools_root.
     *
     * The consequence, stated so it is not rediscovered as a surprise:
     * changing any CONSENSUS-RELEVANT claim or pool field changes a root
     * and therefore the BlockID, but two different AUTHORIZATION
     * WITNESSES for the same claim produce the same identity. That is the
     * intent-season property (consensus state binds intent, not witness)
     * applied to claims, not an oversight — and the substitute witness
     * must still verify, so nothing unauthorized becomes acceptable.
     * Reconstructing the claim/pool INPUT bytes from committed state is a
     * sync concern and is deliberately out of scope here.
     *
     * Included envelopes, in canonical batch order (the order IS the
     * intra-phase execution and index order). NULL/0 = none. */
    const nodus_v2_envelope_t *envs;
    size_t   n_envs;
    /* S6 generic claims (routed to each claim's COMMITTED target
     * runtime; processed INSIDE the one block transaction, phase 6b).
     * NULL/0 = none. */
    const dna_claim_t *claims;
    size_t   n_claims;
    /* S7 pool-state batches (INACTIVE test/fixture surface; processed
     * INSIDE the one block transaction, phase 6p; strictly ascending
     * (domain_id, pool_id) — duplicates reject). NULL/0 = none. */
    const nodus_v2_pool_mut_t *pool_muts;
    size_t   n_pool_muts;
    /* Follower-mode expected roots — any NULL = leader mode (fill). A
     * non-NULL expectation that mismatches the recomputation rejects the
     * whole block. */
    const uint8_t *expect_tx_root;
    const uint8_t *expect_dupd_root;
    const uint8_t *expect_domains_root;
    const uint8_t *expect_global_root;
    /* OPTIONAL opaque finalization certificate (the encoded QC V2), bound
     * into the SAME v2_blocks INSERT as the block it certifies. The
     * engine does not parse or verify it — verification is the caller's
     * (nodus_witness_v2_finalize.c), which runs it BEFORE any durable
     * mutation. Carrying it here rather than writing it afterwards is
     * what keeps "commit once" true: there is no window in which a
     * committed block lacks its certificate. NULL/0 = store SQL NULL. */
    const uint8_t *qc_bytes;
    size_t   qc_len;
    /* Fault injection */
    nodus_v2_apply_fail_t fail_at;
    uint32_t fail_domain_batch;         /* domain_id for point 4         */
    uint32_t fail_claim_index;          /* claim index for points 16-18  */
    uint32_t fail_pool_index;           /* batch index for points 19-25  */
    uint32_t fail_env_index;            /* envelope index for point 27   */
    uint32_t fail_effect_index;         /* effect index for point 37     */
    uint32_t fail_leg_index;            /* leg index for point 38        */
    /* ── Outputs ───────────────────────────────────────────────────────
     * Roots/header/identity are valid on rc 0/2 (committed). On rc 1
     * (idempotent replay) `out_block_id`, `out_prev_block_id` and
     * `out_header` are served from the ALREADY-COMMITTED row, so a
     * caller can still compare the certified id against the stored one
     * without the engine re-executing anything. */
    uint8_t  out_tx_root[64];
    uint8_t  out_dupd_root[64];
    uint8_t  out_domains_root[64];
    uint8_t  out_global_root[64];
    uint8_t  out_prev_block_id[64];
    uint8_t  out_vset_hash[64];
    /* The canonical 413-byte header v3 the engine built from LOCALLY
     * DERIVED results, and the BlockID over its 405 bound bytes. This
     * id — never an input byte — is what `v2_blocks.block_id` stores. */
    uint8_t  out_header[DNA_BH2_ENC_SIZE];
    uint8_t  out_block_id[DNA_BH2_ID_LEN];
    /* ── WHY the engine refused (DIAGNOSTIC ONLY) ──────────────────────
     * NUL-terminated ASCII, written by the exact site that refused, so
     * an operator reading a log can tell WHICH check failed instead of
     * only that one did. Cleared at entry; non-empty on EVERY refusal
     * class (-1 / -2 / -3), empty on rc 0/1/2 — a caller that sees an
     * empty string on a refusal is looking at a path that could not name
     * itself, not at a missing failure.
     *
     * The first token is the CLASS, and it is emitted by the exit macro
     * itself, never chosen per site, so it cannot drift from the return
     * code:
     *   "VERDICT: " -1  a deterministic judgement about the block
     *   "FAULT: "   -2  THIS NODE could not compute — never a judgement
     *   "DEFER: "   -3  not evaluable here yet — never a judgement
     * A fault and a verdict therefore never read alike, which is the
     * whole point: an operator (and a log grep) must not be able to
     * mistake "my node is broken" for "the proposer is lying".
     *
     * NOT CONSENSUS MATERIAL, and the engine enforces that by
     * construction: this field is never hashed, never persisted, never
     * placed on the wire, never entered into any root, header or
     * preimage, and never read back by the engine — the ONE read is the
     * `[0] == '\0'` empty test at the exit labels, which selects a
     * fallback STRING and cannot change a return code or a branch that
     * leads to one. Two nodes may legitimately print different text for
     * the same block (a fault reason is local by definition); no node's
     * verdict depends on any of it.
     *
     * ASCII and bounded by construction: every format string is an
     * engine literal, and every substitution is an integer, a hex
     * rendering the engine derived, or another literal the ENGINE picked
     * (a ternary between two fixed phrases, or a stringified
     * fault-point name). No block-carried, peer-carried or
     * runtime-carried TEXT is ever interpolated, so nothing an attacker
     * controls can reach a log line as characters. Truncation at
     * NODUS_V2_APPLY_REASON_MAX-1 is silent and harmless. */
    char     out_reason[NODUS_V2_APPLY_REASON_MAX];
} nodus_v2_block_t;

/** V2 supply-conservation gate (header equation). @return 0 / -1. */
int nodus_witness_v2_supply_check(nodus_witness_t *w);

/**
 * V2 genesis: requires schema version 8; one atomic transaction seeding
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
                             uint64_t epoch);   /* MUST be 0: genesis is
                                                 * height 0 and the epoch
                                                 * is DERIVED (0/LEN == 0)
                                                 * — any other value is
                                                 * rejected              */

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
 *
 * On every refusal the engine also fills `blk->out_reason` with the
 * class-tagged text of the site that refused — see the field's contract
 * in nodus_v2_block_t. It is DIAGNOSTIC ONLY and changes no verdict: the
 * return codes below are exactly what they were before the reason
 * existed. The signature is deliberately unchanged so that every
 * existing caller (nodus_witness_v2_finalize.c:171 and the V2 test
 * suites) keeps compiling and gets the reason for free in the block it
 * already owns.
 *
 * @return 0 committed; 1 idempotent replay (no writes); 2 committed but
 *         the post-commit/pre-cache crash window fired (state IS
 *         committed; restart reconstructs it); -1 CONSENSUS-VERDICT
 *         rejection, rolled back; -2 NODE-LOCAL FAULT, rolled back —
 *         this node could not compute; a consensus caller fails its own
 *         operation (does not vote) and never converts -2 into a
 *         rejection (FAULT vs VERDICT block above).
 */
int nodus_witness_v2_apply_block(nodus_witness_t *w, nodus_v2_block_t *blk);

/**
 * ENGINE-INTERNAL, exposed for direct test: find `wire_id` (the
 * FULL-WIRE identity) in a domain's per-block ordered id list. A MISS
 * FAILS CLOSED (-1, *lidx_out untouched) — it must NEVER alias local
 * index 0: the pre-execution-season code defaulted a miss to lidx = 0
 * silently (nodus_witness_v2_env.h documented it as the migration
 * hazard), and this helper is the one place the answer is computed.
 * @return 0 with *lidx_out set / -1.
 */
int nodus_witness_v2_local_index_find(const uint8_t ids[][64], uint32_t n,
                                      const uint8_t wire_id[64],
                                      uint32_t *lidx_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_APPLY_H */
