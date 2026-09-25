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
 *   domain/global roots → persistence, inside the HOST's transaction.
 *
 * There is NO second execution path and NO raw-SQL fallback inside this
 * engine boundary: no V2 request, runtime result or effect can carry
 * SQL text, a table name, a schema string, an SQLite handle or a
 * callback address — the envelope and effect codecs cannot represent
 * them. The only SQL in this file is the ENGINE'S OWN persistence
 * (heads/updates/history/indices/metadata and the per-item SAVEPOINTs),
 * compiled into the engine, never accepted from a caller or a runtime.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── ONE LANE: THE COMETBFT LANE (tokenomics-v3 P4) ────────────────────
 * The engine applies DECIDED cometbft blocks only (`blk->cmt.on`); the
 * legacy block lane — the engine owning its own BEGIN IMMEDIATE / COMMIT
 * / ROLLBACK, a whole-batch all-or-nothing verdict, the rc 1 idempotent
 * replay, the rc 2 post-commit window, a derived dna_bh2 identity and
 * schema S9-S12 — is DELETED (OBLIGATION atlas-dec-71525f3b). The HOST
 * owns the one transaction (D-23 rev 5 (5)): it opens it before
 * FinalizeBlock and closes it at Commit; the engine joins it, never
 * commits or rolls back, and returns with it OPEN. Each item runs in its
 * own SAVEPOINT inside it. The full lane contract is at
 * nodus_v2_block_cmt_t and nodus_witness_v2_apply_block below. Phase
 * order (the fault points in brackets):
 *
 *   entry: schema S16, a host transaction open, the result array sized,
 *       no identity assertion (expect_*), blk->epoch == the derivation
 *   0.  linkage against v2_blocks (read-only): height 0 refused, a gap
 *       ahead deferred (-3), a height at or below the head refused, the
 *       parent row read (64 zero bytes for the chain's first block)
 *   0a. FROZEN BLOCK-START EXECUTION SNAPSHOT (read-only):
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
 *   0b. the item working set (heap)                       [F1 after it]
 *   2.  supply gate (pre-apply)
 *   4-6b. THE ITEMS, in the block's order — envelopes, then claims —
 *       each in its own SAVEPOINT; an item-attributable refusal rolls
 *       its savepoint back and records a nonzero nodus_v2_tx_code_t, the
 *       block continues. Per envelope: the contextual ruleset table
 *       (CONTEXT) → dna_env_preflight (DECODE / CONTEXT) → the
 *       COMMITTED-IDENTITY REPLAY GUARD, intent_id then wire_id against
 *       v2_intent_index / v2_tx_index, which also see this block's
 *       earlier items (REPLAY) → per-leg admission: block-entry ACTIVE
 *       domain with exec + auth hooks, INVOKE access (READ legs refused
 *       this season), runtime_op OWNED by the committed ruleset, the
 *       runtime's auth-kind allowlist (ADMISSION), the manifest's
 *       per-domain tx quota (CAPACITY) → meter reserve (CAPACITY) →
 *       verified authorization (AUTH) → exec: meter activate → per leg
 *       mediated read plan [F29] + engine-charged reads [F30] → native
 *       exec [F31] → strict result decode [F32] → effect charge [F33] →
 *       adapter application [F37 mid-effect-list, F38 BETWEEN legs] →
 *       meter finalize (EXEC) → the item's identity index rows. A block
 *       carrying pool batches is a node FAULT (a block message cannot
 *       express one). Per claim: derivation, in-block duplicate,
 *       target-domain check, then admit (committed manifest names the
 *       TARGET domain + asset) → target-runtime output [F16] →
 *       spent-claim insert [F17] → distribution-state decrement [F18],
 *       on claim `fail_claim_index` (CLAIM).
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
 *   6d. attendance credit (decided_last_commit, out of every root)
 *   6e. the epoch boundary (a no-op off a boundary height)
 *                                     [F39-F45, F53-F60, boundary only]
 *   6f. the econ band's build-identity check
 *   7.  supply gate (post-stage)                          [F6 "supply"]
 *   8.  domain state roots — dispatched through each REGISTERED
 *       runtime's state_root hook — + the UNTOUCHED-DOMAIN GUARD:
 *       an untouched domain's recomputed root MUST equal its persisted
 *       head root — an op that mutated a domain it did not declare
 *       (cross-domain substitution) refuses the whole block  [F7]
 *   9.  DomainUpdate build + verify + persist (touched only)  [F8]
 *   10. DomainHead write                                   [F9]
 *   11. root history append                                [F10]
 *   12. the APPLIED items' v2_tx_local_index rows (their identity rows
 *       were written inside each item's savepoint)         [F11]
 *   12c. the claim count + canonical claim bytes           [F49]
 *   13. tx_root (APPLIED items) + domain_updates_root + domains_root +
 *       global root; compare every caller-expected root; the v2_blocks
 *       row: consensus's block hash + Comet ValidatorsHash verbatim  [F12]
 *   14. supply gate (pre-commit)                           [F13]
 *   15. return 0 with the host's transaction OPEN.
 *
 * Any BLOCK-level failure is returned to the host, which rolls back
 * EVERYTHING (UTXOs, supply counters, registry, updates, heads, history,
 * indices, metadata) — the tests prove it by byte-comparing table dumps
 * and roots, not by return codes. There are no authoritative V2
 * in-memory caches to un-publish; the reconstruct-on-restart path is the
 * table state itself. The IN-MEMORY meter/budget state rolls back too:
 * an item refusal aborts that item's meter, which restores the block
 * budget byte-identically, and a block failure aborts every non-terminal
 * meter — no reservation is ever stranded.
 *
 * ── FAULT vs VERDICT vs DEFERRAL ──────────────────────────────────────
 * The named values are nodus_v2_result_t (nodus_witness_v2_result.h).
 * Inside the body a refusal site is still labelled by its class —
 * VERDICT (-1, a deterministic function of committed state and block
 * bytes), FAULT (-2, this node could not compute) or DEFERRAL (-3, a
 * height AHEAD of this node's head: the predecessor state is absent and
 * nothing was judged) — and the reason text names it. But a DECIDED
 * block is never refused: nodus_witness_v2_apply_block folds every
 * negative return into -2 INTERNAL_FAULT (see its contract), and the
 * host rolls the block back and stops. Item-level verdicts never travel
 * as a return code; they live in `blk->cmt.results[i].code`.
 *
 * CONSERVATIVE CLASSIFICATION SEAM: nodus_witness_v2_runtime_for
 * conflates "tuple not carried by this build" with a node-local domreg
 * read fault (one -1). Everywhere the engine re-resolves a runtime
 * INSIDE the block (the 6c lifecycle re-scan, the phase-8 root pass) a
 * NULL result is therefore classified -2 — the SAFE direction: the
 * deterministic unsupported-tuple case also reads as "do not vote"
 * rather than risking one starved witness voting reject. The
 * deterministic answers about resolvability live in the strict block-
 * start doms_load and the per-item admission checks.
 *
 * ── HONEST LABELS (what this engine still does NOT do) ────────────────
 *   (DRIFT REPAIR, intent season: the former "authorization stays with a
 *   later season" label was stale — the native-auth season shipped the
 *   verified boundary. Authorization is verified per item into the
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
 * ── Replay ────────────────────────────────────────────────────────────
 *   BLOCK-LEVEL: a height at or below the committed head, or a block
 *     hash already committed at another height → refused (a node FAULT
 *     after the fold: the host never hands a decided height twice). The
 *     legacy lane's rc-1 idempotent replay is deleted (tokenomics-v3 P4).
 *   ITEM-LEVEL (intent season): an envelope whose intent_id is already
 *     committed — or applied earlier in this block — is refused REPLAY
 *     (semantic replay, including under a DIFFERENT valid authorization
 *     witness, in ANY later block); likewise its wire_id (the intent
 *     guard subsumes this for byte-identical envelopes; the wire check
 *     is the independent second leg); both backstopped by the
 *     v2_intent_index / v2_tx_index UNIQUE constraints.
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
 * another. Checked u64 arithmetic throughout. Global cap:
 * NODUS_V2_GLOBAL_UNIT_BUDGET (a CONSENSUS value, 2 097 152 since the
 * operator's 2026-09-24 decision — docs/plans/decisions/
 * 2026-09-24-block-capacity-trial-b.md; the chain-config
 * MAX_TXS_PER_BLOCK count cap was RETIRED 2026-09-18, W4-C delta 2);
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
 *     Σ delegated + reward_pool + Σ accrued + unclaimed CORE-NATIVE
 *     distribution + shielded — tokenomics-v3 P2 replaced the
 *     epoch_pool term with the reward pool and the per-recipient
 *     accrual), including a fail-closed guard that no foreign
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
#include "dnac/manifest_wire.h"             /* DNA_CLAIM_FIXED_LEN       */
#include "dnac/block_v2.h"                  /* O14: the engine OWNS the
                                             * canonical header v3 and
                                             * the BlockID it persists   */
#include "dnac/dnac.h"                      /* DNAC_EPOCH_LENGTH         */
#include "dnac/cmt_params.h"                /* CMT_MAX_BLOCK_SIZE_BYTES  */
#include "dnac/effect_wire.h"               /* DNA_EFFECT_MAX_KEY_LEN    */
#include "witness/nodus_witness_runtime.h"  /* nodus_rt_auth_verdict_t   */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Global per-block unit budget for the envelope lane. OPERATOR
 *  DECISION 2026-09-24 (block capacity trial B, measured 15.91 TPS vs
 *  7.55 at 1 000 000 on the same machine, then made permanent —
 *  docs/plans/decisions/2026-09-24-block-capacity-trial-b.md; was
 *  1 000 000, a JUDGMENT constant): 2 097 152 = the policy's per-block
 *  envelope BYTE bound, max_block_env_bytes = 2 x DNA_ENV_MAX_TOTAL_LEN
 *  = 2 MiB (nodus_witness_runtime.c sys_policy_build). Every metering
 *  weight is 1 (same function), so one unit is roughly one envelope
 *  byte and the two per-block bounds sit at the same place. Consensus
 *  value: changing it is a devnet wipe + stop-all deploy. Kept a plain
 *  literal (bench_tps_v2.sh reads it from this line). Never a price: it
 *  bounds what a block may reserve, the policy alone prices. */
#define NODUS_V2_GLOBAL_UNIT_BUDGET  2097152u

/**
 * R3 W4-C delta 2 (operator "kaldır" 2026-09-18;
 * atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1) — THE ENGINE'S
 * PER-BLOCK ENVELOPE-SCRATCH ALLOCATION BUDGET.
 *
 * The chain-config governance parameter that used to bound envelopes
 * per block (`MAX_TXS_PER_BLOCK`, id 1) is RETIRED — the operator's
 * ruling is that a block's capacity is bytes and units only, matching
 * the pinned reference (cometbft @709fd12b bounds blocks by
 * `Block.MaxBytes` alone, no transaction-count parameter). This engine
 * still needs SOME ceiling on how many envelopes' worth of per-block
 * scratch it will allocate in one call (`pf`/`meters`, sized by
 * `blk->n_envs` since R3 W4-C delta 1; the legacy lane's `env_phase` /
 * `auth_off` went with it, tokenomics-v3 P4)
 * — a RELEASE RESOURCE CHOICE, the same kind of number as the W3
 * receive arena's 64 MiB (nodus_witness_cmt_net.h) — not a consensus
 * parameter, never governed, never voted. 64 MiB. (Unlike
 * `NODUS_V2_GLOBAL_UNIT_BUDGET` above, which decides which blocks are
 * valid and IS a consensus value — an earlier version of this comment
 * put the two in one class.) */
#define NODUS_V2_APPLY_SCRATCH_BUDGET_BYTES \
    ((size_t)64u * 1024u * 1024u)

/**
 * THE ENGINE'S OWN MEMORY COST OF ONE ENVELOPE'S PER-BLOCK SCRATCH.
 *
 * Three components, each sized by `sizeof()` (the compiler's own
 * measurement, never a hardcoded guess), plus the wire-id bytes a
 * touched domain's `wire_ids` entry costs:
 *   - `dna_env_preflight_t` — ONE per envelope (`pf[i]`). MEASURED on
 *     this build (env_preflight.h:159-161, `test_env_preflight`'s own
 *     printed figure): 15 096 B.
 *   - `dna_meter_t` — ONE per envelope (`meters[i]`). AUDITED ceiling
 *     `sizeof(dna_meter_t) <= 4096` (res_meter.h:437-438); no build ran
 *     in this session to print the exact figure, so `sizeof()` is used
 *     directly here rather than a guessed literal — whatever the real
 *     compiled size is, it is what this macro adds.
 *   - `nodus_rt_auth_verdict_t` — one per REAL leg, but this is a
 *     compile-time COST BOUND, which cannot see a block's real leg
 *     counts. Priced for TWO legs — the largest shape any shipped
 *     runtime op produces today: every cross-domain op in
 *     `nodus_witness_rt_native.c` hard-refuses any leg_count other than
 *     2 for its cross-domain forms (e.g. `if (env->leg_count != 2 ||
 *     leg_index != 0) return -1;` and the SYSFUND sibling's
 *     `leg_index != 1` twin, nodus_witness_rt_native.c) — there is no
 *     third registered domain today, so no shipped op can address more
 *     than 2. A future 64-leg envelope (env_wire.h's own DNA_ENV_MAX_LEGS
 *     ceiling) would cost more scratch than this bound prices, but
 *     cannot exist while only SYSTEM and CORE are registered; the
 *     `_Static_assert` below is the trip-wire if that ever changes
 *     without this cost formula being revisited. Computed from the
 *     struct layout (`nodus_witness_runtime.h:250`'s own
 *     `NODUS_RT_AUTH_MAX_SIGNERS` = 15 — not env_wire.h):
 *     2 + 15×64 + 2 + 2 = 966 B exactly (no padding — every member is
 *     `uint16_t`/`uint8_t`, naturally 2-aligned, and 966 is already
 *     even).
 *   - 2 × 64 B — the `wire_ids` entry each of those (up to) two touched
 *     domains gets (`nodus_witness_v2_apply.c`'s `dom_ctx_t.wire_ids`,
 *     delta 1: heap, lazily allocated, 64 B per touched domain).
 */
#define NODUS_V2_APPLY_ENV_COST_BYTES \
    (sizeof(dna_env_preflight_t) + sizeof(dna_meter_t) + \
     2u * sizeof(nodus_rt_auth_verdict_t) + 2u * 64u)

/**
 * Largest ENVELOPE batch the engine will allocate per-block scratch
 * for, derived: `NODUS_V2_APPLY_SCRATCH_BUDGET_BYTES /
 * NODUS_V2_APPLY_ENV_COST_BYTES` (integer division floors, the SAFE
 * direction — it under-counts, never over-counts, how many envelopes'
 * worth of scratch 64 MiB actually buys).
 *
 * PROVABLY ABOVE what the surviving bounds allow for AUTHORIZABLE
 * envelopes in practice (the operator's decision's own requirement),
 * verified by the two `_Static_assert`s below rather than asserted by
 * fiat:
 *   - The smallest AUTHORIZABLE envelope (one that could actually pass
 *     the auth boundary, not merely decode) is `DNA_ENV_FIXED_HEAD` +
 *     `DNA_ENV_LEG_HDR_LEN` (43 + 30 = 73 B, env_wire.h:198-199) + a
 *     real call payload (>= 41 B, the smallest shipped op's own call
 *     encoding) + a kind-1 (single-signer ML-DSA-87) auth blob (1 +
 *     `DNA_CLAIM_PUBKEY_LEN` 2592 + `DNA_CLAIM_SIG_LEN` 4627 = 7220 B,
 *     manifest_wire.h:283-284) = 7 334 B.
 *   - At this chain's own configured genesis `Block.MaxBytes` (22 020
 *     096, D-4 rev 3's default — nodus_witness_cmt_app.c cites the same
 *     figure), the most such envelopes ANY block could carry is
 *     22 020 096 / 7 334 = 3 002 (floor) — a byte-derived ceiling no
 *     block will ever exceed regardless of this engine's own bound.
 *   - Using ONLY the documented, already-`_Static_assert`-enforced
 *     ceilings (`dna_env_preflight_t` MEASURED 15 096 B, `dna_meter_t`
 *     audited <= 4096 B), the WORST-CASE per-envelope cost is 15 096 +
 *     4 096 + 2x966 + 128 = 21 252 B, giving a WORST-CASE
 *     `NODUS_V2_ENV_BATCH_MAX` of 67 108 864 / 21 252 = 3 157 — already
 *     above the 3 002 byte-derived practical ceiling. The REAL compiled
 *     value (using the true, possibly-smaller `sizeof(dna_meter_t)`)
 *     can only be EQUAL OR LARGER, so it is provably above 3 002 too.
 *   - MEASURED (ORCHESTRATOR build, 2026-09-18): `sizeof(dna_meter_t)`
 *     = 3 752, so the cost is 20 908 B and this bound is 3 209 — the
 *     pins below hold exactly these figures.
 */
#define NODUS_V2_ENV_BATCH_MAX \
    (NODUS_V2_APPLY_SCRATCH_BUDGET_BYTES / NODUS_V2_APPLY_ENV_COST_BYTES)

_Static_assert(NODUS_V2_APPLY_ENV_COST_BYTES <= 32768,
               "NODUS_V2_APPLY_ENV_COST_BYTES exceeded the 32 KiB working "
               "ceiling this header's arithmetic assumed — re-derive "
               "NODUS_V2_ENV_BATCH_MAX's worst-case margin over the "
               "3 002-envelope byte-derived practical ceiling");
_Static_assert(NODUS_V2_ENV_BATCH_MAX > 3002,
               "NODUS_V2_ENV_BATCH_MAX must stay ABOVE the byte-derived "
               "practical ceiling (this chain's default Block.MaxBytes "
               "22020096 / the smallest authorizable envelope 7334 B = "
               "3002) — the operator's decision requires this bound to "
               "never decide a block's validity in practice; if this "
               "fires, NODUS_V2_APPLY_SCRATCH_BUDGET_BYTES needs raising");

/**
 * R3 W4 package C (ORCHESTRATOR, 2026-09-18) — THE MOST CLAIMS ANY
 * COMETBFT BLOCK CAN CARRY, derived.
 *
 * A claim is not chain-config-metered (MAX_TXS_PER_BLOCK governs
 * envelopes only — NODUS_V2_ENV_BATCH_MAX above), so the only thing that
 * bounds how many can fit in one block is the block's own byte ceiling:
 * cometbft's `MaxBlockSizeBytes` (`CMT_MAX_BLOCK_SIZE_BYTES`,
 * `shared/dnac/cmt_params.h:83` -> `shared/dnac/cmt_bits.h:110`, 100 MiB =
 * 104 857 600) divided by the smallest possible encoded claim
 * (`DNA_CLAIM_FIXED_LEN`, `shared/dnac/manifest_wire.h:452-454`, 7 404
 * bytes — the fixed claim fields plus a full ML-DSA-87 pubkey and
 * signature, zero proof siblings and a one-byte source id). Integer
 * division floors, which is the SAFE direction: it under-counts, never
 * over-counts, how many claims of the smallest possible size could ever
 * be packed side by side, so this bound can never let through more than
 * the block format itself allows.
 *
 * 104 857 600 / 7 404 = 14 162 (the `_Static_assert` below pins the
 * actual value so a change to either input trips it instead of silently
 * moving this bound).
 */
#define NODUS_V2_APPLY_MAX_CLAIMS \
    ((size_t)(CMT_MAX_BLOCK_SIZE_BYTES / DNA_CLAIM_FIXED_LEN))

_Static_assert(NODUS_V2_APPLY_MAX_CLAIMS == 14162,
               "NODUS_V2_APPLY_MAX_CLAIMS drifted — CMT_MAX_BLOCK_SIZE_BYTES "
               "or DNA_CLAIM_FIXED_LEN changed; re-derive the per-block "
               "claim-scratch sizing and every citation of 14162");

/**
 * R3 W3/W4 (ORCHESTRATOR) — THE ENGINE'S PER-BLOCK ITEM CEILING, exported.
 *
 * W3 (2026-09-17) introduced this as a flat, chosen 16 — the size of the
 * per-block scratch arrays the engine held on the stack/heap at the time
 * (`wire_ids[MAX_OPS][64]`, `claim_nuls[MAX_OPS][64]`) — and used it to
 * cap BOTH envelopes and claims together at the two Comet proposal gates,
 * because a 40-claim block decided at production constants FAULTED every
 * node's FinalizeBlock at height 7 (`/tmp/stagef-20260917T034259Z`): the
 * engine could not hold what an honest proposer packed.
 *
 * W4 package C (2026-09-18) replaces the flat 16 with the SUM of the two
 * bounds now derived independently above: the envelope batch max
 * (`NODUS_V2_ENV_BATCH_MAX`, the 64 MiB scratch budget over the measured
 * per-envelope cost — 3 209 on this build; delta 1 briefly tied it to the
 * governance hard cap of 10, retired in delta 2) plus the most claims one
 * cometbft block can carry (`NODUS_V2_APPLY_MAX_CLAIMS`, 14 162) =
 * 17 371. The per-block scratch this bounded
 * (`wire_ids`/`claim_nuls`/`all_ids`/`auths`) is no longer
 * fixed-size at this number — it is heap-allocated and sized by the
 * BLOCK's own `n_envs`/`n_claims`/leg counts (see the per-field comments
 * in nodus_witness_v2_apply.c). What THIS bound still does: it is the
 * ITEM ceiling the Comet application's mixed PrepareProposal trim and
 * ProcessProposal refusal keep using (`n_pool_muts` keeps this as its own
 * verdict bound too — a block message cannot express pool batches on the
 * live lane, so that check is defense in depth, never reached), in
 * ADDITION to the per-class caps the application now also enforces
 * (`NODUS_V2_ENV_BATCH_MAX` for envelopes, `min(claim_bound,
 * NODUS_V2_APPLY_MAX_CLAIMS)` for claims — nodus_witness_cmt_app.c). A
 * release RESOURCE bound of this engine — not a protocol maximum, exactly
 * like `MAX_DOMS`.
 */
#define NODUS_V2_APPLY_MAX_OPS \
    ((size_t)(NODUS_V2_ENV_BATCH_MAX + NODUS_V2_APPLY_MAX_CLAIMS))

/* ORCHESTRATOR (W4-C delta 2, ORC-3) — the writer could not compile, so
 * the exact figures were MEASURED by the ORCHESTRATOR's build on
 * 2026-09-18 (x86-64, gcc): sizeof(dna_env_preflight_t) 15 096,
 * sizeof(dna_meter_t) 3 752, sizeof(nodus_rt_auth_verdict_t) 966 ⇒
 * NODUS_V2_APPLY_ENV_COST_BYTES = 15 096 + 3 752 + 2×966 + 128 = 20 908;
 * NODUS_V2_ENV_BATCH_MAX = 67 108 864 / 20 908 = 3 209;
 * NODUS_V2_APPLY_MAX_OPS = 3 209 + 14 162 = 17 371. The pins below are
 * the trip-wires: a struct layout or budget change moves them and must
 * move every citation of these numbers with it. */
_Static_assert(NODUS_V2_APPLY_ENV_COST_BYTES == 20908,
               "NODUS_V2_APPLY_ENV_COST_BYTES drifted — a struct in the "
               "per-envelope scratch changed size; re-derive "
               "NODUS_V2_ENV_BATCH_MAX and re-check every citation of 20908");
_Static_assert(NODUS_V2_ENV_BATCH_MAX == 3209,
               "NODUS_V2_ENV_BATCH_MAX drifted — re-derive from the scratch "
               "budget / per-envelope cost and re-check every citation of 3209");
_Static_assert(NODUS_V2_APPLY_MAX_OPS == 17371,
               "NODUS_V2_APPLY_MAX_OPS drifted — re-derive from "
               "NODUS_V2_ENV_BATCH_MAX + NODUS_V2_APPLY_MAX_CLAIMS and "
               "re-check every citation of 17371");

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

/** Deterministic fault-injection points (prompt §11, 15 points).
 *
 * tokenomics-v3 P4: the points only the deleted legacy block lane could
 * fire are RETIRED with it — 2-5 (its phase order: SYSTEM, cross-domain,
 * per-domain batch on `fail_domain_batch`, UTXO), 14/15 (its own COMMIT
 * and the post-commit rc-2 window), 19-25 (the in-block S7 pool batches
 * on `fail_pool_index`), 26-28 (its whole-batch reserve, per-envelope
 * phase exec and batch authorization), 34-36 (its committee-snapshot
 * stage, pre-BEGIN replay guard and batch intent-index insert) and 46/47
 * (its dna_bh2 header build and derived BlockID); 48 (phase 12b, the
 * `v2_tx_bytes` persist) is retired by the P4 fix round. The numbers stay
 * RESERVED — never fired, never reused — and the surviving ids keep
 * their values. */
typedef enum {
    V2AP_FAIL_NONE = 0,
    V2AP_FAIL_AFTER_BEGIN = 1,
    /* 2-5 RETIRED (tokenomics-v3 P4) */
    V2AP_FAIL_AFTER_SUPPLY_MUT = 6,
    V2AP_FAIL_AFTER_DOMAIN_ROOTS = 7,
    V2AP_FAIL_AFTER_UPDATES = 8,
    V2AP_FAIL_AFTER_HEADS = 9,
    V2AP_FAIL_AFTER_HISTORY = 10,
    V2AP_FAIL_AFTER_TX_INDEX = 11,
    V2AP_FAIL_AFTER_BLOCK_META = 12,
    V2AP_FAIL_BEFORE_COMMIT = 13,
    /* 14-15 RETIRED (tokenomics-v3 P4) */
    /* S6 claim stages (fire after the named stage of the claim at
     * index blk->fail_claim_index) */
    V2AP_FAIL_AFTER_CLAIM_OUTPUT = 16,  /* target-runtime output created */
    V2AP_FAIL_AFTER_CLAIM_SPEND = 17,   /* spent-claim insert done       */
    V2AP_FAIL_AFTER_CLAIM_STATE = 18,   /* remaining decremented         */
    /* 19-28 RETIRED (tokenomics-v3 P4). 29-33 fire INSIDE the item's
     * SAVEPOINT after the named per-leg stage of the envelope at
     * blk->fail_env_index. */
    V2AP_FAIL_AFTER_READ_PLAN = 29,     /* read plan emitted + validated */
    V2AP_FAIL_AFTER_READS = 30,         /* mediated reads done + charged */
    V2AP_FAIL_AFTER_EXEC_HOOK = 31,     /* native exec returned          */
    V2AP_FAIL_AFTER_EFFECT_DECODE = 32, /* strict result decode done     */
    V2AP_FAIL_AFTER_EFFECT_CHARGE = 33, /* effect charge done            */
    /* 34-36 RETIRED (tokenomics-v3 P4) */
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
     * the stages, this enum owns the numbering (as F19-F25 once mapped
     * the S7 pool stages). They only ever fire on a block whose height IS
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

    /* 46-47 RETIRED (tokenomics-v3 P4) */

    /* 48 RETIRED (tokenomics-v3 P4 fix round): it bracketed phase 12b,
     * the `v2_tx_bytes` persist, deleted with that table. */

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
    /* 50-52 RETIRED by tokenomics-v3 P2 (P2-4 / P2-6): the burning
     * settlement and the per-block mint they bracketed are deleted. The
     * ids stay reserved — never fired, never reused. */
    V2AP_FAIL_AFTER_SETTLE_EMITTED     = 50, /* RETIRED (P2)             */
    V2AP_FAIL_AFTER_SETTLE_APPLIED     = 51, /* RETIRED (P2)             */
    V2AP_FAIL_AFTER_EMISSION           = 52, /* RETIRED (P2)             */

    /* tokenomics-v3 P1 (D-4, S-2) — the attendance digest leg. APPENDED;
     * 39-52 are pinned by shipped tests and are never renumbered. 53
     * fires with the per-epoch digest row written to
     * `v2_attendance_epoch` and NOTHING reset yet: the proof obligation
     * is that an interrupt there leaves no digest row. 54 fires after
     * `v2_attendance.signed_count` has been reset for every row — the
     * second rollback window. Both sit BETWEEN Rule N (F39's sibling,
     * NODUS_V2_EPST_RULE_N) and the boundary flips (F43) in execution
     * order, exactly as F50/F51 sit between graduation and Rule N. */
    V2AP_FAIL_AFTER_ATTENDANCE_DIGEST = 53, /* digest row written        */
    V2AP_FAIL_AFTER_ATTENDANCE_RESET  = 54, /* signed_count reset        */

    /* tokenomics-v3 P2 — the reward stages. APPENDED; 39-54 are pinned
     * by shipped tests and are never renumbered. All five fire INSIDE
     * the transaction on a boundary height only, from the boundary
     * module's stage callback (NODUS_V2_EPST_DIST_* / _PAYDAY_* /
     * _BALANCE_COPY, mapped BY NAME in epoch_stage_fault).
     *   55 every accrual row of the distribution credited, the reward
     *      pool NOT yet debited — an interrupt must leave no accrual row
     *      and no pool movement;
     *   56 the pool debited — the second window of the distribution;
     *   57 every payday UTXO written, the accrual rows NOT yet deleted —
     *      an interrupt must leave neither a paid UTXO nor a missing
     *      accrual;
     *   58 the accrual rows deleted;
     *   59 copy(H) written and the older copy pruned (out of every root:
     *      the proof obligation is the whole-DB digest, not a root). */
    V2AP_FAIL_AFTER_DIST_ACCRUED      = 55, /* accrual rows credited     */
    V2AP_FAIL_AFTER_DIST_APPLIED      = 56, /* reward pool debited       */
    V2AP_FAIL_AFTER_PAYDAY_EMITTED    = 57, /* payday UTXOs written      */
    V2AP_FAIL_AFTER_PAYDAY_APPLIED    = 58, /* accrual rows deleted      */
    V2AP_FAIL_AFTER_BALANCE_COPY      = 59, /* copy(H) written, pruned   */

    /* tokenomics-v3 P3-4 — the graduation's delegation release. APPENDED;
     * 39-59 are pinned by shipped tests and are never renumbered. Fires
     * on the FIRST graduate (candidate index 0, the F40/F41 convention)
     * with its bond release UTXO written, every delegation it held
     * released as a locked UTXO and its delegation rows deleted, and its
     * validators row NOT yet rewritten (NODUS_V2_EPST_GRAD_DELEG_RELEASED,
     * mapped BY NAME in epoch_stage_fault). The proof obligation: an
     * interrupt there leaves no release UTXO, every delegation row and
     * the row's delegated totals exactly as before the block. */
    V2AP_FAIL_AFTER_FIRST_GRAD_DELEG_RELEASE = 60 /* graduate 0 delegations
                                                   * released            */
} nodus_v2_apply_fail_t;

/*
 * The caller-shaped raw-SQL operation type (nodus_v2_op_t: tx_id / sql /
 * verify_cost) is RETIRED. A block carries nodus_v2_envelope_t — bytes
 * and length, NOTHING else: no identity field, no SQL, no cost, no
 * touched list. Identity is DERIVED, the touched set is the leg list,
 * and the price comes from the frozen policy snapshot.
 */

/* ══ THE COMETBFT LANE (FLEET-TM-R3 W2, package R3-C1a) ══════════════
 *
 * D-23 rev 4/5. Under cometbft a DECIDED block is APPLIED, never
 * re-judged: `FinalizeBlock` executes every item and returns one
 * `ExecTxResult` per item, and an item that fails does NOT fail the
 * block (abci/types/application.go's contract; state/execution.go:224-258
 * — the reference's BaseApplication builds one result per tx and the
 * block goes on). That is the whole difference between this lane and the
 * legacy one, where any bad item rejects the block.
 */

/**
 * The per-item verdict code that becomes `ExecTxResult.code`.
 *
 * ⚠ THIS ENUM IS CONSENSUS DATA. Each value is marshalled into the item's
 * `ExecTxResult` and Merkle-hashed into the block's results hash
 * (`cmt_abci_results_hash`, D-23 rev 4), which the NEXT header's
 * `LastResultsHash` commits to (D-19 rev 6 (7)). RENUMBERING A VALUE, OR
 * MOVING AN ITEM FROM ONE CLASS TO ANOTHER, IS A CONSENSUS CHANGE: two
 * builds that disagree about a code produce different results hashes for
 * the same block and the chain splits. Append at the end; never reorder.
 *
 * One value per refusal CLASS the engine can attribute to a single item.
 * Every class names the construct it aggregates by NAME first and line
 * second, because the line moves and the name does not — resolve the
 * name if the two disagree.
 *
 *   1 DECODE     the codec refused the bytes, or the preflight rejected
 *                them for something that is a property of the bytes
 *                alone: `dna_env_decode` and every `dna_env_preflight`
 *                status other than the ERR_CTX_* family and ERR_HASH —
 *                ERR_ARG, ERR_DECODE, ERR_EXPIRED
 *                (env_preflight.h:89-91). Also a claim whose bytes do
 *                not decode, which the application codes before the
 *                engine sees it.
 *   2 CONTEXT    the item does not fit the COMMITTED CONTEXT: a leg
 *                names a domain with no entry in the block-start
 *                ruleset table, or one at a ruleset version the
 *                committed registry does not carry. Both the table
 *                build (the "item's own contextual ruleset table" block,
 *                apply.c:3192-3240) and the preflight's ERR_CTX_COUNT /
 *                ERR_CTX_DOMAIN / ERR_CTX_VERSION
 *                (env_preflight.h:92-94) land here.
 *                ⚠ "DOMAIN NOT REGISTERED / NOT ACTIVE" IS THIS CLASS,
 *                not ADMISSION: the block-start table is built from the
 *                ACTIVE domains only (`doms_load` with strict_active,
 *                then `block_ctx_from_doms`), so a leg naming any other
 *                domain finds no entry and is refused while the table is
 *                being assembled — before any admission predicate runs.
 *   3 REPLAY     the item's DERIVED identity is already committed
 *                (`v2_intent_index` / `v2_tx_index`), or an EARLIER item
 *                of this same block already committed it — the Comet
 *                lane reads the live indices inside the transaction, so
 *                one guard covers both (the "REPLAY" block,
 *                apply.c:3257-3307).
 *   4 ADMISSION  a per-leg admission PREDICATE refused, with the domain
 *                present and ACTIVE: no exec hook, no auth hook,
 *                access_mode not INVOKE, runtime_op not owned by the
 *                committed ruleset, or auth_kind outside the runtime's
 *                allowlist (the "ADMISSION, per leg" block,
 *                apply.c:3308-3332).
 *   5 CAPACITY   the item does not fit what is LEFT: the global unit
 *                ceiling or a per-domain unit budget (`dna_meter_reserve`
 *                statuses other than DNA_METER_ERR_FAULT, at the
 *                "RESERVE" block, apply.c:3333-3357), or the committed
 *                manifest's per-domain transaction quota (the admission
 *                block above). ⚠ R3 W4 package C: the admission block's
 *                per-domain `n_tx` array-bound check is NO LONGER part of
 *                this class — it is now a proven-unreachable FAULT (a
 *                domain cannot appear twice in one envelope's leg list,
 *                env_wire.c:364-365/:276), split from the quota check it
 *                used to share a verdict with.
 *   6 AUTH       the resolved runtime's `auth` hook refused a leg
 *                against the engine-derived leg digest
 *                (`env_authorize_legs`, apply.c:1665-1750).
 *   7 EXEC       execution refused the item: the runtime's exec hook,
 *                the strict effect decode, the adapter's validation, the
 *                effect charge or the adapter's application
 *                (`exec_one_env`, apply.c:1176-1505, every return other
 *                than -2).
 *   8 CLAIM      a claim's derivation, admission or target runtime
 *                refused it (`claim_prescan_one` / `claim_execute_one`).
 *
 * ⚠ HONEST LABEL ON CODE 8, and an OPEN ROW FOR R3-C2 (operator ruling
 * 2026-09-16: no change in W2). The helpers the claim stage calls —
 * `nodus_witness_v2_manifest_load_by_hash` and the three claim write
 * stages — answer -1 for BOTH "deterministically refused" and "this
 * node could not read", a conflation this engine's header has always
 * recorded. In the deleted legacy lane that conflation cost a wrongly
 * rejected block. HERE IT COSTS MORE: code 8 is hashed into the block's results
 * hash, so a node-local read fault becomes CONSENSUS-VISIBLE DATA
 * instead of stopping the node, and a node with a failing disk could
 * commit a results hash its healthy peers do not compute. The named fix
 * is to make those helpers TRI-STATE (refused / fault / ok) so the
 * claim stage can route a fault to NODUS_V2_INTERNAL_FAULT the way the
 * envelope stage already does; it is R3-C2's, not W2's.
 *
 * A NODE-LOCAL fault is NEVER one of these: it aborts the whole apply
 * with NODUS_V2_INTERNAL_FAULT and the host rolls the block back.
 */
typedef enum {
    NODUS_V2_TX_OK            = 0,
    NODUS_V2_TX_ERR_DECODE    = 1,
    NODUS_V2_TX_ERR_CONTEXT   = 2,
    NODUS_V2_TX_ERR_REPLAY    = 3,
    NODUS_V2_TX_ERR_ADMISSION = 4,
    NODUS_V2_TX_ERR_CAPACITY  = 5,
    NODUS_V2_TX_ERR_AUTH      = 6,
    NODUS_V2_TX_ERR_EXEC      = 7,
    NODUS_V2_TX_ERR_CLAIM     = 8
} nodus_v2_tx_code_t;

/**
 * One item's result, in the shape D-23 rev 4 binds to cometbft's
 * `ExecTxResult`: `code` = `nodus_v2_tx_code_t`; `gas_wanted` = the units
 * the item RESERVED; `gas_used` = the units it CONSUMED (the value on an
 * aborted meter is `g_consumed` at the abort — res_meter.h:427-428, and
 * res_meter.h:506-509 says an ABORTED meter's released counters stay
 * zero, so consumed is the only readable figure). A claim reserves and
 * consumes nothing: 0/0. An item that never reached the meter reports
 * 0/0 as well, which is honest — nothing was reserved.
 *
 * `data` (the canonical runtime effect bytes of D-23 rev 4) is NOT
 * carried: the engine's effect bytes are consumed by the adapters and
 * are not retained per item anywhere in this engine, so producing them
 * would mean changing `exec_one_env`'s contract. Reported as a gap; the
 * caller writes an EMPTY `data`, which is one of the two values rev 4
 * allows ("canonical runtime effect bytes in leg order OR EMPTY").
 */
typedef struct {
    uint32_t code;         /* nodus_v2_tx_code_t                        */
    uint64_t gas_wanted;   /* reserved units                            */
    uint64_t gas_used;     /* consumed units                            */
} nodus_v2_tx_result_t;

/**
 * The cometbft-lane inputs and outputs of one apply.
 *
 * `on` selects the lane. With it FALSE every field here is ignored and
 * the engine behaves exactly as it did before this struct existed.
 */
typedef struct {
    bool on;

    /** The cometbft block hash consensus passed to `FinalizeBlock`
     *  (`RequestFinalizeBlock.Hash`, state/execution.go:224-232). It
     *  becomes `v2_blocks.block_id` verbatim: the ledger derives no
     *  identity of its own in this lane (D-17 rev 7 (6)). */
    uint8_t block_hash[64];

    /**
     * The `NextValidatorsHash` the FinalizeBlock request carries
     * (`RequestFinalizeBlock.NextValidatorsHash`, state/execution.go:226)
     * — it becomes `v2_blocks.vset_hash` verbatim. The engine does NOT
     * re-derive it in this lane.
     *
     * ⚠ REGISTER ROW R3-C1a-10. D-17 rev 7 (6) words this column as "the
     * block's Comet ValidatorsHash", and `RequestFinalizeBlock` has NO
     * such field: of the two validator hashes in the header, only
     * `NextValidatorsHash` is passed to the application (execution.go:
     * 222-232). In W2 the two COINCIDE, because `finalize_block` returns
     * no validator updates (R3-T), so the set never changes and
     * `NextValidatorsHash == ValidatorsHash` at every height. The moment
     * validator updates land, they diverge by one block and this column
     * will hold the NEXT set's hash unless the host is changed to pass
     * the header's own `ValidatorsHash`. The VALUE stored here is the
     * request's; only the naming is corrected.
     */
    uint8_t validators_hash[64];

    /** OUT: one result per item, in BLOCK ORDER — every envelope in the
     *  order the block carries them, then every claim. The caller sizes
     *  the array; `n_envs + n_claims` entries are required and a smaller
     *  capacity is a node-local fault. */
    nodus_v2_tx_result_t *results;
    size_t                results_cap;
    size_t                results_len;   /* OUT */

    /**
     * tokenomics-v3 P1 (D-2) — `decided_last_commit`, copied VERBATIM by
     * the app from `req->decided_last_commit.votes[i].validator.address`
     * / `.block_id_flag` (nodus_witness_cmt_host.h:167-193
     * nodus_abci_vote_info_t; the request itself:
     * nodus_witness_cmt_host.h:336-351
     * nodus_abci_request_finalize_block_t.decided_last_commit). Two
     * parallel arrays, both sized `votes_len`: `votes_address[i]` is
     * validator i's cometbft address (32 B, = SHA3-512(pubkey)[0..31],
     * vset_wire.h:121); `votes_block_id_flag[i]` is that validator's raw
     * `cmt_pb_block_id_flag_t` for the commit THIS block carries — the
     * commit FOR global_height-1 (state/execution.go's BuildLastCommitInfo
     * contract; the host builds it BEFORE calling FinalizeBlock, so a
     * COMMIT-flagged vote here means "signed global_height-1", never
     * "signed this block"). The engine credits ONLY
     * CMT_PB_BLOCK_ID_FLAG_COMMIT votes (D-2, Q1: NIL/ABSENT do not
     * count) into the out-of-root `v2_attendance` table
     * (nodus_witness_v2_epoch.c). The initial height
     * (no previous commit to report, execution.go:451-455) leaves both
     * arrays NULL and `votes_len` 0 — that is the legal empty case, never
     * a fault. */
    const uint8_t (*votes_address)[32];
    const int32_t  *votes_block_id_flag;
    size_t          votes_len;
} nodus_v2_block_cmt_t;

/* ── WHAT THE BLOCK ROW COUNTS IN THIS LANE (register row R3-C1a-7) ──
 *
 * `v2_blocks.tx_count` is the number of ids `v2_blocks.tx_root` commits
 * to, and that list holds the items this block APPLIED — never the
 * refused ones. The two facts are one fact: a refused item's state
 * changes went away with its SAVEPOINT, so binding its id into the
 * block's transaction root would commit the block to a transaction that
 * did not happen.
 *
 * THIS IS NOT THE BLOCK'S TRANSACTION COUNT. The cometbft block carries
 * `Data.Txs` — every item, refused or not — and consensus commits that
 * count through the header's `DataHash`. The ledger's row counts what
 * the ledger did. On a block with a refused item the two numbers differ,
 * and that difference is the design, not a discrepancy: one is what was
 * decided, the other is what was applied. Every node computes both
 * identically, because the refusal set is a deterministic function of
 * the block's bytes and the committed state.
 */

/**
 * One V2 global block for the engine — a DECIDED cometbft block
 * (`cmt.on` MUST be set; tokenomics-v3 P4 deleted the legacy lane, and
 * the engine refuses a block without it as a node FAULT).
 *
 * ── THE IDENTITY IS CONSENSUS'S (D-17 rev 7 (6)) ──────────────────────
 * The v2_blocks row stores `cmt.block_hash` (cometbft's header hash) as
 * `block_id` and `cmt.validators_hash` as `vset_hash`, verbatim; the
 * ledger derives no identity of its own. `prev_block_id` is the previous
 * v2_blocks row's id (64 zero bytes for the chain's first block); the
 * roots and `tx_count` (the APPLIED items) are execution's. The legacy
 * lane's dna_bh2 header build and derived BlockID (O14) are deleted.
 */
typedef struct {
    uint64_t global_height;
    uint64_t epoch;                     /* MUST equal
                                         * nodus_v2_epoch_for_height(
                                         *   global_height) — verified,
                                         * never trusted               */
    /* ── Block material from the decided header (informational) ───── */
    uint8_t  proposer_id[32];
    uint64_t timestamp;

    /* ── The legacy lane's identity ASSERTIONS. MUST be NULL: the
     * identity is consensus's input here, not a derivation to assert,
     * and the engine refuses a block carrying any of them as a node
     * FAULT (the entry gate). Kept as fields so that refusal stays
     * expressible — and tested. */
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
     * Included envelopes, in the block's order (the order IS the item
     * execution order). NULL/0 = none. */
    const nodus_v2_envelope_t *envs;
    size_t   n_envs;
    /* S6 generic claims (routed to each claim's COMMITTED target
     * runtime; each processed as an item inside its own SAVEPOINT).
     * NULL/0 = none. */
    const dna_claim_t *claims;
    size_t   n_claims;
    /* S7 pool-state batches. A decided block cannot carry one (the block
     * message's pool_batch_count must be zero, shared/dnac/blockmsg_v2.h);
     * a non-zero count is refused as a node FAULT. The in-block pool
     * phase (6p) is deleted with the legacy lane (tokenomics-v3 P4).
     * NULL/0 = none. */
    const nodus_v2_pool_mut_t *pool_muts;
    size_t   n_pool_muts;
    /* Follower-mode expected roots — any NULL = fill only. A non-NULL
     * expectation that mismatches the recomputation refuses the block
     * (a node FAULT: the block is decided). */
    const uint8_t *expect_tx_root;
    const uint8_t *expect_dupd_root;
    const uint8_t *expect_domains_root;
    const uint8_t *expect_global_root;
    /* Fault injection (tokenomics-v3 P4: the legacy lane's
     * `fail_domain_batch` (point 4) and `fail_pool_index` (points 19-25)
     * are deleted with those points, as are the `qc_bytes`/`qc_len`
     * certificate the legacy v2_blocks row stored). */
    nodus_v2_apply_fail_t fail_at;
    uint32_t fail_claim_index;          /* claim index for points 16-18  */
    uint32_t fail_env_index;            /* envelope index, points 29-38  */
    uint32_t fail_effect_index;         /* effect index for point 37     */
    uint32_t fail_leg_index;            /* leg index for point 38        */
    /* ── Outputs — valid on rc 0 (applied). ─────────────────────────── */
    uint8_t  out_tx_root[64];
    uint8_t  out_dupd_root[64];
    uint8_t  out_domains_root[64];
    uint8_t  out_global_root[64];
    uint8_t  out_prev_block_id[64];
    uint8_t  out_vset_hash[64];
    /* The id `v2_blocks.block_id` stores: `cmt.block_hash`, verbatim.
     * (The legacy lane's `out_header` — its dna_bh2 header bytes — is
     * deleted with that lane.) */
    uint8_t  out_block_id[DNA_BH2_ID_LEN];
    /* ── THE COMETBFT LANE (D-23 rev 4/5) — `cmt.on` MUST be set. See
     * nodus_v2_block_cmt_t. */
    nodus_v2_block_cmt_t cmt;
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

/* tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b): the version-2 engine
 * genesis entries nodus_witness_v2_genesis / nodus_witness_v2_genesis_ex
 * (schema S9-S12, a height-0 v2_blocks row carrying a derived dna_bh2
 * genesis BlockID) are DELETED with the legacy block lane. The one
 * genesis is nodus_witness_v2_genesis_cmt, below. The build's `nm` gate
 * (CMakeLists.txt test_v2_seam_linked) fails if either symbol is linked
 * again. */

/**
 * Apply one V2 global block (header contract).
 *
 * On every refusal the engine also fills `blk->out_reason` with the
 * class-tagged text of the site that refused — see the field's contract
 * in nodus_v2_block_t. It is DIAGNOSTIC ONLY and changes no verdict: the
 * return codes below are exactly what they were before the reason
 * existed.
 *
 * @return 0 applied — the host's transaction still OPEN, per-item codes
 *         in `blk->cmt.results`; NODUS_V2_INTERNAL_FAULT (-2) — the
 *         host rolls the block back and the node stops. No other value
 *         is returned (see REFUSAL below). tokenomics-v3 P4 deleted the
 *         legacy lane with its rc 1 idempotent replay, its rc 2
 *         post-commit window and its -1 verdicts; a block without
 *         `cmt.on` is refused (-2) without being judged.
 *
 * ── THE COMETBFT LANE (`blk->cmt.on`, D-23 rev 4/5) ───────────────────
 * The entry behaves as cometbft's `FinalizeBlock`:
 *
 *   · SCHEMA. S16 only (tokenomics-v3 P1 round 5 moved this gate's
 *     accepted value from the earlier S14 to S15; P2 moves it to S16).
 *     At any other version the entry returns -2 — the Comet row shape
 *     needs the three columns S14 dropped to be gone, S15's own two
 *     `validators` columns (`last_signed_block`,
 *     `signed_blocks_this_epoch`) to be gone, and S16's reward pool
 *     column and two reward tables to exist.
 *   · TRANSACTION. The entry opens NOTHING and closes NOTHING. It
 *     REQUIRES the caller's transaction to be open already
 *     (`sqlite3_get_autocommit(w->db) == 0`) and returns -2 otherwise;
 *     the host's `apply_verified_block` owns the BEGIN and `app.commit`
 *     owns the COMMIT (D-23 rev 5 (5)). Every failure leaves the
 *     rollback to the host.
 *   · IDENTITY. `v2_blocks.block_id` is `cmt.block_hash` verbatim,
 *     `vset_hash` is `cmt.validators_hash`, `prev_block_id` is the
 *     previous row's id or 64 zero bytes at the FIRST block (a version-3
 *     chain has no height-0 row at all — D-18 rev 4), and NO header, qc
 *     or commit_cert column is written. The engine derives no identity.
 *   · ITEMS. Every item is executed in BLOCK ORDER — envelopes as the
 *     block carries them, then claims — each inside its own SAVEPOINT
 *     nested in the caller's transaction. An item-attributable refusal
 *     rolls that SAVEPOINT back, pays no fee, writes no index row, and
 *     records a nonzero `nodus_v2_tx_code_t` in `cmt.results[i]`; the
 *     block CONTINUES. (The deleted legacy lane's phase order — SYSTEM →
 *     cross-domain → domain-local — was a different consensus protocol's
 *     rule.)
 *   · REFUSAL. A decided block is never refused. EVERY negative the
 *     body produces other than -2 becomes -2 —
 *     both -1 CONSENSUS_INVALID and -3 NOT_YET_LINKABLE —
 *     including the refusals that are not attributable to one item
 *     (SYSTEM not ACTIVE, an unreadable block context, an unreadable
 *     authority snapshot). A node that cannot apply a decided block
 *     stops.
 *     WHY -3 FOLDS TOO: a deferral means "the predecessor state is
 *     absent here, nothing was judged", which is a legitimate answer
 *     when blocks arrive out of order from a peer. Under cometbft they
 *     cannot: consensus drives heights strictly sequentially and hands
 *     this engine height h only after committing h-1. A gap at
 *     FinalizeBlock therefore is not "wait for more" — it is this node's
 *     ledger disagreeing with the height consensus already decided, and
 *     the only safe answer is to stop. Deferring instead would let the
 *     node return CMT_OK-shaped success for a block it never applied.
 *   · The whole-batch capacity seam
 *     (`nodus_witness_v2_produce_batch_check_ex`) is NOT used here: it
 *     belongs to PrepareProposal/ProcessProposal, which run BEFORE the
 *     vote.
 */
int nodus_witness_v2_apply_block(nodus_witness_t *w, nodus_v2_block_t *blk);

/* ── THE PER-ITEM DRY RUN (CheckTx parity, package CHECKTX-P1) ─────────
 *
 * ⚠ NOTHING ELSE ON THE MEMPOOL SIDE VERIFIES AN ENVELOPE'S SIGNATURES.
 * `dna_env_preflight` derives commitments and identities and says so
 * itself (env_preflight.h:57-63: it decides nothing about "whether any
 * authorization is VALID"), and the admission lane
 * (`verify_v2_successor_tx`, nodus_witness_verify.c:674-784) runs no
 * signature check at all. This dry run's authorization stage (the item
 * loop's own `env_authorize_legs`) is the CheckTx signature check —
 * D-4 rev 3 (1): "signature, format, double spend, size". (The former
 * signature-only entry `nodus_witness_v2_env_authorize` is deleted,
 * CHECKTX-P1 round 2: this entry subsumes it and it had no production
 * caller left.)
 *
 * One envelope, judged by the SAME per-item stages the Comet apply lane
 * runs for one item (nodus_witness_v2_apply.c, the item loop), against
 * COMMITTED state at the candidate height tip + 1, WITHOUT A WRITE:
 *
 *   decode → positional ruleset table → dna_env_preflight →
 *   replay guard (committed intent / wire index) → per-leg admission
 *   (ownership, access mode, auth-kind allowlist, per-domain quota) →
 *   meter reservation against a FRESH block budget → authorization
 *   (the runtime's own auth hook, env_authorize_legs) → per leg:
 *   read_plan + mediated reads + native exec + strict effect decode +
 *   effect charge + the adapter's validate / probe / precondition
 *   decision — every step the apply path runs EXCEPT the adapter's
 *   mutate. `exec_one_env` is the ONE body both modes run; the dry mode
 *   differs from apply in exactly that last step.
 *
 * WHY PROBE-ONLY EQUALS APPLY for one item: within one leg the effect
 * list's logical keys are unique (the strict codec,
 * dna_effect_result_decode), and one envelope's legs address distinct
 * domains (env_wire.c's strictly ascending leg order), while every
 * adapter call is scoped to its leg's own domain — so no effect of the
 * item can observe another effect of the same item, and probing every
 * effect against committed state answers what probe-then-mutate would.
 * RESIDUAL ASSUMPTION (read in the two compiled adapters, not proven in
 * general): an adapter's probe of one key depends on that key's row
 * alone.
 *
 * NOT CONSENSUS-VISIBLE: nothing is written, no block is judged. The
 * answer is a node-local admission decision (mempool CheckTx); the
 * block's own verdicts stay the apply engine's.
 */

/** A leg authorization verdict a caller already holds for THESE bytes
 *  (the CheckTx recheck cache). A leg's entry is consulted only when
 *  `present[l]` is 1, the leg's auth_kind is 1 (NODUS_RT_AUTHKIND_DSA87_
 *  MULTI_V1, whose verdict is a pure function of the bytes and the leg
 *  digest — nodus_witness_runtime.h's auth contract) AND `digest[l]`
 *  equals the digest this run derives. auth_kind 2 is ALWAYS verified
 *  afresh: its verdict depends on the governing committee snapshot. */
typedef struct {
    uint16_t                       leg_count;
    const uint8_t                 *present;   /* [leg_count]              */
    const uint8_t                (*digest)[64]; /* [leg_count]            */
    const nodus_rt_auth_verdict_t *verdict;   /* [leg_count]              */
} nodus_v2_auth_reuse_t;

/** One ROW-IDENTITY row an envelope's effects claim — reported
 *  generically from the decoded effect list, never from any
 *  runtime-specific call parsing. EXACTLY two classes are reported:
 *
 *   - every DELETE, whatever its precondition: once an earlier item in
 *     the block deleted the row, a later item's mediated read of it
 *     (taken inside the block transaction, after the earlier item's
 *     effects — nodus_witness_v2_apply.c exec_one_env: read_one, then
 *     exec, then effects_apply) finds it ABSENT, so the later item
 *     cannot apply: a true conflict;
 *   - every PRE_ABSENT CREATE: once an earlier item created the key, it
 *     is PRESENT for the later item's precondition check — a true
 *     conflict for an op whose CREATE has no other shape. ONE known
 *     exception (nodus/BUGS.md, accepted): a DELEGATE picks its shape
 *     from its own read (nodus_witness_rt_native.c `rtn_delegate_exec`,
 *     `topup = dr->present`), so a second first-time DELEGATE from the
 *     same delegator to the same validator would apply in the block as
 *     a top-up; keying its CREATE refuses it at CheckTx (false conflict,
 *     node-local, only that delegator is affected).
 *
 *  NOT reported: SETs of any precondition. A PRE_EXISTS_VHASH SET's
 *  expected hash is computed by the runtime from ITS OWN mediated read
 *  (nodus_witness_rt_native.c `rtn_row_set_eff`), and that read sees the
 *  earlier items' writes — so two such SETs of one row (two DELEGATEs to
 *  one validator, an UNDELEGATE beside a DELEGATE) BOTH apply in one
 *  block; keying them was a false conflict (CHECKTX-P1 round 3). SETs
 *  under PRE_EXISTS / PRE_EXISTS_VERSION are the shared counters
 *  (supply, validator stats) every ordinary item updates, re-read the
 *  same way. */
typedef struct {
    uint32_t domain_id;                       /* the leg's domain          */
    uint32_t op_id;                           /* the adapter operation     */
    uint16_t key_len;
    uint8_t  key[DNA_EFFECT_MAX_KEY_LEN];
} nodus_v2_dry_run_row_t;

/** The dry run's answer. Large (per-leg verdicts) — heap-allocate it.
 *  `rows` is owned by the struct: release it with
 *  nodus_witness_v2_env_dry_run_free. */
typedef struct {
    uint32_t code;                /* nodus_v2_tx_code_t the apply lane
                                   * would record; NODUS_V2_TX_OK on 0    */
    uint8_t  wire_id[64];         /* valid once preflight passed           */
    uint8_t  intent_id[64];
    uint16_t leg_count;
    uint8_t  auth_kind[DNA_ENV_MAX_LEGS];
    uint8_t  leg_digest[DNA_ENV_MAX_LEGS][64];
    nodus_rt_auth_verdict_t verdict[DNA_ENV_MAX_LEGS];
    uint8_t  verdict_reused[DNA_ENV_MAX_LEGS]; /* 1 = taken from `reuse` */
    nodus_v2_dry_run_row_t *rows;              /* heap, `n_rows` rows     */
    size_t   n_rows;
} nodus_v2_env_dry_run_t;

/**
 * Run the per-item dry run over one envelope (contract above).
 *
 * @param reuse   optional (NULL = verify every leg).
 * @param out     zeroed and filled; release with _free on every return.
 * @param reason  optional; the class-tagged refusal / fault text.
 * @return 0 the item would APPLY at tip + 1 against committed state;
 *         -1 the item would be REFUSED (`out->code` names the class the
 *         apply lane would record); -2 a node-local fault — never a
 *         verdict about the bytes.
 */
int nodus_witness_v2_env_dry_run(nodus_witness_t *w, const uint8_t *bytes,
                                 size_t len,
                                 const nodus_v2_auth_reuse_t *reuse,
                                 nodus_v2_env_dry_run_t *out,
                                 char *reason, size_t reason_size);

/** Free what nodus_witness_v2_env_dry_run allocated inside `out`
 *  (not `out` itself). NULL-safe. */
void nodus_witness_v2_env_dry_run_free(nodus_v2_env_dry_run_t *out);

/**
 * One claim's canonical NULLIFIER from its wire bytes — the derivation
 * the apply lane runs for that claim (`claim_prescan_one`: shape,
 * committed manifest, distribution leaf hash, "DNA.CLNUL.v1"), exposed
 * so the mempool can key a pending claim by what makes two claims the
 * SAME claim. Reads committed state, writes nothing.
 * @return 0 with `out_nul` filled; -1 the bytes do not decode or the
 *         derivation refuses them (a verdict); -2 a node-local fault.
 */
int nodus_witness_v2_claim_nullifier(nodus_witness_t *w, const uint8_t *bytes,
                                     size_t len, uint8_t out_nul[64]);

/**
 * THE LEDGER'S COMMITTED GLOBAL ROOT — the one quantity that answers
 * "what is the ledger's state root after the last block it committed?".
 *
 * There are two committed sources and they must never be asked
 * separately:
 *   · a chain that has committed blocks: the TIP `v2_blocks` row's
 *     `global_root` column — the exact bytes phase 13 computed and
 *     wrote, which is what `FinalizeBlock` returned as `app_hash` and
 *     what consensus bound as the next header's AppHash (D-19 rev 6 (1));
 *   · a chain that has committed only its genesis: no row exists in the
 *     cometbft lane at all (D-19 rev 6 withdrew the genesis block), so
 *     the root is RECOMPUTED from the committed DomainHeads exactly as
 *     `nodus_witness_v2_genesis_cmt` composed it — `dna_v2_domains_root`
 *     over the heads in domain_id order, then `dna_v2_global_root`.
 *
 * WHY THIS EXISTS rather than `nodus_witness_global_root_v2`: that
 * function RECOMPUTES from whatever the live tables hold now. It agrees
 * with the stored row only while nothing has moved since the block was
 * written, and it can never be the authority for "the root at height h"
 * once h is in the past. The row is the authority; this helper reads it
 * and falls back to the genesis composition only where there is no row
 * to read.
 *
 * @return 0 with `out` filled; -1 when neither source answers (a chain
 *         with no committed block row AND no committed head has no root).
 */
int nodus_witness_v2_committed_global_root(nodus_witness_t *w,
                                           uint8_t out[64]);

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

/**
 * THE COMETBFT-LANE GENESIS (FLEET-TM-R3 W2, package R3-C1b).
 *
 * THE genesis (the version-2 entry nodus_witness_v2_genesis_ex, which it
 * was written beside, is deleted since tokenomics-v3 P4). Everything
 * that entry did to the LEDGER's state —
 * the registry's genesis initialisation, the committed genesis manifest,
 * one canonical activation DomainHead per ACTIVE domain with its
 * height-0 root-history row, the domains/global roots, the committed-
 * authority cross-check of `vset_hash`, and the supply gate — in ONE
 * transaction, with exactly one thing removed and one thing added:
 *
 *   REMOVED  the height-0 `v2_blocks` row, and with it the genesis
 *            header, the derived genesis BlockID and the `header`/`qc`
 *            columns S14 drops. D-19 rev 6 withdrew the genesis block:
 *            under cometbft the chain's identity is the genesis
 *            DOCUMENT's hash (D-18 rev 4), not a block's.
 *   ADDED    `out_global_root` — the ledger's global state root after
 *            this apply. It is the document's `app_hash` (D-19 rev 6
 *            (1): AppHash carries the ledger's root), and the caller
 *            cannot read it back from a block row that no longer exists.
 *
 * SCHEMA (HISTORY): S12 OR S14 in W2; S14 alone from W3. The destination
 * WAS S14 — that is where the Comet stores live — but the ledger genesis
 * below runs the CORE runtime's `state_init`, whose own gate stops at S12
 * (nodus_witness_v2_pools.c:1174-1182), and that gate is one of the five
 * D-17 rev 7 (7) assigns to W3 together with the live S14 flip. So the
 * derivation builds the ledger at S12 and climbs to S14 afterwards
 * (nodus_witness_v2_gen_derive_v3, step 9), and this entry admitted both
 * versions for that one window. W3 narrowed it back to S14 in the same
 * commit that widens the pool gate. (The version-2 entry's own S9-S12
 * gate is deleted with it, tokenomics-v3 P4.)
 *
 * CURRENT (tokenomics-v3 P2): the destination is S16 (P1 round 5 had
 * S15) — the derivation climbs S12 -> S16 (`nodus_witness_db_migrate_
 * v2s16` cascades through S15, S14 and S13, nodus_witness_v2_gen.c
 * derive_v3), and this entry's own gate accepts S16 only. Everything in
 * the paragraph above this one is the W2/W3 history that shaped the
 * climb, not today's target version. The entry also writes the epoch-0
 * frozen balance copy (nodus_witness_v2_balance_copy_write, P2-5).
 *
 * NOT IDEMPOTENT, and it cannot be: the deleted version-2 entry decided
 * "already done" from the height-0 row this one does not write. A
 * database that
 * already carries a committed genesis manifest is REFUSED here. Under
 * D-23 rev 5 (7) that is the right shape anyway — a restarting node
 * VERIFIES its committed genesis through InitChain, it never re-applies
 * it.
 *
 * @param w                the open chain (S16), outside a transaction.
 * @param vset_hash        the 64-byte genesis authority hash. An
 *                         ASSERTION: when a genesis snapshot is already
 *                         committed it MUST equal it.
 * @param manifest_bytes   the canonical genesis manifest. REQUIRED.
 * @param manifest_len     its length.
 * @param out_global_root  receives the 64-byte global state root.
 * @return 0 committed; -1 refused or failed (nothing partial);
 *         NODUS_V2_INTERNAL_FAULT for a node-local fault (an allocation
 *         failure), never reported as a judgement.
 */
int nodus_witness_v2_genesis_cmt(nodus_witness_t *w,
                                 const uint8_t vset_hash[64],
                                 const uint8_t *manifest_bytes,
                                 size_t manifest_len,
                                 uint8_t out_global_root[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_APPLY_H */
