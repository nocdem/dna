/**
 * @file nodus_witness_v2_adapter.h
 * @brief Ledger V2 — the compile-time STORAGE-ADAPTER boundary between a
 *        domain runtime's typed effects and that domain's own storage
 *        (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Nothing in live consensus calls anything here, and the S5 apply engine
 * is deliberately NOT re-based onto this boundary this season — it still
 * executes `op->sql` (nodus_witness_v2_apply.h). This header exists so it
 * becomes STRUCTURALLY POSSIBLE for a future domain runtime to return
 * bounded, deterministic, domain-scoped typed effects instead of raw SQL.
 * The production runtime table carries NO adapter and
 * nodus_witness_runtime_selfcheck() enforces that (the apply_reserved
 * discipline).
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── AUTHORITY MODEL (the whole point of the file) ─────────────────────
 *
 * 1. THE DOMAIN COMES FROM THE RESOLVED RUNTIME, NOWHERE ELSE. A typed
 *    effect result carries no domain id at all — that is the codec's
 *    explicit contract (shared/dnac/effect_wire.h: "NO domain id — the
 *    authoritative domain is engine-supplied CONTEXT"). This layer takes
 *    the domain from `rt->domain_id` of the runtime the caller resolved,
 *    and there is no parameter, field or override through which a caller
 *    or a result could name a different one.
 *
 * 2. THE ADAPTER IS REACHED ONLY THROUGH THE FIVE-AXIS EXACT-TUPLE
 *    LOOKUP. It is registered as a FIELD of the runtime descriptor
 *    (nodus_domain_runtime_t.adapter), so an adapter resolves exactly
 *    when its runtime does — through
 *    (domain_id, runtime_kind, runtime_abi, ruleset_version,
 *     ruleset_hash) matching byte-exactly. There is NO adapter name, NO
 *    adapter id, NO adapter registry, NO second resolution path, and NO
 *    fallback adapter: a runtime without one cannot execute typed
 *    effects at all (NODUS_ADAPTER_ERR_NO_ADAPTER, fail-closed).
 *
 * 3. NO SQL, TABLE NAME, SCHEMA STRING OR CALLBACK CAN CROSS THE
 *    BOUNDARY. Everything a result carries is (op_id, key, value, kind,
 *    precondition) over opaque octet strings. `op_id` selects a COMPILED
 *    descriptor in the adapter's own `ops[]` array; only the compiled
 *    probe/mutate code — which is part of the runtime, not of the
 *    transaction — knows which tables exist and holds the statements
 *    over them.
 *
 * ── PROBE / EVAL / MUTATE (why the split) ─────────────────────────────
 * The adapter supplies FACTS (does the row exist, at what version, with
 * what value hash) and performs MUTATIONS. It does NOT decide whether a
 * precondition holds: that decision is ONE piece of shipped generic code,
 * nodus_adapter_precond_eval, so precondition semantics cannot fork per
 * adapter. Two adapters can disagree about where a row lives; they can
 * never disagree about what EXISTS_VERSION means.
 *
 * ── A FAULT IS NOT A VERDICT ──────────────────────────────────────────
 * A storage failure is a NODE-local fault, never a transaction verdict —
 * the same rule env_preflight.h states for ERR_HASH
 * (shared/dnac/env_preflight.h:96-107) and the same rule nodus/CLAUDE.md
 * states as "a DB failure is never a value". A probe that cannot read
 * MUST return NODUS_ADAPTER_ERR_STORAGE_FAULT and MUST NOT report
 * `exists == 0`; this layer propagates that status untranslated and never
 * converts it into a precondition verdict. One starved witness answering
 * "precondition failed" while the rest answer "applied" is a chain split.
 *
 * ── HONEST LABEL: what validate/apply do NOT say ──────────────────────
 *   - nothing about AUTHORIZATION: no signature, no ownership, no spend
 *     authority is consulted here;
 *   - nothing about FEES or METERING: an effect's cost is not computed,
 *     charged or bounded by this layer;
 *   - nothing about whether the effects semantically BELONG to the leg
 *     that produced them — that binding is the future engine's job;
 *   - nothing about whether the adapter's own statements USE the domain
 *     they were handed: the boundary guarantees which domain id reaches
 *     probe/mutate, and that is all it can guarantee — a compiled
 *     adapter that fails to scope its tables by that id is a broken
 *     TRUSTED component (adapters are compiled, registration-reviewed
 *     code, the same trust class as the runtime hooks themselves);
 *   - nothing about canonicality: order, duplicates, global bounds and
 *     kind/precondition legality are the CODEC's authority. This layer
 *     only ever consumes a DECODED view, which is canonical by
 *     construction, which is exactly why no ERR_ORDER / ERR_DUP status
 *     exists below. A non-canonical result never reaches here — it dies
 *     as `dna_effect_result_decode` returning -1.
 *
 * @file nodus_witness_v2_adapter.h
 */

#ifndef NODUS_WITNESS_V2_ADAPTER_H
#define NODUS_WITNESS_V2_ADAPTER_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/effect_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This release's compiled adapter descriptor version. */
#define NODUS_DOMAIN_ADAPTER_V1  1u

/**
 * Typed status values.
 *
 * The distinctness is load-bearing: a MISSING row, a FAILED precondition
 * and a STORAGE FAULT must never be conflated. Collapsing any two of them
 * into one code is how a node fault becomes a transaction verdict.
 *
 * Canonicality rejections (order, duplicates, global bounds, kind /
 * precondition legality) are deliberately ABSENT from this enum — see the
 * HONEST LABEL block above.
 *
 * ── CONSUMPTION RULE (the enum's two classes) ─────────────────────────
 * VERDICT-CLASS statuses — NO_ADAPTER, UNKNOWN_OP, KIND, PRECOND_FORM,
 * SHAPE, PRECOND_EXISTS, PRECOND_MISSING, PRECOND_VERSION, PRECOND_HASH —
 * are deterministic functions of (result bytes, compiled adapter, state):
 * two honest nodes with the same inputs produce the same one.
 * NODE-LOCAL-CLASS statuses — ERR_ARG and ERR_STORAGE_FAULT — are NOT
 * transaction verdicts and MUST NOT be converted into one: ERR_ARG is a
 * caller-side programming error and ERR_STORAGE_FAULT is this node's
 * storage or adapter failing (possibly on this node alone). A future
 * consensus caller failing ITS OWN operation on either is correct; voting
 * "reject the transaction" on either is the one-starved-witness chain
 * split env_preflight.h:96-107 describes.
 */
typedef enum {
    NODUS_ADAPTER_OK = 0,
    NODUS_ADAPTER_ERR_ARG             = 1,  /* NULL/malformed argument      */
    NODUS_ADAPTER_ERR_NO_ADAPTER      = 2,  /* runtime carries no adapter   */
    NODUS_ADAPTER_ERR_UNKNOWN_OP      = 3,  /* op_id not in the descriptor  */
    NODUS_ADAPTER_ERR_KIND            = 4,  /* kind not allowed for this op */
    NODUS_ADAPTER_ERR_PRECOND_FORM    = 5,  /* precond tag not allowed here */
    NODUS_ADAPTER_ERR_SHAPE           = 6,  /* key/value outside op bounds  */
    NODUS_ADAPTER_ERR_PRECOND_EXISTS  = 7,  /* CREATE: key already present  */
    NODUS_ADAPTER_ERR_PRECOND_MISSING = 8,  /* SET/DELETE: key absent       */
    NODUS_ADAPTER_ERR_PRECOND_VERSION = 9,  /* expected_version mismatch    */
    NODUS_ADAPTER_ERR_PRECOND_HASH    = 10, /* expected value-hash mismatch */
    NODUS_ADAPTER_ERR_STORAGE_FAULT   = 11  /* DB/storage fault — NODE-local*/
} nodus_adapter_status_t;

/* ── Permission bitmasks ─────────────────────────────────────────────────
 * Bit (value - 1) of the mask, for both enums, because both enums reserve
 * 0 for INVALID (effect_wire.h) — so bit 0 belongs to the first REAL
 * value and a zeroed mask permits nothing. Never expand these macros with
 * a 0 argument. */
#define NODUS_ADAPTER_KIND_BIT(k)     ((uint8_t)(1u << ((unsigned)(k) - 1u)))
#define NODUS_ADAPTER_PRECOND_BIT(t)  ((uint8_t)(1u << ((unsigned)(t) - 1u)))
/** CREATE|SET|DELETE — every kind the codec can carry. */
#define NODUS_ADAPTER_KINDS_ALL       ((uint8_t)0x07)
/** ABSENT|EXISTS|EXISTS_VERSION|EXISTS_VHASH — every precondition tag. */
#define NODUS_ADAPTER_PRECONDS_ALL    ((uint8_t)0x0F)

/**
 * One compiled adapter operation descriptor — immutable compiled data.
 *
 * The bounds are INCLUSIVE on both ends and are the op's OWN, narrower
 * contract inside the codec's global caps; they are not a restatement of
 * them. An op may legitimately pin an exact width by setting min == max.
 */
typedef struct {
    uint32_t op_id;             /* unique within the adapter, ASCENDING     */
    uint8_t  allowed_kinds;     /* bitmask, bit (kind-1): CREATE=1<<0,
                                 * SET=1<<1, DELETE=1<<2                    */
    uint8_t  allowed_preconds;  /* bitmask, bit (tag-1): ABSENT=1<<0,
                                 * EXISTS=1<<1, EXISTS_VERSION=1<<2,
                                 * EXISTS_VHASH=1<<3                        */
    uint16_t key_len_min, key_len_max;      /* inclusive, within codec caps */
    uint32_t value_len_min, value_len_max;  /* inclusive, within codec caps */
} nodus_adapter_op_t;

/**
 * Raw storage FACTS about one row, as the adapter's probe reports them.
 *
 * `version` and `value_hash` are meaningful ONLY when `exists == 1`; a
 * probe reporting absence leaves them at whatever it left them at, and
 * the generic decision below never reads them on that branch.
 */
typedef struct {
    int      exists;                            /* 0 or 1 — nothing else    */
    uint64_t version;                           /* meaningful iff exists    */
    uint8_t  value_hash[DNA_EFFECT_HASH_LEN];   /* meaningful iff exists;
                                                 * dna_effect_value_hash of
                                                 * the STORED value         */
} nodus_adapter_row_facts_t;

struct nodus_domain_adapter;
struct nodus_domain_runtime;
struct nodus_witness;

/**
 * Probe one row.
 *
 * @param authoritative_domain_id ALWAYS the resolved runtime's own
 *        domain_id — the adapter must scope its read by it, never by
 *        anything derived from the effect.
 * @return NODUS_ADAPTER_OK with `facts_out` filled (`exists` 0 or 1), or
 *         NODUS_ADAPTER_ERR_STORAGE_FAULT. It must NEVER report a fault
 *         as `exists == 0` — that conflation is exactly what the typed
 *         statuses exist to prevent. The contract is ENFORCED, not
 *         trusted: nodus_witness_v2_effects_apply COERCES any other
 *         return to ERR_STORAGE_FAULT, so precondition statuses can only
 *         originate in nodus_adapter_precond_eval, never in adapter code.
 */
typedef nodus_adapter_status_t (*nodus_adapter_probe_fn)(
    const struct nodus_domain_adapter *ad, struct nodus_witness *w,
    uint32_t authoritative_domain_id, const nodus_adapter_op_t *op,
    const uint8_t *key, uint16_t key_len,
    nodus_adapter_row_facts_t *facts_out);

/**
 * Perform one ALREADY-VALIDATED mutation inside the CALLER's transaction.
 *
 * Shape, kind, precondition form and the precondition itself have all
 * been decided before this is called; the adapter's job is the write.
 * It NEVER opens, commits or rolls back a transaction — same contract as
 * every S5 helper.
 *
 * @param value NULL exactly when `value_len` is 0 (DELETE always, and a
 *        legitimately empty CREATE/SET value).
 * @return NODUS_ADAPTER_OK or NODUS_ADAPTER_ERR_STORAGE_FAULT. As with
 *         the probe, apply COERCES any other return to
 *         ERR_STORAGE_FAULT — a mutate answering with a precondition
 *         status would be a second decision point after the shipped
 *         table already ruled.
 */
typedef nodus_adapter_status_t (*nodus_adapter_mutate_fn)(
    const struct nodus_domain_adapter *ad, struct nodus_witness *w,
    uint32_t authoritative_domain_id, const nodus_adapter_op_t *op,
    uint8_t effect_kind,
    const uint8_t *key, uint16_t key_len,
    const uint8_t *value, uint32_t value_len);

/**
 * The compiled adapter descriptor.
 *
 * Registered as a field of the runtime descriptor
 * (nodus_domain_runtime_t.adapter), so it resolves ONLY through the
 * five-axis exact-tuple runtime lookup — no name, no path, no id of its
 * own, no fallback. It contains NO SQL and no schema strings; only the
 * compiled probe/mutate code may hold prepared statements over the
 * domain's own tables.
 */
typedef struct nodus_domain_adapter {
    uint32_t adapter_version;       /* NODUS_DOMAIN_ADAPTER_V1 == 1         */
    const nodus_adapter_op_t *ops;  /* n_ops entries, STRICTLY ascending    */
    size_t n_ops;
    nodus_adapter_probe_fn  probe;  /* both mandatory                       */
    nodus_adapter_mutate_fn mutate;
} nodus_domain_adapter_t;

/**
 * Fail-closed op lookup: exact `op_id` match in the ascending `ops[]`
 * array. NULL adapter, NULL ops, or an op that is not present all return
 * NULL — an unknown op never resolves to a "closest" or default one.
 *
 * Linear scan with an early stop on the first greater id (the same shape
 * as rt_owns_type in nodus_witness_runtime.c): `n_ops` is small compiled
 * data, and the scan order is fixed, so the result is deterministic.
 *
 * @return the descriptor or NULL.
 */
const nodus_adapter_op_t *nodus_adapter_op_lookup(
    const nodus_domain_adapter_t *ad, uint32_t op_id);

/**
 * Structural sanity of one compiled adapter — used by validate/apply and
 * directly testable:
 *   - `adapter_version` == NODUS_DOMAIN_ADAPTER_V1;
 *   - `ops` non-NULL with `n_ops` >= 1;
 *   - `ops` STRICTLY ascending by op_id (rejects descending AND duplicate
 *     ids, so one op_id can never resolve two ways);
 *   - `probe` and `mutate` both non-NULL;
 *   - every op: min <= max on both blob bounds, and both maxima within
 *     the codec caps (DNA_EFFECT_MAX_KEY_LEN / DNA_EFFECT_MAX_VALUE_LEN);
 *   - every op: `allowed_kinds` nonzero and within NODUS_ADAPTER_KINDS_ALL,
 *     `allowed_preconds` nonzero and within NODUS_ADAPTER_PRECONDS_ALL —
 *     an op that permits no kind or no precondition is a dead op, and a
 *     mask with an undefined bit set is a mask this build cannot honour;
 *   - every op: the masks must be SATISFIABLE under the codec's
 *     CREATE <=> ABSENT biconditional — an allowed CREATE requires
 *     ABSENT allowed, allowed SET/DELETE require some EXISTS* allowed,
 *     and vice versa (an allowed tag with no compatible allowed kind is
 *     equally dead); an op allowing DELETE must have value_len_min == 0
 *     (the codec pins a DELETE's value_len to 0, so a nonzero floor
 *     would make every one of that op's DELETEs unshapeable). All these
 *     dead shapes fail in the DENY direction, but a compiled adapter
 *     must not SHIP believing it registered a path that can never fire.
 *
 * HONEST LABEL: a `key_len_min` of 0 passes (only the min <= max relation
 * and the maxima are judged). It is harmless rather than correct — the
 * codec's own floor is key_len >= 1, so such a bound can never be the
 * reason an effect is admitted; it simply is not a bound.
 *
 * @return 0 healthy, -1 on the first violation.
 */
int nodus_adapter_selfcheck(const nodus_domain_adapter_t *ad);

/**
 * THE shipped precondition decision: facts x (kind, tag, expected_*) ->
 * status. PURE — no storage, no witness, no adapter.
 *
 * Frozen decision table:
 *   - an illegal (kind, tag) pair, or an unknown kind / tag value ->
 *     ERR_PRECOND_FORM. This is defence in depth: the codec already
 *     rejects every illegal combination on the wire (7 of the 12 enum
 *     pairs are legal; every other pair of ANY two byte values rejects —
 *     effect_wire.h:86-99), so this branch is unreachable from a decoded
 *     view — it exists so a direct caller cannot invent one;
 *   - CREATE / ABSENT:            exists -> ERR_PRECOND_EXISTS, else OK;
 *   - SET|DELETE / EXISTS:       !exists -> ERR_PRECOND_MISSING, else OK;
 *   - SET|DELETE / EXISTS_VERSION:
 *        !exists                             -> ERR_PRECOND_MISSING;
 *        facts->version != expected_version  -> ERR_PRECOND_VERSION;
 *        otherwise OK;
 *   - SET|DELETE / EXISTS_VHASH:
 *        !exists                             -> ERR_PRECOND_MISSING;
 *        memcmp(facts->value_hash, expected_vhash, 64) != 0
 *                                            -> ERR_PRECOND_HASH;
 *        otherwise OK.
 *
 * `facts` NULL or a NULL `expected_vhash` under EXISTS_VHASH return
 * ERR_ARG (caller-side programming errors). `facts->exists` outside
 * {0, 1} returns ERR_STORAGE_FAULT: the probe said OK and then reported
 * a fact outside its contract, which means the COMPILED ADAPTER is
 * broken on this node — a node-local fault, never rounded to "absent"
 * and never turned into a verdict.
 *
 * The absence check comes BEFORE the version/hash comparison on purpose:
 * comparing against the fields of a row that does not exist would read
 * meaningless memory and could turn a missing row into a version verdict.
 */
nodus_adapter_status_t nodus_adapter_precond_eval(
    uint8_t effect_kind, uint8_t precond_tag,
    uint64_t expected_version,
    const uint8_t expected_vhash[DNA_EFFECT_HASH_LEN],
    const nodus_adapter_row_facts_t *facts);

/**
 * PURE generic validation of one decoded result against one RESOLVED
 * runtime. Touches NO storage, so it can never be the reason state moved.
 *
 * Order (first failure wins):
 *   1. `rt` non-NULL                                        -> ERR_ARG;
 *   2. `rt->adapter` present  -> ERR_NO_ADAPTER when absent (fail closed:
 *      there is no fallback adapter);
 *   3. adapter selfcheck      -> ERR_ARG when the compiled descriptor is
 *      malformed;
 *   4. the view is usable: non-NULL, NOT a rejected/zeroed view
 *      (`buf == NULL` is the rejected marker, effect_wire.h:269-272 —
 *      the count alone can never tell the two apart, because
 *      `effect_count == 0` is a perfectly VALID empty result, which
 *      validates vacuously), `result_version` accepted and
 *      `effect_count` within DNA_EFFECT_MAX_COUNT — all ERR_ARG
 *      (fail-closed against hand-built views);
 *   5. then per effect IN ORDER: both blob windows inside the view's
 *      declared buffer (ERR_ARG — the env_wire view_slice_ok defence in
 *      depth; a decode-produced view satisfies it by construction), op
 *      lookup (miss -> ERR_UNKNOWN_OP), kind allowed (ERR_KIND),
 *      precondition tag allowed AND the CREATE <=> ABSENT biconditional
 *      (ERR_PRECOND_FORM), key and value lengths inside the op's bounds
 *      (ERR_SHAPE).
 *
 * @param fail_index_out OPTIONAL. Set to the failing effect's index, and
 *        to 0 for every result-level reject (steps 1-4) and on success.
 */
nodus_adapter_status_t nodus_witness_v2_effects_validate(
    const struct nodus_domain_runtime *rt,
    const dna_effect_view_t *v,
    uint16_t *fail_index_out);

/**
 * Validate (exactly as above), then apply each effect IN CANONICAL ORDER
 * inside the CALLER's transaction: probe -> precond_eval -> mutate.
 *
 * The authoritative domain handed to probe and mutate is `rt->domain_id`
 * and NOTHING ELSE — no parameter exists through which a caller or a
 * result could supply a different one.
 *
 * FAILURE CONTRACT: the first failure returns its status with
 * *fail_index_out set to that effect's index. Effects already applied
 * STAY until the CALLER rolls back — this function never opens, commits
 * or rolls back a transaction (the S5 helper contract), so a caller that
 * applies outside a transaction keeps a partial result and that is the
 * caller's bug, not a silent repair here.
 *
 * A probe returning ERR_STORAGE_FAULT propagates AS a storage fault,
 * untranslated: it is never treated as `exists == 0` and never converted
 * into a precondition verdict.
 *
 * `w` may not be NULL (ERR_ARG).
 */
nodus_adapter_status_t nodus_witness_v2_effects_apply(
    struct nodus_witness *w,
    const struct nodus_domain_runtime *rt,
    const dna_effect_view_t *v,
    uint16_t *fail_index_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_ADAPTER_H */
