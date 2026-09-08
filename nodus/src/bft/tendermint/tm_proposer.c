/* DNA — Tendermint proposer selection (T1), design §6.
 *
 * A line-by-line C port of the CometBFT weighted round-robin priority counter
 * pinned at cometbft@709fd12b:
 *
 *   types/validator_set.go:32       PriorityWindowSizeFactor = 2
 *   types/validator_set.go:77-89    NewValidatorSet          -> tm_proposer_create
 *   types/validator_set.go:131-153  IncrementProposerPriority-> increment_times
 *   types/validator_set.go:158-179  RescalePriorities        -> rescale
 *   types/validator_set.go:181-192  incrementProposerPriority-> increment_once
 *   types/validator_set.go:196-209  computeAvgProposerPriority-> compute_avg
 *   types/validator_set.go:211-231  computeMaxMinPriorityDiff-> max_min_diff
 *   types/validator_set.go:233-239  getValWithMostPriority   -> most_priority
 *   types/validator_set.go:241-249  shiftByAvgProposerPriority-> shift_by_avg
 *   types/validator_set.go:59,:152  the stored `Proposer` field-> proposer_idx
 *   types/validator_set.go:512-533  computeNewPriorities     -> tm_proposer_next_height
 *   types/validator_set.go:624-676  updateWithChangeSet      -> tm_proposer_next_height
 *   types/validator.go:65-85        CompareProposerPriority  -> most_priority tie-break
 *   consensus/state.go:1071-1075    enterNewRound            -> tm_proposer_at
 *   state/execution.go:608,617      updateState              -> tm_proposer_next_height
 *
 * TWO DIVISIONS, TWO SEMANTICS (design §6.1) — this is the single subtlety of
 * the whole module:
 *
 *   RescalePriorities (:172-178) uses Go's `/` on int64, which TRUNCATES
 *   TOWARD ZERO. C's `/` does the same (C99 6.5.5p6), so a plain `/` is the
 *   faithful port.
 *
 *   computeAvgProposerPriority (:196-209) sums into math/big and divides with
 *   `Int.Div`, which is EUCLIDEAN — go1.22.0 math/big/int.go:299-302 says so
 *   in as many words ("Div implements Euclidean division (unlike Go)"), and
 *   cometbft's go.mod pins go 1.22.11. For a positive divisor Euclidean
 *   division is FLOOR, which is NOT C's `/`. floor_div() below is that step.
 *
 *   The consequence is visible in the reference document's own worked example:
 *   proposer-selection.md's "New Validator" table computes avg = -4 for
 *   sum = -13, n = 3 (truncation), while the pinned CODE computes -5 (floor).
 *   THE DNA RULE IS THE PINNED CODE. test_tm_proposer §C carries the
 *   code-path numbers and §C-neg re-runs the same step with truncation to
 *   prove the two really differ.
 *
 * Weights: the DNA path passes weights == NULL, i.e. every member has weight
 * 1. General int64 weights are supported only so the reference KATs can be
 * replayed. Saturation (safeAddClip/safeSubClip, :1011-1031) is UNREACHABLE at
 * n <= 128 with weight 1; instead of clipping — which would silently change
 * the proposer sequence — this module REFUSES with -1 past TM_PRIO_ABS_BOUND.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "../dna_consensus.h"
#include "tm_core.h"
#include "dnac/ledger_ids.h"   /* DNA_MAX_ACTIVE_VALIDATORS */

struct tm_proposer {
    uint32_t n;
    uint8_t (*ids)[DNA_CONSENSUS_ID_LEN];   /* owned copy, strictly ascending */
    int64_t *vp;                            /* voting power, > 0 */
    int64_t *prio;                          /* accumulated priority A(i) */
    int64_t  total_vp;                      /* P = sum(vp) */
    uint32_t proposer_idx;                  /* validator_set.go:59 `Proposer` */
    int      weights_given;                 /* the set was created WITH explicit weights */
};

/* ── arithmetic helpers ───────────────────────────────────────────────── */

/* Euclidean division for a POSITIVE divisor == floor.
 * go1.22.0 math/big/int.go:299-302 (Int.Div). */
static int64_t floor_div(int64_t a, int64_t n)
{
    int64_t q = a / n;
    if ((a % n) != 0 && a < 0) q--;
    return q;
}

static int prio_in_bounds(int64_t v)
{
    return (v < TM_PRIO_ABS_BOUND) && (v > -TM_PRIO_ABS_BOUND);
}

/* computeMaxMinPriorityDiff (validator_set.go:211-231). */
static int64_t max_min_diff(const int64_t *prio, uint32_t n)
{
    int64_t mx = prio[0], mn = prio[0];
    uint32_t i;
    for (i = 1; i < n; i++) {
        if (prio[i] < mn) mn = prio[i];
        if (prio[i] > mx) mx = prio[i];
    }
    {
        int64_t diff = mx - mn;
        return diff < 0 ? -diff : diff;
    }
}

/* RescalePriorities (validator_set.go:158-179). Go's `/` truncates toward
 * zero and so does C's — deliberately NOT floor_div here. */
static void rescale(int64_t *prio, uint32_t n, int64_t diff_max)
{
    int64_t diff, ratio;
    uint32_t i;

    if (diff_max <= 0) return;                       /* :167-169 sanity check */
    diff = max_min_diff(prio, n);
    ratio = (diff + diff_max - 1) / diff_max;        /* :173 ceil(diff/diffMax) */
    if (diff > diff_max) {                           /* :174 */
        for (i = 0; i < n; i++) prio[i] /= ratio;    /* :176 truncating */
    }
}

/* computeAvgProposerPriority (:196-209) + shiftByAvgProposerPriority
 * (:241-249). The Go sum is arbitrary precision; here the TM_PRIO_ABS_BOUND
 * refusal keeps |sum| <= 128 * 2^40 = 2^47, far inside int64, so a plain int64
 * accumulator is exact rather than merely convenient. */
static int shift_by_avg(int64_t *prio, uint32_t n)
{
    int64_t sum = 0, avg;
    uint32_t i;

    for (i = 0; i < n; i++) {
        if (!prio_in_bounds(prio[i])) return -1;
        sum += prio[i];
    }
    avg = floor_div(sum, (int64_t)n);                /* Int.Div == floor */
    for (i = 0; i < n; i++) {
        prio[i] -= avg;
        if (!prio_in_bounds(prio[i])) return -1;
    }
    return 0;
}

/* getValWithMostPriority (:233-239) with validator.go:65-85's tie-break:
 * higher priority wins, and on equality the LOWER address wins (memcmp over
 * the 32-byte id — DNA's stand-in for bytes.Compare). */
static uint32_t most_priority(const int64_t *prio, const uint8_t (*ids)[DNA_CONSENSUS_ID_LEN],
                              uint32_t n)
{
    uint32_t best = 0, i;
    for (i = 1; i < n; i++) {
        if (prio[i] > prio[best]) {
            best = i;
        } else if (prio[i] == prio[best] &&
                   memcmp(ids[i], ids[best], DNA_CONSENSUS_ID_LEN) < 0) {
            best = i;
        }
    }
    return best;
}

/* incrementProposerPriority (:181-192): A(i) += VP(i) for all i, then the
 * highest-priority member is elected and pushed back by P. */
static int increment_once(int64_t *prio, const int64_t *vp,
                          const uint8_t (*ids)[DNA_CONSENSUS_ID_LEN],
                          uint32_t n, int64_t total_vp, uint32_t *out_prop)
{
    uint32_t i, best;
    for (i = 0; i < n; i++) {
        prio[i] += vp[i];                            /* :184 safeAddClip -> refuse instead */
        if (!prio_in_bounds(prio[i])) return -1;
    }
    best = most_priority(prio, ids, n);              /* :188 */
    prio[best] -= total_vp;                          /* :190 safeSubClip -> refuse instead */
    if (!prio_in_bounds(prio[best])) return -1;
    *out_prop = best;
    return 0;
}

/* IncrementProposerPriority(times) (:131-153): rescale, centre, then `times`
 * elections; the proposer is the one the LAST election picked. */
static int increment_times(int64_t *prio, const int64_t *vp,
                           const uint8_t (*ids)[DNA_CONSENSUS_ID_LEN],
                           uint32_t n, int64_t total_vp, uint32_t times,
                           uint32_t *out_prop)
{
    uint32_t t, prop = 0;

    if (times == 0) return -1;                       /* :138-140 panics on times <= 0 */
    rescale(prio, n, 2 * total_vp);                  /* :143, PriorityWindowSizeFactor = 2 */
    if (shift_by_avg(prio, n) != 0) return -1;       /* :144 */
    for (t = 0; t < times; t++) {                    /* :148 election loop */
        if (increment_once(prio, vp, ids, n, total_vp, &prop) != 0) return -1;
    }
    *out_prop = prop;                                /* :152 vals.Proposer = proposer */
    return 0;
}

/* ── set validation / construction ────────────────────────────────────── */

static int vset_check(const dna_vset_t *set)
{
    uint32_t i;
    if (!set || set->n == 0 || !set->ids) return -1;
    if (set->n > (uint32_t)DNA_MAX_ACTIVE_VALIDATORS) return -1;
    for (i = 1; i < set->n; i++) {
        if (memcmp(set->ids[i - 1], set->ids[i], DNA_CONSENSUS_ID_LEN) >= 0) return -1;
    }
    if (set->weights) {
        for (i = 0; i < set->n; i++) {
            if (set->weights[i] <= 0) return -1;
            if (!prio_in_bounds(set->weights[i])) return -1;
        }
    }
    return 0;
}

static void proposer_free(tm_proposer_t *p)
{
    if (!p) return;
    free(p->ids);
    free(p->vp);
    free(p->prio);
    free(p);
}

static tm_proposer_t *proposer_alloc(const dna_vset_t *set)
{
    tm_proposer_t *p;
    uint32_t i;
    int64_t total = 0;

    p = (tm_proposer_t *)calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->n = set->n;
    p->ids  = (uint8_t (*)[DNA_CONSENSUS_ID_LEN])calloc(set->n, DNA_CONSENSUS_ID_LEN);
    p->vp   = (int64_t *)calloc(set->n, sizeof(int64_t));
    p->prio = (int64_t *)calloc(set->n, sizeof(int64_t));
    if (!p->ids || !p->vp || !p->prio) { proposer_free(p); return NULL; }

    memcpy(p->ids, set->ids, (size_t)set->n * DNA_CONSENSUS_ID_LEN);
    for (i = 0; i < set->n; i++) {
        p->vp[i] = set->weights ? set->weights[i] : 1;
        total += p->vp[i];
        if (!prio_in_bounds(total)) { proposer_free(p); return NULL; }
    }
    p->total_vp = total;
    p->weights_given = set->weights ? 1 : 0;
    p->proposer_idx = 0;
    return p;
}

/* ── public API ───────────────────────────────────────────────────────── */

/* NewValidatorSet (:77-89): updateWithChangeSet on an EMPTY set — every member
 * is an addition and therefore gets the -1.125*P entry penalty (:531) — then
 * rescale + centre (:671-672), then IncrementProposerPriority(1) (:87). */
int tm_proposer_create(tm_proposer_t **out, const dna_vset_t *genesis_set)
{
    tm_proposer_t *p;
    uint32_t i;
    int64_t penalty;

    if (!out) return -1;
    *out = NULL;
    if (vset_check(genesis_set) != 0) return -1;

    p = proposer_alloc(genesis_set);
    if (!p) return -1;

    /* computeNewPriorities (:512-533): the updated total voting power BEFORE
     * removals — for an empty starting set that is simply P. */
    penalty = -(p->total_vp + (p->total_vp >> 3));
    for (i = 0; i < p->n; i++) p->prio[i] = penalty;

    rescale(p->prio, p->n, 2 * p->total_vp);
    if (shift_by_avg(p->prio, p->n) != 0) { proposer_free(p); return -1; }
    if (increment_times(p->prio, p->vp, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])p->ids,
                        p->n, p->total_vp, 1, &p->proposer_idx) != 0) {
        proposer_free(p);
        return -1;
    }
    *out = p;
    return 0;
}

void tm_proposer_destroy(tm_proposer_t *p) { proposer_free(p); }

int tm_proposer_set_equals(const tm_proposer_t *p, const dna_vset_t *set)
{
    uint32_t i;
    if (!p || !set) return 0;
    if (p->n != set->n) return 0;
    if (memcmp(p->ids, set->ids, (size_t)set->n * DNA_CONSENSUS_ID_LEN) != 0) return 0;
    for (i = 0; i < set->n; i++) {
        int64_t w = set->weights ? set->weights[i] : 1;
        if (p->vp[i] != w) return 0;
    }
    return 1;
}

/* updateWithChangeSet (:624-676) followed by IncrementProposerPriority(1)
 * (execution.go:608 then :617). When the change set is EMPTY, Go's
 * updateWithChangeSet returns at :629 without rescaling or centring, and
 * execution.go only calls it at all when len(validatorUpdates) > 0 — so an
 * unchanged set performs the increment ALONE, exactly as here.
 *
 * When it is not empty, the centring runs TWICE: once at :672 and once inside
 * IncrementProposerPriority at :148. That is what the code does and it is NOT
 * collapsed into a single pass. */
int tm_proposer_next_height(tm_proposer_t *p, const dna_vset_t *set_for_next)
{
    uint32_t i, j;
    int64_t  tvp_after_updates_before_removals;
    int64_t  new_total = 0, penalty;
    uint8_t (*new_ids)[DNA_CONSENSUS_ID_LEN] = NULL;
    int64_t *new_vp = NULL, *new_prio = NULL;
    int rc = -1;

    if (!p) return -1;
    if (vset_check(set_for_next) != 0) return -1;

    if (tm_proposer_set_equals(p, set_for_next)) {
        return increment_times(p->prio, p->vp,
                               (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])p->ids,
                               p->n, p->total_vp, 1, &p->proposer_idx);
    }

    /* verifyUpdates (:462-488): tvpAfterUpdatesBeforeRemovals = P_old plus the
     * per-update delta (new power, or new-minus-old for an existing member).
     * Removals are deliberately NOT subtracted — that is the whole point of
     * the name, and it is what a joiner's penalty is measured against. */
    tvp_after_updates_before_removals = p->total_vp;
    for (i = 0; i < set_for_next->n; i++) {
        int64_t w = set_for_next->weights ? set_for_next->weights[i] : 1;
        int64_t old_w = 0;
        for (j = 0; j < p->n; j++) {
            if (memcmp(p->ids[j], set_for_next->ids[i], DNA_CONSENSUS_ID_LEN) == 0) {
                old_w = p->vp[j];
                break;
            }
        }
        tvp_after_updates_before_removals += (w - old_w);
        if (!prio_in_bounds(tvp_after_updates_before_removals)) return -1;
    }
    penalty = -(tvp_after_updates_before_removals + (tvp_after_updates_before_removals >> 3));

    new_ids  = (uint8_t (*)[DNA_CONSENSUS_ID_LEN])calloc(set_for_next->n, DNA_CONSENSUS_ID_LEN);
    new_vp   = (int64_t *)calloc(set_for_next->n, sizeof(int64_t));
    new_prio = (int64_t *)calloc(set_for_next->n, sizeof(int64_t));
    if (!new_ids || !new_vp || !new_prio) goto done;

    memcpy(new_ids, set_for_next->ids, (size_t)set_for_next->n * DNA_CONSENSUS_ID_LEN);
    for (i = 0; i < set_for_next->n; i++) {
        int found = 0;
        new_vp[i] = set_for_next->weights ? set_for_next->weights[i] : 1;
        new_total += new_vp[i];
        for (j = 0; j < p->n; j++) {
            if (memcmp(p->ids[j], set_for_next->ids[i], DNA_CONSENSUS_ID_LEN) == 0) {
                /* computeNewPriorities :527-528 — an EXISTING member keeps its
                 * accumulated priority, even when its weight changed. */
                new_prio[i] = p->prio[j];
                found = 1;
                break;
            }
        }
        if (!found) new_prio[i] = penalty;            /* :531 -(P' + P'>>3) */
    }
    if (!prio_in_bounds(new_total)) goto done;

    /* :671-672 — scale and centre against the RESULTING set. */
    rescale(new_prio, set_for_next->n, 2 * new_total);
    if (shift_by_avg(new_prio, set_for_next->n) != 0) goto done;

    /* execution.go:617 — one increment per height, AFTER the set change. */
    {
        uint32_t prop = 0;
        if (increment_times(new_prio, new_vp,
                            (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])new_ids,
                            set_for_next->n, new_total, 1, &prop) != 0) goto done;
        free(p->ids); free(p->vp); free(p->prio);
        p->ids = new_ids; p->vp = new_vp; p->prio = new_prio;
        new_ids = NULL; new_vp = NULL; new_prio = NULL;
        p->n = set_for_next->n;
        p->total_vp = new_total;
        p->proposer_idx = prop;
        p->weights_given = set_for_next->weights ? 1 : 0;
    }
    rc = 0;

done:
    free(new_ids); free(new_vp); free(new_prio);
    return rc;
}

/* enterNewRound (consensus/state.go:1071-1075): for round r the set is COPIED
 * and incremented (r - round_p) times; at round 0 nothing is incremented and
 * GetProposer returns the stored Proposer. `p` is never modified.
 *
 * DNA's definition is PATH-INDEPENDENT and that is a deliberate difference
 * (design §6.1). CometBFT KEEPS the advanced set (state.go:1081
 * `cs.Validators = validators`) and moves to the next round by the DELTA, so a
 * node that jumps 0 -> 2 runs Increment(2) while one that walks 0 -> 1 -> 2
 * runs Increment(1) twice — a different number of rescale/centre passes, hence
 * in principle a different answer for weighted sets. DNA computes proposer(h,
 * r) as Increment(r) from S_h ALWAYS: same S_h and same r give the same
 * proposer whatever route the node took to get there (DG-2). At weight 1 the
 * two definitions coincide — the priority sum stays 0 across increments so
 * centring subtracts nothing, and diff <= n <= 2P so rescaling never triggers
 * — which is what test_tm_proposer §D-c pins. Cost is O(round x n), bounded
 * per message by the lookahead; a cache is a T3 option if measurement asks. */
int tm_proposer_index_at(const tm_proposer_t *p, uint32_t round, uint32_t *out_idx)
{
    int64_t copy[DNA_MAX_ACTIVE_VALIDATORS];
    uint32_t prop = 0;

    if (!p || !out_idx) return -1;
    if (p->n == 0 || p->n > (uint32_t)DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (round == 0) { *out_idx = p->proposer_idx; return 0; }

    memcpy(copy, p->prio, (size_t)p->n * sizeof(int64_t));
    if (increment_times(copy, p->vp, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])p->ids,
                        p->n, p->total_vp, round, &prop) != 0) return -1;
    *out_idx = prop;
    return 0;
}

int tm_proposer_at(const tm_proposer_t *p, uint32_t round, uint8_t out[DNA_CONSENSUS_ID_LEN])
{
    uint32_t idx = 0;
    if (!p || !out) return -1;
    if (tm_proposer_index_at(p, round, &idx) != 0) return -1;
    memcpy(out, p->ids[idx], DNA_CONSENSUS_ID_LEN);
    return 0;
}

/* S_h is a TRIPLE. The elected proposer index leaves with the vector because
 * the election ends with A(prop) -= P, which means the maximum of the exported
 * vector is no longer the member that was elected (validator_set.go:190) and
 * round 0 is therefore not recoverable from the numbers alone. */
int tm_proposer_export(const tm_proposer_t *p, dna_vset_t *set_out, int64_t *prio_out, uint32_t cap,
                       uint32_t *proposer_idx_out)
{
    if (!p || !set_out || !prio_out || !proposer_idx_out) return -1;
    if (cap < p->n) return -1;
    set_out->n       = p->n;
    set_out->ids     = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])p->ids;
    set_out->weights = p->weights_given ? p->vp : NULL;
    memcpy(prio_out, p->prio, (size_t)p->n * sizeof(int64_t));
    *proposer_idx_out = p->proposer_idx;
    return 0;
}

/* The imported object IS S_h for EVERY round, round 0 included: rounds >= 1
 * are a function of (set, weights, priority vector) through
 * IncrementProposerPriority, and round 0 is the index carried here.
 *
 * There is deliberately NO findProposer fallback (validator_set.go:351-359).
 * That path answers a DIFFERENT question — who WOULD be picked from this
 * vector, not who WAS picked — and taking it silently would reintroduce the
 * very divergence the index exists to remove. An out-of-range index is an
 * error, not something to repair. */
int tm_proposer_import(tm_proposer_t **out, const dna_vset_t *set, const int64_t *prio,
                       uint32_t proposer_idx)
{
    tm_proposer_t *p;
    uint32_t i;

    if (!out) return -1;
    *out = NULL;
    if (!prio) return -1;
    if (vset_check(set) != 0) return -1;
    if (proposer_idx >= set->n) return -1;

    p = proposer_alloc(set);
    if (!p) return -1;
    for (i = 0; i < set->n; i++) {
        if (!prio_in_bounds(prio[i])) { proposer_free(p); return -1; }
        p->prio[i] = prio[i];
    }
    p->proposer_idx = proposer_idx;
    *out = p;
    return 0;
}

int tm_proposer_clone(const tm_proposer_t *p, tm_proposer_t **out)
{
    tm_proposer_t *c;
    dna_vset_t set;

    if (!p || !out) return -1;
    *out = NULL;
    set.n = p->n;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])p->ids;
    set.weights = p->vp;
    c = proposer_alloc(&set);
    if (!c) return -1;
    memcpy(c->prio, p->prio, (size_t)p->n * sizeof(int64_t));
    c->proposer_idx = p->proposer_idx;
    c->weights_given = p->weights_given;
    *out = c;
    return 0;
}
