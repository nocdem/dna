/* DNA — Tendermint message log (T1), design §5.4 - §5.6.
 *
 * ONE log per height. Round slots are opened on demand and indexed BY ROUND
 * NUMBER, because Algorithm 1 reads more than the current round: line 28 reads
 * the PREVOTEs of an EARLIER round vr, and line 49 reads ANY round of this
 * height. Line 53's "empty message log" is therefore only ever performed at
 * the height boundary, from tm_core_start_height.
 *
 * Every iteration in this file walks the set in INDEX order, and the set is
 * strictly ascending by identity, so two nodes holding the same messages count
 * them in the same order (DG-1). There is no hash table anywhere.
 *
 * EQUIVOCATION — TWO SLOTS (design §5.4, the 2026-09-08 revision). The paper
 * is silent here because it leans on the "at most f faulty" assumption, so the
 * rule is a [JUDGMENT]. The same sender's second, DIFFERENT value for one
 * (h, r, type) is reported as evidence AND KEPT: it counts toward its own
 * value's threshold. At most TM_VOTE_SLOTS distinct values are held per
 * sender; a third is evidence only and is not stored. PROPOSAL keeps ONE slot
 * — a proposal is not counted toward any threshold, so a second one buys the
 * proposer nothing and is pure evidence.
 *
 * ONE SLOT COST LIVENESS, and this is what it looked like. Under first-arrival
 * wins, an honest node that happened to receive the equivocator's OTHER half
 * first could never complete, LOCALLY, the very quorum the other honest nodes
 * had already decided on: their count included the equivocator's vote for v,
 * this node's did not, and no later message could repair it — the slot was
 * taken forever. That is a permanent local stall, not a delay, and it was
 * measured at n = 4 (Codex C-2). CometBFT repairs it with the peerMaj23 hint:
 * a peer claiming "+2/3 exists for v" makes the node keep the conflicting vote
 * for v. T1 has no hint protocol; two slots reach the same state without one.
 *
 * TWO SLOTS DO NOT COST SAFETY. Counting is by DISTINCT SENDER: count(id) is
 * the number of senders holding a vote for id, each contributing at most 1 to
 * each id. Two quorums of q = floor(2n/3)+1 therefore intersect, AS SENDER
 * SETS, in at least 2q - n members — 2 at n = 4, 3 at n = 7, 4 at n = 10,
 * which is exactly f+1 in each case. At most f of them are Byzantine, so at
 * least ONE member of the intersection is honest, and an honest member votes
 * once per (h, r, type): it cannot appear in the quorums of two different
 * values. Two different values therefore cannot both reach a quorum in one
 * round. A member counted for BOTH values is by definition one of the <= f
 * faulty, which the intersection argument already budgets for.
 *
 * WHAT REMAINS ARRIVAL-ORDER DEPENDENT is only which of the two is reported to
 * the host as "first" (design §8, DG-5). The COUNT no longer depends on order,
 * which is precisely what one slot got wrong.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "../dna_consensus.h"
#include "tm_core.h"

static void round_free(tm_round_t *r)
{
    if (!r) return;
    free(r->prop_value);
    free(r->prevote);
    free(r->precommit);
    free(r->seen);
    free(r);
}

void tm_log_init(tm_log_t *log, uint64_t height, uint32_t n, size_t max_bytes)
{
    if (!log) return;
    memset(log, 0, sizeof(*log));
    log->height    = height;
    log->n         = n;
    log->max_bytes = max_bytes;
}

void tm_log_clear(tm_log_t *log)
{
    uint32_t i;
    if (!log) return;
    if (log->rounds) {
        for (i = 0; i < log->rounds_end; i++) round_free(log->rounds[i]);
        free(log->rounds);
    }
    log->rounds      = NULL;
    log->rounds_cap  = 0;
    log->rounds_end  = 0;
    log->value_bytes = 0;
}

tm_round_t *tm_log_round(tm_log_t *log, uint32_t round, int create)
{
    tm_round_t *r;

    if (!log) return NULL;
    if (round < log->rounds_end && log->rounds[round]) return log->rounds[round];
    if (!create) return NULL;

    if (round >= log->rounds_cap) {
        uint32_t want = log->rounds_cap ? log->rounds_cap : 8u;
        tm_round_t **grown;
        while (want <= round) {
            if (want > 0x40000000u) return NULL;   /* refuse rather than wrap */
            want *= 2u;
        }
        grown = (tm_round_t **)realloc(log->rounds, (size_t)want * sizeof(*grown));
        if (!grown) return NULL;
        memset(grown + log->rounds_cap, 0, (size_t)(want - log->rounds_cap) * sizeof(*grown));
        log->rounds     = grown;
        log->rounds_cap = want;
    }
    if (round >= log->rounds_end) log->rounds_end = round + 1u;

    r = (tm_round_t *)calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->prop_valid_round = -1;
    r->prevote   = (tm_vote_t *)calloc(log->n, sizeof(tm_vote_t));
    r->precommit = (tm_vote_t *)calloc(log->n, sizeof(tm_vote_t));
    r->seen      = (uint8_t *)calloc(log->n, 1);
    if (!r->prevote || !r->precommit || !r->seen) { round_free(r); return NULL; }

    log->rounds[round] = r;
    return r;
}

/* The byte cap (design §5.6) bounds only the PROPOSAL VALUE BYTES: identities
 * and votes stay, because dropping those would change what this node counts,
 * and therefore what it decides. Reclaiming a round's bytes means line 49 can
 * no longer fire LOCALLY for that round — the block still arrives through the
 * sync path, which is a T3 concern.
 *
 * The ORDER is a security property, not a tuning choice (red-team F1). Before
 * it, a single member who is the legitimate proposer of a FUTURE round could
 * fill the budget with cap-sized proposals and then watch the CURRENT round's
 * proposal be refused for lack of room — and because the proposer arms no
 * timeoutPropose, the starved proposer would sit in the round with nothing
 * logged and no timer, which is a liveness stop (G6), not a slowdown. */
static void drop_round_value(tm_log_t *log, uint32_t i)
{
    tm_round_t *r = (i < log->rounds_end) ? log->rounds[i] : NULL;
    if (!r || !r->prop_value) return;
    log->value_bytes -= r->prop_value_len;
    free(r->prop_value);
    r->prop_value     = NULL;
    r->prop_value_len = 0;
    r->prop_dropped   = 1;
}

int tm_log_reserve(tm_log_t *log, size_t need, uint32_t writing_round, uint32_t current_round)
{
    uint64_t i;

    if (!log) return -1;
    if (need > log->max_bytes) return -1;
    if (log->value_bytes + need <= log->max_bytes) return 0;

    /* A round two or more ahead reclaims NOTHING: nobody honest is proposing
     * that far in advance, so the only writer is an adversary and it must not
     * be able to evict anything. */
    if ((uint64_t)writing_round >= (uint64_t)current_round + 2u) return -1;

    if (writing_round == current_round + 1u) {
        /* The NEXT round's honest proposer enters its round before anyone else
         * and its proposal can reach this node before the timeout, so it must
         * be able to make room — but only from rounds already behind, never
         * from the round being voted in (red-team round 2, F3). */
        for (i = 0; i < (uint64_t)current_round && i < log->rounds_end; i++) {
            drop_round_value(log, (uint32_t)i);
            if (log->value_bytes + need <= log->max_bytes) return 0;
        }
        return (log->value_bytes + need <= log->max_bytes) ? 0 : -1;
    }

    /* writing_round <= current_round */
    /* 1. future rounds, HIGHEST downward (all strictly above the writer) */
    for (i = log->rounds_end; i > (uint64_t)current_round + 1u; ) {
        i--;
        drop_round_value(log, (uint32_t)i);
        if (log->value_bytes + need <= log->max_bytes) return 0;
    }
    /* 2. past rounds, OLDEST upward, strictly below the writing round */
    for (i = 0; i < (uint64_t)writing_round && i < log->rounds_end; i++) {
        drop_round_value(log, (uint32_t)i);
        if (log->value_bytes + need <= log->max_bytes) return 0;
    }
    return (log->value_bytes + need <= log->max_bytes) ? 0 : -1;
}

int tm_log_put_proposal(tm_log_t *log, uint32_t round, uint32_t sender_idx,
                        const uint8_t value_id[DNA_CONSENSUS_VALUE_ID_LEN],
                        int32_t valid_round, const uint8_t *value, size_t len,
                        uint32_t current_round,
                        uint8_t first_id[DNA_CONSENSUS_VALUE_ID_LEN], int32_t *first_vr)
{
    tm_round_t *r;
    uint8_t *copy;

    if (!log || !value_id || !value || len == 0) return TM_PUT_ERR;
    if (sender_idx >= log->n) return TM_PUT_ERR;

    r = tm_log_round(log, round, 1);
    if (!r) return TM_PUT_ERR;

    if (r->prop_have) {
        if (first_id) memcpy(first_id, r->prop_value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        if (first_vr) *first_vr = r->prop_valid_round;
        if (memcmp(r->prop_value_id, value_id, DNA_CONSENSUS_VALUE_ID_LEN) != 0) return TM_PUT_EQUIV;
        if (!r->prop_dropped) return TM_PUT_DUP;

        /* REHYDRATION (design §5.6, Codex C-3). The bytes for THIS id were
         * reclaimed by the cap; the same proposal arriving again is the only
         * local way to get them back, and without it line 49 could never fire
         * for that round again — a late but complete commit would be
         * undecidable locally and would have to wait for the sync path. The
         * identity is unchanged, so nothing about what this node counted
         * moves; only the bytes come back. A DIFFERENT id is still evidence. */
        if (tm_log_reserve(log, len, round, current_round) != 0) return TM_PUT_DUP;
        copy = (uint8_t *)malloc(len);
        if (!copy) return TM_PUT_ERR;
        memcpy(copy, value, len);
        r->prop_value     = copy;
        r->prop_value_len = len;
        r->prop_dropped   = 0;
        log->value_bytes += len;
        return TM_PUT_LOGGED;
    }

    if (tm_log_reserve(log, len, round, current_round) != 0) {
        return TM_PUT_DUP;                              /* out of budget: ignored, rc 1 */
    }
    copy = (uint8_t *)malloc(len);
    if (!copy) return TM_PUT_ERR;
    memcpy(copy, value, len);

    r->prop_have        = 1;
    r->prop_dropped     = 0;
    r->prop_valid_memo  = (uint8_t)TM_VALID_UNKNOWN;
    r->prop_valid_round = valid_round;
    r->prop_sender      = sender_idx;
    r->prop_value       = copy;
    r->prop_value_len   = len;
    memcpy(r->prop_value_id, value_id, DNA_CONSENSUS_VALUE_ID_LEN);
    log->value_bytes += len;

    if (!r->seen[sender_idx]) { r->seen[sender_idx] = 1; r->n_seen++; }
    return TM_PUT_LOGGED;
}

int tm_log_put_vote(tm_log_t *log, uint32_t round, uint32_t sender_idx, int is_precommit,
                    const uint8_t value_id[DNA_CONSENSUS_VALUE_ID_LEN],
                    uint8_t first_id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    tm_round_t *r;
    tm_vote_t  *slot;
    uint8_t     k;

    if (!log || !value_id) return TM_PUT_ERR;
    if (sender_idx >= log->n) return TM_PUT_ERR;

    r = tm_log_round(log, round, 1);
    if (!r) return TM_PUT_ERR;

    slot = is_precommit ? &r->precommit[sender_idx] : &r->prevote[sender_idx];

    /* Slot 0 is the first value seen from this sender and stays the one the
     * host is told about as "first"; it is written before the outcome is
     * known, so it is set on the DUP path as well as the EQUIV path. */
    if (slot->n > 0 && first_id) {
        memcpy(first_id, slot->value_id[0], DNA_CONSENSUS_VALUE_ID_LEN);
    }
    for (k = 0; k < slot->n; k++) {
        if (memcmp(slot->value_id[k], value_id, DNA_CONSENSUS_VALUE_ID_LEN) == 0) return TM_PUT_DUP;
    }
    /* A third distinct value is evidence only. Storing it would let one sender
     * hold a slot for every value in flight, which is exactly the unbounded
     * per-sender growth the slot count is there to stop. */
    if (slot->n >= TM_VOTE_SLOTS) return TM_PUT_EQUIV;

    memcpy(slot->value_id[slot->n], value_id, DNA_CONSENSUS_VALUE_ID_LEN);
    slot->n++;

    /* n_prevote / n_precommit are the "*" counts of Algorithm 1 lines 34, 47
     * and 55 — DISTINCT SENDERS — so only a sender's FIRST vote moves them. A
     * second value comes from a sender that is already in the count. */
    if (slot->n == 1) {
        if (is_precommit) r->n_precommit++; else r->n_prevote++;
    }
    if (!r->seen[sender_idx]) { r->seen[sender_idx] = 1; r->n_seen++; }

    /* Stored AND counted for its own value, and still evidence: rc 2 here does
     * not mean "dropped", and the caller must re-run the rules (tm_core.h). */
    return (slot->n == 1) ? TM_PUT_LOGGED : TM_PUT_EQUIV;
}

/* Threshold counting is a count of DISTINCT SENDERS. With two slots a sender
 * can hold votes for two different values and contributes 1 to EACH of them,
 * never 2 to one: a repeat of a value already in a slot is a duplicate and is
 * never stored twice, and the inner loop stops at the first match. `value_id
 * == NULL` is Algorithm 1's "*". Weights are not consulted: the DNA
 * instantiation is one member, one vote (design §5.3). */
uint32_t tm_log_count_votes(const tm_round_t *r, uint32_t n, int is_precommit,
                            const uint8_t *value_id)
{
    const tm_vote_t *v;
    uint32_t i, count = 0;
    uint8_t  k;

    if (!r) return 0;
    v = is_precommit ? r->precommit : r->prevote;
    if (!v) return 0;
    if (!value_id) return is_precommit ? r->n_precommit : r->n_prevote;
    for (i = 0; i < n; i++) {
        for (k = 0; k < v[i].n; k++) {
            if (memcmp(v[i].value_id[k], value_id, DNA_CONSENSUS_VALUE_ID_LEN) == 0) {
                count++;
                break;
            }
        }
    }
    return count;
}
