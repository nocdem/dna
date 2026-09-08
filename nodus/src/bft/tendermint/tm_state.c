/* DNA — Tendermint state machine (T1): Algorithm 1 lines 1-67.
 *
 * Reference: arXiv:1807.04938v3, Algorithm 1 (PDF SHA-256 1225e75c...), read
 * line by line against consensus.tex @ 709fd12b. Every "upon" clause of the
 * paper is one function here and the mapping is one-to-one:
 *
 *   1-9    state variables            struct tm_core fields
 *   10     upon start                 tm_core_start_height (the HOST calls it)
 *   11-21  StartRound(round)          tm_start_round
 *   22-27  PROPOSAL, vr = -1          rule_l22
 *   28-33  PROPOSAL + 2f+1 PREVOTE@vr rule_l28
 *   34-35  2f+1 PREVOTE, first time   rule_l34
 *   36-43  PROPOSAL + 2f+1 PREVOTE@r  rule_l36
 *   44-46  2f+1 PREVOTE nil           rule_l44
 *   47-48  2f+1 PRECOMMIT, first time rule_l47
 *   49-54  PROPOSAL + 2f+1 PRECOMMIT  rule_l49  (52-54 = the D-4 deviation)
 *   55-56  f+1 at a higher round      rule_l55
 *   57-60  OnTimeoutPropose           tm_on_timeout, TM_STEP_PROPOSE
 *   61-64  OnTimeoutPrevote           tm_on_timeout, TM_STEP_PREVOTE
 *   65-67  OnTimeoutPrecommit         tm_on_timeout, TM_STEP_PRECOMMIT
 *
 * DNA instantiation (design §5.3): the paper presents n = 3f+1 and writes
 * "2f+1" and "f+1"; DNA runs a general n, so those are dna_bft_quorum(n) and
 * dna_bft_f_plus_one(n) from the single shared source, dnac/ledger_ids.h. f is
 * NEVER re-derived from n - quorum (DG-3).
 *
 * Determinism (design §8): rules are evaluated in ONE fixed order (§5.8),
 * every walk over voters is in validator-set index order, the set is strictly
 * ascending by identity, there is no hash table, and the only clock is the
 * now_ms parameter (DG-4). Two cores fed the same inputs in the same order
 * produce the same emit/decide sequence and the same snapshot.
 *
 * Lines 52-54 are the ONE deliberate deviation (design §5.7, decision D-4):
 * after decide() the core is IDLE — it arms no timer and opens no round. The
 * HOST performs its inter-block wait and calls tm_core_start_height for h+1,
 * which is where the log is emptied, the locks are reset and the h+1 buffer is
 * drained.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "../dna_consensus.h"
#include "tm_core.h"
#include "dnac/ledger_ids.h"   /* dna_bft_quorum, dna_bft_f_plus_one, DNA_MAX_ACTIVE_VALIDATORS */

#define TM_NO_INDEX  0xFFFFFFFFu

/* A message held for the NEXT height (design §5.6). */
typedef struct tm_h1_msg {
    dna_cmsg_t  m;
    uint8_t    *value;      /* owned copy of the PROPOSAL bytes, or NULL */
} tm_h1_msg_t;

struct tm_core {
    dna_consensus_host_t host;
    tm_params_t          params;

    /* Algorithm 1 lines 2-9. */
    uint64_t  height;                                   /* h_p; 0 = no height open */
    uint32_t  round;                                    /* round_p */
    tm_step_t step;                                     /* step_p */
    int       decided;                                  /* decision_p[h_p] != nil */
    /* PERMANENT fault (design §5.9). An internal failure — an allocation, the
     * fixpoint guard, the proposer walk, the round ceiling — that happens AFTER
     * state has been mutated cannot be recovered from inside the core: the
     * obvious repair, re-opening the same height, would wipe the log and the
     * own vote slots and let this node vote twice in one round (G4). So the
     * core latches, every entry point refuses, and the host halts. FAULT is
     * not a VERDICT: nothing is decided, the node simply stops. */
    int       fault;
    uint8_t  *locked_value;  size_t locked_len;  int32_t locked_round;
    uint8_t   locked_id[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t  *valid_value;   size_t valid_len;   int32_t valid_round;
    uint8_t   valid_id[DNA_CONSENSUS_VALUE_ID_LEN];

    /* The governing set for this height. */
    uint32_t  n;
    uint8_t (*ids)[DNA_CONSENSUS_ID_LEN];
    uint32_t  self_idx;
    uint32_t  quorum;                                   /* "2f+1" */
    uint32_t  f_plus_one;                               /* "f+1" */
    tm_proposer_t *prop;                                /* private clone of S_h */
    uint8_t (*commit_scratch)[DNA_CONSENSUS_ID_LEN];    /* n entries */

    tm_log_t    log;
    tm_timers_t timers;

    /* h+1 buffer, with a (round, sender, type) seen-map: without it one member
     * can fill the buffer with repeats and blind this node to h+1 (design
     * §5.9). Sized (round_lookahead + 1) x n x 3. */
    tm_h1_msg_t *h1;
    uint32_t     h1_count, h1_cap;
    size_t       h1_bytes;
    uint8_t     *h1_seen;
    size_t       h1_seen_len;

    /* Observation. */
    uint32_t equivocations;
    uint8_t  last_prevote_id[DNA_CONSENSUS_VALUE_ID_LEN];   int32_t last_prevote_round;
    uint8_t  last_precommit_id[DNA_CONSENSUS_VALUE_ID_LEN]; int32_t last_precommit_round;

    int replay;      /* outward callbacks and timers suppressed */
};

static const uint8_t TM_NIL_ID[DNA_CONSENSUS_VALUE_ID_LEN] = { 0 };

static int is_nil_id(const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    return memcmp(id, TM_NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN) == 0;
}

static int tm_eval(tm_core_t *c, uint64_t now_ms);
static int tm_start_round(tm_core_t *c, uint32_t round, uint64_t now_ms);

/* ── set lookup ───────────────────────────────────────────────────────── */

/* Linear walk in index order. n <= 128 and the ids are strictly ascending, so
 * this is both cheap and order-stable; a map would not be (DG-1). */
static uint32_t set_index(const tm_core_t *c, const uint8_t id[DNA_CONSENSUS_ID_LEN])
{
    uint32_t i;
    for (i = 0; i < c->n; i++) {
        if (memcmp(c->ids[i], id, DNA_CONSENSUS_ID_LEN) == 0) return i;
    }
    return TM_NO_INDEX;
}

/* ── own messages (design §5.9) ───────────────────────────────────────── */

/* EVERY message this node sends — the PROPOSAL INCLUDED — is written to its
 * OWN log immediately before emit. That is not bookkeeping: the paper keeps
 * sent and received messages in one log (consensus.tex:182-184), and for the
 * proposer it is a LIVENESS REQUIREMENT. Line 20-21 means the proposer arms no
 * timeoutPropose, so if its own proposal were absent from its log, lines 22,
 * 28, 36 and 49 could never fire for it and it would never vote in its own
 * round. */
static void broadcast_vote(tm_core_t *c, int is_precommit, uint32_t round,
                           const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    dna_cmsg_t out;

    /* IN REPLAY THIS NODE'S OWN VOTES COME ONLY FROM THE WAL (design §5.9,
     * the structural answer to red-team round 2, F2). Rules and timeouts still
     * advance `step` while replaying, but they write NEITHER the own vote slot
     * NOR last_*: those are filled solely by replay_restore_own_vote from
     * `sender == self` records. The "persist then send" contract means every
     * vote this node actually sent before the crash IS in the WAL, so a
     * synthesised one is at best a duplicate and at worst OCCUPIES THE SLOT
     * the real record needs — which is how a genuine record ends up counted as
     * an equivocation against a vote the node never sent. A vote absent from
     * the WAL was never sent, and if a rule re-fires after replay_end it is
     * safe to send it then. */
    if (c->replay) return;

    /* G4 backstop (design §5.9): if ANY vote for this (round, type) already
     * stands in this node's OWN slot, nothing leaves, nothing is recorded and
     * last_* is not touched. The caller has already advanced step; the rule
     * still fires, only the outward vote is withheld.
     *
     * THE CHECK COMES BEFORE THE PUT, and that ordering is the whole point
     * under the two-slot rule (design §5.4). Relying on tm_log_put_vote's
     * return code was sufficient while a second value was discarded; now the
     * second value is STORED AND COUNTED, so putting first would write a vote
     * this node never signed into its own slot and then count itself toward
     * that value's threshold. One fabricated own vote turns a 2f+1 quorum into
     * 2f genuine ones and breaks the intersection argument that safety rests
     * on — locally, silently, and only on this node. The put below can no
     * longer return anything but LOGGED or ERR; it is kept as a guard. */
    {
        tm_round_t *own_slot = tm_log_round(&c->log, round, 1);
        const tm_vote_t *own;

        if (!own_slot || c->self_idx == TM_NO_INDEX) return;
        own = is_precommit ? &own_slot->precommit[c->self_idx]
                           : &own_slot->prevote[c->self_idx];
        if (own->n != 0) return;
    }
    if (tm_log_put_vote(&c->log, round, c->self_idx, is_precommit, id, NULL) != TM_PUT_LOGGED) {
        return;
    }

    if (is_precommit) {
        memcpy(c->last_precommit_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
        c->last_precommit_round = (int32_t)round;
    } else {
        memcpy(c->last_prevote_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
        c->last_prevote_round = (int32_t)round;
    }

    memset(&out, 0, sizeof(out));
    out.type        = is_precommit ? DNA_CMSG_PRECOMMIT : DNA_CMSG_PREVOTE;
    out.height      = c->height;
    out.round       = round;
    out.valid_round = -1;
    memcpy(out.sender, c->host.self, DNA_CONSENSUS_ID_LEN);
    memcpy(out.value_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
    c->host.emit(c->host.ctx, &out);
}

/* 0 = logged (and emitted unless replaying), -1 = NOT logged. The caller must
 * treat -1 as "this node did not propose": design §5.9 says StartRound then
 * falls to the non-proposer path and arms timeoutPropose, because a proposer
 * that arms no timer and has nothing in its own log can neither vote nor time
 * out — it just stops (G6). */
static int broadcast_proposal(tm_core_t *c, uint32_t round,
                              const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN],
                              const uint8_t *value, size_t len, int32_t vr)
{
    dna_cmsg_t out;
    tm_round_t *slot;

    if (len == 0 || len > c->params.max_value_bytes) return -1;
    if (tm_log_put_proposal(&c->log, round, c->self_idx, id, vr, value, len,
                            c->round, NULL, NULL) != TM_PUT_LOGGED) {
        return -1;   /* already have one for this round, or out of budget */
    }
    if (c->replay) return 0;

    slot = tm_log_round(&c->log, round, 0);
    memset(&out, 0, sizeof(out));
    out.type        = DNA_CMSG_PROPOSAL;
    out.height      = c->height;
    out.round       = round;
    out.valid_round = vr;
    memcpy(out.sender, c->host.self, DNA_CONSENSUS_ID_LEN);
    memcpy(out.value_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
    out.value     = slot ? slot->prop_value : NULL;
    out.value_len = slot ? slot->prop_value_len : 0;
    c->host.emit(c->host.ctx, &out);
    return 0;
}

/* ── valid() with memoisation and the FAULT semantics (design §5.5) ───── */

static int eval_valid(tm_core_t *c, tm_round_t *r)
{
    int rc;

    if (r->prop_valid_memo != (uint8_t)TM_VALID_UNKNOWN) return (int)r->prop_valid_memo;
    if (!r->prop_value) return TM_VALID_UNKNOWN;

    rc = c->host.valid(c->host.ctx, c->height, r->prop_value, r->prop_value_len, r->prop_value_id);
    if (rc == 1) { r->prop_valid_memo = (uint8_t)TM_VALID_YES; return TM_VALID_YES; }
    if (rc == 0) { r->prop_valid_memo = (uint8_t)TM_VALID_NO;  return TM_VALID_NO;  }
    /* -1 is a FAULT, not a verdict: the memo stays UNKNOWN, the rule does not
     * fire in THIS evaluation, and the next message or tick asks again. The
     * node casts neither an id nor a nil PREVOTE meanwhile; line 59's timeout
     * is what eventually carries it to nil. Only this node's liveness is
     * affected — no decision is produced either way. */
    return TM_VALID_UNKNOWN;
}

static int prop_usable(const tm_round_t *r)
{
    return r && r->prop_have && r->prop_value;
}

/* proposer(h, round), computed at most ONCE per (height, round) and cached in
 * the round slot (design §5.6, red-team F6). The walk is O(round x n), so
 * re-running it for every message is a CPU amplifier anyone in the set can
 * pull; the answer cannot change within a height because the proposer object
 * is a private clone the core never advances. */
static int round_proposer(tm_core_t *c, uint32_t round, uint32_t *out)
{
    tm_round_t *r = tm_log_round(&c->log, round, 1);

    if (!r) return -1;
    if (!r->proposer_known) {
        if (tm_proposer_index_at(c->prop, round, &r->proposer_idx) != 0) return -1;
        r->proposer_known = 1;
    }
    *out = r->proposer_idx;
    return 0;
}

/* ── StartRound, Algorithm 1 lines 11-21 ──────────────────────────────── */

/* Entering a round, THIS NODE'S OWN SLOTS decide the step (design §5.9,
 * red-team F4). The WAL's contract is APPEND ORDER, and that order can put
 * "own vote at r+1" BEFORE the timeout record that opens r+1 — the vote was
 * produced inside the same tick. Replayed that way the vote lands while
 * round_p is still r and only moves last_*; the timeout would then open r+1 at
 * step = propose, replay_end would arm timeoutPropose, and the timeout would
 * emit a nil vote for a round already voted in. THE CORE TOLERATES THAT ONE
 * REORDERING by reading its own slots on entry — it does not require the WAL
 * to be written in any particular order. In live mode the slots are empty on
 * entry and nothing changes.
 *
 * last_* moves FORWARD ONLY, the same discipline as replay_restore_own_vote:
 * entering round 1 must not drag last_prevote_round back from a round 5 vote
 * that is also in the WAL. The STEP is always taken from the round being
 * entered, because that is the round the state machine is now in. */
static void adopt_own_slots(tm_core_t *c, uint32_t round)
{
    tm_round_t *r = tm_log_round(&c->log, round, 0);

    if (!r || c->self_idx == TM_NO_INDEX || !r->prevote || !r->precommit) return;

    /* SLOT 0 ONLY, and under the host contract it is the only one there is
     * (design §5.4, §5.9). broadcast_vote refuses to write a second own value,
     * so nothing this node produces can fill slot 1; and a `sender == self`
     * record from the network reaches the log only after the HOST has verified
     * its signature (dna_consensus.h:3-4), so it can only be a vote this node
     * itself signed — and by G4 it signs at most one per (round, type). Slot 0
     * is therefore the vote this node actually cast. */
    if (r->prevote[c->self_idx].n > 0) {
        if ((int32_t)round > c->last_prevote_round) {
            memcpy(c->last_prevote_id, r->prevote[c->self_idx].value_id[0],
                   DNA_CONSENSUS_VALUE_ID_LEN);
            c->last_prevote_round = (int32_t)round;
        }
        if (c->step < TM_STEP_PREVOTE) c->step = TM_STEP_PREVOTE;
    }
    if (r->precommit[c->self_idx].n > 0) {
        if ((int32_t)round > c->last_precommit_round) {
            memcpy(c->last_precommit_id, r->precommit[c->self_idx].value_id[0],
                   DNA_CONSENSUS_VALUE_ID_LEN);
            c->last_precommit_round = (int32_t)round;
        }
        c->step = TM_STEP_PRECOMMIT;
    }
}

static int tm_start_round(tm_core_t *c, uint32_t round, uint64_t now_ms)
{
    uint32_t pidx = TM_NO_INDEX;

    /* The round counter never wraps: locked_round / valid_round / last_*_round
     * are int32 and a wrapped round would silently look OLDER than a lock
     * (design §5.6, red-team F7). Refusing halts the host, which is the
     * correct outcome for a height that has run 2^31 rounds. */
    if (round > TM_MAX_ROUND) return -1;

    c->round = round;                                   /* 12 */
    c->step  = TM_STEP_PROPOSE;                         /* 13 */

    if (round_proposer(c, round, &pidx) != 0) return -1;

    /* The round announcement is an OUTWARD event (D-10), so replay suppresses
     * it exactly as it suppresses emit. */
    if (!c->replay && c->host.on_round_start) {
        c->host.on_round_start(c->host.ctx, c->height, round, c->ids[pidx]);
    }

    /* In replay the proposal is NOT re-manufactured: the WAL carries this
     * node's own PROPOSAL record, and asking the host for a value again could
     * produce a different block than the one it already signed. */
    if (pidx == c->self_idx && !c->replay) {            /* 14 */
        uint8_t *value = NULL;
        size_t   len = 0;
        uint8_t  id[DNA_CONSENSUS_VALUE_ID_LEN];
        int32_t  vr = -1;
        int      have = 0;

        memset(id, 0, sizeof(id));
        if (c->valid_value) {                           /* 15-16 */
            memcpy(id, c->valid_id, DNA_CONSENSUS_VALUE_ID_LEN);
            have = (broadcast_proposal(c, round, id, c->valid_value,       /* 19 */
                                       c->valid_len, c->valid_round) == 0);
        } else if (c->host.get_value &&                 /* 17-18 */
                   c->host.get_value(c->host.ctx, c->height, &value, &len, id) == 0) {
            if (value && len > 0 && !is_nil_id(id)) {
                vr = c->valid_round;                    /* nil validValue => -1 */
                have = (broadcast_proposal(c, round, id, value, len, vr) == 0);   /* 19 */
            }
            /* Ownership passed to the core; the log keeps its own copy. */
            free(value);
        }
        if (have) { adopt_own_slots(c, round); return 0; }
        /* Either get_value said "no value this round" (design §5.2) or the
         * proposal did not fit the byte budget: EITHER WAY this node behaves
         * exactly like a non-proposer — it proposes nothing, arms
         * timeoutPropose and prevotes nil when that fires. */
    }

    adopt_own_slots(c, round);

    /* An own vote already standing for this round means the step has moved
     * past propose, and OnTimeoutPropose would be a no-op anyway. */
    if (!c->replay && c->step == TM_STEP_PROPOSE) {     /* 20-21 */
        tm_timers_schedule(&c->timers, TM_STEP_PROPOSE, c->height, round,
                           tm_deadline_ms(now_ms, tm_timeout_ms(&c->params, TM_STEP_PROPOSE, round)));
    }
    return 0;
}

/* ── the rules ────────────────────────────────────────────────────────── */

/* 55-56: f+1 messages of ANY type at a round STRICTLY GREATER than round_p,
 * counted as DISTINCT SENDERS (the proposer's PROPOSAL counts too).
 *
 * When several rounds qualify, the HIGHEST is taken — design §5.2, line 55 row
 * (the paper itself is silent). Taking the lowest reaches the same final round
 * (the rule fires again immediately) but first runs StartRound for every
 * intermediate round, emitting proposals and arming timers for rounds this
 * node already knows are behind: the same state with a strict superset of the
 * side effects. */
static int rule_l55(tm_core_t *c, uint64_t now_ms, int *fired)
{
    uint64_t rr;

    for (rr = c->log.rounds_end; rr > (uint64_t)c->round + 1u; ) {
        const tm_round_t *r;
        rr--;
        r = c->log.rounds[rr];
        if (r && r->n_seen >= c->f_plus_one) {
            *fired = 1;
            return tm_start_round(c, (uint32_t)rr, now_ms);      /* 56 */
        }
    }
    return 0;
}

/* 22-27 */
static int rule_l22(tm_core_t *c, int *fired)
{
    tm_round_t *r = tm_log_round(&c->log, c->round, 0);
    int v;

    if (c->step != TM_STEP_PROPOSE) return 0;
    if (!prop_usable(r)) return 0;
    if (r->prop_valid_round != -1) return 0;

    v = eval_valid(c, r);
    if (v == TM_VALID_UNKNOWN) return 0;

    /* 23: "lockedValue_p = v" is value equality; id(v) determines v, so the
     * 64-byte id is compared (design §4.1 — the core never sees enough of v to
     * compare it any other way). */
    c->step = TM_STEP_PREVOTE;                                   /* 27 */
    if (v == TM_VALID_YES &&
        (c->locked_round == -1 ||
         memcmp(c->locked_id, r->prop_value_id, DNA_CONSENSUS_VALUE_ID_LEN) == 0)) {
        broadcast_vote(c, 0, c->round, r->prop_value_id);        /* 24 */
    } else {
        broadcast_vote(c, 0, c->round, TM_NIL_ID);               /* 26 */
    }
    *fired = 1;
    return 0;
}

/* 28-33 */
static int rule_l28(tm_core_t *c, int *fired)
{
    tm_round_t *r = tm_log_round(&c->log, c->round, 0);
    tm_round_t *rv;
    int32_t vr;
    int v;

    if (c->step != TM_STEP_PROPOSE) return 0;
    if (!prop_usable(r)) return 0;
    vr = r->prop_valid_round;
    if (vr < 0 || (uint32_t)vr >= c->round) return 0;

    rv = tm_log_round(&c->log, (uint32_t)vr, 0);
    if (tm_log_count_votes(rv, c->n, 0, r->prop_value_id) < c->quorum) return 0;

    v = eval_valid(c, r);
    if (v == TM_VALID_UNKNOWN) return 0;

    c->step = TM_STEP_PREVOTE;                                   /* 33 */
    if (v == TM_VALID_YES &&
        (c->locked_round <= vr ||
         memcmp(c->locked_id, r->prop_value_id, DNA_CONSENSUS_VALUE_ID_LEN) == 0)) {
        broadcast_vote(c, 0, c->round, r->prop_value_id);        /* 30 */
    } else {
        broadcast_vote(c, 0, c->round, TM_NIL_ID);               /* 32 */
    }
    *fired = 1;
    return 0;
}

/* 34-35 */
static int rule_l34(tm_core_t *c, uint64_t now_ms, int *fired)
{
    tm_round_t *r = tm_log_round(&c->log, c->round, 0);

    if (c->step != TM_STEP_PREVOTE) return 0;
    if (!r || r->l34_fired) return 0;
    if (tm_log_count_votes(r, c->n, 0, NULL) < c->quorum) return 0;

    r->l34_fired = 1;                                            /* "for the first time" */
    if (!c->replay) {
        tm_timers_schedule(&c->timers, TM_STEP_PREVOTE, c->height, c->round,
                           tm_deadline_ms(now_ms, tm_timeout_ms(&c->params, TM_STEP_PREVOTE, c->round)));  /* 35 */
    }
    *fired = 1;
    return 0;
}

/* 36-43 */
static int rule_l36(tm_core_t *c, int *fired)
{
    tm_round_t *r = tm_log_round(&c->log, c->round, 0);
    uint8_t *lock_copy = NULL, *valid_copy = NULL;

    if (c->step < TM_STEP_PREVOTE) return 0;
    if (!prop_usable(r) || r->l36_fired) return 0;
    if (tm_log_count_votes(r, c->n, 0, r->prop_value_id) < c->quorum) return 0;
    if (eval_valid(c, r) != TM_VALID_YES) return 0;

    /* IN REPLAY THE RULES NEVER WRITE lock OR validValue (design §5.9, Codex
     * C-1 generalised). Replay reconstructs state from RECORDED ACTIONS, and
     * a lock is an action — it is recorded as this node's own non-nil
     * PRECOMMIT and restored from there. Inferring one here would let a
     * proposal whose valid() FAULTED live but answers 1 on replay manufacture
     * a lock the node never took. The lock is one-directional (more
     * restrictive), so an invented one does not break safety — but "state
     * derived by inference" and "state recorded as an action" would then have
     * two different sources, and the single-source rule is what makes replay
     * checkable at all. The step machine still runs. */
    if (c->replay) {
        r->l36_fired = 1;
        if (c->step == TM_STEP_PREVOTE) {
            c->step = TM_STEP_PRECOMMIT;                         /* 41 */
            broadcast_vote(c, 1, c->round, r->prop_value_id);    /* 40 — no-op in replay */
        }
        *fired = 1;
        return 0;
    }

    /* ALLOCATE BEFORE THE FLAG (design §5.2, Codex C-10). If the second copy
     * failed after l36_fired had been set, the rule could never fire again for
     * this round and the node would sit unlocked with a quorum in its log. */
    valid_copy = (uint8_t *)malloc(r->prop_value_len);           /* 42 */
    if (!valid_copy) return -1;
    if (c->step == TM_STEP_PREVOTE) {                            /* 37 */
        lock_copy = (uint8_t *)malloc(r->prop_value_len);
        if (!lock_copy) { free(valid_copy); return -1; }
        memcpy(lock_copy, r->prop_value, r->prop_value_len);
    }
    memcpy(valid_copy, r->prop_value, r->prop_value_len);

    r->l36_fired = 1;                                            /* "for the first time" */

    if (lock_copy) {
        free(c->locked_value);
        c->locked_value = lock_copy;                             /* 38 */
        c->locked_len   = r->prop_value_len;
        memcpy(c->locked_id, r->prop_value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        c->locked_round = (int32_t)c->round;                     /* 39 */
        c->step         = TM_STEP_PRECOMMIT;                     /* 41 */
        broadcast_vote(c, 1, c->round, r->prop_value_id);        /* 40 */
    }

    free(c->valid_value);
    c->valid_value = valid_copy;
    c->valid_len   = r->prop_value_len;
    memcpy(c->valid_id, r->prop_value_id, DNA_CONSENSUS_VALUE_ID_LEN);
    c->valid_round = (int32_t)c->round;                          /* 43 */

    *fired = 1;
    return 0;
}

/* 44-46. No first-time flag is needed: the rule requires step = prevote and
 * sets step = precommit, so it cannot fire twice in a round. */
static int rule_l44(tm_core_t *c, int *fired)
{
    tm_round_t *r = tm_log_round(&c->log, c->round, 0);

    if (c->step != TM_STEP_PREVOTE) return 0;
    if (tm_log_count_votes(r, c->n, 0, TM_NIL_ID) < c->quorum) return 0;

    c->step = TM_STEP_PRECOMMIT;                                 /* 46 */
    broadcast_vote(c, 1, c->round, TM_NIL_ID);                   /* 45 */
    *fired = 1;
    return 0;
}

/* 47-48 */
static int rule_l47(tm_core_t *c, uint64_t now_ms, int *fired)
{
    tm_round_t *r = tm_log_round(&c->log, c->round, 0);

    if (!r || r->l47_fired) return 0;
    if (tm_log_count_votes(r, c->n, 1, NULL) < c->quorum) return 0;

    r->l47_fired = 1;                                            /* "for the first time" */
    if (!c->replay) {
        tm_timers_schedule(&c->timers, TM_STEP_PRECOMMIT, c->height, c->round,
                           tm_deadline_ms(now_ms, tm_timeout_ms(&c->params, TM_STEP_PRECOMMIT, c->round)));  /* 48 */
    }
    *fired = 1;
    return 0;
}

/* 49-54. "any r" — the whole height's log is read, ascending, so that two
 * nodes holding the same messages name the same round in the commit. Under at
 * most f faulty members two different rounds cannot carry 2f+1 PRECOMMITs for
 * DIFFERENT values, so the ascending walk fixes the round, never the value. */
static int rule_l49(tm_core_t *c, int *fired)
{
    uint32_t rr;

    if (c->decided) return 0;

    for (rr = 0; rr < c->log.rounds_end; rr++) {
        tm_round_t *r = c->log.rounds[rr];
        dna_commit_t commit;
        uint32_t i, nv = 0;

        if (!prop_usable(r)) continue;
        if (tm_log_count_votes(r, c->n, 1, r->prop_value_id) < c->quorum) continue;
        if (eval_valid(c, r) != TM_VALID_YES) continue;          /* 50 */

        for (i = 0; i < c->n; i++) {                             /* ascending voter_id */
            uint8_t k;
            /* ONCE PER SENDER, whichever slot carries the decided id. The
             * commit lists voter IDENTITIES and must agree with the count that
             * let this rule fire, and tm_log_count_votes counts each sender
             * once (design §5.4). An equivocator that also precommitted
             * something else appears here exactly once — for the value that
             * was decided — so `nv` cannot exceed n and the quorum check above
             * remains the only gate. */
            for (k = 0; k < r->precommit[i].n; k++) {
                if (memcmp(r->precommit[i].value_id[k], r->prop_value_id,
                           DNA_CONSENSUS_VALUE_ID_LEN) == 0) {
                    memcpy(c->commit_scratch[nv], c->ids[i], DNA_CONSENSUS_ID_LEN);
                    nv++;
                    break;
                }
            }
        }

        c->decided = 1;                                          /* 51 */
        tm_timers_reset(&c->timers);                             /* IDLE: design §5.7 */

        memset(&commit, 0, sizeof(commit));
        commit.height   = c->height;
        commit.round    = rr;
        memcpy(commit.value_id, r->prop_value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        commit.n_voters = nv;
        commit.voters   = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])c->commit_scratch;

        /* Unlike emit, decide is NOT suppressed in replay: a node that crashed
         * between "the core decided" and "the host persisted the block" must
         * still be told, and committing a block the host already holds is
         * idempotent. Lines 52-54 do NOT run here — the host opens h+1. */
        c->host.decide(c->host.ctx, c->height, r->prop_value, r->prop_value_len, &commit);
        *fired = 1;
        return 0;
    }
    return 0;
}

/* Fixed evaluation order (design §5.8): 55, 22, 28, 34, 36, 44, 47, 49; on any
 * firing, start again from the top; stop when nothing fires. The order is what
 * makes two nodes fed the same input sequence produce the same TRACE (DG-1) —
 * safety itself does not depend on it (consensus.tex:180-182).
 *
 * Termination: every firing advances a monotone quantity (step, round, one of
 * the three per-round first-time flags, or decided), and rule 55 can carry the
 * round forward at most round_lookahead times, so the loop is finite. The
 * guard is not a substitute for that argument — if it ever trips, the core has
 * a defect and says so with -1 rather than spinning. */
static int tm_eval(tm_core_t *c, uint64_t now_ms)
{
    uint32_t it;

    for (it = 0; it < TM_EVAL_MAX_ITERATIONS; it++) {
        int fired = 0;

        if (c->decided) return 0;

        if (rule_l55(c, now_ms, &fired) != 0) return -1;
        if (fired) continue;
        if (rule_l22(c, &fired)         != 0) return -1;
        if (fired) continue;
        if (rule_l28(c, &fired)         != 0) return -1;
        if (fired) continue;
        if (rule_l34(c, now_ms, &fired) != 0) return -1;
        if (fired) continue;
        if (rule_l36(c, &fired)         != 0) return -1;
        if (fired) continue;
        if (rule_l44(c, &fired)         != 0) return -1;
        if (fired) continue;
        if (rule_l47(c, now_ms, &fired) != 0) return -1;
        if (fired) continue;
        if (rule_l49(c, &fired)         != 0) return -1;
        if (fired) continue;
        return 0;
    }
    return -1;
}

/* ── timeouts, Algorithm 1 lines 57-67 ────────────────────────────────── */

static int tm_on_timeout(tm_core_t *c, tm_step_t step, uint64_t h, uint32_t round, uint64_t now_ms)
{
    if (c->decided) return 0;                            /* IDLE after a decision */

    switch (step) {
        case TM_STEP_PROPOSE:                            /* 57-60 */
            if (h == c->height && round == c->round && c->step == TM_STEP_PROPOSE) {
                c->step = TM_STEP_PREVOTE;               /* 60 */
                broadcast_vote(c, 0, c->round, TM_NIL_ID);   /* 59 */
            }
            return 0;
        case TM_STEP_PREVOTE:                            /* 61-64 */
            if (h == c->height && round == c->round && c->step == TM_STEP_PREVOTE) {
                c->step = TM_STEP_PRECOMMIT;             /* 64 */
                broadcast_vote(c, 1, c->round, TM_NIL_ID);   /* 63 */
            }
            return 0;
        case TM_STEP_PRECOMMIT:                          /* 65-67 */
            if (h == c->height && round == c->round) {
                /* At the ceiling the core REFUSES rather than staying silently
                 * in a round it can never leave: a wrapped round would compare
                 * as older than the lock (design §5.6, F7). The host halts. */
                if (c->round >= TM_MAX_ROUND) return -1;
                return tm_start_round(c, c->round + 1u, now_ms);   /* 67 */
            }
            return 0;
        default:
            return 0;
    }
}

/* ── h+1 buffer (design §5.6) ─────────────────────────────────────────── */

static void h1_free(tm_core_t *c)
{
    uint32_t i;
    if (c->h1) {
        for (i = 0; i < c->h1_count; i++) free(c->h1[i].value);
        free(c->h1);
    }
    c->h1 = NULL;
    c->h1_count = 0;
    c->h1_cap = 0;
    c->h1_bytes = 0;
    if (c->h1_seen) memset(c->h1_seen, 0, c->h1_seen_len);
}

/* The buffer keeps the FIRST record per (round, sender, type) — design §5.9,
 * verifier finding. Without that key, one member repeating a vote fills the
 * buffer and the node enters h+1 blind to everyone else: the byte bound still
 * held (G5) but liveness did not (G6). A repeat AND a conflicting value are
 * both rc 1; the conflict is not evidence here because this height has not
 * begun and the h+1 committee is not yet known.
 *
 * Sender resolution goes through the CURRENT set. An id that is not in it gets
 * no buffer slot: the core cannot index it, and the h+1 set is the host's to
 * supply at start_height.
 *
 * A BUFFERED PROPOSAL may carry round <= TM_H1_PROPOSAL_ROUNDS only (red-team
 * round 2, F4). The h+1 proposer is not known yet — the set for h+1 has not
 * arrived — so the proposer check that guards the live path cannot run here,
 * and without a round limit one member could offer a cap-sized value for every
 * round in the lookahead window and fill the whole buffer budget alone. The
 * limit cuts that to three proposals per member. RESIDUAL, documented: f
 * members x 3 x max_value_bytes can still exceed the budget once n is large;
 * a node in that state enters h+1 with nothing buffered, prevotes nil in round
 * 0 and recovers through the sync path (G6 degrades, G5 holds). */
static int h1_push(tm_core_t *c, const dna_cmsg_t *m)
{
    uint32_t max_entries, sender_idx, tidx;
    size_t   key;
    tm_h1_msg_t *e;

    if (m->round > TM_MAX_ROUND) return 1;
    if (m->round > c->params.round_lookahead) return 1;

    switch (m->type) {
        case DNA_CMSG_PROPOSAL:  tidx = 0u; break;
        case DNA_CMSG_PREVOTE:   tidx = 1u; break;
        case DNA_CMSG_PRECOMMIT: tidx = 2u; break;
        default: return 1;
    }
    sender_idx = set_index(c, m->sender);
    if (sender_idx == TM_NO_INDEX) return 1;
    if (!c->h1_seen) return 1;

    key = (((size_t)m->round * c->n) + sender_idx) * 3u + tidx;
    if (key >= c->h1_seen_len) return 1;
    if (c->h1_seen[key]) return 1;              /* first arrival already kept */

    max_entries = (c->params.round_lookahead + 1u) * c->n * 3u;
    if (c->h1_count >= max_entries) return 1;

    if (m->type == DNA_CMSG_PROPOSAL) {
        if (m->round > TM_H1_PROPOSAL_ROUNDS) return 1;
        /* Height-INDEPENDENT shape checks run BEFORE the bytes are copied
         * (design §5.6, Codex C-6): a malformed proposal would otherwise buy
         * buffer space and be thrown away on the drain anyway. */
        if (!m->value || m->value_len == 0) return 1;
        if (is_nil_id(m->value_id)) return 1;
        if (m->valid_round < -1) return 1;
        if (m->valid_round >= 0 && (uint32_t)m->valid_round >= m->round) return 1;
        if (m->value_len > c->params.max_value_bytes) return 1;
        if (c->h1_bytes + m->value_len > c->params.max_height_log_bytes) return 1;
    }

    if (c->h1_count == c->h1_cap) {
        uint32_t want = c->h1_cap ? c->h1_cap * 2u : 16u;
        tm_h1_msg_t *grown;
        if (want > max_entries) want = max_entries;
        grown = (tm_h1_msg_t *)realloc(c->h1, (size_t)want * sizeof(*grown));
        if (!grown) return -1;
        c->h1 = grown;
        c->h1_cap = want;
    }

    e = &c->h1[c->h1_count];
    memset(e, 0, sizeof(*e));
    e->m = *m;
    e->m.value = NULL;
    if (m->type == DNA_CMSG_PROPOSAL) {
        e->value = (uint8_t *)malloc(m->value_len);
        if (!e->value) return -1;
        memcpy(e->value, m->value, m->value_len);
        c->h1_bytes += m->value_len;
    }
    c->h1_count++;
    c->h1_seen[key] = 1;
    return 0;
}

/* ── message ingestion ────────────────────────────────────────────────── */

static void report_equivocation(tm_core_t *c, const dna_cmsg_t *second,
                                const uint8_t first_id[DNA_CONSENSUS_VALUE_ID_LEN],
                                int32_t first_vr)
{
    dna_cmsg_t first;

    c->equivocations++;
    if (c->replay || !c->host.on_equivocation) return;

    first = *second;
    first.value       = NULL;
    first.value_len   = 0;
    first.valid_round = (second->type == DNA_CMSG_PROPOSAL) ? first_vr : -1;
    memcpy(first.value_id, first_id, DNA_CONSENSUS_VALUE_ID_LEN);
    c->host.on_equivocation(c->host.ctx, &first, second);
}

/* G4 ACROSS A RESTART (design §5.9). During replay a PREVOTE or PRECOMMIT
 * whose sender is THIS node is not just another vote in the log — it is the
 * authoritative record of what this node already signed, and the state it
 * implies has to come back with it.
 *
 * Without this, one path re-votes: the WAL is replayed, the host's valid()
 * answers FAULT (-1) because whatever it needs is not warm yet, so the rule
 * that produced the vote does not re-fire; step stays at propose; replay_end
 * sees "step = propose and no own PROPOSAL" and arms timeoutPropose; the
 * timeout emits a nil PREVOTE for a round in which this node had already
 * voted for a value. That is two different votes for one (height, round) —
 * exactly what G4 forbids and what a double-signing slash punishes.
 *
 * At the CURRENT round the record is authoritative for both last_* and step.
 * At any other round only last_* is updated, and only forward, so that the
 * replay order of older records cannot walk the pointer backwards. */
static void replay_restore_own_vote(tm_core_t *c, const dna_cmsg_t *m)
{
    int       is_pre    = (m->type == DNA_CMSG_PRECOMMIT);
    int32_t  *last_r    = is_pre ? &c->last_precommit_round : &c->last_prevote_round;
    uint8_t  *last_id   = is_pre ? c->last_precommit_id     : c->last_prevote_id;
    tm_step_t at_least  = is_pre ? TM_STEP_PRECOMMIT        : TM_STEP_PREVOTE;

    if (m->round == c->round || (int32_t)m->round > *last_r) {
        memcpy(last_id, m->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        *last_r = (int32_t)m->round;
    }
    if (m->round == c->round && c->step < at_least) c->step = at_least;

    /* THE LOCK COMES BACK TOO (design §5.9, verifier finding, G3). Algorithm 1
     * only broadcasts PRECOMMIT id(v) at line 40, AFTER lines 38-39 have set
     * lockedValue/lockedRound — so this node's own NON-NIL PRECOMMIT at round r
     * IS the record "I locked on v at r".
     *
     * It has to be restored explicitly. If valid() FAULTs during replay,
     * rule_l36 does not re-fire; step has been raised to precommit, so 36-41
     * can never run again for that round either; the lock would stay -1 and in
     * the NEXT round line 23 would see lockedRound = -1 and happily PREVOTE a
     * different value. At n = 4 one honest node forgetting its lock is the
     * entire safety margin. */
    if (is_pre && !is_nil_id(m->value_id) && (int32_t)m->round > c->locked_round) {
        tm_round_t *slot = tm_log_round(&c->log, m->round, 0);
        uint8_t *copy = NULL;
        size_t   len  = 0;

        /* Bytes only if the slot holds the proposal we precommitted; no rule
         * reads lockedValue's bytes, so their absence is not an error. */
        if (slot && slot->prop_value &&
            memcmp(slot->prop_value_id, m->value_id, DNA_CONSENSUS_VALUE_ID_LEN) == 0) {
            copy = (uint8_t *)malloc(slot->prop_value_len);
            if (copy) { memcpy(copy, slot->prop_value, slot->prop_value_len); len = slot->prop_value_len; }
        }
        free(c->locked_value);
        c->locked_value = copy;
        c->locked_len   = copy ? len : 0;
        memcpy(c->locked_id, m->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        c->locked_round = (int32_t)m->round;

        /* Lines 42-43 ran in the same breath, so validValue was set too — but
         * ONLY restore it when the bytes are present. validValue is a liveness
         * improvement (it is what gets re-proposed) and the invariant
         * valid_value == NULL <=> valid_round == -1 must hold. */
        if (copy && (int32_t)m->round > c->valid_round) {
            uint8_t *vcopy = (uint8_t *)malloc(len);
            if (vcopy) {
                memcpy(vcopy, copy, len);
                free(c->valid_value);
                c->valid_value = vcopy;
                c->valid_len   = len;
                memcpy(c->valid_id, m->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
                c->valid_round = (int32_t)m->round;
            }
        }
    }
}

static int ingest(tm_core_t *c, const dna_cmsg_t *m, uint64_t now_ms)
{
    uint32_t sender_idx, pidx = TM_NO_INDEX;
    uint8_t  first_id[DNA_CONSENSUS_VALUE_ID_LEN];
    int32_t  first_vr = -1;
    int      put;

    if (m->height != c->height) {
        if (m->height == c->height + 1u) {
            int rc = h1_push(c, m);
            if (rc == 0) return 0;                       /* buffered = accepted */
            return (rc < 0) ? -1 : 1;                    /* -1 allocation failure, 1 over a limit */
        }
        return 1;                                        /* stale or too far ahead */
    }
    if (c->decided) return 1;                            /* the decision cannot change */

    if (m->round > TM_MAX_ROUND) return 1;               /* the round counter never wraps */
    if ((uint64_t)m->round > (uint64_t)c->round + c->params.round_lookahead) return 1;

    /* A sender outside this height's set is IGNORED, not an error (design
     * §5.9). The host filters membership against the set of the message's
     * height, but a record admitted into the h+1 buffer was checked against
     * set_h and the h+1 set may legitimately differ — an epoch boundary drops
     * members. Such a record is dropped silently on the drain. A host that
     * forwards a genuinely foreign sender is misbehaving, and its misbehaviour
     * is still not a fault of this core. */
    sender_idx = set_index(c, m->sender);
    if (sender_idx == TM_NO_INDEX) return 1;

    memset(first_id, 0, sizeof(first_id));

    switch (m->type) {
        case DNA_CMSG_PROPOSAL: {
            tm_round_t *slot;
            if (!m->value || m->value_len == 0) return 1;
            if (m->value_len > c->params.max_value_bytes) return 1;
            if (is_nil_id(m->value_id)) return 1;
            if (m->valid_round < -1) return 1;
            if (m->valid_round >= 0 && (uint32_t)m->valid_round >= m->round) return 1;

            /* The duplicate / conflict decision comes FIRST (design §5.6, F6):
             * a taken proposal slot already records who the proposer was, so a
             * repeat costs no O(round x n) proposer walk at all. */
            slot = tm_log_round(&c->log, m->round, 0);
            if (slot && slot->prop_have) {
                if (slot->prop_sender != sender_idx) return 1;   /* not the proposer */
                if (memcmp(slot->prop_value_id, m->value_id, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
                    report_equivocation(c, m, slot->prop_value_id, slot->prop_valid_round);
                    return 2;
                }
                if (!slot->prop_dropped) return 1;               /* plain duplicate */
                /* Same id, bytes reclaimed by the cap: fall through so
                 * tm_log_put_proposal can REHYDRATE the slot (design §5.6). */
            }
            /* "from proposer(h_p, round)" — anything else is not a proposal. */
            if (round_proposer(c, m->round, &pidx) != 0) return -1;
            if (pidx != sender_idx) return 1;
            put = tm_log_put_proposal(&c->log, m->round, sender_idx, m->value_id,
                                      m->valid_round, m->value, m->value_len,
                                      c->round, first_id, &first_vr);
            break;
        }
        case DNA_CMSG_PREVOTE:
            put = tm_log_put_vote(&c->log, m->round, sender_idx, 0, m->value_id, first_id);
            break;
        case DNA_CMSG_PRECOMMIT:
            put = tm_log_put_vote(&c->log, m->round, sender_idx, 1, m->value_id, first_id);
            break;
        default:
            return 1;
    }

    if (put == TM_PUT_ERR)   return -1;
    if (put == TM_PUT_DUP)   return 1;
    if (put == TM_PUT_EQUIV) {
        /* Evidence first, so the host sees the report before any rule effect
         * it may cause. Then RUN THE RULES: under the two-slot rule the second
         * distinct value is stored and counted (design §5.4), so this message
         * can be the one that crosses a threshold — which is the entire point
         * of holding two, and without this call the second slot would be
         * recorded and never read. tm_eval is idempotent, so the paths where
         * nothing was stored (a third distinct value) cost only the scan. */
        report_equivocation(c, m, first_id, first_vr);
        if (tm_eval(c, now_ms) != 0) return -1;
        return 2;
    }

    /* Only in replay, and only for this node's own votes. A message with
     * sender == self arriving from the NETWORK is an echo or a forgery; it
     * gets no special authority and stays on the ordinary DUP/EQUIV path. */
    if (c->replay && sender_idx == c->self_idx &&
        (m->type == DNA_CMSG_PREVOTE || m->type == DNA_CMSG_PRECOMMIT)) {
        replay_restore_own_vote(c, m);
    }

    if (tm_eval(c, now_ms) != 0) return -1;
    return 0;
}

/* ── public API ───────────────────────────────────────────────────────── */

int tm_core_create(tm_core_t **out, const dna_consensus_host_t *host, const tm_params_t *p)
{
    tm_core_t *c;

    if (!out) return -1;
    *out = NULL;
    if (!host || !host->valid || !host->emit || !host->decide || !host->get_value) return -1;

    c = (tm_core_t *)calloc(1, sizeof(*c));
    if (!c) return -1;
    c->host = *host;                                     /* the caller need not keep it alive */
    if (p) c->params = *p; else tm_params_default(&c->params);
    /* Design §6.1: the three INITIAL timeouts must be positive. A zero one
     * degenerates the round it governs — the timer expires at the instant it
     * is armed, so the step it is supposed to wait through never happens and
     * the node races to nil. The DELTAS may be 0 (a flat, non-growing
     * schedule is a legitimate configuration, only a slower one to converge). */
    if (c->params.propose_init_ms == 0 ||
        c->params.prevote_init_ms == 0 ||
        c->params.precommit_init_ms == 0 ||
        c->params.round_lookahead == 0 ||
        /* lookahead + 1 sizes the h+1 seen-map; an absurd value would overflow
         * the multiplication and silently close the buffer (round-2 note). */
        c->params.round_lookahead > TM_ROUND_LOOKAHEAD_MAX ||
        c->params.max_height_log_bytes == 0 ||
        c->params.max_value_bytes == 0 ||
        c->params.max_value_bytes > c->params.max_height_log_bytes) {
        /* A per-proposal cap of 0 admits nothing; one larger than the height
         * budget is unsatisfiable — tm_log_reserve would refuse every single
         * proposal and the node would never log a value (design §5.6). */
        free(c);
        return -1;
    }
    c->self_idx            = TM_NO_INDEX;
    c->locked_round        = -1;
    c->valid_round         = -1;
    c->last_prevote_round  = -1;
    c->last_precommit_round = -1;
    *out = c;
    return 0;
}

void tm_core_destroy(tm_core_t *c)
{
    if (!c) return;
    tm_log_clear(&c->log);
    h1_free(c);
    free(c->h1_seen);
    free(c->locked_value);
    free(c->valid_value);
    free(c->ids);
    free(c->commit_scratch);
    tm_proposer_destroy(c->prop);
    free(c);
}

int tm_core_start_height(tm_core_t *c, uint64_t h, const dna_vset_t *set,
                         const tm_proposer_t *prop, uint64_t now_ms)
{
    uint32_t i, self_idx;
    tm_h1_msg_t *pending = NULL;
    uint32_t pending_count = 0;
    uint8_t (*new_ids)[DNA_CONSENSUS_ID_LEN] = NULL;
    uint8_t (*new_scratch)[DNA_CONSENSUS_ID_LEN] = NULL;
    uint8_t *new_seen = NULL;
    size_t   new_seen_len;
    tm_proposer_t *new_prop = NULL;
    int drain, drain_rc = 0, start_failed = 0;

    if (!c || !set || !prop) return -1;
    if (c->fault) return -1;                             /* latched; only destroy works */
    if (h == 0) return -1;                               /* heights start at 1; 0 = "not open" */
    if (set->weights) return -1;                         /* T1: DNA is one member, one vote */
    if (set->n == 0 || set->n > (uint32_t)DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (!set->ids) return -1;
    for (i = 1; i < set->n; i++) {
        if (memcmp(set->ids[i - 1], set->ids[i], DNA_CONSENSUS_ID_LEN) >= 0) return -1;
    }
    /* HEIGHT MONOTONICITY (design §5.9, verifier finding). Re-opening a height
     * the core is already at — or an older one — would wipe the log and last_*
     * and let the node vote a SECOND time in a round it had already voted in
     * (G4). Refusing here rather than trusting the host is the whole point; a
     * FORWARD jump of more than one (post-sync) stays legal, it just does not
     * drain the buffer. */
    if (c->height != 0 && h <= c->height) return -1;

    /* The proposer object must describe THIS set, or PROPOSAL authority at
     * this height would be decided against a different committee. */
    if (!tm_proposer_set_equals(prop, set)) return -1;

    self_idx = TM_NO_INDEX;
    for (i = 0; i < set->n; i++) {
        if (memcmp(set->ids[i], c->host.self, DNA_CONSENSUS_ID_LEN) == 0) { self_idx = i; break; }
    }
    if (self_idx == TM_NO_INDEX) return -1;              /* the core is a MEMBER's state machine */

    /* EVERY allocation that can fail happens BEFORE a single byte of the
     * current height is disturbed (design §5.9, verifier finding). The old
     * code resized one buffer, failed on the other and returned -1 with the
     * log already cleared and the locks already gone — a partial wipe that
     * looks to the caller like "nothing happened". malloc rather than realloc,
     * so the old buffers stay intact and pointer-and-n move together. */
    new_seen_len = (size_t)(c->params.round_lookahead + 1u) * set->n * 3u;
    new_ids     = (uint8_t (*)[DNA_CONSENSUS_ID_LEN])calloc(set->n, DNA_CONSENSUS_ID_LEN);
    new_scratch = (uint8_t (*)[DNA_CONSENSUS_ID_LEN])calloc(set->n, DNA_CONSENSUS_ID_LEN);
    new_seen    = (uint8_t *)calloc(new_seen_len, 1u);
    if (!new_ids || !new_scratch || !new_seen) goto oom;
    if (tm_proposer_clone(prop, &new_prop) != 0) goto oom;

    /* ── from here on nothing can fail; commit ── */

    /* Only a real h -> h+1 step can consume the buffer; any other jump (sync,
     * bootstrap) leaves it describing a height that is no longer next. */
    drain = (c->height != 0 && h == c->height + 1u);
    if (drain) {
        pending       = c->h1;
        pending_count = c->h1_count;
        c->h1 = NULL; c->h1_count = 0; c->h1_cap = 0; c->h1_bytes = 0;
        if (c->h1_seen) memset(c->h1_seen, 0, c->h1_seen_len);
    } else {
        h1_free(c);
    }

    /* 53: empty the message log and reset the locks — for THIS height only. */
    tm_log_clear(&c->log);
    free(c->locked_value); c->locked_value = NULL; c->locked_len = 0;
    free(c->valid_value);  c->valid_value  = NULL; c->valid_len  = 0;
    memset(c->locked_id, 0, sizeof(c->locked_id));
    memset(c->valid_id,  0, sizeof(c->valid_id));
    c->locked_round = -1;
    c->valid_round  = -1;
    c->decided        = 0;
    c->equivocations  = 0;
    memset(c->last_prevote_id,   0, sizeof(c->last_prevote_id));
    memset(c->last_precommit_id, 0, sizeof(c->last_precommit_id));
    c->last_prevote_round   = -1;
    c->last_precommit_round = -1;
    tm_timers_reset(&c->timers);

    free(c->ids);
    free(c->commit_scratch);
    free(c->h1_seen);
    c->ids            = new_ids;
    c->commit_scratch = new_scratch;
    c->h1_seen        = new_seen;
    c->h1_seen_len    = new_seen_len;
    new_ids = NULL; new_scratch = NULL; new_seen = NULL;

    memcpy(c->ids, set->ids, (size_t)set->n * DNA_CONSENSUS_ID_LEN);
    c->n          = set->n;
    c->self_idx   = self_idx;
    c->quorum     = dna_bft_quorum(set->n);
    c->f_plus_one = dna_bft_f_plus_one(set->n);
    c->height     = h;

    tm_proposer_destroy(c->prop);
    c->prop  = new_prop;
    new_prop = NULL;

    tm_log_init(&c->log, h, set->n, c->params.max_height_log_bytes);

    if (tm_start_round(c, 0, now_ms) != 0) start_failed = 1;   /* 10 */
    else if (tm_eval(c, now_ms) != 0)      start_failed = 1;

    /* The buffered h+1 messages are replayed IN ARRIVAL ORDER and only now:
     * before StartRound(0) neither round_p nor the lookahead window exists.
     * An ingest failure is REMEMBERED, not swallowed (design §5.9): the loop
     * still runs to the end so every buffered allocation is released, and the
     * call reports the failure. If the round could not be opened at all the
     * messages are only freed — feeding them into a half-built height would
     * compound the failure. */
    for (i = 0; i < pending_count; i++) {
        dna_cmsg_t m = pending[i].m;
        m.value = pending[i].value;
        if (!start_failed && ingest(c, &m, now_ms) == -1) drain_rc = -1;
        free(pending[i].value);
    }
    free(pending);
    /* Past the commit point, a failure is PERMANENT: the height is half open
     * and the only way to re-open it would be start_height with the same h,
     * which the monotonicity rule forbids precisely because it would wipe the
     * own vote slots (design §5.9). */
    if (start_failed || drain_rc) { c->fault = 1; return -1; }
    return 0;

oom:
    /* Nothing has been committed — the previous height is intact, the core
     * stays usable, and this is NOT a fault. */
    free(new_ids);
    free(new_scratch);
    free(new_seen);
    tm_proposer_destroy(new_prop);
    return -1;
}

int tm_core_on_message(tm_core_t *c, const dna_cmsg_t *m, uint64_t now_ms)
{
    int rc;

    if (!c || !m) return -1;
    if (c->fault) return -1;
    if (c->height == 0) return -1;                       /* no height open */
    rc = ingest(c, m, now_ms);
    if (rc == -1) c->fault = 1;
    return rc;
}

int tm_core_on_tick(tm_core_t *c, uint64_t now_ms)
{
    tm_step_t step;
    uint64_t  h;
    uint32_t  r;
    int       guard = 0;

    if (!c) return -1;
    if (c->fault) return -1;
    if (c->height == 0) return -1;

    while (tm_timers_take_expired(&c->timers, now_ms, &step, &h, &r)) {
        if (tm_on_timeout(c, step, h, r, now_ms) != 0) { c->fault = 1; return -1; }
        if (++guard > 64) { c->fault = 1; return -1; }   /* a timer storm is a defect */
    }
    if (tm_eval(c, now_ms) != 0) { c->fault = 1; return -1; }
    return 0;
}

void tm_core_replay_begin(tm_core_t *c)
{
    if (c && !c->fault) c->replay = 1;
}

int tm_core_replay_message(tm_core_t *c, const dna_cmsg_t *m)
{
    int rc;

    if (!c || !m) return -1;
    if (c->fault) return -1;
    if (c->height == 0) return -1;
    rc = ingest(c, m, 0);
    if (rc == -1) c->fault = 1;
    return rc;
}

int tm_core_replay_timeout(tm_core_t *c, uint64_t h, uint32_t round, tm_step_t step)
{
    if (!c) return -1;
    if (c->fault) return -1;
    if (c->height == 0) return -1;
    if (tm_on_timeout(c, step, h, round, 0) != 0) { c->fault = 1; return -1; }
    if (tm_eval(c, 0) != 0) { c->fault = 1; return -1; }
    return 0;
}

/* Design §5.9: replay armed no timer, so the pending set is DERIVED from the
 * state it rebuilt, with a fresh window measured from `now` — the elapsed part
 * of the old window is deliberately NOT counted, because a restarting node has
 * no honest way to know it. */
void tm_core_replay_end(tm_core_t *c, uint64_t now_ms)
{
    tm_round_t *r;

    if (!c || c->fault) return;                          /* latched; only destroy works */
    c->replay = 0;
    tm_timers_reset(&c->timers);
    if (c->height == 0 || c->decided) return;            /* decided => IDLE */

    r = tm_log_round(&c->log, c->round, 0);

    if (c->step == TM_STEP_PROPOSE &&
        !(r && r->prop_have && r->prop_sender == c->self_idx)) {
        tm_timers_schedule(&c->timers, TM_STEP_PROPOSE, c->height, c->round,
                           tm_deadline_ms(now_ms, tm_timeout_ms(&c->params, TM_STEP_PROPOSE, c->round)));
    }
    if (r && r->l34_fired && c->step == TM_STEP_PREVOTE) {
        tm_timers_schedule(&c->timers, TM_STEP_PREVOTE, c->height, c->round,
                           tm_deadline_ms(now_ms, tm_timeout_ms(&c->params, TM_STEP_PREVOTE, c->round)));
    }
    if (r && r->l47_fired) {
        tm_timers_schedule(&c->timers, TM_STEP_PRECOMMIT, c->height, c->round,
                           tm_deadline_ms(now_ms, tm_timeout_ms(&c->params, TM_STEP_PRECOMMIT, c->round)));
    }
}

void tm_core_snapshot(const tm_core_t *c, tm_snapshot_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!c) return;
    out->height        = c->height;
    out->round         = c->round;
    out->step          = c->step;
    out->decided       = c->decided;
    out->fault         = c->fault;
    out->locked_round  = c->locked_round;
    out->valid_round   = c->valid_round;
    memcpy(out->locked_id, c->locked_id, DNA_CONSENSUS_VALUE_ID_LEN);
    memcpy(out->valid_id,  c->valid_id,  DNA_CONSENSUS_VALUE_ID_LEN);
    out->equivocations = c->equivocations;
    {
        uint32_t i;
        for (i = 0; i < c->log.rounds_end; i++) {
            if (c->log.rounds && c->log.rounds[i]) out->rounds_open++;
        }
    }
    out->log_value_bytes = c->log.value_bytes;
    out->h1_entries      = c->h1_count;
    out->h1_bytes        = c->h1_bytes;
    memcpy(out->last_prevote_id,   c->last_prevote_id,   DNA_CONSENSUS_VALUE_ID_LEN);
    memcpy(out->last_precommit_id, c->last_precommit_id, DNA_CONSENSUS_VALUE_ID_LEN);
    out->last_prevote_round   = c->last_prevote_round;
    out->last_precommit_round = c->last_precommit_round;
}

/* ── engine table (D-11) ──────────────────────────────────────────────── */

static int ops_create(dna_consensus_t **out, const dna_consensus_host_t *host, const void *params)
{
    tm_core_t *c = NULL;
    int rc = tm_core_create(&c, host, (const tm_params_t *)params);
    if (rc != 0) return rc;
    *out = (dna_consensus_t *)c;
    return 0;
}

static void ops_destroy(dna_consensus_t *c) { tm_core_destroy((tm_core_t *)c); }

static int ops_start_height(dna_consensus_t *c, uint64_t height, const dna_vset_t *set,
                            const void *proposer_state, uint64_t now_ms)
{
    return tm_core_start_height((tm_core_t *)c, height, set,
                                (const tm_proposer_t *)proposer_state, now_ms);
}

static int ops_on_message(dna_consensus_t *c, const dna_cmsg_t *m, uint64_t now_ms)
{
    return tm_core_on_message((tm_core_t *)c, m, now_ms);
}

static int ops_on_tick(dna_consensus_t *c, uint64_t now_ms)
{
    return tm_core_on_tick((tm_core_t *)c, now_ms);
}

const dna_consensus_ops_t tm_ops = {
    DNA_CONSENSUS_PROTOCOL_TENDERMINT,
    "arXiv:1807.04938v3 Algorithm 1; cometbft@709fd12b",
    ops_create,
    ops_destroy,
    ops_start_height,
    ops_on_message,
    ops_on_tick
};
