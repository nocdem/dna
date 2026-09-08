/**
 * Nodus — Tendermint T1: Algorithm 1 line tests.
 *
 * Covers nodus/src/bft/tendermint/tm_state.c, tm_log.c and tm_timeouts.c
 * against arXiv:1807.04938v3 Algorithm 1 and the DNA instantiation rules of
 * docs/plans/2026-09-08-tendermint-t1-core-design.md §5.
 *
 * ── WHAT WOULD BE FALSE IF THIS FILE FAILED ───────────────────────────
 *
 * §0  The thresholds are the SHARED formulas for a general n, and "f+1" is
 *     not "n - quorum". A wrong threshold is a chain split, not a bug.
 * §A  StartRound: the proposer proposes and arms NO timeoutPropose (lines
 *     14-19), a non-proposer arms one (20-21) and prevotes nil when it
 *     expires (57-60). And — this is the liveness leg of design §5.9 — the
 *     proposer PREVOTES ITS OWN PROPOSAL, which is only possible because the
 *     core writes its own messages into its own log. If that went red the
 *     proposer would never vote in its own round and every round would time
 *     out.
 * §B  Line 22-27 fires exactly on PROPOSAL(vr = -1) from THE proposer while
 *     step = propose, and votes nil when valid() says no or when the node is
 *     locked on something else (G3).
 * §C  Line 28-33 fires only with 2f+1 PREVOTEs at the proposal's vr, and vr
 *     outside [0, round) is refused at the door.
 * §D  Line 34-35 arms timeoutPrevote ONCE per round ("for the first time"):
 *     a later prevote must not push the deadline out.
 * §E  Line 36-43 locks and precommits when step = prevote, and when step is
 *     already precommit it updates validValue ONLY — it does not re-lock and
 *     does not emit a second precommit (G3, G4).
 * §F  Line 44-46 turns 2f+1 nil prevotes into a nil precommit.
 * §G  Line 47-48 arms timeoutPrecommit once, and line 65-67 opens the next
 *     round when it expires.
 * §H  Line 49-54 decides on ANY round of the height, names the voters in
 *     ascending identity order, and then the core is IDLE (design §5.7): no
 *     timer, no new round, and further messages for that height are ignored.
 * §I  Line 55-56 jumps to a higher round on f+1 DISTINCT senders, and one
 *     sender is not enough.
 * §J  A timer that belongs to a round the node has left is discarded by the
 *     equality check at lines 58/62/66 instead of acting.
 * §K  Equivocation keeps TWO SLOTS per sender per (round, type): the second,
 *     DIFFERENT value is reported AND counted toward its own value, the third
 *     is reported only, and a repeat of a value already held is a plain
 *     duplicate. A PROPOSAL keeps one slot.
 * §K-b TWO VALUES CANNOT BOTH REACH A QUORUM even though the equivocator is
 *     counted for both — the sender-intersection argument, measured on the log
 *     itself rather than inferred from a scenario.
 * §L  The round lookahead is a hard door: round_p + lookahead is admitted,
 *     one more is not (G5).
 * §M  Messages for h+1 are buffered and drained by start_height, in arrival
 *     order; h+2 is refused.
 * §N  valid() = -1 is a FAULT, not a verdict: no rule fires, nothing is
 *     memoised, and the question is asked again. A 1/0 answer IS memoised
 *     and asked at most once.
 * §O  Replay rebuilds state without emitting, keeps the lock, and re-arms the
 *     three timers by the design §5.9 table.
 * §O-d G4 SURVIVES A RESTART. A replayed PREVOTE/PRECOMMIT sent by THIS node
 *     restores last_* and raises step, so a valid() that FAULTs during replay
 *     can no longer leave the node at propose, arm timeoutPropose and emit a
 *     nil vote for a round it had already voted in — a double signature. The
 *     same record twice is idempotent, and the restored vote still counts
 *     towards this height's thresholds. The withheld vote is also not WRITTEN:
 *     under the two-slot rule a vote stored in the own slot would be counted,
 *     so a vote this node never sent must never reach the log.
 * §O-e THE LOCK SURVIVES A RESTART (G3). This node's own non-nil PRECOMMIT in
 *     the WAL IS the record "I locked here" (Algorithm 1 broadcasts line 40
 *     only after locking at 38-39), so replaying it restores lockedRound and
 *     lockedValue — and validValue too, but ONLY when the round's bytes are
 *     still in the log, because validValue is what gets re-proposed and
 *     valid_value == NULL <=> valid_round == -1 must hold.
 * §O-f ENTERING A ROUND, THIS NODE'S OWN SLOTS SET THE STEP. The WAL may hold
 *     "own vote at r+1" before the timeout record that opens r+1; without this
 *     the round would open at propose and the derived timeoutPropose would
 *     emit a nil vote for a round already voted in.
 * §O-g adopt_own_slots moves last_* FORWARD ONLY: entering round 1 must not
 *     drag last_prevote_round back from a round-5 record also in the WAL.
 * §O-h IN REPLAY THE OWN VOTES COME ONLY FROM THE WAL. A timeout record that
 *     was a no-op when it ran live must not make the core synthesise a nil
 *     vote into its own slot — the WAL's real record for that round would then
 *     be counted as an equivocation against a vote the node never sent, and
 *     the lock would be lost with it (G3 + G4).
 * §M-c a buffered h+1 vote from a member the NEW set does not contain is
 *     ignored on the drain: rc 1, start_height still succeeds, no fault.
 * §M-d a BUFFERED h+1 PROPOSAL is capped at TM_H1_PROPOSAL_ROUNDS, because the
 *     h+1 proposer cannot be checked yet; votes keep the full lookahead.
 * §V  a refusal BEFORE start_height's commit point does not latch the fault
 *     and leaves the core fully usable.
 * §U  THE BYTE CAP RECLAIMS IN THE RIGHT ORDER (G5/G6). A round two or more
 *     ahead evicts nothing; the NEXT round may evict only rounds already
 *     behind, never the round in progress; a single value above the
 *     per-proposal cap never enters at all.
 * §T  start_height refuses h <= height (re-opening would wipe last_* and let
 *     the node vote twice in one round) while a forward jump stays legal.
 * §W  IN REPLAY THE RULES NEVER WRITE lock OR validValue. Live, valid()
 *     FAULTed and this node voted nil; on replay valid() is healthy and
 *     rule_l36 CAN fire. It must advance the step and nothing else — otherwise
 *     it manufactures a lock the node never took, and replay stops being a
 *     function of the recorded actions.
 * §X  G7 SEAM. The core computes no hash, so only the HOST can bind the bytes
 *     to the id. What is proved here is the core half: a 0 verdict is honoured
 *     and becomes a nil PREVOTE. The binding itself is not in this module and
 *     is not tested here.
 * §S2 A DEADLINE THAT WOULD WRAP SATURATES. `now` is the host's clock; a
 *     wrapped now + timeout compares as already expired and would fire the
 *     timer at the instant it was armed, collapsing the round.
 * §U(6) A RECLAIMED ROUND IS REHYDRATED by the same proposal, which re-enables
 *     line 49 for it. Without that, a late but complete commit is locally
 *     undecidable forever and only the sync path can finish it.
 * §S  tm_core_create refuses a zero INITIAL timeout (a timer that expires the
 *     instant it is armed skips the step it exists to wait through), refuses a
 *     zero or unsatisfiable max_value_bytes, refuses a round_lookahead above
 *     TM_ROUND_LOOKAHEAD_MAX, and accepts zero DELTAS (a flat schedule is
 *     slow, not degenerate).
 * §P  get_value() = 1 makes the proposer behave as a non-proposer for that
 *     round.
 * §Q  G4: one PREVOTE and one PRECOMMIT per (height, round) leave this node.
 * §R  The registry resolves 1 to Tendermint, refuses 0 and refuses unknown.
 *
 * ── WHAT IT REQUIRES ──────────────────────────────────────────────────
 *
 * Nothing beyond a default build: no compile flags, no environment variables,
 * no files, no ports. There is no clock (every now_ms is a literal) and no
 * RNG, so a failure reproduces byte for byte on any machine.
 *
 * ── WHAT IT LEAVES BEHIND ─────────────────────────────────────────────
 *
 * Nothing. Every fixture destroys its core and its proposer on every exit
 * path, including the failure paths.
 *
 * ── HOW IT COULD LIE ──────────────────────────────────────────────────
 *
 *  1. A STUB THAT ALWAYS SAYS YES. If valid() returned 1 unconditionally the
 *     INVALID and FAULT branches would never be measured. Each section sets
 *     the stub's answer explicitly, and §B-neg, §H-neg and §N are separate
 *     sections that require 0 and -1.
 *  2. A GREEN THAT EMITTED NOTHING. A rule that never fires satisfies every
 *     "did not do the wrong thing" assertion. Every positive section therefore
 *     asserts an EXACT EMISSION COUNT **or** an EXACT STATE — §G, §I and §L
 *     assert the resulting ROUND NUMBER rather than an emission, because the
 *     rule they cover (a timer arming, a round jump, a door closing) produces
 *     no message at all. Claiming "every section asserts an emission" would be
 *     false; this is the honest form of the guard.
 *  3. TIMERS ASSERTED BY PEEKING. Nothing here reads a timer field; a timer
 *     is proven by ticking one millisecond BEFORE its deadline (nothing may
 *     happen) and then AT it (the action must happen). An absent timer is
 *     proven by ticking far past every deadline and requiring silence.
 *  4. THE PROPOSER BEING WHOEVER THE CODE SAYS. §0 pins the round-0 proposer
 *     of the 4-member fixture to a hand-derived literal, so a broken proposer
 *     counter cannot quietly re-label every scenario.
 *  5. FIXPOINT FAILURE READ AS SUCCESS. tm_eval returns -1 if its guard trips;
 *     every call site here checks the return code, so a spinning evaluator
 *     shows up as a failure rather than as a silent no-op.
 *  6. THE FAULT LATCH IS ONLY HALF COVERED — SAID PLAINLY. §V asserts that a
 *     refusal BEFORE start_height's commit point does NOT latch and that the
 *     core stays usable. It does NOT assert the positive half (an internal
 *     failure latching, every entry point refusing afterwards): every path
 *     that sets `fault` needs an allocation failure, a tripped fixpoint guard
 *     or 2^31 rounds, none reachable from the public API without a build flag
 *     or an allocator hook. An injection seam was deliberately NOT added —
 *     putting a production-visible branch in the core to make a test easier is
 *     a worse trade than an admitted gap. This is coverage that did not
 *     happen, not coverage that passed.
 *  7. A NEGATIVE THAT NEVER RAN. §M-c, §M-d, §O-g, §O-h and §U(5) each pair
 *     their refusal with a POSITIVE consequence measured afterwards (a lock
 *     that must not form, a vote that must still be accepted, a step that must
 *     still be raised, a lock that must survive), so a section cannot pass by
 *     the core having simply stopped.
 *  8. AN ASSERTION THAT ANOTHER CHECK ALREADY COVERED (found by an external
 *     mutation campaign, 2026-09-08, and fixed rather than argued away):
 *     §A now holds the proposer AT step propose with a FAULTing valid(), so
 *     "the proposer armed no timer" is observable instead of being masked by
 *     the step check; §J fires the stale timer while the CURRENT round is at
 *     step prevote, so the round equality check is the only thing standing;
 *     §U's cap case uses a budget four values wide and EMPTY, so the refusal
 *     can only come from the per-proposal cap; the reclaim-order legs offer
 *     TWO candidates on each side and name which one was taken; and the four
 *     previously discarded send_vote return codes are now checked.
 */

#include "bft/tendermint/tm_core.h"
#include "bft/dna_consensus.h"
#include "dnac/ledger_ids.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define MAXN        16u
#define EMIT_MAX    256
#define VAL_LEN     8u
#define TAG_A       0xA1u
#define TAG_B       0xB2u
#define TAG_C       0xC3u
#define T0          1000ull      /* the fixture's start_height instant */

/* ── host stub ────────────────────────────────────────────────────────── */

typedef struct {
    dna_cmsg_type_t type;
    uint64_t        height;
    uint32_t        round;
    int32_t         valid_round;
    uint8_t         value_id[DNA_CONSENSUS_VALUE_ID_LEN];
} emit_rec_t;

typedef struct {
    emit_rec_t emits[EMIT_MAX];
    uint32_t   n_emit;

    int      get_value_mode;      /* 0 = supply a value, 1 = "no value this round" */
    uint8_t  gv_tag;
    uint32_t gv_calls;

    int      valid_result;        /* 1 or 0 */
    int      fault_budget;        /* this many calls answer -1 first */
    /* G7: when set, valid() actually CHECKS that the value's tag matches the
     * id's tag, which is the host-side binding the core cannot do itself. */
    int      enforce_binding;
    uint32_t valid_calls;

    uint32_t n_decide;
    uint64_t dec_height;
    uint32_t dec_round;
    uint32_t dec_voters;
    uint8_t  dec_voter_ids[MAXN][DNA_CONSENSUS_ID_LEN];
    uint8_t  dec_value_id[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t  dec_value0;

    uint32_t n_round_start;
    uint32_t last_round_started;

    uint32_t n_equiv;
} host_ctx_t;

static void mkid(uint8_t out[DNA_CONSENSUS_ID_LEN], uint8_t tag)
{
    memset(out, tag, DNA_CONSENSUS_ID_LEN);
}

static void mkvalue_id(uint8_t tag, uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    memset(id, 0, DNA_CONSENSUS_VALUE_ID_LEN);
    id[0] = tag;
    id[1] = 0x5Au;
}

static int hv_get_value(void *ctx, uint64_t height, uint8_t **value, size_t *len,
                        uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    host_ctx_t *hc = (host_ctx_t *)ctx;
    (void)height;
    hc->gv_calls++;
    if (hc->get_value_mode) return 1;
    *value = (uint8_t *)malloc(VAL_LEN);
    if (!*value) return 1;
    memset(*value, hc->gv_tag, VAL_LEN);
    *len = VAL_LEN;
    mkvalue_id(hc->gv_tag, id);
    return 0;
}

static int hv_valid(void *ctx, uint64_t height, const uint8_t *value, size_t len,
                    const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    host_ctx_t *hc = (host_ctx_t *)ctx;
    (void)height;
    hc->valid_calls++;
    if (hc->fault_budget > 0) { hc->fault_budget--; return -1; }
    if (hc->enforce_binding) {
        /* G7 (dna_consensus.h): the HOST is the only place the bytes are bound
         * to the id. Here the value is a run of the tag byte and the id's
         * first byte is that tag, so "id(value) == value_id" is exactly
         * value[0] == id[0]. */
        if (!value || len == 0 || value[0] != id[0]) return 0;
    }
    return hc->valid_result;
}

static void hv_emit(void *ctx, const dna_cmsg_t *own)
{
    host_ctx_t *hc = (host_ctx_t *)ctx;
    emit_rec_t *e;
    if (hc->n_emit >= (uint32_t)EMIT_MAX) return;
    e = &hc->emits[hc->n_emit++];
    e->type        = own->type;
    e->height      = own->height;
    e->round       = own->round;
    e->valid_round = own->valid_round;
    memcpy(e->value_id, own->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
}

static void hv_decide(void *ctx, uint64_t height, const uint8_t *value, size_t len,
                      const dna_commit_t *commit)
{
    host_ctx_t *hc = (host_ctx_t *)ctx;
    uint32_t i;
    hc->n_decide++;
    hc->dec_height = height;
    hc->dec_round  = commit->round;
    hc->dec_voters = commit->n_voters;
    hc->dec_value0 = (len > 0 && value) ? value[0] : 0;
    memcpy(hc->dec_value_id, commit->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
    for (i = 0; i < commit->n_voters && i < MAXN; i++) {
        memcpy(hc->dec_voter_ids[i], commit->voters[i], DNA_CONSENSUS_ID_LEN);
    }
}

static void hv_round_start(void *ctx, uint64_t height, uint32_t round,
                           const uint8_t proposer[DNA_CONSENSUS_ID_LEN])
{
    host_ctx_t *hc = (host_ctx_t *)ctx;
    (void)height; (void)proposer;
    hc->n_round_start++;
    hc->last_round_started = round;
}

static void hv_equivocation(void *ctx, const dna_cmsg_t *first, const dna_cmsg_t *second)
{
    host_ctx_t *hc = (host_ctx_t *)ctx;
    (void)first; (void)second;
    hc->n_equiv++;
}

/* ── fixture ──────────────────────────────────────────────────────────── */

typedef struct {
    host_ctx_t           hc;
    dna_consensus_host_t host;
    uint8_t              ids[MAXN][DNA_CONSENSUS_ID_LEN];
    dna_vset_t           set;
    tm_proposer_t       *prop;
    tm_core_t           *core;
    tm_params_t          params;
    uint32_t             n;
    uint32_t             self_idx;
    /* The height the core is CURRENTLY at. The message helpers read it, so a
     * scenario that opens h+1 keeps addressing the right height instead of
     * silently sending to height 1 forever (red-team T1). */
    uint64_t             height;
} fx_t;

static void fx_free(fx_t *f)
{
    if (!f) return;
    tm_core_destroy(f->core);
    tm_proposer_destroy(f->prop);
    f->core = NULL;
    f->prop = NULL;
}

/* Builds the host, the set and a core already at height 1, round 0, with the
 * clock at T0. `replay` opens the height in replay mode so that StartRound(0)
 * emits nothing. */
/* `fault_budget` is installed BEFORE start_height, so a scenario can hold the
 * core in a valid()-FAULT state from the very first rule evaluation. */
static int fx_init_full(fx_t *f, uint32_t n, uint32_t self_idx, int replay,
                        const tm_params_t *params_override, int fault_budget)
{
    uint32_t i;

    memset(f, 0, sizeof(*f));
    f->n = n;
    f->self_idx = self_idx;
    f->hc.valid_result = 1;
    f->hc.gv_tag = (uint8_t)TAG_A;

    for (i = 0; i < n; i++) mkid(f->ids[i], (uint8_t)(0x21u + i));
    f->set.n = n;
    f->set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])f->ids;
    f->set.weights = NULL;

    f->host.ctx = &f->hc;
    memcpy(f->host.self, f->ids[self_idx], DNA_CONSENSUS_ID_LEN);
    f->host.get_value       = hv_get_value;
    f->host.valid           = hv_valid;
    f->host.emit            = hv_emit;
    f->host.decide          = hv_decide;
    f->host.on_round_start  = hv_round_start;
    f->host.on_equivocation = hv_equivocation;

    tm_params_default(&f->params);
    if (params_override) f->params = *params_override;
    f->hc.fault_budget = fault_budget;

    if (tm_proposer_create(&f->prop, &f->set) != 0) return -1;
    if (tm_core_create(&f->core, &f->host, &f->params) != 0) { fx_free(f); return -1; }
    if (replay) tm_core_replay_begin(f->core);
    if (tm_core_start_height(f->core, 1, &f->set, f->prop, T0) != 0) { fx_free(f); return -1; }
    f->height = 1;
    return 0;
}

static int fx_init_ex(fx_t *f, uint32_t n, uint32_t self_idx, int replay)
{
    return fx_init_full(f, n, self_idx, replay, NULL, 0);
}

static int fx_init(fx_t *f, uint32_t n, uint32_t self_idx)
{
    return fx_init_full(f, n, self_idx, 0, NULL, 0);
}

/* Opens the next height and KEEPS THE FIXTURE'S IDEA OF IT IN STEP, so the
 * helpers below address the height the core is actually at. */
static int fx_start_height(fx_t *f, uint64_t h, uint64_t now)
{
    int rc = tm_core_start_height(f->core, h, &f->set, f->prop, now);
    if (rc == 0) f->height = h;
    return rc;
}

static uint32_t proposer_index(const fx_t *f, uint32_t round)
{
    uint8_t got[DNA_CONSENSUS_ID_LEN];
    uint32_t i;
    if (tm_proposer_at(f->prop, round, got) != 0) return MAXN;
    for (i = 0; i < f->n; i++) {
        if (memcmp(f->ids[i], got, DNA_CONSENSUS_ID_LEN) == 0) return i;
    }
    return MAXN;
}

/* ── message helpers ──────────────────────────────────────────────────── */

static int send_vote(fx_t *f, dna_cmsg_type_t type, uint32_t sender, uint32_t round,
                     const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN], uint64_t now)
{
    dna_cmsg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.height = f->height;
    m.round = round;
    m.valid_round = -1;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    memcpy(m.value_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
    return tm_core_on_message(f->core, &m, now);
}

/* Explicit height — for the h+1 / h+2 buffer cases only. */
static int send_vote_h(fx_t *f, dna_cmsg_type_t type, uint32_t sender, uint64_t height,
                       uint32_t round, const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN], uint64_t now)
{
    dna_cmsg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.height = height;
    m.round = round;
    m.valid_round = -1;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    memcpy(m.value_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
    return tm_core_on_message(f->core, &m, now);
}

static int send_proposal(fx_t *f, uint32_t sender, uint32_t round, uint8_t tag,
                         int32_t vr, uint64_t now)
{
    dna_cmsg_t m;
    uint8_t value[VAL_LEN];
    memset(&m, 0, sizeof(m));
    memset(value, tag, VAL_LEN);
    m.type = DNA_CMSG_PROPOSAL;
    m.height = f->height;
    m.round = round;
    m.valid_round = vr;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    mkvalue_id(tag, m.value_id);
    m.value = value;
    m.value_len = VAL_LEN;
    return tm_core_on_message(f->core, &m, now);
}

static uint32_t count_emits(const fx_t *f, dna_cmsg_type_t type, uint32_t round)
{
    uint32_t i, c = 0;
    for (i = 0; i < f->hc.n_emit; i++) {
        if (f->hc.emits[i].type == type && f->hc.emits[i].round == round) c++;
    }
    return c;
}

static int emit_is(const fx_t *f, uint32_t idx, dna_cmsg_type_t type, uint32_t round,
                   const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    if (idx >= f->hc.n_emit) return 0;
    if (f->hc.emits[idx].type != type) return 0;
    if (f->hc.emits[idx].round != round) return 0;
    return memcmp(f->hc.emits[idx].value_id, id, DNA_CONSENSUS_VALUE_ID_LEN) == 0;
}

static const uint8_t NIL_ID[DNA_CONSENSUS_VALUE_ID_LEN] = { 0 };

/* ── §0  thresholds and the fixture's own proposer ────────────────────── */

static void test_0_thresholds(void)
{
    struct row { uint32_t n, q, f1; };
    static const struct row rows[] = {
        {   4,  3,  2 },
        {   7,  5,  3 },
        {   8,  6,  3 },
        {   9,  7,  3 },
        {  10,  7,  4 },
        {  30, 21, 10 },
        { 128, 86, 43 }
    };
    size_t i;

    TEST("0 quorum / f+1 literals for n in {4,7,8,9,10,30,128}");
    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        if (dna_bft_quorum(rows[i].n) != rows[i].q ||
            dna_bft_f_plus_one(rows[i].n) != rows[i].f1) {
            char buf[96];
            snprintf(buf, sizeof(buf), "n=%u got %u/%u want %u/%u", rows[i].n,
                     dna_bft_quorum(rows[i].n), dna_bft_f_plus_one(rows[i].n),
                     rows[i].q, rows[i].f1);
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_0_fixture_proposer(void)
{
    fx_t f;

    /* Hand-derived (test_tm_proposer §D/§F carries the arithmetic): the
     * genesis state of a 4-member weight-1 set is [-3, 1, 1, 1] with v0
     * elected, so round 0 of height 1 belongs to index 0. Every scenario in
     * this file leans on that, so it is pinned here rather than trusted. */
    TEST("0 fixture: proposer(h=1, r=0) is index 0, r=1 is index 1");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (proposer_index(&f, 0) != 0) { fx_free(&f); FAIL("round 0 proposer"); return; }
    if (proposer_index(&f, 1) != 1) { fx_free(&f); FAIL("round 1 proposer"); return; }
    fx_free(&f);
    PASS();
}

/* ── §A  StartRound, lines 11-21 + the own-log liveness rule ──────────── */

static void test_a_proposer_proposes_and_prevotes(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];

    TEST("A proposer emits PROPOSAL then PREVOTEs its OWN proposal");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 0) != 0) { FAIL("fixture"); return; }   /* self IS proposer(0) */

    if (f.hc.n_emit != 2) { fx_free(&f); FAIL("expected PROPOSAL then PREVOTE"); return; }
    if (!emit_is(&f, 0, DNA_CMSG_PROPOSAL, 0, idA)) { fx_free(&f); FAIL("no proposal"); return; }
    if (f.hc.emits[0].valid_round != -1) { fx_free(&f); FAIL("vr should be -1"); return; }
    if (!emit_is(&f, 1, DNA_CMSG_PREVOTE, 0, idA)) { fx_free(&f); FAIL("no self prevote"); return; }

    /* Lines 20-21: the proposer arms NO timeoutPropose, so ticking long past
     * every deadline must add nothing. */
    if (tm_core_on_tick(f.core, T0 + 1000000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 2) { fx_free(&f); FAIL("proposer armed timeoutPropose"); return; }
    fx_free(&f);

    /* THE DISCRIMINATING LEG (Codex mutation): above, the node had already
     * left step = propose, so OnTimeoutPropose would have been a no-op even if
     * a timer HAD been armed — the assertion could not see the difference.
     * Hold the proposer AT step propose by making valid() FAULT forever: now
     * an armed timer WOULD fire and emit a nil PREVOTE, and its absence is the
     * observation. */
    if (fx_init_full(&f, 4, 0, 0, NULL, 1000000) != 0) { FAIL("fixture 2"); return; }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PROPOSAL, 0, idA)) {
        fx_free(&f); FAIL("the proposal itself did not go out"); return;
    }
    {
        tm_snapshot_t s;
        tm_core_snapshot(f.core, &s);
        if (s.step != TM_STEP_PROPOSE) {
            fx_free(&f); FAIL("the FAULT path was not exercised"); return;
        }
    }
    if (tm_core_on_tick(f.core, T0 + 1000000ull) != 0) { fx_free(&f); FAIL("tick 2"); return; }
    if (f.hc.n_emit != 1) {
        fx_free(&f); FAIL("a nil PREVOTE left — the proposer HAD armed a timer"); return;
    }
    fx_free(&f);
    PASS();
}

static void test_a_non_proposer_timeout(void)
{
    fx_t f;
    uint64_t deadline;

    TEST("A non-proposer arms timeoutPropose and prevotes nil at it (57-60)");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("non-proposer emitted early"); return; }

    deadline = T0 + TM_TIMEOUT_PROPOSE_INIT_MS;
    if (tm_core_on_tick(f.core, deadline - 1ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("fired before the deadline"); return; }

    if (tm_core_on_tick(f.core, deadline) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, NIL_ID)) {
        fx_free(&f); FAIL("no nil PREVOTE at the deadline"); return;
    }
    {
        tm_snapshot_t s;
        tm_core_snapshot(f.core, &s);
        if (s.step != TM_STEP_PREVOTE) { fx_free(&f); FAIL("step did not advance"); return; }
    }
    fx_free(&f);
    PASS();
}

/* ── §B  lines 22-27 ─────────────────────────────────────────────────── */

static void test_b_l22_positive(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("B line 22: PROPOSAL(vr=-1), valid, unlocked -> PREVOTE id(v)");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("proposal rejected"); return;
    }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, idA)) {
        fx_free(&f); FAIL("no PREVOTE for id(v)"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PREVOTE) { fx_free(&f); FAIL("step"); return; }
    fx_free(&f);
    PASS();
}

static void test_b_l22_negatives(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];

    mkvalue_id((uint8_t)TAG_A, idA);

    TEST("B line 22 negatives: wrong proposer / invalid / wrong step");

    /* (1) not the proposer for that round -> ignored, nothing logged. */
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (send_proposal(&f, 2, 0, (uint8_t)TAG_A, -1, T0 + 10) != 1) {
        fx_free(&f); FAIL("a non-proposer's PROPOSAL was accepted"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("emitted on a bogus proposal"); return; }
    fx_free(&f);

    /* (2) valid() = 0 -> PREVOTE nil (line 26). */
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    f.hc.valid_result = 0;
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("proposal rejected"); return;
    }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, NIL_ID)) {
        fx_free(&f); FAIL("invalid value did not produce a nil PREVOTE"); return;
    }
    fx_free(&f);

    /* (3) step is no longer propose -> the rule must not fire again. */
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (tm_core_on_tick(f.core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    if (f.hc.n_emit != 1) { fx_free(&f); FAIL("expected the nil PREVOTE"); return; }
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 5000) != 0) {
        fx_free(&f); FAIL("late proposal rejected"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 1) {
        fx_free(&f); FAIL("prevoted twice in one round"); return;
    }
    fx_free(&f);
    PASS();
}

static void test_b_lock_blocks_prevote(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* G3: once locked on A the node will not prevote B in a later round with
     * vr = -1 (line 23's second conjunct). */
    TEST("B G3: locked on A, a round-1 PROPOSAL(B, vr=-1) yields nil");
    mkvalue_id((uint8_t)TAG_A, idA);
    /* self = index 2: not the proposer at round 0 (index 0) nor at round 1
     * (index 1), so both proposals in this scenario arrive from the wire. */
    if (fx_init(&f, 4, 2) != 0) { FAIL("fixture"); return; }

    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 20) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 1, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("v1"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0) { fx_free(&f); FAIL("did not lock"); return; }

    /* Reach round 1 through line 55: f+1 = 2 distinct senders at round 1. */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 1, NIL_ID, T0 + 40) != 0) { fx_free(&f); FAIL("r1a"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 1, NIL_ID, T0 + 50) != 0) {
        fx_free(&f); FAIL("r1b"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("line 55 did not open round 1"); return; }

    if (send_proposal(&f, proposer_index(&f, 1), 1, (uint8_t)TAG_B, -1, T0 + 60) != 0) {
        fx_free(&f); FAIL("round-1 proposal rejected"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 1) != 1) {
        fx_free(&f); FAIL("expected exactly one round-1 PREVOTE"); return;
    }
    {
        uint32_t i;
        for (i = 0; i < f.hc.n_emit; i++) {
            if (f.hc.emits[i].type == DNA_CMSG_PREVOTE && f.hc.emits[i].round == 1) {
                if (memcmp(f.hc.emits[i].value_id, NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
                    fx_free(&f); FAIL("locked node prevoted a different value"); return;
                }
            }
        }
    }
    fx_free(&f);
    PASS();
}

/* ── §C  lines 28-33 ─────────────────────────────────────────────────── */

/* Drives a 7-member fixture to round 1 with 2f+1 = 5 PREVOTEs for id(A)
 * standing at round 0, without ever putting a value into round 0's proposal
 * slot. Returns 0 on success. */
static int drive_to_round1_with_prevotes(fx_t *f, const uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN])
{
    uint32_t i;
    tm_snapshot_t s;

    /* self = index 3: the round-r proposer of this weight-1 7-set is index
     * r mod 7, so index 3 is neither the round-0 nor the round-1 proposer. */
    if (fx_init(f, 7, 3) != 0) return -1;
    if (proposer_index(f, 0) == 3 || proposer_index(f, 1) == 3) return -1;

    /* self prevotes nil on the propose timeout */
    if (tm_core_on_tick(f->core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) return -1;

    /* five DISTINCT senders prevote A at round 0 */
    for (i = 0; i < 6; i++) {
        if (i == 3) continue;
        if (send_vote(f, DNA_CMSG_PREVOTE, i, 0, idA, T0 + 5000 + i) < 0) return -1;
    }
    /* five PRECOMMITs from OTHER members arm timeoutPrecommit (line 47) */
    for (i = 0; i < 6; i++) {
        if (i == 3) continue;
        if (send_vote(f, DNA_CMSG_PRECOMMIT, i, 0, NIL_ID, T0 + 6000 + i) < 0) return -1;
    }
    if (tm_core_on_tick(f->core, T0 + 60000ull) != 0) return -1;
    tm_core_snapshot(f->core, &s);
    return (s.round == 1) ? 0 : -1;
}

static void test_c_l28_positive(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint32_t before;

    TEST("C line 28: PROPOSAL(vr=0) + 2f+1 PREVOTE@0 -> PREVOTE id(v)");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (drive_to_round1_with_prevotes(&f, idA) != 0) { fx_free(&f); FAIL("setup"); return; }

    before = count_emits(&f, DNA_CMSG_PREVOTE, 1);
    if (before != 0) { fx_free(&f); FAIL("already prevoted at round 1"); return; }
    if (send_proposal(&f, proposer_index(&f, 1), 1, (uint8_t)TAG_A, 0, T0 + 61000) != 0) {
        fx_free(&f); FAIL("proposal rejected"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 1) != 1) {
        fx_free(&f); FAIL("line 28 did not fire"); return;
    }
    {
        uint32_t i;
        int seen = 0;
        for (i = 0; i < f.hc.n_emit; i++) {
            if (f.hc.emits[i].type == DNA_CMSG_PREVOTE && f.hc.emits[i].round == 1) {
                if (memcmp(f.hc.emits[i].value_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
                    fx_free(&f); FAIL("prevoted nil instead of id(v)"); return;
                }
                seen = 1;
            }
        }
        if (!seen) { fx_free(&f); FAIL("no round-1 PREVOTE at all"); return; }
    }
    fx_free(&f);
    PASS();
}

static void test_c_l28_negatives(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];

    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);

    TEST("C line 28 negatives: vr out of range, and no quorum at vr");

    /* vr >= round and vr < -1 are refused at the door. */
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, 0, T0 + 10) != 1) {
        fx_free(&f); FAIL("vr == round accepted"); return;
    }
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -2, T0 + 11) != 1) {
        fx_free(&f); FAIL("vr < -1 accepted"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("emitted on a malformed proposal"); return; }
    fx_free(&f);

    /* A proposal whose vr points at a round WITHOUT a quorum for its value
     * must not make the node vote; only the timeout does. */
    if (drive_to_round1_with_prevotes(&f, idA) != 0) { fx_free(&f); FAIL("setup"); return; }
    if (send_proposal(&f, proposer_index(&f, 1), 1, (uint8_t)TAG_B, 0, T0 + 61000) != 0) {
        fx_free(&f); FAIL("proposal rejected"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 1) != 0) {
        fx_free(&f); FAIL("line 28 fired without a quorum for id(v)"); return;
    }
    /* and the timeout still carries it to nil */
    if (tm_core_on_tick(f.core,
                        T0 + 61000ull + TM_TIMEOUT_PROPOSE_INIT_MS + TM_TIMEOUT_PROPOSE_DELTA_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 1) != 1) {
        fx_free(&f); FAIL("no nil PREVOTE after timeoutPropose(1)"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §D  lines 34-35, "for the first time" ───────────────────────────── */

static void test_d_l34_first_time(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    uint64_t deadline;

    TEST("D line 34 arms timeoutPrevote ONCE; a later prevote must not move it");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);

    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (tm_core_on_tick(f.core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    /* self = nil, v0 = A, v2 = B: quorum(4) = 3 prevotes, no id has 3. */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 4100) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idB, T0 + 4200) != 0) { fx_free(&f); FAIL("v2"); return; }

    deadline = T0 + 4200ull + TM_TIMEOUT_PREVOTE_INIT_MS;

    /* A fourth prevote arrives much later. If line 34 re-armed, the deadline
     * would move out and the tick below would find nothing. */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 0, idB, deadline - 10ull) != 0) {
        fx_free(&f); FAIL("v3"); return;
    }
    if (tm_core_on_tick(f.core, deadline - 1ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 0) {
        fx_free(&f); FAIL("fired before the deadline"); return;
    }
    if (tm_core_on_tick(f.core, deadline) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 1) {
        fx_free(&f); FAIL("timeoutPrevote did not fire at the FIRST deadline"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §E  lines 36-43 ─────────────────────────────────────────────────── */

static void test_e_l36_locks(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("E line 36 at step=prevote: lock, PRECOMMIT id(v), validValue set");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 20) != 0) { fx_free(&f); FAIL("v0"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) { fx_free(&f); FAIL("locked below quorum"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("v2"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 ||
        memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("did not lock on A"); return;
    }
    if (s.valid_round != 0 || memcmp(s.valid_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("validValue/validRound not set"); return;
    }
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("step"); return; }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 1) {
        fx_free(&f); FAIL("no PRECOMMIT id(v)"); return;
    }
    if (memcmp(s.last_precommit_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0 ||
        s.last_precommit_round != 0) {
        fx_free(&f); FAIL("last_precommit not recorded"); return;
    }
    fx_free(&f);
    PASS();
}

static void test_e_l36_at_precommit_step(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    uint32_t i, emits_before;
    uint64_t t;

    /* Lines 42-43 run for every step >= prevote, but 37-41 only at prevote.
     * Reaching step = precommit through timeoutPrevote (and NOT through 2f+1
     * nil prevotes, which cannot coexist with 2f+1 id prevotes in one round)
     * makes the difference observable. */
    TEST("E line 36 at step=precommit: validValue only, no lock, no PRECOMMIT");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 7, 1) != 0) { FAIL("fixture"); return; }
    if (proposer_index(&f, 0) == 1) { fx_free(&f); FAIL("self is the proposer"); return; }

    if (tm_core_on_tick(f.core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    /* four prevotes for A plus self's nil = 5 = quorum(7): line 34 arms. */
    t = T0 + 4000ull;
    for (i = 2; i <= 5; i++) {
        if (send_vote(&f, DNA_CMSG_PREVOTE, i, 0, idA, t + i) != 0) {
            fx_free(&f); FAIL("prevote"); return;
        }
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) { fx_free(&f); FAIL("locked without a proposal"); return; }

    /* timeoutPrevote carries it to precommit with a nil vote */
    if (tm_core_on_tick(f.core, t + 5ull + TM_TIMEOUT_PREVOTE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("step is not precommit"); return; }

    /* now the proposal and the fifth A prevote arrive */
    if (send_proposal(&f, proposer_index(&f, 0), 0, (uint8_t)TAG_A, -1, t + 9000) != 0) {
        fx_free(&f); FAIL("late proposal rejected"); return;
    }
    emits_before = f.hc.n_emit;
    if (send_vote(&f, DNA_CMSG_PREVOTE, 6, 0, idA, t + 9100) != 0) {
        fx_free(&f); FAIL("prevote"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.valid_round != 0 || memcmp(s.valid_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("validValue was not updated"); return;
    }
    if (s.locked_round != -1) { fx_free(&f); FAIL("re-locked at step precommit"); return; }
    if (f.hc.n_emit != emits_before) { fx_free(&f); FAIL("emitted a second PRECOMMIT"); return; }
    fx_free(&f);
    PASS();
}

/* ── §F  lines 44-46 ─────────────────────────────────────────────────── */

static void test_f_l44_nil_precommit(void)
{
    fx_t f;
    tm_snapshot_t s;

    TEST("F line 44: 2f+1 nil PREVOTEs -> PRECOMMIT nil");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    if (tm_core_on_tick(f.core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, NIL_ID, T0 + 4100) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 0) {
        fx_free(&f); FAIL("fired below quorum"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, NIL_ID, T0 + 4200) != 0) { fx_free(&f); FAIL("v2"); return; }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 1) {
        fx_free(&f); FAIL("no nil PRECOMMIT at quorum"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("step"); return; }
    if (memcmp(s.last_precommit_id, NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("last_precommit is not nil"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §G  lines 47-48 and 65-67 ───────────────────────────────────────── */

static void test_g_l47_and_next_round(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    uint64_t deadline;
    tm_snapshot_t s;

    TEST("G line 47 arms timeoutPrecommit once; 65-67 opens the next round");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    /* self = index 2 so that the round it lands in (1) belongs to index 1 and
     * the new round really does stay at step = propose. */
    if (fx_init(&f, 4, 2) != 0) { FAIL("fixture"); return; }

    /* three PRECOMMITs with DIFFERENT values: quorum for "*" but for no id,
     * so line 49 cannot fire and only line 47 is measured. */
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 10) != 0) { fx_free(&f); FAIL("p0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 1, 0, idB, T0 + 20) != 0) { fx_free(&f); FAIL("p1"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 0, NIL_ID, T0 + 30) != 0) { fx_free(&f); FAIL("p3"); return; }

    deadline = T0 + 30ull + TM_TIMEOUT_PRECOMMIT_INIT_MS;
    if (tm_core_on_tick(f.core, deadline - 1ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.round != 0) { fx_free(&f); FAIL("round moved before the deadline"); return; }

    if (tm_core_on_tick(f.core, deadline) != 0) { fx_free(&f); FAIL("tick"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("timeoutPrecommit did not open round 1"); return; }
    if (f.hc.n_round_start < 2 || f.hc.last_round_started != 1) {
        fx_free(&f); FAIL("on_round_start not reported"); return;
    }
    if (s.step != TM_STEP_PROPOSE) { fx_free(&f); FAIL("new round must start at propose"); return; }
    fx_free(&f);
    PASS();
}

/* ── §H  lines 49-54 and the IDLE state ──────────────────────────────── */

static void test_h_decide_any_round(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    uint32_t emits_after;

    TEST("H line 49 decides on ANY round, names voters, then goes IDLE");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    /* Move to round 1 through line 55 so that round 0's slots stay free. */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 1, NIL_ID, T0 + 10) < 0) { fx_free(&f); FAIL("r1a"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 1, NIL_ID, T0 + 20) != 0) {
        fx_free(&f); FAIL("r1b"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("line 55 did not open round 1"); return; }

    /* Now a complete round-0 commit arrives late. */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 30) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("c0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 2, 0, idA, T0 + 50) != 0) { fx_free(&f); FAIL("c2"); return; }
    if (f.hc.n_decide != 0) { fx_free(&f); FAIL("decided below quorum"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 0, idA, T0 + 60) != 0) { fx_free(&f); FAIL("c3"); return; }

    if (f.hc.n_decide != 1) { fx_free(&f); FAIL("no decision at quorum"); return; }
    if (f.hc.dec_height != 1 || f.hc.dec_round != 0) { fx_free(&f); FAIL("wrong height/round"); return; }
    if (memcmp(f.hc.dec_value_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("wrong value_id"); return;
    }
    if (f.hc.dec_value0 != (uint8_t)TAG_A) { fx_free(&f); FAIL("wrong value bytes"); return; }
    if (f.hc.dec_voters != 3) { fx_free(&f); FAIL("wrong voter count"); return; }
    if (memcmp(f.hc.dec_voter_ids[0], f.ids[0], DNA_CONSENSUS_ID_LEN) != 0 ||
        memcmp(f.hc.dec_voter_ids[1], f.ids[2], DNA_CONSENSUS_ID_LEN) != 0 ||
        memcmp(f.hc.dec_voter_ids[2], f.ids[3], DNA_CONSENSUS_ID_LEN) != 0) {
        fx_free(&f); FAIL("voters are not in ascending identity order"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (!s.decided || s.round != 1) { fx_free(&f); FAIL("snapshot after decide"); return; }

    /* IDLE: nothing more for this height, and no timer survives. */
    emits_after = f.hc.n_emit;
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 1, idA, T0 + 70) != 1) {
        fx_free(&f); FAIL("accepted a message for a decided height"); return;
    }
    if (tm_core_on_tick(f.core, T0 + 10000000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != emits_after || f.hc.n_decide != 1) {
        fx_free(&f); FAIL("the core was not IDLE after deciding"); return;
    }
    fx_free(&f);
    PASS();
}

static void test_h_invalid_never_decides(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];

    TEST("H line 50: an INVALID value is never decided even with 2f+1");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    f.hc.valid_result = 0;

    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 20) != 0) { fx_free(&f); FAIL("c0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 2, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("c2"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("c3"); return; }
    if (f.hc.n_decide != 0) { fx_free(&f); FAIL("decided an invalid value"); return; }
    /* the stub really was consulted — otherwise this section proves nothing */
    if (f.hc.valid_calls == 0) { fx_free(&f); FAIL("valid() was never called"); return; }
    fx_free(&f);
    PASS();
}

/* ── §I  lines 55-56 ─────────────────────────────────────────────────── */

static void test_i_l55_needs_f_plus_one(void)
{
    fx_t f;
    tm_snapshot_t s;

    TEST("I line 55 needs f+1 DISTINCT senders; one is not enough");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 3, NIL_ID, T0 + 10) != 0) { fx_free(&f); FAIL("a"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.round != 0) { fx_free(&f); FAIL("jumped on one sender"); return; }

    /* the SAME sender again is a duplicate, not a second voice */
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 3, NIL_ID, T0 + 20) != 0) { fx_free(&f); FAIL("b"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.round != 0) { fx_free(&f); FAIL("one sender counted twice"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 3, NIL_ID, T0 + 30) != 0) {
        fx_free(&f); FAIL("second f+1 sender"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.round != 3) { fx_free(&f); FAIL("did not jump to round 3"); return; }
    if (f.hc.last_round_started != 3) { fx_free(&f); FAIL("on_round_start"); return; }
    fx_free(&f);
    PASS();
}

/* ── §J  stale timers ────────────────────────────────────────────────── */

static void test_j_stale_timer_discarded(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    uint32_t before;

    TEST("J a timer for a round the node has left does nothing (58/62/66)");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    /* arm timeoutPrevote at round 0 */
    if (tm_core_on_tick(f.core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 4010) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idB, T0 + 4020) != 0) { fx_free(&f); FAIL("v2"); return; }

    /* Leave round 0 through line 55 BEFORE that deadline. The two jump
     * messages are PRECOMMITs, and the type matters: line 55 counts f+1
     * DISTINCT SENDERS with ANY message at the higher round, so a PRECOMMIT
     * carries the jump exactly as a PREVOTE would — but it leaves round 2's
     * PREVOTE tally empty. With nil PREVOTEs here, the round-2 propose timeout
     * below adds this node's own nil PREVOTE and the round would hold 3 nil
     * prevotes = quorum(4): lines 34 AND 44 would fire, the node would reach
     * step = precommit and emit a round-2 PRECOMMIT of its own, and the
     * assertion "no PRECOMMIT at round 2" would be measuring line 44 instead
     * of the stale timer it is named after. Two round-2 PRECOMMITs are 2 <
     * quorum(4) = 3, so line 47 does not fire either and the round stays at
     * step = prevote with nothing of its own precommitted. */
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 2, NIL_ID, T0 + 4030) < 0) { fx_free(&f); FAIL("j1"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 2, NIL_ID, T0 + 4040) != 0) {
        fx_free(&f); FAIL("j2"); return;
    }
    {
        tm_snapshot_t s;
        tm_core_snapshot(f.core, &s);
        if (s.round != 2) { fx_free(&f); FAIL("did not leave round 0"); return; }
    }

    before = count_emits(&f, DNA_CMSG_PRECOMMIT, 0);

    /* THE DISCRIMINATING TICK (Codex mutation). One tick, late enough that BOTH
     * the round-2 propose timer and the stale round-0 prevote timer are due.
     * The fixed scan order fires PROPOSE first, so by the time the stale
     * PREVOTE slot is taken the node IS at step = prevote — and the ONLY thing
     * left standing between it and a round-2 PRECOMMIT is the round equality
     * check at line 62. Before, the step check alone would have covered for a
     * missing round check and the assertion measured nothing. */
    if (tm_core_on_tick(f.core,
                        T0 + 4040ull + TM_TIMEOUT_PROPOSE_INIT_MS
                                     + 2ull * TM_TIMEOUT_PROPOSE_DELTA_MS) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    {
        tm_snapshot_t s;
        tm_core_snapshot(f.core, &s);
        if (s.round != 2 || s.step != TM_STEP_PREVOTE) {
            fx_free(&f); FAIL("round 2 did not reach step prevote"); return;
        }
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 2) != 1) {
        fx_free(&f); FAIL("the round-2 propose timeout did not fire"); return;
    }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != before ||
        count_emits(&f, DNA_CMSG_PRECOMMIT, 2) != 0) {
        fx_free(&f); FAIL("a stale timeoutPrevote acted in the CURRENT round"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §K  equivocation ────────────────────────────────────────────────── */

static void test_k_equivocation(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("K a duplicate is rc 1; a second DIFFERENT value is rc 2 and reported");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 10) != 0) { fx_free(&f); FAIL("first"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 20) != 1) {
        fx_free(&f); FAIL("a repeat of the SAME vote is not a duplicate"); return;
    }
    if (f.hc.n_equiv != 0) { fx_free(&f); FAIL("a duplicate was reported as equivocation"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idB, T0 + 30) != 2) {
        fx_free(&f); FAIL("a conflicting vote was not reported"); return;
    }
    if (f.hc.n_equiv != 1) { fx_free(&f); FAIL("on_equivocation not called"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.equivocations != 1) { fx_free(&f); FAIL("counter"); return; }

    /* THE FIRST VALUE STILL COUNTS. Slot 0 holds v2's A, this node PREVOTEs A
     * on the proposal (line 22), v0 PREVOTEs A: three DISTINCT senders for A =
     * quorum(4), so line 36 locks. */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 40) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 50) != 0) { fx_free(&f); FAIL("v0"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the FIRST vote did not count"); return;
    }

    /* A conflicting PROPOSAL is NOT the same rule: the proposal slot stays
     * single (design §5.4), because a proposal is not counted toward any
     * threshold and a second one would buy the proposer nothing. */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_B, -1, T0 + 60) != 2) {
        fx_free(&f); FAIL("a double proposal was not reported"); return;
    }
    if (f.hc.n_equiv != 2) { fx_free(&f); FAIL("proposal equivocation not counted"); return; }
    fx_free(&f);
    PASS();
}

/* THE SECOND VALUE COUNTS FOR ITS OWN THRESHOLD — the whole reason two slots
 * exist (design §5.4, Codex C-2). Same shape as §K above with the roles of the
 * equivocator's two values swapped: the quorum is completed by the value that
 * arrived SECOND. Under one slot per sender this is the permanent local stall
 * that was measured at n = 4 — B would count 2 of 3 forever, with no message
 * left in the protocol that could repair it. */
static void test_k_second_value_counts(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("K the SECOND value of an equivocator completes its own quorum");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 10) != 0) { fx_free(&f); FAIL("first"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idB, T0 + 20) != 2) {
        fx_free(&f); FAIL("the second value was not reported"); return;
    }

    /* B now stands in v2's SECOND slot. The proposal makes this node PREVOTE B
     * (line 22, no lock held), v0 PREVOTEs B, and B needs v2's second slot to
     * reach 3 distinct senders. */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_B, -1, T0 + 30) != 0) { fx_free(&f); FAIL("p"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) { fx_free(&f); FAIL("locked on two prevotes"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idB, T0 + 40) != 0) { fx_free(&f); FAIL("v0"); return; }

    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idB, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the SECOND value did not count towards its quorum"); return;
    }
    if (s.equivocations != 1) { fx_free(&f); FAIL("counter"); return; }
    fx_free(&f);
    PASS();
}

/* A THIRD DISTINCT VALUE IS EVIDENCE ONLY. Same shape again, so the ONLY
 * difference from the test above is which slot the completing vote would have
 * to come from — and there is no third slot, so no quorum forms. Without this
 * case "two slots" and "unbounded slots" both pass every other test here. */
static void test_k_third_value_not_stored(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idC[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("K a THIRD distinct value is reported but never counted");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    mkvalue_id((uint8_t)TAG_C, idC);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 10) != 0) { fx_free(&f); FAIL("first"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idB, T0 + 20) != 2) { fx_free(&f); FAIL("second"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idC, T0 + 30) != 2) {
        fx_free(&f); FAIL("the third value was not reported"); return;
    }
    /* Every rc 2 is one piece of evidence, so three votes from one sender for
     * three values report twice. The chosen behaviour, pinned. */
    tm_core_snapshot(f.core, &s);
    if (s.equivocations != 2 || f.hc.n_equiv != 2) {
        fx_free(&f); FAIL("the third value was counted as a different number of reports"); return;
    }
    /* A repeat of the DROPPED third value is still a third distinct value, not
     * a duplicate: it was never stored, so there is nothing to duplicate. */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idC, T0 + 40) != 2) {
        fx_free(&f); FAIL("a repeat of the dropped value changed the answer"); return;
    }

    if (send_proposal(&f, 0, 0, (uint8_t)TAG_C, -1, T0 + 50) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idC, T0 + 60) != 0) { fx_free(&f); FAIL("v0"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) {
        fx_free(&f); FAIL("the third value reached a quorum"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §K-b  two values cannot both reach a quorum ─────────────────────── */

/* THE SAFETY ARGUMENT, MEASURED. Counting an equivocator for BOTH of its
 * values does not let two values reach a quorum in one round, and the reason
 * is arithmetic on SENDER SETS, not on votes: two quorums of q = 3 over n = 4
 * intersect in at least 2q - n = 2 = f+1 senders, at most f = 1 of them is
 * Byzantine, so at least one HONEST sender is in both — and an honest sender
 * votes once per (h, r, type), so it cannot be in the quorums of two different
 * values.
 *
 * Here: senders 0 and 1 are honest and vote A, sender 3 is honest and votes B,
 * sender 2 equivocates and is counted for BOTH. count(A) = {0, 1, 2} = 3 =
 * quorum; count(B) = {2, 3} = 2. B cannot be completed, because the only
 * senders left are 0 and 1 and they have already spent their one vote on A.
 *
 * This runs on the LOG DIRECTLY rather than through a scenario, because every
 * rule that could report a quorum is "for the first time" per round — once
 * line 36 has fired for A, a scenario can no longer tell "B did not reach a
 * quorum" apart from "B reached one and the flag suppressed it". */
static void test_k_b_two_quorums_impossible(void)
{
    tm_log_t log;
    tm_round_t *r;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    const uint32_t N = 4u;
    const uint32_t Q = 3u;               /* dna_bft_quorum(4), pinned by §0 */

    TEST("K-b one equivocator counted twice still yields only ONE quorum");

    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    tm_log_init(&log, 1, N, 4u * VAL_LEN);

    if (dna_bft_quorum(N) != Q) { tm_log_clear(&log); FAIL("quorum literal"); return; }

    if (tm_log_put_vote(&log, 0, 0, 0, idA, NULL) != TM_PUT_LOGGED ||
        tm_log_put_vote(&log, 0, 1, 0, idA, NULL) != TM_PUT_LOGGED ||
        tm_log_put_vote(&log, 0, 2, 0, idA, NULL) != TM_PUT_LOGGED ||
        tm_log_put_vote(&log, 0, 3, 0, idB, NULL) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup"); return;
    }
    /* sender 2 equivocates: recorded, reported, and counted for B as well */
    if (tm_log_put_vote(&log, 0, 2, 0, idB, NULL) != TM_PUT_EQUIV) {
        tm_log_clear(&log); FAIL("the second value was not reported"); return;
    }

    r = tm_log_round(&log, 0, 0);
    if (!r) { tm_log_clear(&log); FAIL("round slot"); return; }

    if (tm_log_count_votes(r, N, 0, idA) != 3u) {
        tm_log_clear(&log); FAIL("count(A) is not 3"); return;
    }
    if (tm_log_count_votes(r, N, 0, idB) != 2u) {
        tm_log_clear(&log); FAIL("count(B) is not 2"); return;
    }
    if (tm_log_count_votes(r, N, 0, idA) < Q && tm_log_count_votes(r, N, 0, idB) < Q) {
        tm_log_clear(&log); FAIL("neither value reached a quorum"); return;
    }
    if (tm_log_count_votes(r, N, 0, idA) >= Q && tm_log_count_votes(r, N, 0, idB) >= Q) {
        tm_log_clear(&log); FAIL("BOTH values reached a quorum"); return;
    }

    /* The "*" count (lines 34/47/55) is DISTINCT SENDERS, so the equivocator
     * contributes one, not two — four senders have voted, not five. */
    if (tm_log_count_votes(r, N, 0, NULL) != 4u) {
        tm_log_clear(&log); FAIL("the * count double-counted the equivocator"); return;
    }
    /* A sender never counts twice for ONE value either: a repeat of a value
     * already in a slot is a duplicate and changes nothing. */
    if (tm_log_put_vote(&log, 0, 0, 0, idA, NULL) != TM_PUT_DUP) {
        tm_log_clear(&log); FAIL("a repeat was not a duplicate"); return;
    }
    if (tm_log_count_votes(r, N, 0, idA) != 3u) {
        tm_log_clear(&log); FAIL("a duplicate moved the count"); return;
    }
    /* PRECOMMITs are a separate tally at the same round: nothing above leaked. */
    if (tm_log_count_votes(r, N, 1, idA) != 0u || tm_log_count_votes(r, N, 1, NULL) != 0u) {
        tm_log_clear(&log); FAIL("prevotes leaked into the precommit tally"); return;
    }

    tm_log_clear(&log);
    PASS();
}

/* ── §L  the round lookahead ─────────────────────────────────────────── */

static void test_l_lookahead(void)
{
    fx_t f;

    TEST("L round_p + lookahead is admitted, one more is refused");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, TM_ROUND_LOOKAHEAD, NIL_ID, T0 + 10) != 0) {
        fx_free(&f); FAIL("the boundary round was refused"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, TM_ROUND_LOOKAHEAD + 1u, NIL_ID, T0 + 20) != 1) {
        fx_free(&f); FAIL("a round past the lookahead was accepted"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 1000000u, NIL_ID, T0 + 30) != 1) {
        fx_free(&f); FAIL("a far-future round was accepted"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §M  the h+1 buffer ──────────────────────────────────────────────── */

static void test_m_h1_buffer(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("M h+1 is buffered and drained by start_height; h+2 is refused");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 2) != 0) { FAIL("fixture"); return; }   /* self = index 2 */

    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 0, 2, 0, idA, T0 + 10) != 0) {
        fx_free(&f); FAIL("h+1 was not buffered"); return;
    }
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 3, 3, 0, idA, T0 + 20) != 1) {
        fx_free(&f); FAIL("h+2 was accepted"); return;
    }

    /* finish height 1 */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 30) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("c0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 1, 0, idA, T0 + 50) != 0) { fx_free(&f); FAIL("c1"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 0, idA, T0 + 60) != 0) { fx_free(&f); FAIL("c3"); return; }
    if (f.hc.n_decide != 1) { fx_free(&f); FAIL("height 1 did not decide"); return; }

    /* the host advances the proposer object and opens height 2 */
    if (tm_proposer_next_height(f.prop, &f.set) != 0) { fx_free(&f); FAIL("next_height"); return; }
    if (fx_start_height(&f, 2, T0 + 100) != 0) {
        fx_free(&f); FAIL("start_height(2)"); return;
    }
    if (proposer_index(&f, 0) == 2) { fx_free(&f); FAIL("self is the height-2 proposer"); return; }

    /* The buffered PREVOTE from v0 must be IN the round-0 log: with it plus
     * this node's own prevote plus one more, quorum(4) = 3 is reached and the
     * node locks. Without it there would be only two and no lock. */
    if (send_proposal(&f, proposer_index(&f, 0), 0, (uint8_t)TAG_A, -1, T0 + 110) != 0) {
        fx_free(&f); FAIL("height-2 proposal"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 0, idA, T0 + 120) != 0) { fx_free(&f); FAIL("v3"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.height != 2) { fx_free(&f); FAIL("height"); return; }
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the buffered h+1 PREVOTE was lost"); return;
    }
    fx_free(&f);
    PASS();
}

static void test_m_b_h1_dedup(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* One member repeating a vote must not be able to fill the h+1 buffer:
     * the key is (round, sender, type) and the FIRST record wins. The
     * discriminating assertion is the last one — after the height opens, the
     * value that counts towards quorum is A (the first), not B. */
    TEST("M-b h+1 buffer keeps the FIRST record per (round, sender, type)");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    if (fx_init(&f, 4, 2) != 0) { FAIL("fixture"); return; }   /* self = index 2 */

    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 0, 2, 0, idA, T0 + 10) != 0) {
        fx_free(&f); FAIL("first h+1 vote was not buffered"); return;
    }
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 0, 2, 0, idA, T0 + 20) != 1) {
        fx_free(&f); FAIL("an identical repeat was buffered again"); return;
    }
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 0, 2, 0, idB, T0 + 30) != 1) {
        fx_free(&f); FAIL("a conflicting value was buffered as a second record"); return;
    }
    /* a DIFFERENT member still gets in, and so does a different type */
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 3, 2, 0, idA, T0 + 40) != 0) {
        fx_free(&f); FAIL("a second member was rejected"); return;
    }
    if (send_vote_h(&f, DNA_CMSG_PRECOMMIT, 0, 2, 0, idA, T0 + 50) != 0) {
        fx_free(&f); FAIL("a different type from the same member was rejected"); return;
    }

    /* finish height 1 and open height 2 */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 60) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 70) != 0) { fx_free(&f); FAIL("c0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 1, 0, idA, T0 + 80) != 0) { fx_free(&f); FAIL("c1"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 0, idA, T0 + 90) != 0) { fx_free(&f); FAIL("c3"); return; }
    if (f.hc.n_decide != 1) { fx_free(&f); FAIL("height 1 did not decide"); return; }
    if (tm_proposer_next_height(f.prop, &f.set) != 0) { fx_free(&f); FAIL("next_height"); return; }
    if (fx_start_height(&f, 2, T0 + 100) != 0) { fx_free(&f); FAIL("start_height(2)"); return; }

    /* v0's FIRST vote (A) plus v3's plus this node's own reaches quorum(4) = 3
     * on A. If B had displaced A, A would stall at 2 and no lock would form. */
    if (send_proposal(&f, proposer_index(&f, 0), 0, (uint8_t)TAG_A, -1, T0 + 110) != 0) {
        fx_free(&f); FAIL("height-2 proposal"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the FIRST buffered value did not count"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §T  start_height monotonicity ───────────────────────────────────── */

static void test_t_height_monotonicity(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* Re-opening the height the core is already at would wipe the log and
     * last_*, and the node could then vote a SECOND time in a round it had
     * already voted in (G4). A forward jump of more than one stays legal — a
     * node that fell behind and re-synced must be able to land at h+2. */
    TEST("T start_height refuses h <= height; h + 2 is accepted, no drain");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (tm_core_start_height(f.core, 1, &f.set, f.prop, T0 + 10) == 0) {
        fx_free(&f); FAIL("re-opened the SAME height"); return;
    }
    /* height 0 is the "not open" sentinel, never a real height */
    if (tm_core_start_height(f.core, 0, &f.set, f.prop, T0 + 10) == 0) {
        fx_free(&f); FAIL("opened height 0"); return;
    }
    /* the refusal must have changed nothing */
    tm_core_snapshot(f.core, &s);
    if (s.height != 1 || s.round != 0) { fx_free(&f); FAIL("a refused call moved the state"); return; }

    /* a buffered h+1 record is NOT drained by a jump to h+2 */
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 0, 2, 0, idA, T0 + 20) != 0) {
        fx_free(&f); FAIL("h+1 buffering"); return;
    }
    if (tm_proposer_next_height(f.prop, &f.set) != 0) { fx_free(&f); FAIL("nh1"); return; }
    if (tm_proposer_next_height(f.prop, &f.set) != 0) { fx_free(&f); FAIL("nh2"); return; }
    if (fx_start_height(&f, 3, T0 + 30) != 0) { fx_free(&f); FAIL("h+2 was refused"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.height != 3) { fx_free(&f); FAIL("height"); return; }

    /* The buffered height-2 vote must be GONE, not silently applied at 3: with
     * only two more prevotes, quorum(4) = 3 must NOT be reached. */
    if (send_proposal(&f, proposer_index(&f, 0), 0, (uint8_t)TAG_A, -1, T0 + 40) != 0) {
        fx_free(&f); FAIL("height-3 proposal"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 50) != 0) { fx_free(&f); FAIL("v0"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) {
        fx_free(&f); FAIL("a stale buffered vote leaked into h+2"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §N  valid() FAULT and the memo ──────────────────────────────────── */

static void test_n_valid_fault_and_memo(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    uint32_t calls_after_fire;

    TEST("N valid() = -1 defers without memoising; 1/0 is asked once");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    f.hc.fault_budget = 2;

    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) { fx_free(&f); FAIL("p"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("voted while valid() was FAULT"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PROPOSE) { fx_free(&f); FAIL("step advanced on a FAULT"); return; }
    if (f.hc.valid_calls != 1) { fx_free(&f); FAIL("valid() call count"); return; }

    /* a tick BEFORE the propose deadline asks again */
    if (tm_core_on_tick(f.core, T0 + 20) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.valid_calls != 2) { fx_free(&f); FAIL("FAULT was memoised"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("voted on the second FAULT"); return; }

    /* the fault budget is spent: the next ask succeeds and the rule fires */
    if (tm_core_on_tick(f.core, T0 + 30) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, idA)) {
        fx_free(&f); FAIL("the rule never fired after the FAULT cleared"); return;
    }
    calls_after_fire = f.hc.valid_calls;

    /* the VERDICT is memoised: more traffic must not re-ask for this value */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 50) != 0) { fx_free(&f); FAIL("v2"); return; }
    if (f.hc.valid_calls != calls_after_fire) {
        fx_free(&f); FAIL("valid() was asked again for a memoised value"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0) { fx_free(&f); FAIL("did not proceed to lock"); return; }
    fx_free(&f);
    PASS();
}

/* ── §O  replay ──────────────────────────────────────────────────────── */

static int replay_msg(fx_t *f, dna_cmsg_type_t type, uint32_t sender, uint32_t round,
                      const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    dna_cmsg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.height = f->height;
    m.round = round;
    m.valid_round = -1;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    memcpy(m.value_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
    return tm_core_replay_message(f->core, &m);
}

static int replay_proposal(fx_t *f, uint32_t sender, uint32_t round, uint8_t tag, int32_t vr)
{
    dna_cmsg_t m;
    uint8_t value[VAL_LEN];
    memset(&m, 0, sizeof(m));
    memset(value, tag, VAL_LEN);
    m.type = DNA_CMSG_PROPOSAL;
    m.height = f->height;
    m.round = round;
    m.valid_round = vr;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    mkvalue_id(tag, m.value_id);
    m.value = value;
    m.value_len = VAL_LEN;
    return tm_core_replay_message(f->core, &m);
}

static void test_o_replay_silent_and_keeps_lock(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("O replay emits nothing, keeps the lock, and arms no timer");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 0, 1) != 0) { FAIL("fixture"); return; }   /* self IS proposer(0) */
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("start_height emitted in replay"); return; }
    if (f.hc.gv_calls != 0) { fx_free(&f); FAIL("get_value was called in replay"); return; }

    if (replay_proposal(&f, 0, 0, (uint8_t)TAG_A, -1) != 0) { fx_free(&f); FAIL("wal proposal"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 0, 0, idA) < 0) { fx_free(&f); FAIL("wal own prevote"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 2, 0, idA) < 0) { fx_free(&f); FAIL("wal v2"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 3, 0, idA) < 0) { fx_free(&f); FAIL("wal v3"); return; }
    /* The rule fired and locked, but in replay it wrote NO own vote — the own
     * PRECOMMIT comes from the WAL, which is what a real WAL contains
     * (design §5.9). */
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA) < 0) {
        fx_free(&f); FAIL("wal own precommit"); return;
    }

    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("replay emitted"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("replay did not rebuild the lock"); return;
    }
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("replay step"); return; }
    if (memcmp(s.last_precommit_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("replay did not record the own PRECOMMIT"); return;
    }

    /* step = precommit, no own proposal missing, l34 fired but step is not
     * prevote, l47 not fired: design §5.9 arms nothing. */
    tm_core_replay_end(f.core, 50000ull);
    if (tm_core_on_tick(f.core, 50000ull + 1000000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("a timer was armed that should not be"); return; }
    fx_free(&f);
    PASS();
}

static void test_o_replay_end_rearms(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    const uint64_t RE = 50000ull;

    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);

    TEST("O replay_end re-arms the three timers by the design table");

    /* (a) step = propose with no own proposal -> timeoutPropose */
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture a"); return; }
    tm_core_replay_end(f.core, RE);
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PROPOSE_INIT_MS - 1ull) != 0) {
        fx_free(&f); FAIL("tick a"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("a: fired early"); return; }
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick a"); return;
    }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, NIL_ID)) {
        fx_free(&f); FAIL("a: timeoutPropose was not re-armed"); return;
    }
    fx_free(&f);

    /* (b) l34 fired and step = prevote -> timeoutPrevote */
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture b"); return; }
    if (tm_core_replay_timeout(f.core, 1, 0, TM_STEP_PROPOSE) != 0) {
        fx_free(&f); FAIL("b: wal timeout"); return;
    }
    /* THE OWN NIL PREVOTE IS A WAL RECORD, not a side effect of replaying the
     * timeout. In replay this node's own votes come ONLY from the WAL
     * (design §5.9), so the timeout record above advances `step` and writes
     * nothing into the own slot — which is exactly what a real WAL looks like,
     * because the vote the timeout produced was persisted as its own record
     * before it was sent. Without replaying it here the round holds two
     * prevotes, line 34 never fires, and replay_end has no `l34_fired` to
     * derive the timer from. */
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 0, NIL_ID) < 0) { fx_free(&f); FAIL("b own"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 0, 0, idA) < 0) { fx_free(&f); FAIL("b v0"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 2, 0, idB) < 0) { fx_free(&f); FAIL("b v2"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("b: replay emitted"); return; }
    tm_core_replay_end(f.core, RE);
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PREVOTE_INIT_MS - 1ull) != 0) {
        fx_free(&f); FAIL("tick b"); return;
    }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 0) { fx_free(&f); FAIL("b: fired early"); return; }
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PREVOTE_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick b"); return;
    }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 1) {
        fx_free(&f); FAIL("b: timeoutPrevote was not re-armed"); return;
    }
    fx_free(&f);

    /* (c) l47 fired and not decided -> timeoutPrecommit -> next round */
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture c"); return; }
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA) < 0) { fx_free(&f); FAIL("c p0"); return; }
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 2, 0, idB) < 0) { fx_free(&f); FAIL("c p2"); return; }
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 3, 0, NIL_ID) < 0) { fx_free(&f); FAIL("c p3"); return; }
    tm_core_replay_end(f.core, RE);
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PRECOMMIT_INIT_MS - 1ull) != 0) {
        fx_free(&f); FAIL("tick c"); return;
    }
    {
        tm_snapshot_t s;
        tm_core_snapshot(f.core, &s);
        if (s.round != 0) { fx_free(&f); FAIL("c: fired early"); return; }
    }
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PRECOMMIT_INIT_MS) != 0) {
        fx_free(&f); FAIL("tick c"); return;
    }
    {
        tm_snapshot_t s;
        tm_core_snapshot(f.core, &s);
        if (s.round != 1) { fx_free(&f); FAIL("c: timeoutPrecommit was not re-armed"); return; }
    }
    fx_free(&f);
    PASS();
}

/* ── §O-d  G4 across a restart (design §5.9) ─────────────────────────── */

static void test_o_d_own_vote_from_wal(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    const uint64_t RE = 50000ull;

    /* THE DEFECT THIS PINS. The WAL holds this node's own PREVOTE(A) for
     * (h, 0). On replay the host's valid() answers FAULT, so rule_l22 cannot
     * re-fire and nothing else would move step off propose. replay_end would
     * then see "step = propose and no own PROPOSAL", arm timeoutPropose, and
     * the timeout would broadcast a nil PREVOTE — a SECOND, DIFFERENT vote for
     * a round this node had already voted in.
     *
     * VACUITY GUARD: if valid() answered 1 instead of FAULT, rule_l22 would
     * fire during replay and set step itself, and this section would pass
     * without the restore existing at all. Step 2 therefore asserts the state
     * BEFORE the own vote is replayed — step still propose, last_prevote_round
     * still -1, and valid() actually consulted — which is only true on the
     * FAULT path. */
    TEST("O-d G4 on restart: own PREVOTE from the WAL restores step and last_*");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture"); return; }   /* self = 1, not proposer(0) */
    f.hc.fault_budget = 1000000;                                     /* valid() always FAULTs */

    /* 1. the proposer's PROPOSAL(A) comes back from the WAL */
    if (replay_proposal(&f, 0, 0, (uint8_t)TAG_A, -1) != 0) {
        fx_free(&f); FAIL("wal proposal"); return;
    }
    /* 2. the FAULT really happened and no rule fired */
    if (f.hc.valid_calls == 0) { fx_free(&f); FAIL("valid() was never consulted"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PROPOSE || s.last_prevote_round != -1) {
        fx_free(&f); FAIL("rule_l22 fired — the FAULT path was not exercised"); return;
    }

    /* 3. this node's OWN prevote comes back from the WAL */
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 0, idA) != 0) {
        fx_free(&f); FAIL("wal own prevote"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (memcmp(s.last_prevote_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0 ||
        s.last_prevote_round != 0) {
        fx_free(&f); FAIL("last_prevote_* was not restored from the WAL"); return;
    }
    if (s.step < TM_STEP_PREVOTE) { fx_free(&f); FAIL("step was not raised"); return; }

    /* 4. replay_end must NOT arm timeoutPropose, and no nil vote may leave */
    tm_core_replay_end(f.core, RE);
    if (tm_core_on_tick(f.core, RE + TM_TIMEOUT_PROPOSE_INIT_MS + 1000ull) != 0) {
        fx_free(&f); FAIL("tick"); return;
    }
    if (f.hc.n_emit != 0) {
        fx_free(&f); FAIL("a second, different vote left after the restart"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (memcmp(s.last_prevote_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("last_prevote_id changed after the timeout"); return;
    }
    fx_free(&f);
    PASS();
}

static void test_o_d_duplicate_own_vote(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    const uint64_t RE = 50000ull;

    /* The same own vote appearing TWICE in the WAL must be idempotent, and the
     * restored vote must then be USABLE: it counts towards this height's
     * thresholds exactly as if the node had just cast it.
     *
     * The count assertions are the point. `count_emits(PREVOTE, 0) == 0` says
     * the node never re-sent a vote it had already sent before the crash —
     * that is the G4 half. `count_emits(PRECOMMIT, 0) == 1` says it still made
     * progress — and it is the VACUITY GUARD, because line 36 requires
     * step >= prevote: without the restore of step this leg would be 0 and the
     * "no re-emission" assertion would be trivially satisfied by a node that
     * had simply stopped working.
     *
     * HONEST LIMIT: broadcast_vote's own-slot early return is the BACKSTOP,
     * not the primary defence. The primary ones are the two restore rules —
     * §O-d's own-vote authority and §O-f's own-slot adoption on round entry —
     * and with both in place no input the HOST CONTRACT permits reaches the
     * backstop. What this section measures is therefore the LOG-level
     * idempotence plus the absence of a second emission, not that branch. The
     * section below constructs the one input that violates the contract — a
     * message whose sender is this node — because it is the only route to the
     * branch, and pins what the branch must not do. */
    TEST("O-d the same own vote twice is idempotent and still counts");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture"); return; }
    f.hc.valid_result = 1;

    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 0, idA) != 0) {
        fx_free(&f); FAIL("wal own prevote"); return;
    }
    /* the second copy is a plain duplicate */
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 0, idA) != 1) {
        fx_free(&f); FAIL("the second copy was not a duplicate"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (memcmp(s.last_prevote_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0 ||
        s.last_prevote_round != 0 || s.step != TM_STEP_PREVOTE) {
        fx_free(&f); FAIL("the duplicate disturbed the restored state"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("replay emitted"); return; }

    tm_core_replay_end(f.core, RE);

    /* Live again: the proposal arrives, then two more prevotes for A. With the
     * restored own vote that is quorum(4) = 3 and line 36 must lock and
     * precommit — while never re-sending the prevote. */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, RE + 10) != 0) {
        fx_free(&f); FAIL("proposal"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, RE + 20) != 0) { fx_free(&f); FAIL("v2"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 0, idA, RE + 30) != 0) { fx_free(&f); FAIL("v3"); return; }

    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 0) {
        fx_free(&f); FAIL("re-sent a vote already cast before the restart"); return;
    }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 1) {
        fx_free(&f); FAIL("the restored vote did not count towards quorum"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("did not lock on A"); return;
    }
    fx_free(&f);
    PASS();
}

/* THE BACKSTOP REACHED, AND WHAT IT MUST NOT DO UNDER THE TWO-SLOT RULE.
 *
 * broadcast_vote refuses to emit when this node's own slot for (round, type)
 * already holds a vote. Under one slot per sender that refusal could be read
 * off tm_log_put_vote's return code, because the conflicting value was
 * discarded on the way. Under two slots the value would be STORED AND COUNTED
 * (design §5.4), so the check has to happen BEFORE the put — otherwise the
 * node writes a vote it never signed into its own slot and then counts itself
 * towards that value's threshold. One fabricated own vote turns a quorum of
 * 2f+1 into 2f genuine ones, which is the intersection argument safety rests
 * on, broken locally and silently.
 *
 * HOW THE SLOT GETS OCCUPIED HERE: a message whose sender is this node. That
 * cannot happen under the host contract — the host verifies the signature
 * before the core sees the message (dna_consensus.h:3-4), so a `sender ==
 * self` record can only be a vote this node itself signed, and by G4 it signs
 * one per (round, type). It is constructed deliberately because it is the ONLY
 * public-API route to the backstop (§O-d above says the restore rules cover
 * every reachable one), and the property being measured — a vote this node
 * never sent is never counted — has to hold whatever the input was. */
static void test_o_d_backstop_writes_nothing(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("O-d a withheld own vote is not written into this node's own slot");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }        /* self = 1 */

    if (send_vote(&f, DNA_CMSG_PREVOTE, 1, 0, idB, T0 + 10) != 0) {
        fx_free(&f); FAIL("the own slot was not occupied"); return;
    }

    /* The proposer's PROPOSAL(A) makes line 22 want to PREVOTE A. The rule
     * fires — step moves — but the vote is withheld. */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 20) != 0) { fx_free(&f); FAIL("p"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PREVOTE) {
        fx_free(&f); FAIL("line 22 did not fire — the backstop was not reached"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("a second vote for the round left the node"); return; }
    if (s.last_prevote_round != -1) {
        fx_free(&f); FAIL("last_prevote_* moved for a vote that never left"); return;
    }

    /* THE DISCRIMINATOR. Two genuine prevotes for A. With the withheld vote
     * absent from the log, A holds 2 of the 3 it needs and nothing fires; if
     * it had been stored, A would be at quorum(4) = 3 and line 36 would lock
     * and precommit on a vote that was never sent. */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("v2"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("v3"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) {
        fx_free(&f); FAIL("a vote this node never sent was counted towards a quorum"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("it precommitted on a phantom quorum"); return; }
    fx_free(&f);
    PASS();
}

/* ── §O-e  the LOCK comes back from the WAL (G3) ─────────────────────── */

static void test_o_e_lock_from_wal(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    const uint64_t RE = 50000ull;
    uint32_t i;

    /* THE DEFECT THIS PINS (G3). Algorithm 1 broadcasts PRECOMMIT id(v) at
     * line 40 only AFTER lines 38-39 have locked, so the WAL's own non-nil
     * PRECOMMIT IS the lock record. If it is not restored: valid() FAULTs on
     * replay so rule_l36 never re-fires; step is already precommit so 36-41
     * can never run for that round again; lockedRound stays -1; and in the
     * NEXT round line 23 sees "unlocked" and prevotes a DIFFERENT value. At
     * n = 4 that one honest node is the entire safety margin.
     *
     * VACUITY GUARD: step 2 asserts step == propose and locked_round == -1
     * BEFORE the own precommit is replayed, with valid_calls > 0 — proving
     * rule_l36 really did not fire and the lock can only have come from the
     * restore. */
    TEST("O-e replayed own PRECOMMIT restores the lock and later forces nil");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    /* self = index 2: not the proposer at round 0 (index 0) nor at round 1
     * (index 1), so both proposals in this scenario arrive from the wire. */
    if (fx_init_ex(&f, 4, 2, 1) != 0) { FAIL("fixture"); return; }
    f.hc.fault_budget = 1000000;

    if (replay_proposal(&f, 0, 0, (uint8_t)TAG_A, -1) != 0) { fx_free(&f); FAIL("wal proposal"); return; }
    if (f.hc.valid_calls == 0) { fx_free(&f); FAIL("valid() was never consulted"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.step != TM_STEP_PROPOSE || s.locked_round != -1) {
        fx_free(&f); FAIL("rule_l36 fired — the FAULT path was not exercised"); return;
    }

    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 2, 0, idA) != 0) {
        fx_free(&f); FAIL("wal own precommit"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the lock was not restored"); return;
    }
    if (s.valid_round != 0 || memcmp(s.valid_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("validValue was not restored (the bytes ARE in the slot)"); return;
    }
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("step"); return; }

    /* live again, valid() healthy */
    f.hc.fault_budget = 0;
    tm_core_replay_end(f.core, RE);

    /* reach round 1: quorum(4) = 3 PRECOMMITs of any value arm timeoutPrecommit */
    for (i = 0; i < 4u; i++) {
        if (i == 2u) continue;
        if (send_vote(&f, DNA_CMSG_PRECOMMIT, i, 0, NIL_ID, RE + 10 + i) < 0) {
            fx_free(&f); FAIL("precommit"); return;
        }
    }
    if (tm_core_on_tick(f.core, RE + 100000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("did not reach round 1"); return; }

    /* THE POINT: locked on A, a fresh proposal for B must draw a NIL prevote */
    if (send_proposal(&f, proposer_index(&f, 1), 1, (uint8_t)TAG_B, -1, RE + 200000ull) != 0) {
        fx_free(&f); FAIL("round-1 proposal"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 1) != 1) {
        fx_free(&f); FAIL("expected exactly one round-1 PREVOTE"); return;
    }
    for (i = 0; i < f.hc.n_emit; i++) {
        if (f.hc.emits[i].type == DNA_CMSG_PREVOTE && f.hc.emits[i].round == 1 &&
            memcmp(f.hc.emits[i].value_id, NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
            fx_free(&f); FAIL("a node that forgot its lock prevoted B"); return;
        }
    }
    fx_free(&f);
    PASS();
}

static void test_o_e_lock_without_bytes(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* Same record, but the round's proposal is NOT in the log (dropped by the
     * byte cap, or simply never received). The lock still comes back — no rule
     * reads lockedValue's bytes — while validValue does NOT, because
     * validValue is re-proposed and the invariant
     * valid_value == NULL <=> valid_round == -1 must hold. */
    TEST("O-e lock restores without bytes; validValue stays unset");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture"); return; }
    f.hc.fault_budget = 1000000;

    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 1, 0, idA) != 0) {
        fx_free(&f); FAIL("wal own precommit"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the lock was not restored"); return;
    }
    if (s.valid_round != -1) {
        fx_free(&f); FAIL("validValue was restored without its bytes"); return;
    }
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("step"); return; }
    /* a nil PRECOMMIT must NOT create a lock */
    fx_free(&f);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture 2"); return; }
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 1, 0, NIL_ID) != 0) {
        fx_free(&f); FAIL("wal own nil precommit"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) { fx_free(&f); FAIL("a NIL precommit created a lock"); return; }
    fx_free(&f);
    PASS();
}

/* ── §O-f  entering a round, the own slots set the step ──────────────── */

static void test_o_f_own_slot_sets_step(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    const uint64_t RE = 50000ull;

    /* The WAL can hold "own vote at r+1" BEFORE the timeout record that opens
     * r+1 — the vote was produced inside the same tick. Replayed in that
     * order the vote lands while round_p is still r, so only last_* moves;
     * without the entry rule the timeout would then open r+1 at step =
     * propose, replay_end would arm timeoutPropose and the timeout would emit
     * a nil vote for a round already voted in.
     *
     * VACUITY GUARD: step 2 asserts the vote really did land at round 1 while
     * the core was still at round 0 and step propose — if it had been ingested
     * at the current round instead, §O-d would be the thing under test, not
     * this. */
    TEST("O-f entering a round adopts this node's own slots (step + last_*)");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture"); return; }   /* self = 1 */

    /* 1. own PREVOTE for round 1 arrives while the core is at round 0 */
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 1, idA) != 0) {
        fx_free(&f); FAIL("wal own prevote at round 1"); return;
    }
    /* 2. it moved last_* but NOT the round-0 step */
    tm_core_snapshot(f.core, &s);
    if (s.round != 0 || s.step != TM_STEP_PROPOSE) {
        fx_free(&f); FAIL("the round-1 vote changed the round-0 step"); return;
    }
    if (s.last_prevote_round != 1 ||
        memcmp(s.last_prevote_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("last_prevote_* not recorded for the future round"); return;
    }

    /* 3. the timeout record opens round 1 — the own slot must set the step */
    if (tm_core_replay_timeout(f.core, 1, 0, TM_STEP_PRECOMMIT) != 0) {
        fx_free(&f); FAIL("wal timeout"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("round 1 was not opened"); return; }
    if (s.step < TM_STEP_PREVOTE) {
        fx_free(&f); FAIL("the own round-1 slot did not raise the step"); return;
    }

    /* 4. no timer is derived, so nothing is emitted */
    tm_core_replay_end(f.core, RE);
    if (tm_core_on_tick(f.core, RE + 1000000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 0) {
        fx_free(&f); FAIL("a second, different vote left after the restart"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §U  byte-cap reclaim priority and the per-proposal cap (G5/F1) ──── */

static int send_proposal_len(fx_t *f, uint32_t sender, uint32_t round, uint8_t tag,
                             int32_t vr, uint64_t now, size_t len)
{
    dna_cmsg_t m;
    uint8_t value[64];
    memset(&m, 0, sizeof(m));
    memset(value, tag, sizeof(value));
    if (len > sizeof(value)) return -2;
    m.type = DNA_CMSG_PROPOSAL;
    m.height = f->height;
    m.round = round;
    m.valid_round = vr;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    mkvalue_id(tag, m.value_id);
    m.value = value;
    m.value_len = len;
    return tm_core_on_message(f->core, &m, now);
}

static void test_u_reclaim_priority(void)
{
    fx_t f;
    tm_params_t p;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* THE DEFECT THIS PINS (red-team F1). The budget is one value wide. The
     * legitimate proposer of a FUTURE round fills it; then the CURRENT round's
     * proposal arrives. If the reclaim only walked PAST rounds, the current
     * proposal would be refused, and because the proposer arms no
     * timeoutPropose it would sit in the round with nothing logged and no
     * timer — a stop, not a slowdown (G6). */
    TEST("U a future round's bytes yield to the current round, never the reverse");
    mkvalue_id((uint8_t)TAG_A, idA);
    tm_params_default(&p);
    p.max_height_log_bytes = VAL_LEN;      /* room for exactly ONE value */
    p.max_value_bytes      = VAL_LEN;
    if (fx_init_full(&f, 4, 1, 0, &p, 0) != 0) { FAIL("fixture"); return; }

    /* (1) the future round's proposer fills the whole budget */
    if (send_proposal(&f, proposer_index(&f, 3), 3, (uint8_t)TAG_B, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("the round-3 proposal was refused"); return;
    }
    /* (2) the CURRENT round's proposal must still get in, evicting round 3 */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 20) != 0) {
        fx_free(&f); FAIL("the current round was starved by a future round"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 1) {
        fx_free(&f); FAIL("no round-0 PREVOTE — the value did not reach the rules"); return;
    }
    fx_free(&f);

    /* (3) the reverse order: the future round gets NOTHING and the current
     *     round's bytes survive (proved by the lock that needs them). */
    if (fx_init_full(&f, 4, 1, 0, &p, 0) != 0) { FAIL("fixture 2"); return; }
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("round-0 proposal"); return;
    }
    if (send_proposal(&f, proposer_index(&f, 3), 3, (uint8_t)TAG_B, -1, T0 + 20) != 1) {
        fx_free(&f); FAIL("a future round evicted the current round"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("v2"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0) {
        fx_free(&f); FAIL("the current round's bytes were lost"); return;
    }

    fx_free(&f);

    /* (4) the per-proposal cap is what refuses an oversize value, NOT the
     *     height budget: the budget here is FOUR values wide and EMPTY, so a
     *     VAL_LEN+1 value would fit comfortably. It still must not enter, and
     *     nothing may be charged to the budget (Codex mutation). */
    {
        tm_params_t cap = p;
        tm_snapshot_t s;
        cap.max_value_bytes      = VAL_LEN;
        cap.max_height_log_bytes = 4u * VAL_LEN;
        if (fx_init_full(&f, 4, 1, 0, &cap, 0) != 0) { FAIL("fixture cap"); return; }
        if (send_proposal_len(&f, 0, 0, (uint8_t)TAG_B, -1, T0 + 10, VAL_LEN + 1u) != 1) {
            fx_free(&f); FAIL("an oversize PROPOSAL was accepted"); return;
        }
        tm_core_snapshot(f.core, &s);
        if (s.log_value_bytes != 0) {
            fx_free(&f); FAIL("the refused value was charged to the budget"); return;
        }
        fx_free(&f);
    }

    /* (5) the NEXT round may evict PAST rounds but never the CURRENT one.
     *     At round 0 there is no past, so the next round's proposal simply
     *     does not fit — and round 0's bytes are still there afterwards. */
    if (fx_init_full(&f, 4, 1, 0, &p, 0) != 0) { FAIL("fixture 5"); return; }
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("round-0 proposal"); return;
    }
    if (send_proposal(&f, proposer_index(&f, 1), 1, (uint8_t)TAG_B, -1, T0 + 20) != 1) {
        fx_free(&f); FAIL("the next round evicted the current round"); return;
    }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("v2"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != 0) {
        fx_free(&f); FAIL("the current round's bytes were lost to the next round"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §U(6)  a reclaimed slot is REHYDRATED by the same proposal ──────── */

static void test_u_rehydrate(void)
{
    fx_t f;
    tm_params_t p;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* Once the cap reclaims a round's bytes, line 49 can no longer fire for
     * that round: a late but COMPLETE commit becomes locally undecidable and
     * has to wait for the sync path. Re-offering the same proposal is the only
     * local way back, and its identity is unchanged so nothing this node
     * counted moves (design §5.6, Codex C-3).
     *
     * Budget is 3 values wide, the per-proposal cap 2. Rounds 0 (8 bytes),
     * 1 (16) and 2 (16) are written in that order while the node walks
     * forward, and writing round 2 has to reclaim BOTH round 0 and round 1 to
     * fit — which leaves 8 bytes free, exactly the room round 0 needs back.
     *
     * VACUITY GUARD: the quorum of PRECOMMITs is delivered BEFORE the
     * re-offer and must NOT decide. If it did, the re-offer would be
     * decorative and the section would prove nothing. */
    TEST("U(6) a reclaimed round is rehydrated by the same proposal and decides");
    mkvalue_id((uint8_t)TAG_A, idA);
    tm_params_default(&p);
    p.max_height_log_bytes = 3u * VAL_LEN;
    p.max_value_bytes      = 2u * VAL_LEN;
    /* self = 3: not the proposer of rounds 0, 1 or 2 (r mod 4) */
    if (fx_init_full(&f, 4, 3, 0, &p, 0) != 0) { FAIL("fixture"); return; }

    if (send_proposal_len(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10, VAL_LEN) != 0) {
        fx_free(&f); FAIL("round-0 proposal"); return;
    }
    /* walk to round 1 (f+1 = 2 distinct senders at round 1) */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 1, NIL_ID, T0 + 20) != 0) { fx_free(&f); FAIL("j1a"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 1, 1, NIL_ID, T0 + 30) != 0) { fx_free(&f); FAIL("j1b"); return; }
    if (send_proposal_len(&f, 1, 1, (uint8_t)TAG_B, -1, T0 + 40, 2u * VAL_LEN) != 0) {
        fx_free(&f); FAIL("round-1 proposal"); return;
    }
    /* walk to round 2 */
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 2, NIL_ID, T0 + 50) != 0) { fx_free(&f); FAIL("j2a"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 1, 2, NIL_ID, T0 + 60) != 0) { fx_free(&f); FAIL("j2b"); return; }
    if (send_proposal_len(&f, 2, 2, (uint8_t)TAG_C, -1, T0 + 70, 2u * VAL_LEN) != 0) {
        fx_free(&f); FAIL("round-2 proposal"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.round != 2) { fx_free(&f); FAIL("did not reach round 2"); return; }
    if (s.log_value_bytes != 2u * VAL_LEN) {
        fx_free(&f); FAIL("the reclaim did not free rounds 0 and 1"); return;
    }

    /* the round-0 commit arrives in full — and must NOT decide, because the
     * bytes are gone */
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 80) != 0) { fx_free(&f); FAIL("c0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 1, 0, idA, T0 + 90) != 0) { fx_free(&f); FAIL("c1"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 2, 0, idA, T0 + 100) != 0) { fx_free(&f); FAIL("c2"); return; }
    if (f.hc.n_decide != 0) {
        fx_free(&f); FAIL("decided without the value bytes"); return;
    }

    /* the same proposal again: rehydrate, then decide */
    if (send_proposal_len(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 110, VAL_LEN) != 0) {
        fx_free(&f); FAIL("the re-offer was refused"); return;
    }
    if (f.hc.n_decide != 1) { fx_free(&f); FAIL("rehydration did not re-enable line 49"); return; }
    if (f.hc.dec_round != 0 ||
        memcmp(f.hc.dec_value_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("decided the wrong round or value"); return;
    }
    if (f.hc.dec_value0 != (uint8_t)TAG_A) { fx_free(&f); FAIL("wrong value bytes"); return; }

    fx_free(&f);

    /* a DIFFERENT id on a dropped slot is still evidence, not a rehydrate */
    if (fx_init_full(&f, 4, 3, 0, &p, 0) != 0) { FAIL("fixture 2"); return; }
    if (send_proposal_len(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10, VAL_LEN) != 0) {
        fx_free(&f); FAIL("round-0 proposal"); return;
    }
    if (send_proposal_len(&f, 0, 0, (uint8_t)TAG_B, -1, T0 + 20, VAL_LEN) != 2) {
        fx_free(&f); FAIL("a conflicting proposal was not reported"); return;
    }
    fx_free(&f);
    PASS();
}

static int plant_value(tm_log_t *log, uint32_t round, uint32_t sender, uint8_t tag, uint32_t cur)
{
    uint8_t v[VAL_LEN];
    uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN];
    memset(v, tag, VAL_LEN);
    mkvalue_id(tag, id);
    return tm_log_put_proposal(log, round, sender, id, -1, v, VAL_LEN, cur, NULL, NULL);
}

static int has_bytes(tm_log_t *log, uint32_t round)
{
    tm_round_t *r = tm_log_round(log, round, 0);
    return r && r->prop_value != NULL;
}

static void test_u_reserve_unit(void)
{
    tm_log_t log;

    /* tm_log_reserve on its own, so the ORDER is measured rather than inferred
     * from a scenario that could reach the same end state another way. */
    TEST("U tm_log_reserve: future-highest first, then past-oldest, never self");

    /* (a) a FUTURE writer reclaims nothing at all */
    tm_log_init(&log, 1, 4, 2u * VAL_LEN);
    if (plant_value(&log, 0, 0, 0x11u, 0) != TM_PUT_LOGGED ||
        plant_value(&log, 1, 1, 0x12u, 1) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup a"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 3u, 1u) == 0) {
        tm_log_clear(&log); FAIL("a future writer was allowed to reclaim"); return;
    }
    if (!has_bytes(&log, 0) || !has_bytes(&log, 1)) {
        tm_log_clear(&log); FAIL("a refused reserve still dropped bytes"); return;
    }
    tm_log_clear(&log);

    /* (b) FUTURE rounds go first, HIGHEST downward. TWO future candidates (5
     *     and 7) and one value's worth requested, so the test says WHICH one
     *     was taken and not merely "a future round was" (Codex mutation). */
    tm_log_init(&log, 1, 4, 4u * VAL_LEN);
    if (plant_value(&log, 0, 0, 0x21u, 0) != TM_PUT_LOGGED ||
        plant_value(&log, 1, 1, 0x22u, 1) != TM_PUT_LOGGED ||
        plant_value(&log, 5, 2, 0x23u, 5) != TM_PUT_LOGGED ||
        plant_value(&log, 7, 3, 0x24u, 7) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup b"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 1u, 1u) != 0) {
        tm_log_clear(&log); FAIL("reserve b failed"); return;
    }
    if (has_bytes(&log, 7)) { tm_log_clear(&log); FAIL("the HIGHEST future round survived"); return; }
    if (!has_bytes(&log, 5)) { tm_log_clear(&log); FAIL("a lower future round was taken first"); return; }
    if (!has_bytes(&log, 0) || !has_bytes(&log, 1)) {
        tm_log_clear(&log); FAIL("a past round was reclaimed before the future ones"); return;
    }
    tm_log_clear(&log);

    /* (b2) the NEXT round (writer == current + 1) reclaims PAST rounds only */
    tm_log_init(&log, 1, 4, VAL_LEN);
    if (plant_value(&log, 0, 0, 0x41u, 0) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup b2"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 2u, 1u) != 0) {
        tm_log_clear(&log); FAIL("the next round could not reclaim a past round"); return;
    }
    if (has_bytes(&log, 0)) { tm_log_clear(&log); FAIL("the past round survived"); return; }
    tm_log_clear(&log);

    /* (b3) the next round may NOT touch the CURRENT round */
    tm_log_init(&log, 1, 4, VAL_LEN);
    if (plant_value(&log, 1, 0, 0x42u, 1) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup b3"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 2u, 1u) == 0) {
        tm_log_clear(&log); FAIL("the next round evicted the CURRENT round"); return;
    }
    if (!has_bytes(&log, 1)) { tm_log_clear(&log); FAIL("the current round lost its bytes"); return; }
    tm_log_clear(&log);

    /* (b4) two or more ahead still reclaims nothing */
    tm_log_init(&log, 1, 4, VAL_LEN);
    if (plant_value(&log, 0, 0, 0x43u, 0) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup b4"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 3u, 1u) == 0) {
        tm_log_clear(&log); FAIL("a writer two rounds ahead reclaimed"); return;
    }
    if (!has_bytes(&log, 0)) { tm_log_clear(&log); FAIL("it dropped bytes anyway"); return; }
    tm_log_clear(&log);

    /* (c) with no future rounds left, PAST rounds go OLDEST upward and the
     *     writing round is never touched. TWO past candidates (0 and 1) so the
     *     test says WHICH one was taken. */
    tm_log_init(&log, 1, 4, 3u * VAL_LEN);
    if (plant_value(&log, 0, 0, 0x31u, 0) != TM_PUT_LOGGED ||
        plant_value(&log, 1, 1, 0x32u, 1) != TM_PUT_LOGGED ||
        plant_value(&log, 2, 2, 0x33u, 2) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup c"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 2u, 2u) != 0) {
        tm_log_clear(&log); FAIL("reserve c failed"); return;
    }
    if (has_bytes(&log, 0)) { tm_log_clear(&log); FAIL("the OLDEST past round survived"); return; }
    if (!has_bytes(&log, 1)) { tm_log_clear(&log); FAIL("a newer past round was taken first"); return; }
    if (!has_bytes(&log, 2)) { tm_log_clear(&log); FAIL("the WRITING round was reclaimed"); return; }
    tm_log_clear(&log);

    /* (d) a request larger than the whole budget is refused outright */
    tm_log_init(&log, 1, 4, 2u * VAL_LEN);
    if (tm_log_reserve(&log, 3u * VAL_LEN, 0u, 0u) == 0) {
        tm_log_clear(&log); FAIL("a request above the budget was granted"); return;
    }
    tm_log_clear(&log);

    /* (e) REHYDRATION: the same id on a dropped slot puts the bytes back and
     *     reports LOGGED so the caller re-evaluates the rules; a different id
     *     on the same slot is still evidence. */
    tm_log_init(&log, 1, 4, VAL_LEN);
    if (plant_value(&log, 0, 0, 0x51u, 0) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("setup e"); return;
    }
    if (tm_log_reserve(&log, VAL_LEN, 1u, 1u) != 0) {
        tm_log_clear(&log); FAIL("could not drop round 0"); return;
    }
    if (has_bytes(&log, 0)) { tm_log_clear(&log); FAIL("round 0 was not dropped"); return; }
    if (plant_value(&log, 0, 0, 0x51u, 0) != TM_PUT_LOGGED) {
        tm_log_clear(&log); FAIL("the same id did not rehydrate the slot"); return;
    }
    if (!has_bytes(&log, 0)) { tm_log_clear(&log); FAIL("the bytes did not come back"); return; }
    if (plant_value(&log, 0, 0, 0x52u, 0) != TM_PUT_EQUIV) {
        tm_log_clear(&log); FAIL("a different id on the slot was not evidence"); return;
    }
    tm_log_clear(&log);
    PASS();
}

/* ── §O-g  adopt_own_slots moves last_* FORWARD only ─────────────────── */

static void test_o_g_adopt_forward_only(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    /* The WAL can hold own votes for several rounds. Entering round 1 must set
     * the STEP from round 1's own slot but must not drag last_prevote_round
     * BACKWARDS from the round-5 record — last_* is the double-sign cross-check
     * the T2 signer reads, and walking it back would understate what this node
     * has already signed. */
    TEST("O-g entering a round never walks last_* backwards");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture"); return; }

    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 5, idA) != 0) {
        fx_free(&f); FAIL("wal own prevote at round 5"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.last_prevote_round != 5 || s.round != 0) {
        fx_free(&f); FAIL("the round-5 record did not land"); return;
    }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 1, idA) != 0) {
        fx_free(&f); FAIL("wal own prevote at round 1"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.last_prevote_round != 5) {
        fx_free(&f); FAIL("ingest walked last_* backwards"); return;
    }

    /* open round 1 — the step must come from round 1, last_* must not move */
    if (tm_core_replay_timeout(f.core, 1, 0, TM_STEP_PRECOMMIT) != 0) {
        fx_free(&f); FAIL("wal timeout"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("round 1 was not opened"); return; }
    if (s.step < TM_STEP_PREVOTE) { fx_free(&f); FAIL("the own round-1 slot did not set the step"); return; }
    if (s.last_prevote_round != 5) {
        fx_free(&f); FAIL("entering round 1 walked last_* back from 5"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §O-h  in replay the own votes come ONLY from the WAL ────────────── */

static void test_o_h_own_votes_only_from_wal(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    const uint64_t RE = 50000ull;

    /* THE DEFECT THIS PINS. A timeout record that was a NO-OP when it ran live
     * is still in the WAL. Replayed, it used to make the core SYNTHESISE a nil
     * PRECOMMIT into its own slot — and then the WAL's real own PRECOMMIT(A)
     * for the same round arrived and was counted as an EQUIVOCATION against a
     * vote this node never sent, leaving the lock unrestored (G3) and the
     * evidence counter lying (G4).
     *
     * "Persist then send" means every vote actually sent is in the WAL, so a
     * synthesised one is at best a duplicate; in replay the rules move `step`
     * and nothing else.
     *
     * VACUITY GUARD: equivocations == 0 is the assertion that would fail on
     * the old behaviour, and locked_round == 0 is the consequence that makes
     * it matter. */
    TEST("O-h replay: a no-op timeout record does not forge an own vote");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init_ex(&f, 4, 1, 1) != 0) { FAIL("fixture"); return; }   /* self = 1 */

    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 0, idA) != 0) { fx_free(&f); FAIL("own PV"); return; }
    if (tm_core_replay_timeout(f.core, 1, 0, TM_STEP_PREVOTE) != 0) {
        fx_free(&f); FAIL("no-op timeout record"); return;
    }
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 1, 0, idA) != 0) { fx_free(&f); FAIL("own PC"); return; }
    if (replay_proposal(&f, 0, 0, (uint8_t)TAG_A, -1) != 0) { fx_free(&f); FAIL("proposal"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 0, 0, idA) < 0) { fx_free(&f); FAIL("PV0"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 2, 0, idA) < 0) { fx_free(&f); FAIL("PV2"); return; }

    tm_core_snapshot(f.core, &s);
    if (s.equivocations != 0) {
        fx_free(&f); FAIL("the node accused itself of equivocating"); return;
    }
    if (s.locked_round != 0 || memcmp(s.locked_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("the lock was lost"); return;
    }
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("step"); return; }
    if (memcmp(s.last_precommit_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("last_precommit is not the WAL's record"); return;
    }

    tm_core_replay_end(f.core, RE);
    if (tm_core_on_tick(f.core, RE + 1000000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("something was emitted after the restart"); return; }
    fx_free(&f);
    PASS();
}

/* ── §M-c  a sender the NEW set does not contain ─────────────────────── */

static void test_m_c_foreign_sender_on_drain(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t new_ids[4][DNA_CONSENSUS_ID_LEN];
    dna_vset_t new_set;
    tm_proposer_t *new_prop = NULL;
    tm_snapshot_t s;
    uint32_t i;

    /* An h+1 record was admitted against set_h. If the h+1 set drops that
     * member (an epoch boundary does exactly this), the drain must ignore the
     * record and carry on: it is not this core's fault and it is not a reason
     * to refuse the height. */
    TEST("M-c a buffered vote from a member the NEW set drops is ignored");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 2) != 0) { FAIL("fixture"); return; }   /* self = index 2 */

    /* v3 votes for h+1, then v3 leaves the set */
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 3, 2, 0, idA, T0 + 10) != 0) {
        fx_free(&f); FAIL("h+1 buffering"); return;
    }

    /* finish height 1 */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 20) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 0, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("c0"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 1, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("c1"); return; }
    if (send_vote(&f, DNA_CMSG_PRECOMMIT, 3, 0, idA, T0 + 50) != 0) { fx_free(&f); FAIL("c3"); return; }
    if (f.hc.n_decide != 1) { fx_free(&f); FAIL("height 1 did not decide"); return; }

    /* the h+1 set replaces v3 (0x24) with a new member that sorts after it */
    for (i = 0; i < 3u; i++) memcpy(new_ids[i], f.ids[i], DNA_CONSENSUS_ID_LEN);
    memset(new_ids[3], 0x30u, DNA_CONSENSUS_ID_LEN);
    new_set.n = 4;
    new_set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])new_ids;
    new_set.weights = NULL;
    if (tm_proposer_create(&new_prop, &new_set) != 0) { fx_free(&f); FAIL("new proposer"); return; }

    if (tm_core_start_height(f.core, 2, &new_set, new_prop, T0 + 60) != 0) {
        tm_proposer_destroy(new_prop); fx_free(&f);
        FAIL("start_height refused because of a foreign buffered sender"); return;
    }
    f.height = 2;
    tm_core_snapshot(f.core, &s);
    if (s.fault != 0) {
        tm_proposer_destroy(new_prop); fx_free(&f);
        FAIL("a foreign sender was treated as a core fault"); return;
    }
    if (s.height != 2) {
        tm_proposer_destroy(new_prop); fx_free(&f); FAIL("height"); return;
    }
    /* the dropped vote must NOT count: with only two more prevotes, quorum(4)
     * = 3 must not be reached and no lock may form */
    {
        uint8_t got[DNA_CONSENSUS_ID_LEN];
        uint32_t pidx = 4;
        dna_cmsg_t m;
        uint8_t value[VAL_LEN];
        if (tm_proposer_at(new_prop, 0, got) != 0) {
            tm_proposer_destroy(new_prop); fx_free(&f); FAIL("proposer_at"); return;
        }
        for (i = 0; i < 4u; i++) {
            if (memcmp(new_ids[i], got, DNA_CONSENSUS_ID_LEN) == 0) { pidx = i; break; }
        }
        if (pidx > 3u || pidx == 2u) {
            tm_proposer_destroy(new_prop); fx_free(&f);
            FAIL("fixture: self is the height-2 proposer"); return;
        }
        memset(&m, 0, sizeof(m));
        memset(value, (uint8_t)TAG_A, VAL_LEN);
        m.type = DNA_CMSG_PROPOSAL; m.height = 2; m.round = 0; m.valid_round = -1;
        memcpy(m.sender, new_ids[pidx], DNA_CONSENSUS_ID_LEN);
        mkvalue_id((uint8_t)TAG_A, m.value_id);
        m.value = value; m.value_len = VAL_LEN;
        if (tm_core_on_message(f.core, &m, T0 + 70) != 0) {
            tm_proposer_destroy(new_prop); fx_free(&f); FAIL("height-2 proposal"); return;
        }
    }
    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) {
        tm_proposer_destroy(new_prop); fx_free(&f);
        FAIL("the foreign vote was counted"); return;
    }
    tm_proposer_destroy(new_prop);
    fx_free(&f);
    PASS();
}

/* ── §M-d  h+1 PROPOSAL round limit ──────────────────────────────────── */

static int send_proposal_h(fx_t *f, uint32_t sender, uint64_t height, uint32_t round,
                           uint8_t tag, uint64_t now)
{
    dna_cmsg_t m;
    uint8_t value[VAL_LEN];
    memset(&m, 0, sizeof(m));
    memset(value, tag, VAL_LEN);
    m.type = DNA_CMSG_PROPOSAL;
    m.height = height;
    m.round = round;
    m.valid_round = -1;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    mkvalue_id(tag, m.value_id);
    m.value = value;
    m.value_len = VAL_LEN;
    return tm_core_on_message(f->core, &m, now);
}

static void test_m_d_h1_proposal_round_limit(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];

    /* The h+1 proposer cannot be checked — that set has not arrived — so
     * without a round limit one member could offer a cap-sized value for every
     * round in the lookahead window and fill the buffer budget alone. VOTES
     * keep the full window; only PROPOSALs are capped. */
    TEST("M-d h+1 PROPOSAL is capped at TM_H1_PROPOSAL_ROUNDS; votes are not");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_proposal_h(&f, 0, 2, TM_H1_PROPOSAL_ROUNDS, (uint8_t)TAG_A, T0 + 10) != 0) {
        fx_free(&f); FAIL("a proposal at the limit was refused"); return;
    }
    if (send_proposal_h(&f, 0, 2, TM_H1_PROPOSAL_ROUNDS + 1u, (uint8_t)TAG_B, T0 + 20) != 1) {
        fx_free(&f); FAIL("a proposal past the limit was buffered"); return;
    }
    /* a VOTE at the same round is still fine */
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 0, 2, TM_H1_PROPOSAL_ROUNDS + 1u, idA, T0 + 30) != 0) {
        fx_free(&f); FAIL("a vote was caught by the PROPOSAL limit"); return;
    }
    /* and out at the far end of the lookahead too */
    if (send_vote_h(&f, DNA_CMSG_PREVOTE, 2, 2, TM_ROUND_LOOKAHEAD, idA, T0 + 40) != 0) {
        fx_free(&f); FAIL("a vote at the lookahead edge was refused"); return;
    }

    /* SHAPE CHECKS run before the bytes are copied (design §5.6): a malformed
     * proposal must not buy buffer space only to be thrown away on the drain. */
    {
        dna_cmsg_t m;
        uint8_t value[VAL_LEN];
        tm_snapshot_t s0, s1;
        tm_core_snapshot(f.core, &s0);

        memset(&m, 0, sizeof(m));
        memset(value, (uint8_t)TAG_B, VAL_LEN);
        m.type = DNA_CMSG_PROPOSAL; m.height = 2; m.round = 1; m.valid_round = -1;
        memcpy(m.sender, f.ids[3], DNA_CONSENSUS_ID_LEN);
        m.value = value; m.value_len = VAL_LEN;
        /* nil id */
        memcpy(m.value_id, NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN);
        if (tm_core_on_message(f.core, &m, T0 + 50) != 1) {
            fx_free(&f); FAIL("a nil-id h+1 PROPOSAL was buffered"); return;
        }
        /* valid_round == round */
        mkvalue_id((uint8_t)TAG_B, m.value_id);
        m.valid_round = 1;
        if (tm_core_on_message(f.core, &m, T0 + 60) != 1) {
            fx_free(&f); FAIL("valid_round == round was buffered"); return;
        }
        /* valid_round < -1 */
        m.valid_round = -2;
        if (tm_core_on_message(f.core, &m, T0 + 70) != 1) {
            fx_free(&f); FAIL("valid_round < -1 was buffered"); return;
        }
        /* zero length */
        m.valid_round = -1;
        m.value_len = 0;
        if (tm_core_on_message(f.core, &m, T0 + 80) != 1) {
            fx_free(&f); FAIL("a zero-length h+1 PROPOSAL was buffered"); return;
        }
        tm_core_snapshot(f.core, &s1);
        if (s1.h1_entries != s0.h1_entries || s1.h1_bytes != s0.h1_bytes) {
            fx_free(&f); FAIL("a malformed proposal grew the buffer"); return;
        }
        /* the WELL-FORMED one from the same member still gets in, so the
         * refusals above were about shape and not about the sender */
        m.valid_round = -1;
        m.value_len = VAL_LEN;
        if (tm_core_on_message(f.core, &m, T0 + 90) != 0) {
            fx_free(&f); FAIL("a well-formed h+1 PROPOSAL was refused"); return;
        }
    }
    fx_free(&f);
    PASS();
}

/* ── §V  the FAULT latch ─────────────────────────────────────────────── */

static void test_v_fault_latch(void)
{
    fx_t f;
    tm_snapshot_t s;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];

    /* HONEST COVERAGE GAP, stated plainly: the POSITIVE half of the fault
     * latch — an internal failure after the commit point setting fault = 1 and
     * every entry point refusing afterwards — is NOT reachable from a test.
     * Every path that sets it needs either an allocation failure, a tripped
     * fixpoint guard, or 2^31 rounds, and reaching any of them from the public
     * API would require a build flag or an allocator hook that this module
     * deliberately does not have. Adding an injection seam would put a
     * production-visible branch in the core to make a test easier, which is a
     * worse trade than an admitted gap.
     *
     * What IS asserted here is the negative half, which is the half a
     * mis-implementation is most likely to get wrong: a REFUSAL BEFORE the
     * commit point must not latch, and the core must still be fully usable
     * afterwards. */
    TEST("V a pre-commit refusal does not latch the fault and leaves the core usable");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    tm_core_snapshot(f.core, &s);
    if (s.fault != 0) { fx_free(&f); FAIL("a fresh core reports a fault"); return; }

    /* four different pre-commit refusals */
    if (tm_core_start_height(f.core, 0, &f.set, f.prop, T0 + 10) == 0) {
        fx_free(&f); FAIL("start_height(0) accepted"); return;
    }
    if (tm_core_start_height(f.core, 1, &f.set, f.prop, T0 + 10) == 0) {
        fx_free(&f); FAIL("the same height was re-opened"); return;
    }
    {
        dna_vset_t bad = f.set;
        bad.n = 0;
        if (tm_core_start_height(f.core, 2, &bad, f.prop, T0 + 10) == 0) {
            fx_free(&f); FAIL("an empty set was accepted"); return;
        }
    }
    {
        /* a proposer object built for a DIFFERENT set */
        uint8_t other[3][DNA_CONSENSUS_ID_LEN];
        dna_vset_t oset;
        tm_proposer_t *op = NULL;
        uint32_t i;
        for (i = 0; i < 3u; i++) memset(other[i], (uint8_t)(0x71u + i), DNA_CONSENSUS_ID_LEN);
        oset.n = 3;
        oset.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])other;
        oset.weights = NULL;
        if (tm_proposer_create(&op, &oset) != 0) { fx_free(&f); FAIL("other proposer"); return; }
        if (tm_core_start_height(f.core, 2, &f.set, op, T0 + 10) == 0) {
            tm_proposer_destroy(op); fx_free(&f);
            FAIL("a mismatched proposer object was accepted"); return;
        }
        tm_proposer_destroy(op);
    }

    tm_core_snapshot(f.core, &s);
    if (s.fault != 0) { fx_free(&f); FAIL("a pre-commit refusal latched the fault"); return; }
    if (s.height != 1 || s.round != 0) { fx_free(&f); FAIL("a refusal moved the state"); return; }

    /* and the core still works */
    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 20) != 0) {
        fx_free(&f); FAIL("the core stopped working after a refusal"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 1) {
        fx_free(&f); FAIL("no PREVOTE — the core is not usable"); return;
    }
    tm_core_snapshot(f.core, &s);
    if (s.fault != 0) { fx_free(&f); FAIL("fault appeared during normal work"); return; }
    fx_free(&f);
    PASS();
}

/* ── §W  live-FAULT, replay-healthy: rules never write the lock ──────── */

static void test_w_replay_rules_never_lock(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;
    const uint64_t RE = 50000ull;
    uint32_t i;

    /* THE DEFECT THIS PINS (design §5.9, Codex C-1 generalised). Live, this
     * node's valid() FAULTed, so rule_l36 never fired and it voted NIL — that
     * is what its WAL records. On replay valid() is healthy, so rule_l36 CAN
     * fire, and if the rules were allowed to write state it would manufacture
     * a lock the node never took. Replay must reconstruct state from RECORDED
     * ACTIONS only.
     *
     * VACUITY GUARD: the last leg is the one that can tell the difference. A
     * node holding an invented lock on A prevotes NIL for B in round 1; a node
     * that correctly has no lock prevotes B. Asserting locked_round == -1
     * alone would pass on a build where rule_l36 simply never fired, so the
     * step assertion (PRECOMMIT — l36 DID fire and did advance the machine) is
     * carried alongside it. */
    TEST("W replay: rules advance step but never write lock/validValue");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);
    /* self = 2: not proposer(0) = 0 and not proposer(1) = 1 */
    if (fx_init_ex(&f, 4, 2, 1) != 0) { FAIL("fixture"); return; }
    f.hc.valid_result = 1;                       /* healthy DURING replay */

    if (replay_proposal(&f, 0, 0, (uint8_t)TAG_A, -1) != 0) { fx_free(&f); FAIL("wal proposal"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 0, 0, idA) < 0) { fx_free(&f); FAIL("PV0"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 1, 0, idA) < 0) { fx_free(&f); FAIL("PV1"); return; }
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 3, 0, idA) < 0) { fx_free(&f); FAIL("PV3"); return; }
    /* what the FAULTed live node actually persisted: nil, nil */
    if (replay_msg(&f, DNA_CMSG_PREVOTE, 2, 0, NIL_ID) != 0) { fx_free(&f); FAIL("own PV"); return; }
    if (replay_msg(&f, DNA_CMSG_PRECOMMIT, 2, 0, NIL_ID) != 0) { fx_free(&f); FAIL("own PC"); return; }

    tm_core_snapshot(f.core, &s);
    if (s.locked_round != -1) { fx_free(&f); FAIL("replay invented a lock"); return; }
    if (s.valid_round != -1) { fx_free(&f); FAIL("replay invented a validValue"); return; }
    if (s.step != TM_STEP_PRECOMMIT) { fx_free(&f); FAIL("the rules did not advance the step"); return; }
    if (memcmp(s.last_precommit_id, NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("last_precommit is not the WAL's nil"); return;
    }
    if (f.hc.n_emit != 0) { fx_free(&f); FAIL("replay emitted"); return; }

    /* live again: reach round 1, then a fresh proposal for B */
    tm_core_replay_end(f.core, RE);
    for (i = 0; i < 4u; i++) {
        if (i == 2u) continue;
        if (send_vote(&f, DNA_CMSG_PRECOMMIT, i, 0, NIL_ID, RE + 10 + i) < 0) {
            fx_free(&f); FAIL("precommit"); return;
        }
    }
    if (tm_core_on_tick(f.core, RE + 100000ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.round != 1) { fx_free(&f); FAIL("did not reach round 1"); return; }

    if (send_proposal(&f, proposer_index(&f, 1), 1, (uint8_t)TAG_B, -1, RE + 200000ull) != 0) {
        fx_free(&f); FAIL("round-1 proposal"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 1) != 1) {
        fx_free(&f); FAIL("expected exactly one round-1 PREVOTE"); return;
    }
    for (i = 0; i < f.hc.n_emit; i++) {
        if (f.hc.emits[i].type == DNA_CMSG_PREVOTE && f.hc.emits[i].round == 1 &&
            memcmp(f.hc.emits[i].value_id, idB, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
            fx_free(&f); FAIL("prevoted nil — an invented lock survived replay"); return;
        }
    }
    fx_free(&f);
    PASS();
}

/* ── §X  G7: the value/id binding is the HOST's ──────────────────────── */

static int send_proposal_id(fx_t *f, uint32_t sender, uint32_t round,
                            uint8_t value_tag, uint8_t id_tag, int32_t vr, uint64_t now)
{
    dna_cmsg_t m;
    uint8_t value[VAL_LEN];
    memset(&m, 0, sizeof(m));
    memset(value, value_tag, VAL_LEN);
    m.type = DNA_CMSG_PROPOSAL;
    m.height = f->height;
    m.round = round;
    m.valid_round = vr;
    memcpy(m.sender, f->ids[sender], DNA_CONSENSUS_ID_LEN);
    mkvalue_id(id_tag, m.value_id);
    m.value = value;
    m.value_len = VAL_LEN;
    return tm_core_on_message(f->core, &m, now);
}

static void test_x_g7_binding_seam(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t idB[DNA_CONSENSUS_VALUE_ID_LEN];

    /* G7 (dna_consensus.h): the core computes NO hash, so it cannot tell that
     * a proposal's bytes are not the value its id names. The HOST must, and
     * the contract says valid() returns 0 in that case. What this section
     * proves is the CORE half of the seam — that a 0 verdict is honoured and
     * turns into a nil PREVOTE. The binding ITSELF is not tested here and
     * cannot be: it does not live in this module. */
    TEST("X G7 seam: a host that rejects a mismatched id yields a nil PREVOTE");
    mkvalue_id((uint8_t)TAG_A, idA);
    mkvalue_id((uint8_t)TAG_B, idB);

    /* positive control first: a MATCHED binding must still prevote the id, or
     * the negative below would pass on a core that prevotes nil for everything */
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }
    f.hc.enforce_binding = 1;
    if (send_proposal_id(&f, 0, 0, (uint8_t)TAG_A, (uint8_t)TAG_A, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("matched proposal rejected"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 1 ||
        !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, idA)) {
        fx_free(&f); FAIL("a correctly bound value did not draw its id"); return;
    }
    fx_free(&f);

    /* the seam: bytes of A carried under the id of B */
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture 2"); return; }
    f.hc.enforce_binding = 1;
    if (send_proposal_id(&f, 0, 0, (uint8_t)TAG_A, (uint8_t)TAG_B, -1, T0 + 10) != 0) {
        fx_free(&f); FAIL("proposal rejected at the door"); return;
    }
    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 1 ||
        !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, NIL_ID)) {
        fx_free(&f); FAIL("the core ignored the host's 0 verdict"); return;
    }
    if (f.hc.valid_calls == 0) { fx_free(&f); FAIL("valid() was never asked"); return; }
    fx_free(&f);
    PASS();
}

/* ── §S2  the deadline saturates ─────────────────────────────────────── */

static void test_s2_saturating_deadline(void)
{
    fx_t f;

    /* `now` is whatever the host's clock says. now + timeout can wrap in u64,
     * and a wrapped deadline compares as ALREADY EXPIRED — the timer it
     * belongs to would fire the instant it was armed, collapsing the round.
     * Saturating at UINT64_MAX turns that into "never fires", which is the
     * safe direction. */
    TEST("S2 a deadline that would wrap saturates instead of firing at once");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }   /* self = 1, non-proposer */

    if (fx_start_height(&f, 2, UINT64_MAX - 100ull) != 0) {
        fx_free(&f); FAIL("start_height at a near-max clock"); return;
    }
    /* the arming instant itself: a wrapped deadline would already be due */
    if (tm_core_on_tick(f.core, UINT64_MAX - 100ull) != 0) { fx_free(&f); FAIL("tick"); return; }
    if (f.hc.n_emit != 0) {
        fx_free(&f); FAIL("the timer fired at the instant it was armed"); return;
    }
    /* and at the ceiling it does fire, so the timer is real and not just absent */
    if (tm_core_on_tick(f.core, UINT64_MAX) != 0) { fx_free(&f); FAIL("tick 2"); return; }
    if (f.hc.n_emit != 1 || !emit_is(&f, 0, DNA_CMSG_PREVOTE, 0, NIL_ID)) {
        fx_free(&f); FAIL("the saturated timer never fired at all"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §S  tm_core_create parameter validation (design §6.1) ───────────── */

static void test_s_params_validation(void)
{
    fx_t f;
    tm_params_t bad;
    tm_core_t *core = NULL;

    TEST("S a zero initial timeout is refused by tm_core_create");
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    bad = f.params;
    bad.propose_init_ms = 0;
    if (tm_core_create(&core, &f.host, &bad) == 0) {
        tm_core_destroy(core); fx_free(&f); FAIL("propose_init_ms = 0 accepted"); return;
    }
    bad = f.params;
    bad.prevote_init_ms = 0;
    if (tm_core_create(&core, &f.host, &bad) == 0) {
        tm_core_destroy(core); fx_free(&f); FAIL("prevote_init_ms = 0 accepted"); return;
    }
    bad = f.params;
    bad.precommit_init_ms = 0;
    if (tm_core_create(&core, &f.host, &bad) == 0) {
        tm_core_destroy(core); fx_free(&f); FAIL("precommit_init_ms = 0 accepted"); return;
    }
    bad = f.params;
    bad.max_value_bytes = 0;
    if (tm_core_create(&core, &f.host, &bad) == 0) {
        tm_core_destroy(core); fx_free(&f); FAIL("max_value_bytes = 0 accepted"); return;
    }
    /* a per-proposal cap above the height budget is unsatisfiable: reserve
     * would refuse every proposal and the node would never log a value */
    bad = f.params;
    bad.max_value_bytes = bad.max_height_log_bytes + 1u;
    if (tm_core_create(&core, &f.host, &bad) == 0) {
        tm_core_destroy(core); fx_free(&f);
        FAIL("max_value_bytes > max_height_log_bytes accepted"); return;
    }
    /* lookahead + 1 sizes the h+1 seen-map; an absurd value would overflow the
     * multiplication and silently close the buffer */
    bad = f.params;
    bad.round_lookahead = TM_ROUND_LOOKAHEAD_MAX + 1u;
    if (tm_core_create(&core, &f.host, &bad) == 0) {
        tm_core_destroy(core); fx_free(&f);
        FAIL("round_lookahead above the ceiling accepted"); return;
    }
    bad = f.params;
    bad.round_lookahead = TM_ROUND_LOOKAHEAD_MAX;
    if (tm_core_create(&core, &f.host, &bad) != 0) {
        fx_free(&f); FAIL("round_lookahead AT the ceiling was refused"); return;
    }
    tm_core_destroy(core);

    /* the DELTAS may legitimately be zero — a flat schedule is slower to
     * converge, not degenerate, so refusing it would be wrong. */
    bad = f.params;
    bad.propose_delta_ms = 0;
    bad.prevote_delta_ms = 0;
    bad.precommit_delta_ms = 0;
    if (tm_core_create(&core, &f.host, &bad) != 0) {
        fx_free(&f); FAIL("zero deltas were refused"); return;
    }
    tm_core_destroy(core);
    fx_free(&f);
    PASS();
}

/* ── §P  get_value() = 1 ─────────────────────────────────────────────── */

static void test_p_get_value_declines(void)
{
    host_ctx_t *hc;
    tm_proposer_t *prop = NULL;
    tm_core_t *core = NULL;
    uint32_t i;
    static uint8_t ids[4][DNA_CONSENSUS_ID_LEN];
    static host_ctx_t ctx;
    dna_consensus_host_t host;
    dna_vset_t set;
    tm_params_t params;

    TEST("P get_value() = 1: the proposer behaves as a non-proposer");

    memset(&ctx, 0, sizeof(ctx));
    ctx.valid_result = 1;
    ctx.gv_tag = (uint8_t)TAG_A;
    ctx.get_value_mode = 1;
    hc = &ctx;

    for (i = 0; i < 4; i++) mkid(ids[i], (uint8_t)(0x21u + i));
    set.n = 4;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = NULL;

    memset(&host, 0, sizeof(host));
    host.ctx = hc;
    memcpy(host.self, ids[0], DNA_CONSENSUS_ID_LEN);       /* index 0 = proposer(0) */
    host.get_value = hv_get_value;
    host.valid = hv_valid;
    host.emit = hv_emit;
    host.decide = hv_decide;
    host.on_round_start = hv_round_start;
    host.on_equivocation = hv_equivocation;
    tm_params_default(&params);

    if (tm_proposer_create(&prop, &set) != 0) { FAIL("proposer"); return; }
    if (tm_core_create(&core, &host, &params) != 0) { tm_proposer_destroy(prop); FAIL("core"); return; }
    if (tm_core_start_height(core, 1, &set, prop, T0) != 0) {
        tm_core_destroy(core); tm_proposer_destroy(prop); FAIL("start"); return;
    }
    if (hc->gv_calls != 1) {
        tm_core_destroy(core); tm_proposer_destroy(prop); FAIL("get_value not called"); return;
    }
    if (hc->n_emit != 0) {
        tm_core_destroy(core); tm_proposer_destroy(prop); FAIL("proposed without a value"); return;
    }
    if (tm_core_on_tick(core, T0 + TM_TIMEOUT_PROPOSE_INIT_MS) != 0) {
        tm_core_destroy(core); tm_proposer_destroy(prop); FAIL("tick"); return;
    }
    if (hc->n_emit != 1 || hc->emits[0].type != DNA_CMSG_PREVOTE ||
        memcmp(hc->emits[0].value_id, NIL_ID, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        tm_core_destroy(core); tm_proposer_destroy(prop);
        FAIL("no nil PREVOTE at timeoutPropose"); return;
    }
    tm_core_destroy(core);
    tm_proposer_destroy(prop);
    PASS();
}

/* ── §Q  G4 one vote per (h, r, type) ────────────────────────────────── */

static void test_q_single_vote(void)
{
    fx_t f;
    uint8_t idA[DNA_CONSENSUS_VALUE_ID_LEN];
    tm_snapshot_t s;

    TEST("Q G4: exactly one PREVOTE and one PRECOMMIT leave per round");
    mkvalue_id((uint8_t)TAG_A, idA);
    if (fx_init(&f, 4, 1) != 0) { FAIL("fixture"); return; }

    if (send_proposal(&f, 0, 0, (uint8_t)TAG_A, -1, T0 + 10) != 0) { fx_free(&f); FAIL("p"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 0, 0, idA, T0 + 20) != 0) { fx_free(&f); FAIL("v0"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 2, 0, idA, T0 + 30) != 0) { fx_free(&f); FAIL("v2"); return; }
    if (send_vote(&f, DNA_CMSG_PREVOTE, 3, 0, idA, T0 + 40) != 0) { fx_free(&f); FAIL("v3"); return; }
    /* every timer of round 0 expires; none of them may add a second vote */
    if (tm_core_on_tick(f.core, T0 + 100000ull) != 0) { fx_free(&f); FAIL("tick"); return; }

    if (count_emits(&f, DNA_CMSG_PREVOTE, 0) != 1) { fx_free(&f); FAIL("two PREVOTEs"); return; }
    if (count_emits(&f, DNA_CMSG_PRECOMMIT, 0) != 1) { fx_free(&f); FAIL("two PRECOMMITs"); return; }
    tm_core_snapshot(f.core, &s);
    if (s.last_prevote_round != 0 || s.last_precommit_round != 0) {
        fx_free(&f); FAIL("last_* rounds"); return;
    }
    if (memcmp(s.last_prevote_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0 ||
        memcmp(s.last_precommit_id, idA, DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
        fx_free(&f); FAIL("last_* ids"); return;
    }
    fx_free(&f);
    PASS();
}

/* ── §R  the registry ────────────────────────────────────────────────── */

static void test_r_registry(void)
{
    const dna_consensus_ops_t *ops;

    TEST("R registry: 0 and unknown are NULL, 1 is Tendermint with a pin");
    if (dna_consensus_lookup(DNA_CONSENSUS_PROTOCOL_INVALID) != NULL) {
        FAIL("identity 0 resolved"); return;
    }
    if (dna_consensus_lookup(99u) != NULL) { FAIL("an unknown identity resolved"); return; }
    ops = dna_consensus_lookup(DNA_CONSENSUS_PROTOCOL_TENDERMINT);
    if (!ops) { FAIL("Tendermint did not resolve"); return; }
    if (ops != &tm_ops) { FAIL("wrong table entry"); return; }
    if (!ops->spec_ref || strstr(ops->spec_ref, "1807.04938v3") == NULL ||
        strstr(ops->spec_ref, "709fd12b") == NULL) {
        FAIL("spec_ref does not carry the pinned references"); return;
    }
    if (strstr(ops->spec_ref, "latest") != NULL) { FAIL("spec_ref says latest"); return; }
    if (!ops->create || !ops->destroy || !ops->start_height || !ops->on_message || !ops->on_tick) {
        FAIL("an ops entry is NULL"); return;
    }
    PASS();
}

int main(void)
{
    printf("\nNodus Tendermint T1 — Algorithm 1 line tests\n");
    printf("==========================================\n\n");

    test_0_thresholds();
    test_0_fixture_proposer();
    test_a_proposer_proposes_and_prevotes();
    test_a_non_proposer_timeout();
    test_b_l22_positive();
    test_b_l22_negatives();
    test_b_lock_blocks_prevote();
    test_c_l28_positive();
    test_c_l28_negatives();
    test_d_l34_first_time();
    test_e_l36_locks();
    test_e_l36_at_precommit_step();
    test_f_l44_nil_precommit();
    test_g_l47_and_next_round();
    test_h_decide_any_round();
    test_h_invalid_never_decides();
    test_i_l55_needs_f_plus_one();
    test_j_stale_timer_discarded();
    test_k_equivocation();
    test_k_second_value_counts();
    test_k_third_value_not_stored();
    test_k_b_two_quorums_impossible();
    test_l_lookahead();
    test_m_h1_buffer();
    test_n_valid_fault_and_memo();
    test_o_replay_silent_and_keeps_lock();
    test_o_replay_end_rearms();
    test_m_b_h1_dedup();
    test_m_c_foreign_sender_on_drain();
    test_m_d_h1_proposal_round_limit();
    test_t_height_monotonicity();
    test_o_d_own_vote_from_wal();
    test_o_d_duplicate_own_vote();
    test_o_d_backstop_writes_nothing();
    test_o_e_lock_from_wal();
    test_o_e_lock_without_bytes();
    test_o_f_own_slot_sets_step();
    test_o_g_adopt_forward_only();
    test_o_h_own_votes_only_from_wal();
    test_w_replay_rules_never_lock();
    test_x_g7_binding_seam();
    test_u_reclaim_priority();
    test_u_rehydrate();
    test_u_reserve_unit();
    test_v_fault_latch();
    test_s2_saturating_deadline();
    test_s_params_validation();
    test_p_get_value_declines();
    test_q_single_vote();
    test_r_registry();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
