/**
 * Nodus — Tendermint T1: seeded N-node simulation.
 *
 * Drives real tm_core instances (nodus/src/bft/tendermint/) through a virtual
 * network with delay, pre-GST disruption and five Byzantine models, and checks
 * the security goals of the T1 design document §9 plus the trace-equality
 * invariant of §8.
 *
 * ── WHAT WOULD BE FALSE IF THIS FILE FAILED ───────────────────────────
 *
 * G1 AGREEMENT — two honest nodes never decide different value_ids for the
 *    same height. This is the chain-split property; nothing else in the suite
 *    exercises it across nodes.
 * G2 VALIDITY — every decided value is BYTE FOR BYTE a value the proposer of
 *    the commit's round put on the wire. The simulator records every proposal
 *    it sends and compares against that record; the structural magic byte is
 *    kept as a second, weaker leg. Checking only the magic would accept any
 *    well-formed value, including one this round's proposer never sent.
 *    The record holds up to TWO distinct values per (h, r): an honest
 *    proposer sends one, the double proposer sends two, and the honest nodes
 *    may legitimately decide EITHER of the two (whichever half reached them
 *    first — direct or relayed — is the one they accepted). A record that
 *    kept only the first would call a correct decision on the second half a
 *    validity failure. A third distinct value for one (h, r) is a simulator
 *    defect and is reported as one, never silently dropped.
 * G6 LIVENESS — after GST, with at most f faulty members, every honest node
 *    decides all H heights. `decided_all == H` is asserted per node; a run
 *    that merely ran out of virtual time is a FAILURE, not a pass.
 * G5 MEMORY — a member spamming a far-future round cannot make a receiver
 *    allocate. This is now MEASURED, not inferred from a return code: a
 *    snapshot is taken either side of every spam delivery and rounds_open,
 *    log_value_bytes and h1_entries must all be unchanged. The h+1 buffer's
 *    entry count is also checked against its (lookahead+1)*n*3 bound on every
 *    delivery.
 * DG-1 TRACE EQUALITY — two SEPARATE simulator instances driven by the same
 *    seed produce the same FNV-1a-64 digest over the whole event trace. The
 *    digest covers each emission's type, height, round, valid_round, value_id
 *    AND VALUE BYTES, each round entry's proposer, and each decision's round
 *    and full voter list — so a build that emitted the right envelope with the
 *    wrong payload, or committed with a different voter set, hashes
 *    differently. If this went red, two nodes replaying the same inputs could
 *    diverge.
 *
 * ── THE NETWORK MODEL IS TWO STAND-INS, NOT THE CORE ──────────────────
 *
 * T1 has no gossip reactor and no sync path; both are T3. The simulator
 * supplies the minimum of each so that the ALGORITHM can be measured rather
 * than their absence (design §11.3):
 *
 *   RELAY — each honest node re-broadcasts once every message its core
 *   ACCEPTED (rc 0 or 2), to every peer but itself and the origin. One hop,
 *   bounded by an explicit counter. This is the paper's gossip property.
 *
 *   SYNC — a live node that has NOT decided its current height while a peer
 *   has GENUINELY decided it, and has made no progress for SIM_SYNC_LAG_MS,
 *   is handed that peer's value, marked as SYNCED, and moved on. Synced
 *   values are excluded from the G1 comparison; they count only towards
 *   progress. The trigger is "a peer holds a commit for my height", NOT
 *   "I am behind the highest height": at the matrix's LAST height nobody
 *   advances past it, so a node stranded there is never "behind" anyone,
 *   and the height-based trigger left it stranded for the whole budget
 *   (double proposer, n = 10, seed 3 — see sim_sync_stragglers).
 *
 * WITHOUT THESE THE MATRIX STRANDS NODES, AND THAT IS NOT A CORE DEFECT. A
 * message that reaches only part of the set on its direct path has no second
 * route in T1, and a node that falls more than one height behind has no way
 * back: both are the missing T3 layer, not the algorithm. §9's G6 is stated
 * with the host's sync path included for exactly this reason.
 *
 * ONE STRANDING CAUSE HAS BEEN REMOVED FROM THE CORE ITSELF, and the history
 * matters because this file measured it. Under the old first-arrival-wins rule
 * (design §5.4 before 2026-09-08) a node that counted an equivocator's FIRST
 * vote could never count its second, so if the other honest nodes reached a
 * commit using the second, this node could not reach it locally EVER — not a
 * delay, a permanent local stall, and the matrix went red at n = 4 with the
 * equivocating-voter model. The rule now keeps TWO SLOTS per sender and counts
 * both, so that node completes the same quorum the others did. CometBFT
 * reaches the same place by a different route (its VoteSet keeps a conflicting
 * vote once a peer claims "+2/3 exists" for that value — the peerMaj23 hint),
 * which T1 has no protocol for. The stand-ins remain load-bearing: they are
 * what delivers the second half in the first place.
 *
 * ── WHAT IT REQUIRES ──────────────────────────────────────────────────
 *
 * Nothing beyond a default build: no compile flags, no environment variables,
 * no files, no ports, no threads. The clock is virtual (every now_ms is
 * computed by the simulator) and the randomness is a seeded xorshift64, so
 * every run reproduces byte for byte on any machine and any failing
 * (model, n, seed) triple can be re-run alone.
 *
 * ── WHAT IT LEAVES BEHIND ─────────────────────────────────────────────
 *
 * Nothing. Every run frees its cores, its proposer objects and its message
 * queue on every exit path.
 *
 * ── HOW IT COULD LIE ──────────────────────────────────────────────────
 *
 *  1. AN IDEAL NETWORK. With zero delay and zero disruption no rule is ever
 *     stressed and round 0 always succeeds, so every round-change path would
 *     be untested while the suite stayed green. The matrix therefore runs
 *     with delay uniform on [0, D] where D >= timeoutPropose/2, with pre-GST
 *     disruption, AND asserts that a round > 0 was actually observed in at
 *     least one seed of every model. "A nil round never happened" is a
 *     FAILURE.
 *  2. A SHORT RUN COUNTED AS LIVENESS. Every honest node must reach H
 *     decisions; the virtual-time budget running out is reported as a
 *     failure of that run, never folded into a green count.
 *  3. A TWIN THAT COMPARES A RUN WITH ITSELF. The twin check builds TWO
 *     independent simulator instances from the same seed and compares their
 *     digests; nothing is read twice from one object.
 *  4. A BYZANTINE MODEL THAT IS NOT WIRED. A model whose actor never acts
 *     behaves honestly and passes everything. Each model therefore asserts
 *     its OWN SIGNATURE: crash — the crashed nodes decided nothing; equivocating
 *     voter — on_equivocation fired; double proposer — the conflict was
 *     detected once the relay carried each half across (per seed) AND, over
 *     the sweep, at least one seed had two distinct honest nodes accept
 *     different halves (a per-seed timing draw, checked cumulatively like the
 *     crash model); always-nil — the actor
 *     emitted only nil and at least one round timed out; far-round spam — every
 *     spam message was refused.
 *  5. REDUCED CONSTANTS READ AS PRODUCTION. The timeouts here are 100/20,
 *     40/10, 40/10 ms, NOT the shipped 3000/500, 1000/500, 1000/500, because
 *     the virtual timeline would otherwise be 30x longer for no additional
 *     coverage. This run proves the LOGIC at those constants. It proves
 *     nothing about behaviour that depends on their MAGNITUDE; the shipped
 *     values are pinned in test_tm_core, not here.
 *  6. A LOSSY NETWORK MISTAKEN FOR PARTIAL SYNCHRONY. A message that is
 *     "dropped" before GST is RE-SCHEDULED past GST rather than destroyed,
 *     which is the paper's model (arbitrary delay before GST, bounded after).
 *     T1 has no gossip and no retransmission, so true loss would measure the
 *     ABSENCE of the T3 gossip layer rather than the algorithm. For the same
 *     reason a message refused because the receiver is MORE THAN ONE height
 *     behind is re-queued a bounded number of times: that is the simulator
 *     standing in for the sync path. The bound is deliberate — re-queueing at
 *     exactly receiver + 1 would mask every rejection the core's own h+1
 *     buffer makes, including its dedup, and the suite would be measuring the
 *     simulator instead of the core.
 *  7. AN ERROR READ AS A REJECTION. tm_core returns -1 for a real fault and 1
 *     for a policy refusal; treating both as "not accepted" would let an
 *     allocation failure or a tripped fixpoint guard pass as a clean run. Any
 *     -1 from any entry fails the run.
 *  8. A CRASHED NODE'S DECISION EXCLUDED FROM G1. A node that decided and only
 *     then crashed decided honestly; dropping it from the agreement check
 *     would hide precisely the disagreement G1 exists to catch. The
 *     comparison spans every node that ever decided, live or not.
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

/* ── simulation constants ────────────────────────────────────────────── */

#define SIM_MAXN        10u
#define SIM_H           20u          /* heights every honest node must decide */
#define SIM_HMAX        (SIM_H + 4u)
/* The actor's bookkeeping is sized for the rounds a live run can reach; past
 * this the actor simply stops acting, which is safe because a run that needs
 * 32 rounds for one height has already failed its liveness assertion. */
#define SIM_ROUNDS_MAX  32u
#define SIM_VAL_LEN     16u
#define SIM_TICK_MS     5ull
#define SIM_DELAY_MAX   60ull        /* >= timeoutPropose/2 = 50 */
#define SIM_GST_MS      600ull
#define SIM_DROP_PCT    25u
#define SIM_BUDGET_MS   120000ull
#define SIM_SPAM_ROUND  10000u
#define SIM_MAX_RETRY   64u
/* How long a node may make no progress before the sync stand-in carries it. */
#define SIM_SYNC_LAG_MS (2ull * P_PROPOSE_INIT + 4ull * SIM_DELAY_MAX)

#define P_PROPOSE_INIT   100u
#define P_PROPOSE_DELTA   20u
#define P_PREVOTE_INIT    40u
#define P_PREVOTE_DELTA   10u
#define P_PRECOMMIT_INIT  40u
#define P_PRECOMMIT_DELTA 10u

#define VAL_MAGIC 0xD1u

enum {
    MODEL_CRASH = 0,
    MODEL_EQUIV_VOTER,
    MODEL_DOUBLE_PROPOSER,
    MODEL_ALWAYS_NIL,
    MODEL_FAR_ROUND_SPAM,
    MODEL_COUNT
};

static const char *model_name(int m)
{
    switch (m) {
        case MODEL_CRASH:            return "crash f nodes";
        case MODEL_EQUIV_VOTER:      return "equivocating voter";
        case MODEL_DOUBLE_PROPOSER:  return "double proposer";
        case MODEL_ALWAYS_NIL:       return "always nil";
        case MODEL_FAR_ROUND_SPAM:   return "far-round spam";
        default:                     return "?";
    }
}

/* ── values ──────────────────────────────────────────────────────────── */

static void sim_make_value(uint64_t height, uint32_t maker, uint8_t variant,
                           uint8_t out[SIM_VAL_LEN])
{
    memset(out, 0, SIM_VAL_LEN);
    out[0] = (uint8_t)VAL_MAGIC;
    out[1] = (uint8_t)(height & 0xFFu);
    out[2] = (uint8_t)((height >> 8) & 0xFFu);
    out[3] = (uint8_t)maker;
    out[4] = variant;
}

static void sim_value_id(const uint8_t value[SIM_VAL_LEN], uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    memset(id, 0, DNA_CONSENSUS_VALUE_ID_LEN);
    memcpy(id, value, SIM_VAL_LEN);
    id[SIM_VAL_LEN] = 0x99u;      /* keeps id(v) distinct from v and never nil */
}

/* ── event queue (a deterministic min-heap on (at, seq)) ─────────────── */

typedef struct {
    uint64_t at;
    uint64_t seq;
    uint32_t to;
    uint32_t origin;        /* the node that first put this message on the wire */
    uint32_t retries;
    dna_cmsg_t m;
    uint8_t value[SIM_VAL_LEN];
    uint8_t is_spam;
    uint8_t hops;           /* 0 = direct from the origin, 1 = relayed once */
} sim_ev_t;

/* Every PROPOSAL the simulator ever put on the wire, so G2 can be checked
 * against what was actually PROPOSED rather than against a magic byte.
 * Two slots: the double proposer puts two distinct values on the wire for
 * one (h, r) and the honest nodes may decide either one (header, G2). */
#define SIM_PROP_SLOTS  2u
typedef struct {
    uint8_t  value[SIM_PROP_SLOTS][SIM_VAL_LEN];
    uint32_t proposer[SIM_PROP_SLOTS];
    uint8_t  n;
} sim_prop_rec_t;

typedef struct sim sim_t_fwd;
typedef struct { sim_t_fwd *s; uint32_t idx; } sim_nctx_t;

typedef struct sim {
    uint32_t n;
    int      model;
    uint64_t rng;
    uint64_t now;
    uint64_t seq;
    uint64_t next_tick;

    uint8_t  ids[SIM_MAXN][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set;
    tm_params_t params;

    tm_core_t     *core[SIM_MAXN];
    tm_proposer_t *prop[SIM_MAXN];
    tm_proposer_t *oracle;                   /* the simulator's own copy, for the actor */
    uint64_t       oracle_height;
    sim_nctx_t     nctx[SIM_MAXN];
    dna_consensus_host_t host[SIM_MAXN];

    uint8_t  is_actor[SIM_MAXN];             /* scripted Byzantine, has no core */
    uint8_t  crashed[SIM_MAXN];
    uint64_t crash_at[SIM_MAXN];
    uint8_t  pending_next[SIM_MAXN];
    uint64_t height[SIM_MAXN];
    uint32_t decided_count[SIM_MAXN];
    uint8_t  decided_id[SIM_MAXN][SIM_HMAX][DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t  decided_have[SIM_MAXN][SIM_HMAX];
    uint8_t  decided_genuine[SIM_MAXN][SIM_HMAX];   /* from the core's decide(), not synced */
    uint8_t  decided_val0[SIM_MAXN][SIM_HMAX];
    uint8_t  decided_value[SIM_MAXN][SIM_HMAX][SIM_VAL_LEN];
    uint32_t decided_round[SIM_MAXN][SIM_HMAX];
    uint64_t last_progress[SIM_MAXN];               /* a decision or a round entry */
    sim_prop_rec_t props[SIM_HMAX][SIM_ROUNDS_MAX];
    const char *g2_fail;

    sim_ev_t *q;
    uint32_t  qn, qcap;

    /* observations */
    uint64_t digest;
    uint32_t max_round_seen;
    uint32_t equivocations;
    uint32_t spam_sent, spam_refused, spam_allocated;
    int      h1_over;
    uint32_t synced_total;
    uint32_t actor_nil_votes, actor_nonnil_votes;
    uint32_t distinct_proposals_delivered;
    uint8_t  acted[SIM_HMAX][SIM_ROUNDS_MAX];
    uint8_t  dp_seen_id[SIM_HMAX][SIM_ROUNDS_MAX][2][DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t  dp_seen_n[SIM_HMAX][SIM_ROUNDS_MAX];
    int      oom;
    int      core_error;      /* any tm_core entry returned -1 */
} sim_t;

static uint64_t xrnd(sim_t *s)
{
    s->rng ^= s->rng << 13;
    s->rng ^= s->rng >> 7;
    s->rng ^= s->rng << 17;
    return s->rng;
}

static uint64_t fnv_mix(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (uint64_t)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void heap_swap(sim_ev_t *a, sim_ev_t *b) { sim_ev_t t = *a; *a = *b; *b = t; }

static int heap_less(const sim_ev_t *a, const sim_ev_t *b)
{
    if (a->at != b->at) return a->at < b->at;
    return a->seq < b->seq;
}

static int q_push(sim_t *s, const sim_ev_t *ev)
{
    uint32_t i;
    if (s->qn == s->qcap) {
        uint32_t want = s->qcap ? s->qcap * 2u : 4096u;
        sim_ev_t *grown = (sim_ev_t *)realloc(s->q, (size_t)want * sizeof(*grown));
        if (!grown) { s->oom = 1; return -1; }
        s->q = grown;
        s->qcap = want;
    }
    s->q[s->qn] = *ev;
    i = s->qn++;
    while (i > 0) {
        uint32_t p = (i - 1u) / 2u;
        if (heap_less(&s->q[i], &s->q[p])) { heap_swap(&s->q[i], &s->q[p]); i = p; }
        else break;
    }
    return 0;
}

static void q_pop(sim_t *s, sim_ev_t *out)
{
    uint32_t i = 0;
    *out = s->q[0];
    s->q[0] = s->q[--s->qn];
    for (;;) {
        uint32_t l = 2u * i + 1u, r = l + 1u, m = i;
        if (l < s->qn && heap_less(&s->q[l], &s->q[m])) m = l;
        if (r < s->qn && heap_less(&s->q[r], &s->q[m])) m = r;
        if (m == i) break;
        heap_swap(&s->q[i], &s->q[m]);
        i = m;
    }
}

/* ── the network ─────────────────────────────────────────────────────── */

static void sim_record_proposal(sim_t *s, uint64_t h, uint32_t r, uint32_t proposer,
                                const uint8_t *value)
{
    sim_prop_rec_t *rec;
    uint8_t k;
    if (h >= SIM_HMAX || r >= SIM_ROUNDS_MAX || !value) return;
    rec = &s->props[h][r];
    for (k = 0; k < rec->n; k++) {
        if (memcmp(rec->value[k], value, SIM_VAL_LEN) == 0) return;   /* already recorded */
    }
    if (rec->n >= SIM_PROP_SLOTS) {
        /* Nothing in the matrix sends three distinct values for one (h, r):
         * an honest proposer sends one, the double proposer two. A third is
         * a simulator defect and must not be dropped on the floor. */
        if (!s->g2_fail) s->g2_fail = "G2 record: a third distinct proposal for one (h, r)";
        return;
    }
    memcpy(rec->value[rec->n], value, SIM_VAL_LEN);
    rec->proposer[rec->n] = proposer;
    rec->n++;
}

static void sim_send_one_from(sim_t *s, uint32_t to, uint32_t origin, uint8_t hops,
                              const dna_cmsg_t *m, const uint8_t *value, int is_spam)
{
    sim_ev_t ev;
    uint64_t delay;

    if (to >= s->n) return;
    memset(&ev, 0, sizeof(ev));
    ev.to = to;
    ev.origin = origin;
    ev.hops = hops;
    ev.m = *m;
    ev.m.value = NULL;
    ev.is_spam = (uint8_t)(is_spam ? 1 : 0);
    if (m->type == DNA_CMSG_PROPOSAL && value) {
        memcpy(ev.value, value, SIM_VAL_LEN);
        ev.m.value_len = SIM_VAL_LEN;
    }

    delay = xrnd(s) % (SIM_DELAY_MAX + 1ull);
    if (s->now < SIM_GST_MS && (xrnd(s) % 100ull) < (uint64_t)SIM_DROP_PCT) {
        /* Partial synchrony: arbitrary delay before GST, never destruction. */
        ev.at = SIM_GST_MS + (xrnd(s) % (SIM_DELAY_MAX + 1ull));
        if (ev.at <= s->now) ev.at = s->now + 1ull;
    } else {
        ev.at = s->now + delay;
    }
    ev.seq = s->seq++;
    (void)q_push(s, &ev);
}

static void sim_send_one(sim_t *s, uint32_t to, const dna_cmsg_t *m,
                         const uint8_t *value, int is_spam)
{
    /* Origin unknown at this call site means "the sender is the origin"; the
     * actor and the honest emit path both send their own messages. */
    uint32_t origin = s->n;   /* n = "no origin", never equal to a node index */
    uint32_t i;
    for (i = 0; i < s->n; i++) {
        if (memcmp(s->ids[i], m->sender, DNA_CONSENSUS_ID_LEN) == 0) { origin = i; break; }
    }
    sim_send_one_from(s, to, origin, 0u, m, value, is_spam);
}

static void sim_broadcast(sim_t *s, uint32_t from, const dna_cmsg_t *m, const uint8_t *value)
{
    uint32_t i;
    for (i = 0; i < s->n; i++) {
        if (i == from) continue;
        sim_send_one_from(s, i, from, 0u, m, value, 0);
    }
}

/* RELAY — the paper's gossip property, which T1 does not implement (design
 * §11.3). A node re-broadcasts once each message its core ACCEPTED, to every
 * peer except itself and the origin. `hops` bounds it at one: a relayed copy
 * is never relayed again, so the message count stays O(n^2) per message and
 * the loop cannot run away. Without this, a message dropped on its direct path
 * has no second route and the equivocation model strands nodes. */
static void sim_relay(sim_t *s, const sim_ev_t *ev)
{
    uint32_t i;
    const uint8_t *value = (ev->m.type == DNA_CMSG_PROPOSAL) ? ev->value : NULL;

    if (ev->hops != 0u || ev->is_spam) return;
    for (i = 0; i < s->n; i++) {
        if (i == ev->to || i == ev->origin) continue;
        sim_send_one_from(s, i, ev->origin, 1u, &ev->m, value, 0);
    }
}

/* ── host callbacks ──────────────────────────────────────────────────── */

static int sim_get_value(void *ctx, uint64_t height, uint8_t **value, size_t *len,
                         uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    sim_nctx_t *nc = (sim_nctx_t *)ctx;
    uint8_t v[SIM_VAL_LEN];

    sim_make_value(height, nc->idx, 0, v);
    *value = (uint8_t *)malloc(SIM_VAL_LEN);
    if (!*value) return 1;
    memcpy(*value, v, SIM_VAL_LEN);
    *len = SIM_VAL_LEN;
    sim_value_id(v, id);
    return 0;
}

static int sim_valid(void *ctx, uint64_t height, const uint8_t *value, size_t len,
                     const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN])
{
    uint8_t expect[DNA_CONSENSUS_VALUE_ID_LEN];
    (void)ctx; (void)height;
    if (!value || len != SIM_VAL_LEN) return 0;
    if (value[0] != (uint8_t)VAL_MAGIC) return 0;
    sim_value_id(value, expect);
    return memcmp(expect, id, DNA_CONSENSUS_VALUE_ID_LEN) == 0 ? 1 : 0;
}

static void sim_emit(void *ctx, const dna_cmsg_t *own)
{
    sim_nctx_t *nc = (sim_nctx_t *)ctx;
    sim_t *s = nc->s;

    /* DG-1: the digest covers everything the message CARRIES, value bytes
     * included — a build that emitted the right envelope with the wrong
     * payload would otherwise hash identically. */
    s->digest = fnv_mix(s->digest, &nc->idx, sizeof(nc->idx));
    s->digest = fnv_mix(s->digest, &own->type, sizeof(own->type));
    s->digest = fnv_mix(s->digest, &own->height, sizeof(own->height));
    s->digest = fnv_mix(s->digest, &own->round, sizeof(own->round));
    s->digest = fnv_mix(s->digest, &own->valid_round, sizeof(own->valid_round));
    s->digest = fnv_mix(s->digest, own->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
    if (own->value && own->value_len > 0) {
        s->digest = fnv_mix(s->digest, own->value, own->value_len);
    }

    if (own->type == DNA_CMSG_PROPOSAL && own->value) {
        sim_record_proposal(s, own->height, own->round, nc->idx, own->value);
    }
    sim_broadcast(s, nc->idx, own, own->value);
}

static void sim_decide(void *ctx, uint64_t height, const uint8_t *value, size_t len,
                       const dna_commit_t *commit)
{
    sim_nctx_t *nc = (sim_nctx_t *)ctx;
    sim_t *s = nc->s;

    s->digest = fnv_mix(s->digest, &nc->idx, sizeof(nc->idx));
    s->digest = fnv_mix(s->digest, &height, sizeof(height));
    s->digest = fnv_mix(s->digest, &commit->round, sizeof(commit->round));
    s->digest = fnv_mix(s->digest, commit->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
    {
        uint32_t k;
        for (k = 0; k < commit->n_voters; k++) {
            s->digest = fnv_mix(s->digest, commit->voters[k], DNA_CONSENSUS_ID_LEN);
        }
    }

    if (height < SIM_HMAX) {
        s->decided_have[nc->idx][height]    = 1;
        s->decided_genuine[nc->idx][height] = 1;
        s->decided_round[nc->idx][height]   = commit->round;
        memcpy(s->decided_id[nc->idx][height], commit->value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        s->decided_val0[nc->idx][height] = (len > 0 && value) ? value[0] : 0;
        if (value && len == SIM_VAL_LEN) {
            memcpy(s->decided_value[nc->idx][height], value, SIM_VAL_LEN);
        }
        /* G2 the strong way (design §11.3): the decided value must be exactly
         * the bytes the PROPOSER of the commit's round put on the wire — any
         * one of the (at most two) values it sent. The magic-byte check alone
         * would accept any well-formed value. */
        if (commit->round < SIM_ROUNDS_MAX) {
            const sim_prop_rec_t *rec = &s->props[height][commit->round];
            uint8_t k, matched = 0;
            if (rec->n == 0) {
                if (!s->g2_fail) s->g2_fail = "G2: decided a round nobody proposed in";
            } else {
                for (k = 0; k < rec->n; k++) {
                    if (value && len == SIM_VAL_LEN &&
                        memcmp(rec->value[k], value, SIM_VAL_LEN) == 0) { matched = 1; break; }
                }
                if (!matched) {
                    if (!s->g2_fail) s->g2_fail = "G2: decided bytes are not the proposed bytes";
                }
            }
        }
    }
    s->decided_count[nc->idx]++;
    s->last_progress[nc->idx] = s->now;
    s->pending_next[nc->idx] = 1;
}

static void sim_actor_on_round(sim_t *s, uint64_t height, uint32_t round);

static void sim_round_start(void *ctx, uint64_t height, uint32_t round,
                            const uint8_t proposer[DNA_CONSENSUS_ID_LEN])
{
    sim_nctx_t *nc = (sim_nctx_t *)ctx;
    sim_t *s = nc->s;

    s->digest = fnv_mix(s->digest, &nc->idx, sizeof(nc->idx));
    s->digest = fnv_mix(s->digest, &height, sizeof(height));
    s->digest = fnv_mix(s->digest, &round, sizeof(round));
    s->digest = fnv_mix(s->digest, proposer, DNA_CONSENSUS_ID_LEN);

    if (round > s->max_round_seen) s->max_round_seen = round;
    s->last_progress[nc->idx] = s->now;
    sim_actor_on_round(s, height, round);
}

static void sim_equivocation(void *ctx, const dna_cmsg_t *first, const dna_cmsg_t *second)
{
    sim_nctx_t *nc = (sim_nctx_t *)ctx;
    (void)first; (void)second;
    nc->s->equivocations++;
}

/* ── the Byzantine actor ─────────────────────────────────────────────── */

/* The actor is always the LAST member: it is scripted from the simulator and
 * owns no tm_core, so nothing it does can be an artefact of the code under
 * test. It reacts to the round entries the HONEST nodes announce, which is
 * both deterministic and the only information a real Byzantine peer has. */
static uint32_t actor_index(const sim_t *s) { return s->n - 1u; }

static int model_has_actor(int model)
{
    return model != MODEL_CRASH;
}

static void actor_vote(sim_t *s, dna_cmsg_type_t type, uint64_t h, uint32_t r,
                       const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN], uint32_t lo, uint32_t hi)
{
    dna_cmsg_t m;
    uint32_t i;

    memset(&m, 0, sizeof(m));
    m.type = type;
    m.height = h;
    m.round = r;
    m.valid_round = -1;
    memcpy(m.sender, s->ids[actor_index(s)], DNA_CONSENSUS_ID_LEN);
    memcpy(m.value_id, id, DNA_CONSENSUS_VALUE_ID_LEN);
    for (i = lo; i <= hi && i < s->n; i++) {
        if (i == actor_index(s)) continue;
        sim_send_one(s, i, &m, NULL, 0);
    }
}

static void actor_propose(sim_t *s, uint64_t h, uint32_t r, uint8_t variant,
                          uint32_t lo, uint32_t hi)
{
    dna_cmsg_t m;
    uint8_t v[SIM_VAL_LEN];
    uint32_t i;

    sim_make_value(h, actor_index(s), variant, v);
    memset(&m, 0, sizeof(m));
    m.type = DNA_CMSG_PROPOSAL;
    m.height = h;
    m.round = r;
    m.valid_round = -1;
    memcpy(m.sender, s->ids[actor_index(s)], DNA_CONSENSUS_ID_LEN);
    sim_value_id(v, m.value_id);
    m.value_len = SIM_VAL_LEN;
    sim_record_proposal(s, h, r, actor_index(s), v);
    for (i = lo; i <= hi && i < s->n; i++) {
        if (i == actor_index(s)) continue;
        sim_send_one(s, i, &m, v, 0);
    }
}

static int actor_is_proposer(sim_t *s, uint64_t h, uint32_t r)
{
    uint8_t got[DNA_CONSENSUS_ID_LEN];
    if (!s->oracle || s->oracle_height != h) return 0;
    if (tm_proposer_at(s->oracle, r, got) != 0) return 0;
    return memcmp(got, s->ids[actor_index(s)], DNA_CONSENSUS_ID_LEN) == 0;
}

static void sim_actor_on_round(sim_t *s, uint64_t height, uint32_t round)
{
    uint32_t mid, last;
    uint8_t idX[DNA_CONSENSUS_VALUE_ID_LEN], idY[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t vx[SIM_VAL_LEN], vy[SIM_VAL_LEN];

    if (!model_has_actor(s->model)) return;
    if (height >= SIM_HMAX || round >= SIM_ROUNDS_MAX) return;
    if (s->acted[height][round]) return;

    /* Two models need to know whose turn it is, and they need the proposer
     * state OF THAT HEIGHT: the double proposer to know when to double-propose,
     * and the equivocating voter to aim one of its two votes at the HONEST
     * proposer's real value. The oracle walks forward with the announcements;
     * if an announcement arrives for a height the oracle has already passed,
     * the actor skips it WITHOUT marking it done. */
    if (s->model == MODEL_DOUBLE_PROPOSER || s->model == MODEL_EQUIV_VOTER) {
        while (s->oracle_height < height) {
            if (tm_proposer_next_height(s->oracle, &s->set) != 0) { s->oom = 1; return; }
            s->oracle_height++;
        }
        if (s->oracle_height != height) return;
    }
    s->acted[height][round] = 1;

    last = s->n - 2u;                 /* the actor itself is index n-1 */
    mid  = last / 2u;

    switch (s->model) {
        case MODEL_EQUIV_VOTER: {
            /* Two conflicting votes to two recipient groups that OVERLAP at
             * `mid`. The overlap is deliberate: with disjoint groups no honest
             * node would ever hold both halves of the evidence and the model's
             * signature would be unobservable.
             *
             * WHAT THIS MODEL NOW EXPECTS: LIVENESS THROUGH THE SECOND SLOT.
             * A node that received the wrong half first still reaches the
             * quorum the others reached, because the right half lands in the
             * sender's second slot and is counted there (design §5.4). Under
             * one slot per sender the same run stalled such a node for good —
             * its count was one short and no message left in the protocol
             * could raise it — which is the failure this model was measuring
             * when it was red at n = 4. The relay and the sync stand-in are
             * both still here and still load-bearing: they are what delivers
             * the second half at all.
             *
             * ONE OF THE TWO IS THE HONEST PROPOSER'S REAL VALUE (red-team T6).
             * With two invented ids the equivocation was inert: no honest node
             * was ever going to count either of them, so the equivocation rule
             * never touched quorum formation and the model measured nothing
             * but the counter. Aiming half the votes at the value the honest
             * majority IS forming a quorum on makes the contention real.
             * The reference is the round-0 proposer (its get_value output does
             * not depend on the round); if that happens to be the actor
             * itself, both ids are invented for that height and only that
             * height loses the sharpened contention. */
            uint8_t rp[DNA_CONSENSUS_ID_LEN];
            uint32_t j, real_idx = actor_index(s);
            if (tm_proposer_at(s->oracle, 0u, rp) == 0) {
                for (j = 0; j < s->n; j++) {
                    if (memcmp(s->ids[j], rp, DNA_CONSENSUS_ID_LEN) == 0) { real_idx = j; break; }
                }
            }
            sim_make_value(height, real_idx, 0, vx);          /* the REAL value */
            sim_make_value(height, actor_index(s), 1, vy);    /* an invented one */
            sim_value_id(vx, idX);
            sim_value_id(vy, idY);
            actor_vote(s, DNA_CMSG_PREVOTE,   height, round, idX, 0, mid);
            actor_vote(s, DNA_CMSG_PREVOTE,   height, round, idY, mid, last);
            actor_vote(s, DNA_CMSG_PRECOMMIT, height, round, idX, 0, mid);
            actor_vote(s, DNA_CMSG_PRECOMMIT, height, round, idY, mid, last);
            s->actor_nonnil_votes += 4u;
            break;
        }

        case MODEL_DOUBLE_PROPOSER:
            /* Two different values to DISJOINT recipient groups: the DIRECT
             * delivery gives no honest node both halves, which is what makes
             * `distinct_proposals_delivered` meaningful — two honest nodes
             * really are looking at different proposals for one (h, r). The
             * relay stand-in then carries each half to the other group, so the
             * conflict IS detected afterwards and the equivocation counter is
             * a positive signature of this model rather than a zero to
             * preserve (see sim_model_signature). */
            if (actor_is_proposer(s, height, round)) {
                actor_propose(s, height, round, 0, 0, mid);
                actor_propose(s, height, round, 1, mid + 1u, last);
            }
            break;

        case MODEL_ALWAYS_NIL: {
            uint8_t nil_id[DNA_CONSENSUS_VALUE_ID_LEN];
            memset(nil_id, 0, sizeof(nil_id));
            actor_vote(s, DNA_CMSG_PREVOTE,   height, round, nil_id, 0, last);
            actor_vote(s, DNA_CMSG_PRECOMMIT, height, round, nil_id, 0, last);
            s->actor_nil_votes += 2u;
            break;
        }

        case MODEL_FAR_ROUND_SPAM: {
            dna_cmsg_t m;
            uint32_t i;
            uint8_t nil_id[DNA_CONSENSUS_VALUE_ID_LEN];
            memset(nil_id, 0, sizeof(nil_id));
            memset(&m, 0, sizeof(m));
            m.type = DNA_CMSG_PREVOTE;
            m.height = height;
            m.round = SIM_SPAM_ROUND;
            m.valid_round = -1;
            memcpy(m.sender, s->ids[actor_index(s)], DNA_CONSENSUS_ID_LEN);
            memcpy(m.value_id, nil_id, DNA_CONSENSUS_VALUE_ID_LEN);
            for (i = 0; i + 1u < s->n; i++) {
                sim_send_one(s, i, &m, NULL, 1);
                s->spam_sent++;
            }
            break;
        }
        default:
            break;
    }
}

/* ── setup / teardown ────────────────────────────────────────────────── */

static void sim_free(sim_t *s)
{
    uint32_t i;
    for (i = 0; i < SIM_MAXN; i++) {
        tm_core_destroy(s->core[i]);
        tm_proposer_destroy(s->prop[i]);
        s->core[i] = NULL;
        s->prop[i] = NULL;
    }
    tm_proposer_destroy(s->oracle);
    s->oracle = NULL;
    free(s->q);
    s->q = NULL;
    s->qn = 0;
    s->qcap = 0;
}

static int sim_init(sim_t *s, uint32_t n, int model, uint64_t seed)
{
    uint32_t i, f, crashed = 0;

    memset(s, 0, sizeof(*s));
    s->n = n;
    s->model = model;
    s->rng = seed ? seed : 0x9E3779B97F4A7C15ULL;
    s->digest = 14695981039346656037ULL;
    s->next_tick = SIM_TICK_MS;

    for (i = 0; i < n; i++) {
        memset(s->ids[i], 0, DNA_CONSENSUS_ID_LEN);
        s->ids[i][0] = (uint8_t)(0x40u + i);
    }
    s->set.n = n;
    s->set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])s->ids;
    s->set.weights = NULL;

    s->params.propose_init_ms      = P_PROPOSE_INIT;
    s->params.propose_delta_ms     = P_PROPOSE_DELTA;
    s->params.prevote_init_ms      = P_PREVOTE_INIT;
    s->params.prevote_delta_ms     = P_PREVOTE_DELTA;
    s->params.precommit_init_ms    = P_PRECOMMIT_INIT;
    s->params.precommit_delta_ms   = P_PRECOMMIT_DELTA;
    s->params.round_lookahead      = TM_ROUND_LOOKAHEAD;
    s->params.max_height_log_bytes = TM_MAX_HEIGHT_LOG_BYTES;
    s->params.max_value_bytes      = TM_MAX_VALUE_BYTES;

    if (tm_proposer_create(&s->oracle, &s->set) != 0) return -1;
    s->oracle_height = 1;

    f = dna_bft_f_plus_one(n) - 1u;

    for (i = 0; i < n; i++) {
        if (model_has_actor(model) && i == actor_index(s)) { s->is_actor[i] = 1; continue; }
        if (model == MODEL_CRASH && crashed < f) {
            /* Deterministic crash instants derived from the seed: after GST,
             * so the run is not merely a smaller cluster from the start, and
             * early enough in the virtual timeline that the crash certainly
             * lands inside a run of H heights rather than after it. */
            s->crash_at[i] = SIM_GST_MS + (xrnd(s) % 600ull);
            crashed++;
        } else {
            s->crash_at[i] = UINT64_MAX;
        }
        s->nctx[i].s = s;
        s->nctx[i].idx = i;
        memset(&s->host[i], 0, sizeof(s->host[i]));
        s->host[i].ctx = &s->nctx[i];
        memcpy(s->host[i].self, s->ids[i], DNA_CONSENSUS_ID_LEN);
        s->host[i].get_value       = sim_get_value;
        s->host[i].valid           = sim_valid;
        s->host[i].emit            = sim_emit;
        s->host[i].decide          = sim_decide;
        s->host[i].on_round_start  = sim_round_start;
        s->host[i].on_equivocation = sim_equivocation;

        if (tm_proposer_create(&s->prop[i], &s->set) != 0) return -1;
        if (tm_core_create(&s->core[i], &s->host[i], &s->params) != 0) return -1;
        s->height[i] = 1;
        if (tm_core_start_height(s->core[i], 1, &s->set, s->prop[i], 0) != 0) return -1;
    }
    return 0;
}

/* Counts as "honest and expected to decide": has a core and never crashed. */
static int node_is_live(const sim_t *s, uint32_t i)
{
    return s->core[i] != NULL && !s->crashed[i];
}

static void sim_advance_heights(sim_t *s)
{
    uint32_t i;
    for (i = 0; i < s->n; i++) {
        if (!s->pending_next[i]) continue;
        s->pending_next[i] = 0;
        if (!node_is_live(s, i)) continue;
        if (s->height[i] >= SIM_H) continue;             /* done with the matrix */
        if (tm_proposer_next_height(s->prop[i], &s->set) != 0) { s->oom = 1; continue; }
        s->height[i] += 1u;
        if (tm_core_start_height(s->core[i], s->height[i], &s->set, s->prop[i], s->now) != 0) {
            s->oom = 1;
        }
    }
}

/* SYNC STAND-IN — the HOST's sync2 path, which T1 does not implement (design
 * §11.3, §9 G6). The core alone does not guarantee liveness: a node can be
 * left behind by messages that never reached it — the two-slot rule (§5.4)
 * closed the case where the message HAD arrived and the core refused to count
 * it, but it cannot conjure a message that was only ever delivered elsewhere,
 * and a node more than one height behind has no buffer for what it is missing.
 * CometBFT hands such a straggler the block through block-sync. Here the
 * simulator plays that part: a live node that has not decided its current
 * height, while a peer genuinely has, and has made no progress for
 * SIM_SYNC_LAG_MS, is handed that peer's value.
 *
 * A SECOND CASE THE SAME PATH COVERS — a node holding the WRONG HALF of a
 * double proposal. The core keeps ONE proposal per (h, r) and reports the
 * conflicting second one as an equivocation without storing it; a node that
 * accepted half X first can then collect a precommit quorum for id(Y) and
 * still not decide, because line 49 needs the PROPOSAL for Y in hand and it
 * never will be. Every other node moves on, the round dies with it alone, and
 * it cannot leave the round on its own (no 2f+1 prevotes ever arrive to arm
 * timeoutPrevote). CometBFT meets exactly this in enterCommit: "commit is for
 * a block we do not know about" — it drops its own ProposalBlock, builds an
 * empty part set for the committed block id and WAITS FOR THE PARTS from the
 * gossip reactor (pinned state.go, enterCommit, the `!cs.ProposalBlock.HashesTo
 * (blockID.Hash)` branch). That reactor is T3 here, so the sync stand-in is
 * what hands the node the value.
 *
 * THE TRIGGER IS "A PEER HOLDS A COMMIT FOR MY HEIGHT", NOT "I AM BEHIND THE
 * BEST HEIGHT". The two agree everywhere except at the matrix's last height:
 * a node that decides SIM_H does not start SIM_H + 1, so a node stranded AT
 * SIM_H is never behind anyone and a height-based trigger leaves it stranded
 * for the whole budget (double proposer, n = 10, seed 3: node 1 sat at
 * h = 20, round 1, step prevote, from t = 2035 to t = 120000 with the other
 * eight nodes finished). In a real chain there is always a next height; the
 * bound is the simulator's, so the trigger must not depend on it.
 *
 * Synced decisions are marked and EXCLUDED from the G1 comparison — they are
 * copies, not independent decisions, and counting them would let the sim
 * agree with itself. They count only towards progress. */
static void sim_sync_stragglers(sim_t *s)
{
    uint32_t i, j;

    for (i = 0; i < s->n; i++) {
        uint64_t h = s->height[i];
        if (!node_is_live(s, i)) continue;
        if (h >= SIM_HMAX) continue;
        if (s->decided_have[i][h]) continue;
        if (s->now < s->last_progress[i] + SIM_SYNC_LAG_MS) continue;

        for (j = 0; j < s->n; j++) {                 /* lowest index: deterministic */
            if (j == i || !node_is_live(s, j)) continue;
            if (!s->decided_genuine[j][h]) continue;
            s->decided_have[i][h]    = 1;
            s->decided_genuine[i][h] = 0;            /* a COPY, not a decision */
            memcpy(s->decided_id[i][h], s->decided_id[j][h], DNA_CONSENSUS_VALUE_ID_LEN);
            s->decided_val0[i][h] = s->decided_val0[j][h];
            s->decided_count[i]++;
            s->synced_total++;
            s->last_progress[i] = s->now;
            s->pending_next[i] = 1;
            break;
        }
    }
}

static void sim_note_double_proposal(sim_t *s, const sim_ev_t *ev)
{
    uint32_t r = ev->m.round;
    uint64_t h = ev->m.height;
    uint32_t k;

    if (h >= SIM_HMAX || r >= SIM_ROUNDS_MAX) return;
    if (memcmp(ev->m.sender, s->ids[actor_index(s)], DNA_CONSENSUS_ID_LEN) != 0) return;
    for (k = 0; k < s->dp_seen_n[h][r]; k++) {
        if (memcmp(s->dp_seen_id[h][r][k], ev->m.value_id, DNA_CONSENSUS_VALUE_ID_LEN) == 0) return;
    }
    if (s->dp_seen_n[h][r] < 2u) {
        memcpy(s->dp_seen_id[h][r][s->dp_seen_n[h][r]], ev->m.value_id, DNA_CONSENSUS_VALUE_ID_LEN);
        s->dp_seen_n[h][r]++;
        if (s->dp_seen_n[h][r] == 2u) s->distinct_proposals_delivered++;
    }
}

static void sim_deliver(sim_t *s, sim_ev_t *ev)
{
    dna_cmsg_t m = ev->m;
    tm_snapshot_t before, after;
    int rc;

    if (!node_is_live(s, ev->to)) return;
    if (m.type == DNA_CMSG_PROPOSAL) {
        m.value = ev->value;
        m.value_len = SIM_VAL_LEN;
    }

    /* G5: far-round spam must not make the receiver ALLOCATE. The observation
     * is a snapshot either side of the delivery — a return code alone would
     * only say the message was refused, not that nothing was kept. Taken ONLY
     * for spam: with the relay in place the ordinary delivery count is an
     * order of magnitude higher and two snapshots on that path would dominate
     * the run. The h+1 entry bound is swept once per tick instead. */
    if (ev->is_spam) {
        tm_core_snapshot(s->core[ev->to], &before);
        rc = tm_core_on_message(s->core[ev->to], &m, s->now);
        tm_core_snapshot(s->core[ev->to], &after);
        if (after.rounds_open != before.rounds_open ||
            after.log_value_bytes != before.log_value_bytes ||
            after.h1_entries != before.h1_entries) {
            s->spam_allocated++;
        }
    } else {
        rc = tm_core_on_message(s->core[ev->to], &m, s->now);
    }
    /* A -1 is a CORE ERROR (allocation, fixpoint guard, a sender outside the
     * set) and must fail the run. Swallowing it would let a defect look like a
     * clean pass, which is exactly how a simulator lies (red-team T2). */
    if (rc < 0) { s->core_error = 1; return; }
    /* The double-proposer signature counts only proposals the core ACCEPTED:
     * a rejected one proves nothing about what the honest nodes saw. */
    if (rc == 0 && m.type == DNA_CMSG_PROPOSAL && s->model == MODEL_DOUBLE_PROPOSER) {
        sim_note_double_proposal(s, ev);
    }
    if (ev->is_spam) {
        s->spam_refused += (rc == 1) ? 1u : 0u;
        return;
    }
    /* gossip stand-in: relay what this node accepted */
    if (rc == 0 || rc == 2) sim_relay(s, ev);
    /* Stand-in for the T3 gossip/sync layer, which T1 does not implement: a
     * message refused ONLY because the receiver is further behind than the
     * one-height buffer reaches is offered again later, a bounded number of
     * times. The condition is height > receiver + 1, NOT height > receiver:
     * at exactly receiver + 1 the core's own h+1 buffer is the thing under
     * test, and re-queueing there would mask every rejection it makes —
     * including the dedup this suite is supposed to measure (red-team T3). */
    if (rc == 1 && m.height > s->height[ev->to] + 1u && ev->retries < SIM_MAX_RETRY) {
        sim_ev_t again = *ev;
        again.retries++;
        again.at = s->now + SIM_DELAY_MAX;
        again.seq = s->seq++;
        (void)q_push(s, &again);
    }
}

/* Runs one configuration to completion or to the virtual-time budget.
 * Returns 0 when every live node decided SIM_H heights. */
static int sim_run(sim_t *s)
{
    uint32_t i;

    for (;;) {
        uint64_t t_ev = (s->qn > 0) ? s->q[0].at : UINT64_MAX;
        uint64_t t = (t_ev < s->next_tick) ? t_ev : s->next_tick;
        int all_done = 1;

        if (s->oom || s->core_error) return -1;
        if (t > SIM_BUDGET_MS) break;
        s->now = t;

        for (i = 0; i < s->n; i++) {
            if (!node_is_live(s, i)) continue;
            if (s->now >= s->crash_at[i]) { s->crashed[i] = 1; continue; }
        }

        if (s->now == s->next_tick) {
            for (i = 0; i < s->n; i++) {
                tm_snapshot_t sn;
                if (!node_is_live(s, i)) continue;
                if (tm_core_on_tick(s->core[i], s->now) != 0) return -1;
                /* G5: the h+1 buffer's entry bound, READ rather than argued. */
                tm_core_snapshot(s->core[i], &sn);
                if (sn.h1_entries > (s->params.round_lookahead + 1u) * s->n * 3u) {
                    s->h1_over = 1;
                }
            }
            s->next_tick += SIM_TICK_MS;
            sim_advance_heights(s);
            sim_sync_stragglers(s);
            sim_advance_heights(s);
        }

        while (s->qn > 0 && s->q[0].at <= s->now) {
            sim_ev_t ev;
            q_pop(s, &ev);
            sim_deliver(s, &ev);
            sim_advance_heights(s);
        }

        if (s->oom || s->core_error) return -1;
        for (i = 0; i < s->n; i++) {
            if (!node_is_live(s, i)) continue;
            if (s->decided_count[i] < SIM_H) { all_done = 0; break; }
        }
        if (all_done) return 0;
    }
    return -1;
}

/* ── per-run checks ──────────────────────────────────────────────────── */

/* Returns NULL when the run satisfies G1, G2 and G6, otherwise a reason. */
static const char *sim_check(sim_t *s)
{
    uint32_t i;
    uint64_t h;

    for (i = 0; i < s->n; i++) {
        if (!node_is_live(s, i)) continue;
        if (s->decided_count[i] != SIM_H) return "G6: a live node did not decide H heights";
    }
    if (s->g2_fail) return s->g2_fail;

    /* G1 spans CRASHED nodes too (red-team T4) but ONLY GENUINE decisions: a
     * synced value is a copy of a peer's decision, so comparing it would be
     * the simulator agreeing with itself. A node that decided height h and only
     * crashed afterwards decided honestly, and if its value differs from the
     * survivors' that is a chain split. */
    for (h = 1; h <= SIM_H; h++) {
        const uint8_t *ref = NULL;
        int any_live_genuine = 0;
        for (i = 0; i < s->n; i++) {
            if (s->is_actor[i] || !s->core[i] || !s->decided_genuine[i][h]) continue;
            if (node_is_live(s, i)) any_live_genuine = 1;
            if (s->decided_val0[i][h] != (uint8_t)VAL_MAGIC) return "G2: a decided value lacks the magic";
            if (!ref) { ref = s->decided_id[i][h]; continue; }
            if (memcmp(ref, s->decided_id[i][h], DNA_CONSENSUS_VALUE_ID_LEN) != 0) {
                return "G1: two honest nodes decided different values";
            }
        }
        if (!ref || !any_live_genuine) return "G1/G6: no live node genuinely decided this height";
    }
    if (s->h1_over) return "G5: the h+1 buffer exceeded its entry bound";
    if (s->spam_allocated != 0) return "G5: far-round spam made a receiver allocate";
    /* the actor never decides anything, by construction */
    for (i = 0; i < s->n; i++) {
        if (s->is_actor[i] && s->decided_count[i] != 0) return "the scripted actor decided";
    }
    return NULL;
}

/* A crashed node really stopped: it is not live and it did not reach H. */
static int sim_crash_was_effective(const sim_t *s)
{
    uint32_t i;
    for (i = 0; i < s->n; i++) {
        if (s->crashed[i] && s->decided_count[i] < SIM_H) return 1;
    }
    return 0;
}

/* Checks that the model's actor really acted. A model that is silently
 * unwired behaves honestly and would pass every other assertion. */
static const char *sim_model_signature(const sim_t *s)
{
    switch (s->model) {
        case MODEL_CRASH:
            /* Checked cumulatively over the whole seed sweep instead: a single
             * seed may schedule its crash after that run finished. */
            return NULL;
        case MODEL_EQUIV_VOTER:
            if (s->actor_nonnil_votes == 0) return "the equivocator never voted";
            if (s->equivocations == 0) return "no equivocation was ever detected";
            return NULL;
        case MODEL_DOUBLE_PROPOSER:
            /* "Two distinct proposals were ACCEPTED by two distinct honest
             * nodes" is checked cumulatively over the whole seed sweep, like
             * the crash model: whether the split is observed in ONE seed is a
             * timing draw, not a property of the code under test. The direct
             * copy of one half races the RELAYED copies of the other half,
             * and at n = 4 the second group is a single node racing two
             * relays; a seed in which the relay wins at every one of the
             * actor's heights (n = 4, seed 30: five heights, five relay wins)
             * makes every honest node accept the same half first and the
             * other half arrive as a conflict everywhere. That run is a
             * correct run, and the sweep still has to show the split at
             * least once.
             *
             * THE EQUIVOCATION COUNTER IS A POSITIVE SIGNATURE HERE, not a
             * zero to defend. The two proposals are sent to DISJOINT groups,
             * but the gossip stand-in relays whatever a node accepted, so
             * every honest node ends up holding both halves and the
             * proposal-slot conflict IS detected. Asserting zero would have
             * been asserting that the relay does not work. */
            if (s->equivocations == 0) {
                return "the two proposals were never detected as a conflict";
            }
            return NULL;
        case MODEL_ALWAYS_NIL:
            if (s->actor_nil_votes == 0) return "the nil voter never voted";
            if (s->actor_nonnil_votes != 0) return "the nil voter cast a non-nil vote";
            return NULL;
        case MODEL_FAR_ROUND_SPAM:
            if (s->spam_sent == 0) return "no spam was sent";
            if (s->spam_refused != s->spam_sent) return "G5: a far-round message was accepted";
            if (s->equivocations != 0) return "spam should not raise equivocation";
            return NULL;
        default:
            return "unknown model";
    }
}

/* ── the matrix ──────────────────────────────────────────────────────── */

static const uint32_t NS[3] = { 4u, 7u, 10u };
#define SEEDS 32u

/* EVERY MODEL RUNS, even after one has failed. Returning at the first failure
 * reports one broken model and hides the rest, which is how a green-looking
 * two-line diff turns out to have broken four things. Each model records its
 * first failure and the sweep reports the whole list. */
static void test_matrix(void)
{
    uint32_t ni, seed;
    int model;
    char buf[200];
    char failures[MODEL_COUNT][160];
    int  failed_models = 0;

    for (model = 0; model < MODEL_COUNT; model++) failures[model][0] = '\0';

    for (model = 0; model < MODEL_COUNT; model++) {
        int rounds_above_zero = 0;
        int crash_effective = 0;
        int split_observed = 0;      /* double proposer: two honest nodes accepted different halves */
        int done = 0;

        for (ni = 0; ni < 3 && !done; ni++) {
            for (seed = 1; seed <= SEEDS && !done; seed++) {
                sim_t s;
                const char *why;

                if (sim_init(&s, NS[ni], model,
                             0x1000000000000000ULL + (uint64_t)seed * 1000003ULL +
                             (uint64_t)NS[ni] * 7919ULL + (uint64_t)model * 104729ULL) != 0) {
                    snprintf(failures[model], sizeof(failures[model]),
                             "%s n=%u seed=%u: setup", model_name(model), NS[ni], seed);
                    sim_free(&s);
                    done = 1;
                    break;
                }
                if (sim_run(&s) != 0) {
                    /* A core error, an allocation failure and an exhausted
                     * budget are THREE different failures and must not share a
                     * message: the first is a defect in the code under test,
                     * the last is a liveness result. */
                    snprintf(failures[model], sizeof(failures[model]),
                             "%s n=%u seed=%u: %s", model_name(model), NS[ni], seed,
                             s.core_error ? "core returned -1"
                                          : (s.oom ? "simulator allocation failed"
                                                   : "ran out of virtual time (liveness)"));
                    sim_free(&s);
                    done = 1;
                    break;
                }
                why = sim_check(&s);
                if (!why) why = sim_model_signature(&s);
                if (why) {
                    snprintf(failures[model], sizeof(failures[model]),
                             "%s n=%u seed=%u: %s", model_name(model), NS[ni], seed, why);
                    sim_free(&s);
                    done = 1;
                    break;
                }
                if (s.max_round_seen > 0) rounds_above_zero = 1;
                if (sim_crash_was_effective(&s)) crash_effective = 1;
                if (s.distinct_proposals_delivered > 0) split_observed = 1;
                sim_free(&s);
            }
        }
        if (!done && !rounds_above_zero) {
            snprintf(failures[model], sizeof(failures[model]),
                     "%s: no seed ever left round 0 — nothing was measured", model_name(model));
        } else if (!done && model == MODEL_CRASH && !crash_effective) {
            snprintf(failures[model], sizeof(failures[model]),
                     "%s: no node was ever stopped — the model is not wired", model_name(model));
        } else if (!done && model == MODEL_DOUBLE_PROPOSER && !split_observed) {
            snprintf(failures[model], sizeof(failures[model]),
                     "%s: no seed ever had two honest nodes accept different proposals for one (h, r)",
                     model_name(model));
        }
        if (failures[model][0] != '\0') failed_models++;
    }

    snprintf(buf, sizeof(buf), "matrix: %d models x n in {4,7,10} x %u seeds, H=%u",
             MODEL_COUNT, SEEDS, SIM_H);
    TEST(buf);
    if (failed_models == 0) { PASS(); return; }
    printf("FAIL: %d model(s)\n", failed_models);
    for (model = 0; model < MODEL_COUNT; model++) {
        if (failures[model][0] != '\0') printf("      - %s\n", failures[model]);
    }
    failed++;
}

/* ── DG-1 twin trace ─────────────────────────────────────────────────── */

static void test_twin_trace(void)
{
    uint32_t ni, seed;
    int model;
    char buf[160];

    TEST("DG-1: two SEPARATE simulators, same seed, identical trace digest");

    for (model = 0; model < MODEL_COUNT; model++) {
        for (ni = 0; ni < 3; ni++) {
            for (seed = 1; seed <= 4u; seed++) {
                sim_t a, b;
                uint64_t sd = 0x2000000000000000ULL + (uint64_t)seed * 1000003ULL +
                              (uint64_t)NS[ni] * 7919ULL + (uint64_t)model * 104729ULL;

                if (sim_init(&a, NS[ni], model, sd) != 0) { sim_free(&a); FAIL("setup a"); return; }
                if (sim_run(&a) != 0) { sim_free(&a); FAIL("run a"); return; }
                if (sim_init(&b, NS[ni], model, sd) != 0) {
                    sim_free(&a); sim_free(&b); FAIL("setup b"); return;
                }
                if (sim_run(&b) != 0) { sim_free(&a); sim_free(&b); FAIL("run b"); return; }

                if (a.digest != b.digest) {
                    snprintf(buf, sizeof(buf), "model=%d n=%u seed=%u digests differ",
                             model, NS[ni], seed);
                    sim_free(&a); sim_free(&b);
                    FAIL(buf);
                    return;
                }
                if (a.digest == 14695981039346656037ULL) {
                    sim_free(&a); sim_free(&b);
                    FAIL("the digest never absorbed an event");
                    return;
                }
                sim_free(&a);
                sim_free(&b);
            }
        }
    }
    PASS();
}

/* Different seeds must be able to produce different traces, or the digest is
 * measuring nothing about the schedule. */
static void test_seeds_differ(void)
{
    sim_t a, b;
    uint64_t da, db;

    TEST("different seeds produce different traces (the digest is live)");
    if (sim_init(&a, 7u, MODEL_EQUIV_VOTER, 0x3000000000000001ULL) != 0) {
        sim_free(&a); FAIL("setup a"); return;
    }
    if (sim_run(&a) != 0) { sim_free(&a); FAIL("run a"); return; }
    da = a.digest;
    sim_free(&a);

    if (sim_init(&b, 7u, MODEL_EQUIV_VOTER, 0x3000000000000002ULL) != 0) {
        sim_free(&b); FAIL("setup b"); return;
    }
    if (sim_run(&b) != 0) { sim_free(&b); FAIL("run b"); return; }
    db = b.digest;
    sim_free(&b);

    if (da == db) { FAIL("two different seeds gave the same trace"); return; }
    PASS();
}

int main(void)
{
    printf("\nNodus Tendermint T1 — N-node seeded simulation\n");
    printf("==========================================\n\n");

    test_matrix();
    test_twin_trace();
    test_seeds_differ();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
