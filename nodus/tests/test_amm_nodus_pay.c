/**
 * test_amm_nodus_pay.c -- the nodus-amm NODUS payout and refund
 * (amm_nodus_pay.c) against a scriptable STUB node behind the amm_node.h seam
 * table and a REAL journal; the planner, the builder and the signer are the
 * REAL ones (nodus_v2_spend_*, ML-DSA-87) with the newest pinned rule-set
 * generation, so a built envelope is a real signed envelope.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 11 payout paragraph, section 17 write-ahead rule, section 19
 * "test_amm_eth_pay" / "test_amm_engine" Nodus lines; givens items 28, 39,
 * 51, 52, 53):
 *   P1  the pure verdict: net = gross - fee SATURATES at zero (a fee above the
 *       amount never wraps); the minimum is compared with net AFTER the fee
 *       (givens item 51): net == minimum pays, net == minimum - 1 is below, a
 *       minimum that the GROSS satisfies but the net does not is below;
 *   P2  a payout is ONE ordinary native CORE SPEND: one recipient output to
 *       the swap's destination, native token, amount = gross - fee, the bot's
 *       own change, expiry = tip + expiry_ahead, recipient + fee == gross
 *       (the Nodus fee is deducted from the amount, givens item 39); a
 *       refund goes to the request's SENDER; nothing is submitted by signing;
 *   P3  WRITE-AHEAD (plan line 369): the envelope is in the journal before any
 *       submit; the submit sends exactly the stored bytes; a RESTART between
 *       store and broadcast (journal reopened, a new payer) sends the SAME
 *       bytes and builds no new envelope;
 *   P4  resubmission: not before `resubmit_blocks`, then the same bytes
 *       again; a node refusal or no answer moves no terminal state (no answer
 *       keeps the attempt signed and is tried again);
 *   P5  settlement ONLY by a completely scanned block that holds the intent
 *       id: the swap becomes paid (payout) / refunded (refund) and the attempt
 *       confirmed in ONE transaction; the scan cursor survives a restart;
 *   P6  expiry and replacement: an attempt is expired only when the tip is
 *       past its expiry AND every block up to it was scanned; a replacement is
 *       made only after that, from the old attempt's coins, sharing an input,
 *       with the stored gross; never while the attempt is open; with none of
 *       the old coins left nothing is signed;
 *   P7  an unreadable answer is never a zero: a chain id that does not match,
 *       an unreadable tip, a gas price that is not REPORTED (absent) or
 *       unreadable, an unreadable or incomplete coin list, an incomplete
 *       block scan -> AMM_NP_UNKNOWN with the swap and the attempt unchanged;
 *       a reported gas price of 0 is a valid price; a block the node does not
 *       hold makes the swap `unknown`;
 *   P8a the fee is the SDK's rule max(floor, units x gas price), checked
 *       against the units declared in the BUILT envelope (not the planner's
 *       own quote), arithmetic cross-checked with python3; a nonzero gas price
 *       CHANGES the fee; a coin EXACTLY equal to gross funds gross - fee plus
 *       the fee (one input, no change output);
 *   P8b a zero REPLACEMENT refund is DROPPED (not retried every step); a payout
 *       whose net falls below its minimum after a fee rise takes the refund
 *       path (payout_pending -> refund_pending), nothing signed;
 *   P8  FEE AT, BELOW AND ABOVE THE AMOUNT (gas price 0 and a gas price that
 *       lifts the fee): fee < amount pays amount - fee; fee == amount and
 *       fee > amount are never signed or broadcast: a refund is DROPPED
 *       (givens items 89, 90), a payout returns AMM_NP_ZERO and moves to
 *       refund_pending;
 *   P9  the minimum after the fee on a real payout: net == minimum signs,
 *       net == minimum - 1 is AMM_NP_BELOW_MIN with nothing signed and the
 *       swap on the refund path; a minimum satisfied before the fee but not
 *       after is refused;
 *   P10 1..15 inputs: a payout needing 15 coins is built with 15 inputs, one
 *       needing 16 is refused (FUNDS, "more than 15 coins"), coins the payout
 *       does not need are NOT swept in (coin joining is DEFERRED); funds
 *       short and a truncated listing are FUNDS (the listing says
 *       "incomplete");
 *   P11 payouts_paused: nothing is signed or submitted; settlement scans
 *       continue (plan section 16);
 *   P12 the journal's guards seen through the payer: a swap that owes no
 *       NODUS payout, a second first-sign, a zero gross are refused;
 *   P13 one payout in flight: the head swap (oldest by seq) is driven, the
 *       next waits; a second swap's envelope is NOT stored while the first
 *       attempt is open (the same coin would be spent twice), and after the
 *       first is settled the second needs its own sign;
 *   P15 the input coins of an expired attempt of a swap that still owes its
 *       payout are reserved: no payout decided meanwhile, no refund's first
 *       attempt and no quote uses them; the swap's own replacement does and
 *       shares an input; a replacement that cannot be stored is reported as
 *       waiting; the reservation survives a restart and ends when the swap
 *       leaves the owed states (see the comment of P15);
 *   P14 configuration: expiry_ahead outside 1..100, a zero resubmit or scan
 *       bound, a missing key / rand / seam function are refused (NULL).
 * WHAT IT REQUIRES: a default build (the newest pinned rule-set generation);
 *   one mkdtemp directory per scenario under /tmp (removed); no network.
 *   Signing ML-DSA-87 makes it slower than the other AMM tests.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the node's answers, the tip and the block contents are
 *   scripted; the node's real mempool, CheckTx and chain are not here. A
 *   built envelope is checked by decoding it, not by executing it on a chain,
 *   and the signature is produced but not verified by a node. The fee at a
 *   gas price is the planner's number, calibrated by a quote in the test, not
 *   an independently computed one.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/nodus_identity.h"
#include "amm_nodus_pay.h"
#include "nodus/nodus_v2_spend.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── deterministic randomness (xorshift64*, fixed seed) ────────────── */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static int test_rand(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27;
        buf[i] = (uint8_t)((g_rng * 0x2545F4914F6CDD1DULL) >> 56);
    }
    return 0;
}

/* ── the stub node ──────────────────────────────────────────────────── */
typedef struct {
    uint8_t  chain[32];
    int      chain_rc;
    nodus_dnac_ruleset_info_t ri;
    int      ri_rc;
    uint64_t gas;
    int      gas_rc;                 /* 0 ok, AMM_NODE_UNREPORTED, AMM_NODE_ERR */
    amm_coin_list_t nat;
    int      nat_rc;                 /* 0 ok, AMM_NODE_ERR, AMM_NODE_INCOMPLETE */
    uint64_t applied_height;         /* 0 = never applied                       */
    uint8_t  applied_intent[64];
    uint64_t not_held_below;         /* heights below this: NOT_HELD            */
    uint64_t err_height;             /* this height: ERR (incomplete walk)      */
    int      submit_rc;
    int      submit_calls;
    uint8_t *last_env;
    size_t   last_env_len;
    int      scan_calls;
    uint64_t scan_first;             /* the first height scanned since reset    */
} stub_t;

static int s_chain(void *c, uint8_t out[32], uint64_t dl) {
    stub_t *s = c; (void)dl;
    if (s->chain_rc) return s->chain_rc;
    memcpy(out, s->chain, 32);
    return AMM_NODE_OK;
}
static int s_ri(void *c, nodus_dnac_ruleset_info_t *out, uint64_t dl) {
    stub_t *s = c; (void)dl;
    if (s->ri_rc) return s->ri_rc;
    *out = s->ri;
    return AMM_NODE_OK;
}
static int s_gas(void *c, uint64_t *out, uint64_t dl) {
    stub_t *s = c; (void)dl;
    if (s->gas_rc) return s->gas_rc;
    *out = s->gas;
    return AMM_NODE_OK;
}
static int s_coins(void *c, const uint8_t token[64], amm_coin_list_t *out, uint64_t dl) {
    stub_t *s = c; (void)dl; (void)token;
    if (s->nat_rc) return s->nat_rc;
    *out = s->nat;
    return AMM_NODE_OK;
}
static int s_scan(void *c, uint64_t h, const uint8_t intent[64], uint32_t *from, int *found,
                  uint64_t dl) {
    stub_t *s = c; (void)dl; (void)from;
    s->scan_calls++;
    if (!s->scan_first) s->scan_first = h;
    if (s->err_height && h == s->err_height) return AMM_NODE_ERR;
    if (s->not_held_below && h < s->not_held_below) return AMM_NODE_NOT_HELD;
    *found = (s->applied_height == h && memcmp(intent, s->applied_intent, 64) == 0);
    return AMM_NODE_OK;
}
static int s_submit(void *c, const uint8_t wire[64], const uint8_t *env, size_t len, char *msg,
                    size_t cap, uint64_t dl) {
    stub_t *s = c; (void)wire; (void)dl;
    s->submit_calls++;
    free(s->last_env);
    s->last_env = malloc(len);
    memcpy(s->last_env, env, len);
    s->last_env_len = len;
    if (cap) snprintf(msg, cap, "stub");
    return s->submit_rc;
}

static void stub_vt(stub_t *s, amm_node_t *vt) {
    memset(vt, 0, sizeof(*vt));
    vt->ctx = s;
    vt->chain_id32 = s_chain;
    vt->ruleset_info = s_ri;
    vt->gas_price = s_gas;
    vt->coins = s_coins;
    vt->scan_block = s_scan;
    vt->submit = s_submit;
}

/* ── the environment ────────────────────────────────────────────────── */
typedef struct {
    stub_t           st;
    amm_node_t       vt;
    amm_nodus_pay_cfg_t cfg;
    amm_journal_t   *j;
    amm_nodus_pay_t *p;
    char             dir[64];
    char             jpath[96];
} env_t;

static nodus_identity_t *g_id;

static void ensure_id(void) {
    if (g_id) return;
    g_id = calloc(1, sizeof(*g_id));
    if (!g_id || nodus_identity_generate(g_id) != 0) {
        printf("FATAL: identity generation failed\n");
        exit(2);
    }
}

static void add_coin(amm_coin_list_t *l, int seed, uint64_t amount) {
    amm_coin_t *c = &l->c[l->n++];
    memset(c, 0, sizeof(*c));
    for (int i = 0; i < 64; i++) c->nul[i] = (uint8_t)(seed * 31 + i);
    c->amount = amount;
    c->unlock_block = 0;
}

static void wire(env_t *e) {
    stub_vt(&e->st, &e->vt);
    e->cfg.node = &e->vt;
    e->cfg.journal = e->j;
    e->p = amm_nodus_pay_new(&e->cfg);
    if (!e->p) { printf("FATAL: payer\n"); exit(2); }
}

/* A bot with one coin of 10^13 raw (100 000 NODUS) at tip 1000. */
static void env_open(env_t *e) {
    ensure_id();
    memset(e, 0, sizeof(*e));
    snprintf(e->dir, sizeof(e->dir), "/tmp/amm_npay_test_XXXXXX");
    if (!mkdtemp(e->dir)) { printf("FATAL: mkdtemp\n"); exit(2); }
    snprintf(e->jpath, sizeof(e->jpath), "%s/journal.db", e->dir);
    stub_t *s = &e->st;
    for (int i = 0; i < 32; i++) s->chain[i] = (uint8_t)(0xC0 + i);
    uint32_t gen = nodus_v2_pins_generation_count();
    s->ri.tip = 1000;
    s->ri.generation = gen;
    nodus_v2_pins_tuples(gen, &s->ri.sys_version, s->ri.sys_hash, &s->ri.core_version,
                         s->ri.core_hash);
    s->gas = 0;
    add_coin(&s->nat, 1, 10000000000000ULL);
    s->nat.tip = 1000;
    s->submit_rc = 0;
    e->cfg.pk = g_id->pk.bytes;
    e->cfg.sk = g_id->sk.bytes;
    e->cfg.rand = test_rand;
    memcpy(e->cfg.chain_id, s->chain, 32);
    e->cfg.expiry_ahead = 90;
    e->cfg.resubmit_blocks = 3;
    e->cfg.scan_blocks = 64;
    if (amm_journal_open(e->jpath, &e->j) != 0) { printf("FATAL: journal\n"); exit(2); }
    wire(e);
}

static void env_reopen(env_t *e) {
    amm_nodus_pay_free(e->p);
    amm_journal_close(e->j);
    if (amm_journal_open(e->jpath, &e->j) != 0) { printf("FATAL: journal reopen\n"); exit(2); }
    wire(e);
}

static void env_close(env_t *e) {
    amm_nodus_pay_free(e->p);
    amm_journal_close(e->j);
    free(e->st.last_env);
    char p[160];
    snprintf(p, sizeof(p), "%s/journal.db", e->dir); unlink(p);
    snprintf(p, sizeof(p), "%s/journal.db-wal", e->dir); unlink(p);
    snprintf(p, sizeof(p), "%s/journal.db-shm", e->dir); unlink(p);
    rmdir(e->dir);
}

/* ── swaps ──────────────────────────────────────────────────────────── */

static uint64_t g_ctr = 1;

/* paid_waiting_depth is the SEEN payment (revision 12): amm_journal_swap_seen with a
 * 500 USDT total takes the room; every other target is the plain transition. */
static int tr(env_t *e, int64_t seq, const char *to, const char *inc) {
    if (!strcmp(to, "paid_waiting_depth"))
        return amm_journal_swap_seen(e->j, seq, inc, NULL, 500000000ULL, 0, NULL);
    return amm_journal_swap_transition(e->j, seq, to, inc, NULL, NULL);
}

static void dest_hex(char out[129]) { memset(out, 'e', 128); out[128] = '\0'; }
static void sender_hex(char out[129]) { memset(out, 'c', 128); out[128] = '\0'; }

static int approve_common(env_t *e, amm_dir_t dir, uint64_t minimum, amm_swap_t *s) {
    static char snd[8][129], dst[8][129], idt[8][40];
    static unsigned k = 0;
    unsigned i = k++ % 8;
    uint64_t n = g_ctr++;
    char sc = (char)('a' + (n % 6));
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    a.dir = dir;
    if (dir == AMM_USDT_TO_NODUS) {
        memset(snd[i], sc, 40); snd[i][40] = '\0';          /* the Ethereum sender   */
        dest_hex(dst[i]);                                    /* the payout address    */
    } else {
        sender_hex(snd[i]);                                  /* the Nodus sender      */
        memset(dst[i], 'b', 40); dst[i][40] = '\0';          /* the Ethereum address  */
    }
    snprintf(idt[i], sizeof(idt[i]), "nodus:t%llu", (unsigned long long)n);
    a.sender = snd[i]; a.dest = dst[i];
    a.amount = 1000 + n; a.minimum = minimum; a.value_usdt = 1;
    a.approved_at = 1; a.expiry = 100; a.approved_tip = 1;
    a.incoming_id = "";
    for (int b = 0; b < 8; b++) a.req_no[31 - b] = (uint8_t)(n >> (8 * b));
    for (int b = 0; b < 16; b++) a.rand16[b] = (uint8_t)(n * 29 + b);
    a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    if (amm_journal_approve(e->j, &a, s) != AMM_J_OK) return 0;
    return tr(e, s->seq, "paid_waiting_depth", idt[i]) == 0 && tr(e, s->seq, "counted", NULL) == 0;
}

/* A USDT -> NODUS swap in payout_pending (dest = 128 x 'e'). */
static int mk_payout(env_t *e, uint64_t minimum, amm_swap_t *s) {
    return approve_common(e, AMM_USDT_TO_NODUS, minimum, s) && tr(e, s->seq, "payout_pending", NULL) == 0;
}

/* A NODUS -> USDT swap in refund_pending (sender = 128 x 'c'). */
static int mk_refund(env_t *e, amm_swap_t *s) {
    return approve_common(e, AMM_NODUS_TO_USDT, 0, s) && tr(e, s->seq, "refund_pending", NULL) == 0;
}

static int swap_is(env_t *e, const amm_swap_t *s, const char *st) {
    amm_swap_t g;
    return amm_journal_swap_by_seq(e->j, s->seq, &g) == 0 && !strcmp(g.state, st);
}

/* Sign a swap's payout. A USDT -> NODUS PAYOUT is signed by the engine's decision
 * since revision 12 (plan section 12): amm_nodus_pay_prepare plans, builds and signs
 * WITHOUT touching the journal and the attempt is stored by the caller -- here by
 * this helper, as the decision does (amm_journal_swap_decide stores it in the same
 * transaction as the ledger update; that transaction is tested in test_amm_journal
 * J27 and test_amm_engine E3). The payer no longer moves a payout to refund_pending:
 * ZERO and BELOW_MIN are only returned and the swap stays payout_pending. A REFUND
 * is signed by amm_nodus_pay_sign as before. */
static int sign(env_t *e, const amm_swap_t *s, uint64_t gross, amm_np_step_t *o) {
    amm_swap_t cur;
    if (amm_journal_swap_by_seq(e->j, s->seq, &cur) == 0 && cur.dir == AMM_USDT_TO_NODUS &&
        !strcmp(cur.state, AMM_S_PAYOUT_PENDING)) {
        amm_attempt_t prev;
        memset(o, 0, sizeof(*o));
        o->swap_seq = cur.seq;
        if (gross == 0) return AMM_NP_ERR;
        int ar = amm_journal_attempt_latest(e->j, cur.seq, &prev);
        if (ar == 0) { amm_attempt_free(&prev); return AMM_NP_ERR; }     /* an attempt exists */
        amm_np_prepared_t pre;
        int r = amm_nodus_pay_prepare(e->p, cur.dest, gross, cur.minimum, 0, &pre);
        snprintf(o->msg, sizeof(o->msg), "%s", pre.msg);
        if (r == AMM_NP_OK) {
            pre.attempt.swap_seq = cur.seq;
            int jr = amm_journal_attempt_sign(e->j, &pre.attempt);
            if (jr == AMM_J_OK) { o->worked = 1; o->signed_ = 1; }
            else r = jr == AMM_J_ILLEGAL ? AMM_NP_BUSY : AMM_NP_ERR;
        }
        amm_np_prepared_free(&pre);
        return r;
    }
    return amm_nodus_pay_sign(e->p, s->seq, gross, 0, o);
}

static int step(env_t *e, amm_np_step_t *o) { return amm_nodus_pay_step(e->p, 0, o); }

static int attempt(env_t *e, const amm_swap_t *s, amm_attempt_t *a) {
    return amm_journal_attempt_latest(e->j, s->seq, a);
}

/* The nullifier add_coin(seed) gives its coin. */
static void coin_nul(int seed, uint8_t out[64]) {
    for (int i = 0; i < 64; i++) out[i] = (uint8_t)(seed * 31 + i);
}

static int has_nul(const amm_attempt_t *a, const uint8_t *nul) {
    for (int i = 0; i < a->n_in; i++)
        if (!memcmp(a->inputs[i], nul, 64)) return 1;
    return 0;
}

/* The planner's fee for a payout of `gross` right now (a quote). */
static uint64_t fee_of(env_t *e, uint64_t gross) {
    amm_np_quote_t q;
    if (amm_nodus_pay_quote(e->p, gross, 0, &q) != AMM_NP_OK) return 0;
    return q.fee;
}

int main(void) {
    printf("test_amm_nodus_pay\n");
    env_t e;
    amm_swap_t s, s2;
    amm_np_step_t o;
    amm_attempt_t at, at2;
    nodus_v2_spend_decoded_t d;
    char dst[129], snd[129];
    dest_hex(dst);
    sender_hex(snd);
    static const uint8_t zero64[64] = {0};

    /* ── P1 the pure verdict ─────────────────────────────────────── */
    uint64_t net = 99;
    CHECK(amm_nodus_pay_judge(1000, 100, 0, &net) == AMM_NP_PAY && net == 900, "P1 fee below the amount: net = gross - fee");
    CHECK(amm_nodus_pay_judge(1000, 1000, 0, &net) == AMM_NP_NOTHING && net == 0, "P1 fee == amount: nothing is left");
    CHECK(amm_nodus_pay_judge(5, 10, 0, &net) == AMM_NP_NOTHING && net == 0, "P1 fee above the amount: saturates at zero, never wraps");
    CHECK(amm_nodus_pay_judge(0, 1, 0, &net) == AMM_NP_NOTHING && net == 0, "P1 gross 0, fee 1: zero");
    CHECK(amm_nodus_pay_judge(UINT64_MAX, 1, 0, &net) == AMM_NP_PAY && net == UINT64_MAX - 1, "P1 the largest amount");
    CHECK(amm_nodus_pay_judge(1000, 100, 900, &net) == AMM_NP_PAY, "P1 net == minimum: pays (the minimum is a floor)");
    CHECK(amm_nodus_pay_judge(1000, 100, 901, &net) == AMM_NP_BELOW && net == 900, "P1 net == minimum - 1: below");
    CHECK(amm_nodus_pay_judge(1000, 100, 950, NULL) == AMM_NP_BELOW,
          "P1 the minimum is compared with the amount AFTER the fee (gross 1000 would satisfy 950)");
    CHECK(amm_nodus_pay_judge(1000, 1000, 0, NULL) == AMM_NP_NOTHING && amm_nodus_pay_judge(1000, 1000, 5, NULL) == AMM_NP_NOTHING,
          "P1 nothing left is nothing left whatever the minimum");

    /* ── P2 shapes; P3 write-ahead ───────────────────────────────── */
    env_open(&e);
    CHECK(mk_payout(&e, 1, &s), "P2 setup: a USDT -> NODUS swap in payout_pending");
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK && o.signed_ == 1, "P2 sign stores an envelope");
    CHECK(e.st.submit_calls == 0, "P2/P3 nothing is submitted by signing");
    CHECK(attempt(&e, &s, &at) == 0 && at.n == 1 && !strcmp(at.state, "signed"), "P2 attempt 1 is stored, signed");
    CHECK(nodus_v2_spend_decode(at.env, at.env_len, &d) == NODUS_V2_SPEND_OK, "P2 the stored bytes decode");
    CHECK(d.n_recipient_out == 1 && !strcmp(d.out_owner[0], dst) && !memcmp(d.out_token[0], zero64, 64),
          "P2 ONE native recipient output to the swap's destination");
    CHECK(d.out_amount[0] + d.fee == 5000000000ULL && at.gross == 5000000000ULL && at.net == d.out_amount[0] &&
          at.fee == d.fee && d.fee >= 1000000ULL,
          "P2 recipient amount + Nodus fee == gross: the fee is deducted from the amount");
    int change_ok = 1;
    for (int k = 1; k < d.n_out; k++)
        if (strcmp(d.out_owner[k], amm_nodus_pay_self(e.p))) change_ok = 0;
    CHECK(change_ok && d.n_out == 2, "P2 the only other output is the bot's own change");
    CHECK(d.expiry_height == 1090 && at.expiry == 1090 && at.build_tip == 1000 && at.scan_next == 1001,
          "P2 expiry = tip + 90, build tip and scan cursor stored");
    CHECK(at.n_in == 1 && !strcmp(at.dest, dst), "P2 one input; the destination stored");
    static uint8_t stored_first[65536];
    size_t stored_len = at.env_len;
    memcpy(stored_first, at.env, at.env_len < sizeof(stored_first) ? at.env_len : sizeof(stored_first));
    uint8_t wire_first[64];
    memcpy(wire_first, at.wire_id, 64);
    CHECK(stored_len <= sizeof(stored_first), "P3 setup: the envelope fits the comparison buffer");
    amm_attempt_free(&at);

    /* P3 the submit sends exactly the stored bytes */
    CHECK(step(&e, &o) == AMM_NP_OK && o.submitted == 1 && e.st.submit_calls == 1, "P3 the step submits");
    CHECK(e.st.last_env_len == stored_len && !memcmp(e.st.last_env, stored_first, stored_len),
          "P3 the submitted bytes are exactly the stored bytes");
    CHECK(attempt(&e, &s, &at) == 0 && !strcmp(at.state, "submitted") && at.last_submit_tip == 1000,
          "P3 signed -> submitted, the submit tip is stored");
    amm_attempt_free(&at);
    env_close(&e);

    /* P3 a restart between store and broadcast */
    env_open(&e);
    CHECK(mk_payout(&e, 1, &s) && sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK, "P3 setup: an envelope is stored, nothing sent");
    attempt(&e, &s, &at);
    memcpy(stored_first, at.env, at.env_len);
    stored_len = at.env_len;
    amm_attempt_free(&at);
    env_reopen(&e);
    CHECK(e.st.submit_calls == 0, "P3 the restart sent nothing");
    CHECK(step(&e, &o) == AMM_NP_OK && o.submitted == 1 && e.st.submit_calls == 1 && e.st.last_env_len == stored_len &&
          !memcmp(e.st.last_env, stored_first, stored_len),
          "P3 after the restart the SAME stored bytes are sent (nothing is rebuilt)");
    CHECK(attempt(&e, &s, &at) == 0 && at.n == 1, "P3 still attempt 1");
    amm_attempt_free(&at);
    env_close(&e);

    /* P2 a refund goes to the request's sender */
    env_open(&e);
    CHECK(mk_refund(&e, &s), "P2 setup: a NODUS -> USDT swap in refund_pending");
    CHECK(sign(&e, &s, 7000000000ULL, &o) == AMM_NP_OK, "P2 the refund is signed");
    attempt(&e, &s, &at);
    nodus_v2_spend_decode(at.env, at.env_len, &d);
    CHECK(!strcmp(d.out_owner[0], snd) && !strcmp(at.dest, snd) && d.out_amount[0] + d.fee == 7000000000ULL,
          "P2 the refund goes to the request's SENDER, minus the Nodus fee");
    amm_attempt_free(&at);
    env_close(&e);

    /* ── P4 resubmission ─────────────────────────────────────────── */
    env_open(&e);
    mk_payout(&e, 1, &s);
    sign(&e, &s, 5000000000ULL, &o);
    attempt(&e, &s, &at);
    memcpy(stored_first, at.env, at.env_len);
    stored_len = at.env_len;
    amm_attempt_free(&at);
    e.st.submit_rc = -1;                                   /* no answer */
    CHECK(step(&e, &o) == AMM_NP_OK && o.submitted == 0 && e.st.submit_calls == 1, "P4 no answer: tried");
    attempt(&e, &s, &at);
    CHECK(!strcmp(at.state, "signed") && at.last_submit_tip == 0, "P4 no answer keeps the attempt signed");
    amm_attempt_free(&at);
    CHECK(step(&e, &o) == AMM_NP_OK && e.st.submit_calls == 2, "P4 ... and it is tried again at once");
    e.st.submit_rc = 1;                                    /* the node refused */
    CHECK(step(&e, &o) == AMM_NP_OK && o.submitted == 1 && e.st.submit_calls == 3, "P4 a refusal is an answer: submitted");
    attempt(&e, &s, &at);
    CHECK(!strcmp(at.state, "submitted") && at.last_submit_tip == 1000 && swap_is(&e, &s, "payout_pending"),
          "P4 a node refusal terminates nothing");
    amm_attempt_free(&at);
    CHECK(step(&e, &o) == AMM_NP_OK && e.st.submit_calls == 3, "P4 no resubmit within 3 blocks of the last submit");
    e.st.ri.tip = 1003;
    CHECK(step(&e, &o) == AMM_NP_OK && e.st.submit_calls == 4 && e.st.last_env_len == stored_len &&
          !memcmp(e.st.last_env, stored_first, stored_len), "P4 after 3 blocks the SAME bytes go again");
    attempt(&e, &s, &at);
    CHECK(at.scan_next == 1004, "P4 the scan covered 1001..1003 completely");
    amm_attempt_free(&at);
    env_close(&e);

    /* ── P5 settlement ───────────────────────────────────────────── */
    env_open(&e);
    mk_payout(&e, 1, &s);
    sign(&e, &s, 5000000000ULL, &o);
    step(&e, &o);
    attempt(&e, &s, &at);
    e.st.applied_height = 1004;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    e.st.ri.tip = 1005;
    CHECK(step(&e, &o) == AMM_NP_OK && o.confirmed == 1 && swap_is(&e, &s, "paid"),
          "P5 the intent id in a completely scanned block: the swap is paid");
    attempt(&e, &s, &at2);
    CHECK(!strcmp(at2.state, "confirmed"), "P5 the attempt is confirmed");
    amm_attempt_free(&at2);
    CHECK(step(&e, &o) == AMM_NP_OK && o.worked == 0, "P5 nothing left to do");
    amm_attempt_free(&at);
    env_close(&e);

    env_open(&e);                                         /* a refund settles to refunded */
    mk_refund(&e, &s);
    sign(&e, &s, 7000000000ULL, &o);
    step(&e, &o);
    attempt(&e, &s, &at);
    e.st.applied_height = 1001;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    e.st.ri.tip = 1002;
    CHECK(step(&e, &o) == AMM_NP_OK && o.confirmed == 1 && swap_is(&e, &s, "refunded"), "P5 a refund settles to refunded");
    amm_attempt_free(&at);
    env_close(&e);

    /* a submit answer is not evidence; another intent id in the block is not either */
    env_open(&e);
    mk_payout(&e, 1, &s);
    sign(&e, &s, 5000000000ULL, &o);
    e.st.submit_rc = 0;                                    /* the node ACCEPTED */
    step(&e, &o);
    CHECK(swap_is(&e, &s, "payout_pending"), "P5 a node 'accepted' does not settle");
    e.st.applied_height = 1001;
    memset(e.st.applied_intent, 0x99, 64);                 /* another transfer's intent id */
    e.st.ri.tip = 1002;
    step(&e, &o);
    CHECK(swap_is(&e, &s, "payout_pending"), "P5 another intent id applied in the block does not settle");
    /* the scan cursor survives a restart */
    attempt(&e, &s, &at);
    uint64_t cur = at.scan_next;
    amm_attempt_free(&at);
    env_reopen(&e);
    e.st.ri.tip = 1004;
    e.st.scan_first = 0;
    step(&e, &o);
    CHECK(cur == 1003 && e.st.scan_first == cur, "P5 after a restart the scan resumes at the stored cursor (1003)");
    env_close(&e);

    /* ── P6 expiry and replacement ───────────────────────────────── */
    env_open(&e);
    mk_refund(&e, &s);
    sign(&e, &s, 7000000000ULL, &o);
    step(&e, &o);
    attempt(&e, &s, &at);
    e.st.ri.tip = 1050;
    CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 0, "P6 tip 1050: not found yet, not expired");
    attempt(&e, &s, &at2);
    CHECK(at2.n == 1 && !strcmp(at2.state, "submitted") && at2.scan_next == 1051, "P6 an open attempt is never replaced (attempt 1, cursor 1051)");
    amm_attempt_free(&at2);
    int calls_before = e.st.submit_calls;
    e.st.ri.tip = 1091;
    CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 1, "P6 tip past the expiry AND every block up to it scanned: expired");
    CHECK(e.st.submit_calls == calls_before, "P6 nothing is submitted past the expiry");
    attempt(&e, &s, &at2);
    CHECK(!strcmp(at2.state, "expired") && at2.n == 1, "P6 attempt 1 is expired");
    amm_attempt_free(&at2);
    CHECK(step(&e, &o) == AMM_NP_OK && o.signed_ == 1, "P6 the next step signs a replacement");
    attempt(&e, &s, &at2);
    CHECK(at2.n == 2 && at2.build_tip == 1091 && at2.expiry == 1181 && at2.scan_next == 1092 && at2.gross == 7000000000ULL &&
          !strcmp(at2.state, "signed"), "P6 attempt 2: built at the new tip, the stored gross, signed");
    CHECK(at2.n_in == at.n_in && has_nul(&at2, at.inputs[0]), "P6 the replacement spends the old attempt's coin (shares an input)");
    CHECK(at2.env_len != at.env_len || memcmp(at2.env, at.env, at.env_len) != 0, "P6 it is another envelope");
    CHECK(e.st.submit_calls == calls_before, "P6 and it was not submitted by the signing");
    amm_attempt_free(&at2);
    amm_attempt_free(&at);
    /* expiry before a block that cannot be read: not expired */
    env_close(&e);

    env_open(&e);
    e.cfg.scan_blocks = 200;                               /* one step may scan up to 200 blocks */
    amm_nodus_pay_free(e.p);
    e.p = amm_nodus_pay_new(&e.cfg);
    mk_payout(&e, 1, &s);
    sign(&e, &s, 5000000000ULL, &o);
    step(&e, &o);
    e.st.ri.tip = 1200;
    e.st.err_height = 1010;                                /* a block that cannot be read completely */
    CHECK(step(&e, &o) == AMM_NP_UNKNOWN && swap_is(&e, &s, "payout_pending"), "P6 a block that cannot be read: unknown, the swap unchanged");
    attempt(&e, &s, &at);
    CHECK(!strcmp(at.state, "submitted") && at.scan_next == 1010, "P6 not expired, the cursor stays BEFORE the unreadable block");
    amm_attempt_free(&at);
    e.st.err_height = 0;
    CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 1, "P6 readable again: scanned through the expiry, then expired");
    /* the old coins are gone: nothing is signed */
    e.st.nat.n = 0;
    add_coin(&e.st.nat, 9, 10000000000000ULL);             /* another coin only */
    CHECK(step(&e, &o) == AMM_NP_FUNDS && strstr(o.msg, "no longer unspent") != NULL, "P6 none of the old coins left: nothing signed, the operator must check");
    attempt(&e, &s, &at);
    CHECK(at.n == 1 && !strcmp(at.state, "expired"), "P6 no new attempt was stored");
    amm_attempt_free(&at);
    env_close(&e);

    /* ── P7 an unreadable answer is never a zero ─────────────────── */
    env_open(&e);
    mk_payout(&e, 1, &s);
    e.st.chain[0] ^= 0xff;                                 /* another chain */
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN && attempt(&e, &s, &at) == 1, "P7 a chain id that does not match: unknown, nothing signed");
    e.st.chain[0] ^= 0xff;
    e.st.chain_rc = AMM_NODE_ERR;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN, "P7 an unreadable chain id: unknown");
    e.st.chain_rc = 0;
    e.st.ri_rc = AMM_NODE_ERR;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN, "P7 an unreadable tip: unknown");
    e.st.ri_rc = 0;
    e.st.gas_rc = AMM_NODE_UNREPORTED;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN && strstr(o.msg, "gas price") != NULL && attempt(&e, &s, &at) == 1,
          "P7 a gas price that is not REPORTED is not the price 0: unknown, nothing signed");
    e.st.gas_rc = AMM_NODE_ERR;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN, "P7 an unreadable gas price: unknown");
    e.st.gas_rc = 0;
    e.st.nat_rc = AMM_NODE_ERR;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN, "P7 an unreadable coin list: unknown, never 'no funds'");
    e.st.nat_rc = AMM_NODE_INCOMPLETE;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_UNKNOWN && strstr(o.msg, "incomplete") != NULL, "P7 a coin list the node did not filter: unknown, 'incomplete'");
    e.st.nat_rc = 0;
    e.st.gas = 0; e.st.gas_rc = 0;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK, "P7 a REPORTED gas price of 0 is a valid price: it signs");
    CHECK(swap_is(&e, &s, "payout_pending"), "P7 the swap is as it was");
    /* the step: chain mismatch and an unreadable tip */
    e.st.chain[0] ^= 0xff;
    CHECK(step(&e, &o) == AMM_NP_UNKNOWN && e.st.submit_calls == 0, "P7 the step on another chain: unknown, nothing submitted");
    e.st.chain[0] ^= 0xff;
    e.st.ri_rc = AMM_NODE_ERR;
    CHECK(step(&e, &o) == AMM_NP_UNKNOWN && e.st.submit_calls == 0, "P7 the step with an unreadable tip: unknown, nothing submitted");
    e.st.ri_rc = 0;
    /* a block the node does not hold */
    e.st.not_held_below = 1002;
    e.st.ri.tip = 1003;
    CHECK(step(&e, &o) == AMM_NP_OK && swap_is(&e, &s, "unknown") && strstr(o.msg, "not held") != NULL,
          "P7 a committed block the node does not hold: the swap is unknown (stops new approvals)");
    amm_swap_t sx;
    CHECK(amm_journal_swap_by_seq(e.j, s.seq, &sx) == 0 && !strcmp(sx.state, "unknown"), "P7 recorded in the journal");
    env_close(&e);

    /* ── P8a the SDK's fee rule, computed independently ──────────── */
    /* The chain requires fee >= max(floor, units x gas_price) (nodus_v2_spend.c:
     * 898-915). The floor is max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE) =
     * max(1000000, 1000000) (dnac.h:160, nodus_types.h:293). `units` is read
     * from the BUILT AND SIGNED envelope itself (nodus_v2_spend_decode:
     * res_max_total_units), not from the planner. Arithmetic, cross-checked
     * with python3 integer arithmetic on sample values: units 7, gas 100000 ->
     * max(1000000, 700000) = 1000000 (the floor wins); units 213456, gas 100000
     * -> 21345600000; units 11, gas 100000 -> 1100000. */
    {
        const uint64_t FLOOR = 1000000ULL, GAS = 100000ULL, GR = 9000000000ULL;
        uint64_t units0 = 0, unitsG = 0, fee0 = 0, feeG = 0;
        for (int gi = 0; gi < 2; gi++) {
            env_open(&e);
            e.st.gas = gi ? GAS : 0;
            CHECK(mk_payout(&e, 1, &s) && sign(&e, &s, GR, &o) == AMM_NP_OK, "P8a setup: a payout is signed");
            attempt(&e, &s, &at);
            nodus_v2_spend_decode(at.env, at.env_len, &d);
            uint64_t want = d.units * e.st.gas;
            if (want < FLOOR) want = FLOOR;
            CHECK(d.fee == want, gi ? "P8a gas 100000: fee == max(floor, units x gas), units from the envelope"
                                    : "P8a gas 0: fee == the floor");
            CHECK(d.out_amount[0] + d.fee == GR, "P8a the recipient gets gross - that fee");
            if (gi) { unitsG = d.units; feeG = d.fee; } else { units0 = d.units; fee0 = d.fee; }
            amm_attempt_free(&at);
            env_close(&e);
        }
        CHECK(units0 == unitsG && units0 * GAS > FLOOR, "P8a the same shape has the same units, and units x 100000 is above the floor");
        CHECK(feeG != fee0 && feeG > fee0, "P8a a nonzero gas price CHANGES the fee (it is honoured)");

        /* the exactly-funded case: ONE coin equal to gross, no change output.
         * The fee needed by THAT shape (1 in, 1 out) is again max(floor, units x gas)
         * with the units of the built envelope. */
        env_open(&e);
        e.st.gas = GAS;
        e.st.nat.n = 0;
        add_coin(&e.st.nat, 70, GR);
        CHECK(mk_payout(&e, 1, &s) && sign(&e, &s, GR, &o) == AMM_NP_OK,
              "P8a a coin exactly equal to gross funds gross - required fee plus the required fee");
        attempt(&e, &s, &at);
        nodus_v2_spend_decode(at.env, at.env_len, &d);
        uint64_t want = d.units * GAS;
        if (want < FLOOR) want = FLOOR;
        CHECK(d.n_in == 1 && d.n_out == 1 && d.fee == want && d.out_amount[0] + d.fee == GR && at.net == d.out_amount[0],
              "P8a one input, no change, fee == max(floor, units x gas), recipient + fee == gross");
        CHECK(d.fee > FLOOR, "P8a (the fee is above the floor: the old fee-raising plan would have refused this coin)");
        amm_attempt_free(&at);
        env_close(&e);
    }

    /* ── P8b a zero REPLACEMENT refund is dropped; a payout that falls below its minimum takes the refund path ── */
    env_open(&e);
    e.cfg.scan_blocks = 200;
    amm_nodus_pay_free(e.p);
    e.p = amm_nodus_pay_new(&e.cfg);
    mk_refund(&e, &s);
    CHECK(sign(&e, &s, 1000500ULL, &o) == AMM_NP_OK, "P8b a refund of floor + 500 signs at gas 0 (net 500)");
    step(&e, &o);
    e.st.ri.tip = 1091;
    CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 1, "P8b the attempt expires");
    e.st.gas = 100000;                                      /* the fee now exceeds the amount */
    CHECK(step(&e, &o) == AMM_NP_ZERO && swap_is(&e, &s, "dropped") && attempt(&e, &s, &at2) == 0 && at2.n == 1,
          "P8b the zero replacement refund is DROPPED (givens items 89, 90), like a first attempt; no attempt 2 is stored");
    amm_attempt_free(&at2);
    CHECK(step(&e, &o) == AMM_NP_OK && o.worked == 0, "P8b it is not retried: the dropped swap is no longer the head");
    env_close(&e);

    env_open(&e);
    e.cfg.scan_blocks = 200;
    amm_nodus_pay_free(e.p);
    e.p = amm_nodus_pay_new(&e.cfg);
    mk_payout(&e, 9000000000000ULL - 1000000ULL, &s);       /* minimum = gross - floor: just met at gas 0 */
    CHECK(sign(&e, &s, 9000000000000ULL, &o) == AMM_NP_OK, "P8b a payout whose net equals its minimum signs at gas 0");
    step(&e, &o);
    e.st.ri.tip = 1091;
    CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 1, "P8b the attempt expires");
    e.st.gas = 100000;                                      /* the fee rose: net is now below the minimum */
    CHECK(step(&e, &o) == AMM_NP_UNKNOWN && swap_is(&e, &s, "payout_pending") && attempt(&e, &s, &at2) == 0 && at2.n == 1,
          "P8b after the fee rise the replacement would need another fee than the decided one: NOT BUILT "
          "(givens item 97), nothing signed, the decided payout stays payout_pending (no turn into a refund)");
    amm_attempt_free(&at2);
    CHECK(step(&e, &o) == AMM_NP_UNKNOWN && o.worked == 0 && swap_is(&e, &s, "payout_pending"),
          "P8b it is retried each step and never replaced at another fee");
    env_close(&e);

    /* ── P8 fee at, below and above the amount ───────────────────── */
    static const uint64_t gases[2] = {0, 100000};      /* rule off; a price that lifts the fee */
    for (int gi = 0; gi < 2; gi++) {
        char lab[96];
        env_open(&e);
        e.st.gas = gases[gi];
        uint64_t F = fee_of(&e, 9000000000000ULL);
        snprintf(lab, sizeof(lab), "P8 gas %llu: the quoted fee is above zero and at least the floor", (unsigned long long)gases[gi]);
        CHECK(F >= 1000000ULL, lab);
        /* a refund */
        CHECK(mk_refund(&e, &s), "P8 setup: a refund");
        snprintf(lab, sizeof(lab), "P8 gas %llu: refund of fee + 1: signs (net 1)", (unsigned long long)gases[gi]);
        CHECK(sign(&e, &s, F + 1, &o) == AMM_NP_OK, lab);
        attempt(&e, &s, &at);
        nodus_v2_spend_decode(at.env, at.env_len, &d);
        CHECK(d.out_amount[0] == 1 && d.fee == F, "P8 the recipient gets 1 raw, the chain gets the fee");
        amm_attempt_free(&at);
        CHECK(mk_refund(&e, &s2), "P8 setup: a second refund");
        /* the first swap's attempt is open: none of the signs below may STORE an
         * attempt (the journal allows one payout in flight, P13) -- each ends in
         * zero, dropped or below the minimum, before anything is stored */
        snprintf(lab, sizeof(lab), "P8 gas %llu: refund of exactly the fee: zero, DROPPED, nothing signed", (unsigned long long)gases[gi]);
        calls_before = e.st.submit_calls;
        CHECK(sign(&e, &s2, F, &o) == AMM_NP_ZERO && swap_is(&e, &s2, "dropped") && attempt(&e, &s2, &at) == 1, lab);
        CHECK(mk_refund(&e, &s2), "P8 setup: a third refund");
        snprintf(lab, sizeof(lab), "P8 gas %llu: refund of less than the fee: zero (no wrap), DROPPED", (unsigned long long)gases[gi]);
        CHECK(sign(&e, &s2, F - 1, &o) == AMM_NP_ZERO && swap_is(&e, &s2, "dropped") && attempt(&e, &s2, &at) == 1, lab);
        CHECK(mk_refund(&e, &s2), "P8 setup");
        CHECK(sign(&e, &s2, 1, &o) == AMM_NP_ZERO && swap_is(&e, &s2, "dropped"), "P8 refund of 1 raw: dropped");
        CHECK(e.st.submit_calls == calls_before, "P8 nothing was broadcast");
        /* a payout: zero is never signed; the swap takes the refund path (plan line 226) */
        CHECK(mk_payout(&e, 0, &s2), "P8 setup: a payout with minimum 0");
        snprintf(lab, sizeof(lab), "P8 gas %llu: payout of exactly the fee: ZERO, nothing signed, swap not moved", (unsigned long long)gases[gi]);
        CHECK(sign(&e, &s2, F, &o) == AMM_NP_ZERO && swap_is(&e, &s2, "payout_pending") && attempt(&e, &s2, &at) == 1, lab);
        CHECK(mk_payout(&e, 0, &s2), "P8 setup: another payout");
        CHECK(sign(&e, &s2, F - 1, &o) == AMM_NP_ZERO && swap_is(&e, &s2, "payout_pending") && attempt(&e, &s2, &at) == 1,
              "P8 payout of less than the fee: zero, nothing signed, the swap not moved");
        CHECK(amm_nodus_pay_quote(e.p, F, 0, (amm_np_quote_t[1]){{0}}) == AMM_NP_ZERO, "P8 the quote says zero for fee == amount");
        amm_np_quote_t q;
        CHECK(amm_nodus_pay_quote(e.p, F + 5, 0, &q) == AMM_NP_OK && q.net == 5 && q.fee == F && q.n_in == 1, "P8 the quote for fee + 5: net 5");
        env_close(&e);
    }

    /* ── P9 the minimum after the fee ────────────────────────────── */
    env_open(&e);
    uint64_t F0 = fee_of(&e, 9000000000000ULL);
    const uint64_t G = 5000000000ULL;
    CHECK(mk_payout(&e, G - F0, &s), "P9 setup: minimum = gross - fee");
    CHECK(sign(&e, &s, G, &o) == AMM_NP_OK, "P9 net == minimum: signs");
    attempt(&e, &s, &at);
    nodus_v2_spend_decode(at.env, at.env_len, &d);
    CHECK(d.out_amount[0] == G - F0, "P9 the recipient gets exactly the minimum");
    amm_attempt_free(&at);
    env_close(&e);
    env_open(&e);
    CHECK(mk_payout(&e, G - F0 + 1, &s), "P9 setup: minimum = gross - fee + 1 (the gross G satisfies it)");
    CHECK(sign(&e, &s, G, &o) == AMM_NP_BELOW_MIN && swap_is(&e, &s, "payout_pending") && attempt(&e, &s, &at) == 1 &&
          strstr(o.msg, "below the minimum") != NULL,
          "P9 net == minimum - 1: refused, nothing signed, the verdict is returned (minimum compared after the fee); the engine refunds");
    CHECK(e.st.submit_calls == 0, "P9 nothing broadcast");
    CHECK(mk_refund(&e, &s2), "P9 setup: a refund has no minimum");
    env_close(&e);

    /* ── P10 1..15 inputs, no coin joining ───────────────────────── */
    env_open(&e);
    e.st.nat.n = 0;
    for (int k = 0; k < 20; k++) add_coin(&e.st.nat, 20 + k, 10000000ULL);   /* 20 coins of 0.1 NODUS */
    mk_payout(&e, 0, &s);
    CHECK(sign(&e, &s, 150000000ULL, &o) == AMM_NP_OK, "P10 a payout needing exactly 15 coins is signed");
    attempt(&e, &s, &at);
    nodus_v2_spend_decode(at.env, at.env_len, &d);
    CHECK(at.n_in == 15 && d.n_in == 15 && d.n_out == 1, "P10 15 inputs, no change output");
    amm_attempt_free(&at);
    env_close(&e);
    env_open(&e);
    e.st.nat.n = 0;
    for (int k = 0; k < 20; k++) add_coin(&e.st.nat, 20 + k, 10000000ULL);
    mk_payout(&e, 0, &s);
    CHECK(sign(&e, &s, 150000001ULL, &o) == AMM_NP_FUNDS && strstr(o.msg, "more than 15") != NULL && attempt(&e, &s, &at) == 1,
          "P10 a payout needing 16 coins is refused (the operator must consolidate), nothing signed");
    env_close(&e);
    env_open(&e);
    e.st.nat.n = 0;
    add_coin(&e.st.nat, 40, 10000000000ULL);
    for (int k = 0; k < 5; k++) add_coin(&e.st.nat, 41 + k, 5000000ULL);    /* dust the payout does not need */
    mk_payout(&e, 0, &s);
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK, "P10 setup: a payout one big coin covers");
    attempt(&e, &s, &at);
    CHECK(at.n_in == 1, "P10 the small coins are NOT swept in (coin joining is deferred)");
    amm_attempt_free(&at);
    env_close(&e);
    env_open(&e);
    mk_payout(&e, 0, &s);
    e.st.nat.n = 0;
    add_coin(&e.st.nat, 50, 1000000000ULL);
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_FUNDS && strstr(o.msg, "cannot cover") != NULL && attempt(&e, &s, &at) == 1,
          "P10 funds short: AMM_NP_FUNDS, nothing signed");
    e.st.nat.truncated = 1;
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_FUNDS && strstr(o.msg, "incomplete") != NULL,
          "P10 a listing that filled the node's cap says 'incomplete', never 'funding short'");
    e.st.nat.n = 0;
    e.st.nat.truncated = 0;
    add_coin(&e.st.nat, 51, 10000000000000ULL);
    e.st.nat.c[0].unlock_block = 5000;                     /* locked */
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_FUNDS, "P10 a coin that is still locked is not spendable");
    env_close(&e);

    /* ── P11 payouts_paused ──────────────────────────────────────── */
    env_open(&e);
    e.cfg.payouts_paused = 1;
    amm_nodus_pay_free(e.p);
    e.p = amm_nodus_pay_new(&e.cfg);
    mk_payout(&e, 1, &s);
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_PAUSED && attempt(&e, &s, &at) == 1, "P11 paused: nothing is signed");
    CHECK(step(&e, &o) == AMM_NP_NEED_SIGN && e.st.submit_calls == 0, "P11 paused: the step has nothing to broadcast");
    e.cfg.payouts_paused = 0;
    amm_nodus_pay_free(e.p);
    e.p = amm_nodus_pay_new(&e.cfg);
    sign(&e, &s, 5000000000ULL, &o);
    attempt(&e, &s, &at);
    e.cfg.payouts_paused = 1;
    amm_nodus_pay_free(e.p);
    e.p = amm_nodus_pay_new(&e.cfg);
    e.st.ri.tip = 1002;
    CHECK(step(&e, &o) == AMM_NP_OK && e.st.submit_calls == 0, "P11 paused: a signed attempt is not broadcast");
    attempt(&e, &s, &at2);
    CHECK(at2.scan_next == 1003 && !strcmp(at2.state, "signed"), "P11 ... but the settlement scan continues");
    amm_attempt_free(&at2);
    e.st.applied_height = 1003;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    e.st.ri.tip = 1003;
    CHECK(step(&e, &o) == AMM_NP_OK && o.confirmed == 1 && swap_is(&e, &s, "paid"), "P11 ... and settles a payout found on chain");
    amm_attempt_free(&at);
    env_close(&e);

    /* ── P12 the journal's guards ────────────────────────────────── */
    env_open(&e);
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    char es[41], ed[129];
    memset(es, 'a', 40); es[40] = '\0'; dest_hex(ed);
    a.dir = AMM_USDT_TO_NODUS; a.sender = es; a.dest = ed; a.amount = 1; a.minimum = 1; a.value_usdt = 1;
    a.approved_at = 1; a.expiry = 100; a.approved_tip = 1; a.incoming_id = "";
    a.req_no[31] = 1; a.rand16[0] = 1; a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    amm_swap_t ap;
    CHECK(amm_journal_approve(e.j, &a, &ap) == AMM_J_OK, "P12 setup: an approved swap");
    CHECK(sign(&e, &ap, 5000000000ULL, &o) == AMM_NP_ERR, "P12 a swap that owes no payout is refused");
    CHECK(mk_payout(&e, 1, &s) && sign(&e, &s, 0, &o) == AMM_NP_ERR, "P12 a zero gross is refused");
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK && sign(&e, &s, 5000000000ULL, &o) == AMM_NP_ERR,
          "P12 a second first-sign is refused (a replacement is the step's, after the expiry)");
    attempt(&e, &s, &at);
    CHECK(at.n == 1, "P12 still attempt 1");
    amm_attempt_free(&at);
    CHECK(sign(&e, &s, 5000000000ULL, &o) == AMM_NP_ERR && sign(&e, &(amm_swap_t){.seq = 9999}, 100, &o) == AMM_NP_ERR,
          "P12 an unknown swap is refused");
    env_close(&e);

    /* ── P13 one payout in flight ────────────────────────────────── */
    env_open(&e);
    mk_payout(&e, 1, &s);
    mk_payout(&e, 1, &s2);
    CHECK(step(&e, &o) == AMM_NP_NEED_SIGN && o.swap_seq == s.seq, "P13 the head is the oldest swap; it needs a sign first");
    sign(&e, &s, 5000000000ULL, &o);
    step(&e, &o);
    attempt(&e, &s, &at);
    e.st.applied_height = 1001;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    e.st.ri.tip = 1002;
    amm_attempt_free(&at);
    CHECK(attempt(&e, &s2, &at2) == 1, "P13 the second swap has no attempt while the first is open");
    CHECK(sign(&e, &s2, 5000000000ULL, &o) == AMM_NP_BUSY && attempt(&e, &s2, &at2) == 1,
          "P13 a second swap cannot be signed while the first attempt is open (the same coin would be spent twice)");
    step(&e, &o);
    CHECK(swap_is(&e, &s, "paid"), "P13 the first is paid");
    CHECK(step(&e, &o) == AMM_NP_NEED_SIGN && o.swap_seq == s2.seq, "P13 then the second is the head and needs its sign");
    CHECK(sign(&e, &s2, 5000000000ULL, &o) == AMM_NP_OK, "P13 once the first is settled the second signs");
    env_close(&e);

    /* ── P13b head selection (revision 12 correction, claim 2) ─────────
     * PROVES: an OLDER NODUS refund_pending swap with no attempt does not hold the
     * payer back while a YOUNGER USDT -> NODUS swap's decided attempt is open: the
     * step drives the younger stored attempt (submit, then settlement) and only then
     * asks for the refund's sign. With oldest-first head selection the step would
     * return NEED_SIGN for the refund, the refund's sign would be refused (BUSY,
     * another attempt open) and the younger attempt would never settle.
     * FALSE PASS: the scripted node applies the intent at the height the test sets; the
     * younger attempt is stored by the test's sign() helper (as the decision stores it),
     * so the decision transaction itself is test_amm_journal J27. */
    env_open(&e);
    CHECK(mk_refund(&e, &s) && mk_payout(&e, 1, &s2), "P13b setup: an older refund, a younger payout");
    CHECK(s.seq < s2.seq && sign(&e, &s2, 5000000000ULL, &o) == AMM_NP_OK && attempt(&e, &s, &at2) == 1,
          "P13b the younger payout's decided attempt is stored; the older refund has none");
    CHECK(step(&e, &o) == AMM_NP_OK && o.swap_seq == s2.seq && o.submitted == 1,
          "P13b the step drives the YOUNGER swap's open attempt (not NEED_SIGN for the older refund)");
    attempt(&e, &s2, &at);
    e.st.applied_height = 1001;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    e.st.ri.tip = 1002;
    amm_attempt_free(&at);
    CHECK(step(&e, &o) == AMM_NP_OK && swap_is(&e, &s2, "paid"), "P13b the younger payout settles: paid");
    CHECK(step(&e, &o) == AMM_NP_NEED_SIGN && o.swap_seq == s.seq,
          "P13b then the older refund is the head and needs its sign");
    CHECK(sign(&e, &s, 1000ULL + 20000000ULL, &o) != AMM_NP_BUSY, "P13b and its sign is no longer refused as busy");
    env_close(&e);

    /* ── P15 the coins of an expired payout are reserved ──────────────
     * PROVES (faucet pattern, faucet_core.c:556-568; red team finding 1): while a
     * swap that still owes a NODUS payout has an EXPIRED latest attempt, no other
     * plan uses that attempt's input coins: not a payout planned in the decision
     * (amm_nodus_pay_prepare), not a refund's first attempt (amm_nodus_pay_sign),
     * and a quote (amm_nodus_pay_quote) answers the same as a decision would see.
     * The expired swap's own replacement still uses them and shares an input with
     * the expired attempt. The reservation is read from the journal: a fresh payer
     * over a reopened journal file excludes the same coins; it ends when the swap
     * leaves the owed states (here: unknown). A replacement that cannot be stored
     * is reported (`waiting`), nothing stored.
     * BUILD FLAGS / ENVIRONMENT: a default build; one mkdtemp directory under /tmp
     * (removed); no network; the node is the scripted stub (coin 1 = 10^13 raw,
     * coin 2 = 5*10^12 raw; the planner takes the LARGEST coin first, so the first
     * payout of 5*10^9 spends coin 1).
     * LEAVES BEHIND: nothing.
     * FALSE PASS: the stub lists coins by script, not as a real node's unspent set;
     * the "unreadable read" is a scripted error answer. The coin that a later plan
     * would take is the planner's largest-first choice: if the planner's order
     * changed, the "would have taken coin 1" premise would no longer hold (the
     * negative control is the replacement, which MUST take coin 1 although coin 2
     * exists: it shares an input only because it plans over the expired coins). */
    {
        uint8_t c1[64], c2[64];
        coin_nul(1, c1);
        coin_nul(2, c2);
        amm_np_quote_t qq;
        amm_np_prepared_t pre;
        env_open(&e);
        e.cfg.scan_blocks = 200;
        amm_nodus_pay_free(e.p);
        e.p = amm_nodus_pay_new(&e.cfg);
        add_coin(&e.st.nat, 2, 5000000000000ULL);
        CHECK(mk_payout(&e, 1, &s) && sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK, "P15 setup: swap P signs its payout");
        attempt(&e, &s, &at);
        CHECK(has_nul(&at, c1) && !has_nul(&at, c2), "P15 premise: the first payout spends the largest coin (coin 1)");
        amm_attempt_free(&at);
        step(&e, &o);
        e.st.ri.tip = 1091;
        CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 1, "P15 P's attempt expires");
        e.st.nat_rc = AMM_NODE_ERR;                         /* the replacement's read fails once */
        CHECK(step(&e, &o) == AMM_NP_UNKNOWN && o.waiting == 1 && o.worked == 0 && o.signed_ == 0 &&
              attempt(&e, &s, &at2) == 0 && at2.n == 1,
              "P15 (b) the replacement cannot be stored (unreadable coins): reported as waiting, no attempt 2");
        amm_attempt_free(&at2);
        e.st.nat_rc = 0;

        /* (b) a payout decided meanwhile does not take coin 1 */
        CHECK(mk_payout(&e, 1, &s2), "P15 setup: a second USDT -> NODUS swap");
        CHECK(amm_nodus_pay_prepare(e.p, dst, 5000000000ULL, 1, 0, &pre) == AMM_NP_OK &&
              !has_nul(&pre.attempt, c1) && has_nul(&pre.attempt, c2),
              "P15 (b) a new payout is planned over coin 2 only: the expired attempt's coin 1 is not used");
        amm_np_prepared_free(&pre);
        CHECK(amm_nodus_pay_quote(e.p, 7000000000000ULL, 0, &qq) == AMM_NP_FUNDS,
              "P15 a quote of 7*10^12 raw is short (coin 1 is reserved, coin 2 holds 5*10^12), as a decision sees it");
        CHECK(amm_nodus_pay_quote(e.p, 5000000000ULL, 0, &qq) == AMM_NP_OK && qq.n_in == 1,
              "P15 a quote of 5*10^9 is funded from coin 2");

        /* (c) restart: a fresh journal handle and payer over the same file */
        env_reopen(&e);
        CHECK(amm_nodus_pay_quote(e.p, 7000000000000ULL, 0, &qq) == AMM_NP_FUNDS,
              "P15 (c) after a restart the quote still treats coin 1 as reserved");
        CHECK(amm_nodus_pay_prepare(e.p, dst, 5000000000ULL, 1, 0, &pre) == AMM_NP_OK &&
              !has_nul(&pre.attempt, c1) && has_nul(&pre.attempt, c2),
              "P15 (c) after a restart a new payout still does not use coin 1");
        amm_np_prepared_free(&pre);

        /* (b) the read recovers: the replacement is stored and shares an input */
        CHECK(step(&e, &o) == AMM_NP_OK && o.signed_ == 1 && o.waiting == 0,
              "P15 (b) when the read recovers the replacement is stored");
        CHECK(attempt(&e, &s, &at) == 0 && at.n == 2 && has_nul(&at, c1),
              "P15 (b) attempt 2 spends coin 1: it shares an input with the expired attempt");
        amm_attempt_free(&at);
        env_close(&e);

        /* a refund's first attempt avoids the reserved coin; the reservation ends when the swap leaves the owed states */
        env_open(&e);
        e.cfg.scan_blocks = 200;
        amm_nodus_pay_free(e.p);
        e.p = amm_nodus_pay_new(&e.cfg);
        add_coin(&e.st.nat, 2, 5000000000000ULL);
        CHECK(mk_payout(&e, 1, &s) && sign(&e, &s, 5000000000ULL, &o) == AMM_NP_OK, "P15 setup: swap P signs its payout");
        step(&e, &o);
        e.st.ri.tip = 1091;
        CHECK(step(&e, &o) == AMM_NP_OK && o.expired == 1, "P15 P's attempt expires");
        CHECK(mk_refund(&e, &s2) && sign(&e, &s2, 2000000000ULL, &o) == AMM_NP_OK, "P15 a refund of another swap signs");
        attempt(&e, &s2, &at);
        CHECK(!has_nul(&at, c1) && has_nul(&at, c2),
              "P15 the refund's first attempt does not use the expired payout's coin 1");
        amm_attempt_free(&at);
        CHECK(amm_nodus_pay_quote(e.p, 7000000000000ULL, 0, &qq) == AMM_NP_FUNDS,
              "P15 coin 1 is still reserved: a quote of 7*10^12 is short");
        CHECK(amm_journal_swap_transition(e.j, s.seq, AMM_S_UNKNOWN, NULL, NULL, NULL) == 0 &&
              amm_nodus_pay_quote(e.p, 7000000000000ULL, 0, &qq) == AMM_NP_OK && qq.n_in == 1,
              "P15 P left the owed states (unknown): coin 1 is released, the quote is funded again");
        env_close(&e);
    }

    /* ── P14 configuration ───────────────────────────────────────── */
    env_open(&e);
    amm_nodus_pay_cfg_t c = e.cfg;
    amm_nodus_pay_t *pp = amm_nodus_pay_new(&c);
    CHECK(pp != NULL && strlen(amm_nodus_pay_self(pp)) == 128, "P14 a valid configuration builds; the bot's address is 128 hex");
    amm_nodus_pay_free(pp);
    c = e.cfg; c.expiry_ahead = 0;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 expiry_ahead 0: refused");
    c = e.cfg; c.expiry_ahead = 101;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 expiry_ahead 101 (above the chain's 100): refused");
    c = e.cfg; c.expiry_ahead = 100;
    pp = amm_nodus_pay_new(&c);
    CHECK(pp != NULL, "P14 expiry_ahead 100: accepted");
    amm_nodus_pay_free(pp);
    c = e.cfg; c.resubmit_blocks = 0;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 a zero resubmit bound: refused");
    c = e.cfg; c.scan_blocks = 0;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 a zero scan bound: refused");
    c = e.cfg; c.rand = NULL;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 no randomness source: refused");
    c = e.cfg; c.sk = NULL;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 no key: refused");
    c = e.cfg; c.journal = NULL;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 no journal: refused");
    amm_node_t vt = e.vt;
    vt.submit = NULL;
    c = e.cfg; c.node = &vt;
    CHECK(amm_nodus_pay_new(&c) == NULL, "P14 a missing seam function: refused");
    env_close(&e);

    free(g_id);
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
