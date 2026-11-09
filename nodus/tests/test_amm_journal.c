/**
 * test_amm_journal.c -- the nodus-amm journal (SQLite, WAL, FULL).
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 19 "test_amm_journal": legal transitions only; restart from every
 * state; permanent markers survive; sections 7 step 4, 9, 13, 17; givens
 * items 31, 54, 55, 57, 59):
 *   J1  an approval writes the row (state approved), the request-number
 *       marker and its in-flight value together; fields read back exactly;
 *   J2  every approval refusal writes NOTHING and consumes NO request
 *       number: paused (settings flag), stopped (a swap in unknown), request
 *       number reused, an open approval with the same sender and amount (the
 *       refusal returns THAT swap, item 57; the same sender with another
 *       amount is accepted), per-swap limit, in-flight total; the same
 *       request number is accepted once the refusal reason is gone; a field
 *       outside its format is AMM_J_RANGE;
 *   J3  the legal state graph: the whole success path and each refund /
 *       held / unknown / expired branch; illegal moves (skipping a state,
 *       moving back, leaving a terminal state, targeting approved or
 *       reversed directly) return AMM_J_ILLEGAL and change nothing;
 *   J4  the incoming-transfer marker is written when the payment counts and
 *       is permanent: a second swap naming the same incoming id is refused
 *       (AMM_J_DUP_TRANSFER) with its row, the marker count and the pool
 *       unchanged; marker and request-number markers survive a reopen;
 *   J5  the in-flight sum is computed from rows: approved, paid_waiting_depth,
 *       counted, payout_pending and refund_pending hold room, paid, refunded,
 *       expired, unknown, reversed do not; `held` holds room only when the
 *       setting held_keeps_room is 1 (both values tested through the sum and
 *       through an approval at the 500 limit; the plan defers the question,
 *       plan lines 312, 407); finishing a swap frees room for a new approval;
 *   J6  the ledger reserves round-trip as 32-byte blobs and a transition that
 *       carries a pool writes both or neither;
 *   J7  RESTART FROM EVERY STATE: one swap in each of the eleven states, the
 *       journal closed and reopened, every swap reads back in its state and
 *       the next legal move works;
 *   J8  amm_journal_payment_gone: a payment waiting for its depth -> record
 *       dropped, swap approved again with its incoming id cleared; a counted
 *       / payout_pending / paid / refund_pending / refunded / HELD / UNKNOWN
 *       payment (a payment that was counted, givens item 55) -> record
 *       and swap reversed and the reversal pause set; a record no swap
 *       carries, or an expired swap -> dropped; the pause survives a reopen and refuses new
 *       approvals even with the settings flag off (there is no clear call);
 *       an already dropped record is refused;
 *   J9  one outer transaction: a hook that fails the commit leaves the swap,
 *       the record, the pause flag and the cursor exactly as before (checked
 *       after a REOPEN, the restart between decision and write); the same
 *       writes commit without the hook; a refusal inside the transaction does
 *       not poison it; tx_rollback undoes the writes;
 *   J10 cursors move forward only (equal and lower refused), reset sets any
 *       value, all survive a reopen;
 *   J11 blocks: replace by height, delete from a height, prune below,
 *       block_after_ts (lowest height above a timestamp, bounded by
 *       max_height);
 *   J12 records: the record state table (candidate -> seen -> deep -> held,
 *       the dropped / reversed ends, a new record only as candidate or seen),
 *       listing order (block, tx, log index) with the cap as a fault, the
 *       candidate-exists query;
 *   J16 ONE LIVE RECORD PER TRANSACTION: a second live record of a
 *       transaction (another log index) is refused; a quorum (seen) record
 *       displaces a false candidate of the same transaction and the dropped
 *       candidate cannot be revived beside it; a dropped record is revived
 *       only when no other record of the transaction is live (successive
 *       reorganisations); the candidate-exists query counts only candidates
 *       whose block time is within the approval's validity or unknown
 *       (block_ts 96 <= 100 blocks, 108 does not, 0 blocks);
 *   J17 incoming transfer ids: full-length "nodus:" + 128 hex ids (wire id
 *       and intent id, 64 bytes each, nodus_v2_spend.h:448-449) are stored,
 *       found, counted with a marker and survive a reopen; an id longer than
 *       the capacity is refused; the Ethereum key is "eth:" + the 64-hex
 *       transaction hash alone;
 *   J13 a row that does not read back (a pool blob of the wrong length, a
 *       swap with a malformed address) fails the read with -1, never an
 *       empty value;
 *   J14 the database is in WAL mode (read by a second connection);
 *   J15 the Nodus seam header amm_node.h compiles and a stub table is
 *       callable (a unit-level compile and call check of the seam; no
 *       consumer exists in this package).
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp,
 *   removed at the end; no network.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: single process, no crash injection: durability across a
 *   real power cut (synchronous=FULL) is SQLite's property, not shown here
 *   (the setting is applied by amm_journal_open and not readable from outside,
 *   so it is not asserted); the "restart" is a close and reopen of the same
 *   file. The commit failure is simulated by the test-only pre-commit hook,
 *   which proves the rollback path, not an operating-system fault. J13
 *   damages rows through a second connection; a failing bind cannot be forced
 *   (every bind is checked by construction).
 */
#include <dirent.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_journal.h"
#include "amm_node.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static char g_dir[64];
static char g_path[128];
static amm_journal_t *g_j;

static void cleanup_dir(void) {
    DIR *d = opendir(g_dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", g_dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(g_dir);
}

/* A fresh journal file. */
static void fresh(void) {
    if (g_j) { amm_journal_close(g_j); g_j = NULL; }
    unlink(g_path);
    char p[160];
    snprintf(p, sizeof(p), "%s-wal", g_path); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", g_path); unlink(p);
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL open\n"); exit(2); }
}

static void reopen(void) {
    amm_journal_close(g_j);
    g_j = NULL;
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL reopen\n"); exit(2); }
}

/* ── fixtures ───────────────────────────────────────────────────────── */

static uint64_t g_ctr = 1;

/* An approval, USDT -> NODUS, sender 40 x `c`, with a fresh request number
 * and a fresh swap id. The sender text lives in a ring of buffers so that
 * several approvals built before they are used keep their own sender. */
static amm_approve_t mk(char c, uint64_t amount, uint64_t v) {
    static char ring[512][41];
    static unsigned ri = 0;
    static char d[129];
    char *s = ring[ri++ % 512];
    memset(s, c, 40); s[40] = '\0';
    memset(d, 'e', 128); d[128] = '\0';
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    a.dir = AMM_USDT_TO_NODUS;
    a.sender = s; a.dest = d;
    a.amount = amount; a.minimum = 1; a.value_usdt = v;
    a.approved_at = 1000; a.expiry = 2800;
    a.incoming_id = "";
    uint64_t n = g_ctr++;
    for (int i = 0; i < 8; i++) a.req_no[31 - i] = (uint8_t)(n >> (8 * i));
    for (int i = 0; i < 16; i++) a.rand16[i] = (uint8_t)(n * 31 + i);
    a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    a.swaps_paused_cfg = 0;
    return a;
}

static int approve_ok(amm_approve_t *a, amm_swap_t *out) {
    return amm_journal_approve(g_j, a, out) == AMM_J_OK;
}

static int state_is(const amm_swap_t *s, const char *st) { return !strcmp(s->state, st); }

static int tr(int64_t seq, const char *to, const char *inc) {
    return amm_journal_swap_transition(g_j, seq, to, inc, NULL, NULL);
}

static int swap_state(const char *id, char *out) {
    amm_swap_t s;
    if (amm_journal_swap_get(g_j, id, &s) != 0) return -1;
    strcpy(out, s.state);
    return 0;
}

/* Drive a fresh swap (from c) to `target` along the legal graph. */
static int drive(amm_swap_t *s, const char *target, const char *inc) {
    const char *i = inc ? inc : "nodus:aa";
    if (!strcmp(target, "approved")) return 1;
    if (!strcmp(target, "expired")) return tr(s->seq, "expired", NULL) == 0;
    if (tr(s->seq, "paid_waiting_depth", i) != 0) return 0;
    if (!strcmp(target, "paid_waiting_depth")) return 1;
    if (tr(s->seq, "counted", NULL) != 0) return 0;
    if (!strcmp(target, "counted")) return 1;
    if (!strcmp(target, "payout_pending") || !strcmp(target, "paid") ||
        !strcmp(target, "unknown")) {
        if (tr(s->seq, "payout_pending", NULL) != 0) return 0;
        if (!strcmp(target, "payout_pending")) return 1;
        return tr(s->seq, target, NULL) == 0;
    }
    if (tr(s->seq, "refund_pending", NULL) != 0) return 0;
    if (!strcmp(target, "refund_pending")) return 1;
    if (!strcmp(target, "unknown_refund")) return tr(s->seq, "unknown", NULL) == 0;
    return tr(s->seq, target, NULL) == 0;      /* refunded | held */
}

static int swap_count_rows(void) {
    int tot = 0, n;
    static const char *st[] = {"approved","paid_waiting_depth","counted",
        "payout_pending","paid","refund_pending","refunded","expired","held",
        "reversed","unknown"};
    for (size_t i = 0; i < sizeof(st) / sizeof(st[0]); i++) {
        if (amm_journal_state_count(g_j, st[i], &n) != 0) return -1;
        tot += n;
    }
    return tot;
}

static void j1_approve(void) {
    printf("J1 approval\n");
    fresh();
    amm_approve_t a = mk('a', 50000000ULL, 50000000ULL);
    a.minimum = 123; a.incoming_id = "nodus:beef";
    amm_swap_t s;
    CHECK(amm_journal_approve(g_j, &a, &s) == AMM_J_OK, "approved");
    CHECK(state_is(&s, "approved") && s.dir == AMM_USDT_TO_NODUS &&
          s.amount == 50000000ULL && s.minimum == 123 &&
          s.value_usdt == 50000000ULL && s.approved_at == 1000 &&
          s.expiry == 2800 && !strcmp(s.incoming_id, "nodus:beef") &&
          strlen(s.id) == 32 && !strcmp(s.sender, a.sender) &&
          !strcmp(s.dest, a.dest), "fields written as given");
    amm_swap_t g;
    CHECK(amm_journal_swap_get(g_j, s.id, &g) == 0 && g.seq == s.seq, "read back by id");
    CHECK(amm_journal_swap_by_seq(g_j, s.seq, &g) == 0 && !strcmp(g.id, s.id), "by seq");
    CHECK(amm_journal_swap_by_incoming(g_j, "nodus:beef", &g) == 0 && g.seq == s.seq,
          "by incoming id");
    CHECK(amm_journal_swap_get(g_j, "00000000000000000000000000000000", &g) == 1, "unknown id: none");
    uint64_t sum = 0;
    CHECK(amm_journal_inflight_sum(g_j, 0, &sum) == 0 && sum == 50000000ULL, "in-flight sum 50 USDT");
    CHECK(amm_journal_req_marker_exists(g_j, a.sender, a.req_no) == 0,
          "request-number marker written with the approval");
}

static void j2_refusals(void) {
    printf("J2 approval refusals write nothing\n");
    fresh();
    amm_swap_t s, o;
    amm_approve_t a = mk('a', 10000000ULL, 10000000ULL);
    CHECK(approve_ok(&a, &s), "first approval");

    /* request number reused */
    amm_approve_t r = mk('b', 5, 5);
    memcpy(r.req_no, a.req_no, 32);
    r.sender = a.sender;                    /* same sender as the used number */
    r.amount = 77;
    CHECK(amm_journal_approve(g_j, &r, &o) == AMM_J_REQ_REUSED, "reused request number refused");
    CHECK(swap_count_rows() == 1, "  no row written");

    /* open duplicate: same sender and amount -> existing swap returned */
    amm_approve_t d = mk('a', 10000000ULL, 10000000ULL);
    CHECK(amm_journal_approve(g_j, &d, &o) == AMM_J_OPEN_DUP && !strcmp(o.id, s.id),
          "same sender + amount refused, refusal carries the open swap");
    CHECK(amm_journal_req_marker_exists(g_j, d.sender, d.req_no) == 1,
          "  the refused request number is NOT consumed");
    CHECK(swap_count_rows() == 1, "  no row written");
    /* same sender, another amount: accepted */
    amm_approve_t d2 = mk('a', 10000001ULL, 10000001ULL);
    CHECK(amm_journal_approve(g_j, &d2, &o) == AMM_J_OK, "same sender, another amount accepted");
    /* paid_waiting_depth is still open (item 57) */
    CHECK(tr(s.seq, "paid_waiting_depth", "nodus:01") == 0, "first swap now waiting for depth");
    CHECK(amm_journal_approve(g_j, &d, &o) == AMM_J_OPEN_DUP, "still open while waiting for depth");
    /* counted is no longer open */
    CHECK(tr(s.seq, "counted", NULL) == 0, "counted");
    CHECK(amm_journal_approve(g_j, &d, &o) == AMM_J_OK,
          "accepted again once the first is no longer approved / waiting");

    /* per-swap limit */
    amm_approve_t big = mk('c', 100000001ULL, 100000001ULL);
    CHECK(amm_journal_approve(g_j, &big, &o) == AMM_J_SWAP_LIMIT, "100 USDT + 1 raw: per-swap limit");
    CHECK(amm_journal_req_marker_exists(g_j, big.sender, big.req_no) == 1, "  request number not consumed");
    big.value_usdt = 100000000ULL;
    CHECK(amm_journal_approve(g_j, &big, &o) == AMM_J_OK, "same request number accepted at the limit");

    /* in-flight total: 10 + 10.000001 + 10 + 100 = 130.000001 so far */
    uint64_t sum = 0;
    CHECK(amm_journal_inflight_sum(g_j, 0, &sum) == 0 && sum == 130000001ULL, "sum is 130.000001 USDT");
    for (char c = 'd'; c <= 'f'; c++) {
        amm_approve_t f = mk(c, 100000000ULL, 100000000ULL);
        CHECK(amm_journal_approve(g_j, &f, &o) == AMM_J_OK, "fill the book");
    }
    /* 430.000001 now; 70 more fits, 70.000000 + 430.000001 = 500.000001 > 500 */
    amm_approve_t over = mk('0', 70000000ULL, 70000000ULL);
    CHECK(amm_journal_approve(g_j, &over, &o) == AMM_J_INFLIGHT, "in-flight total refused");
    over.value_usdt = 69999999ULL;
    CHECK(amm_journal_approve(g_j, &over, &o) == AMM_J_OK, "exactly 500 USDT admitted");

    /* paused by the settings flag */
    amm_approve_t p = mk('1', 1, 1);
    p.swaps_paused_cfg = 1;
    CHECK(amm_journal_approve(g_j, &p, &o) == AMM_J_PAUSED, "paused by the settings flag");
    CHECK(amm_journal_req_marker_exists(g_j, p.sender, p.req_no) == 1, "  request number not consumed");

    /* a swap in unknown stops new approvals (plan section 17) */
    fresh();
    amm_approve_t u = mk('a', 1, 1);
    CHECK(approve_ok(&u, &s), "approval");
    CHECK(drive(&s, "unknown", "nodus:u1"), "swap driven to unknown");
    amm_approve_t n = mk('b', 2, 2);
    CHECK(amm_journal_approve(g_j, &n, &o) == AMM_J_STOPPED, "stopped while a swap is unknown");

    /* format */
    fresh();
    amm_approve_t bad = mk('a', 1, 1);
    bad.sender = "ABCDEF";
    CHECK(amm_journal_approve(g_j, &bad, &o) == AMM_J_RANGE, "malformed sender: RANGE");
    bad = mk('a', 1, 1);
    bad.amount = (uint64_t)INT64_MAX + 1;
    CHECK(amm_journal_approve(g_j, &bad, &o) == AMM_J_RANGE, "amount above INT64_MAX: RANGE");
    bad = mk('a', 1, 1);
    bad.incoming_id = "has space";
    CHECK(amm_journal_approve(g_j, &bad, &o) == AMM_J_RANGE, "incoming id with a space: RANGE");
    CHECK(swap_count_rows() == 0, "  nothing written");
}

static void j3_graph(void) {
    printf("J3 legal transitions\n");
    fresh();
    amm_swap_t s, g;
    amm_approve_t a = mk('a', 1, 1);
    CHECK(approve_ok(&a, &s), "approval");
    /* illegal from approved */
    CHECK(tr(s.seq, "counted", "nodus:x") == AMM_J_ILLEGAL, "approved -> counted refused");
    CHECK(tr(s.seq, "paid", NULL) == AMM_J_ILLEGAL, "approved -> paid refused");
    CHECK(tr(s.seq, "approved", NULL) == AMM_J_ILLEGAL, "-> approved refused");
    CHECK(tr(s.seq, "reversed", NULL) == AMM_J_ILLEGAL, "-> reversed refused (only payment_gone)");
    CHECK(tr(s.seq, "paid_waiting_depth", NULL) == AMM_J_ILLEGAL,
          "paid_waiting_depth without the incoming id refused");
    CHECK(tr(s.seq, "nonsense", NULL) == AMM_J_ILLEGAL, "unknown state refused");
    CHECK(tr(99999, "expired", NULL) == AMM_J_ILLEGAL, "unknown swap refused");
    CHECK(amm_journal_swap_get(g_j, s.id, &g) == 0 && state_is(&g, "approved"), "  nothing changed");

    CHECK(tr(s.seq, "paid_waiting_depth", "nodus:aa") == 0, "approved -> paid_waiting_depth");
    CHECK(tr(s.seq, "expired", NULL) == AMM_J_ILLEGAL, "paid_waiting_depth -> expired refused (stays in flight)");
    CHECK(tr(s.seq, "approved", NULL) == AMM_J_ILLEGAL, "paid_waiting_depth -> approved refused here");
    CHECK(tr(s.seq, "counted", NULL) == 0, "paid_waiting_depth -> counted");
    CHECK(tr(s.seq, "paid", NULL) == AMM_J_ILLEGAL, "counted -> paid refused (no payout yet)");
    CHECK(tr(s.seq, "refunded", NULL) == AMM_J_ILLEGAL, "counted -> refunded refused");
    CHECK(tr(s.seq, "payout_pending", NULL) == 0, "counted -> payout_pending");
    CHECK(tr(s.seq, "refund_pending", NULL) == AMM_J_ILLEGAL, "payout_pending -> refund_pending refused");
    CHECK(tr(s.seq, "paid", NULL) == 0, "payout_pending -> paid");
    CHECK(tr(s.seq, "payout_pending", NULL) == AMM_J_ILLEGAL, "paid -> payout_pending refused");
    CHECK(tr(s.seq, "expired", NULL) == AMM_J_ILLEGAL, "paid is terminal here");

    /* the other branches, each on its own swap (a swap in unknown stops new
     * approvals, so every swap is approved first) */
    fresh();
    static const char *br[] = {"expired", "refunded", "held", "unknown",
                               "unknown_refund"};
    amm_swap_t bs[5];
    for (size_t i = 0; i < 5; i++) {
        amm_approve_t b = mk((char)('b' + i), 1, 1);
        CHECK(approve_ok(&b, &bs[i]), "approval for a branch");
    }
    for (size_t i = 0; i < 5; i++) {
        char msg[96], inc[32];
        snprintf(msg, sizeof(msg), "branch to %s", br[i]);
        snprintf(inc, sizeof(inc), "nodus:b%zu", i);
        CHECK(drive(&bs[i], br[i], inc), msg);
    }
    fresh();
    /* terminal states refuse every move */
    {
        amm_approve_t b = mk('2', 1, 1);
        amm_swap_t t;
        CHECK(approve_ok(&b, &t) && drive(&t, "refunded", "nodus:zz"), "swap refunded");
        CHECK(tr(t.seq, "refund_pending", NULL) == AMM_J_ILLEGAL, "refunded -> refund_pending refused");
        amm_approve_t h = mk('3', 1, 1);
        amm_swap_t u;
        CHECK(approve_ok(&h, &u) && drive(&u, "held", "nodus:yy"), "swap held");
        CHECK(tr(u.seq, "refunded", NULL) == AMM_J_ILLEGAL, "held -> refunded refused (resolution tool DEFERRED)");
    }
    /* message set and kept */
    {
        amm_approve_t m = mk('4', 1, 1);
        amm_swap_t t, g2;
        CHECK(approve_ok(&m, &t), "approval for message test");
        CHECK(amm_journal_swap_transition(g_j, t.seq, "expired", NULL, NULL,
                                          "window observed") == 0 &&
              amm_journal_swap_get(g_j, t.id, &g2) == 0 &&
              !strcmp(g2.message, "window observed"), "message stored with the transition");
    }
}

static void j4_markers(void) {
    printf("J4 permanent incoming-transfer marker\n");
    fresh();
    amm_swap_t s1, s2, g;
    amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2);
    CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2), "two approvals");
    CHECK(tr(s1.seq, "paid_waiting_depth", "nodus:same") == 0 &&
          tr(s2.seq, "paid_waiting_depth", "nodus:same") == 0,
          "both swaps name the same incoming transfer");
    CHECK(amm_journal_marker_exists(g_j, "nodus:same") == 1, "no marker before counting");
    amm_pool_t p = { {{1,0,0,0}}, {{2,0,0,0}}, {{3,0,0,0}} };
    CHECK(amm_journal_swap_transition(g_j, s1.seq, "counted", NULL, NULL, NULL) == 0,
          "first swap counts");
    CHECK(amm_journal_marker_exists(g_j, "nodus:same") == 0, "marker written at counting");
    CHECK(amm_journal_swap_transition(g_j, s2.seq, "counted", NULL, &p, NULL) == AMM_J_DUP_TRANSFER,
          "second swap with the same incoming id: refused");
    CHECK(amm_journal_swap_get(g_j, s2.id, &g) == 0 && state_is(&g, "paid_waiting_depth"),
          "  its row is unchanged (stays unpaid)");
    amm_pool_t q;
    CHECK(amm_journal_pool_get(g_j, &q) == 1, "  its pool update was not written");
    reopen();
    CHECK(amm_journal_marker_exists(g_j, "nodus:same") == 0, "marker survives a reopen");
    CHECK(amm_journal_req_marker_exists(g_j, a.sender, a.req_no) == 0, "request marker survives a reopen");
    /* counted without any incoming id */
    fresh();
    amm_approve_t c = mk('c', 1, 1);
    amm_swap_t s3;
    CHECK(approve_ok(&c, &s3), "approval without incoming id");
    CHECK(tr(s3.seq, "counted", NULL) == AMM_J_ILLEGAL, "cannot count without a payment");
}

static void j5_inflight(void) {
    printf("J5 in-flight states\n");
    fresh();
    static const char *holds[] = {"approved", "paid_waiting_depth", "counted",
                                  "payout_pending", "refund_pending"};
    static const char *free_[] = {"paid", "refunded", "expired", "held", "unknown"};
    for (size_t i = 0; i < 5; i++) {
        fresh();
        amm_approve_t a = mk('a', 1, 7000000ULL);
        amm_swap_t s;
        uint64_t sum = 0;
        char msg[96];
        CHECK(approve_ok(&a, &s) && drive(&s, holds[i], "nodus:h1"), "drive");
        snprintf(msg, sizeof(msg), "%s holds its room", holds[i]);
        CHECK(amm_journal_inflight_sum(g_j, 0, &sum) == 0 && sum == 7000000ULL, msg);
    }
    for (size_t i = 0; i < 5; i++) {
        fresh();
        amm_approve_t a = mk('a', 1, 7000000ULL);
        amm_swap_t s;
        uint64_t sum = 1;
        char msg[96];
        CHECK(approve_ok(&a, &s) && drive(&s, free_[i], "nodus:h2"), "drive");
        snprintf(msg, sizeof(msg), "%s does not hold room", free_[i]);
        CHECK(amm_journal_inflight_sum(g_j, 0, &sum) == 0 && sum == 0, msg);
    }
    /* room freed by finishing: 5 swaps of 100 fill 500, then one finishes */
    fresh();
    amm_swap_t first;
    memset(&first, 0, sizeof(first));
    for (char c = 'a'; c <= 'e'; c++) {
        amm_approve_t a = mk(c, 100000000ULL, 100000000ULL);
        amm_swap_t s;
        CHECK(approve_ok(&a, &s), "fill");
        if (c == 'a') first = s;
    }
    amm_swap_t o;
    amm_approve_t more = mk('f', 100000000ULL, 100000000ULL);
    CHECK(amm_journal_approve(g_j, &more, &o) == AMM_J_INFLIGHT, "book full at 500");
    CHECK(drive(&first, "paid", "nodus:f1"), "first swap paid");
    CHECK(amm_journal_approve(g_j, &more, &o) == AMM_J_OK, "room freed by the payout");

    /* held keeps its room only when the setting held_keeps_room is 1
     * (plan lines 312, 407 defer it: the journal decides nothing) */
    for (int flag = 0; flag < 2; flag++) {
        fresh();
        char msg[96];
        amm_approve_t h = mk('a', 100000000ULL, 100000000ULL);
        h.held_keeps_room = flag;
        amm_swap_t hs, t;
        uint64_t sum = 99;
        snprintf(msg, sizeof(msg), "held_keeps_room=%d: a swap driven to held", flag);
        CHECK(approve_ok(&h, &hs) && drive(&hs, "held", "nodus:hk"), msg);
        snprintf(msg, sizeof(msg), "held_keeps_room=%d: the sum %s the held swap", flag,
                 flag ? "includes" : "excludes");
        CHECK(amm_journal_inflight_sum(g_j, flag, &sum) == 0 &&
              sum == (flag ? 100000000ULL : 0), msg);
        for (char c = 'b'; c <= 'e'; c++) {
            amm_approve_t f = mk(c, 100000000ULL, 100000000ULL);
            f.held_keeps_room = flag;
            CHECK(approve_ok(&f, &t), "fill 400");
        }
        amm_approve_t last = mk('f', 100000000ULL, 100000000ULL);
        last.held_keeps_room = flag;
        snprintf(msg, sizeof(msg), "held_keeps_room=%d: the fifth 100 USDT swap is %s", flag,
                 flag ? "refused (held 100 + 400 + 100 > 500)" : "admitted (400 + 100 = 500)");
        CHECK(amm_journal_approve(g_j, &last, &o) == (flag ? AMM_J_INFLIGHT : AMM_J_OK), msg);
    }
}

static void j6_pool(void) {
    printf("J6 ledger reserves\n");
    fresh();
    amm_pool_t p, g;
    evm_u256_from_u64(&p.depth_n, 3000000000000000ULL);
    evm_u256_from_u64(&p.depth_u, 3000000000ULL);
    evm_u256_from_u64(&p.units, 3000000000000000ULL);
    CHECK(amm_journal_pool_get(g_j, &g) == 1, "no pool yet: none");
    CHECK(amm_journal_pool_put(g_j, &p) == 0, "pool stored");
    CHECK(amm_journal_pool_get(g_j, &g) == 0 && !memcmp(&g, &p, sizeof(p)), "read back");
    /* a 2^255 + 5 value round-trips */
    evm_u256 one, sh, big, five;
    evm_u256_from_u64(&one, 1); evm_u256_from_u64(&sh, 255); evm_u256_from_u64(&five, 5);
    evm_u256_shl(&big, &sh, &one); evm_u256_add(&big, &big, &five);
    p.depth_n = big;
    CHECK(amm_journal_pool_put(g_j, &p) == 0 && amm_journal_pool_get(g_j, &g) == 0 &&
          !memcmp(&g, &p, sizeof(p)), "a 256-bit value round-trips");
    /* transition carrying a pool: both or neither */
    amm_swap_t s;
    amm_approve_t a = mk('a', 1, 1);
    CHECK(approve_ok(&a, &s) && drive(&s, "counted", "nodus:p1"), "swap counted");
    amm_pool_t np = p;
    evm_u256_from_u64(&np.depth_u, 42);
    CHECK(amm_journal_swap_transition(g_j, s.seq, "paid", NULL, &np, NULL) == AMM_J_ILLEGAL,
          "illegal transition with a pool");
    CHECK(amm_journal_pool_get(g_j, &g) == 0 && !memcmp(&g, &p, sizeof(p)), "  pool unchanged");
    CHECK(amm_journal_swap_transition(g_j, s.seq, "payout_pending", NULL, &np, NULL) == 0,
          "legal transition with a pool");
    reopen();
    CHECK(amm_journal_pool_get(g_j, &g) == 0 && !memcmp(&g, &np, sizeof(np)),
          "pool and state both written, survive a reopen");
    amm_swap_t r;
    CHECK(amm_journal_swap_get(g_j, s.id, &r) == 0 && state_is(&r, "payout_pending"), "state written");
}

static void j7_restart(void) {
    printf("J7 restart from every state\n");
    fresh();
    static const char *states[] = {"approved", "paid_waiting_depth", "counted",
        "payout_pending", "paid", "refund_pending", "refunded", "expired",
        "held", "unknown"};
    char ids[12][33];
    int64_t seqs[12];
    size_t n = 0;
    for (; n < sizeof(states) / sizeof(states[0]); n++) {
        amm_approve_t a = mk("0123456789"[n], 1, 1000);   /* sender chars must be lowercase hex */
        amm_swap_t s;
        char inc[40];
        snprintf(inc, sizeof(inc), "nodus:r%zu", n);
        /* `unknown` stops approvals: approve it last */
        if (!strcmp(states[n], "unknown")) break;
        if (!approve_ok(&a, &s) || !drive(&s, states[n], inc)) { CHECK(0, "setup"); return; }
        strcpy(ids[n], s.id); seqs[n] = s.seq;
    }
    {   amm_approve_t a = mk('f', 1, 1000);
        amm_swap_t s;
        if (!approve_ok(&a, &s) || !drive(&s, "unknown", "nodus:r9")) { CHECK(0, "setup unknown"); return; }
        strcpy(ids[n], s.id); seqs[n] = s.seq; n++; }
    reopen();
    for (size_t i = 0; i < n; i++) {
        char st[AMM_STATE_MAX];
        char msg[96];
        snprintf(msg, sizeof(msg), "state %s read back after a reopen", states[i]);
        CHECK(swap_state(ids[i], st) == 0 && !strcmp(st, states[i]), msg);
    }
    /* next legal move works after the reopen */
    CHECK(tr(seqs[0], "paid_waiting_depth", "nodus:next") == 0, "approved -> paid_waiting_depth after reopen");
    CHECK(tr(seqs[3], "paid", NULL) == 0, "payout_pending -> paid after reopen");
    CHECK(tr(seqs[5], "refunded", NULL) == 0, "refund_pending -> refunded after reopen");
    CHECK(tr(seqs[2], "refund_pending", NULL) == 0, "counted -> refund_pending after reopen");
    CHECK(tr(seqs[9], "paid", NULL) == AMM_J_ILLEGAL, "unknown stays terminal after reopen");
    int u = 0;
    CHECK(amm_journal_state_count(g_j, "unknown", &u) == 0 && u == 1, "unknown still counted");

    /* reversed state */
    fresh();
    amm_approve_t a = mk('a', 1, 1);
    amm_swap_t s;
    uint8_t tx[32]; memset(tx, 0x11, 32);
    char key[AMM_TID_MAX];
    amm_journal_eth_key(tx, key, sizeof(key));
    amm_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.tx, tx, 32); rec.block_number = 10; strcpy(rec.state, "seen");
    CHECK(approve_ok(&a, &s) && drive(&s, "counted", key) &&
          amm_journal_rec_put(g_j, &rec) == 0, "counted swap with its record");
    amm_gone_t out;
    CHECK(amm_journal_payment_gone(g_j, tx, 0, &out) == 0 && out == AMM_GONE_REVERSED, "reversed");
    reopen();
    char st[AMM_STATE_MAX];
    CHECK(swap_state(s.id, st) == 0 && !strcmp(st, "reversed"), "state reversed read back after a reopen");
    CHECK(tr(s.seq, "paid", NULL) == AMM_J_ILLEGAL, "reversed is terminal");
}

static amm_rec_t mkrec(uint8_t t, uint32_t li, uint64_t blk, const char *st) {
    amm_rec_t r;
    memset(&r, 0, sizeof(r));
    memset(r.tx, t, 32); r.log_index = li; r.block_number = blk; r.block_ts = blk * 12;
    memset(r.block_hash, (int)blk, 32); memset(r.from, 0x0f, 20); memset(r.to, 0x0e, 20);
    r.value[31] = 5;
    snprintf(r.state, sizeof(r.state), "%s", st);
    return r;
}

static void j8_gone(void) {
    printf("J8 payment gone: dropped or reversed\n");
    fresh();
    amm_gone_t out;
    amm_rec_t rec, got;
    amm_swap_t s, g;
    char key[AMM_TID_MAX], st2[AMM_STATE_MAX];

    /* (a) waiting for depth -> unpaid again */
    amm_approve_t a = mk('a', 1, 1);
    rec = mkrec(1, 0, 10, "seen");
    amm_journal_eth_key(rec.tx, key, sizeof(key));
    CHECK(approve_ok(&a, &s) && drive(&s, "paid_waiting_depth", key) &&
          amm_journal_rec_put(g_j, &rec) == 0, "waiting swap with its record");
    CHECK(amm_journal_payment_gone(g_j, rec.tx, 0, &out) == 0 && out == AMM_GONE_DROPPED, "dropped");
    CHECK(amm_journal_swap_get(g_j, s.id, &g) == 0 && state_is(&g, "approved") &&
          g.incoming_id[0] == '\0', "swap approved again, incoming id cleared");
    CHECK(amm_journal_rec_get(g_j, rec.tx, 0, &got) == 0 && !strcmp(got.state, "dropped"), "record dropped");
    int p = 1;
    CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 0, "no reversal pause for an unpaid drop");
    CHECK(amm_journal_payment_gone(g_j, rec.tx, 0, &out) == AMM_J_ILLEGAL, "an already dropped record refused");
    CHECK(amm_journal_payment_gone(g_j, rec.tx, 9, &out) == AMM_J_ILLEGAL, "an unknown record refused");

    /* (b) no swap carries the record */
    rec = mkrec(2, 0, 11, "candidate");
    CHECK(amm_journal_rec_put(g_j, &rec) == 0 &&
          amm_journal_payment_gone(g_j, rec.tx, 0, &out) == 0 && out == AMM_GONE_DROPPED,
          "a record with no swap is dropped");

    /* (c) every counted-or-later state is a reversal */
    static const char *rev[] = {"counted", "payout_pending", "paid", "refund_pending", "refunded"};
    for (size_t i = 0; i < 5; i++) {
        fresh();
        amm_approve_t b = mk('b', 1, 1);
        amm_swap_t t;
        amm_rec_t r = mkrec((uint8_t)(20 + i), 3, 30, "seen");
        char k2[AMM_TID_MAX], msg[96];
        amm_journal_eth_key(r.tx, k2, sizeof(k2));
        CHECK(approve_ok(&b, &t) && drive(&t, rev[i], k2) && amm_journal_rec_put(g_j, &r) == 0, "setup");
        snprintf(msg, sizeof(msg), "%s payment gone: reversed, swap reversed, pause set", rev[i]);
        int pz = 0;
        CHECK(amm_journal_payment_gone(g_j, r.tx, 3, &out) == 0 && out == AMM_GONE_REVERSED &&
              amm_journal_swap_get(g_j, t.id, &g) == 0 && state_is(&g, "reversed") &&
              amm_journal_rec_get(g_j, r.tx, 3, &got) == 0 && !strcmp(got.state, "reversed") &&
              amm_journal_reversal_pause_get(g_j, &pz) == 0 && pz == 1, msg);
        reopen();
        pz = 0;
        CHECK(amm_journal_reversal_pause_get(g_j, &pz) == 0 && pz == 1, "  the pause survives a reopen");
        amm_approve_t n = mk('9', 1, 1);
        amm_swap_t o;
        CHECK(amm_journal_approve(g_j, &n, &o) == AMM_J_PAUSED,
              "  new approvals refused with the settings flag off");
    }

    /* (d) a held or unknown swap WAS counted: its payment gone is a confirmed
     * reversal like every other counted state (givens item 55: "counted and
     * paid payments") */
    static const char *late[] = {"held", "unknown"};
    for (size_t i = 0; i < 2; i++) {
        fresh();
        amm_approve_t h = mk('8', 1, 1);
        amm_swap_t hs;
        amm_rec_t hr = mkrec(40, 0, 50, "seen");
        char hk[AMM_TID_MAX], msg[96];
        amm_journal_eth_key(hr.tx, hk, sizeof(hk));
        snprintf(msg, sizeof(msg), "%s swap with its record", late[i]);
        CHECK(approve_ok(&h, &hs) && drive(&hs, late[i], hk) && amm_journal_rec_put(g_j, &hr) == 0, msg);
        snprintf(msg, sizeof(msg), "%s swap: payment gone is a reversal, record reversed, pause set", late[i]);
        int pz = 0;
        CHECK(amm_journal_payment_gone(g_j, hr.tx, 0, &out) == 0 && out == AMM_GONE_REVERSED &&
              amm_journal_swap_get(g_j, hs.id, &g) == 0 && state_is(&g, "reversed") &&
              amm_journal_rec_get(g_j, hr.tx, 0, &got) == 0 && !strcmp(got.state, "reversed") &&
              amm_journal_reversal_pause_get(g_j, &pz) == 0 && pz == 1, msg);
    }
    /* an expired swap never counted a payment: left as it is, record dropped */
    fresh();
    amm_approve_t ex = mk('8', 1, 1);
    amm_swap_t es;
    amm_rec_t er = mkrec(41, 0, 51, "seen");
    char ek[AMM_TID_MAX];
    amm_journal_eth_key(er.tx, ek, sizeof(ek));
    CHECK(approve_ok(&ex, &es) && tr(es.seq, "expired", NULL) == 0 &&
          amm_journal_rec_put(g_j, &er) == 0, "expired swap with a record");
    CHECK(amm_journal_payment_gone(g_j, er.tx, 0, &out) == 0 && out == AMM_GONE_DROPPED &&
          swap_state(es.id, st2) == 0 && !strcmp(st2, "expired"),
          "expired swap left as it is, record dropped");
}

static int fail_hook(void) { return 1; }

static void j9_tx(void) {
    printf("J9 outer transaction\n");
    fresh();
    amm_swap_t s, g;
    amm_rec_t rec = mkrec(7, 0, 100, "seen");
    char key[AMM_TID_MAX];
    amm_journal_eth_key(rec.tx, key, sizeof(key));
    amm_approve_t a = mk('a', 1, 1);
    CHECK(approve_ok(&a, &s) && drive(&s, "counted", key) &&
          amm_journal_rec_put(g_j, &rec) == 0 &&
          amm_journal_cursor_put(g_j, "eth_scan", 100) == 0, "setup");

    amm_gone_t out;
    amm_journal_test_precommit_hook(fail_hook);
    CHECK(amm_journal_tx_begin(g_j) == 0, "begin");
    CHECK(amm_journal_payment_gone(g_j, rec.tx, 0, &out) == 0 && out == AMM_GONE_REVERSED, "reversal decided inside");
    CHECK(amm_journal_cursor_reset(g_j, "eth_scan", 50) == 0, "cursor rewritten inside");
    CHECK(amm_journal_tx_commit(g_j) == -1, "commit refused by the hook");
    amm_journal_test_precommit_hook(NULL);
    reopen();                              /* the restart between decision and write */
    int p = 1;
    uint64_t cur = 0;
    amm_rec_t got;
    CHECK(amm_journal_swap_get(g_j, s.id, &g) == 0 && state_is(&g, "counted"), "swap still counted");
    CHECK(amm_journal_rec_get(g_j, rec.tx, 0, &got) == 0 && !strcmp(got.state, "seen"), "record still seen");
    CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 0, "no pause");
    CHECK(amm_journal_cursor_get(g_j, "eth_scan", &cur) == 0 && cur == 100, "cursor unchanged");

    /* the same writes commit without the hook */
    CHECK(amm_journal_tx_begin(g_j) == 0, "begin again");
    CHECK(amm_journal_payment_gone(g_j, rec.tx, 0, &out) == 0 && out == AMM_GONE_REVERSED, "reversal inside");
    CHECK(amm_journal_cursor_reset(g_j, "eth_scan", 50) == 0, "cursor inside");
    CHECK(amm_journal_tx_commit(g_j) == 0, "commit");
    reopen();
    CHECK(amm_journal_swap_get(g_j, s.id, &g) == 0 && state_is(&g, "reversed") &&
          amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 1 &&
          amm_journal_cursor_get(g_j, "eth_scan", &cur) == 0 && cur == 50,
          "all writes present after a reopen");

    /* a refusal inside the transaction does not poison it; rollback undoes */
    CHECK(amm_journal_tx_begin(g_j) == 0, "begin for refusal test");
    CHECK(amm_journal_cursor_put(g_j, "eth_scan", 10) == AMM_J_ILLEGAL, "a refusal inside");
    CHECK(amm_journal_cursor_put(g_j, "eth_tip", 5) == 0, "a later write inside");
    CHECK(amm_journal_tx_commit(g_j) == 0, "commit succeeds (not poisoned)");
    CHECK(amm_journal_cursor_get(g_j, "eth_tip", &cur) == 0 && cur == 5, "the later write is there");
    CHECK(amm_journal_tx_begin(g_j) == 0 && amm_journal_cursor_put(g_j, "eth_tip", 9) == 0, "begin + write");
    amm_journal_tx_rollback(g_j);
    CHECK(amm_journal_cursor_get(g_j, "eth_tip", &cur) == 0 && cur == 5, "rollback undid the write");
    /* nesting is refused */
    CHECK(amm_journal_tx_begin(g_j) == 0 && amm_journal_tx_begin(g_j) == -1, "no nested begin");
    amm_journal_tx_rollback(g_j);
    CHECK(amm_journal_cursor_put(g_j, "eth_tip", 6) == 0, "journal usable after rollback");
}

static void j10_cursors(void) {
    printf("J10 cursors\n");
    fresh();
    uint64_t v = 7;
    CHECK(amm_journal_cursor_get(g_j, "eth_scan", &v) == 1, "no cursor: none");
    CHECK(amm_journal_cursor_put(g_j, "eth_scan", 100) == 0, "first put");
    CHECK(amm_journal_cursor_put(g_j, "eth_scan", 101) == 0, "forward");
    CHECK(amm_journal_cursor_put(g_j, "eth_scan", 101) == AMM_J_ILLEGAL, "equal refused");
    CHECK(amm_journal_cursor_put(g_j, "eth_scan", 99) == AMM_J_ILLEGAL, "backwards refused");
    CHECK(amm_journal_cursor_get(g_j, "eth_scan", &v) == 0 && v == 101, "value unchanged by refusals");
    CHECK(amm_journal_cursor_reset(g_j, "eth_scan", 90) == 0, "reset lower");
    reopen();
    CHECK(amm_journal_cursor_get(g_j, "eth_scan", &v) == 0 && v == 90, "survives a reopen");
    CHECK(amm_journal_cursor_get(g_j, "other", &v) == 1, "cursors are independent");
}

static amm_blk_t mkblk(uint64_t h, uint8_t hash, uint8_t parent, uint64_t ts) {
    amm_blk_t b;
    memset(&b, 0, sizeof(b));
    b.height = h; memset(b.hash, hash, 32); memset(b.parent, parent, 32); b.ts = ts;
    return b;
}

static void j11_blocks(void) {
    printf("J11 blocks\n");
    fresh();
    amm_blk_t b, g;
    for (uint64_t h = 10; h <= 14; h++) {
        b = mkblk(h, (uint8_t)h, (uint8_t)(h - 1), h * 12);
        CHECK(amm_journal_block_put(g_j, &b) == 0, "put");
    }
    CHECK(amm_journal_block_get(g_j, 12, &g) == 0 && g.hash[0] == 12 && g.parent[0] == 11 && g.ts == 144,
          "read back");
    b = mkblk(12, 99, 11, 144);
    CHECK(amm_journal_block_put(g_j, &b) == 0 && amm_journal_block_get(g_j, 12, &g) == 0 && g.hash[0] == 99,
          "replace by height");
    CHECK(amm_journal_block_get(g_j, 77, &g) == 1, "missing: none");
    uint64_t h = 0;
    CHECK(amm_journal_block_after_ts(g_j, 130, 14, &h) == 0 && h == 11, "lowest block after ts 130 is 11 (ts 132)");
    CHECK(amm_journal_block_after_ts(g_j, 168, 14, &h) == 1, "none above ts 168 (the last is 168)");
    CHECK(amm_journal_block_after_ts(g_j, 130, 10, &h) == 1, "bounded by max_height");
    CHECK(amm_journal_blocks_prune_below(g_j, 12) == 0 && amm_journal_block_get(g_j, 11, &g) == 1 &&
          amm_journal_block_get(g_j, 12, &g) == 0, "prune below 12 keeps 12");
    CHECK(amm_journal_blocks_delete_from(g_j, 13) == 0 && amm_journal_block_get(g_j, 13, &g) == 1 &&
          amm_journal_block_get(g_j, 12, &g) == 0, "delete from 13 keeps 12");
    reopen();
    CHECK(amm_journal_block_get(g_j, 12, &g) == 0, "survives a reopen");
}

static int rec_state_of(const uint8_t tx[32], uint32_t li, char *out) {
    amm_rec_t r;
    int g = amm_journal_rec_get(g_j, tx, li, &r);
    if (g != 0) return g;
    strcpy(out, r.state);
    return 0;
}

static void j12_records(void) {
    printf("J12 records\n");
    fresh();
    amm_rec_t r = mkrec(1, 0, 10, "deep"), g;
    CHECK(amm_journal_rec_put(g_j, &r) == AMM_J_ILLEGAL, "a new record cannot start deep");
    r = mkrec(1, 0, 10, "candidate");
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "new candidate");
    CHECK(amm_journal_rec_candidate_exists(g_j, r.from, r.value, 1000) == 0, "candidate exists query");
    r.state[0] = '\0'; strcpy(r.state, "deep");
    CHECK(amm_journal_rec_put(g_j, &r) == AMM_J_ILLEGAL, "candidate -> deep refused");
    strcpy(r.state, "seen");
    r.block_number = 11;
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "candidate -> seen (block refreshed)");
    CHECK(amm_journal_rec_get(g_j, r.tx, 0, &g) == 0 && g.block_number == 11 && !strcmp(g.state, "seen"), "refreshed");
    CHECK(amm_journal_rec_candidate_exists(g_j, r.from, r.value, 1000) == 1, "no candidate any more");
    strcpy(r.state, "deep");
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "seen -> deep");
    strcpy(r.state, "held");
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "deep -> held");
    strcpy(r.state, "seen");
    CHECK(amm_journal_rec_put(g_j, &r) == AMM_J_ILLEGAL, "held -> seen refused");
    strcpy(r.state, "dropped");
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "held -> dropped");
    strcpy(r.state, "dropped");
    CHECK(amm_journal_rec_put(g_j, &r) == AMM_J_ILLEGAL, "dropped refresh refused");
    strcpy(r.state, "seen");
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "dropped -> seen (the transaction is mined again)");

    /* listing order and cap */
    fresh();
    amm_rec_t a = mkrec(9, 1, 30, "seen"), b = mkrec(3, 0, 30, "seen"),
              c = mkrec(5, 0, 20, "candidate"), d = mkrec(4, 0, 30, "seen"),
              e = mkrec(8, 0, 5, "seen");
    amm_rec_t arr[8];
    int n = 0;
    CHECK(amm_journal_rec_put(g_j, &a) == 0 && amm_journal_rec_put(g_j, &b) == 0 &&
          amm_journal_rec_put(g_j, &c) == 0 && amm_journal_rec_put(g_j, &d) == 0 &&
          amm_journal_rec_put(g_j, &e) == 0, "five records");
    CHECK(amm_journal_rec_list(g_j, 10, NULL, arr, 8, &n) == 0 && n == 4, "four at or above block 10");
    CHECK(arr[0].block_number == 20 && arr[1].tx[0] == 3 && arr[1].log_index == 0 &&
          arr[2].tx[0] == 4 && arr[2].log_index == 0 && arr[3].tx[0] == 9,
          "ordered by (block, tx, log index)");
    CHECK(amm_journal_rec_list(g_j, 0, NULL, arr, 4, &n) == -1, "more rows than the cap is a fault, never cut");
    CHECK(amm_journal_rec_list(g_j, 0, "candidate", arr, 8, &n) == 0 && n == 1 &&
          arr[0].tx[0] == 5, "state filter: the one candidate");
    CHECK(amm_journal_rec_list(g_j, 0, "bogus", arr, 8, &n) == -1, "an unknown state filter is refused");
    CHECK(amm_journal_rec_other_live(g_j, b.tx, 5) == 0, "a live record of tx 3 (log 0) is another than log 5");
    CHECK(amm_journal_rec_other_live(g_j, b.tx, 0) == 1, "tx 3 has no other live record than log 0");
    CHECK(amm_journal_rec_other_live(g_j, a.tx, 1) == 1, "tx 9 has no other live record");
    amm_gone_t out;
    CHECK(amm_journal_payment_gone(g_j, e.tx, 0, &out) == 0, "drop one");
    CHECK(amm_journal_rec_list(g_j, 0, NULL, arr, 8, &n) == 0 && n == 4, "dropped records are not listed");
}

/* J16: one live record per transaction; candidates by block time. */
static void j16_one_live(void) {
    printf("J16 one live record per transaction\n");
    fresh();
    amm_rec_t seen0 = mkrec(7, 0, 10, "seen"), seen1 = mkrec(7, 1, 10, "seen"),
              cand0 = mkrec(7, 0, 10, "candidate"), cand1 = mkrec(7, 1, 10, "candidate"),
              got;
    char st[16];

    /* a seen record beside a live seen record of the same transaction */
    CHECK(amm_journal_rec_put(g_j, &seen0) == 0, "seen (tx 7, log 0)");
    CHECK(amm_journal_rec_put(g_j, &seen1) == AMM_J_ILLEGAL, "seen (tx 7, log 1) beside it refused");
    CHECK(amm_journal_rec_put(g_j, &cand1) == AMM_J_ILLEGAL, "a candidate (tx 7, log 1) beside a live record refused");
    CHECK(amm_journal_rec_get(g_j, seen1.tx, 1, &got) == 1, "  nothing was written for log 1");

    /* a candidate is displaced by a quorum (seen) record of the same tx */
    fresh();
    CHECK(amm_journal_rec_put(g_j, &cand0) == 0, "a false candidate (tx 7, log 0) first");
    CHECK(amm_journal_rec_put(g_j, &seen1) == 0, "the genuine quorum record (tx 7, log 1) is stored");
    CHECK(amm_journal_rec_get(g_j, cand0.tx, 0, &got) == 0 && !strcmp(got.state, "dropped"),
          "  the candidate was dropped in the same transaction");
    CHECK(amm_journal_rec_get(g_j, seen1.tx, 1, &got) == 0 && !strcmp(got.state, "seen"), "  the genuine record is live");
    CHECK(amm_journal_rec_put(g_j, &cand0) == AMM_J_ILLEGAL,
          "  the dropped candidate cannot be revived beside the live record");

    /* a dropped record is revived only when no other record of the tx is live */
    fresh();
    CHECK(amm_journal_rec_put(g_j, &seen0) == 0, "seen (log 0)");
    amm_gone_t out;
    CHECK(amm_journal_payment_gone(g_j, seen0.tx, 0, &out) == 0 && out == AMM_GONE_DROPPED, "log 0 gone: dropped");
    CHECK(amm_journal_rec_put(g_j, &seen1) == 0, "tx mined again as log 1: stored");
    CHECK(amm_journal_rec_put(g_j, &seen0) == AMM_J_ILLEGAL,
          "reviving the dropped log 0 beside live log 1 refused (the report's successive-reorg case)");
    CHECK(amm_journal_payment_gone(g_j, seen1.tx, 1, &out) == 0, "log 1 gone: dropped");
    CHECK(amm_journal_rec_put(g_j, &seen0) == 0, "now log 0 may be revived");
    CHECK(rec_state_of(seen0.tx, 0, st) == 0 && !strcmp(st, "seen") && rec_state_of(seen0.tx, 1, st) == 0 &&
          !strcmp(st, "dropped"), "exactly one live record");

    /* candidates by block time (plan lines 314, 319) */
    fresh();
    amm_rec_t c96 = mkrec(11, 0, 8, "candidate"), c108 = mkrec(12, 0, 9, "candidate"),
              c0 = mkrec(13, 0, 7, "candidate");
    c96.block_ts = 96; c108.block_ts = 108; c0.block_ts = 0;
    memset(c96.from, 0x11, 20); memset(c108.from, 0x12, 20); memset(c0.from, 0x13, 20);
    CHECK(amm_journal_rec_put(g_j, &c96) == 0 && amm_journal_rec_put(g_j, &c108) == 0 &&
          amm_journal_rec_put(g_j, &c0) == 0, "three candidates, block times 96, 108, unknown");
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 100) == 0,
          "block time 96 <= expiry 100: blocks the approval");
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 95) == 1,
          "expiry 95 < block time 96: does not");
    CHECK(amm_journal_rec_candidate_exists(g_j, c108.from, c108.value, 100) == 1,
          "block time 108 > expiry 100: outside the validity, does not block");
    CHECK(amm_journal_rec_candidate_exists(g_j, c108.from, c108.value, 108) == 0,
          "expiry 108: block time 108 is within it");
    CHECK(amm_journal_rec_candidate_exists(g_j, c0.from, c0.value, 1) == 0,
          "unknown block time (0) is kept conservatively: blocks");
}

/* J17: incoming transfer ids of full length; the Ethereum key is the hash. */
static void j17_ids(void) {
    printf("J17 incoming transfer ids\n");
    fresh();
    /* fixed size, independent of AMM_TID_MAX: "nodus:" + 128 hex = 134
     * characters + NUL; with a smaller capacity the assertions below fail,
     * the fixture itself never overflows */
    char wire[135], intent[135];
    memset(wire, 0, sizeof(wire)); memset(intent, 0, sizeof(intent));
    strcpy(wire, "nodus:");
    strcpy(intent, "nodus:");
    for (int i = 0; i < 128; i++) { wire[6 + i] = "0123456789abcdef"[i % 16]; intent[6 + i] = "fedcba9876543210"[i % 16]; }
    CHECK(strlen(wire) == 134 && AMM_TID_MAX >= 135, "a nodus id is 134 characters and fits with its NUL");

    amm_approve_t a = mk('a', 1, 1);
    a.incoming_id = wire;
    amm_swap_t s, g;
    CHECK(amm_journal_approve(g_j, &a, &s) == AMM_J_OK && !strcmp(s.incoming_id, wire),
          "approval naming a full-length wire id");
    CHECK(amm_journal_swap_by_incoming(g_j, wire, &g) == 0 && g.seq == s.seq, "found by the full id");
    CHECK(tr(s.seq, "paid_waiting_depth", wire) == 0 && tr(s.seq, "counted", NULL) == 0,
          "counted with it");
    CHECK(amm_journal_marker_exists(g_j, wire) == 0, "the permanent marker holds the full id");
    CHECK(amm_journal_marker_exists(g_j, intent) == 1, "another 128-hex id is another marker");
    amm_approve_t b = mk('b', 2, 2);
    b.incoming_id = intent;
    amm_swap_t s2;
    CHECK(amm_journal_approve(g_j, &b, &s2) == AMM_J_OK && tr(s2.seq, "paid_waiting_depth", intent) == 0 &&
          tr(s2.seq, "counted", NULL) == 0 && amm_journal_marker_exists(g_j, intent) == 0,
          "a full-length intent id counts with its own marker");
    reopen();
    CHECK(amm_journal_marker_exists(g_j, wire) == 0 && amm_journal_swap_by_incoming(g_j, intent, &g) == 0,
          "both full ids survive a reopen");
    /* one character more is refused */
    char too_long[AMM_TID_MAX + 8];
    memset(too_long, 'a', sizeof(too_long)); too_long[sizeof(too_long) - 1] = '\0';
    amm_approve_t c = mk('c', 3, 3);
    c.incoming_id = too_long;
    amm_swap_t s3;
    CHECK(amm_journal_approve(g_j, &c, &s3) == AMM_J_RANGE, "an id longer than the capacity is refused");

    /* the Ethereum key is the transaction hash alone */
    uint8_t tx[32];
    memset(tx, 0xab, 32);
    char k1[AMM_TID_MAX];
    amm_journal_eth_key(tx, k1, sizeof(k1));
    CHECK(strlen(k1) == 68 && !strncmp(k1, "eth:abab", 8), "eth:<64 hex>: no log index in the key");
}

static void j13_damage(void) {
    printf("J13 rows that do not read back\n");
    fresh();
    amm_swap_t s, o;
    amm_approve_t a = mk('a', 1, 1);
    amm_pool_t p;
    memset(&p, 0, sizeof(p));
    CHECK(approve_ok(&a, &s) && amm_journal_pool_put(g_j, &p) == 0, "setup");
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(g_path, &db) == SQLITE_OK, "second connection");
    CHECK(sqlite3_exec(db, "UPDATE pool SET depth_u = x'0102'", NULL, NULL, NULL) == SQLITE_OK,
          "pool blob cut to 2 bytes");
    amm_pool_t g;
    CHECK(amm_journal_pool_get(g_j, &g) == -1, "pool read fails (-1)");
    CHECK(sqlite3_exec(db, "UPDATE swaps SET sender = 'xyz'", NULL, NULL, NULL) == SQLITE_OK,
          "swap sender malformed");
    CHECK(amm_journal_swap_get(g_j, s.id, &o) == -1, "swap read fails (-1)");
    sqlite3_close(db);
}

static void j14_wal(void) {
    printf("J14 WAL\n");
    fresh();
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int ok = 0;
    if (sqlite3_open(g_path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *m = (const char *)sqlite3_column_text(st, 0);
        ok = m && !strcmp(m, "wal");
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    CHECK(ok, "journal_mode is wal (persisted in the file)");
}

/* ── J15: the Nodus seam header ─────────────────────────────────────── */
static int stub_chain_id(void *ctx, uint8_t out[32], uint64_t deadline_ms) {
    (void)deadline_ms;
    memset(out, *(uint8_t *)ctx, 32);
    return AMM_NODE_OK;
}

static void j15_node_seam(void) {
    printf("J15 amm_node.h seam\n");
    uint8_t byte = 0x5a;
    amm_node_t n;
    memset(&n, 0, sizeof(n));
    n.ctx = &byte;
    n.chain_id32 = stub_chain_id;
    uint8_t id[32];
    CHECK(n.chain_id32(n.ctx, id, AMM_NODE_NO_DEADLINE) == AMM_NODE_OK && id[0] == 0x5a && id[31] == 0x5a,
          "a stub table answers through the seam");
    CHECK(amm_now_ms() > 0 && AMM_COINS_MAX == 100, "clock helper and the coin cap");
}

int main(void) {
    printf("test_amm_journal\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/amm_jnl_testXXXXXX");
    if (!mkdtemp(g_dir)) { printf("FATAL mkdtemp\n"); return 2; }
    snprintf(g_path, sizeof(g_path), "%s/journal.db", g_dir);

    j1_approve();
    j2_refusals();
    j3_graph();
    j4_markers();
    j5_inflight();
    j6_pool();
    j7_restart();
    j8_gone();
    j9_tx();
    j10_cursors();
    j11_blocks();
    j12_records();
    j16_one_live();
    j17_ids();
    j13_damage();
    j14_wal();
    j15_node_seam();

    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
