/**
 * test_amm_journal.c -- the nodus-amm journal (SQLite, WAL, FULL).
 *
 * J25 (revision 10, schema 5): the approval written at the price question
 * (the bot's number, estimated fee, 32-bit request number unique among the
 * approvals, expiry, value, in-flight room: one transaction) and the signed
 * request that names it by that number (amount match, once, item 57 and the
 * per-sender reuse refusal at that step), the dropped state (givens items 89,
 * 90: refund_pending -> dropped only, holds no room), the mark of a ledger
 * update and its idempotent reversal, the network-fee book (givens items 80,
 * 92: the USDT fee kept by the Foundation as USDT, the pool untouched; the
 * unbooked-paid list pages without a lifetime row cap), list by state; J26:
 * the unconsumed-record list (no block window; a counted swap's record is
 * consumed) and payment_unmatched (a moved payment outside its approval's
 * validity: the swap is approved again, the record held). How it can lie: the states are driven through the journal's
 * own API; the engine's use of them is test_amm_engine.
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
 *       (AMM_J_DUP_TRANSFER) already at paid_waiting_depth (review finding
 *       (b), see J18); a marker that already exists refuses the count itself
 *       with the row, the marker and the pool unchanged; marker and
 *       request-number markers survive a reopen;
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
 *       callable (a unit-level compile and call check of the seam; the
 *       behaviour of the seam is tested with the watcher and the payout
 *       tests);
 *   J16 (above) also: the candidate-exists query has a lower bound by chain
 *       HEIGHT (the approval's approved_tip, the tip read at approval;
 *       review finding (a)): a candidate in a block at or below it holds
 *       nothing, one block above it does, an unknown block time (0) is still
 *       kept on the time bound; J2 also: an approval with an unreadable tip
 *       (0) is refused (AMM_J_RANGE), never stored as 0, and the tip reads
 *       back from the row;
 *   J18 ONE INCOMING TRANSFER, ONE SWAP (review finding (b)): a second swap
 *       naming an incoming id that another swap carries in ANY state that has
 *       taken the payment (paid_waiting_depth, counted, payout_pending, paid,
 *       refund_pending, refunded, held, unknown, reversed) is refused with
 *       AMM_J_DUP_TRANSFER at paid_waiting_depth and is left approved; swaps
 *       that are only approved, or expired, do not block (READING of "live");
 *   J19 amm_journal_payment_gone handles EVERY swap carrying the key: two
 *       waiting swaps are both approved again; a counted swap is reversed
 *       with the pause while a waiting swap on the same key is unpaid again
 *       and an approved one is left; two counted-or-later swaps are both
 *       reversed (the impossible-by-API states are set through a second
 *       connection);
 *   J20 the Nodus incoming rows: stored once per (height, item, seq), read
 *       back exactly, listed in order, a cap overflow is a fault, a damaged
 *       row fails the read, range refusals, survive a reopen;
 *   J21 the NODUS payout attempts (write-ahead): refused unless the swap owes
 *       a NODUS payout (the payout of a USDT -> NODUS swap to its
 *       destination, the refund of a NODUS -> USDT swap to its sender),
 *       net + fee == gross and net > 0 and 1..15 inputs; stored, read back
 *       byte for byte and kept across a reopen; a second attempt only after
 *       the first is expired; submit and scan cursor moves; confirmed or
 *       expired is final; the head payout is the oldest by seq; ONE PAYOUT IN
 *       FLIGHT: another swap's attempt is refused while one swap's attempt is
 *       signed or submitted (the bot's coins are not reserved per swap);
 *   J22 the open NODUS approval query: by transfer id, sender and amount,
 *       only NODUS -> USDT swaps in state approved;
 *   J23 an incoming id, once set, is never changed (B on Y naming X at
 *       counted is refused and unchanged; the same id again is accepted) and
 *       the carrier check runs at every transition that names an id;
 *       payout_pending -> refund_pending is allowed with no attempt (with the
 *       pool in the same transaction), refused while an attempt is signed or
 *       submitted, allowed after it expired, illegal from paid; the head
 *       payout is only a swap that owes a NODUS payout.
 *   J24 the USDT payout attempts (package 3, plan section 10 line 265,
 *       section 17 write-ahead): refused unless the swap owes a USDT payout
 *       (the payout of a NODUS -> USDT swap to its Ethereum destination, the
 *       refund of a USDT -> NODUS swap to its Ethereum sender), net + fee ==
 *       gross and net > 0 (givens item 52), keccak256(raw) == hash, gas
 *       limit > 0, fees within INT64_MAX; stored, read back byte for byte, kept
 *       across a reopen; ONE attempt per swap; the database's UNIQUE(hash)
 *       and UNIQUE(chain_id, nonce) refuse a duplicate hash and a duplicate
 *       nonce on the same chain (another chain id is another key); the next
 *       nonce is the highest stored + 1 and survives a reopen; the pending
 *       USDT is the sum of net over signed / submitted attempts only;
 *       submitted / confirmed / failed / orphaned are final in the order the
 *       table allows; payout_pending -> refund_pending is refused while a USDT
 *       attempt is signed or submitted and allowed for a swap with none; a
 *       stored attempt whose bytes no longer hash to its hash fails the read;
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
#include "crypto/hash/keccak256.h"

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
    a.approved_tip = 100;
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
          s.value_usdt == 50000000ULL && s.approved_at == 1000 && s.approved_tip == 100 &&
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
    bad.approved_tip = 0;
    CHECK(amm_journal_approve(g_j, &bad, &o) == AMM_J_RANGE,
          "an unreadable tip (0) refuses the approval: it is never stored as 0");
    CHECK(amm_journal_req_marker_exists(g_j, bad.sender, bad.req_no) == 1 && swap_count_rows() == 0,
          "  nothing written, the request number is not consumed");
    bad = mk('a', 1, 1);
    bad.approved_tip = (uint64_t)INT64_MAX + 1;
    CHECK(amm_journal_approve(g_j, &bad, &o) == AMM_J_RANGE, "a tip above INT64_MAX: RANGE");
    bad = mk('a', 1, 1);
    bad.approved_tip = 1;
    CHECK(amm_journal_approve(g_j, &bad, &o) == AMM_J_OK && o.approved_tip == 1,
          "tip 1 is a readable tip: stored as 1");
    fresh();
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
    /* payout_pending -> refund_pending is legal only with no open attempt (J23) */
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
    CHECK(tr(s1.seq, "paid_waiting_depth", "nodus:same") == 0,
          "the first swap names an incoming transfer and waits on it");
    /* review finding (b): the second swap naming the SAME transfer is refused
     * at the transition, not only at counting */
    CHECK(tr(s2.seq, "paid_waiting_depth", "nodus:same") == AMM_J_DUP_TRANSFER,
          "the second swap naming the same incoming transfer is refused at paid_waiting_depth");
    CHECK(amm_journal_swap_get(g_j, s2.id, &g) == 0 && state_is(&g, "approved") &&
          g.incoming_id[0] == '\0', "  its row is unchanged (stays approved, no id stored)");
    CHECK(amm_journal_marker_exists(g_j, "nodus:same") == 1, "no marker before counting");
    CHECK(amm_journal_swap_transition(g_j, s1.seq, "counted", NULL, NULL, NULL) == 0,
          "first swap counts");
    CHECK(amm_journal_marker_exists(g_j, "nodus:same") == 0, "marker written at counting");
    CHECK(tr(s2.seq, "paid_waiting_depth", "nodus:same") == AMM_J_DUP_TRANSFER,
          "still refused once the first swap is counted");
    reopen();
    CHECK(amm_journal_marker_exists(g_j, "nodus:same") == 0, "marker survives a reopen");
    CHECK(amm_journal_req_marker_exists(g_j, a.sender, a.req_no) == 0, "request marker survives a reopen");
    /* second line of defence: a marker that already exists (written through
     * another connection, as a previous run would have left it) refuses the
     * count itself, with the swap row and the pool unchanged */
    fresh();
    amm_approve_t d = mk('d', 1, 1);
    amm_swap_t s4;
    amm_pool_t p = { {{1,0,0,0}}, {{2,0,0,0}}, {{3,0,0,0}} };
    CHECK(approve_ok(&d, &s4) && tr(s4.seq, "paid_waiting_depth", "nodus:pre") == 0,
          "a swap waits on a transfer");
    sqlite3 *mdb = NULL;
    CHECK(sqlite3_open(g_path, &mdb) == SQLITE_OK &&
          sqlite3_exec(mdb, "INSERT INTO paid_markers(transfer_id, swap_seq) VALUES('nodus:pre', 999)",
                       NULL, NULL, NULL) == SQLITE_OK, "a marker of an earlier swap exists");
    sqlite3_close(mdb);
    CHECK(amm_journal_swap_transition(g_j, s4.seq, "counted", NULL, &p, NULL) == AMM_J_DUP_TRANSFER,
          "counting is refused by the permanent marker");
    CHECK(amm_journal_swap_get(g_j, s4.id, &g) == 0 && state_is(&g, "paid_waiting_depth"),
          "  its row is unchanged (stays unpaid)");
    amm_pool_t q;
    CHECK(amm_journal_pool_get(g_j, &q) == 1, "  its pool update was not written");
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
    CHECK(amm_journal_rec_candidate_exists(g_j, r.from, r.value, 0, 1000) == 0, "candidate exists query");
    r.state[0] = '\0'; strcpy(r.state, "deep");
    CHECK(amm_journal_rec_put(g_j, &r) == AMM_J_ILLEGAL, "candidate -> deep refused");
    strcpy(r.state, "seen");
    r.block_number = 11;
    CHECK(amm_journal_rec_put(g_j, &r) == 0, "candidate -> seen (block refreshed)");
    CHECK(amm_journal_rec_get(g_j, r.tx, 0, &g) == 0 && g.block_number == 11 && !strcmp(g.state, "seen"), "refreshed");
    CHECK(amm_journal_rec_candidate_exists(g_j, r.from, r.value, 0, 1000) == 1, "no candidate any more");
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
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 0, 100) == 0,
          "block time 96 <= expiry 100: blocks the approval");
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 0, 95) == 1,
          "expiry 95 < block time 96: does not");
    CHECK(amm_journal_rec_candidate_exists(g_j, c108.from, c108.value, 0, 100) == 1,
          "block time 108 > expiry 100: outside the validity, does not block");
    CHECK(amm_journal_rec_candidate_exists(g_j, c108.from, c108.value, 0, 108) == 0,
          "expiry 108: block time 108 is within it");
    CHECK(amm_journal_rec_candidate_exists(g_j, c0.from, c0.value, 0, 1) == 0,
          "unknown block time (0) is kept conservatively: blocks");
    /* review finding (a): the lower bound is a chain HEIGHT (the tip read at
     * approval), exclusive; c96 sits in block 8, c0 in block 7 */
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 8, 100) == 1,
          "block 8, approval tip 8: a payment in the tip block is not above it, does not block");
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 9, 100) == 1,
          "approval tip 9 (above the block): does not block");
    CHECK(amm_journal_rec_candidate_exists(g_j, c96.from, c96.value, 7, 100) == 0,
          "approval tip 7, block 8 (one above): blocks");
    CHECK(amm_journal_rec_candidate_exists(g_j, c0.from, c0.value, 6, 1) == 0,
          "unknown block time (0) is kept conservatively on the time bound: blocks");
    CHECK(amm_journal_rec_candidate_exists(g_j, c0.from, c0.value, 7, 1) == 1,
          "unknown block time, but block 7 is not above tip 7: does not block");
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

/* A NODUS -> USDT approval: sender = 128 x `c` (a Nodus address), dest = 40 x
 * 'b' (an Ethereum address), naming the transfer `incoming`. */
static amm_approve_t mk_n2u(char c, uint64_t amount, uint64_t v, const char *incoming) {
    static char ring[64][129];
    static unsigned ri = 0;
    static char dest[41];
    char *s = ring[ri++ % 64];
    memset(s, c, 128); s[128] = '\0';
    memset(dest, 'b', 40); dest[40] = '\0';
    amm_approve_t a = mk('a', amount, v);
    a.dir = AMM_NODUS_TO_USDT;
    a.sender = s; a.dest = dest;
    a.incoming_id = incoming;
    return a;
}

/* Setup only: run `sql` on the journal file through a second connection. */
static int side_sql(const char *sql) {
    sqlite3 *db = NULL;
    int ok = sqlite3_open(g_path, &db) == SQLITE_OK;
    if (ok) sqlite3_busy_timeout(db, 5000);
    ok = ok && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

/* J18: one incoming transfer, one swap (orchestrator's review finding (b)). */
static void j18_one_transfer_one_swap(void) {
    printf("J18 one incoming transfer, one swap\n");
    static const char *taken[] = {"paid_waiting_depth", "counted", "payout_pending",
        "paid", "refund_pending", "refunded", "held", "unknown"};
    for (size_t i = 0; i < sizeof(taken) / sizeof(taken[0]); i++) {
        fresh();
        amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2);
        amm_swap_t s1, s2, g;
        char msg[120];
        /* both approved first: a swap in unknown stops new approvals */
        CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2) && drive(&s1, taken[i], "nodus:t"), "setup");
        snprintf(msg, sizeof(msg), "swap 1 in %s carries the id: a second swap naming it is refused", taken[i]);
        CHECK(tr(s2.seq, "paid_waiting_depth", "nodus:t") == AMM_J_DUP_TRANSFER, msg);
        CHECK(amm_journal_swap_get(g_j, s2.id, &g) == 0 && state_is(&g, "approved") &&
              g.incoming_id[0] == '\0', "  the second swap is unchanged (approved, no id)");
    }
    /* a reversed swap still carries its id */
    fresh();
    {
        amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2);
        amm_swap_t s1, s2;
        amm_rec_t r = mkrec(7, 0, 10, "seen");
        char key[AMM_TID_MAX];
        amm_journal_eth_key(r.tx, key, sizeof(key));
        amm_gone_t out;
        CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2) && drive(&s1, "counted", key) &&
              amm_journal_rec_put(g_j, &r) == 0 &&
              amm_journal_payment_gone(g_j, r.tx, 0, &out) == 0 && out == AMM_GONE_REVERSED,
              "setup: swap 1 reversed");
        CHECK(tr(s2.seq, "paid_waiting_depth", key) == AMM_J_DUP_TRANSFER,
              "a reversed swap still carries the id: a second swap is refused");
    }
    /* approved swaps naming the same id do not block each other; an expired
     * swap never took a payment */
    fresh();
    {
        amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2);
        a.incoming_id = "nodus:x"; b.incoming_id = "nodus:x";
        amm_swap_t s1, s2, g;
        CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2), "two approvals naming the same transfer");
        CHECK(tr(s1.seq, "paid_waiting_depth", "nodus:x") == 0,
              "an approved swap carrying the same id does not block the first to take the payment");
        CHECK(tr(s2.seq, "paid_waiting_depth", "nodus:x") == AMM_J_DUP_TRANSFER,
              "the second is then refused");
        CHECK(amm_journal_swap_get(g_j, s2.id, &g) == 0 && state_is(&g, "approved") &&
              !strcmp(g.incoming_id, "nodus:x"), "  and keeps the id its approval named");
    }
    fresh();
    {
        amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2);
        a.incoming_id = "nodus:y"; b.incoming_id = "nodus:y";
        amm_swap_t s1, s2;
        CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2) && tr(s1.seq, "expired", NULL) == 0,
              "swap 1 expired");
        CHECK(tr(s2.seq, "paid_waiting_depth", "nodus:y") == 0,
              "an expired swap carrying the id does not block");
    }
    /* the swap's own re-entry is not "another swap" */
    fresh();
    {
        amm_approve_t a = mk('a', 1, 1);
        amm_swap_t s1;
        CHECK(approve_ok(&a, &s1) && tr(s1.seq, "paid_waiting_depth", "nodus:self") == 0 &&
              tr(s1.seq, "paid_waiting_depth", "nodus:self") == AMM_J_ILLEGAL,
              "a swap moving to the state it is in is illegal, not a duplicate");
    }
}

/* J19: payment_gone handles EVERY swap that carries the key (review finding
 * (b)). The states are set through a second connection: the transition table
 * itself no longer lets two swaps wait on one payment. */
static void j19_gone_every_swap(void) {
    printf("J19 payment gone: every swap carrying the key\n");
    uint8_t tx[32];
    memset(tx, 0x44, 32);
    char key[AMM_TID_MAX], sql[256];
    amm_journal_eth_key(tx, key, sizeof(key));
    amm_gone_t out;
    amm_swap_t g;
    amm_rec_t r = mkrec(0x44, 0, 10, "seen");

    /* two swaps both waiting on the payment: both are unpaid again */
    fresh();
    amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2);
    amm_swap_t s1, s2;
    CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2) && amm_journal_rec_put(g_j, &r) == 0, "setup");
    snprintf(sql, sizeof(sql), "UPDATE swaps SET state='paid_waiting_depth', incoming_id='%s'", key);
    CHECK(side_sql(sql), "both swaps set waiting on the key (second connection)");
    CHECK(amm_journal_payment_gone(g_j, tx, 0, &out) == 0 && out == AMM_GONE_DROPPED,
          "payment gone: dropped (no counted swap)");
    CHECK(amm_journal_swap_get(g_j, s1.id, &g) == 0 && state_is(&g, "approved") && g.incoming_id[0] == '\0' &&
          amm_journal_swap_get(g_j, s2.id, &g) == 0 && state_is(&g, "approved") && g.incoming_id[0] == '\0',
          "BOTH swaps are approved again with the id cleared (not only the oldest)");

    /* a counted swap and a waiting swap on one key: the counted one is
     * reversed with the pause, the waiting one is unpaid again */
    fresh();
    amm_approve_t c = mk('c', 1, 1), d = mk('d', 2, 2), e = mk('e', 3, 3);
    amm_swap_t s3, s4, s5;
    CHECK(approve_ok(&c, &s3) && approve_ok(&d, &s4) && approve_ok(&e, &s5) &&
          amm_journal_rec_put(g_j, &r) == 0, "setup");
    snprintf(sql, sizeof(sql), "UPDATE swaps SET state='paid_waiting_depth', incoming_id='%s' WHERE seq=%lld",
             key, (long long)s4.seq);
    CHECK(drive(&s3, "counted", key) && side_sql(sql), "swap 1 counted, swap 2 waiting, swap 3 approved on one key");
    snprintf(sql, sizeof(sql), "UPDATE swaps SET incoming_id='%s' WHERE seq=%lld", key, (long long)s5.seq);
    CHECK(side_sql(sql), "swap 3 (approved) carries the key as well");
    CHECK(amm_journal_payment_gone(g_j, tx, 0, &out) == 0 && out == AMM_GONE_REVERSED,
          "payment gone: a reversal");
    CHECK(amm_journal_swap_get(g_j, s3.id, &g) == 0 && state_is(&g, "reversed"), "the counted swap is reversed");
    CHECK(amm_journal_swap_get(g_j, s4.id, &g) == 0 && state_is(&g, "approved") && g.incoming_id[0] == '\0',
          "the waiting swap is approved again with the id cleared");
    CHECK(amm_journal_swap_get(g_j, s5.id, &g) == 0 && state_is(&g, "approved") &&
          !strcmp(g.incoming_id, key), "the approved swap is left as it is");
    int p = 0;
    CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 1, "the reversal pause is set");
    CHECK(amm_journal_rec_get(g_j, tx, 0, &r) == 0 && !strcmp(r.state, "reversed"), "the record is reversed");

    /* two counted-or-later swaps: both reversed */
    fresh();
    amm_approve_t f = mk('f', 1, 1), h = mk('1', 2, 2);
    amm_swap_t s6, s7;
    r = mkrec(0x44, 0, 10, "seen");
    CHECK(approve_ok(&f, &s6) && approve_ok(&h, &s7) && drive(&s6, "paid", key) &&
          amm_journal_rec_put(g_j, &r) == 0, "setup");
    snprintf(sql, sizeof(sql), "UPDATE swaps SET state='refund_pending', incoming_id='%s' WHERE seq=%lld",
             key, (long long)s7.seq);
    CHECK(side_sql(sql), "a second swap in refund_pending carries the key");
    CHECK(amm_journal_payment_gone(g_j, tx, 0, &out) == 0 && out == AMM_GONE_REVERSED &&
          amm_journal_swap_get(g_j, s6.id, &g) == 0 && state_is(&g, "reversed") &&
          amm_journal_swap_get(g_j, s7.id, &g) == 0 && state_is(&g, "reversed"),
          "BOTH counted swaps are reversed");
}

/* J20: incoming Nodus rows. */
static amm_nrow_t mknrow(uint64_t h, uint32_t i, uint32_t q, uint8_t w, const char *st) {
    amm_nrow_t r;
    memset(&r, 0, sizeof(r));
    r.height = h; r.item = i; r.seq = q;
    memset(r.wire, w, 64);
    memset(r.peer, 'a', 128);
    r.amount = 5; r.ts = 1000 + h;
    snprintf(r.state, sizeof(r.state), "%s", st);
    return r;
}

static void j20_nodus_rows(void) {
    printf("J20 Nodus incoming rows\n");
    fresh();
    amm_nrow_t r = mknrow(10, 2, 0, 0x01, "held"), g;
    snprintf(r.reason, sizeof(r.reason), "matches no approval");
    CHECK(amm_journal_nrow_put(g_j, &r) == 0, "a held row is stored");
    CHECK(amm_journal_nrow_put(g_j, &r) == AMM_J_ILLEGAL, "the same (height, item, seq) again: refused, nothing changed");
    CHECK(amm_journal_nrow_get(g_j, 10, 2, 0, &g) == 0 && g.height == 10 && g.item == 2 && g.seq == 0 &&
          g.amount == 5 && g.ts == 1010 && !strcmp(g.state, "held") && !strcmp(g.reason, "matches no approval") &&
          g.swap_seq == 0 && g.wire[0] == 0x01 && g.wire[63] == 0x01 && !strcmp(g.peer, r.peer),
          "it reads back exactly");
    CHECK(amm_journal_nrow_get(g_j, 10, 2, 1, &g) == 1, "another seq: none");
    amm_nrow_t r2 = mknrow(10, 2, 1, 0x01, "counted");
    r2.swap_seq = 7;
    CHECK(amm_journal_nrow_put(g_j, &r2) == 0, "a second row of the same wire id (another q) is a row of its own");
    amm_nrow_t r3 = mknrow(9, 0, 0, 0x02, "held");
    CHECK(amm_journal_nrow_put(g_j, &r3) == 0, "a row of a lower height");
    CHECK(amm_journal_nrow_by_wire(g_j, r.wire, &g) == 0 && g.height == 10 && g.seq == 0,
          "by wire id: the oldest row of that wire");
    uint8_t other[64];
    memset(other, 0x09, 64);
    CHECK(amm_journal_nrow_by_wire(g_j, other, &g) == 1, "by wire id: none");
    amm_nrow_t list[8];
    int n = 0;
    CHECK(amm_journal_nrow_list(g_j, NULL, list, 8, &n) == 0 && n == 3 && list[0].height == 9 &&
          list[1].seq == 0 && list[2].seq == 1, "listed in (height, item, seq) order");
    CHECK(amm_journal_nrow_list(g_j, "held", list, 8, &n) == 0 && n == 2, "held rows");
    CHECK(amm_journal_nrow_list(g_j, "counted", list, 8, &n) == 0 && n == 1 && list[0].swap_seq == 7,
          "counted rows carry their swap");
    CHECK(amm_journal_nrow_list(g_j, NULL, list, 2, &n) == -1, "a result above the cap is a fault, never cut");
    /* range */
    amm_nrow_t bad = mknrow(11, 0, 0, 0x03, "held");
    bad.amount = (uint64_t)INT64_MAX + 1;
    CHECK(amm_journal_nrow_put(g_j, &bad) == AMM_J_RANGE, "an amount above INT64_MAX: RANGE");
    bad = mknrow(11, 0, 0, 0x03, "held");
    bad.peer[5] = 'Z';
    CHECK(amm_journal_nrow_put(g_j, &bad) == AMM_J_RANGE, "a malformed peer: RANGE");
    bad = mknrow(11, 0, 0, 0x03, "maybe");
    CHECK(amm_journal_nrow_put(g_j, &bad) == AMM_J_RANGE, "an unknown state: RANGE");
    reopen();
    CHECK(amm_journal_nrow_get(g_j, 10, 2, 1, &g) == 0 && g.swap_seq == 7, "rows survive a reopen");
    CHECK(side_sql("UPDATE nodus_rows SET peer='xyz' WHERE height=9"), "damage: a malformed peer");
    CHECK(amm_journal_nrow_get(g_j, 9, 0, 0, &g) == -1, "a damaged row read fails (-1), never a value");
}

/* J21: NODUS payout attempts (write-ahead). */
static int mkenv(amm_attempt_t *a, int64_t swap_seq, const char *dest, uint64_t gross,
                 uint64_t fee, uint8_t tag) {
    memset(a, 0, sizeof(*a));
    a->swap_seq = swap_seq;
    snprintf(a->dest, sizeof(a->dest), "%s", dest);
    a->gross = gross; a->fee = fee; a->net = gross - fee;
    a->env_len = 300;
    a->env = malloc(a->env_len);
    for (size_t i = 0; i < a->env_len; i++) a->env[i] = (uint8_t)(tag + i);
    memset(a->wire_id, tag, 64);
    memset(a->intent_id, (uint8_t)(tag ^ 0xff), 64);
    a->n_in = 2;
    memset(a->inputs[0], 0x10 + tag, 64);
    memset(a->inputs[1], 0x20 + tag, 64);
    a->build_tip = 1000; a->expiry = 1090; a->scan_next = 1001;
    return a->env != NULL;
}

static void j21_attempts(void) {
    printf("J21 NODUS payout attempts\n");
    fresh();
    amm_approve_t a = mk('a', 1, 1);
    amm_swap_t s, hd;
    amm_attempt_t at, got;
    char destu[129];
    memset(destu, 'e', 128); destu[128] = '\0';
    CHECK(approve_ok(&a, &s), "setup: a USDT -> NODUS swap");
    CHECK(amm_journal_swap_head_payout(g_j, &hd) == 1, "no swap owes a payout yet");
    CHECK(mkenv(&at, s.seq, destu, 1000, 100, 1) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "approved: no attempt can be stored");
    amm_attempt_free(&at);
    CHECK(drive(&s, "payout_pending", "nodus:p1"), "swap driven to payout_pending");
    CHECK(amm_journal_swap_head_payout(g_j, &hd) == 0 && hd.seq == s.seq, "it is the head payout");

    /* refusals write nothing */
    char wrong[129];
    memset(wrong, 'd', 128); wrong[128] = '\0';
    CHECK(mkenv(&at, s.seq, wrong, 1000, 100, 1) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "a destination other than the swap's: refused");
    amm_attempt_free(&at);
    mkenv(&at, s.seq, destu, 1000, 100, 1);
    at.net = 800;
    CHECK(amm_journal_attempt_sign(g_j, &at) == AMM_J_RANGE, "net + fee != gross: RANGE");
    at.net = 0; at.fee = 1000;
    CHECK(amm_journal_attempt_sign(g_j, &at) == AMM_J_RANGE, "a zero net amount is never stored: RANGE");
    at.net = 900; at.fee = 100; at.n_in = 0;
    CHECK(amm_journal_attempt_sign(g_j, &at) == AMM_J_RANGE, "no input: RANGE");
    at.n_in = AMM_MAX_INPUTS + 1;
    CHECK(amm_journal_attempt_sign(g_j, &at) == AMM_J_RANGE, "16 inputs: RANGE");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_latest(g_j, s.seq, &got) == 1, "nothing was written by the refusals");

    /* store, read back */
    CHECK(mkenv(&at, s.seq, destu, 1000, 100, 1) && amm_journal_attempt_sign(g_j, &at) == 0 &&
          at.n == 1 && !strcmp(at.state, "signed"), "the envelope is stored (attempt 1, signed)");
    CHECK(amm_journal_attempt_latest(g_j, s.seq, &got) == 0 && got.n == 1 && got.env_len == 300 &&
          !memcmp(got.env, at.env, 300) && !memcmp(got.wire_id, at.wire_id, 64) &&
          !memcmp(got.intent_id, at.intent_id, 64) && got.n_in == 2 &&
          !memcmp(got.inputs[0], at.inputs[0], 64) && !memcmp(got.inputs[1], at.inputs[1], 64) &&
          got.gross == 1000 && got.fee == 100 && got.net == 900 && !strcmp(got.dest, destu) &&
          got.build_tip == 1000 && got.expiry == 1090 && got.scan_next == 1001 &&
          got.last_submit_tip == 0 && !strcmp(got.state, "signed"),
          "it reads back byte for byte");
    amm_attempt_free(&got);
    CHECK(mkenv(&at, s.seq, destu, 1000, 100, 2) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "a second attempt while the first is signed: refused (replacement only after expiry)");
    amm_attempt_free(&at);

    /* it survives a reopen: the restart between store and send */
    reopen();
    CHECK(amm_journal_attempt_latest(g_j, s.seq, &got) == 0 && got.n == 1 && got.env[0] == 1 &&
          !strcmp(got.state, "signed"), "the stored envelope survives a reopen");
    amm_attempt_free(&got);

    /* submitted, scanned */
    CHECK(amm_journal_attempt_submitted(g_j, s.seq, 1001) == 0 &&
          amm_journal_attempt_latest(g_j, s.seq, &got) == 0 && !strcmp(got.state, "submitted") &&
          got.last_submit_tip == 1001, "signed -> submitted, last submit tip stored");
    amm_attempt_free(&got);
    CHECK(amm_journal_attempt_submitted(g_j, s.seq, 1004) == 0 &&
          amm_journal_attempt_latest(g_j, s.seq, &got) == 0 && got.last_submit_tip == 1004,
          "a later submit moves the tip");
    amm_attempt_free(&got);
    CHECK(amm_journal_attempt_scanned(g_j, s.seq, 1002) == 0 &&
          amm_journal_attempt_scanned(g_j, s.seq, 1002) == AMM_J_ILLEGAL &&
          amm_journal_attempt_scanned(g_j, s.seq, 1001) == AMM_J_ILLEGAL,
          "the scan cursor moves forward only");
    CHECK(amm_journal_attempt_submitted(g_j, 9999, 1) == AMM_J_ILLEGAL &&
          amm_journal_attempt_scanned(g_j, 9999, 5) == AMM_J_ILLEGAL &&
          amm_journal_attempt_finish(g_j, 9999, "expired") == AMM_J_ILLEGAL, "no attempt: illegal");
    CHECK(amm_journal_attempt_finish(g_j, s.seq, "signed") == AMM_J_ILLEGAL, "finish names expired or confirmed only");
    CHECK(amm_journal_attempt_finish(g_j, s.seq, "expired") == 0 &&
          amm_journal_attempt_submitted(g_j, s.seq, 1100) == AMM_J_ILLEGAL &&
          amm_journal_attempt_finish(g_j, s.seq, "confirmed") == AMM_J_ILLEGAL, "an expired attempt is final");
    /* the replacement */
    CHECK(mkenv(&at, s.seq, destu, 1000, 100, 3) && amm_journal_attempt_sign(g_j, &at) == 0 && at.n == 2,
          "after expiry a replacement is stored as attempt 2");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_latest(g_j, s.seq, &got) == 0 && got.n == 2 && got.env[0] == 3 &&
          !strcmp(got.state, "signed"), "the latest attempt is the replacement");
    amm_attempt_free(&got);
    CHECK(amm_journal_attempt_finish(g_j, s.seq, "confirmed") == 0 &&
          amm_journal_attempt_latest(g_j, s.seq, &got) == 0 && !strcmp(got.state, "confirmed"),
          "confirmed");
    amm_attempt_free(&got);
    CHECK(mkenv(&at, s.seq, destu, 1000, 100, 4) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "no attempt after a confirmed one");
    amm_attempt_free(&at);

    /* NODUS -> USDT: only its refund is a NODUS payout, to its sender */
    fresh();
    amm_approve_t b = mk_n2u('c', 1, 1, "nodus:w1");
    amm_swap_t t;
    char sndr[129];
    memset(sndr, 'c', 128); sndr[128] = '\0';
    CHECK(approve_ok(&b, &t) && drive(&t, "payout_pending", "nodus:w1"), "a NODUS -> USDT swap in payout_pending (a USDT payout)");
    CHECK(mkenv(&at, t.seq, sndr, 1000, 100, 5) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "its payout is in USDT: no NODUS attempt");
    amm_attempt_free(&at);
    fresh();
    amm_approve_t b2 = mk_n2u('c', 1, 1, "nodus:w2");
    CHECK(approve_ok(&b2, &t) && drive(&t, "refund_pending", "nodus:w2"), "a NODUS -> USDT swap in refund_pending");
    CHECK(amm_journal_swap_head_payout(g_j, &hd) == 0 && hd.seq == t.seq, "it is the head payout");
    char eth[41];
    memset(eth, 'b', 40); eth[40] = '\0';
    CHECK(mkenv(&at, t.seq, destu, 1000, 100, 6) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "the refund must go to the request's sender, not to another address");
    amm_attempt_free(&at);
    CHECK(mkenv(&at, t.seq, sndr, 1000, 100, 6) && amm_journal_attempt_sign(g_j, &at) == 0,
          "the refund to the sender is stored");
    amm_attempt_free(&at);
    (void)eth;
    /* the oldest of two payouts is the head */
    fresh();
    amm_approve_t o1 = mk('a', 1, 1), o2 = mk('b', 2, 2);
    amm_swap_t so1, so2;
    CHECK(approve_ok(&o1, &so1) && approve_ok(&o2, &so2) && drive(&so2, "payout_pending", "nodus:o2") &&
          drive(&so1, "payout_pending", "nodus:o1"), "two swaps in payout_pending (the younger first)");
    CHECK(amm_journal_swap_head_payout(g_j, &hd) == 0 && hd.seq == so1.seq, "the head is the oldest by seq");
    /* ONE PAYOUT IN FLIGHT: no coin is reserved per swap, so a second swap's
     * attempt is refused while another swap's attempt is open */
    CHECK(mkenv(&at, so1.seq, destu, 1000, 100, 7) && amm_journal_attempt_sign(g_j, &at) == 0,
          "swap 1: an attempt is stored");
    amm_attempt_free(&at);
    CHECK(mkenv(&at, so2.seq, destu, 1000, 100, 8) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "swap 2: refused while swap 1's attempt is signed");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_submitted(g_j, so1.seq, 1001) == 0 &&
          mkenv(&at, so2.seq, destu, 1000, 100, 8) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "swap 2: refused while swap 1's attempt is submitted");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_latest(g_j, so2.seq, &got) == 1, "  nothing was stored for swap 2");
    CHECK(amm_journal_attempt_finish(g_j, so1.seq, "expired") == 0 &&
          mkenv(&at, so2.seq, destu, 1000, 100, 8) && amm_journal_attempt_sign(g_j, &at) == 0 && at.n == 1,
          "swap 2: allowed once swap 1's attempt is no longer open (expired)");
    amm_attempt_free(&at);
    CHECK(mkenv(&at, so1.seq, destu, 1000, 100, 9) && amm_journal_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "swap 1's replacement is refused while swap 2's attempt is open");
    amm_attempt_free(&at);
}

/* J22: the open NODUS approval query. */
static void j22_open_nodus(void) {
    printf("J22 open NODUS approval by transfer id, sender and amount\n");
    fresh();
    amm_approve_t a = mk_n2u('c', 50, 5, "nodus:id1"), b = mk_n2u('d', 50, 5, "nodus:id1");
    amm_swap_t s1, s2, g;
    char sndr[129];
    memset(sndr, 'c', 128); sndr[128] = '\0';
    CHECK(approve_ok(&a, &s1) && approve_ok(&b, &s2), "two approvals naming one transfer (different senders)");
    CHECK(amm_journal_swap_open_nodus(g_j, "nodus:id1", sndr, 50, &g) == 0 && g.seq == s1.seq,
          "found by id, sender and amount");
    CHECK(amm_journal_swap_open_nodus(g_j, "nodus:id1", sndr, 51, &g) == 1, "another amount: none");
    CHECK(amm_journal_swap_open_nodus(g_j, "nodus:id2", sndr, 50, &g) == 1, "another id: none");
    char other[129];
    memset(other, 'f', 128); other[128] = '\0';
    CHECK(amm_journal_swap_open_nodus(g_j, "nodus:id1", other, 50, &g) == 1, "another sender: none");
    CHECK(tr(s1.seq, "paid_waiting_depth", "nodus:id1") == 0 &&
          amm_journal_swap_open_nodus(g_j, "nodus:id1", sndr, 50, &g) == 1,
          "a swap no longer approved is not an open approval");
    /* a USDT -> NODUS swap is not returned */
    fresh();
    amm_approve_t u = mk('a', 50, 5);
    u.incoming_id = "nodus:id3";
    amm_swap_t su;
    char eth[41];
    memset(eth, 'a', 40); eth[40] = '\0';
    CHECK(approve_ok(&u, &su) && amm_journal_swap_open_nodus(g_j, "nodus:id3", eth, 50, &g) == 1,
          "a USDT -> NODUS approval is not a NODUS payment approval");
    CHECK(amm_journal_swap_open_nodus(g_j, "", sndr, 50, &g) == -1, "an empty id is a bad argument");
}

/* J23: an incoming id is never changed; payout_pending -> refund_pending only
 * while no attempt is open; the head payout is only a NODUS payout. */
static void j23_id_edge_head(void) {
    printf("J23 id reassignment, the refund edge, the head payout\n");
    /* reassignment: B waits on Y and tries to count on A's transfer X */
    fresh();
    amm_approve_t a = mk('a', 1, 1), b = mk('b', 2, 2), c = mk('c', 3, 3);
    amm_swap_t sa, sb, sc, g;
    CHECK(approve_ok(&a, &sa) && approve_ok(&b, &sb) && approve_ok(&c, &sc) &&
          tr(sa.seq, "paid_waiting_depth", "nodus:X") == 0 &&
          tr(sb.seq, "paid_waiting_depth", "nodus:Y") == 0, "setup: A waits on X, B waits on Y");
    CHECK(tr(sb.seq, "counted", "nodus:X") == AMM_J_ILLEGAL,
          "B naming X at counted: refused, its id is Y and is never changed");
    CHECK(amm_journal_swap_get(g_j, sb.id, &g) == 0 && state_is(&g, "paid_waiting_depth") &&
          !strcmp(g.incoming_id, "nodus:Y"), "  B is unchanged, still on Y");
    CHECK(amm_journal_marker_exists(g_j, "nodus:X") == 1, "  no marker for X was written");
    CHECK(tr(sb.seq, "counted", "nodus:Y") == 0 && amm_journal_marker_exists(g_j, "nodus:Y") == 0,
          "naming the SAME id again is accepted; B counts on its own transfer");
    /* the carrier check runs on every transition that names an id */
    CHECK(tr(sc.seq, "expired", "nodus:X") == AMM_J_DUP_TRANSFER,
          "C (no id yet) naming X at ANY transition: refused, A carries X");
    CHECK(amm_journal_swap_get(g_j, sc.id, &g) == 0 && state_is(&g, "approved") && g.incoming_id[0] == '\0',
          "  C is unchanged");

    /* the refund edge */
    fresh();
    amm_approve_t p = mk('a', 1, 1);
    amm_swap_t s, hd;
    amm_attempt_t at;
    char destu[129];
    memset(destu, 'e', 128); destu[128] = '\0';
    CHECK(approve_ok(&p, &s) && drive(&s, "payout_pending", "nodus:r1"), "setup: a USDT -> NODUS swap in payout_pending");
    amm_pool_t pool = { {{1,0,0,0}}, {{2,0,0,0}}, {{3,0,0,0}} };
    CHECK(amm_journal_swap_transition(g_j, s.seq, "refund_pending", NULL, &pool, "fee rose") == 0 &&
          amm_journal_swap_get(g_j, s.id, &g) == 0 && state_is(&g, "refund_pending") && !strcmp(g.message, "fee rose"),
          "payout_pending -> refund_pending is allowed with no attempt (with a pool update in the same transaction)");
    amm_pool_t q;
    CHECK(amm_journal_pool_get(g_j, &q) == 0, "  the pool was written");
    fresh();
    amm_approve_t p2 = mk('a', 1, 1);
    CHECK(approve_ok(&p2, &s) && drive(&s, "payout_pending", "nodus:r2") &&
          mkenv(&at, s.seq, destu, 1000, 100, 1) && amm_journal_attempt_sign(g_j, &at) == 0, "setup: an attempt is signed");
    amm_attempt_free(&at);
    CHECK(tr(s.seq, "refund_pending", NULL) == AMM_J_ILLEGAL, "refused while an attempt is signed");
    CHECK(amm_journal_attempt_submitted(g_j, s.seq, 1001) == 0 && tr(s.seq, "refund_pending", NULL) == AMM_J_ILLEGAL,
          "refused while an attempt is submitted");
    CHECK(amm_journal_swap_get(g_j, s.id, &g) == 0 && state_is(&g, "payout_pending"), "  the swap is unchanged");
    CHECK(amm_journal_attempt_finish(g_j, s.seq, "expired") == 0 && tr(s.seq, "refund_pending", NULL) == 0,
          "allowed once the attempt is expired (it can never apply)");
    /* confirmed: the payout happened; payout_pending is then moved only to paid */
    fresh();
    amm_approve_t p3 = mk('a', 1, 1);
    CHECK(approve_ok(&p3, &s) && drive(&s, "payout_pending", "nodus:r3") &&
          mkenv(&at, s.seq, destu, 1000, 100, 1) && amm_journal_attempt_sign(g_j, &at) == 0 &&
          amm_journal_attempt_finish(g_j, s.seq, "confirmed") == 0, "setup: a confirmed attempt");
    amm_attempt_free(&at);
    /* the edge exists only from payout_pending */
    CHECK(tr(s.seq, "paid", NULL) == 0 && tr(s.seq, "refund_pending", NULL) == AMM_J_ILLEGAL, "paid -> refund_pending stays illegal");

    /* the head payout is only a NODUS payout */
    fresh();
    amm_approve_t n1 = mk_n2u('c', 1, 1, "nodus:h1"), u1 = mk('a', 2, 2), n2 = mk_n2u('d', 3, 3, "nodus:h2");
    amm_swap_t sn1, su1, sn2;
    CHECK(approve_ok(&n1, &sn1) && approve_ok(&u1, &su1) && approve_ok(&n2, &sn2), "setup: three swaps");
    CHECK(drive(&sn1, "payout_pending", "nodus:h1") && drive(&su1, "refund_pending", "nodus:u1"),
          "a NODUS -> USDT swap in payout_pending and a USDT -> NODUS swap in refund_pending (both USDT payouts)");
    CHECK(amm_journal_swap_head_payout(g_j, &hd) == 1, "neither is a NODUS payout: no head");
    CHECK(drive(&sn2, "refund_pending", "nodus:h2") && amm_journal_swap_head_payout(g_j, &hd) == 0 && hd.seq == sn2.seq,
          "a NODUS -> USDT refund_pending is the head, though older swaps wait in the other combinations");
}

/* ── J24: USDT payout attempts (package 3, write-ahead) ─────────────── */

/* An attempt of `len` bytes whose bytes depend on `tag`; hash = keccak256. */
static int mkeatt(amm_eattempt_t *a, int64_t swap_seq, uint8_t recip, uint64_t gross,
                  uint64_t fee, uint64_t nonce, uint8_t tag) {
    memset(a, 0, sizeof(*a));
    a->swap_seq = swap_seq;
    a->chain_id = 1;
    a->nonce = nonce;
    memset(a->recipient, recip, 20);
    a->gross = gross; a->fee = fee; a->net = gross - fee;
    a->gas_limit = 65000;
    a->max_fee_per_gas = 30000000000ULL;
    a->max_priority_fee_per_gas = 2000000000ULL;
    a->raw_len = 200;
    a->raw = malloc(a->raw_len);
    if (!a->raw) return 0;
    for (size_t i = 0; i < a->raw_len; i++) a->raw[i] = (uint8_t)(tag * 7 + i);
    return keccak256(a->raw, a->raw_len, a->hash) == 0;
}

static void j24_eth_attempts(void) {
    printf("J24 USDT payout attempts\n");
    fresh();
    amm_swap_t s, s2, s3, u, lst[8];
    amm_eattempt_t at, got;
    int n = 0;
    /* a NODUS -> USDT swap pays USDT to its destination (40 x 'b' = 0xbb..) */
    amm_approve_t a1 = mk_n2u('c', 1, 1, "nodus:e1"), a2 = mk_n2u('d', 2, 2, "nodus:e2"),
                  a3 = mk_n2u('f', 3, 3, "nodus:e3");
    CHECK(approve_ok(&a1, &s) && approve_ok(&a2, &s2) && approve_ok(&a3, &s3), "setup: three NODUS -> USDT swaps");
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 5, 1) && amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "approved: no USDT attempt can be stored");
    amm_eattempt_free(&at);
    CHECK(drive(&s, "payout_pending", "nodus:e1") && drive(&s2, "payout_pending", "nodus:e2") &&
          drive(&s3, "payout_pending", "nodus:e3"), "the swaps reach payout_pending");
    CHECK(amm_journal_swap_list_usdt_owed(g_j, lst, 8, &n) == 0 && n == 3 && lst[0].seq == s.seq &&
          lst[1].seq == s2.seq && lst[2].seq == s3.seq, "all three owe a USDT payout, oldest first");
    CHECK(amm_journal_swap_list_usdt_owed(g_j, lst, 2, &n) == -1, "a list above the cap is a fault, never cut");

    /* refusals write nothing */
    CHECK(mkeatt(&at, s.seq, 0xaa, 1000, 100, 5, 1) && amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "a recipient that is not the swap's destination: ILLEGAL");
    amm_eattempt_free(&at);
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 5, 1) && (at.net = 899, 1) &&
          amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_RANGE, "net + fee != gross: RANGE");
    amm_eattempt_free(&at);
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 1000, 5, 1) && amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_RANGE,
          "a zero net amount is never stored (givens item 52): RANGE");
    amm_eattempt_free(&at);
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 5, 1) && (at.raw[3] ^= 1, 1) &&
          amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_RANGE, "stored bytes that do not hash to the hash: RANGE");
    amm_eattempt_free(&at);
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 5, 1) && (at.max_fee_per_gas = (uint64_t)INT64_MAX + 1, 1) &&
          amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_RANGE, "a fee above INT64_MAX: RANGE");
    amm_eattempt_free(&at);
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 5, 1) && (at.gas_limit = 0, 1) &&
          amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_RANGE, "gas limit 0: RANGE");
    amm_eattempt_free(&at);
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &got) == 1, "refusals stored nothing");

    /* the write-ahead record */
    uint64_t nx = 99;
    CHECK(amm_journal_eth_next_nonce(g_j, 1, &nx) == 1, "no attempt stored: no next nonce from the journal");
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 5, 1) && amm_journal_eth_attempt_sign(g_j, &at) == 0 &&
          at.n == 1 && !strcmp(at.state, "signed"), "an attempt is stored (state signed)");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &got) == 0 && got.nonce == 5 && got.chain_id == 1 &&
          got.gross == 1000 && got.net == 900 && got.fee == 100 && got.gas_limit == 65000 &&
          got.max_fee_per_gas == 30000000000ULL && got.max_priority_fee_per_gas == 2000000000ULL &&
          got.raw_len == at.raw_len && !memcmp(got.raw, at.raw, at.raw_len) && !memcmp(got.hash, at.hash, 32) &&
          !strcmp(got.state, "signed") && got.last_submit_tip == 0, "it reads back byte for byte");
    amm_eattempt_free(&got);
    CHECK(amm_journal_eth_next_nonce(g_j, 1, &nx) == 0 && nx == 6, "next nonce = highest stored + 1");
    CHECK(amm_journal_eth_next_nonce(g_j, 2, &nx) == 1, "another chain has none");
    reopen();
    CHECK(amm_journal_eth_attempt_by_hash(g_j, at.hash, &got) == 0 && got.swap_seq == s.seq && got.nonce == 5 &&
          !memcmp(got.raw, at.raw, at.raw_len), "the attempt survives a reopen, found by hash");
    amm_eattempt_free(&got);
    CHECK(amm_journal_eth_next_nonce(g_j, 1, &nx) == 0 && nx == 6, "nonce uniqueness state survives a reopen");

    /* one attempt per swap; UNIQUE on the hash and on (chain, nonce) */
    amm_eattempt_t dup;
    CHECK(mkeatt(&dup, s.seq, 0xbb, 1000, 100, 6, 2) && amm_journal_eth_attempt_sign(g_j, &dup) == AMM_J_ILLEGAL,
          "a second attempt of the same swap: ILLEGAL (no automatic replacement)");
    amm_eattempt_free(&dup);
    CHECK(mkeatt(&dup, s2.seq, 0xbb, 1000, 100, 6, 1) && amm_journal_eth_attempt_sign(g_j, &dup) == AMM_J_ILLEGAL,
          "the same transaction hash on another swap: refused by UNIQUE(hash)");
    amm_eattempt_free(&dup);
    CHECK(mkeatt(&dup, s2.seq, 0xbb, 1000, 100, 5, 2) && amm_journal_eth_attempt_sign(g_j, &dup) == AMM_J_ILLEGAL,
          "the same (chain, nonce) on another swap: refused by UNIQUE(chain, nonce)");
    amm_eattempt_free(&dup);
    CHECK(amm_journal_eth_attempt_latest(g_j, s2.seq, &got) == 1, "the refusals stored nothing");
    CHECK(mkeatt(&dup, s2.seq, 0xbb, 2000, 100, 6, 2) && amm_journal_eth_attempt_sign(g_j, &dup) == 0,
          "another hash and another nonce is accepted");
    amm_eattempt_free(&dup);
    CHECK(mkeatt(&dup, s3.seq, 0xbb, 500, 100, 5, 3) && (dup.chain_id = 2, 1) &&
          amm_journal_eth_attempt_sign(g_j, &dup) == 0, "the same nonce on ANOTHER chain id is a different key");
    amm_eattempt_free(&dup);

    /* the bot's own pending USDT: sum of net over signed / submitted */
    uint64_t pend = 0;
    CHECK(amm_journal_eth_pending_usdt(g_j, &pend) == 0 && pend == 900 + 1900 + 400,
          "pending USDT = the sum of net over the open attempts (900 + 1900 + 400)");

    /* states */
    CHECK(amm_journal_eth_attempt_submitted(g_j, s.seq, 1234) == 0 &&
          amm_journal_eth_attempt_latest(g_j, s.seq, &got) == 0 && !strcmp(got.state, "submitted") &&
          got.last_submit_tip == 1234, "submitted records the tip");
    amm_eattempt_free(&got);
    CHECK(amm_journal_eth_attempt_submitted(g_j, s.seq, 1240) == 0, "a re-broadcast of the same attempt is recorded");
    CHECK(amm_journal_eth_attempt_finish(g_j, s.seq, "paid") == AMM_J_ILLEGAL, "an unknown final state is refused");
    CHECK(amm_journal_eth_attempt_finish(g_j, s.seq, "confirmed") == 0 &&
          amm_journal_eth_attempt_latest(g_j, s.seq, &got) == 0 && !strcmp(got.state, "confirmed"),
          "confirmed");
    amm_eattempt_free(&got);
    CHECK(amm_journal_eth_attempt_finish(g_j, s.seq, "failed") == AMM_J_ILLEGAL &&
          amm_journal_eth_attempt_submitted(g_j, s.seq, 1300) == AMM_J_ILLEGAL, "confirmed is final");
    CHECK(amm_journal_eth_pending_usdt(g_j, &pend) == 0 && pend == 1900 + 400,
          "a finished attempt is not pending any more");
    CHECK(amm_journal_eth_attempt_finish(g_j, s2.seq, "failed") == 0 &&
          amm_journal_eth_attempt_finish(g_j, s3.seq, "orphaned") == 0, "failed and orphaned are final states");
    CHECK(amm_journal_eth_pending_usdt(g_j, &pend) == 0 && pend == 0, "nothing pending");
    CHECK(amm_journal_eth_next_nonce(g_j, 1, &nx) == 0 && nx == 7, "a finished attempt's nonce stays used (6 + 1)");

    /* payout_pending -> refund_pending is refused while a USDT attempt is open */
    fresh();
    amm_approve_t b1 = mk_n2u('c', 1, 1, "nodus:f1"), b2 = mk_n2u('d', 2, 2, "nodus:f2");
    CHECK(approve_ok(&b1, &s) && approve_ok(&b2, &s2) && drive(&s, "payout_pending", "nodus:f1") &&
          drive(&s2, "payout_pending", "nodus:f2"), "setup: two NODUS -> USDT swaps in payout_pending");
    CHECK(mkeatt(&at, s.seq, 0xbb, 1000, 100, 0, 4) && amm_journal_eth_attempt_sign(g_j, &at) == 0,
          "setup: an attempt is signed");
    amm_eattempt_free(&at);
    CHECK(tr(s.seq, "refund_pending", NULL) == AMM_J_ILLEGAL, "refused while the USDT attempt is signed");
    CHECK(amm_journal_eth_attempt_submitted(g_j, s.seq, 10) == 0 && tr(s.seq, "refund_pending", NULL) == AMM_J_ILLEGAL,
          "refused while the USDT attempt is submitted");
    CHECK(tr(s2.seq, "refund_pending", NULL) == 0, "allowed for a swap with no attempt (zero USDT after the fee, plan line 241)");
    CHECK(amm_journal_swap_list_usdt_owed(g_j, lst, 8, &n) == 0 && n == 1 && lst[0].seq == s.seq,
          "the NODUS -> USDT refund_pending is a NODUS refund: not in the USDT list");
    CHECK(amm_journal_eth_attempt_finish(g_j, s.seq, "confirmed") == 0 && tr(s.seq, "paid", NULL) == 0,
          "the caller settles the swap after the attempt");

    /* a USDT refund: USDT -> NODUS swap in refund_pending, recipient = its Ethereum sender */
    fresh();
    amm_approve_t r1 = mk('a', 1, 1);
    CHECK(approve_ok(&r1, &u) && drive(&u, "refund_pending", "nodus:g1"), "setup: a USDT -> NODUS swap in refund_pending");
    CHECK(amm_journal_swap_list_usdt_owed(g_j, lst, 8, &n) == 0 && n == 1 && lst[0].seq == u.seq,
          "a USDT -> NODUS refund_pending owes a USDT refund");
    CHECK(mkeatt(&at, u.seq, 0xbb, 1000, 100, 0, 5) && amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "the refund goes to the request's sender, not to the NODUS destination");
    amm_eattempt_free(&at);
    CHECK(mkeatt(&at, u.seq, 0xaa, 1000, 100, 0, 5) && amm_journal_eth_attempt_sign(g_j, &at) == 0,
          "the refund to the sender (40 x 'a') is stored");
    amm_eattempt_free(&at);
    /* a USDT -> NODUS swap in payout_pending is a NODUS payout: no USDT attempt */
    amm_approve_t r2 = mk('b', 2, 2);
    amm_swap_t u2;
    CHECK(approve_ok(&r2, &u2) && drive(&u2, "payout_pending", "nodus:g2") &&
          mkeatt(&at, u2.seq, 0xbb, 1000, 100, 1, 6) && amm_journal_eth_attempt_sign(g_j, &at) == AMM_J_ILLEGAL,
          "a NODUS payout owes no USDT attempt");
    amm_eattempt_free(&at);

    /* the receipt's Transfer log (plan line 264): an attempt can end `unknown`,
     * and a payout whose delivered USDT differs is held (payout_pending -> held) */
    amm_approve_t hq = mk_n2u('9', 7, 7, "nodus:h1");
    amm_swap_t hs, hg;
    CHECK(approve_ok(&hq, &hs) && drive(&hs, "payout_pending", "nodus:h1") &&
          mkeatt(&at, hs.seq, 0xbb, 1000, 100, 9, 7) && amm_journal_eth_attempt_sign(g_j, &at) == 0 &&
          amm_journal_eth_attempt_finish(g_j, hs.seq, "unknown") == 0 &&
          amm_journal_eth_attempt_latest(g_j, hs.seq, &got) == 0 && !strcmp(got.state, "unknown"),
          "an attempt can be finished `unknown` (no Transfer log)");
    amm_eattempt_free(&at);
    amm_eattempt_free(&got);
    CHECK(amm_journal_swap_transition(g_j, hs.seq, "held", NULL, NULL, "USDT delivered 5 differs") == 0 &&
          amm_journal_swap_get(g_j, hs.id, &hg) == 0 && !strcmp(hg.state, "held") &&
          !strcmp(hg.message, "USDT delivered 5 differs"),
          "payout_pending -> held is legal and keeps the message");

    /* damage: the stored bytes no longer hash to the stored hash */
    CHECK(side_sql("UPDATE eth_attempts SET raw=x'00112233'"), "damage: the stored bytes are replaced");
    CHECK(amm_journal_eth_attempt_latest(g_j, u.seq, &got) == -1, "a damaged attempt fails the read (-1), never a value");
    CHECK(amm_journal_eth_pending_usdt(g_j, &pend) == 0, "the pending sum reads amounts only");
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

/* ── J25 (revision 10): the approval at the price question, the signed
 *    request that names it by the bot's number, the dropped refund, the
 *    network-fee booking (schema 5) ─────────────────────────────────── */

static amm_quote_t mkq(uint32_t bot_req, uint64_t amount, uint64_t v) {
    amm_quote_t q;
    memset(&q, 0, sizeof(q));
    q.dir = AMM_USDT_TO_NODUS;
    q.amount = amount; q.quote_out = 400; q.est_fee = 7; q.value_usdt = v;
    q.approved_at = 1000; q.expiry = 1300; q.approved_tip = 100;
    q.bot_req = bot_req;
    for (int i = 0; i < 16; i++) q.rand16[i] = (uint8_t)(bot_req * 7 + i);
    q.swap_max = 100000000ULL; q.inflight_max = 500000000ULL;
    return q;
}

static amm_accept_t mka(uint32_t bot_req, const char *sender, uint64_t amount) {
    static char d[129];
    memset(d, 'e', 128); d[128] = '\0';
    amm_accept_t a;
    memset(&a, 0, sizeof(a));
    a.dir = AMM_USDT_TO_NODUS;
    a.bot_req = bot_req; a.sender = sender; a.dest = d;
    a.amount = amount; a.minimum = 5; a.incoming_id = "";
    for (int i = 0; i < 4; i++) a.req_no[31 - i] = (uint8_t)(bot_req >> (8 * i));
    return a;
}

static void j25_quote_accept(void) {
    printf("J25 approval at the price question, signed request, dropped, fee book\n");
    fresh();
    char sa[41], sb[41];
    memset(sa, 'a', 40); sa[40] = '\0';
    memset(sb, 'b', 40); sb[40] = '\0';
    amm_swap_t s, o, x;

    amm_quote_t q = mkq(12345, 50000000ULL, 50000000ULL);
    CHECK(amm_journal_quote_approve(g_j, &q, &s) == AMM_J_OK &&
          state_is(&s, "approved") && s.req_no_bot == 12345 && !*s.sender &&
          !*s.dest && s.quote_out == 400 && s.est_fee == 7 &&
          s.amount == 50000000ULL && s.expiry == 1300 && s.value_usdt == 50000000ULL,
          "approval written with the bot's number, estimated fee, request number, expiry, value");
    uint64_t sum = 0;
    CHECK(amm_journal_inflight_sum(g_j, 0, &sum) == 0 && sum == 50000000ULL,
          "its room is reserved in the same transaction");
    CHECK(amm_journal_quote_approve(g_j, &q, &x) == AMM_J_NUMBER_TAKEN, "the same number twice refused");
    int cnt = 0;
    CHECK(amm_journal_state_count(g_j, "approved", &cnt) == 0 && cnt == 1,
          "  the refusal wrote nothing");
    CHECK(amm_journal_swap_by_botreq(g_j, 12345, &o) == 0 && !strcmp(o.id, s.id) &&
          amm_journal_swap_by_botreq(g_j, 99, &o) == 1, "lookup by the bot's number");

    amm_accept_t a = mka(777, sa, 50000000ULL);
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_NO_APPROVAL, "unknown number refused");
    a = mka(12345, sa, 50000001ULL);
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_AMOUNT,
          "a signed amount that differs from the approval's refused (item 87)");
    a = mka(12345, sa, 50000000ULL);
    a.dir = AMM_NODUS_TO_USDT;
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_RANGE, "wrong address form for the direction");
    a = mka(12345, sa, 50000000ULL);
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_OK && !strcmp(x.sender, sa) &&
          x.minimum == 5 && x.req_no_bot == 12345 && state_is(&x, "approved"),
          "the signed request written to the approval");
    CHECK(amm_journal_req_marker_exists(g_j, sa, a.req_no) == 0, "the (sender, number) marker written");
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_ILLEGAL, "a number is accepted once");

    /* item 57 at the signed request: same sender and amount while the first is open */
    q = mkq(2, 50000000ULL, 50000000ULL);
    CHECK(amm_journal_quote_approve(g_j, &q, &s) == AMM_J_OK, "second approval, same amount");
    a = mka(2, sa, 50000000ULL);
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_OPEN_DUP && x.req_no_bot == 12345,
          "same sender and amount refused, the open swap named (item 57)");
    CHECK(amm_journal_req_marker_exists(g_j, sa, a.req_no) == 1, "  no marker consumed");
    a = mka(2, sb, 50000000ULL);
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_OK, "another sender accepted");

    /* a number already used by the sender (old-style approval) */
    amm_approve_t old = mk('c', 9, 9);
    amm_swap_t os;
    memcpy(old.req_no, (uint8_t[32]){0}, 32);
    old.req_no[31] = 5;
    old.sender = sb;
    CHECK(approve_ok(&old, &os), "old-style approval of sender b with number 5");
    q = mkq(5, 1234567ULL, 1234567ULL);
    CHECK(amm_journal_quote_approve(g_j, &q, &s) == AMM_J_OK, "approval numbered 5");
    a = mka(5, sb, 1234567ULL);
    CHECK(amm_journal_accept_request(g_j, &a, &x) == AMM_J_REQ_REUSED,
          "the existing per-sender reuse refusal stays");

    /* quote refusals */
    q = mkq(40, 200000000ULL, 200000000ULL);
    CHECK(amm_journal_quote_approve(g_j, &q, &x) == AMM_J_SWAP_LIMIT, "above the per-swap limit");
    q = mkq(41, 90000000ULL, 90000000ULL);
    q.inflight_max = 100000000ULL;
    CHECK(amm_journal_quote_approve(g_j, &q, &x) == AMM_J_INFLIGHT, "above the in-flight total");
    q = mkq(42, 1000000ULL, 1000000ULL); q.swaps_paused_cfg = 1;
    CHECK(amm_journal_quote_approve(g_j, &q, &x) == AMM_J_PAUSED, "swaps paused");
    q = mkq(43, 1000000ULL, 1000000ULL); q.approved_tip = 0;
    CHECK(amm_journal_quote_approve(g_j, &q, &x) == AMM_J_RANGE, "an unread tip refused");

    /* every unsigned row survives a reopen and still reads back */
    reopen();
    CHECK(amm_journal_swap_by_botreq(g_j, 5, &o) == 0 && !*o.sender && o.quote_out == 400,
          "an unsigned approval reads back after a reopen");
    amm_swap_t list[16];
    int n = 0;
    CHECK(amm_journal_swap_list_state(g_j, "approved", list, 16, &n) == 0 && n >= 4 &&
          list[0].seq < list[1].seq, "list by state, oldest first");
    CHECK(amm_journal_swap_list_state(g_j, "approved", list, 2, &n) == -1,
          "a list that would exceed the cap is a fault, never cut");

    /* dropped (givens items 89, 90) */
    fresh();
    amm_approve_t da = mk('d', 1, 77);
    amm_swap_t ds;
    CHECK(approve_ok(&da, &ds) && drive(&ds, "refund_pending", "nodus:dd"), "a refund pending");
    uint64_t before = 0, after = 0;
    amm_journal_inflight_sum(g_j, 0, &before);
    CHECK(tr(ds.seq, "dropped", NULL) == 0, "refund_pending -> dropped");
    CHECK(amm_journal_inflight_sum(g_j, 0, &after) == 0 && before == 77 && after == 0,
          "a dropped swap holds no room");
    CHECK(tr(ds.seq, "refunded", NULL) == AMM_J_ILLEGAL && tr(ds.seq, "paid", NULL) == AMM_J_ILLEGAL,
          "dropped is terminal");
    amm_approve_t da2 = mk('d', 2, 1);
    amm_swap_t ds2;
    CHECK(approve_ok(&da2, &ds2) && drive(&ds2, "counted", "nodus:de") &&
          tr(ds2.seq, "dropped", NULL) == AMM_J_ILLEGAL, "counted -> dropped refused");

    /* the mark of the ledger update and its idempotent reversal */
    amm_approve_t la = mk('9', 4, 4);
    amm_swap_t ls, lg;
    amm_pool_t lp, lq;
    evm_u256_from_u64(&lp.depth_n, 500); evm_u256_from_u64(&lp.depth_u, 600);
    evm_u256_from_u64(&lp.units, 1);
    lq = lp;
    evm_u256_from_u64(&lq.depth_n, 400);
    CHECK(approve_ok(&la, &ls) && drive(&ls, "counted", "nodus:9a") &&
          amm_journal_swap_transition(g_j, ls.seq, "payout_pending", NULL, &lq, NULL) == 0 &&
          amm_journal_swap_get(g_j, ls.id, &lg) == 0 && lg.ledger_applied == 1,
          "the move to payout_pending with a pool marks the ledger update");
    CHECK(amm_journal_ledger_reverse(g_j, ls.seq, &lp) == AMM_J_ILLEGAL,
          "no reversal while the swap is not a refund");
    CHECK(tr(ls.seq, "refund_pending", NULL) == 0 &&
          amm_journal_ledger_reverse(g_j, ls.seq, &lp) == AMM_J_OK &&
          amm_journal_pool_get(g_j, &lq) == 0 && !memcmp(&lq, &lp, sizeof(lp)) &&
          amm_journal_swap_get(g_j, ls.id, &lg) == 0 && lg.ledger_applied == 0,
          "refund: the reserves are restored and the mark cleared in one transaction");
    CHECK(amm_journal_ledger_reverse(g_j, ls.seq, &lq) == AMM_J_ILLEGAL,
          "a second reversal refused (idempotent across a restart)");
    amm_approve_t lb = mk('8', 5, 5);
    amm_swap_t lbs;
    CHECK(approve_ok(&lb, &lbs) && drive(&lbs, "refund_pending", "nodus:8a") &&
          amm_journal_ledger_reverse(g_j, lbs.seq, &lp) == AMM_J_ILLEGAL,
          "a swap whose ledger was never updated has nothing to reverse");

    /* fee book (givens items 80, 92): the USDT fee is kept by the Foundation
     * AS USDT; the pool is not written */
    fresh();
    amm_pool_t p, g;
    evm_u256_from_u64(&p.depth_n, 2000); evm_u256_from_u64(&p.depth_u, 3000);
    evm_u256_from_u64(&p.units, 10);
    CHECK(amm_journal_pool_put(g_j, &p) == 0, "a pool is stored");
    amm_approve_t fa = mk_n2u('f', 3, 3, "nodus:ff");
    amm_swap_t fs;
    CHECK(approve_ok(&fa, &fs) && drive(&fs, "payout_pending", "nodus:ff"), "a payout pending");
    CHECK(amm_journal_book_fee(g_j, fs.seq, 100) == AMM_J_ILLEGAL,
          "the fee of a swap that is not paid is not booked");
    CHECK(tr(fs.seq, "paid", NULL) == 0 && amm_journal_fee_booked(g_j, fs.seq, NULL) == 1,
          "paid, not yet booked");
    CHECK(amm_journal_book_fee(g_j, fs.seq, 100) == AMM_J_OK, "fee booked");
    uint64_t fee = 0;
    CHECK(amm_journal_fee_booked(g_j, fs.seq, &fee) == 0 && fee == 100 &&
          amm_journal_pool_get(g_j, &g) == 0 && !memcmp(&g, &p, sizeof(p)),
          "the row is written and the pool is NOT: no USDT into the pool, no NODUS out");
    CHECK(amm_journal_book_fee(g_j, fs.seq, 100) == AMM_J_ILLEGAL, "booked once");
    uint64_t total = 0;
    CHECK(amm_journal_foundation_usdt(g_j, &total) == 0 && total == 100,
          "the Foundation's USDT summed from the rows");

    /* the unbooked list pages with no lifetime row cap (the engine's fee
     * booking read once stopped for good past 1,024 paid rows): five paid
     * USDT payouts, pages of two. A USDT -> NODUS paid swap, a swap not yet
     * paid and the booked swap above are never listed. */
    int64_t seqs[5];
    for (int i = 0; i < 5; i++) {
        char inc[16];
        snprintf(inc, sizeof(inc), "nodus:p%d", i);
        amm_approve_t pa = mk_n2u((char)('1' + i), 3, 3, inc);
        amm_swap_t ps;
        CHECK(approve_ok(&pa, &ps) && drive(&ps, "paid", inc), "a paid USDT payout");
        seqs[i] = ps.seq;
    }
    amm_approve_t ua = mk('d', 3, 3);
    amm_swap_t us;
    CHECK(approve_ok(&ua, &us) && drive(&us, "paid", "nodus:dd"), "a paid NODUS payout (other direction)");
    amm_approve_t na = mk_n2u('e', 3, 3, "nodus:ee");
    amm_swap_t ns;
    CHECK(approve_ok(&na, &ns) && drive(&ns, "payout_pending", "nodus:ee"), "a payout still pending");
    amm_swap_t pg[2];
    cnt = 0;
    CHECK(amm_journal_swap_list_unbooked_paid(g_j, 0, pg, 2, &cnt) == 0 && cnt == 2 &&
          pg[0].seq == seqs[0] && pg[1].seq == seqs[1], "page 1: the two oldest unbooked");
    CHECK(amm_journal_swap_list_unbooked_paid(g_j, pg[1].seq, pg, 2, &cnt) == 0 && cnt == 2 &&
          pg[0].seq == seqs[2] && pg[1].seq == seqs[3], "page 2 continues after the last seq");
    CHECK(amm_journal_swap_list_unbooked_paid(g_j, pg[1].seq, pg, 2, &cnt) == 0 && cnt == 1 &&
          pg[0].seq == seqs[4], "page 3: the last one, fewer than the page ends the walk");
    CHECK(amm_journal_book_fee(g_j, seqs[0], 7) == AMM_J_OK &&
          amm_journal_swap_list_unbooked_paid(g_j, 0, pg, 2, &cnt) == 0 && cnt == 2 &&
          pg[0].seq == seqs[1], "a booked swap leaves the list");
}

/* Put a record as `seen`, then walk it to `state` when it is deep. */
static int put_rec_in(uint8_t t, uint64_t blk, const char *state) {
    amm_rec_t r = mkrec(t, 0, blk, "seen");
    if (amm_journal_rec_put(g_j, &r) != AMM_J_OK) return 0;
    if (!strcmp(state, "seen")) return 1;
    snprintf(r.state, sizeof(r.state), "%s", state);
    return amm_journal_rec_put(g_j, &r) == AMM_J_OK;
}

/* J26: the engine reads every UNCONSUMED Ethereum record (no block window) and
 * a moved payment outside its approval's validity is un-linked and held. */
static void j26_unconsumed_and_unmatched(void) {
    printf("J26 unconsumed records (no window), payment unmatched\n");
    fresh();
    amm_rec_t out[8];
    int n = 0;
    char key[AMM_TID_MAX];
    amm_swap_t s;

    /* A: seen, block 1, no swap; B: seen, block 20, carried by a waiting swap;
     * C: deep, block 30, carried by a counted swap (consumed); D: deep, block
     * 2, no swap. Blocks 1 and 2 are far below any tip-window a caller could
     * pass: the query has no height bound. */
    CHECK(put_rec_in(0xA1, 1, "seen") && put_rec_in(0xB1, 20, "seen") &&
          put_rec_in(0xC1, 30, "deep") && put_rec_in(0xD1, 2, "deep"), "four records stored");
    uint8_t tb[32], tc[32];
    memset(tb, 0xB1, 32); memset(tc, 0xC1, 32);
    amm_approve_t ab = mk('b', 1, 1), ac = mk('c', 1, 1);
    amm_journal_eth_key(tb, key, sizeof(key));
    CHECK(approve_ok(&ab, &s) && drive(&s, "paid_waiting_depth", key), "B carried by a waiting swap");
    amm_journal_eth_key(tc, key, sizeof(key));
    CHECK(approve_ok(&ac, &s) && drive(&s, "counted", key), "C carried by a counted swap");

    CHECK(amm_journal_rec_list_unconsumed(g_j, "seen", NULL, out, 8, &n) == 0 && n == 2 &&
          out[0].tx[0] == 0xA1 && out[1].tx[0] == 0xB1,
          "seen: the unclaimed record (block 1) and the one whose swap still waits");
    CHECK(amm_journal_rec_list_unconsumed(g_j, "deep", NULL, out, 8, &n) == 0 && n == 1 &&
          out[0].tx[0] == 0xD1, "deep: only the unclaimed record; the counted swap's record is consumed");
    /* paging (Sol verify 10, claim 6): a page of 1, then the page after it,
     * then an empty page -- every record is reached, none twice */
    {
        amm_rec_t p1[1], p2[1], p3[1];
        int n1 = -1, n2 = -1, n3 = -1;
        CHECK(amm_journal_rec_list_unconsumed(g_j, "seen", NULL, p1, 1, &n1) == 0 && n1 == 1 &&
              p1[0].tx[0] == 0xA1 &&
              amm_journal_rec_list_unconsumed(g_j, "seen", &p1[0], p2, 1, &n2) == 0 && n2 == 1 &&
              p2[0].tx[0] == 0xB1 &&
              amm_journal_rec_list_unconsumed(g_j, "seen", &p2[0], p3, 1, &n3) == 0 && n3 == 0,
              "pages of one: A, then B, then nothing (no record lost past the cap)");
    }
    CHECK(amm_journal_rec_list_unconsumed(g_j, "seen", NULL, out, 0, &n) == -1,
          "a zero page size is refused");
    CHECK(amm_journal_rec_list_unconsumed(g_j, "bogus", NULL, out, 8, &n) == -1, "an unknown state is refused");

    /* payment_unmatched: B becomes deep while its swap waits; then it is moved
     * outside the validity: un-link and hold */
    amm_rec_t rb = mkrec(0xB1, 0, 20, "deep");
    CHECK(amm_journal_payment_unmatched(g_j, tb, 0) == AMM_J_ILLEGAL,
          "a record that is not deep is refused");
    CHECK(amm_journal_rec_put(g_j, &rb) == AMM_J_OK &&
          amm_journal_payment_unmatched(g_j, tb, 0) == AMM_J_OK, "a deep record is unmatched");
    amm_rec_t got;
    amm_swap_t sw;
    CHECK(amm_journal_rec_get(g_j, tb, 0, &got) == 0 && !strcmp(got.state, "held"),
          "the record is held");
    amm_journal_eth_key(tb, key, sizeof(key));
    CHECK(amm_journal_swap_by_incoming(g_j, key, &sw) == 1, "no swap carries the transaction any more");
    amm_swap_t ap[4];
    CHECK(amm_journal_swap_list_state(g_j, "approved", ap, 4, &n) == 0 && n == 1 &&
          !*ap[0].incoming_id, "the swap is approved again with its link cleared");
    CHECK(amm_journal_payment_unmatched(g_j, tb, 0) == AMM_J_ILLEGAL, "a second call is refused (held)");
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
    j18_one_transfer_one_swap();
    j19_gone_every_swap();
    j20_nodus_rows();
    j21_attempts();
    j22_open_nodus();
    j23_id_edge_head();
    j24_eth_attempts();
    j13_damage();
    j14_wal();
    j15_node_seam();
    j25_quote_accept();
    j26_unconsumed_and_unmatched();

    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
