/**
 * test_faucet_journal.c — the nodus-faucet journal (SQLite, WAL, FULL).
 *
 * WHAT IT PROVES (design 2026-10-22-testnet-faucet-design.md section 6.4-6.7,
 * operator "Yeni istekleri durdur"):
 *   J1  a claim and its paid marker are written together; a second claim for
 *       the same name (full) or the same address (start) is FJ_EXISTS and
 *       returns the FIRST claim — the marker is permanent;
 *   J2  one OPEN claim per address (de-dup), the queue cap refuses when full;
 *   J3  the legal state graph: signed only through attempt_sign, terminal
 *       states only through finish, illegal moves are refused (-2) and change
 *       nothing, confirmed is terminal;
 *   J4  attempt_sign stores bytes/intent/inputs/tip/expiry/cursor and flips
 *       the claim to signed atomically with its reservations; a coin held by
 *       ANOTHER claim refuses (-3) and nothing changes;
 *   J5  everything survives a close and reopen (claims, markers, attempts,
 *       reservations, scan cursor) and the scan cursor never moves backwards;
 *   J6  a claim in state unknown stops new claims (FJ_STOPPED);
 *   J7  at the storage ceiling new claims stop (FJ_STORAGE_FULL) while an
 *       existing marker still answers FJ_EXISTS.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp,
 *   removed at the end; no network.
 * LEAVES BEHIND: nothing (the directory is removed).
 * HOW IT CAN LIE: single process, no crash injection — durability across a
 *   real power cut (synchronous=FULL) is SQLite's property, not shown here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "faucet_journal.h"

static int g_failures = 0;
#define CHECK(cond, what)                                                    \
    do {                                                                     \
        if (cond) printf("  ok    %s\n", what);                              \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static void addr_of(char out[129], int seed) {
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 128; i++) out[i] = d[(seed + i) & 15];
    out[128] = '\0';
}

static void rnd16(uint8_t out[16], int seed) {
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(seed * 17 + i);
}

static void mk_attempt(faucet_attempt_t *a, uint8_t *env, int seed, int n_in) {
    memset(a, 0, sizeof(*a));
    for (int i = 0; i < 40; i++) env[i] = (uint8_t)(seed + i);
    a->env = env;
    a->env_len = 40;
    for (int i = 0; i < 64; i++) {
        a->wire_id[i] = (uint8_t)(seed + 1);
        a->intent_id[i] = (uint8_t)(seed + 2);
    }
    a->n_in = n_in;
    for (int k = 0; k < n_in; k++)
        for (int i = 0; i < 64; i++) a->inputs[k][i] = (uint8_t)(seed * 10 + k);
    a->build_tip = 100;
    a->expiry = 190;
    a->scan_next = 101;
}

int main(void) {
    printf("test_faucet_journal\n");
    char dir[] = "/tmp/faucet_jtest_XXXXXX";
    if (!mkdtemp(dir)) { printf("mkdtemp failed\n"); return 2; }
    char path[96];
    snprintf(path, sizeof(path), "%s/j.db", dir);

    faucet_journal_t *j = NULL;
    CHECK(faucet_journal_open(path, 64ULL << 20, &j) == 0, "J0 journal opens");

    char a1[129], a2[129], a3[129];
    addr_of(a1, 1); addr_of(a2, 2); addr_of(a3, 3);
    uint8_t r[16];
    faucet_claim_t c1, c2, tmp;

    /* J1 markers */
    rnd16(r, 1);
    CHECK(faucet_journal_claim_create(j, "full", a1, "alice", 4, r, &c1) == FJ_CREATED &&
          !strcmp(c1.state, "planned") && !strcmp(c1.kind, "full"), "J1 a full claim is created (planned)");
    rnd16(r, 2);
    CHECK(faucet_journal_claim_create(j, "full", a2, "alice", 4, r, &tmp) == FJ_EXISTS &&
          !strcmp(tmp.claim_id, c1.claim_id), "J1 the same NAME from another address returns the first claim");
    CHECK(faucet_journal_claim_create(j, "start", a1, NULL, 4, r, &tmp) == FJ_EXISTS &&
          !strcmp(tmp.claim_id, c1.claim_id), "J2 an address with an open claim gets that claim (de-dup)");

    /* J3 transitions */
    CHECK(faucet_journal_set_state(j, c1.seq, "signed", "") == -2, "J3 signed is reachable only through attempt_sign");
    CHECK(faucet_journal_finish(j, c1.seq, "confirmed", "x") == -2, "J3 planned -> confirmed is illegal");
    CHECK(faucet_journal_set_state(j, c1.seq, "paused", "fee") == 0, "J3 planned -> paused");
    CHECK(faucet_journal_set_state(j, c1.seq, "paused", "fee2") == 0, "J3 paused -> paused (new message)");
    faucet_journal_claim_get(j, c1.claim_id, &tmp);
    CHECK(!strcmp(tmp.state, "paused") && !strcmp(tmp.message, "fee2"), "J3 state and message stored");

    /* J4 attempt_sign */
    uint8_t env1[64], env2[64];
    faucet_attempt_t a;
    mk_attempt(&a, env1, 5, 2);
    CHECK(faucet_journal_attempt_sign(j, c1.seq, &a) == 0 && a.n == 1, "J4 attempt 1 stored, claim signed");
    faucet_journal_claim_get(j, c1.claim_id, &tmp);
    CHECK(!strcmp(tmp.state, "signed"), "J4 the claim is signed");
    faucet_attempt_t got;
    CHECK(faucet_journal_attempt_latest(j, c1.seq, &got) == 0 && got.env_len == 40 &&
          !memcmp(got.env, env1, 40) && got.n_in == 2 && got.build_tip == 100 &&
          got.expiry == 190 && got.scan_next == 101 && got.last_submit_tip == 0,
          "J4 the stored attempt reads back byte for byte");
    faucet_attempt_free(&got);
    CHECK(faucet_journal_attempt_sign(j, c1.seq, &a) == -2, "J4 a second sign from signed is refused");

    rnd16(r, 3);
    CHECK(faucet_journal_claim_create(j, "start", a3, NULL, 4, r, &c2) == FJ_CREATED, "J4 a second claim (start)");
    faucet_attempt_t b;
    mk_attempt(&b, env2, 5, 1);               /* input {5*10+0} == c1's first input */
    CHECK(faucet_journal_attempt_sign(j, c2.seq, &b) == -3, "J4 a coin reserved by another claim refuses (-3)");
    faucet_journal_claim_get(j, c2.claim_id, &tmp);
    CHECK(!strcmp(tmp.state, "planned"), "J4 ... and the refused claim is unchanged");
    CHECK(faucet_journal_attempt_latest(j, c2.seq, &got) == 1, "J4 ... and has no attempt row");
    mk_attempt(&b, env2, 6, 1);
    CHECK(faucet_journal_attempt_sign(j, c2.seq, &b) == 0, "J4 disjoint inputs sign");
    uint8_t (*res)[64] = malloc(64 * 64);
    CHECK(faucet_journal_reserved_other(j, c1.seq, res, 64) == 1, "J4 reserved_other(c1) = c2's single coin");
    CHECK(faucet_journal_reserved_other(j, 0, res, 64) == 3, "J4 reserved_other(none) = all three");
    free(res);

    /* J3 continued: submitted / scan cursor / terminal */
    CHECK(faucet_journal_attempt_submitted(j, c1.seq, 120) == 0, "J3 signed -> submitted records the submit tip");
    faucet_journal_claim_get(j, c1.claim_id, &tmp);
    CHECK(!strcmp(tmp.state, "submitted"), "J3 the claim is submitted");
    CHECK(faucet_journal_attempt_scanned(j, c1.seq, 110) == 0, "J5 scan cursor advances");
    CHECK(faucet_journal_attempt_scanned(j, c1.seq, 105) == -2, "J5 the scan cursor never moves backwards");
    CHECK(faucet_journal_attempt_scanned(j, c1.seq, 110) == -2, "J5 ... nor stands still");

    /* J5 reopen */
    faucet_journal_close(j);
    j = NULL;
    CHECK(faucet_journal_open(path, 64ULL << 20, &j) == 0, "J5 journal reopens");
    CHECK(faucet_journal_attempt_latest(j, c1.seq, &got) == 0 && got.scan_next == 110 &&
          got.last_submit_tip == 120 && !memcmp(got.env, env1, 40), "J5 attempt, cursor, submit tip survived");
    faucet_attempt_free(&got);
    res = malloc(64 * 64);
    CHECK(faucet_journal_reserved_other(j, 0, res, 64) == 3, "J5 reservations survived");
    free(res);
    CHECK(faucet_journal_claim_get(j, c1.claim_id, &tmp) == 0 && !strcmp(tmp.state, "submitted"),
          "J5 claim state survived");
    rnd16(r, 4);
    CHECK(faucet_journal_claim_create(j, "full", a2, "alice", 4, r, &tmp) == FJ_EXISTS &&
          !strcmp(tmp.claim_id, c1.claim_id), "J5 the paid marker survived the restart");

    /* confirmed is terminal and releases the reservations */
    CHECK(faucet_journal_finish(j, c1.seq, "confirmed", "paid") == 0, "J3 submitted -> confirmed");
    CHECK(faucet_journal_set_state(j, c1.seq, "paused", "x") == -2, "J3 confirmed is terminal");
    CHECK(faucet_journal_finish(j, c1.seq, "expired", "x") == -2, "J3 confirmed -> expired is illegal");
    res = malloc(64 * 64);
    CHECK(faucet_journal_reserved_other(j, 0, res, 64) == 1, "J3 confirm released that claim's coins");
    free(res);
    rnd16(r, 5);
    CHECK(faucet_journal_claim_create(j, "full", a1, "alice", 4, r, &tmp) == FJ_EXISTS &&
          !strcmp(tmp.state, "confirmed"), "J1 a confirmed name stays paid (marker, never deleted)");

    /* expired -> replacement attempt */
    CHECK(faucet_journal_attempt_submitted(j, c2.seq, 120) == 0, "J3 (setup) c2 reaches submitted");
    CHECK(faucet_journal_finish(j, c2.seq, "expired", "e") == 0, "J3 submitted -> expired");
    CHECK(faucet_journal_set_state(j, c2.seq, "submitted", "") == -2, "J3 expired -> submitted is illegal");
    mk_attempt(&b, env2, 6, 1);
    CHECK(faucet_journal_attempt_sign(j, c2.seq, &b) == 0 && b.n == 2, "J3 expired -> signed (attempt 2 = replacement)");

    /* J6 unknown stops new work */
    CHECK(faucet_journal_attempt_submitted(j, c2.seq, 130) == 0, "J6 (setup) c2 submitted again");
    CHECK(faucet_journal_finish(j, c2.seq, "unknown", "no block") == 0, "J6 submitted -> unknown");
    char a4[129];
    addr_of(a4, 4);
    rnd16(r, 6);
    CHECK(faucet_journal_claim_create(j, "start", a4, NULL, 4, r, &tmp) == FJ_STOPPED,
          "J6 a claim in state unknown stops new claims");
    CHECK(faucet_journal_claim_create(j, "start", a3, NULL, 4, r, &tmp) == FJ_EXISTS,
          "J6 ... but an existing marker still answers");
    faucet_jcounts_t cnt;
    CHECK(faucet_journal_counts(j, &cnt) == 0 && cnt.unknown == 1 && cnt.open == 1, "J6 counts see the unknown claim");
    CHECK(faucet_journal_finish(j, c2.seq, "confirmed", "later evidence") == 0, "J6 unknown -> confirmed on evidence");

    /* J2 queue cap */
    {
        char a5[129], a6[129], a7[129];
        addr_of(a5, 5); addr_of(a6, 6); addr_of(a7, 7);
        rnd16(r, 7);
        CHECK(faucet_journal_claim_create(j, "start", a5, NULL, 2, r, &tmp) == FJ_CREATED, "J2 open claim 1 of cap 2");
        rnd16(r, 8);
        CHECK(faucet_journal_claim_create(j, "start", a6, NULL, 2, r, &tmp) == FJ_CREATED, "J2 open claim 2 of cap 2");
        rnd16(r, 9);
        CHECK(faucet_journal_claim_create(j, "start", a7, NULL, 2, r, &tmp) == FJ_QUEUE_FULL, "J2 the queue cap refuses");
    }
    faucet_journal_close(j);

    /* J7 storage ceiling */
    j = NULL;
    CHECK(faucet_journal_open(path, 1, &j) == 0, "J7 reopen with a 1-byte ceiling");
    CHECK(faucet_journal_storage_full(j) == 1, "J7 the ceiling is reached");
    char a8[129];
    addr_of(a8, 8);
    rnd16(r, 10);
    CHECK(faucet_journal_claim_create(j, "start", a8, NULL, 99, r, &tmp) == FJ_STORAGE_FULL,
          "J7 at the ceiling new claims stop");
    CHECK(faucet_journal_claim_create(j, "start", a3, NULL, 99, r, &tmp) == FJ_EXISTS,
          "J7 ... an existing marker still answers");
    CHECK(faucet_journal_claim_get(j, c1.claim_id, &tmp) == 0, "J7 reads keep working at the ceiling");
    faucet_journal_close(j);

    char p[128];
    snprintf(p, sizeof(p), "%s/j.db", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/j.db-wal", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/j.db-shm", dir); unlink(p);
    rmdir(dir);

    printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
    return g_failures ? 1 : 0;
}
