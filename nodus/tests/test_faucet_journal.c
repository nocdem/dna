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
 *       existing marker still answers FJ_EXISTS;
 *   J8  REPLACEMENTS ARE BOUNDED: a replacement attempt frees the earlier
 *       expired envelope payloads (the evidence rows — ids, inputs, expiry —
 *       and the paid marker stay) and the live pages do not grow with the
 *       number of replacements (200 KB envelopes, five attempts);
 *   J9  a replacement at the ceiling is refused (-4) with nothing recorded
 *       and nothing freed (rolled back), and is recorded when room returns;
 *   J10 an ABSENT -wal file is not a fault, any other stat() failure is (-1:
 *       the ceiling is not judged, a claim is not admitted);
 *   J11 a row that does not read back (a column of the wrong type, a text of
 *       the wrong length or too long for its field, a blob of the wrong
 *       length) fails the read with -1 — never an empty field, never cut.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp,
 *   removed at the end; no network.
 * LEAVES BEHIND: nothing (the directory is removed).
 * HOW IT CAN LIE: single process, no crash injection — durability across a
 *   real power cut (synchronous=FULL) is SQLite's property, not shown here.
 *   J11 damages rows through a second connection; the allocation-failure
 *   path of sqlite3_column_text (NULL) is covered by the same check
 *   (a NULL/non-TEXT column is a fault) but cannot be triggered here, and a
 *   failing sqlite3_bind_* cannot be forced either — every bind is checked
 *   by construction (B_OK), not by a test.
 */
#include <sqlite3.h>
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

/* A SECOND connection to the journal file: the test looks at (and, for the
 * read-fault cases, damages) the rows behind the journal's back. */
static int64_t q_int(const char *path, const char *sql) {
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int64_t v = -1;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return v;
}

static int live_pages(const char *path) {
    return (int)(q_int(path, "PRAGMA page_count") - q_int(path, "PRAGMA freelist_count"));
}

static void q_exec(const char *path, const char *sql) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK) {
        sqlite3_busy_timeout(db, 5000);
        char *em = NULL;
        if (sqlite3_exec(db, sql, NULL, NULL, &em) != SQLITE_OK) {
            printf("  (setup sql failed: %s)\n", em ? em : "?");
            sqlite3_free(em);
        }
    }
    sqlite3_close(db);
}

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

    /* ── J8 / J9 replacements: compaction and the ceiling ─────────── */
    {
        char kp[96];
        snprintf(kp, sizeof(kp), "%s/k.db", dir);
        faucet_journal_t *k = NULL;
        CHECK(faucet_journal_open(kp, 64ULL << 20, &k) == 0, "J8 a fresh journal opens");
        char b1[129];
        addr_of(b1, 21);
        rnd16(r, 21);
        faucet_claim_t kc;
        CHECK(faucet_journal_claim_create(k, "start", b1, NULL, 4, r, &kc) == FJ_CREATED, "J8 (setup) a claim");
        enum { BIG = 200000 };
        uint8_t *big = malloc(BIG);
        memset(big, 0xAB, BIG);
        faucet_attempt_t ka;
        int64_t live2 = 0, live5 = 0;
        for (int att = 1; att <= 5; att++) {
            mk_attempt(&ka, env1, 21, 1);
            ka.env = big;
            ka.env_len = BIG;
            int sr = faucet_journal_attempt_sign(k, kc.seq, &ka);
            CHECK(sr == 0 && ka.n == att, "J8 attempt signed");
            if (att == 2) live2 = live_pages(kp);
            if (att == 5) live5 = live_pages(kp);
            if (att < 5) CHECK(faucet_journal_finish(k, kc.seq, "expired", "e") == 0, "J8 attempt expired");
        }
        CHECK(q_int(kp, "SELECT length(env) FROM attempts WHERE n=1") == 0 &&
              q_int(kp, "SELECT length(env) FROM attempts WHERE n=4") == 0 &&
              q_int(kp, "SELECT length(env) FROM attempts WHERE n=5") == BIG,
              "J8 a replacement frees the earlier expired envelope payloads; the live one stays");
        CHECK(q_int(kp, "SELECT length(wire_id)+length(intent_id)+length(inputs) FROM attempts WHERE n=1") == 192 &&
              q_int(kp, "SELECT expiry FROM attempts WHERE n=1") == 190 &&
              q_int(kp, "SELECT COUNT(*) FROM paid") == 1,
              "J8 the evidence (ids, inputs, expiry) of the freed attempts and the paid marker stay");
        CHECK(live5 > 0 && live5 - live2 <= 8,
              "J8 live pages do not grow with replacements (the freed payloads are reused)");
        CHECK(faucet_journal_attempt_latest(k, kc.seq, &got) == 0 && got.n == 5 && got.env_len == BIG,
              "J8 the latest attempt still reads back whole");
        faucet_attempt_free(&got);

        /* J9: at the ceiling a replacement is not recorded */
        CHECK(faucet_journal_finish(k, kc.seq, "expired", "e") == 0, "J9 (setup) attempt 5 expired");
        faucet_journal_close(k);
        k = NULL;
        CHECK(faucet_journal_open(kp, 1, &k) == 0, "J9 reopen with a 1-byte ceiling");
        mk_attempt(&ka, env1, 21, 1);
        ka.env = big;
        ka.env_len = BIG;
        CHECK(faucet_journal_attempt_sign(k, kc.seq, &ka) == -4,
              "J9 a replacement at the ceiling is refused (-4)");
        CHECK(q_int(kp, "SELECT COUNT(*) FROM attempts") == 5 &&
              q_int(kp, "SELECT length(env) FROM attempts WHERE n=5") == BIG,
              "J9 ... nothing was recorded and nothing was freed (rolled back)");
        CHECK(faucet_journal_claim_get(k, kc.claim_id, &tmp) == 0 && !strcmp(tmp.state, "expired"),
              "J9 ... the claim stays expired");
        faucet_journal_close(k);
        k = NULL;
        CHECK(faucet_journal_open(kp, 64ULL << 20, &k) == 0, "J9 reopen with room");
        mk_attempt(&ka, env1, 21, 1);
        ka.env = big;
        ka.env_len = BIG;
        CHECK(faucet_journal_attempt_sign(k, kc.seq, &ka) == 0 && ka.n == 6,
              "J9 with room the replacement is recorded");
        faucet_journal_close(k);
        free(big);
        unlink(kp);
        snprintf(kp, sizeof(kp), "%s/k.db-wal", dir); unlink(kp);
        snprintf(kp, sizeof(kp), "%s/k.db-shm", dir); unlink(kp);
    }

    /* ── J10 an absent -wal file is not a fault; any other stat error is ── */
    {
        char mp[96], wal[112];
        snprintf(mp, sizeof(mp), "%s/m.db", dir);
        snprintf(wal, sizeof(wal), "%s/m.db-wal", dir);
        faucet_journal_t *m = NULL;
        CHECK(faucet_journal_open(mp, 64ULL << 20, &m) == 0, "J10 a fresh journal opens");
        unlink(wal);                                   /* absent -wal */
        CHECK(faucet_journal_storage_full(m) == 0, "J10 an ABSENT -wal file is not a fault");
        CHECK(symlink("m.db-wal", wal) == 0, "J10 (setup) a -wal path that cannot be stat()ed (symlink loop)");
        char b3[129];
        addr_of(b3, 23);
        rnd16(r, 23);
        CHECK(faucet_journal_storage_full(m) == -1, "J10 any OTHER stat() error is a fault, not 'room'");
        CHECK(faucet_journal_claim_create(m, "start", b3, NULL, 4, r, &tmp) == FJ_ERR,
              "J10 ... and a claim is NOT admitted on a fault");
        unlink(wal);
        faucet_journal_close(m);
        snprintf(wal, sizeof(wal), "%s/m.db-shm", dir); unlink(wal);
        unlink(mp);
    }

    /* ── J11 a row that does not read back is a fault, never a value ── */
    {
        char np[96];
        snprintf(np, sizeof(np), "%s/n.db", dir);
        faucet_journal_t *n = NULL;
        CHECK(faucet_journal_open(np, 64ULL << 20, &n) == 0, "J11 a fresh journal opens");
        char b4[129];
        addr_of(b4, 24);
        rnd16(r, 24);
        faucet_claim_t nc;
        CHECK(faucet_journal_claim_create(n, "start", b4, NULL, 4, r, &nc) == FJ_CREATED, "J11 (setup) a claim");
        uint8_t env4[64];
        faucet_attempt_t na;
        mk_attempt(&na, env4, 24, 1);
        CHECK(faucet_journal_attempt_sign(n, nc.seq, &na) == 0, "J11 (setup) an attempt");
        CHECK(faucet_journal_claim_get(n, nc.claim_id, &tmp) == 0, "J11 (control) the claim reads");

        q_exec(np, "UPDATE claims SET address=zeroblob(5)");            /* wrong column type */
        CHECK(faucet_journal_claim_get(n, nc.claim_id, &tmp) == -1 && faucet_journal_head(n, &tmp) == -1,
              "J11 a claim column of the wrong type fails the read (-1), not an empty field");
        q_exec(np, "UPDATE claims SET address='short'");                /* wrong length */
        CHECK(faucet_journal_claim_get(n, nc.claim_id, &tmp) == -1, "J11 an address of the wrong length fails the read");
        q_exec(np, "UPDATE claims SET message=replace(hex(zeroblob(200)),'0','x')");   /* 400 chars: does not fit FJ_MSG_MAX */
        char fix[300];
        snprintf(fix, sizeof(fix), "UPDATE claims SET address='%s'", b4);
        q_exec(np, fix);
        CHECK(faucet_journal_claim_get(n, nc.claim_id, &tmp) == -1, "J11 a text that does not fit its field fails the read (never cut)");
        q_exec(np, "UPDATE claims SET message=''");
        CHECK(faucet_journal_claim_get(n, nc.claim_id, &tmp) == 0, "J11 (control) restored, it reads again");

        q_exec(np, "UPDATE attempts SET wire_id=zeroblob(3)");
        CHECK(faucet_journal_attempt_latest(n, nc.seq, &got) == -1, "J11 an attempt blob of the wrong length fails the read");
        q_exec(np, "UPDATE attempts SET wire_id=zeroblob(64), build_tip='x'");
        CHECK(faucet_journal_attempt_latest(n, nc.seq, &got) == -1, "J11 an attempt integer column of the wrong type fails the read");

        q_exec(np, "UPDATE reservations SET nul=zeroblob(3)");
        res = malloc(64 * 64);
        CHECK(faucet_journal_reserved_other(n, 0, res, 64) == -1, "J11 a reservation of the wrong length fails the read");
        free(res);
        faucet_journal_close(n);
        unlink(np);
        snprintf(np, sizeof(np), "%s/n.db-wal", dir); unlink(np);
        snprintf(np, sizeof(np), "%s/n.db-shm", dir); unlink(np);
    }

    char p[128];
    snprintf(p, sizeof(p), "%s/j.db", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/j.db-wal", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/j.db-shm", dir); unlink(p);
    rmdir(dir);

    printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
    return g_failures ? 1 : 0;
}
