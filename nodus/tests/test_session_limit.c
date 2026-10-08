/**
 * Nodus — per-identity client session limit (NODUS_MAX_SESSIONS_PER_IDENTITY).
 *
 * Through 0.25.4 an authentication disconnected every other session of the
 * same fingerprint (nodus_auth.c SESSION_EVICT); two devices of one account
 * on one node evicted each other in a loop. The rule is now: up to 4 live
 * sessions per identity; a new authentication past that disconnects the
 * OLDEST (lowest auth_seq) ones.
 *
 * Pins down, in-process on a plain session array (no sockets, no clock;
 * conn is a non-NULL marker the helpers never dereference):
 *   1. evict plan: with 3 older sessions + the new one (4 live) nothing is
 *      evicted; with 4 older + the new one the single oldest is chosen;
 *      with 6 older (a limit lowered or a backlog) the 3 oldest, oldest
 *      first; the new session is never chosen even when its auth_seq is not
 *      the highest; sessions of another identity, unauthenticated sessions
 *      and slots without a conn are never counted nor chosen; the plan
 *      honours `cap`.
 *   2. newest: the circuit target for an identity (find_session_by_fp in
 *      nodus_server.c) is its live session with the highest auth_seq,
 *      wherever it sits in the array; a dead or unauthenticated slot with a
 *      higher auth_seq is skipped; an unknown identity gives NULL.
 *   3. count: the presence guard in on_tcp_disconnect — the disconnecting
 *      session excluded, the identity stays online while another live
 *      session of it remains, and goes offline with the last one.
 *
 * Not covered here: nodus_auth_handle_auth's disconnect of the planned
 * slots and on_tcp_disconnect's call itself (they need a real AUTH
 * signature and live TCP connections; the decisions they take are exactly
 * these three helpers).
 *
 * RED on the tree before the change: the helpers do not exist, and the old
 * rule (evict every other session) has no "keep 4" outcome.
 */

#include "server/nodus_server.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

#define N 16

/* Marker conn: never dereferenced by the helpers under test. */
static nodus_tcp_conn_t *g_conn_marker;

static nodus_key_t g_fp_a, g_fp_b;

static nodus_session_t *table(void) {
    nodus_session_t *s = calloc(N, sizeof(*s));
    return s;
}

static void live(nodus_session_t *s, int slot, const nodus_key_t *fp,
                 uint64_t seq) {
    s[slot].conn = g_conn_marker;
    s[slot].authenticated = true;
    s[slot].client_fp = *fp;
    s[slot].auth_seq = seq;
}

static void test_evict_plan(void) {
    nodus_session_t *s = table();
    int out[N];
    int n;

    TEST("4 live (3 older + new): nothing evicted");
    CHECK(s, "calloc");
    live(s, 2, &g_fp_a, 10);
    live(s, 5, &g_fp_a, 11);
    live(s, 9, &g_fp_a, 12);
    live(s, 7, &g_fp_a, 13);           /* the new one */
    n = nodus_sessions_evict_plan(s, N, &s[7], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, N);
    CHECK(n == 0, "a fourth session must not evict anyone");
    PASS();

    TEST("5th authentication evicts the single oldest");
    live(s, 12, &g_fp_a, 14);          /* the new one */
    n = nodus_sessions_evict_plan(s, N, &s[12], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, N);
    CHECK(n == 1, "exactly one eviction");
    CHECK(out[0] == 2, "the oldest (auth_seq 10, slot 2) goes");
    PASS();

    TEST("other identity / unauthenticated / conn-less not counted");
    /* identity B: 4 live sessions, all older than A's */
    live(s, 0, &g_fp_b, 1);
    live(s, 1, &g_fp_b, 2);
    live(s, 3, &g_fp_b, 3);
    live(s, 4, &g_fp_b, 4);
    /* A-fingerprint slots that are not live */
    s[6].conn = g_conn_marker; s[6].authenticated = false;
    s[6].client_fp = g_fp_a;   s[6].auth_seq = 0;
    s[8].conn = NULL;          s[8].authenticated = true;
    s[8].client_fp = g_fp_a;   s[8].auth_seq = 5;
    n = nodus_sessions_evict_plan(s, N, &s[12], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, N);
    CHECK(n == 1 && out[0] == 2, "still only A's oldest live session");
    CHECK(nodus_sessions_count_fp(s, N, &g_fp_b, NULL) == 4,
          "B keeps 4 live sessions");
    n = nodus_sessions_evict_plan(s, N, &s[4], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, N);
    CHECK(n == 0, "B at 4 sessions: nothing evicted");
    PASS();

    TEST("backlog of 6 older + new: 3 oldest, oldest first");
    memset(s, 0, N * sizeof(*s));
    live(s, 3, &g_fp_a, 30);
    live(s, 1, &g_fp_a, 26);
    live(s, 10, &g_fp_a, 21);
    live(s, 4, &g_fp_a, 25);
    live(s, 14, &g_fp_a, 22);
    live(s, 6, &g_fp_a, 28);
    live(s, 11, &g_fp_a, 31);          /* the new one */
    n = nodus_sessions_evict_plan(s, N, &s[11], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, N);
    CHECK(n == 3, "three evictions");
    CHECK(out[0] == 10 && out[1] == 14 && out[2] == 4,
          "auth_seq 21, 22, 25 in that order");
    PASS();

    TEST("keep is never chosen; plan honours cap");
    /* keep with the LOWEST auth_seq (a re-auth path cannot make it the
     * victim of its own authentication) */
    n = nodus_sessions_evict_plan(s, N, &s[10], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, N);
    CHECK(n == 3, "three evictions");
    for (int i = 0; i < n; i++) CHECK(out[i] != 10, "keep chosen");
    CHECK(out[0] == 14 && out[1] == 4 && out[2] == 1,
          "the three oldest others: auth_seq 22, 25, 26");
    n = nodus_sessions_evict_plan(s, N, &s[11], NODUS_MAX_SESSIONS_PER_IDENTITY,
                                  out, 2);
    CHECK(n == 2 && out[0] == 10 && out[1] == 14, "cap 2: the two oldest");
    PASS();

out:
    free(s);
}

static void test_newest(void) {
    nodus_session_t *s = table();

    TEST("newest: highest auth_seq among live sessions of fp");
    CHECK(s, "calloc");
    CHECK(nodus_sessions_newest_fp(s, N, &g_fp_a) == NULL, "empty -> NULL");
    live(s, 9, &g_fp_a, 40);
    live(s, 2, &g_fp_a, 44);
    live(s, 13, &g_fp_a, 42);
    live(s, 0, &g_fp_b, 99);           /* another identity, newer */
    s[5].conn = NULL;          s[5].authenticated = true;   /* dead slot */
    s[5].client_fp = g_fp_a;   s[5].auth_seq = 50;
    s[6].conn = g_conn_marker; s[6].authenticated = false;  /* mid-auth */
    s[6].client_fp = g_fp_a;   s[6].auth_seq = 51;
    CHECK(nodus_sessions_newest_fp(s, N, &g_fp_a) == &s[2],
          "slot 2 (auth_seq 44) is A's newest live session");
    CHECK(nodus_sessions_newest_fp(s, N, &g_fp_b) == &s[0], "B's only one");
    {
        nodus_key_t none;
        memset(&none, 0x77, sizeof(none));
        CHECK(nodus_sessions_newest_fp(s, N, &none) == NULL,
              "unknown identity -> NULL");
    }
    PASS();

out:
    free(s);
}

static void test_presence_count(void) {
    nodus_session_t *s = table();

    TEST("presence guard: offline only with the last session");
    CHECK(s, "calloc");
    live(s, 3, &g_fp_a, 1);
    live(s, 8, &g_fp_a, 2);
    live(s, 4, &g_fp_b, 3);
    CHECK(nodus_sessions_count_fp(s, N, &g_fp_a, NULL) == 2, "A has 2");
    CHECK(nodus_sessions_count_fp(s, N, &g_fp_a, &s[3]) == 1,
          "slot 3 closing: another A session remains -> stays online");
    /* slot 3 gone (session_clear) */
    memset(&s[3], 0, sizeof(s[3]));
    CHECK(nodus_sessions_count_fp(s, N, &g_fp_a, &s[8]) == 0,
          "slot 8 closing: last A session -> offline");
    CHECK(nodus_sessions_count_fp(s, N, &g_fp_b, &s[8]) == 1,
          "B unaffected");
    PASS();

out:
    free(s);
}

int main(void) {
    printf("test_session_limit\n");
    g_conn_marker = (nodus_tcp_conn_t *)&g_fp_a;   /* any non-NULL address */
    memset(&g_fp_a, 0xA1, sizeof(g_fp_a));
    memset(&g_fp_b, 0xB2, sizeof(g_fp_b));

    test_evict_plan();
    test_newest();
    test_presence_count();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
