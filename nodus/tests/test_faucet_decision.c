/**
 * test_faucet_decision.c — the faucet's decision rule and claim API.
 *
 * Governing: docs/plans/2026-10-22-testnet-faucet-design.md section 6.1 and
 * the operator's answers in docs/plans/decisions/2026-10-22-testnet-test-
 * tokens-faucet-dex.md ("NODUS bakiyesi 0" for the 10 NODUS start; once per
 * chain name for the full payout; "Hayir" — START only for an address
 * without a name).
 *
 * WHAT IT PROVES
 *   D1  name found -> FULL; no name + native total 0 -> START; no name +
 *       native total > 0 -> NOT_EMPTY; a name wins over a zero balance (an
 *       address with a name is never START);
 *   D2  an error is never a zero and never "no name": a failed name_of or
 *       balance read is UNREADABLE; name_of and balance must come from the
 *       SAME committed height — a mismatch is re-read (exactly
 *       FAUCET_DECIDE_TRIES times in all), a persistent mismatch is
 *       UNREADABLE; a malformed name is UNREADABLE;
 *   A1  the API: START / FULL claims are created once, a repeat returns the
 *       same claim; a refused address gets claim id 000..0 and no journal
 *       row; "faucet empty" refuses without a marker; the queue cap refuses;
 *       a confirmed START is not paid twice; a confirmed FULL never turns
 *       into a START; an unreadable node and a wrong chain are 503 and
 *       create nothing; GET /claim answers known, unknown and the zero id;
 *       /status reports the remaining capacity at the fee ceiling.
 * WHAT IT REQUIRES: a default build; a mkdtemp directory under /tmp (removed);
 *   no network. The builder is not exercised here (test_faucet_state does).
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the stub node answers what the test scripts; the rule is
 *   proven against those answers.
 */
#include "test_faucet_stub.c"

static faucet_verdict_t decide(env_t *e, const char *addr, int *rc) {
    faucet_verdict_t v;
    *rc = faucet_decide(&e->vt, addr, &v);
    return v;
}

int main(void) {
    printf("test_faucet_decision\n");
    env_t e;
    char A[129], B[129], C[129], D[129];
    make_addr(A, 1); make_addr(B, 2); make_addr(C, 3); make_addr(D, 4);
    int rc;
    faucet_verdict_t v;

    /* ── D1 the rule ─────────────────────────────────────────────── */
    env_open(&e, 64ULL << 20);
    e.st.name_found = 1;
    snprintf(e.st.name, sizeof(e.st.name), "alice");
    v = decide(&e, A, &rc);
    CHECK(rc == 0 && v.kind == FD_FULL && !strcmp(v.name, "alice") && v.height == 1000,
          "D1 name found -> FULL (with the name and the common height)");
    e.st.name_found = 0;
    e.st.bal_native = 0;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_START, "D1 no name + native total 0 -> START");
    e.st.bal_native = 1;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_NOT_EMPTY, "D1 no name + native total 1 raw -> NOT_EMPTY");
    e.st.name_found = 1;
    e.st.bal_native = 0;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_FULL, "D1 a name with balance 0 is FULL, never START");

    /* ── D2 errors are never zero ────────────────────────────────── */
    e.st.name_rc = -1;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_UNREADABLE, "D2 a failed name_of is UNREADABLE (not 'no name')");
    e.st.name_rc = 0; e.st.name_found = 0;
    e.st.bal_rc = -1;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_UNREADABLE, "D2 a failed balance is UNREADABLE (not a zero balance)");
    e.st.bal_rc = 0;

    e.st.name_calls = 0;
    e.st.name_ch_off_always = 1;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_UNREADABLE && e.st.name_calls == FAUCET_DECIDE_TRIES,
          "D2 heights that never agree: UNREADABLE after exactly FAUCET_DECIDE_TRIES reads");
    e.st.name_ch_off_always = 0;
    e.st.name_calls = 0;
    e.st.name_ch_off_calls = 1;
    e.st.bal_native = 0;
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_START && e.st.name_calls == 2,
          "D2 one height mismatch is re-read and then decided");
    e.st.name_ch_off_calls = 0;
    e.st.bal_tip = 999;                        /* name says 1000, balance 999 */
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_UNREADABLE, "D2 name height != balance height is UNREADABLE");
    e.st.bal_tip = 1000;
    e.st.name_found = 1;
    snprintf(e.st.name, sizeof(e.st.name), "Al!ce");
    v = decide(&e, A, &rc);
    CHECK(v.kind == FD_UNREADABLE, "D2 a malformed name is UNREADABLE");
    CHECK(faucet_decide(&e.vt, "xyz", &v) == -1, "D2 a bad address is refused");
    env_close(&e);

    /* ── A1 the API ──────────────────────────────────────────────── */
    env_open(&e, 64ULL << 20);
    faucet_answer_t a = api_claim(&e, "nothex");
    CHECK(a.http == 400, "A1 a malformed address is HTTP 400");

    e.st.bal_native = 0;
    a = api_claim(&e, A);
    CHECK(a.http == 200 && !strcmp(a.state, "planned") && !strcmp(a.kind, "start") &&
          strcmp(a.claim_id, FAUCET_NO_CLAIM_ID) != 0, "A1 a START claim is created (planned)");
    char id_a[33];
    snprintf(id_a, sizeof(id_a), "%s", a.claim_id);
    a = api_claim(&e, A);
    CHECK(!strcmp(a.claim_id, id_a), "A1 asking again returns the SAME claim");

    e.st.name_found = 1;
    snprintf(e.st.name, sizeof(e.st.name), "bob");
    a = api_claim(&e, B);
    CHECK(!strcmp(a.kind, "full") && !strcmp(a.state, "planned"), "A1 a name owner gets a FULL claim");
    faucet_claim_t cl;
    CHECK(faucet_journal_claim_by_address(e.j, B, &cl) == 0 && !strcmp(cl.name, "bob"),
          "A1 the FULL claim is keyed by the name");
    char id_b[33];
    snprintf(id_b, sizeof(id_b), "%s", a.claim_id);

    e.st.name_found = 0;
    e.st.bal_native = 5;
    a = api_claim(&e, C);
    CHECK(a.http == 200 && !strcmp(a.state, "refused") && !strcmp(a.kind, "none") &&
          !strcmp(a.claim_id, FAUCET_NO_CLAIM_ID), "A1 a funded address without a name is refused (id 000..0)");
    CHECK(faucet_journal_claim_by_address(e.j, C, &cl) == 1, "A1 ... and nothing was journalled for it");

    e.st.bal_native = 0;
    e.st.self_native = 1000;                    /* below 10 NODUS + ceiling */
    a = api_claim(&e, D);
    CHECK(!strcmp(a.state, "refused") && strstr(a.message, "empty") != NULL, "A1 an empty faucet refuses");
    CHECK(faucet_journal_claim_by_address(e.j, D, &cl) == 1, "A1 ... without writing a paid marker");
    e.st.self_native = 20000000000000ULL;

    e.st.self_token = 10;                       /* tUSDT short: FULL refused, START fine */
    e.st.name_found = 1;
    snprintf(e.st.name, sizeof(e.st.name), "carol");
    a = api_claim(&e, D);
    CHECK(!strcmp(a.state, "refused"), "A1 a FULL payout needs the tUSDT too (empty tUSDT refuses)");
    e.st.self_token = 500000000ULL;
    e.st.name_found = 0;

    /* queue cap 4: A, B are open; add two more, the fifth is refused */
    char E1[129], E2[129], E3[129];
    make_addr(E1, 11); make_addr(E2, 12); make_addr(E3, 13);
    a = api_claim(&e, E1);
    CHECK(!strcmp(a.state, "planned"), "A1 open claim 3 of 4");
    a = api_claim(&e, E2);
    CHECK(!strcmp(a.state, "planned"), "A1 open claim 4 of 4");
    a = api_claim(&e, E3);
    CHECK(!strcmp(a.state, "refused") && strstr(a.message, "queue") != NULL, "A1 the queue cap refuses");

    /* GET /claim */
    faucet_answer_t g;
    faucet_api_get_claim(&e.core, id_a, &g);
    CHECK(g.http == 200 && !strcmp(g.state, "planned") && !strcmp(g.kind, "start"), "A1 GET a known claim");
    faucet_api_get_claim(&e.core, "11111111111111111111111111111111", &g);
    CHECK(g.http == 404, "A1 GET an unknown claim is 404");
    faucet_api_get_claim(&e.core, FAUCET_NO_CLAIM_ID, &g);
    CHECK(g.http == 200 && !strcmp(g.state, "refused"), "A1 GET the zero id answers 'no claim'");
    faucet_api_get_claim(&e.core, "XYZ", &g);
    CHECK(g.http == 400, "A1 GET a malformed id is 400");

    /* a confirmed START is not paid twice; the balance fell back to zero */
    faucet_claim_t ca;
    faucet_journal_claim_get(e.j, id_a, &ca);
    {
        uint8_t env[16] = {1};
        faucet_attempt_t at;
        memset(&at, 0, sizeof(at));
        at.env = env; at.env_len = sizeof(env); at.n_in = 1;
        at.inputs[0][0] = 0xEE; at.build_tip = 1; at.expiry = 2; at.scan_next = 2;
        CHECK(faucet_journal_attempt_sign(e.j, ca.seq, &at) == 0, "A1 (setup) sign the START claim");
        CHECK(faucet_journal_finish(e.j, ca.seq, "confirmed", "paid") == 0, "A1 (setup) confirm it");
    }
    e.st.bal_native = 0;
    a = api_claim(&e, A);
    CHECK(!strcmp(a.claim_id, id_a) && !strcmp(a.state, "confirmed"),
          "A1 an airdropped address with balance 0 again gets its OLD claim, not a second START");

    /* a confirmed FULL is never followed by START ("Hayir") */
    faucet_claim_t cb;
    faucet_journal_claim_get(e.j, id_b, &cb);
    {
        uint8_t env[16] = {2};
        faucet_attempt_t at;
        memset(&at, 0, sizeof(at));
        at.env = env; at.env_len = sizeof(env); at.n_in = 1;
        at.inputs[0][0] = 0xEF; at.build_tip = 1; at.expiry = 2; at.scan_next = 2;
        faucet_journal_attempt_sign(e.j, cb.seq, &at);
        faucet_journal_finish(e.j, cb.seq, "confirmed", "paid");
    }
    e.st.name_found = 1;
    snprintf(e.st.name, sizeof(e.st.name), "bob");
    e.st.bal_native = 0;                        /* it spent everything */
    a = api_claim(&e, B);
    CHECK(!strcmp(a.claim_id, id_b) && !strcmp(a.kind, "full") && !strcmp(a.state, "confirmed"),
          "A1 a name owner that spent everything gets its FULL claim back, never a START");
    CHECK(faucet_journal_claim_by_address(e.j, B, &cl) == 0 && !strcmp(cl.kind, "full"),
          "A1 ... and no START row exists for it");

    /* /status: capacity at the fee ceiling */
    faucet_status_t st;
    faucet_api_status(&e.core, &st);
    uint64_t f_nat = e.st.self_native / (e.cfg.full_native + e.cfg.fee_ceiling);
    uint64_t f_tok = e.st.self_token / e.cfg.full_token;
    CHECK(st.open == 1 && st.full_left == (f_nat < f_tok ? f_nat : f_tok) &&
          st.start_left == e.st.self_native / (e.cfg.start_native + e.cfg.fee_ceiling),
          "A1 /status: open, capacity = min(NODUS, tUSDT) at the fee ceiling");
    env_close(&e);

    /* unreadable node and wrong chain */
    env_open(&e, 64ULL << 20);
    e.st.bal_rc = -1;
    a = api_claim(&e, A);
    CHECK(a.http == 503 && !strcmp(a.state, "refused"), "A1 an unreadable node is 503");
    CHECK(faucet_journal_claim_by_address(e.j, A, &cl) == 1, "A1 ... and creates nothing");
    e.st.bal_rc = 0;
    e.st.chain[0] ^= 0xFF;
    CHECK(faucet_core_check_chain(&e.core) == 0, "A1 a node on another chain is detected");
    a = api_claim(&e, A);
    CHECK(a.http == 503, "A1 ... and the faucet refuses every claim");
    faucet_api_status(&e.core, &st);
    CHECK(st.open == 0, "A1 /status shows it closed");
    env_close(&e);

    free(g_id);
    printf("%s (%d checks, %d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
