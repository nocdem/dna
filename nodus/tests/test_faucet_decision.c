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
 *       /status reports the remaining capacity at the fee ceiling;
 *   A2  DEADLINES: a request whose deadline has passed is 503 and makes NO
 *       node call; a live deadline is handed down to every node read of the
 *       decision (the stub records it); /status makes NO node call at all —
 *       it answers from the worker's cache even while the node is
 *       unreadable, and says "could not be read" when the cache was never
 *       filled, was invalidated by a failed refresh, or is older than
 *       FAUCET_STATUS_MAX_AGE_MS; the cache is refilled by the worker's
 *       refresh;
 *   G1  the gas-price decoder reports PRESENCE: nodus_dnac_fee_info_decode_ex
 *       says has_gas_price only for exactly one unsigned gas_price (a present
 *       0 included); an absent key, a wrong type and a repeated key leave it
 *       false while the plain decoder still reads 0 and every other field.
 * WHAT IT REQUIRES: a default build; a mkdtemp directory under /tmp (removed);
 *   no network. The builder is not exercised here (test_faucet_state does).
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the stub node answers what the test scripts; the rule is
 *   proven against those answers. The stub cannot wait, so A2 proves that the
 *   deadline is CHECKED and HANDED DOWN, not that the real adapter honours it
 *   (that is faucet_node_real.c: clocklock + bounded RPC, not stub-testable).
 */
#include "test_faucet_stub.c"

#include "protocol/nodus_cbor.h"

static faucet_verdict_t decide(env_t *e, const char *addr, int *rc) {
    faucet_verdict_t v;
    *rc = faucet_decide(&e->vt, addr, FAUCET_NODE_NO_DEADLINE, &v);
    return v;
}

/* A dnac_fee_info reply with the gas_price entry shaped by `mode`:
 * 0 absent, 1 uint `gas`, 2 wrong type (text), 3 uint written twice. */
static size_t fee_reply(uint8_t *buf, size_t cap, int mode, uint64_t gas) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, buf, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_fee_info");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, (size_t)(2 + (mode == 0 ? 0 : mode == 3 ? 2 : 1)));
    cbor_encode_cstr(&e, "base_fee"); cbor_encode_uint(&e, 1000000);
    cbor_encode_cstr(&e, "min_fee");  cbor_encode_uint(&e, 1000000);
    if (mode == 1 || mode == 3) { cbor_encode_cstr(&e, "gas_price"); cbor_encode_uint(&e, gas); }
    if (mode == 3) { cbor_encode_cstr(&e, "gas_price"); cbor_encode_uint(&e, gas); }
    if (mode == 2) { cbor_encode_cstr(&e, "gas_price"); cbor_encode_cstr(&e, "7"); }
    return cbor_encoder_len(&e);
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
    CHECK(faucet_decide(&e.vt, "xyz", FAUCET_NODE_NO_DEADLINE, &v) == -1, "D2 a bad address is refused");
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

    /* ── A2 deadlines and the status cache ───────────────────────── */
    env_open(&e, 64ULL << 20);
    e.st.name_found = 0;
    e.st.bal_native = 0;
    int calls = e.st.node_calls;
    faucet_answer_t dl;
    faucet_api_claim(&e.core, A, faucet_now_ms() - 1, &dl);
    CHECK(dl.http == 503 && !strcmp(dl.state, "refused") && e.st.node_calls == calls,
          "A2 a request past its deadline is 503 and makes NO node call");
    CHECK(faucet_journal_claim_by_address(e.j, A, &cl) == 1, "A2 ... and journals nothing");
    uint64_t live = faucet_now_ms() + 60000;
    faucet_api_claim(&e.core, A, live, &dl);
    CHECK(dl.http == 200 && !strcmp(dl.kind, "start") && e.st.node_calls > calls &&
          e.st.last_deadline == live,
          "A2 a live deadline is handed down to the node reads of the decision");

    calls = e.st.node_calls;
    e.st.self_rc = -1;                           /* the node cannot be read now */
    faucet_api_status(&e.core, &st);
    CHECK(e.st.node_calls == calls && st.open == 1 && st.full_left > 0 && st.start_left > 0,
          "A2 /status makes NO node call and answers from the worker's cache");
    e.core.status_at_ms = faucet_now_ms() - FAUCET_STATUS_MAX_AGE_MS - 1;
    faucet_api_status(&e.core, &st);
    CHECK(e.st.node_calls == calls && st.open == 0 && strstr(st.message, "could not be read") &&
          st.full_left == 0, "A2 a cache older than the maximum age is not trusted");
    e.core.status_at_ms = 0;                     /* force the worker refresh   */
    faucet_core_refresh_status(&e.core);
    faucet_api_status(&e.core, &st);
    CHECK(st.open == 0 && strstr(st.message, "could not be read"),
          "A2 a refresh that fails invalidates the cache (no stale number is kept alive)");
    e.st.self_rc = 0;
    faucet_core_refresh_status(&e.core);
    faucet_api_status(&e.core, &st);
    CHECK(st.open == 1 && st.full_left > 0, "A2 the worker's refresh refills the cache");
    env_close(&e);

    /* ── G1 gas price presence (client decoder) ───────────────────── */
    {
        static uint8_t rb[512];
        nodus_dnac_fee_info_t fi;
        bool has = true;
        size_t n = fee_reply(rb, sizeof(rb), 1, 7);
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n, &fi, &has) == 0 && has &&
              fi.gas_price == 7 && fi.min_fee == 1000000, "G1 a present gas_price is reported (and decoded)");
        n = fee_reply(rb, sizeof(rb), 1, 0);
        has = false;
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n, &fi, &has) == 0 && has && fi.gas_price == 0,
              "G1 a present 0 is a VALID price (the rule is off), distinct from unreadable");
        n = fee_reply(rb, sizeof(rb), 0, 0);
        has = true;
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n, &fi, &has) == 0 && !has && fi.min_fee == 1000000,
              "G1 an absent gas_price is NOT reported (older node) — the rest still decodes");
        CHECK(nodus_dnac_fee_info_decode(rb, n, &fi) == 0 && fi.gas_price == 0,
              "G1 the plain decoder is unchanged: absent reads 0 for its other callers");
        n = fee_reply(rb, sizeof(rb), 2, 0);
        has = true;
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n, &fi, &has) == 0 && !has,
              "G1 a wrongly typed gas_price is NOT reported");
        n = fee_reply(rb, sizeof(rb), 3, 7);
        has = true;
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n, &fi, &has) == 0 && !has,
              "G1 a repeated gas_price is NOT reported");
        n = fee_reply(rb, sizeof(rb), 1, 7);
        has = true;
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n - 3, &fi, &has) == -1 && !has,
              "G1 a truncated reply is refused and reports nothing");
        has = true;
        CHECK(nodus_dnac_fee_info_decode_ex(NULL, n, &fi, &has) == -1 && !has &&
              nodus_dnac_fee_info_decode_ex(rb, n, NULL, &has) == -1,
              "G1 NULL arguments are refused");
        CHECK(nodus_dnac_fee_info_decode_ex(rb, n, &fi, NULL) == 0 && fi.gas_price == 7,
              "G1 a NULL flag is the plain decoder");
    }

    free(g_id);
    printf("%s (%d checks, %d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
