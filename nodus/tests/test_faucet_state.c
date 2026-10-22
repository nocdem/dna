/**
 * test_faucet_state.c — the claim state machine and the payout build.
 *
 * Governing: docs/plans/2026-10-22-testnet-faucet-design.md section 6.2-6.6;
 * operator: "Tek islem" (FULL = ONE spend), fee ceiling "0,1 NODUS" (10^7
 * raw), "Kendi dugumune guvensin" (the local node is the evidence; an
 * unreadable block = unknown, stop and wait; never "unpaid").
 *
 * WHAT IT PROVES (REAL planner + builder + signer, stub node, real journal)
 *   F1  a FULL claim is ONE envelope with outputs [recipient NODUS 10^13]
 *       [recipient tUSDT 10^8 of the pinned token id] and only the faucet's
 *       own change; a START is ONE native output of 10^9; the fee is within
 *       the ceiling; expiry = tip + 90;
 *   F2  the fee ceiling: a planner fee above 10^7 raw pauses the claim
 *       BEFORE anything is built — no attempt row, no signature, no submit —
 *       and the claim signs on its own once the fee falls;
 *   F3  planned -> signed -> submitted -> confirmed; confirmation ONLY by an
 *       APPLIED intent id found in a completely scanned block; reservations
 *       are released on confirmation;
 *   F4  resubmission sends the SAME stored bytes, not before 3 blocks;
 *       whatever the node answers (accepted / refused / no answer) moves no
 *       claim terminal; no answer keeps the claim signed;
 *   F5  a failed inclusion is not terminal: an attempt that is never found
 *       stays submitted until the tip is past its expiry AND the scan covered
 *       every block up to the expiry; only then expired;
 *   F6  replacement only from expired, built from the old attempt's coins,
 *       sharing at least one input; with none of the old coins left the claim
 *       pauses and nothing is signed; never replaced while submitted;
 *   F7  ANY required block that cannot be read completely — the node does not
 *       hold it, or the read fails (error / timeout / malformed page) —
 *       records the claim as unknown (the cursor stays BEFORE that block),
 *       new claims are refused (503, nothing journalled), /status is closed;
 *       evidence returning moves it back to submitted and reopens admission;
 *   F8  restart from every state (planned, signed, submitted, expired,
 *       paused, unknown): a new core on the reopened journal resumes —
 *       signed resubmits the SAME bytes, submitted continues from the
 *       stored scan cursor;
 *   F9  a node that ignores the token filter (FAUCET_NODE_INCOMPLETE) pauses with
 *       "coin list incomplete", never "faucet empty"; short funding and
 *       locked coins pause; a wrong chain stops the worker;
 *   F10 one claim in flight: a second claim waits while the first is open;
 *   F11 a coin list that FILLS the node's cap is not "incomplete" by itself
 *       (the node lists the largest coins first): when the listed coins cover
 *       the payout the faucet signs — dust sent to it cannot stop it; only a
 *       truncated list whose coins do not cover the payout pauses as "coin
 *       list incomplete" (a complete list of the same coins is "funding
 *       short");
 *   F12 a node that does not REPORT a gas price (absent / malformed answer)
 *       pauses the claim — nothing built, nothing signed; an unreadable
 *       price is a fault; a reported 0 is a valid price and signs;
 *   F13 a replacement attempt at the journal's storage ceiling is not signed
 *       (the claim pauses, "history is full", no attempt row, no submit) and
 *       signs by itself when room returns.
 * WHAT IT REQUIRES: a default build (the newest pinned rule-set generation);
 *   a mkdtemp directory per scenario under /tmp (removed); no network.
 *   Signing makes it slower than the other faucet tests (ML-DSA-87).
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: block contents and the tip are scripted; the node's real
 *   mempool, CheckTx and chain are not here. A built envelope is checked by
 *   decoding it, not by executing it on a chain. F13 reaches the ceiling by
 *   reopening the journal with a 1-byte ceiling (the logic, not a real full
 *   disk).
 */
#include "test_faucet_stub.c"

static int step(env_t *e) { return faucet_worker_step(&e->core); }

static faucet_claim_t head(env_t *e) {
    faucet_claim_t c;
    memset(&c, 0, sizeof(c));
    if (faucet_journal_head(e->j, &c) != 0) snprintf(c.state, sizeof(c.state), "none");
    return c;
}

static int state_is(env_t *e, const char *s) {
    faucet_claim_t c = head(e);
    return !strcmp(c.state, s);
}

static faucet_claim_t claim_start(env_t *e, int seed) {
    char a[129];
    make_addr(a, seed);
    e->st.name_found = 0;
    e->st.bal_native = 0;
    faucet_answer_t r = api_claim(e, a);
    faucet_claim_t c;
    memset(&c, 0, sizeof(c));
    faucet_journal_claim_get(e->j, r.claim_id, &c);
    return c;
}

static faucet_claim_t claim_full(env_t *e, int seed, const char *name) {
    char a[129];
    make_addr(a, seed);
    e->st.name_found = 1;
    snprintf(e->st.name, sizeof(e->st.name), "%s", name);
    faucet_answer_t r = api_claim(e, a);
    faucet_claim_t c;
    memset(&c, 0, sizeof(c));
    faucet_journal_claim_get(e->j, r.claim_id, &c);
    return c;
}

static int attempt_of(env_t *e, const faucet_claim_t *c, faucet_attempt_t *a) {
    return faucet_journal_attempt_latest(e->j, c->seq, a);
}

static int has_nul(const faucet_attempt_t *a, const uint8_t *nul) {
    for (int i = 0; i < a->n_in; i++)
        if (!memcmp(a->inputs[i], nul, 64)) return 1;
    return 0;
}

int main(void) {
    printf("test_faucet_state\n");
    env_t e;
    faucet_attempt_t at, at2;
    faucet_claim_t cl;
    nodus_v2_spend_decoded_t d;
    int reserved_n;
    uint8_t (*res)[64] = malloc(64 * 64);

    /* ── F1 payout shapes ────────────────────────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_full(&e, 1, "alice");
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F1 planned -> signed (one step)");
    CHECK(attempt_of(&e, &cl, &at) == 0, "F1 the signed attempt is stored");
    CHECK(e.st.submit_calls == 0, "F1 nothing is submitted by the signing step");
    CHECK(nodus_v2_spend_decode(at.env, at.env_len, &d) == NODUS_V2_SPEND_OK, "F1 the stored bytes decode");
    char addr1[129];
    make_addr(addr1, 1);
    CHECK(d.n_recipient_out == 2 && !strcmp(d.out_owner[0], addr1) && !strcmp(d.out_owner[1], addr1),
          "F1 FULL = ONE spend with two recipient outputs, both to the address");
    CHECK(d.out_amount[0] == 10000000000000ULL && d.out_amount[1] == 100000000ULL,
          "F1 amounts: 100 000 NODUS (10^13 raw) and 100 tUSDT (10^8 raw)");
    static const uint8_t zero64[64] = {0};
    CHECK(!memcmp(d.out_token[0], zero64, 64) && !memcmp(d.out_token[1], e.cfg.token_id, 64),
          "F1 output 0 is native, output 1 is the pinned tUSDT id");
    int change_ok = 1;
    for (int o = 2; o < d.n_out; o++)
        if (strcmp(d.out_owner[o], e.core.self_hex)) change_ok = 0;
    CHECK(change_ok && d.n_out >= 3, "F1 every other output is the faucet's own change");
    CHECK(d.fee <= e.cfg.fee_ceiling, "F1 the fee is within the 0.1 NODUS ceiling");
    CHECK(d.expiry_height == 1000 + 90 && at.expiry == 1090 && at.build_tip == 1000 && at.scan_next == 1001,
          "F1 expiry = tip + 90, build tip and scan cursor stored");
    reserved_n = faucet_journal_reserved_other(e.j, 0, res, 64);
    CHECK(reserved_n == at.n_in && at.n_in == 2, "F1 the inputs (native + tUSDT coin) are reserved");
    faucet_attempt_free(&at);

    /* F3 + F4: submit, no resubmit before 3 blocks, same bytes after */
    CHECK(step(&e) == 1 && state_is(&e, "submitted") && e.st.submit_calls == 1, "F3 signed -> submitted (one submit)");
    attempt_of(&e, &cl, &at);
    CHECK(e.st.last_env_len == at.env_len && !memcmp(e.st.last_env, at.env, at.env_len),
          "F4 the submitted bytes are exactly the stored bytes");
    CHECK(step(&e) == 0 && e.st.submit_calls == 1, "F4 no resubmit within 3 blocks of the last submit");
    e.st.ri.tip = 1003;
    CHECK(step(&e) == 1 && e.st.submit_calls == 2 && e.st.last_env_len == at.env_len &&
          !memcmp(e.st.last_env, at.env, at.env_len),
          "F4 after 3 blocks the SAME bytes go again");
    CHECK(state_is(&e, "submitted"), "F4 still submitted: a submit answer never terminates a claim");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.scan_next == 1004, "F3 the scan covered 1001..1003 completely");
    faucet_attempt_free(&at2);
    e.st.applied_height = 1004;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    e.st.ri.tip = 1005;
    CHECK(step(&e) == 1 && state_is(&e, "none"), "F3 the applied intent id in block 1004 -> confirmed");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(!strcmp(cl.state, "confirmed") && strstr(cl.message, "1004") != NULL, "F3 confirmed, with the block");
    CHECK(faucet_journal_reserved_other(e.j, 0, res, 64) == 0, "F3 confirmation released the reservations");
    CHECK(step(&e) == 0, "F3 nothing left to do");
    faucet_attempt_free(&at);

    /* F1 START shape */
    cl = claim_start(&e, 2);
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F1 START: planned -> signed");
    attempt_of(&e, &cl, &at);
    nodus_v2_spend_decode(at.env, at.env_len, &d);
    char addr2[129];
    make_addr(addr2, 2);
    CHECK(d.n_recipient_out == 1 && !strcmp(d.out_owner[0], addr2) && d.out_amount[0] == 1000000000ULL &&
          !memcmp(d.out_token[0], zero64, 64), "F1 START = ONE native output of 10 NODUS (10^9 raw)");
    CHECK(at.n_in == 1, "F1 START spends native coins only");
    faucet_attempt_free(&at);
    env_close(&e);

    /* ── F2 the fee ceiling ──────────────────────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 3);
    e.st.gas = 1000000;                       /* units x 10^6 >> 10^7 raw */
    CHECK(step(&e) == 0 && state_is(&e, "paused"), "F2 a fee above the ceiling pauses the claim");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "ceiling") != NULL, "F2 ... and says why (ceiling / operator)");
    CHECK(attempt_of(&e, &cl, &at) == 1, "F2 NOTHING was built or signed (no attempt row)");
    CHECK(e.st.submit_calls == 0, "F2 nothing was submitted");
    CHECK(faucet_journal_reserved_other(e.j, 0, res, 64) == 0, "F2 no coin was reserved");
    CHECK(step(&e) == 0 && state_is(&e, "paused"), "F2 it stays paused while the fee stays high");
    faucet_status_t fs;
    faucet_api_status(&e.core, &fs);
    CHECK(fs.paused == 1, "F2 /status shows paused");
    e.st.gas = 0;
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F2 the claim signs by itself once the fee is within the ceiling");
    attempt_of(&e, &cl, &at);
    nodus_v2_spend_decode(at.env, at.env_len, &d);
    CHECK(d.fee <= e.cfg.fee_ceiling, "F2 ... at a fee within the ceiling");
    faucet_attempt_free(&at);
    env_close(&e);

    /* ── F4 submit answers move nothing ──────────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 4);
    step(&e);
    e.st.submit_rc = -1;                      /* no answer */
    CHECK(step(&e) == 0 && state_is(&e, "signed") && e.st.submit_calls == 1,
          "F4 no submit answer: the claim stays signed (and it is tried again)");
    e.st.submit_rc = 1;                       /* the node refused */
    CHECK(step(&e) == 1 && state_is(&e, "submitted") && e.st.submit_calls == 2,
          "F4 a node refusal is not evidence: submitted, not terminal");
    CHECK(step(&e) == 0 && state_is(&e, "submitted"), "F4 ... and nothing else moves");
    env_close(&e);

    /* ── F5 failed inclusion is not terminal; F6 replacement ─────── */
    env_open(&e, 64ULL << 20);
    cl = claim_full(&e, 5, "carol");
    step(&e); step(&e);                       /* signed, submitted */
    attempt_of(&e, &cl, &at);
    e.st.ri.tip = 1050;
    CHECK(step(&e) == 1 && state_is(&e, "submitted"), "F5 not found by block 1050: still submitted, not expired");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.n == 1 && at2.scan_next == 1051, "F5 a submitted claim is never replaced (attempt 1, cursor 1051)");
    faucet_attempt_free(&at2);
    int calls_before = e.st.submit_calls;
    e.st.ri.tip = 1091;
    CHECK(step(&e) == 1 && state_is(&e, "expired"), "F5 tip past the expiry AND blocks <= expiry all scanned -> expired");
    CHECK(e.st.submit_calls == calls_before, "F5 nothing is resubmitted past the expiry");

    /* F6: replacement from expired, same coins */
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F6 expired -> a replacement is signed");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.n == 2 && at2.build_tip == 1091 && at2.expiry == 1181 && at2.scan_next == 1092,
          "F6 attempt 2 is built at the new tip with the new expiry");
    int shared = 0;
    for (int i = 0; i < at2.n_in; i++) shared |= has_nul(&at, at2.inputs[i]);
    CHECK(shared, "F6 the replacement shares an input with the expired attempt");
    faucet_attempt_free(&at2);

    /* F6: the old coins are gone -> pause, nothing signed */
    e.st.ri.tip = 1092;
    step(&e);                                  /* submitted */
    e.st.ri.tip = 1300;                        /* past attempt 2's expiry */
    step(&e);                                  /* scans 1093..1156 (64-block bound) */
    step(&e);                                  /* scans 1157..1181, expired */
    CHECK(state_is(&e, "expired"), "F6 (setup) attempt 2 expired too");
    e.st.nat.n = 0; e.st.tok.n = 0;
    add_coin(&e.st.nat, 40, 20000000000000ULL);
    add_coin(&e.st.tok, 41, 500000000ULL);
    int n_att_before = 0;
    attempt_of(&e, &cl, &at2); n_att_before = at2.n; faucet_attempt_free(&at2);
    CHECK(step(&e) == 0 && state_is(&e, "paused"), "F6 none of the old coins left: the claim pauses");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "no longer unspent") != NULL, "F6 ... and says the old coins are gone");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.n == n_att_before, "F6 NO replacement was signed");
    faucet_attempt_free(&at2);
    /* one old coin is back: the replacement shares it and signs */
    attempt_of(&e, &cl, &at2);
    memcpy(e.st.tok.c[0].nul, at2.inputs[0], 64);   /* an old input, listed again */
    faucet_attempt_free(&at2);
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F6 with one old input unspent again the replacement signs");
    faucet_attempt_free(&at);
    env_close(&e);

    /* ── F7 unknown, unreadable ──────────────────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 6);
    step(&e); step(&e);
    e.st.ri.tip = 1002;
    e.st.not_held_below = 2000;
    CHECK(step(&e) == 1 && state_is(&e, "unknown"), "F7 a block the node does not hold -> unknown");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "not held") != NULL, "F7 ... with the reason");
    char other[129];
    make_addr(other, 60);
    e.st.name_found = 0; e.st.bal_native = 0;
    faucet_answer_t ans = api_claim(&e, other);
    CHECK(ans.http == 503 && !strcmp(ans.state, "refused"), "F7 new claims are refused while a claim is unknown");
    faucet_api_status(&e.core, &fs);
    CHECK(fs.open == 0 && strstr(fs.message, "stopped") != NULL, "F7 /status is closed and says stopped");
    CHECK(step(&e) == 0 && state_is(&e, "unknown"), "F7 it waits (no state change without evidence)");
    e.st.not_held_below = 0;
    CHECK(step(&e) == 1 && state_is(&e, "submitted"), "F7 readable evidence with no terminal fact -> back to submitted");
    env_close(&e);

    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 7);
    step(&e); step(&e);
    e.st.ri.tip = 1005;
    e.st.err_height = 1001;
    CHECK(step(&e) == 1 && state_is(&e, "unknown"),
          "F7 a block that cannot be read completely (error, timeout, malformed page) -> unknown");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "could not be read completely") != NULL, "F7 ... with the reason");
    attempt_of(&e, &cl, &at);
    CHECK(at.scan_next == 1001, "F7 ... and the scan cursor did not pass it");
    faucet_attempt_free(&at);
    make_addr(other, 62);
    e.st.name_found = 0; e.st.bal_native = 0;
    ans = api_claim(&e, other);
    CHECK(ans.http == 503 && faucet_journal_claim_by_address(e.j, other, &cl) == 1,
          "F7 an unreadable required block stops admission of new claims too (nothing journalled)");
    faucet_api_status(&e.core, &fs);
    CHECK(fs.open == 0 && strstr(fs.message, "stopped") != NULL, "F7 ... and /status is closed");
    CHECK(step(&e) == -1 && state_is(&e, "unknown"), "F7 a persistent read failure keeps it unknown (no rewrite)");
    e.st.err_height = 0;
    CHECK(step(&e) == 1 && state_is(&e, "submitted"), "F7 once readable the scan goes on and the claim is submitted again");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    attempt_of(&e, &cl, &at);
    CHECK(at.scan_next == 1006, "F7 ... through 1005");
    faucet_attempt_free(&at);
    ans = api_claim(&e, other);
    CHECK(ans.http == 200 && !strcmp(ans.state, "planned"), "F7 admission reopens with the evidence readable");
    env_close(&e);

    /* ── F8 restart from every state ─────────────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 8);
    env_reopen(&e);                            /* planned */
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F8 restart in planned: signs");
    attempt_of(&e, &cl, &at);
    env_reopen(&e);                            /* signed */
    CHECK(step(&e) == 1 && state_is(&e, "submitted") && e.st.last_env_len == at.env_len &&
          !memcmp(e.st.last_env, at.env, at.env_len), "F8 restart in signed: resubmits the SAME stored bytes");
    e.st.ri.tip = 1010;
    step(&e);                                  /* scans 1001..1010 */
    env_reopen(&e);                            /* submitted, cursor 1011 */
    e.st.scan_calls = 0;
    e.st.ri.tip = 1012;
    CHECK(step(&e) == 1 && e.st.scan_calls == 2, "F8 restart in submitted: the scan continues from the stored cursor");
    e.st.ri.tip = 1095;
    step(&e);                                  /* scans 1013..1076 (64-block bound) */
    step(&e);                                  /* scans 1077..1090, expired */
    CHECK(state_is(&e, "expired"), "F8 (setup) expired");
    env_reopen(&e);
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F8 restart in expired: the replacement is built");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.n == 2, "F8 ... as attempt 2");
    faucet_attempt_free(&at2);
    faucet_attempt_free(&at);
    env_close(&e);

    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 9);
    e.st.gas = 1000000;
    step(&e);
    env_reopen(&e);                            /* paused */
    CHECK(state_is(&e, "paused"), "F8 paused survives a restart");
    e.st.gas = 0;
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F8 restart in paused: re-planned and signed");
    step(&e);
    e.st.ri.tip = 1002;
    e.st.not_held_below = 5000;
    step(&e);
    env_reopen(&e);                            /* unknown */
    CHECK(state_is(&e, "unknown"), "F8 unknown survives a restart");
    make_addr(other, 61);
    e.st.name_found = 0; e.st.bal_native = 0;
    ans = api_claim(&e, other);
    CHECK(ans.http == 503, "F8 ... and still stops new claims");
    env_close(&e);

    /* ── F9 coin problems, wrong chain ───────────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_full(&e, 10, "dave");
    e.st.nat_rc = FAUCET_NODE_INCOMPLETE;
    CHECK(step(&e) == 0 && state_is(&e, "paused"), "F9 a native coin list the node filled with other tokens pauses");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(!strcmp(cl.message, "coin list incomplete"), "F9 ... as 'coin list incomplete' (never 'faucet empty')");
    e.st.nat_rc = 0;
    e.st.tok_rc = FAUCET_NODE_INCOMPLETE;
    step(&e);
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(!strcmp(cl.message, "coin list incomplete"), "F9 a node that ignores the token filter is the same");
    e.st.tok_rc = FAUCET_NODE_ERR;
    CHECK(step(&e) == -1 && attempt_of(&e, &cl, &at) == 1, "F9 an unreadable coin list signs nothing");
    e.st.tok_rc = 0;
    e.st.nat.n = 0;
    add_coin(&e.st.nat, 50, 1000000000000ULL);       /* 10 000 NODUS < 100 000 */
    step(&e);
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "funding") != NULL && attempt_of(&e, &cl, &at) == 1,
          "F9 short funding pauses ('waiting for funding'), nothing signed");
    e.st.nat.n = 0;
    add_coin(&e.st.nat, 51, 20000000000000ULL);
    e.st.nat.c[0].unlock_block = 5000;               /* locked beyond the tip */
    step(&e);
    CHECK(state_is(&e, "paused") && attempt_of(&e, &cl, &at) == 1, "F9 a locked coin is not spendable");
    e.st.nat.c[0].unlock_block = 0;
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F9 funded and unlocked: signs");
    env_close(&e);

    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 12);
    e.st.chain[3] ^= 0x5A;
    CHECK(step(&e) == 0 && state_is(&e, "planned") && attempt_of(&e, &cl, &at) == 1,
          "F9 a node on another chain: the worker does nothing");
    env_close(&e);

    /* ── F11 a coin list at the node's cap ───────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 30);
    e.st.nat.n = 0;
    add_coin(&e.st.nat, 70, 20000000000000ULL);      /* the largest: listed first (amount DESC) */
    for (int i = 0; i < FAUCET_COINS_MAX - 1; i++) add_coin(&e.st.nat, 100 + i, 1);   /* dust */
    e.st.nat.truncated = 1;                          /* the listing filled the cap */
    CHECK(e.st.nat.n == FAUCET_COINS_MAX, "F11 (setup) 100 coins listed, the list is truncated");
    CHECK(step(&e) == 1 && state_is(&e, "signed"),
          "F11 a list at the cap whose listed coins cover the payout signs (dust does not stop the faucet)");
    attempt_of(&e, &cl, &at);
    CHECK(at.n_in >= 1 && at.n_in <= 15 && has_nul(&at, e.st.nat.c[0].nul),
          "F11 ... spending the largest coin (the planner's dust sweep may add dust to it)");
    faucet_attempt_free(&at);
    env_close(&e);

    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 31);
    e.st.nat.n = 0;
    for (int i = 0; i < FAUCET_COINS_MAX; i++) {
        add_coin(&e.st.nat, 100 + i, 1000);          /* 100 coins of 1000 raw ...        */
        if (i < 90) e.st.nat.c[i].unlock_block = 5000;   /* ... 90 of them still locked   */
    }
    e.st.nat.truncated = 1;
    CHECK(step(&e) == 0 && state_is(&e, "paused") && attempt_of(&e, &cl, &at) == 1,
          "F11 a truncated list whose listed coins do NOT cover the payout pauses, nothing signed");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(!strcmp(cl.message, "coin list incomplete"), "F11 ... as 'coin list incomplete'");
    e.st.nat.truncated = 0;
    step(&e);
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "funding") != NULL, "F11 the same coins in a COMPLETE list are 'funding short'");
    env_close(&e);

    /* ── F12 the gas price must be reported ──────────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 32);
    e.st.gas_rc = FAUCET_NODE_UNREPORTED;
    CHECK(step(&e) == 0 && state_is(&e, "paused") && attempt_of(&e, &cl, &at) == 1,
          "F12 a node that reports no gas price pauses the claim, nothing built or signed");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "gas price") != NULL, "F12 ... and says why");
    CHECK(e.st.submit_calls == 0, "F12 nothing was submitted");
    e.st.gas_rc = FAUCET_NODE_ERR;
    CHECK(step(&e) == -1 && state_is(&e, "paused"), "F12 an unreadable price is a fault, the claim stays paused");
    e.st.gas_rc = 0;
    e.st.gas = 0;                                    /* a REPORTED 0: the rule is off */
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F12 a reported price 0 is a valid price: it signs");
    env_close(&e);

    /* ── F13 replacement at the storage ceiling ──────────────────── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 33);
    step(&e); step(&e);                              /* signed, submitted */
    e.st.ri.tip = 1091;
    step(&e);                                        /* scans 1001..1064 (64-block bound) */
    step(&e);                                        /* scans 1065..1090: expired */
    CHECK(state_is(&e, "expired"), "F13 (setup) attempt 1 expired");
    e.cfg.storage_ceiling = 1;                       /* the journal is now at its ceiling */
    env_reopen(&e);
    attempt_of(&e, &cl, &at2);
    int att_n = at2.n;
    faucet_attempt_free(&at2);
    CHECK(step(&e) == 0 && state_is(&e, "paused"), "F13 at the ceiling the replacement is NOT signed: the claim pauses");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(strstr(cl.message, "history is full") != NULL, "F13 ... and says the history is full");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.n == att_n, "F13 no replacement attempt row was recorded");
    faucet_attempt_free(&at2);
    CHECK(e.st.submit_calls == 1, "F13 nothing was submitted for the replacement");
    e.cfg.storage_ceiling = 64ULL << 20;
    env_reopen(&e);
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F13 with room again the replacement signs on its own");
    attempt_of(&e, &cl, &at2);
    CHECK(at2.n == att_n + 1, "F13 ... as the next attempt");
    faucet_attempt_free(&at2);
    env_close(&e);

    /* ── F10 one claim in flight ─────────────────────────────────── */
    env_open(&e, 64ULL << 20);
    faucet_claim_t c1 = claim_start(&e, 20);
    faucet_claim_t c2 = claim_start(&e, 21);
    step(&e); step(&e);
    faucet_claim_t h = head(&e);
    CHECK(h.seq == c1.seq && !strcmp(h.state, "submitted"), "F10 the first claim is in flight");
    CHECK(attempt_of(&e, &c2, &at) == 1, "F10 the second claim has no attempt while the first is open");
    CHECK(faucet_journal_reserved_other(e.j, c2.seq, res, 64) == 1, "F10 only the first claim's coin is reserved");
    e.st.applied_height = 1001;
    attempt_of(&e, &c1, &at);
    memcpy(e.st.applied_intent, at.intent_id, 64);
    faucet_attempt_free(&at);
    e.st.ri.tip = 1001;
    step(&e);                                  /* c1 confirmed */
    h = head(&e);
    CHECK(h.seq == c2.seq, "F10 once the first is confirmed the second is the head");
    CHECK(step(&e) == 1 && state_is(&e, "signed"), "F10 and gets signed");
    env_close(&e);

    /* ── F14 a block walk longer than one budget resumes, never restarts ── */
    env_open(&e, 64ULL << 20);
    cl = claim_start(&e, 22);
    step(&e); step(&e);                        /* signed -> submitted */
    attempt_of(&e, &cl, &at);
    e.st.applied_height = 1001;
    memcpy(e.st.applied_intent, at.intent_id, 64);
    faucet_attempt_free(&at);
    e.st.scan_pages = 5;                       /* 5 pages, 2 readable per call */
    e.st.scan_budget_pages = 2;
    e.st.scan_found_page = 4;                  /* the applied item is on the LAST page */
    e.st.ri.tip = 1001;
    CHECK(step(&e) == 1 && state_is(&e, "unknown") && e.st.pages_read == 2,
          "F14 call 1 reads pages 0-1 and runs out of budget: incomplete -> unknown (never 'not found')");
    CHECK(step(&e) == -1 && state_is(&e, "unknown") && e.st.pages_read == 4,
          "F14 call 2 resumes at page 2 (pages 2-3), still incomplete");
    CHECK(step(&e) == 1 && state_is(&e, "none") && e.st.pages_read == 5,
          "F14 call 3 reads page 4 only and finds the applied item: confirmed");
    CHECK(e.st.scan_from_zero == 1, "F14 the walk started at page 0 exactly ONCE across the three steps");
    faucet_journal_claim_get(e.j, cl.claim_id, &cl);
    CHECK(!strcmp(cl.state, "confirmed") && strstr(cl.message, "1001") != NULL,
          "F14 confirmed in block 1001, found on the resumed pages");
    env_close(&e);

    free(res);
    free(g_id);
    printf("%s (%d checks, %d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
