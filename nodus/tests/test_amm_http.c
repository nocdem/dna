/**
 * test_amm_http.c -- the nodus-amm HTTP API (amm_http.c).
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 10,
 * sections 4, 6.4.7, 15, 19 "test_amm_http: request bounds of its own,
 * strict JSON, answer shapes"; givens items 82-88):
 *   H1  the request parser and its bounds: a GET, a POST with its body, the
 *       body bound is the SETTING (a body at the bound is read, one byte above
 *       it is 413, with the bound at 100 and at 20000), Transfer-Encoding 501,
 *       a POST without Content-Length 411, another method 405, a header block
 *       above 4096 bytes 431, 33 header lines 431, a request line above 256
 *       bytes 400, a query string 400, a duplicate Content-Length 400, a GET
 *       with a body 400, a bare LF 400; an incomplete body asks for more (0);
 *   H2  the strict JSON object of string values: one object, no duplicate
 *       key, no escape, no nested value, no number, no byte outside
 *       0x20..0x7e, no trailing byte, at most 8 keys;
 *   H3  `0x` + lowercase hex of an exact length, nothing else;
 *   H4  the routes against a STUB backend: the price question answers with
 *       every field and every refusal word (one per engine code), a bad
 *       direction or amount is bad_request (no backend call); the signed
 *       request of both kinds reaches the backend decoded (sender, amounts,
 *       signature bytes, text, 2592-byte key, 4627-byte signature), every
 *       delivery code has its word, open_approval carries the open request
 *       number, a body that is not exactly its kind's keys is bad_request;
 *       GET /amm/swap/<n> and GET /amm/status shapes; an unknown path 404, a
 *       wrong method 405; an answer above the response bound is a 500;
 *   H5  the server on a real loopback socket: a quote answered end to end, a
 *       body above http_max_body gets 413, an unknown path 404, the
 *       connection cap answers 503, only 127.0.0.1 is bound.
 * FLAGS: a default build; H5 uses loopback sockets (a kernel-chosen port, no
 * fixed port); no files, no network beyond loopback.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN FALSELY PASS: the backend is a stub, so the real engine and the
 * signature checks are not exercised here (test_amm_engine, test_amm_req);
 * the server loop is driven by polling a bounded number of iterations, which
 * proves a reply arrives, not its latency.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "amm_http.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static int parse(const char *s, size_t max_body, amm_http_req_t *r) {
    return amm_http_parse(s, strlen(s), max_body, r);
}

static void h1_parser(void) {
    printf("H1 request parser and bounds\n");
    amm_http_req_t r;
    CHECK(parse("GET /amm/status HTTP/1.1\r\nHost: x\r\n\r\n", 100, &r) == 1 &&
          !strcmp(r.method, "GET") && !strcmp(r.path, "/amm/status") && r.body_len == 0, "a GET");
    CHECK(parse("POST /amm/quote HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", 100, &r) == 1 &&
          r.body_len == 5 && !memcmp(r.body, "hello", 5), "a POST with its body");
    CHECK(parse("POST /amm/quote HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel", 100, &r) == 0,
          "an incomplete body: more bytes needed");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\n", 100, &r) == 0,
          "a body exactly at the bound is accepted (still coming)");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: 101\r\n\r\n", 100, &r) == -413,
          "one byte above the bound: 413");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: 16124\r\n\r\n", 20000, &r) == 0 &&
          parse("POST /x HTTP/1.1\r\nContent-Length: 20001\r\n\r\n", 20000, &r) == -413,
          "the bound is the setting: 16,124 passes at 20,000, 20,001 does not");
    CHECK(parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 100, &r) == -501, "Transfer-Encoding");
    CHECK(parse("POST /x HTTP/1.1\r\nHost: x\r\n\r\n", 100, &r) == -411, "POST without Content-Length");
    CHECK(parse("PUT /x HTTP/1.1\r\n\r\n", 100, &r) == -405, "another method");
    CHECK(parse("GET /x?a=1 HTTP/1.1\r\n\r\n", 100, &r) == -400, "a query string");
    CHECK(parse("GET /x HTTP/2.0\r\n\r\n", 100, &r) == -400, "another version");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", 100, &r) == -400,
          "a duplicate Content-Length");
    CHECK(parse("GET /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", 100, &r) == -400, "a GET with a body");
    CHECK(parse("GET /x HTTP/1.1\nHost: x\r\n\r\n", 100, &r) == -400, "a bare LF");

    char big[6000];
    size_t n = (size_t)snprintf(big, sizeof(big), "GET /x HTTP/1.1\r\nX: ");
    while (n < 4200) big[n++] = 'a';
    memcpy(big + n, "\r\n\r\n", 5);
    CHECK(parse(big, 100, &r) == -431, "a header block above 4096 bytes");
    char many[2400];
    n = (size_t)snprintf(many, sizeof(many), "GET /x HTTP/1.1\r\n");
    for (int i = 0; i < 33; i++) n += (size_t)snprintf(many + n, sizeof(many) - n, "H%d: v\r\n", i);
    memcpy(many + n, "\r\n", 3);
    CHECK(parse(many, 100, &r) == -431, "33 header lines");
    char longline[400];
    n = (size_t)snprintf(longline, sizeof(longline), "GET /");
    while (n < 300) longline[n++] = 'a';
    n += (size_t)snprintf(longline + n, sizeof(longline) - n, " HTTP/1.1\r\n\r\n");
    CHECK(parse(longline, 100, &r) == -400, "a request line above 256 bytes");
}

static void h2_json(void) {
    printf("H2 strict JSON\n");
    amm_json_t j;
    const char *v; size_t n;
    const char *ok = "{\"direction\":\"usdt_to_nodus\", \"amount\" : \"100\"}";
    CHECK(amm_json_parse(ok, strlen(ok), &j) == 0 && j.n == 2 &&
          amm_json_get(&j, "amount", &v, &n) == 1 && n == 3 && !memcmp(v, "100", 3) &&
          amm_json_get(&j, "nope", &v, &n) == 0, "an object of two strings");
    static const char *bad[] = {
        "{\"a\":\"1\",\"a\":\"2\"}", "{\"a\":\"x\\ny\"}", "{\"a\":{\"b\":\"1\"}}", "{\"a\":1}",
        "{\"a\":\"1\"} x", "{\"a\":\"1\",}", "[\"a\"]", "{\"a\":\"\xc3\xa9\"}", "{\"a\":\"1\"",
        "", "{\"a\" \"1\"}", "{a:\"1\"}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char msg[80];
        snprintf(msg, sizeof(msg), "refused: %s", bad[i][0] ? bad[i] : "(empty)");
        CHECK(amm_json_parse(bad[i], strlen(bad[i]), &j) != 0, msg);
    }
    const char *nine = "{\"a\":\"1\",\"b\":\"1\",\"c\":\"1\",\"d\":\"1\",\"e\":\"1\",\"f\":\"1\","
                       "\"g\":\"1\",\"h\":\"1\",\"i\":\"1\"}";
    CHECK(amm_json_parse(nine, strlen(nine), &j) != 0, "nine keys refused");
    const char *eight = "{\"a\":\"1\",\"b\":\"1\",\"c\":\"1\",\"d\":\"1\",\"e\":\"1\",\"f\":\"1\","
                        "\"g\":\"1\",\"h\":\"1\"}";
    CHECK(amm_json_parse(eight, strlen(eight), &j) == 0 && j.n == 8, "eight keys accepted");
    CHECK(amm_json_parse("{}", 2, &j) == 0 && j.n == 0, "the empty object");
}

static void h3_hex(void) {
    printf("H3 0x hex\n");
    uint8_t b[4];
    CHECK(amm_http_hex0x("0x0aff10ab", 10, b, 4) == 0 && b[0] == 0x0a && b[1] == 0xff && b[3] == 0xab,
          "0x0aff10ab");
    CHECK(amm_http_hex0x("0x0AFF10AB", 10, b, 4) != 0, "upper case refused");
    CHECK(amm_http_hex0x("0aff10ab00", 10, b, 4) != 0, "no 0x refused");
    CHECK(amm_http_hex0x("0x0aff10", 8, b, 4) != 0 && amm_http_hex0x("0x0aff10abcd", 12, b, 4) != 0,
          "a wrong length refused");
    CHECK(amm_http_hex0x("0x0aff10zz", 10, b, 4) != 0, "a non-hex digit refused");
}

/* ── the stub backend ─────────────────────────────────────────────────── */

typedef struct {
    int      quote_rc, swap_rc, calls;
    amm_dir_t dir; uint64_t amount;
    char     sender[64], dest[200], amt[32], mnm[32], rno[32];
    uint8_t  sig0, sig64;
    size_t   text_len; uint8_t text0; uint8_t pk0, pk_last, sg0, sg_last;
    uint32_t open_req;
    int      swap_found;
} be_t;

static be_t B;

static int b_quote(void *c, amm_dir_t dir, uint64_t amount, uint64_t dl, amm_quote_answer_t *o) {
    (void)c; (void)dl;
    B.calls++; B.dir = dir; B.amount = amount;
    if (B.quote_rc != AMM_Q_OK) return B.quote_rc;
    memset(o, 0, sizeof(*o));
    o->dir = dir; o->amount = amount; o->number = 93652445369406ULL; o->est_fee = 7;
    o->request_number = 16909060; o->valid_until = 10300;
    snprintf(o->pay_to, sizeof(o->pay_to), "0xabc");
    return AMM_Q_OK;
}
static int b_usdt(void *c, const amm_req_usdt_in_t *in, uint32_t *r, uint32_t *open) {
    (void)c;
    B.calls++;
    snprintf(B.sender, sizeof(B.sender), "%s", in->sender);
    snprintf(B.dest, sizeof(B.dest), "%s", in->destination);
    snprintf(B.amt, sizeof(B.amt), "%s", in->amount);
    snprintf(B.mnm, sizeof(B.mnm), "%s", in->minimum_to_receive);
    snprintf(B.rno, sizeof(B.rno), "%s", in->request_number);
    B.sig0 = in->signature[0]; B.sig64 = in->signature[64];
    *r = 16909060; *open = B.open_req;
    return B.swap_rc;
}
static int b_nodus(void *c, const amm_req_nodus_in_t *in, uint32_t *r, uint32_t *open) {
    (void)c;
    B.calls++;
    B.text_len = in->text_len; B.text0 = in->text[0];
    B.pk0 = in->public_key->bytes[0]; B.pk_last = in->public_key->bytes[NODUS_PK_BYTES - 1];
    B.sg0 = in->signature->bytes[0]; B.sg_last = in->signature->bytes[NODUS_SIG_BYTES - 1];
    *r = 99; *open = B.open_req;
    return B.swap_rc;
}
static int b_get(void *c, uint32_t n, amm_swap_t *o) {
    (void)c;
    if (!B.swap_found) return 1;
    memset(o, 0, sizeof(*o));
    o->req_no_bot = n; o->dir = AMM_NODUS_TO_USDT; o->amount = 5; o->quote_out = 6; o->est_fee = 7;
    o->expiry = 10300;
    snprintf(o->state, sizeof(o->state), "approved");
    return 0;
}
static int b_status(void *c, amm_engine_status_t *o) {
    (void)c;
    memset(o, 0, sizeof(*o));
    o->have_pool = 1;
    evm_u256_from_u64(&o->pool.depth_n, 3000000000000000ULL);
    evm_u256_from_u64(&o->pool.depth_u, 3000000000ULL);
    o->inflight_usdt = 100; o->room_usdt = 400; o->swaps_paused = 1;
    return 0;
}

static amm_cfg_t g_cfg;

static amm_http_ctx_t mkctx(void) {
    amm_cfg_defaults(&g_cfg);
    memset(g_cfg.foundation_eth, 0xcc, 20);
    memset(g_cfg.foundation_nodus, 'a', 128);
    snprintf(g_cfg.eip712_name, sizeof(g_cfg.eip712_name), "Nodus Swap");
    snprintf(g_cfg.expected_origin, sizeof(g_cfg.expected_origin), "https://swap.example");
    memset(g_cfg.chain_id, 0xdd, 32);
    amm_http_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.cfg = &g_cfg;
    c.be.quote = b_quote; c.be.swap_usdt = b_usdt; c.be.swap_nodus = b_nodus;
    c.be.get_swap = b_get; c.be.status = b_status;
    return c;
}

static int route(amm_http_ctx_t *c, const char *method, const char *path, const char *body,
                 char *out, size_t cap) {
    amm_http_req_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.method, sizeof(r.method), "%s", method);
    snprintf(r.path, sizeof(r.path), "%s", path);
    r.body = body; r.body_len = body ? strlen(body) : 0;
    int status = 0;
    amm_http_route(c, &r, 0, &status, out, cap);
    return status;
}

static void h4_routes(void) {
    printf("H4 routes against a stub backend\n");
    amm_http_ctx_t c = mkctx();
    char out[2048];
    memset(&B, 0, sizeof(B));

    CHECK(route(&c, "POST", "/amm/quote", "{\"direction\":\"usdt_to_nodus\",\"amount\":\"100000000\"}", out, sizeof(out)) == 200 &&
          B.dir == AMM_USDT_TO_NODUS && B.amount == 100000000ULL &&
          !strcmp(out, "{\"approved\":true,\"direction\":\"usdt_to_nodus\",\"amount\":\"100000000\","
                       "\"number\":\"93652445369406\",\"estimatedFee\":\"7\",\"requestNumber\":\"16909060\","
                       "\"validUntil\":\"10300\",\"payTo\":\"0xabc\"}"),
          "the approval answer carries direction, amount, number, estimated fee, request number, expiry, pay-to");
    static const struct { int rc; const char *word; } Q[] = {
        {AMM_Q_PAUSED, "paused"}, {AMM_Q_STOPPED, "stopped"}, {AMM_Q_BELOW_MIN, "below_minimum"},
        {AMM_Q_ABOVE_MAX, "above_maximum"}, {AMM_Q_INFLIGHT, "inflight_full"},
        {AMM_Q_NO_LIQUIDITY, "no_liquidity"}, {AMM_Q_CANNOT_PAY, "cannot_pay"},
        {AMM_Q_UNAVAILABLE, "unavailable"}, {AMM_Q_BAD, "bad_request"},
    };
    for (size_t i = 0; i < sizeof(Q) / sizeof(Q[0]); i++) {
        char want[96], msg[96];
        B.quote_rc = Q[i].rc;
        snprintf(want, sizeof(want), "{\"approved\":false,\"reason\":\"%s\"}", Q[i].word);
        snprintf(msg, sizeof(msg), "refusal word %s", Q[i].word);
        CHECK(route(&c, "POST", "/amm/quote", "{\"direction\":\"nodus_to_usdt\",\"amount\":\"5\"}", out, sizeof(out)) == 200 &&
              !strcmp(out, want) && B.dir == AMM_NODUS_TO_USDT, msg);
    }
    B.quote_rc = AMM_Q_ERR;
    CHECK(route(&c, "POST", "/amm/quote", "{\"direction\":\"nodus_to_usdt\",\"amount\":\"5\"}", out, sizeof(out)) == 500 &&
          strstr(out, "internal"), "a journal fault is a 500 internal");
    B.quote_rc = AMM_Q_OK;
    int before = B.calls;
    static const char *badq[] = {
        "{\"direction\":\"sideways\",\"amount\":\"5\"}", "{\"direction\":\"usdt_to_nodus\",\"amount\":\"0\"}",
        "{\"direction\":\"usdt_to_nodus\",\"amount\":\"05\"}", "{\"direction\":\"usdt_to_nodus\",\"amount\":\"-5\"}",
        "{\"direction\":\"usdt_to_nodus\",\"amount\":\"9223372036854775808\"}",
        "{\"direction\":\"usdt_to_nodus\"}", "{\"direction\":\"usdt_to_nodus\",\"amount\":\"5\",\"x\":\"y\"}",
        "{\"direction\":\"usdt_to_nodus\",\"amount\":5}", "nonsense",
    };
    int allbad = 1;
    for (size_t i = 0; i < sizeof(badq) / sizeof(badq[0]); i++)
        if (route(&c, "POST", "/amm/quote", badq[i], out, sizeof(out)) != 400 || !strstr(out, "bad_request"))
            allbad = 0;
    CHECK(allbad && B.calls == before, "every malformed question is 400 bad_request and never reaches the backend");

    /* the signed request, USDT -> NODUS */
    char sig[2 + 130 + 1], body[1024];
    snprintf(sig, sizeof(sig), "0x%0130x", 0);
    sig[2] = 'a'; sig[3] = 'b'; sig[2 + 128] = 'c'; sig[2 + 129] = 'd';
    char dest[129]; memset(dest, 'e', 128); dest[128] = 0;
    snprintf(body, sizeof(body),
             "{\"kind\":\"usdt_to_nodus\",\"sender\":\"0x%040x\",\"destination\":\"%s\",\"amount\":\"100000000\","
             "\"minimumToReceive\":\"5\",\"requestNumber\":\"16909060\",\"signature\":\"%s\"}", 7, dest, sig);
    B.swap_rc = AMM_HS_RECEIVED;
    CHECK(route(&c, "POST", "/amm/swap", body, out, sizeof(out)) == 200 &&
          !strcmp(out, "{\"received\":true,\"requestNumber\":\"16909060\"}") &&
          !strcmp(B.amt, "100000000") && !strcmp(B.mnm, "5") && !strcmp(B.rno, "16909060") &&
          strlen(B.sender) == 42 && !strcmp(B.dest, dest) && B.sig0 == 0xab && B.sig64 == 0xcd,
          "a USDT -> NODUS request reaches the backend decoded; delivery result received");
    static const struct { int rc; const char *word; } S[] = {
        {AMM_HS_FORMAT, "bad_format"}, {AMM_HS_CHAIN, "bad_chain"}, {AMM_HS_ADDRESS, "bad_address"},
        {AMM_HS_SIGNATURE, "bad_signature"}, {AMM_HS_REUSED, "number_reused"},
        {AMM_HS_NO_NUMBER, "unknown_number"}, {AMM_HS_AMOUNT, "amount_mismatch"},
        {AMM_HS_USED, "number_used"}, {AMM_HS_EXPIRED, "approval_expired"},
    };
    for (size_t i = 0; i < sizeof(S) / sizeof(S[0]); i++) {
        char want[96], msg[96];
        B.swap_rc = S[i].rc;
        snprintf(want, sizeof(want), "{\"received\":false,\"reason\":\"%s\"}", S[i].word);
        snprintf(msg, sizeof(msg), "delivery refusal word %s", S[i].word);
        CHECK(route(&c, "POST", "/amm/swap", body, out, sizeof(out)) == 200 && !strcmp(out, want), msg);
    }
    B.swap_rc = AMM_HS_OPEN; B.open_req = 4242;
    CHECK(route(&c, "POST", "/amm/swap", body, out, sizeof(out)) == 200 &&
          !strcmp(out, "{\"received\":false,\"reason\":\"open_approval\",\"openRequestNumber\":\"4242\"}"),
          "item 57: open_approval names the open swap");
    B.swap_rc = AMM_HS_ERR;
    CHECK(route(&c, "POST", "/amm/swap", body, out, sizeof(out)) == 500, "an internal fault is a 500");

    /* the NODUS -> USDT request: hex text, 2592-byte key, 4627-byte signature */
    static char nbody[2 * 5200 + 2 * 9300 + 400];
    static char pkh[2 + 2 * NODUS_PK_BYTES + 1], sgh[2 + 2 * NODUS_SIG_BYTES + 1];
    pkh[0] = '0'; pkh[1] = 'x'; sgh[0] = '0'; sgh[1] = 'x';
    memset(pkh + 2, '1', 2 * NODUS_PK_BYTES); pkh[2] = '0'; pkh[3] = 'a'; pkh[2 + 2 * NODUS_PK_BYTES] = 0;
    memset(sgh + 2, '2', 2 * NODUS_SIG_BYTES); sgh[2] = '0'; sgh[3] = 'b'; sgh[2 + 2 * NODUS_SIG_BYTES] = 0;
    snprintf(nbody, sizeof(nbody), "{\"kind\":\"nodus_to_usdt\",\"text\":\"0x4e6f6475\",\"publicKey\":\"%s\","
             "\"signature\":\"%s\"}", pkh, sgh);
    static char big[8192];
    B.swap_rc = AMM_HS_RECEIVED;
    CHECK(route(&c, "POST", "/amm/swap", nbody, big, sizeof(big)) == 200 &&
          !strcmp(big, "{\"received\":true,\"requestNumber\":\"99\"}") && B.text_len == 4 &&
          B.text0 == 0x4e && B.pk0 == 0x0a && B.pk_last == 0x11 && B.sg0 == 0x0b && B.sg_last == 0x22,
          "a NODUS -> USDT request reaches the backend: text, 2592-byte key, 4627-byte signature");
    snprintf(nbody, sizeof(nbody), "{\"kind\":\"nodus_to_usdt\",\"text\":\"0x4e6f6\",\"publicKey\":\"%s\","
             "\"signature\":\"%s\"}", pkh, sgh);
    CHECK(route(&c, "POST", "/amm/swap", nbody, big, sizeof(big)) == 400, "an odd-length text refused");
    snprintf(nbody, sizeof(nbody), "{\"kind\":\"nodus_to_usdt\",\"text\":\"0x4e\",\"publicKey\":\"0x11\","
             "\"signature\":\"%s\"}", sgh);
    CHECK(route(&c, "POST", "/amm/swap", nbody, big, sizeof(big)) == 400, "a short public key refused");
    snprintf(nbody, sizeof(nbody), "{\"kind\":\"nodus_to_usdt\",\"text\":\"0x4e\",\"publicKey\":\"%s\","
             "\"signature\":\"%s\",\"extra\":\"x\"}", pkh, sgh);
    CHECK(route(&c, "POST", "/amm/swap", nbody, big, sizeof(big)) == 400, "an extra key refused");
    CHECK(route(&c, "POST", "/amm/swap", "{\"kind\":\"other\"}", out, sizeof(out)) == 400 &&
          route(&c, "POST", "/amm/swap", "{\"sender\":\"x\"}", out, sizeof(out)) == 400, "an unknown or missing kind refused");
    char tbody[1024];
    snprintf(tbody, sizeof(tbody),
             "{\"kind\":\"usdt_to_nodus\",\"sender\":\"0x%040x\",\"destination\":\"%s\",\"amount\":\"1\","
             "\"minimumToReceive\":\"5\",\"requestNumber\":\"1\",\"signature\":\"0x12\"}", 7, dest);
    CHECK(route(&c, "POST", "/amm/swap", tbody, out, sizeof(out)) == 400, "a short signature refused");

    /* state and status */
    B.swap_found = 1;
    CHECK(route(&c, "GET", "/amm/swap/16909060", NULL, out, sizeof(out)) == 200 &&
          !strcmp(out, "{\"requestNumber\":\"16909060\",\"state\":\"approved\",\"direction\":\"nodus_to_usdt\","
                       "\"amount\":\"5\",\"number\":\"6\",\"estimatedFee\":\"7\",\"validUntil\":\"10300\"}"),
          "GET /amm/swap/<request number>");
    B.swap_found = 0;
    CHECK(route(&c, "GET", "/amm/swap/16909060", NULL, out, sizeof(out)) == 404 &&
          route(&c, "GET", "/amm/swap/abc", NULL, out, sizeof(out)) == 404 &&
          route(&c, "GET", "/amm/swap/0", NULL, out, sizeof(out)) == 404 &&
          route(&c, "GET", "/amm/swap/4294967296", NULL, out, sizeof(out)) == 404, "unknown swaps are 404");
    CHECK(route(&c, "GET", "/amm/status", NULL, out, sizeof(out)) == 200 &&
          strstr(out, "\"swapsPaused\":true") && strstr(out, "\"roomUsdt\":\"400\"") &&
          strstr(out, "\"reserves\":{\"nodus\":\"3000000000000000\",\"usdt\":\"3000000000\"}") &&
          strstr(out, "\"swapMinUsdt\":\"1000000\"") && strstr(out, "\"commission\":\"0\"") &&
          strstr(out, "\"foundationEthereum\":\"0xcccccccccccccccccccccccccccccccccccccccc\"") &&
          strstr(out, "\"nodusChainId\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\""),
          "GET /amm/status: reserves, settings in force, room, flags, addresses, chain id");
    CHECK(route(&c, "GET", "/amm/nothing", NULL, out, sizeof(out)) == 404 &&
          route(&c, "GET", "/amm/liquidity/add", NULL, out, sizeof(out)) == 404, "an unknown path is 404");
    CHECK(route(&c, "GET", "/amm/quote", NULL, out, sizeof(out)) == 405 &&
          route(&c, "POST", "/amm/status", "{}", out, sizeof(out)) == 405, "a wrong method is 405");
    char tiny[40];
    CHECK(route(&c, "POST", "/amm/quote", "{\"direction\":\"usdt_to_nodus\",\"amount\":\"100\"}", tiny, sizeof(tiny)) == 500 &&
          !strcmp(tiny, "{}"), "an answer above the response bound is a 500, never cut");
}

/* ── the server on a loopback socket ──────────────────────────────────── */

static int client(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}

/* Send `req`, drive the server up to 200 iterations of 20 ms until the answer
 * has arrived (a bound on a wait for an expected asynchronous event, not a
 * retry), return the status code and the body. */
static int exchange(amm_http_t *h, uint16_t port, const char *req, char *resp, size_t cap) {
    int fd = client(port);
    if (fd < 0) return -1;
    send(fd, req, strlen(req), 0);
    size_t got = 0;
    for (int it = 0; it < 200; it++) {
        amm_http_poll(h, 20);
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 0) > 0) {
            ssize_t r = recv(fd, resp + got, cap - 1 - got, 0);
            if (r > 0) got += (size_t)r;
            if (r == 0) break;
        }
    }
    resp[got] = '\0';
    close(fd);
    int status = 0;
    if (got > 12 && !strncmp(resp, "HTTP/1.1 ", 9)) status = atoi(resp + 9);
    return status;
}

static void srv_handler(void *ctx, const amm_http_req_t *req, uint64_t dl, int *status, char *body,
                        size_t cap) {
    amm_http_route(ctx, req, dl, status, body, cap);
}

static void h5_server(void) {
    printf("H5 the server on loopback\n");
    amm_http_ctx_t c = mkctx();
    memset(&B, 0, sizeof(B));
    amm_http_t *h = NULL;
    uint16_t port = 0;
    CHECK(amm_http_open(0, 2, 3000, 200, 4096, srv_handler, &c, &h, &port) == 0 && h && port != 0,
          "listening on a kernel-chosen loopback port");
    char resp[4096];
    CHECK(exchange(h, port, "POST /amm/quote HTTP/1.1\r\nContent-Length: 50\r\n\r\n"
                            "{\"direction\":\"usdt_to_nodus\",\"amount\":\"100000000\"}", resp, sizeof(resp)) == 200 &&
          strstr(resp, "\"approved\":true") && strstr(resp, "Connection: close") &&
          strstr(resp, "Content-Type: application/json"), "a quote answered end to end");
    CHECK(exchange(h, port, "POST /amm/quote HTTP/1.1\r\nContent-Length: 201\r\n\r\n", resp, sizeof(resp)) == 413,
          "a body above http_max_body (200) gets 413");
    CHECK(exchange(h, port, "GET /amm/none HTTP/1.1\r\n\r\n", resp, sizeof(resp)) == 404, "an unknown path 404");
    CHECK(exchange(h, port, "GET /amm/status HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", resp, sizeof(resp)) == 501,
          "Transfer-Encoding 501");

    /* the connection cap: two idle connections fill it, the third gets 503 */
    int a = client(port), b = client(port);
    for (int i = 0; i < 10; i++) amm_http_poll(h, 10);
    CHECK(amm_http_connections(h) == 2, "two connections held");
    int cfd = client(port);
    for (int i = 0; i < 10; i++) amm_http_poll(h, 10);
    char r3[256] = "";
    ssize_t n3 = recv(cfd, r3, sizeof(r3) - 1, MSG_DONTWAIT);
    CHECK(n3 > 0 && !strncmp(r3, "HTTP/1.1 503", 12), "the third connection is answered 503");
    close(a); close(b); close(cfd);
    for (int i = 0; i < 10; i++) amm_http_poll(h, 10);
    CHECK(amm_http_connections(h) == 0, "closed connections are dropped");
    amm_http_close(h);
    CHECK(amm_http_open(0, 0, 3000, 200, 4096, srv_handler, &c, &h, &port) != 0 &&
          amm_http_open(0, 2, 3000, 0, 4096, srv_handler, &c, &h, &port) != 0 &&
          amm_http_open(0, 65, 3000, 200, 4096, srv_handler, &c, &h, &port) != 0,
          "a zero connection cap or body bound and a cap above 64 are refused");
}

int main(void) {
    printf("test_amm_http\n");
    h1_parser();
    h2_json();
    h3_hex();
    h4_routes();
    h5_server();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
