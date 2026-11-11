/**
 * test_amm_eth_rpc.c -- the nodus-amm Ethereum JSON-RPC provider
 * (amm_eth_rpc.c): the request texts, the strict bounded JSON parser and the
 * mapping of every answer onto the amm_eth.h seam, with CANNED answers
 * injected under the HTTP post (amm_rpc_post_fn). No network is used: the
 * libcurl transport is exercised only on the cases that fail before any
 * socket is opened.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 4 boundary rule, section 2 "Pinned for this revision", section 9,
 * section 10, section 19):
 *   R1  the request of every call: exact JSON-RPC text, method and params as
 *       execution-apis 3284ee80 shapes them (the file:line of each is in
 *       amm_eth_rpc.h): eth_chainId, eth_blockNumber, eth_getBlockByNumber
 *       ["0x..", false], eth_getLogs (block range, address, topics [topic0,
 *       null, recipient]), eth_getTransactionByHash, eth_getTransactionReceipt,
 *       eth_call (balanceOf, `input`), eth_estimateGas, eth_getBalance,
 *       eth_getTransactionCount (pending | latest), eth_sendRawTransaction,
 *       eth_gasPrice, eth_maxPriorityFeePerGas;
 *   R2  `uint` strictness (base-types.yaml:59-62): 0x0 and the 64-bit maximum
 *       are read; "0x", a leading zero, upper case, no prefix, a non-hex
 *       digit, 17 digits for a 64-bit field, a JSON number are ERR;
 *   R3  the envelope and the parser: an error object (also "execution
 *       reverted"), result and error together, neither, another id, no or
 *       another jsonrpc version, an unknown top-level key, a batch (array), an
 *       empty body, trailing bytes, an escape, a control byte, a non-ASCII
 *       byte, a duplicate key, nesting beyond the depth bound, a fraction, an
 *       exponent, a leading zero, a number of 16 digits, a truncated text, a
 *       post that fails: all AMM_ETH_ERR, never zero, never an empty list,
 *       never NOT_FOUND;
 *   R4  the size bound: an answer above max_response is ERR (the transport
 *       drops it; a post that reports a length above the cap is ERR too);
 *   R5  `null`: NOT_FOUND for get_block, get_tx and get_receipt ONLY (their
 *       schemas are oneOf [notFound, ...]); ERR for every other call;
 *   R6  get_block from the execution-apis example (block.yaml:85-124): number,
 *       hash, parentHash, timestamp; another number than asked, a missing
 *       field, an upper-case or short hash are ERR;
 *   R7  get_logs from the execution-apis example (filter.yaml:174-215):
 *       fields mapped, an empty list is OK with n = 0 (a valid answer), a
 *       list above `cap` is ERR (never cut), `removed: true`, another block,
 *       five topics, odd-length data, a log index above 32 bits, a missing
 *       field, a non-object element are ERR; data longer than 32 bytes keeps
 *       its TRUE length; an address in mixed case is accepted (address
 *       pattern);
 *   R8  get_tx from the example (transaction.yaml:15-36): from, to (null =
 *       no to), the call data length and its first four bytes; another hash,
 *       a missing input, odd-length input are ERR;
 *   R9  get_receipt from the example (transaction.yaml:144-165): status 0 / 1,
 *       block number and hash; status 2, no status, another transaction hash
 *       are ERR;
 *   R9b REQUIRED FIELDS of the cited schemas (execution-apis schemas/
 *       receipt.yaml:43-54 and :101-105, block.yaml:1-23 and :24-110,
 *       transaction.yaml:364-479 and :487-518): a receipt, a block and a
 *       transaction answer are accepted only when every required field is
 *       present and matches its type (hash32, uint, address, bytes, bytes8,
 *       bytes256, array); each required field removed, and a set of wrong
 *       types (`"logs": false`, numeric numbers, short hashes, a 7-byte nonce,
 *       a short logsBloom), is ERR. A receipt's logs are mapped (the first 8
 *       kept, `logs_total` the true count) and each is checked like an
 *       eth_getLogs log, naming the receipt's own block and transaction;
 *   R9c ELEMENTS: a block whose `transactions` are objects validates each as
 *       a TransactionInfo (`{}`, a missing `r`, a number: ERR; block.yaml:
 *       89-98); the required lists of a transaction are validated per element
 *       (R8b): accessList entries (address + storageKeys of hash32,
 *       transaction.yaml:186-204), blobVersionedHashes (hash32, :148-153),
 *       authorizationList entries (chainId, nonce, address, yParity, r, s,
 *       :59-91); a log's `data_digest` is keccak256 of the WHOLE data, so logs
 *       that differ only in a tail beyond 32 bytes differ (receipt.yaml:32-34);
 *   R10 balances: eth_getBalance and the balanceOf word, big-endian 32 bytes;
 *       65 hex digits, a balanceOf word of 31 bytes are ERR; estimate, counts,
 *       fees; the broadcast returns the hash, anything else is ERR;
 *   R11 the configuration and the transport: a URL that is not https://, one
 *       with a space, an over-long one, no post function, a bound outside
 *       range are refused; the seam table is complete; the libcurl transport
 *       refuses an http:// URL and an expired deadline without a connection,
 *       and a zero timeout cap cannot be built.
 * WHAT IT REQUIRES: a default build with libcurl (pkg-config libcurl); no
 *   network, no files. LEAVES BEHIND: nothing.
 * TLS IS NOT TESTED HERE: CURLOPT_SSL_VERIFYPEER = 1 and CURLOPT_SSL_VERIFYHOST
 *   = 2 are set in amm_rpc_curl_post and verified by READING THE SOURCE (the
 *   verifier did so too); libcurl cannot read an option back and no TLS server
 *   is contacted, so turning verification off would NOT fail any test here.
 * HOW IT CAN LIE: the canned answers are the documentation's examples and
 *   hand-written variations; real providers add fields, change spacing and
 *   differ in details no example shows. The TLS verification options
 *   (CURLOPT_SSL_VERIFYPEER / VERIFYHOST) cannot be read back from libcurl and
 *   no TLS server is contacted: they are checked by reading the source, not
 *   here. The deadline arithmetic of the transport is exercised only at its
 *   already-expired edge.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "amm_eth_rpc.h"
#include "client/nodus_evm_abi.h"
#include "crypto/hash/keccak256.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── the stub post ──────────────────────────────────────────────────── */

static char   g_resp[40000];
static size_t g_resp_len;
static int    g_post_rc = AMM_ETH_OK;
static size_t g_lie_len;                 /* a post that reports a length above the cap */
static char   g_body[4096];
static char   g_url[256];
static int    g_calls;

static void answer(const char *s) { g_resp_len = strlen(s); memcpy(g_resp, s, g_resp_len + 1); }

/* {"jsonrpc":"2.0","id":1,"result":<r>} */
static void result(const char *r) {
    char b[39000];
    snprintf(b, sizeof(b), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":%s}", r);
    answer(b);
}

static int stub_post(void *ctx, const char *url, const uint8_t *body, size_t body_len,
                     uint8_t *resp, size_t resp_cap, size_t *resp_len, uint64_t dl) {
    (void)ctx; (void)dl;
    g_calls++;
    snprintf(g_url, sizeof(g_url), "%s", url);
    size_t n = body_len < sizeof(g_body) - 1 ? body_len : sizeof(g_body) - 1;
    memcpy(g_body, body, n);
    g_body[n] = '\0';
    if (g_post_rc != AMM_ETH_OK) return g_post_rc;
    if (g_resp_len > resp_cap) return AMM_ETH_ERR;          /* what a real transport does */
    memcpy(resp, g_resp, g_resp_len);
    *resp_len = g_lie_len ? g_lie_len : g_resp_len;
    return AMM_ETH_OK;
}

static amm_eth_rpc_t *g_r;
static amm_eth_provider_t g_p;

static void mk(size_t max_response) {
    if (g_r) amm_eth_rpc_free(g_r);
    amm_eth_rpc_cfg_t c = { .url = "https://eth.example.test/v1/SECRET-KEY", .name = "stub-1",
                            .post = stub_post, .post_ctx = NULL, .max_response = max_response };
    g_r = amm_eth_rpc_new(&c);
    if (!g_r) { printf("FATAL rpc_new\n"); exit(2); }
    amm_eth_rpc_provider(g_r, &g_p);
    g_post_rc = AMM_ETH_OK;
    g_lie_len = 0;
}

static int u64call(int (*f)(void *, uint64_t *, uint64_t), uint64_t *out) { return f(g_p.ctx, out, 0); }
static int chain(uint64_t *o) { return u64call(g_p.chain_id, o); }

/* ═══ scenarios ═══════════════════════════════════════════════════════ */

static void r1_requests(void) {
    printf("R1 request texts\n");
    mk(65536);
    uint64_t u;
    uint8_t b32[32], tx[32], addr[20], tok[20], t0[32];
    memset(tx, 0xab, 32); memset(addr, 0x11, 20); memset(tok, 0xdd, 20); memset(t0, 0xee, 32);

    result("\"0x1\"");
    CHECK(chain(&u) == AMM_ETH_OK && u == 1, "eth_chainId -> 1");
    CHECK(!strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}"), "  request text");
    CHECK(!strcmp(g_url, "https://eth.example.test/v1/SECRET-KEY"), "  posted to the provider URL");
    result("\"0x2377\"");
    CHECK(u64call(g_p.block_number, &u) == AMM_ETH_OK && u == 0x2377 &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}"), "eth_blockNumber");
    result("\"0x3e8\"");
    CHECK(u64call(g_p.gas_price, &u) == AMM_ETH_OK && u == 1000 &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_gasPrice\",\"params\":[]}"), "eth_gasPrice");
    result("\"0x773c23ba\"");
    CHECK(u64call(g_p.max_priority_fee, &u) == AMM_ETH_OK && u == 0x773c23ba &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_maxPriorityFeePerGas\",\"params\":[]}"),
          "eth_maxPriorityFeePerGas");

    amm_eth_block_t blk;
    result("null");
    CHECK(g_p.get_block(g_p.ctx, 0x1b4, &blk, 0) == AMM_ETH_NOT_FOUND &&
          strstr(g_body, "\"params\":[\"0x1b4\",false]") != NULL, "eth_getBlockByNumber [\"0x1b4\",false]");
    amm_eth_log_t lg[4];
    int n = 7;
    result("[]");
    CHECK(g_p.get_logs(g_p.ctx, 0x137d3c2, tok, t0, addr, lg, 4, &n, 0) == AMM_ETH_OK && n == 0,
          "eth_getLogs on an empty block");
    CHECK(!strcmp(g_body,
          "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getLogs\",\"params\":[{\"fromBlock\":\"0x137d3c2\","
          "\"toBlock\":\"0x137d3c2\",\"address\":\"0xdddddddddddddddddddddddddddddddddddddddd\","
          "\"topics\":[\"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",null,"
          "\"0x0000000000000000000000001111111111111111111111111111111111111111\"]}]}"),
          "  one-block range, contract, topics [topic0, null, recipient word]");
    amm_eth_tx_t t;
    result("null");
    CHECK(g_p.get_tx(g_p.ctx, tx, &t, 0) == AMM_ETH_NOT_FOUND &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionByHash\",\"params\":"
                          "[\"0xabababababababababababababababababababababababababababababababab\"]}"),
          "eth_getTransactionByHash");
    amm_eth_receipt_t rc;
    CHECK(g_p.get_receipt(g_p.ctx, tx, &rc, 0) == AMM_ETH_NOT_FOUND &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":"
                          "[\"0xabababababababababababababababababababababababababababababababab\"]}"),
          "eth_getTransactionReceipt");

    result("\"0x0\"");
    CHECK(g_p.get_balance(g_p.ctx, addr, b32, 0) == AMM_ETH_OK &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":"
                          "[\"0x1111111111111111111111111111111111111111\",\"latest\"]}"), "eth_getBalance (latest)");
    result("\"0x0000000000000000000000000000000000000000000000000000000000000000\"");
    uint8_t sel[4];
    CHECK(nodus_evm_abi_selector("balanceOf(address)", sel) == 0, "the balanceOf selector is derived from its signature");
    CHECK(g_p.erc20_balance(g_p.ctx, tok, addr, b32, 0) == AMM_ETH_OK, "eth_call balanceOf");
    char want[400];
    snprintf(want, sizeof(want),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":"
             "\"0xdddddddddddddddddddddddddddddddddddddddd\",\"input\":\"0x%02x%02x%02x%02x"
             "0000000000000000000000001111111111111111111111111111111111111111\"},\"latest\"]}",
             sel[0], sel[1], sel[2], sel[3]);
    CHECK(!strcmp(g_body, want), "  to = the token, input = selector + the owner word (execution-apis `input`), block latest");
    result("\"0x7\"");
    CHECK(g_p.tx_count(g_p.ctx, addr, 1, &u, 0) == AMM_ETH_OK && u == 7 &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionCount\",\"params\":"
                          "[\"0x1111111111111111111111111111111111111111\",\"pending\"]}"), "eth_getTransactionCount pending");
    CHECK(g_p.tx_count(g_p.ctx, addr, 0, &u, 0) == AMM_ETH_OK && strstr(g_body, "\"latest\"]}") != NULL, "eth_getTransactionCount latest");
    result("\"0x5208\"");
    uint8_t in[4] = {0xa9, 0x05, 0x9c, 0xbb};
    CHECK(g_p.estimate_gas(g_p.ctx, addr, tok, in, 4, &u, 0) == AMM_ETH_OK && u == 0x5208 &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_estimateGas\",\"params\":[{\"from\":"
                          "\"0x1111111111111111111111111111111111111111\",\"to\":"
                          "\"0xdddddddddddddddddddddddddddddddddddddddd\",\"input\":\"0xa9059cbb\"},\"latest\"]}"),
          "eth_estimateGas {from, to, input}");
    uint8_t raw[3] = {0x02, 0xf8, 0x01};
    result("\"0xabababababababababababababababababababababababababababababababab\"");
    CHECK(g_p.send_raw(g_p.ctx, raw, 3, b32, 0) == AMM_ETH_OK && b32[0] == 0xab && b32[31] == 0xab &&
          !strcmp(g_body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x02f801\"]}"),
          "eth_sendRawTransaction [\"0x<raw>\"] returns the hash");
}

static void r2_uint(void) {
    printf("R2 uint strictness\n");
    mk(65536);
    uint64_t u = 99;
    struct { const char *json; int ok; uint64_t v; const char *what; } t[] = {
        { "\"0x0\"", 1, 0, "0x0" },
        { "\"0x1\"", 1, 1, "0x1" },
        { "\"0xffffffffffffffff\"", 1, UINT64_MAX, "the 64-bit maximum" },
        { "\"0x10000000000000000\"", 0, 0, "17 digits do not fit 64 bits" },
        { "\"0x\"", 0, 0, "0x alone" },
        { "\"0x00\"", 0, 0, "0x00: leading zero" },
        { "\"0x01\"", 0, 0, "0x01: leading zero" },
        { "\"0xAB\"", 0, 0, "upper case" },
        { "\"1\"", 0, 0, "no prefix" },
        { "\"0x1g\"", 0, 0, "a non-hex digit" },
        { "\"0X1\"", 0, 0, "0X prefix" },
        { "1", 0, 0, "a JSON number" },
        { "null", 0, 0, "null is ERR for eth_chainId (never zero)" },
        { "true", 0, 0, "a bool" },
        { "[\"0x1\"]", 0, 0, "an array" },
        { "{\"a\":\"0x1\"}", 0, 0, "an object" },
        { "\"\"", 0, 0, "empty text" },
        { "\" 0x1\"", 0, 0, "a space" },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        u = 99;
        result(t[i].json);
        int rc = chain(&u);
        char m[120];
        snprintf(m, sizeof(m), "chain id %s", t[i].what);
        CHECK(t[i].ok ? (rc == AMM_ETH_OK && u == t[i].v) : (rc == AMM_ETH_ERR && u == 99), m);
    }
}

static void r3_envelope(void) {
    printf("R3 the envelope and the parser\n");
    mk(65536);
    uint64_t u = 99;
    struct { const char *body; const char *what; } bad[] = {
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"nope\"}}", "an error object" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":3,\"message\":\"execution reverted\",\"data\":\"0x\"}}", "execution reverted (code 3)" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\",\"error\":{\"code\":1,\"message\":\"x\"}}", "result and error together" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1}", "neither result nor error" },
        { "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"0x1\"}", "another id" },
        { "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":\"0x1\"}", "a null id" },
        { "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":\"0x1\"}", "a string id" },
        { "{\"id\":1,\"result\":\"0x1\"}", "no jsonrpc" },
        { "{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":\"0x1\"}", "jsonrpc 1.0" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\",\"extra\":1}", "an unknown top-level key" },
        { "[{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}]", "a batch (array)" },
        { "", "an empty body" },
        { "null", "a null document" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"} x", "trailing bytes" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}{}", "two documents" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x\\u0031\"}", "an escape in a string" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\t\"}", "a control byte in a string" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x\xc3\xa9\"}", "a non-ASCII byte" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":1,\"result\":\"0x1\"}", "a duplicate key" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1.0,\"result\":\"0x1\"}", "a fraction" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1e0,\"result\":\"0x1\"}", "an exponent" },
        { "{\"jsonrpc\":\"2.0\",\"id\":01,\"result\":\"0x1\"}", "a leading zero in a number" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"", "a truncated text" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1}", "an unterminated string" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\",}", "a trailing comma" },
        { "{\"jsonrpc\":\"2.0\" \"id\":1,\"result\":\"0x1\"}", "a missing comma" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":tru}", "a bad literal" },
        { "{'jsonrpc':'2.0','id':1,'result':'0x1'}", "single quotes" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[[[[[[[[[[\"0x1\"]]]]]]]]]]}", "nesting beyond the depth bound" },
        { "{\"jsonrpc\":\"2.0\",\"id\":1234567890123456,\"result\":\"0x1\"}", "a number of 16 digits" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        u = 99;
        answer(bad[i].body);
        char m[120];
        snprintf(m, sizeof(m), "ERR: %s", bad[i].what);
        CHECK(chain(&u) == AMM_ETH_ERR && u == 99, m);
    }
    /* what IS accepted: whitespace between tokens, the keys in any order */
    answer(" {\n \"result\" : \"0x1\" ,\t\"id\" : 1 , \"jsonrpc\" : \"2.0\" } \n");
    CHECK(chain(&u) == AMM_ETH_OK && u == 1, "whitespace and key order are free");
    /* a transport that fails */
    g_post_rc = AMM_ETH_ERR;
    u = 99;
    CHECK(chain(&u) == AMM_ETH_ERR && u == 99, "a post that fails (HTTP status != 200, timeout, TLS): ERR");
    g_post_rc = AMM_ETH_OK;
    g_resp_len = 0;
    CHECK(chain(&u) == AMM_ETH_ERR, "an empty answer: ERR");
    /* none of the failures is a NOT_FOUND */
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"x\"}}");
    uint8_t h[32] = {0};
    amm_eth_block_t b; amm_eth_tx_t t; amm_eth_receipt_t r;
    CHECK(g_p.get_block(g_p.ctx, 1, &b, 0) == AMM_ETH_ERR && g_p.get_tx(g_p.ctx, h, &t, 0) == AMM_ETH_ERR &&
          g_p.get_receipt(g_p.ctx, h, &r, 0) == AMM_ETH_ERR, "an error object is ERR, not NOT_FOUND, on the three calls that have NOT_FOUND");
}

static void r4_size(void) {
    printf("R4 the size bound\n");
    mk(1024);
    char big[3000];
    uint64_t u = 99;
    memset(big, 'a', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    char body[3200];
    snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\",\"x\":\"%s\"}", big);
    answer(body);
    CHECK(chain(&u) == AMM_ETH_ERR && u == 99, "an answer above max_response (1024): ERR");
    result("\"0x1\"");
    CHECK(chain(&u) == AMM_ETH_OK && u == 1, "a small answer passes with the same bound");
    g_lie_len = 5000;                                 /* a post that reports more than the cap */
    CHECK(chain(&u) == AMM_ETH_ERR, "a post that reports a length above the cap: ERR");
    g_lie_len = 0;
    /* many values: more nodes than the bound allows is refused, not cut */
    mk(AMM_RPC_RESP_CEIL);
    static char arr[39000];
    size_t o = 0;
    o += (size_t)snprintf(arr + o, sizeof(arr) - o, "[");
    for (int i = 0; i < 6000; i++) o += (size_t)snprintf(arr + o, sizeof(arr) - o, "%s\"0x1\"", i ? "," : "");
    snprintf(arr + o, sizeof(arr) - o, "]");
    result(arr);
    amm_eth_log_t lg[4]; int n = 0;
    uint8_t c[20] = {0}, t0[32] = {0}, to[20] = {0};
    CHECK(g_p.get_logs(g_p.ctx, 1, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "a list of 6000 values above the cap of 4: ERR (never cut)");
}

static void r5_null(void) {
    printf("R5 null\n");
    mk(65536);
    result("null");
    uint64_t u = 99;
    uint8_t h[32] = {0}, a20[20] = {0}, w[32];
    int n = 0;
    amm_eth_block_t b; amm_eth_tx_t t; amm_eth_receipt_t r; amm_eth_log_t lg[2];
    CHECK(g_p.get_block(g_p.ctx, 5, &b, 0) == AMM_ETH_NOT_FOUND, "get_block: null = NOT_FOUND");
    CHECK(g_p.get_tx(g_p.ctx, h, &t, 0) == AMM_ETH_NOT_FOUND, "get_tx: null = NOT_FOUND");
    CHECK(g_p.get_receipt(g_p.ctx, h, &r, 0) == AMM_ETH_NOT_FOUND, "get_receipt: null = NOT_FOUND");
    CHECK(chain(&u) == AMM_ETH_ERR && u == 99, "eth_chainId: null = ERR");
    CHECK(u64call(g_p.block_number, &u) == AMM_ETH_ERR, "eth_blockNumber: null = ERR");
    CHECK(g_p.get_logs(g_p.ctx, 5, a20, h, a20, lg, 2, &n, 0) == AMM_ETH_ERR, "eth_getLogs: null = ERR (not an empty list)");
    CHECK(g_p.get_balance(g_p.ctx, a20, w, 0) == AMM_ETH_ERR, "eth_getBalance: null = ERR (not zero)");
    CHECK(g_p.erc20_balance(g_p.ctx, a20, a20, w, 0) == AMM_ETH_ERR, "eth_call: null = ERR (not zero)");
    CHECK(g_p.tx_count(g_p.ctx, a20, 1, &u, 0) == AMM_ETH_ERR, "eth_getTransactionCount: null = ERR");
    CHECK(g_p.estimate_gas(g_p.ctx, a20, a20, NULL, 0, &u, 0) == AMM_ETH_ERR, "eth_estimateGas: null = ERR");
    CHECK(u64call(g_p.gas_price, &u) == AMM_ETH_ERR && u64call(g_p.max_priority_fee, &u) == AMM_ETH_ERR, "fee reads: null = ERR");
    uint8_t raw[1] = {2};
    CHECK(g_p.send_raw(g_p.ctx, raw, 1, w, 0) == AMM_ETH_ERR, "eth_sendRawTransaction: null = ERR");
}

/* first occurrence of `from` in `src` replaced by `to`, into dst (cap bytes) */
static char *subst(const char *src, const char *from, const char *to, char *dst, size_t cap) {
    const char *p = strstr(src, from);
    if (!p) { snprintf(dst, cap, "%s", src); return dst; }
    snprintf(dst, cap, "%.*s%s%s", (int)(p - src), src, to, p + strlen(from));
    return dst;
}

/* the field `key` made absent: its key renamed ("~..."), the value kept */
static char *drop_key(const char *src, const char *key, char *dst, size_t cap) {
    char pat[80], rep[80];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    snprintf(rep, sizeof(rep), "\"~%s\":", key + 1);
    return subst(src, pat, rep, dst, cap);
}

#define Z64 "0000000000000000000000000000000000000000000000000000000000000000"
#define BLOOM "0x" Z64 Z64 Z64 Z64 Z64 Z64 Z64 Z64

/* a transaction object of type 0x0 (legacy) with the required fields of
 * transaction.yaml:364-479 and :487-518; `hash`, `to` (a JSON value) and
 * `input` are arguments (the example values are transaction.yaml:15-36) */
#define TX_FIELDS(hash, to, input) \
    "{\"blockHash\":\"0x510efccf44a192e6e34bcb439a1947e24b86244280762cbb006858c237093fda\"," \
    "\"blockNumber\":\"0x422\",\"blockTimestamp\":\"0x11\",\"from\":\"0xfe3b557e8fb62b89f4916b721be55ceb828dbd73\"," \
    "\"gas\":\"0x5208\",\"gasPrice\":\"0x3b9aca00\",\"hash\":\"" hash "\",\"input\":\"" input "\"," \
    "\"nonce\":\"0x1\",\"to\":" to ",\"transactionIndex\":\"0x0\",\"value\":\"0x0\",\"type\":\"0x0\"," \
    "\"v\":\"0xfe7\",\"r\":\"0x84caf09aefbd5e539295acc67217563438a4efb224879b6855f56857fa2037d3\"," \
    "\"s\":\"0x5e863be3829812c81439f0ae9d8ecb832b531d651fb234c848d1bf45e62be8b9\"}"

/* the example of block.yaml:85-124 with every field block.yaml:1-23 requires */
#define BLOCK_OK(num, hash, parent, ts) \
    "{\"number\":\"" num "\",\"hash\":\"" hash "\",\"parentHash\":\"" parent "\",\"timestamp\":\"" ts "\"," \
    "\"mixHash\":\"0x24900fb3da77674a861c428429dce0762707ecb6052325bbd9b3c64e74b5af9d\"," \
    "\"nonce\":\"0x378da40ff335b070\"," \
    "\"sha3Uncles\":\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"," \
    "\"logsBloom\":\"" BLOOM "\"," \
    "\"transactionsRoot\":\"0x4d0c8e91e16bdff538c03211c5c73632ed054d00a7e210c0eb25146c20048126\"," \
    "\"stateRoot\":\"0x91309efa7e42c1f137f31fe9edbe88ae087e6620d0d59031324da3e2f4f93233\"," \
    "\"receiptsRoot\":\"0x68461ab700003503a305083630a8fb8d14927238f0bc8b6b3d246c0c64f21f4a\"," \
    "\"extraData\":\"0xd583010502846765746885676f312e37856c696e7578\",\"size\":\"0x334\"," \
    "\"gasLimit\":\"0x47e7c4\",\"gasUsed\":\"0x37993\"," \
    "\"miner\":\"0xb42b6c4a95406c78ff892d270ad20b22642e102d\",\"difficulty\":\"0x66e619a\"," \
    "\"transactions\":[\"0xa0807e117a8dd124ab949f460f08c36c72b710188f01609595223b325e58e0fc\"]," \
    "\"uncles\":[],\"baseFeePerGas\":\"0x7\",\"withdrawals\":[{\"index\":\"0x0\",\"validatorIndex\":\"0x9d8c0\"," \
    "\"address\":\"0xb9d7934878b5fb9610b3fe8a5e441e8fad7e293f\",\"amount\":\"0x11a33e3760\"}]}"

#define H1 "0xd5f1812548be429cbdc6376b29611fc49e06f1359758c4ceaaa3b393e2239f9c"
#define H2 "0x1f68ac259155e2f38211ddad0f0a15394d55417b185a93923e2abe71bb7a4d6d"

static void r6_block(void) {
    printf("R6 get_block\n");
    mk(65536);
    amm_eth_block_t b;
    const char *good0 = BLOCK_OK("0x68b3", H1, H2, "0x5835c54d");
    result(BLOCK_OK("0x68b3", H1, H2, "0x5835c54d"));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_OK && b.number == 0x68b3 && b.timestamp == 0x5835c54d &&
          b.hash[0] == 0xd5 && b.hash[31] == 0x9c && b.parent[0] == 0x1f && b.parent[31] == 0x6d,
          "the example block maps: number, hash, parentHash, timestamp (extra fields ignored)");
    CHECK(g_p.get_block(g_p.ctx, 0x68b4, &b, 0) == AMM_ETH_ERR, "a block with another number than asked: ERR");
    result("{\"number\":\"0x68b3\",\"hash\":\"" H1 "\",\"timestamp\":\"0x1\"}");
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a missing parentHash: ERR");
    result(BLOCK_OK("0x68b3", "0xD5f1812548be429cbdc6376b29611fc49e06f1359758c4ceaaa3b393e2239f9c", H2, "0x1"));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "an upper-case hash (hash32 is lower case): ERR");
    result(BLOCK_OK("0x68b3", "0xd5f1", H2, "0x1"));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a short hash: ERR");
    result(BLOCK_OK("0x68b3", H1, H2, "0x01"));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a timestamp with a leading zero: ERR");
    result(BLOCK_OK("0x068b3", H1, H2, "0x1"));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a number with a leading zero: ERR");
    /* the member cap AMM_RPC_OBJ_MEMBERS = 64 per object (bounds the duplicate-key
     * scan): the example block has 21 top-level keys; + 43 extra keys = 64 members is
     * accepted, + 44 = 65 is ERR */
    {
        static char wide[8192];
        for (int extra = 43; extra <= 44; extra++) {
            size_t w = 0;
            wide[w++] = '{';
            for (int k = 0; k < extra; k++)
                w += (size_t)snprintf(wide + w, sizeof(wide) - w, "\"x%d\":0,", k);
            snprintf(wide + w, sizeof(wide) - w, "%s", good0 + 1);
            result(wide);
            if (extra == 43)
                CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_OK, "a block object of exactly 64 members: OK");
            else
                CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a block object of 65 members: ERR (member cap)");
        }
    }
    /* every required field (block.yaml:1-23), removed: ERR */
    static const char *breq[] = { "hash", "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot",
        "receiptsRoot", "logsBloom", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash",
        "nonce", "size", "transactions", "uncles" };
    const char *good = BLOCK_OK("0x68b3", H1, H2, "0x5835c54d");
    char b2[3000];
    for (size_t i = 0; i < sizeof(breq) / sizeof(breq[0]); i++) {
        char m[100];
        result(drop_key(good, breq[i], b2, sizeof(b2)));
        snprintf(m, sizeof(m), "block without `%s`: ERR", breq[i]);
        CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, m);
    }
    result(subst(good, "\"nonce\":\"0x378da40ff335b070\"", "\"nonce\":\"0x378da40ff335b07\"", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a 7-byte nonce (bytes8): ERR");
    result(subst(good, "\"size\":\"0x334\"", "\"size\":820", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a numeric size: ERR");
    result(subst(good, "\"uncles\":[]", "\"uncles\":false", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "uncles that are not an array: ERR");
    result(subst(good, "\"uncles\":[]", "\"uncles\":[\"0x12\"]", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "an uncle that is not a hash32: ERR");
    result(subst(good, "\"transactions\":[\"0xa0807e", "\"transactions\":[\"0xA0807e", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a transaction hash in upper case: ERR");
    result(subst(good, "\"transactions\":[\"0xa0807e117a8dd124ab949f460f08c36c72b710188f01609595223b325e58e0fc\"]",
                 "\"transactions\":true", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "transactions that are not an array: ERR");
    result(subst(good, "\"miner\":\"0xb42b6c4a95406c78ff892d270ad20b22642e102d\"", "\"miner\":\"0xb42b\"", b2, sizeof(b2)));
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a short miner address: ERR");
    /* `transactions` as OBJECTS (block.yaml:89-98, anyOf full transactions): each
     * must be a TransactionInfo with its required fields */
    {
        char txs[2000], txbad[2000], blk[4000];
        snprintf(txs, sizeof(txs), TX_FIELDS("0xa52be92809541220ee0aaaede6047d9a6c5d0cd96a517c854d944ee70a0ebb44",
                 "\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"", "0xa9059cbb0000"));
        const char *old = "\"transactions\":[\"0xa0807e117a8dd124ab949f460f08c36c72b710188f01609595223b325e58e0fc\"]";
        char rep[2100];
        snprintf(rep, sizeof(rep), "\"transactions\":[%s]", txs);
        result(subst(good, old, rep, blk, sizeof(blk)));
        CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_OK, "a block whose transactions are complete objects: OK");
        snprintf(rep, sizeof(rep), "\"transactions\":[{}]");
        result(subst(good, old, rep, blk, sizeof(blk)));
        CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a transaction object `{}`: ERR");
        drop_key(txs, "r", txbad, sizeof(txbad));
        snprintf(rep, sizeof(rep), "\"transactions\":[%s]", txbad);
        result(subst(good, old, rep, blk, sizeof(blk)));
        CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a transaction object without `r`: ERR");
        snprintf(rep, sizeof(rep), "\"transactions\":[%s,{\"hash\":\"0x12\"}]", txs);
        result(subst(good, old, rep, blk, sizeof(blk)));
        CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a valid object followed by an incomplete one: ERR");
        snprintf(rep, sizeof(rep), "\"transactions\":[1]");
        result(subst(good, old, rep, blk, sizeof(blk)));
        CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a transaction element that is a number: ERR");
    }
    result("[]");
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "an array instead of a block: ERR");
    result("\"0x1\"");
    CHECK(g_p.get_block(g_p.ctx, 0x68b3, &b, 0) == AMM_ETH_ERR, "a string instead of a block: ERR");
}

/* the example of filter.yaml:174-215 (first log) */
#define LOG1(idx, bn, data, topics) \
    "{\"logIndex\":\"" idx "\",\"removed\":false,\"blockNumber\":\"" bn "\",\"blockTimestamp\":\"0x11\"," \
    "\"blockHash\":\"0xfc139f5e2edee9e9c888d8df9a2d2226133a9bd87c88ccbd9c930d3d4c9f9ef5\"," \
    "\"transactionHash\":\"0x66e7a140c8fa27fe98fde923defea7562c3ca2d6bb89798aabec65782c08f63d\"," \
    "\"transactionIndex\":\"0x0\",\"address\":\"0x42699a7612a82f1d9c36148af9c77354759b210b\"," \
    "\"data\":\"" data "\",\"topics\":[" topics "]}"
#define D32 "0x0000000000000000000000000000000000000000000000000000000000000004"
#define TOPIC "\"0x04474795f5b996ff80cb47c148d4c5ccdbe09ef27551820caa9c2f8ed149cce3\""

static void r7_logs(void) {
    printf("R7 get_logs\n");
    mk(65536);
    amm_eth_log_t lg[4];
    int n = -1;
    uint8_t c[20] = {0}, t0[32] = {0}, to[20] = {0};
    char b[2000];
    result("[" LOG1("0x0", "0x233", D32, TOPIC) "]");
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_OK && n == 1, "the example log is read");
    CHECK(lg[0].log_index == 0 && lg[0].block_number == 0x233 && lg[0].n_topics == 1 && lg[0].topics[0][0] == 0x04 &&
          lg[0].topics[0][31] == 0xe3 && lg[0].data_len == 32 && lg[0].data[31] == 4 && lg[0].address[0] == 0x42 &&
          lg[0].address[19] == 0x0b && lg[0].tx[0] == 0x66 && lg[0].block_hash[0] == 0xfc,
          "  every field is mapped");
    snprintf(b, sizeof(b), "[%s,%s]", LOG1("0x0", "0x233", D32, TOPIC), LOG1("0x5", "0x233", D32, TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_OK && n == 2 && lg[1].log_index == 5, "two logs, in order");
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 1, &n, 0) == AMM_ETH_ERR, "two logs above cap 1: ERR (never cut)");
    result("[]");
    n = 9;
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_OK && n == 0, "an empty list is a valid answer: OK, n = 0");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x0", "0x234", D32, TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "a log of another block: ERR");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x0", "0x233", "0x000", TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "odd-length data: ERR");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x0", "0x233", "0x00000000000000000000000000000000000000000000000000000000000000000004", TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_OK && n == 1 && lg[0].data_len == 34,
          "data of 34 bytes keeps its TRUE length (the watcher then refuses it)");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x0", "0x233", D32, TOPIC "," TOPIC "," TOPIC "," TOPIC "," TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "five topics: ERR (the table holds four)");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x100000000", "0x233", D32, TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "a log index above 32 bits: ERR");
    snprintf(b, sizeof(b), "[%s]", LOG1("0xffffffff", "0x233", D32, TOPIC));
    result(b);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_OK && lg[0].log_index == 0xffffffffu, "the largest 32-bit log index");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x0", "0x233", D32, TOPIC));
    char rem[2000];
    const char *p = strstr(b, "\"removed\":false");
    snprintf(rem, sizeof(rem), "%.*s\"removed\":true%s", (int)(p - b), b, p + strlen("\"removed\":false"));
    result(rem);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "removed: true: ERR");
    snprintf(rem, sizeof(rem), "%.*s\"removed\":0%s", (int)(p - b), b, p + strlen("\"removed\":false"));
    result(rem);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "removed as a number: ERR");
    result("[" LOG1("0x0", "0x233", D32, "\"0x04474795f5b996ff80cb47c148d4c5ccdbe09ef27551820caa9c2f8ed149cc\"") "]");
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "a 31-byte topic: ERR");
    result("[1]");
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "a non-object element: ERR");
    result("[{\"logIndex\":\"0x0\"}]");
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_ERR, "a log with missing fields: ERR");
    snprintf(b, sizeof(b), "[%s]", LOG1("0x0", "0x233", D32, TOPIC));
    char mixed[2000];
    const char *a = strstr(b, "0x42699a76");
    snprintf(mixed, sizeof(mixed), "%.*s0x42699A7612a82F1d9c36148af9c77354759b210B%s", (int)(a - b), b, a + 42);
    result(mixed);
    CHECK(g_p.get_logs(g_p.ctx, 0x233, c, t0, to, lg, 4, &n, 0) == AMM_ETH_OK && lg[0].address[0] == 0x42 && lg[0].address[19] == 0x0b,
          "an address in mixed case is accepted (the address pattern allows it)");
}

/* a transaction object of `type` with the common required fields and `extra`
 * (JSON members without braces); hash = the a52b... example, `to` an address */
static const char *txj(char *buf, size_t cap, const char *type, const char *extra) {
    snprintf(buf, cap,
        "{\"blockHash\":\"0x510efccf44a192e6e34bcb439a1947e24b86244280762cbb006858c237093fda\","
        "\"blockNumber\":\"0x422\",\"blockTimestamp\":\"0x11\",\"from\":\"0xfe3b557e8fb62b89f4916b721be55ceb828dbd73\","
        "\"gas\":\"0x5208\",\"hash\":\"0xa52be92809541220ee0aaaede6047d9a6c5d0cd96a517c854d944ee70a0ebb44\","
        "\"input\":\"0x\",\"nonce\":\"0x1\",\"to\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\","
        "\"transactionIndex\":\"0x0\",\"value\":\"0x0\",\"type\":\"%s\","
        "\"r\":\"0x84caf09aefbd5e539295acc67217563438a4efb224879b6855f56857fa2037d3\","
        "\"s\":\"0x5e863be3829812c81439f0ae9d8ecb832b531d651fb234c848d1bf45e62be8b9\",%s}", type, extra);
    return buf;
}

#define HASH32 "\"0x1f68ac259155e2f38211ddad0f0a15394d55417b185a93923e2abe71bb7a4d6d\""
#define FEES2 "\"maxFeePerGas\":\"0x1\",\"maxPriorityFeePerGas\":\"0x1\""
#define ACL_OK "{\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\",\"storageKeys\":[" HASH32 "]}"

static void r8b_tx_lists(void) {
    printf("R8b the elements of a transaction's required lists (transaction.yaml:59-91, 148-153, 186-204)\n");
    mk(65536);
    amm_eth_tx_t t;
    char x[3000], e[1500];
    uint8_t want[32] = {0xa5,0x2b,0xe9,0x28,0x09,0x54,0x12,0x20,0xee,0x0a,0xaa,0xed,0xe6,0x04,0x7d,0x9a,
                        0x6c,0x5d,0x0c,0xd9,0x6a,0x51,0x7c,0x85,0x4d,0x94,0x4e,0xe7,0x0a,0x0e,0xbb,0x44};
    /* type 2 */
    struct { const char *acl; int ok; const char *what; } t2[] = {
        { "[]", 1, "an empty accessList" },
        { "[" ACL_OK "]", 1, "an accessList entry with address and storageKeys" },
        { "[{}]", 0, "an accessList entry `{}`" },
        { "[{\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"}]", 0, "an accessList entry without storageKeys" },
        { "[{\"storageKeys\":[]}]", 0, "an accessList entry without address" },
        { "[{\"address\":\"0x6273\",\"storageKeys\":[]}]", 0, "an accessList entry with a short address" },
        { "[{\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\",\"storageKeys\":[\"0x12\"]}]", 0, "a storage key that is not a hash32" },
        { "[{\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\",\"storageKeys\":false}]", 0, "storageKeys that is not an array" },
        { "[\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"]", 0, "an accessList entry that is a string" },
    };
    for (size_t i = 0; i < sizeof(t2) / sizeof(t2[0]); i++) {
        char m[120];
        snprintf(e, sizeof(e), FEES2 ",\"gasPrice\":\"0x1\",\"chainId\":\"0x1\",\"yParity\":\"0x1\",\"accessList\":%s", t2[i].acl);
        result(txj(x, sizeof(x), "0x2", e));
        snprintf(m, sizeof(m), "type 2: %s: %s", t2[i].what, t2[i].ok ? "OK" : "ERR");
        int rc = g_p.get_tx(g_p.ctx, want, &t, 0);
        CHECK(t2[i].ok ? rc == AMM_ETH_OK : rc == AMM_ETH_ERR, m);
    }
    /* type 3: blobVersionedHashes */
    struct { const char *blobs; int ok; const char *what; } t3[] = {
        { "[" HASH32 "]", 1, "a blob hash" },
        { "[\"0x12\"]", 0, "a blob hash that is not a hash32" },
        { "[1]", 0, "a blob hash that is a number" },
        { "true", 0, "blobVersionedHashes that is not an array" },
    };
    for (size_t i = 0; i < sizeof(t3) / sizeof(t3[0]); i++) {
        char m[120];
        snprintf(e, sizeof(e), FEES2 ",\"maxFeePerBlobGas\":\"0x1\",\"chainId\":\"0x1\",\"yParity\":\"0x1\","
                 "\"accessList\":[],\"blobVersionedHashes\":%s", t3[i].blobs);
        result(txj(x, sizeof(x), "0x3", e));
        snprintf(m, sizeof(m), "type 3: %s: %s", t3[i].what, t3[i].ok ? "OK" : "ERR");
        int rc = g_p.get_tx(g_p.ctx, want, &t, 0);
        CHECK(t3[i].ok ? rc == AMM_ETH_OK : rc == AMM_ETH_ERR, m);
    }
    /* type 4: authorizationList entries need chainId, nonce, address, yParity, r, s */
#define AUTH_OK "{\"chainId\":\"0x1\",\"nonce\":\"0x0\",\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"," \
                "\"yParity\":\"0x0\",\"r\":\"0x1\",\"s\":\"0x2\"}"
    struct { const char *auth; int ok; const char *what; } t4[] = {
        { "[" AUTH_OK "]", 1, "an authorization entry with all six fields" },
        { "[{}]", 0, "an authorization entry `{}`" },
        { "[{\"chainId\":\"0x1\",\"nonce\":\"0x0\",\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\",\"yParity\":\"0x0\",\"r\":\"0x1\"}]", 0, "an authorization entry without s" },
        { "[{\"chainId\":\"0x1\",\"nonce\":\"0x0\",\"address\":\"0x6273\",\"yParity\":\"0x0\",\"r\":\"0x1\",\"s\":\"0x2\"}]", 0, "an authorization entry with a short address" },
        { "[{\"chainId\":\"0x01\",\"nonce\":\"0x0\",\"address\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\",\"yParity\":\"0x0\",\"r\":\"0x1\",\"s\":\"0x2\"}]", 0, "an authorization entry with a leading-zero chainId" },
        { "[\"x\"]", 0, "an authorization entry that is a string" },
    };
    for (size_t i = 0; i < sizeof(t4) / sizeof(t4[0]); i++) {
        char m[120];
        snprintf(e, sizeof(e), FEES2 ",\"chainId\":\"0x1\",\"yParity\":\"0x1\",\"accessList\":[],\"authorizationList\":%s", t4[i].auth);
        result(txj(x, sizeof(x), "0x4", e));
        snprintf(m, sizeof(m), "type 4: %s: %s", t4[i].what, t4[i].ok ? "OK" : "ERR");
        int rc = g_p.get_tx(g_p.ctx, want, &t, 0);
        CHECK(t4[i].ok ? rc == AMM_ETH_OK : rc == AMM_ETH_ERR, m);
    }
}

static void r8_tx_receipt(void) {
    printf("R8 get_tx, R9 get_receipt\n");
    mk(65536);
    amm_eth_tx_t t;
    uint8_t h[32];
    memset(h, 0xa5, 32);
    h[0] = 0xa5;
    /* transaction.yaml:15-36, with the hash the example's request names */
    const char *hh = "0xa52be92809541220ee0aaaede6047d9a6c5d0cd96a517c854d944ee70a0ebb44";
    uint8_t want[32] = {0xa5,0x2b,0xe9,0x28,0x09,0x54,0x12,0x20,0xee,0x0a,0xaa,0xed,0xe6,0x04,0x7d,0x9a,
                        0x6c,0x5d,0x0c,0xd9,0x6a,0x51,0x7c,0x85,0x4d,0x94,0x4e,0xe7,0x0a,0x0e,0xbb,0x44};
    char b[2500], b2[2500];
    /* a legacy transaction (type 0x0) with every field transaction.yaml:364-479 /
     * :487-518 require: contextual blockHash, blockNumber, blockTimestamp, from,
     * hash, transactionIndex; type, nonce, gas, value, input, gasPrice, v, r, s */
    snprintf(b, sizeof(b), TX_FIELDS("%s", "\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"", "0xa9059cbb0000"), hh);
    result(b);
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_OK && t.has_to && t.from[0] == 0xfe && t.from[19] == 0x73 &&
          t.to[0] == 0x62 && t.input_len == 6 && t.input_head[0] == 0xa9 && t.input_head[3] == 0xbb,
          "the example transaction maps: from, to, input length 6, selector bytes");
    CHECK(g_p.get_tx(g_p.ctx, h, &t, 0) == AMM_ETH_ERR, "another hash than asked: ERR");
    snprintf(b, sizeof(b), TX_FIELDS("%s", "null", "0x"), hh);
    result(b);
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_OK && !t.has_to && t.input_len == 0, "to null: no recipient; empty input: length 0");
    snprintf(b, sizeof(b), TX_FIELDS("%s", "null", "0xa9059"), hh);
    result(b);
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, "odd-length input: ERR");
    snprintf(b, sizeof(b), TX_FIELDS("%s", "null", "0xa9059c\\u0062"), hh);
    result(b);
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, "an escaped input: ERR");
    /* every required field, removed (its key renamed) or of the wrong type: ERR */
    snprintf(b, sizeof(b), TX_FIELDS("%s", "\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"", "0xa9059cbb0000"), hh);
    static const char *txreq[] = { "blockHash", "blockNumber", "blockTimestamp", "from", "hash", "transactionIndex",
                                   "type", "nonce", "gas", "value", "input", "gasPrice", "v", "r", "s", "to" };
    for (size_t i = 0; i < sizeof(txreq) / sizeof(txreq[0]); i++) {
        char m[100];
        result(drop_key(b, txreq[i], b2, sizeof(b2)));
        snprintf(m, sizeof(m), "transaction without `%s`: ERR", txreq[i]);
        CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, m);
    }
    result(subst(b, "\"blockNumber\":\"0x422\"", "\"blockNumber\":\"0x0422\"", b2, sizeof(b2)));
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, "transaction with a leading-zero blockNumber: ERR");
    result(subst(b, "\"nonce\":\"0x1\"", "\"nonce\":1", b2, sizeof(b2)));
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, "transaction with a numeric nonce: ERR");
    result(subst(b, "\"type\":\"0x0\"", "\"type\":\"0x9\"", b2, sizeof(b2)));
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, "transaction of an unknown type: ERR");
    /* a type-2 transaction needs its own fields (Transaction1559Unsigned) */
    result(subst(subst(b, "\"type\":\"0x0\"", "\"type\":\"0x2\"", b2, sizeof(b2)), "\"v\":", "\"yParity\":\"0x1\",\"w\":", b, sizeof(b)));
    CHECK(g_p.get_tx(g_p.ctx, want, &t, 0) == AMM_ETH_ERR, "a type-2 transaction without maxFeePerGas, chainId, accessList: ERR");

    /* the receipt: transaction.yaml:144-165 */
    amm_eth_receipt_t r;
    uint8_t rh[32] = {0xc0,0x0e,0x97,0xaf,0x59,0xc6,0xf8,0x8d,0xe1,0x63,0x30,0x69,0x35,0xf7,0x68,0x2a,
                      0xf1,0xa3,0x4c,0x67,0x24,0x5e,0x41,0x45,0x37,0xd0,0x2e,0x42,0x28,0x15,0xef,0xc3};
    const char *rx = "0xc00e97af59c6f88de163306935f7682af1a34c67245e414537d02e422815efc3";
    char rj[2500];
    /* every field receipt.yaml:43-54 requires: blockHash, blockNumber, from,
     * cumulativeGasUsed, gasUsed, logs, logsBloom, transactionHash,
     * transactionIndex, effectiveGasPrice (+ status) */
    snprintf(rj, sizeof(rj), "{\"blockHash\":\"0xe7212a92cfb9b06addc80dec2a0dfae9ea94fd344efeb157c41e12994fcad60a\","
             "\"blockNumber\":\"0x50\",\"contractAddress\":null,\"cumulativeGasUsed\":\"0x5208\","
             "\"from\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\",\"gasUsed\":\"0x5208\",\"effectiveGasPrice\":\"0x1\","
             "\"logs\":[],\"logsBloom\":\"" BLOOM "\",\"status\":\"%%s\",\"to\":\"0xf17f52151ebef6c7334fad080c5704d77216b732\","
             "\"transactionHash\":\"%s\",\"transactionIndex\":\"0x0\"}", rx);
    char out[2500];
    snprintf(out, sizeof(out), rj, "0x1");
    result(out);
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_OK && r.status == 1 && r.block_number == 0x50 &&
          r.block_hash[0] == 0xe7 && r.block_hash[31] == 0x0a, "the example receipt maps: status 1, block 0x50, block hash");
    snprintf(out, sizeof(out), rj, "0x0");
    result(out);
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_OK && r.status == 0, "status 0 maps to 0");
    snprintf(out, sizeof(out), rj, "0x2");
    result(out);
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "status 2: ERR (the schema says 0 or 1)");
    snprintf(out, sizeof(out), rj, "1");
    result(out);
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "status without its prefix: ERR");
    result("{\"blockHash\":\"0xe7212a92cfb9b06addc80dec2a0dfae9ea94fd344efeb157c41e12994fcad60a\",\"blockNumber\":\"0x50\","
           "\"transactionHash\":\"0xc00e97af59c6f88de163306935f7682af1a34c67245e414537d02e422815efc3\"}");
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "no status field (a pre-Byzantium receipt): ERR");
    snprintf(out, sizeof(out), rj, "0x1");
    result(out);
    CHECK(g_p.get_receipt(g_p.ctx, h, &r, 0) == AMM_ETH_ERR, "a receipt of another transaction: ERR");

    /* every required field, removed: ERR (the verifier's `"logs":false` case included) */
    static const char *rreq[] = { "blockHash", "blockNumber", "from", "cumulativeGasUsed", "gasUsed", "logs",
                                  "logsBloom", "transactionHash", "transactionIndex", "effectiveGasPrice", "status" };
    char out2[2500];
    for (size_t i = 0; i < sizeof(rreq) / sizeof(rreq[0]); i++) {
        char m[100];
        result(drop_key(out, rreq[i], out2, sizeof(out2)));
        snprintf(m, sizeof(m), "receipt without `%s`: ERR", rreq[i]);
        CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, m);
    }
    snprintf(out, sizeof(out), rj, "0x1");
    result(subst(out, "\"logs\":[]", "\"logs\":false", out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "\"logs\": false: ERR (logs is an array)");
    result(subst(out, "\"gasUsed\":\"0x5208\"", "\"gasUsed\":21000", out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a numeric gasUsed: ERR");
    result(subst(out, "\"effectiveGasPrice\":\"0x1\"", "\"effectiveGasPrice\":\"0x01\"", out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "an effectiveGasPrice with a leading zero: ERR");
    result(subst(out, BLOOM, "0x00", out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a short logsBloom (bytes256): ERR");
    result(subst(out, "\"from\":\"0x627306090abab3a6e1400e9345bc60c78a8bef57\"", "\"from\":\"0x6273\"", out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a short from address: ERR");
    result(subst(out, "\"contractAddress\":null", "\"contractAddress\":\"0x12\"", out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a contractAddress that is neither null nor an address: ERR");

    /* the logs of a receipt are mapped, and each is validated like an eth_getLogs log */
    const char *lgj = "{\"logIndex\":\"0x3\",\"removed\":false,\"blockNumber\":\"0x50\","
        "\"blockHash\":\"0xe7212a92cfb9b06addc80dec2a0dfae9ea94fd344efeb157c41e12994fcad60a\","
        "\"transactionHash\":\"0xc00e97af59c6f88de163306935f7682af1a34c67245e414537d02e422815efc3\","
        "\"transactionIndex\":\"0x0\",\"address\":\"0x42699a7612a82f1d9c36148af9c77354759b210b\","
        "\"data\":\"" D32 "\",\"topics\":[" TOPIC "]}";
    char lg[1000], two[2200];
    snprintf(lg, sizeof(lg), "\"logs\":[%s]", lgj);
    result(subst(out, "\"logs\":[]", lg, out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_OK && r.n_logs == 1 && r.logs_total == 1 &&
          r.logs[0].log_index == 3 && r.logs[0].n_topics == 1 && r.logs[0].data_len == 32 && r.logs[0].data[31] == 4 &&
          r.logs[0].address[0] == 0x42 && r.logs[0].block_number == 0x50,
          "a receipt with one log: n_logs 1, the log mapped (index, topics, data, emitter, block)");
    snprintf(two, sizeof(two), "\"logs\":[%s,%s]", lgj, lgj);
    result(subst(out, "\"logs\":[]", two, out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_OK && r.n_logs == 2 && r.logs_total == 2, "two logs, both kept");
    char nine[8200];
    size_t o = (size_t)snprintf(nine, sizeof(nine), "\"logs\":[");
    for (int i = 0; i < AMM_ETH_RCPT_LOGS + 1; i++)
        o += (size_t)snprintf(nine + o, sizeof(nine) - o, "%s%s", i ? "," : "", lgj);
    snprintf(nine + o, sizeof(nine) - o, "]");
    static char big[12000];
    mk(65536);
    result(subst(out, "\"logs\":[]", nine, big, sizeof(big)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_OK && r.n_logs == AMM_ETH_RCPT_LOGS &&
          r.logs_total == AMM_ETH_RCPT_LOGS + 1, "nine logs: eight kept, logs_total says nine (the payer then cannot show the result)");
    /* the digest of the WHOLE data: keccak256 of the data bytes, so a tail beyond
     * the first 32 bytes makes two logs different */
    {
        uint8_t d32[32] = {0}, d34a[34] = {0}, d34b[34] = {0}, e32[32], e34a[32], e34b[32];
        d32[31] = 4;
        d34a[31] = 4;                       /* D32 followed by 0x0000 */
        d34b[31] = 4; d34b[33] = 1;         /* D32 followed by 0x0001 */
        keccak256(d32, 32, e32); keccak256(d34a, 34, e34a); keccak256(d34b, 34, e34b);
        amm_eth_receipt_t ra, rb;
        char l1[1000], l2[1000], l3[1000];
        snprintf(l1, sizeof(l1), "\"logs\":[%s]", lgj);
        snprintf(l2, sizeof(l2), "\"logs\":[%s]", subst(lgj, D32, D32 "0000", out2, sizeof(out2)));
        snprintf(l3, sizeof(l3), "\"logs\":[%s]", subst(lgj, D32, D32 "0001", out2, sizeof(out2)));
        result(subst(out, "\"logs\":[]", l1, out2, sizeof(out2)));
        CHECK(g_p.get_receipt(g_p.ctx, rh, &ra, 0) == AMM_ETH_OK && !memcmp(ra.logs[0].data_digest, e32, 32),
              "a 32-byte data field: the digest is keccak256 of the 32 bytes");
        result(subst(out, "\"logs\":[]", l2, out2, sizeof(out2)));
        CHECK(g_p.get_receipt(g_p.ctx, rh, &ra, 0) == AMM_ETH_OK && ra.logs[0].data_len == 34 &&
              !memcmp(ra.logs[0].data_digest, e34a, 32), "a 34-byte data field: the digest covers all 34 bytes");
        result(subst(out, "\"logs\":[]", l3, out2, sizeof(out2)));
        CHECK(g_p.get_receipt(g_p.ctx, rh, &rb, 0) == AMM_ETH_OK && !memcmp(rb.logs[0].data, ra.logs[0].data, 32) &&
              ra.logs[0].data_len == rb.logs[0].data_len && memcmp(ra.logs[0].data_digest, rb.logs[0].data_digest, 32) != 0 &&
              !memcmp(rb.logs[0].data_digest, e34b, 32),
              "two logs equal in the first 32 bytes and in length, different only in the tail: different digests");
    }
    snprintf(lg, sizeof(lg), "\"logs\":[%s]", subst(lgj, "\"blockNumber\":\"0x50\"", "\"blockNumber\":\"0x51\"", out2, sizeof(out2)));
    result(subst(out, "\"logs\":[]", lg, out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a log of another block than the receipt's: ERR");
    snprintf(lg, sizeof(lg), "\"logs\":[%s]", subst(lgj, "0xc00e97af", "0xc00e97ae", out2, sizeof(out2)));
    result(subst(out, "\"logs\":[]", lg, out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a log of another transaction than the receipt's: ERR");
    snprintf(lg, sizeof(lg), "\"logs\":[%s]", subst(lgj, "\"removed\":false", "\"removed\":true", out2, sizeof(out2)));
    result(subst(out, "\"logs\":[]", lg, out2, sizeof(out2)));
    CHECK(g_p.get_receipt(g_p.ctx, rh, &r, 0) == AMM_ETH_ERR, "a removed log inside a receipt: ERR");
}

static void r10_scalars(void) {
    printf("R10 balances, estimate, counts, broadcast\n");
    mk(65536);
    uint8_t a20[20] = {0}, w[32], raw[2] = {2, 1}, h[32];
    uint64_t u = 99;
    result("\"0xde0b6b3a7640000\"");
    CHECK(g_p.get_balance(g_p.ctx, a20, w, 0) == AMM_ETH_OK && w[31] == 0x00 && w[24] == 0x0d && w[25] == 0xe0 &&
          w[26] == 0xb6 && w[27] == 0xb3 && w[28] == 0xa7 && w[29] == 0x64 && w[30] == 0x00 && w[0] == 0, "1 ether = 0x0de0b6b3a7640000, big-endian");
    result("\"0x0\"");
    CHECK(g_p.get_balance(g_p.ctx, a20, w, 0) == AMM_ETH_OK && w[31] == 0 && w[0] == 0, "balance 0x0 is a real zero answer");
    result("\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"");
    CHECK(g_p.get_balance(g_p.ctx, a20, w, 0) == AMM_ETH_OK && w[0] == 0xff && w[31] == 0xff, "the 256-bit maximum");
    result("\"0x10000000000000000000000000000000000000000000000000000000000000000\"");
    CHECK(g_p.get_balance(g_p.ctx, a20, w, 0) == AMM_ETH_ERR, "65 hex digits: ERR");
    result("\"0x0f\"");
    CHECK(g_p.get_balance(g_p.ctx, a20, w, 0) == AMM_ETH_ERR, "a balance with a leading zero: ERR");

    result("\"0x00000000000000000000000000000000000000000000000000000000000f4240\"");
    CHECK(g_p.erc20_balance(g_p.ctx, a20, a20, w, 0) == AMM_ETH_OK && w[29] == 0x0f && w[30] == 0x42 && w[31] == 0x40,
          "the balanceOf word is read as 32 bytes");
    result("\"0x00000000000000000000000000000000000000000000000000000000000f42\"");
    CHECK(g_p.erc20_balance(g_p.ctx, a20, a20, w, 0) == AMM_ETH_ERR, "a 31-byte word: ERR");
    result("\"0x\"");
    CHECK(g_p.erc20_balance(g_p.ctx, a20, a20, w, 0) == AMM_ETH_ERR, "an empty return (no contract): ERR, not zero");
    result("\"0x00000000000000000000000000000000000000000000000000000000000F4240\"");
    CHECK(g_p.erc20_balance(g_p.ctx, a20, a20, w, 0) == AMM_ETH_ERR, "an upper-case word: ERR");

    result("\"0x5208\"");
    CHECK(g_p.estimate_gas(g_p.ctx, a20, a20, NULL, 0, &u, 0) == AMM_ETH_OK && u == 0x5208, "estimate with no input");
    CHECK(g_p.estimate_gas(g_p.ctx, a20, a20, NULL, 5, &u, 0) == AMM_ETH_ERR, "a length with no data: ERR");
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":3,\"message\":\"execution reverted\",\"data\":\"0x\"}}");
    u = 99;
    CHECK(g_p.estimate_gas(g_p.ctx, a20, a20, NULL, 0, &u, 0) == AMM_ETH_ERR && u == 99, "an estimate that reverts: ERR (the payout stays unsent)");
    result("\"0xabababababababababababababababababababababababababababababababab\"");
    CHECK(g_p.send_raw(g_p.ctx, raw, 2, h, 0) == AMM_ETH_OK, "broadcast: a hash comes back");
    result("\"0xabab\"");
    CHECK(g_p.send_raw(g_p.ctx, raw, 2, h, 0) == AMM_ETH_ERR, "broadcast: a short hash: ERR");
    result("\"0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB\"");
    CHECK(g_p.send_raw(g_p.ctx, raw, 2, h, 0) == AMM_ETH_ERR, "broadcast: an upper-case hash: ERR");
    CHECK(g_p.send_raw(g_p.ctx, raw, 0, h, 0) == AMM_ETH_ERR && g_p.send_raw(g_p.ctx, NULL, 2, h, 0) == AMM_ETH_ERR,
          "broadcast: no bytes: ERR, and no request is made");
}

static void r11_config_transport(void) {
    printf("R11 configuration, the seam table, the libcurl transport\n");
    amm_eth_rpc_cfg_t c = { .url = "https://x.example.test/", .name = "n", .post = stub_post, .max_response = 4096 };
    amm_eth_rpc_t *r = amm_eth_rpc_new(&c);
    CHECK(r != NULL, "a good configuration builds");
    amm_eth_provider_t p;
    amm_eth_rpc_provider(r, &p);
    CHECK(p.ctx && p.name && p.chain_id && p.block_number && p.get_block && p.get_logs && p.get_tx && p.get_receipt &&
          p.get_balance && p.erc20_balance && p.tx_count && p.estimate_gas && p.gas_price && p.max_priority_fee && p.send_raw,
          "the seam table is complete");
    CHECK(!strcmp(p.name, "n"), "the name is the caller's label, never the URL");
    amm_eth_rpc_free(r);
    amm_eth_rpc_cfg_t b = c;
    b.url = "http://x.example.test/";   CHECK(amm_eth_rpc_new(&b) == NULL, "http:// is refused");
    b.url = "https://";                 CHECK(amm_eth_rpc_new(&b) == NULL, "https:// alone is refused");
    b.url = "https://x y";              CHECK(amm_eth_rpc_new(&b) == NULL, "a space in the URL is refused");
    b.url = "https://x\n";              CHECK(amm_eth_rpc_new(&b) == NULL, "a control byte in the URL is refused");
    b.url = NULL;                       CHECK(amm_eth_rpc_new(&b) == NULL, "no URL is refused");
    char longu[400];
    memset(longu, 'a', sizeof(longu)); memcpy(longu, "https://", 8); longu[399] = '\0';
    b = c; b.url = longu;               CHECK(amm_eth_rpc_new(&b) == NULL, "a URL longer than the settings field is refused");
    b = c; b.post = NULL;               CHECK(amm_eth_rpc_new(&b) == NULL, "no post function is refused");
    b = c; b.max_response = 1023;       CHECK(amm_eth_rpc_new(&b) == NULL, "a response bound below 1 KiB is refused");
    b = c; b.max_response = AMM_RPC_RESP_CEIL + 1; CHECK(amm_eth_rpc_new(&b) == NULL, "a response bound above 16 MiB is refused");
    b = c; b.max_response = 0;         CHECK(amm_eth_rpc_new(&b) == NULL, "no response bound (no default) is refused");
    CHECK(amm_eth_rpc_new(NULL) == NULL, "no configuration");

    CHECK(amm_rpc_curl_global_init() == 0, "curl_global_init");
    CHECK(amm_rpc_curl_new(0) == NULL, "a zero timeout cap (no default) cannot be built");
    amm_rpc_curl_t *cu = amm_rpc_curl_new(1000);
    CHECK(cu != NULL, "a transport with a timeout cap builds");
    uint8_t resp[64], body[2] = {'{', '}'};
    size_t rl = 7;
    CHECK(amm_rpc_curl_post(cu, "http://127.0.0.1:9/", body, 2, resp, sizeof(resp), &rl, 0) == AMM_ETH_ERR,
          "a plain http:// URL is refused before any connection");
    CHECK(amm_rpc_curl_post(cu, "https://127.0.0.1:9/", body, 2, resp, sizeof(resp), &rl, 1) == AMM_ETH_ERR,
          "an https URL with an already expired deadline is refused before any connection");
    CHECK(amm_rpc_curl_post(NULL, "https://127.0.0.1:9/", body, 2, resp, sizeof(resp), &rl, 0) == AMM_ETH_ERR &&
          amm_rpc_curl_post(cu, NULL, body, 2, resp, sizeof(resp), &rl, 0) == AMM_ETH_ERR &&
          amm_rpc_curl_post(cu, "ftp://x/", body, 2, resp, sizeof(resp), &rl, 0) == AMM_ETH_ERR, "bad arguments");
    amm_rpc_curl_free(cu);
}

/* R12 the warning line of a provider's error answer (operator 2026-11-11, from the
 * live measurement: blockreq answers the newest block's eth_getLogs with code -32014
 * and a message; the log used to say only "the provider answered with an error").
 * The nodus build's logger (src/nodus_log_shim.c) writes every logged line to stderr
 * as "[WRN/TAG] text\n"; stderr is pointed at a temporary file around each call and
 * read back, so the line is captured exactly as the bot would print it.
 * PROVES: the line names the provider (NOT its URL, which may carry a key), shows an
 * integer code and a string message; a message of 300 bytes is cut to exactly 200
 * bytes plus "..."; an error that is not an object, a non-integer code or a
 * non-string message adds nothing (the old text); a raw newline, a tab, an escape or
 * a non-ASCII byte in the message cannot reach the line: the strict parser refuses
 * the whole answer first, so the line is the "not strict JSON" one and has no
 * control byte.
 * BUILD FLAGS: default (the standalone nodus build, whose logger is the shim; the
 * test would not see the lines with another logger). LEAVES BEHIND: nothing (the
 * temporary file is anonymous).
 * HOW IT CAN LIE: the control-byte replacement inside the line builder is defence in
 * depth behind the parser and cannot be reached through the public path (the parser
 * already refuses every byte outside 0x20-0x7E), so it is not exercised here, only
 * the end result "one line, no control byte" is; the checks read stderr, so a
 * logger that printed elsewhere would make them fail, not pass; the live answer's
 * text is copied from main's measurement of 2026-11-11, not fetched. */
static char g_cap[8192];       /* the captured line, without its final newline */
static int  g_cap_lines;       /* newlines in the capture, the final one included */

/* provider call of eth_chainId with stderr captured into g_cap */
static int run_chain(amm_eth_provider_t *p, uint64_t *u) {
    fflush(stderr);
    int saved = dup(2);
    FILE *tmp = tmpfile();
    if (saved < 0 || !tmp) { printf("FATAL capture\n"); exit(2); }
    dup2(fileno(tmp), 2);
    int rc = p->chain_id(p->ctx, u, 0);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    rewind(tmp);
    size_t n = fread(g_cap, 1, sizeof(g_cap) - 1, tmp);
    fclose(tmp);
    g_cap[n] = '\0';
    g_cap_lines = 0;
    for (size_t i = 0; i < n; i++) g_cap_lines += (g_cap[i] == '\n');
    if (n > 0 && g_cap[n - 1] == '\n') g_cap[n - 1] = '\0';
    return rc;
}

static int count_char(const char *s, char c) {
    int n = 0;
    for (; *s; s++) n += (*s == c);
    return n;
}

static int has_control(const char *s) {
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e) return 1;
    return 0;
}

static void r12_error_text(void) {
    printf("R12 the log line of an error answer\n");
    amm_eth_rpc_cfg_t c = { .url = "https://eth.example.test/v1/SECRET-KEY", .name = "p",
                            .post = stub_post, .post_ctx = NULL, .max_response = 65536 };
    amm_eth_rpc_t *r = amm_eth_rpc_new(&c);
    if (!r) { printf("FATAL rpc_new\n"); exit(2); }
    amm_eth_provider_t p;
    amm_eth_rpc_provider(r, &p);
    uint64_t u = 99;
    char b[1024];
    const char *w;

    /* the live answer of 2026-11-11 */
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32014,\"message\":\"block not available: "
           "block not found for eth_getLogs, requested toBlock 12113421 is not yet available on the node "
           "(latestBlock: 12113420, finalizedBlock: 12113343)\"}}");
    CHECK(run_chain(&p, &u) == AMM_ETH_ERR && u == 99, "the live error answer is ERR");
    w = g_cap;
    CHECK(g_cap_lines == 1 && !strncmp(w, "[WRN/AMM_RPC] ", 14), "one warning line");
    CHECK(strstr(w, "p: eth_chainId") != NULL, "the line names the provider and the method");
    CHECK(strstr(w, "-32014") != NULL, "the line carries the integer code");
    CHECK(strstr(w, "block not available: block not found for eth_getLogs") != NULL &&
          strstr(w, "finalizedBlock: 12113343)") != NULL, "the line carries the whole message (163 bytes, under the bound)");
    CHECK(strstr(w, "eth.example.test") == NULL && strstr(w, "SECRET-KEY") == NULL,
          "the line never shows the provider URL");

    /* a 300-byte message: exactly 200 bytes, then "..." */
    char m300[301];
    memset(m300, 'A', 300); m300[300] = '\0';
    snprintf(b, sizeof(b), "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"%s\"}}", m300);
    answer(b);
    CHECK(run_chain(&p, &u) == AMM_ETH_ERR, "a 300-byte message: ERR");
    w = g_cap;
    CHECK(count_char(w, 'A') == 200, "a 300-byte message is cut to exactly 200 bytes");
    size_t wl = strlen(w);
    CHECK(wl >= 3 && !strcmp(w + wl - 3, "..."), "the cut is marked with \"...\" at the end of the line");
    CHECK(strstr(w, "-32000") != NULL, "the code is still shown");
    /* exactly 200 bytes: not cut, no marker */
    memset(m300, 'B', 200); m300[200] = '\0';
    snprintf(b, sizeof(b), "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-1,\"message\":\"%s\"}}", m300);
    answer(b);
    (void)run_chain(&p, &u);
    w = g_cap; wl = strlen(w);
    CHECK(count_char(w, 'B') == 200 && wl >= 3 && strcmp(w + wl - 3, "..."), "a 200-byte message is shown whole, no marker");

    /* control and non-ASCII bytes cannot reach the line */
    static const char *evil[] = {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"x\nFAKE LINE\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"x\tFAKE\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"x\\nFAKE\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"x\xc3\xa9\x1b[31mFAKE\"}}",
    };
    for (size_t i = 0; i < sizeof(evil) / sizeof(evil[0]); i++) {
        answer(evil[i]);
        char msg[96];
        snprintf(msg, sizeof(msg), "hostile message %zu: ERR, one line, no control byte, no provider text", i);
        int rc = run_chain(&p, &u);
        w = g_cap;
        CHECK(rc == AMM_ETH_ERR && g_cap_lines == 1 && !has_control(w) && strstr(w, "FAKE") == NULL, msg);
    }

    /* what is not an integer code / a string message adds nothing */
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":\"boom\"}");
    (void)run_chain(&p, &u);
    w = g_cap;
    CHECK(!strcmp(w, "[WRN/AMM_RPC] p: eth_chainId: the provider answered with an error"),
          "an error that is not an object: the old text, nothing added");
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":\"-32000\",\"message\":7}}");
    (void)run_chain(&p, &u);
    w = g_cap;
    CHECK(!strcmp(w, "[WRN/AMM_RPC] p: eth_chainId: the provider answered with an error"),
          "a string code and a numeric message: the old text");
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"message\":\"only text\"}}");
    (void)run_chain(&p, &u);
    w = g_cap;
    CHECK(strstr(w, "only text") != NULL && strstr(w, "code") == NULL, "a message without a code: the message alone");
    answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601}}");
    (void)run_chain(&p, &u);
    w = g_cap;
    CHECK(strstr(w, "-32601") != NULL, "a code without a message: the code alone");
    amm_eth_rpc_free(r);
}

int main(void) {
    printf("test_amm_eth_rpc\n");
    r1_requests();
    r2_uint();
    r3_envelope();
    r4_size();
    r5_null();
    r6_block();
    r7_logs();
    r8_tx_receipt();
    r8b_tx_lists();
    r10_scalars();
    r11_config_transport();
    r12_error_text();
    if (g_r) amm_eth_rpc_free(g_r);
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
