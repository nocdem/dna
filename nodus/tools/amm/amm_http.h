/**
 * @file amm_http.h
 * @brief nodus-amm HTTP API: a minimal, bounded server on 127.0.0.1 and the
 *        routes of plan sections 4 and 6.4.7 as corrected by givens items
 *        82-88. The parser pattern is the faucet's (FAUCET.md:84-85,
 *        tools/faucet/faucet_http.h); the BODY bound is a setting
 *        (`http_max_body`, plan section 15: a signed Nodus-key request is up
 *        to 16,124 bytes, the faucet's 1,024 cannot carry it) and so is the
 *        answer bound (`http_max_response`).
 *
 * ROUTES (all JSON, byte fields `0x` + lowercase hex, numbers decimal
 * strings, plan 6.4.7; the answers carry no signature, givens item 69):
 *
 *   POST /amm/quote       the site's question (unsigned): exactly
 *                         {"direction":"usdt_to_nodus","amount":"<raw>"} or
 *                         {"direction":"nodus_to_usdt","amount":"<raw>",
 *                         "destination":"0x<40 lowercase hex>"} (the user's
 *                         Ethereum address: the estimate is the fee the payer
 *                         plans for transfer(destination, number)); the old
 *                         two-key NODUS -> USDT shape is refused with
 *                         "page_out_of_date" (HTTP 400)
 *     approved: {"approved":true,"direction":..,"amount":"..","number":"..",
 *                "estimatedFee":"..","requestNumber":"<decimal u32>",
 *                "validUntil":"<unix s>","payTo":".."}
 *       number = the bot's output BEFORE the network fee (NODUS raw for
 *       usdt_to_nodus, USDT raw for nodus_to_usdt); estimatedFee in the same
 *       unit, shown apart; the real fee is deducted at payout (givens 82).
 *     refused:  {"approved":false,"reason":"<word>"}
 *   POST /amm/swap        the paying extension's signed request, bodies of
 *                         6.4.7 (kind usdt_to_nodus / nodus_to_usdt); the
 *                         answer is a DELIVERY RESULT only (givens 83, 84, 88)
 *     {"received":true,"requestNumber":".."} or
 *     {"received":false,"reason":"<word>"} (+ "openRequestNumber" for
 *     open_approval, item 57)
 *   GET  /amm/swap/<request number>   the state of one swap: {"requestNumber":
 *                         "..","state":"..","direction":..,"amount":"..",
 *                         "number":"..","estimatedFee":"..","validUntil":".."}
 *   GET  /amm/status      reserves, settings in force (swap limits, validity,
 *                         commission, chain id, signing name and origin, the
 *                         USDT contract `usdtContract` and the smallest add
 *                         `liquidityMinNodus`), flags, room left, the
 *                         Foundation's addresses, the Nodus chain id
 *   POST /amm/liquidity/quote  the add question (unsigned; the PATH IS THE
 *                         BUILD'S CHOICE, plan 6.4.7 defers it): {"side":
 *                         "usdt"|"nodus","amount":"<raw>"} -- the amount of ONE
 *                         side; answer {"approved":true,"usdtAmount":"..",
 *                         "nodusAmount":"..","requestNumber":"<u32>",
 *                         "validUntil":"<unix s>","payEthereum":"0x..",
 *                         "payNodus":".."} (the exact pair at the pool's
 *                         ratio, where to pay each side) or {"approved":false,
 *                         "reason":"<word>"}; below liquidity_min_nodus:
 *                         "below_minimum"
 *   POST /amm/liquidity/add    the paying extension's two signed halves (plan
 *                         6.4.7). THE BODY IS FLAT, the build's reading of the
 *                         plan's two nested objects (the strict parser takes
 *                         one flat object of string values): "ethereumAddress"
 *                         "nodusAddress" "usdtAmount" "nodusAmount"
 *                         "requestNumber" "ethSignature" (the Ethereum half)
 *                         and "text" "publicKey" "nodusSignature" (the Nodus
 *                         half); same field forms as POST /amm/swap. Answer as
 *                         POST /amm/swap: {"received":true,...} / a refusal.
 *   POST /amm/liquidity/withdraw  the provider's signed withdrawal (plan 6.4.7:
 *                         {"text":"0x<hex of the text bytes>","publicKey":
 *                         "0x<5184 hex>","signature":"0x<9254 hex>"}, the Nodus
 *                         key only). Answer: {"received":true,"requestNumber":
 *                         "<decimal u64, the signed one>"} or {"received":false,
 *                         "reason":"<word>"}; the withdrawal acts after
 *                         liquidity_wait_eth_blocks (plan section 14), nothing is
 *                         paid by this call. Any other path is 404.
 *
 * REFUSAL WORDS (the build's, plan 6.4.5 / 6.4.7 leave them to it; the site
 * only shows them):
 *   quote:  paused, stopped, below_minimum, above_maximum, inflight_full,
 *           no_liquidity, cannot_pay, unavailable, busy, bad_request,
 *           page_out_of_date (a NODUS -> USDT question without a destination:
 *           the site's page script predates the bot), internal
 *           ("busy" = the open unpaid questions are at the limit quote_open_max,
 *           givens item 98: HTTP 200 {"approved":false,"reason":"busy"}, like
 *           every other refusal; "unavailable" = a read failed. The add question
 *           uses the same word. The site may offer "try again later".)
 *   swap:   bad_request, bad_format, bad_chain, bad_address, bad_signature,
 *           number_reused, unknown_number, amount_mismatch, number_used,
 *           open_approval, approval_expired, internal; the withdrawal adds
 *           paused (liquidity paused), no_position (the two addresses are not
 *           a stored position with units) and unavailable (the Ethereum tip
 *           cannot be read)
 *
 * BOUNDS (every one a hard limit, pinned by test_amm_http): request line
 * <= 256 bytes, header block <= 4096, <= 32 header lines of <= 512, path <=
 * 160, body <= the `http_max_body` setting (Content-Length only; any
 * Transfer-Encoding is refused), a connection cap, one deadline per request,
 * Connection: close on every answer, no query strings; an answer above
 * `http_max_response` is a 500 (never cut). JSON bodies: ONE flat object of
 * string values (no escape, printable ASCII), at most AMM_HTTP_MAX_KEYS (12)
 * keys, no duplicate key, nothing before or after.
 *
 * No TLS here: the bot opens no public port; the swap site's web server
 * forwards /amm/ to this loopback port (plan section 4).
 */
#ifndef AMM_HTTP_H
#define AMM_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "amm_cfg.h"
#include "amm_engine.h"
#include "amm_req.h"

#define AMM_HTTP_MAX_REQUEST_LINE  256
#define AMM_HTTP_MAX_HEADER_BLOCK  4096
#define AMM_HTTP_MAX_HEADER_LINE   512
#define AMM_HTTP_MAX_HEADERS       32
#define AMM_HTTP_MAX_PATH          160
#define AMM_HTTP_CONN_HARD_MAX     64
#define AMM_HTTP_MAX_KEYS          12   /* the liquidity add body carries 9 */

typedef struct {
    char        method[8];            /* "GET" | "POST"                      */
    char        path[AMM_HTTP_MAX_PATH];
    const char *body;                 /* points into the caller's buffer     */
    size_t      body_len;
} amm_http_req_t;

/** Parse the bytes received so far. @return 1 a complete request in `req`; 0
 *  more bytes are needed; a negative HTTP status when refused (-400
 *  malformed, -405 method, -411 POST without Content-Length, -413 body above
 *  `max_body`, -431 header block too large, -501 Transfer-Encoding). Pure. */
int amm_http_parse(const char *buf, size_t len, size_t max_body, amm_http_req_t *req);

/** A flat JSON object of string values. Pure, strict. */
typedef struct {
    int         n;
    const char *key[AMM_HTTP_MAX_KEYS];
    size_t      key_len[AMM_HTTP_MAX_KEYS];
    const char *val[AMM_HTTP_MAX_KEYS];
    size_t      val_len[AMM_HTTP_MAX_KEYS];
} amm_json_t;

/** @return 0 / -1 (anything but one object of string values, a duplicate key,
 *  an escape, a byte outside 0x20..0x7e, trailing bytes, more keys than
 *  AMM_HTTP_MAX_KEYS). */
int amm_json_parse(const char *body, size_t len, amm_json_t *out);
/** The value of `key`: 1 found (`*v`, `*n`), 0 missing. */
int amm_json_get(const amm_json_t *j, const char *key, const char **v, size_t *n);

/** `0x` + lowercase hex of exactly `n` bytes into out (n bytes). @return 0 /
 *  -1. `s` is not NUL terminated: `len` is its length. */
int amm_http_hex0x(const char *s, size_t len, uint8_t *out, size_t n);

/* ── the backend the routes call (wired by amm_main, stubbed by tests) ── */

typedef enum {
    AMM_HS_RECEIVED = 0,
    AMM_HS_FORMAT,           /* a byte or value rule of the signed text broken  */
    AMM_HS_CHAIN,            /* `Chain ID` is not the node's                    */
    AMM_HS_ADDRESS,          /* Nodus address != SHA3-512(public key)           */
    AMM_HS_SIGNATURE,
    AMM_HS_REUSED,           /* the signer already used that number             */
    AMM_HS_NO_NUMBER,
    AMM_HS_AMOUNT,
    AMM_HS_USED,
    AMM_HS_OPEN,             /* item 57; `*open_req` = the open swap's number   */
    AMM_HS_EXPIRED,
    AMM_HS_ERR,
    AMM_HS_PAUSED,           /* liquidity paused (withdraw)                     */
    AMM_HS_NO_POSITION,      /* withdraw: not a stored position with units      */
    AMM_HS_UNAVAILABLE       /* withdraw: the Ethereum tip cannot be read       */
} amm_hs_t;

typedef struct {
    void *ctx;
    /** returns an amm_q_rc_t */
    int (*quote)(void *ctx, amm_dir_t dir, uint64_t amount, const uint8_t *dest,
                 uint64_t deadline_ms, amm_quote_answer_t *out);
    /** verify + accept; returns an amm_hs_t; `*req_out` = the request number
     *  on AMM_HS_RECEIVED, `*open_req` on AMM_HS_OPEN */
    int (*swap_usdt)(void *ctx, const amm_req_usdt_in_t *in, uint32_t *req_out,
                     uint32_t *open_req);
    int (*swap_nodus)(void *ctx, const amm_req_nodus_in_t *in, uint32_t *req_out,
                      uint32_t *open_req);
    /** 0 found / 1 none / -1 */
    int (*get_swap)(void *ctx, uint32_t request_number, amm_swap_t *out);
    int (*status)(void *ctx, amm_engine_status_t *out);
    /** the add question: returns an amm_aq_rc_t */
    int (*add_question)(void *ctx, amm_side_t side, uint64_t amount, uint64_t deadline_ms,
                        amm_add_answer_t *out);
    /** verify both halves + accept; returns an amm_hs_t; `*req_out` = the
     *  request number on AMM_HS_RECEIVED, `*open_req` on AMM_HS_OPEN */
    int (*add_accept)(void *ctx, const amm_req_liq_eth_in_t *eth,
                      const amm_req_nodus_in_t *nodus, uint32_t *req_out,
                      uint32_t *open_req);
    /** verify + accept a withdrawal; returns an amm_hs_t; `*req_out` = the signed
     *  request number (a u64) on AMM_HS_RECEIVED */
    int (*withdraw)(void *ctx, const amm_req_nodus_in_t *in, uint64_t *req_out);
} amm_http_backend_t;

typedef struct {
    const amm_cfg_t    *cfg;          /* bounds, settings shown, addresses    */
    amm_http_backend_t  be;
} amm_http_ctx_t;

/** The routing the server calls: fills `*status` and `body` (a NUL
 *  terminated JSON text of at most cap - 1 bytes; an answer that would not fit
 *  is 500 with an empty object). */
void amm_http_route(amm_http_ctx_t *c, const amm_http_req_t *req, uint64_t deadline_ms,
                    int *status, char *body, size_t cap);

/* ── the server ─────────────────────────────────────────────────────── */

typedef void (*amm_http_handler_fn)(void *ctx, const amm_http_req_t *req,
                                    uint64_t deadline_ms, int *status, char *body,
                                    size_t cap);
typedef struct amm_http amm_http_t;

/** Listen on 127.0.0.1:`port` (0 = kernel-chosen, reported in *bound).
 *  `max_body` and `max_response` are the settings (>= 1). */
int  amm_http_open(uint16_t port, int conn_cap, int timeout_ms, size_t max_body,
                   size_t max_response, amm_http_handler_fn handler, void *ctx,
                   amm_http_t **out, uint16_t *bound);
/** One iteration: accept, read, answer, expire. Blocks at most wait_ms. */
int  amm_http_poll(amm_http_t *h, int wait_ms);
int  amm_http_connections(const amm_http_t *h);
void amm_http_close(amm_http_t *h);

#endif /* AMM_HTTP_H */
