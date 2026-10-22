/**
 * @file faucet_http.h
 * @brief nodus-faucet HTTP: a minimal, bounded, 127.0.0.1-only server and
 *        the three routes of the build plan.
 *
 * Governing records: docs/plans/2026-10-22-testnet-faucet-design.md section
 * 6.8 and docs/plans/2026-10-22-mm-dex-build-plan.md (package C: the HTTP
 * API shared with the wallet):
 *
 *   POST /faucet/claim            {"address":"<128 lowercase hex>"}
 *   GET  /faucet/claim/<claim_id>
 *   GET  /faucet/status
 *   claim answer : {"claim_id":"<hex>","state":"...","kind":"...","message":"..."}
 *   status answer: {"open":bool,"paused":bool,"full_left":n,"start_left":n,"message":"..."}
 *
 * BOUNDS (every one a hard limit, each pinned by test_faucet_http):
 *   request line <= 256 bytes, header block <= 4096 bytes, <= 32 header
 *   lines of <= 512 bytes, body <= 1024 bytes (Content-Length only; any
 *   Transfer-Encoding is refused), a connection cap, one deadline per
 *   request, Connection: close on every answer, no query strings.
 *
 * The handler decides + journals + answers; the settlement worker runs on
 * its own thread (faucet_main.c). No TLS here: the faucet opens no public
 * port; the wallet site forwards /faucet/ to this loopback port.
 */
#ifndef FAUCET_HTTP_H
#define FAUCET_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "faucet_core.h"

#define FH_MAX_REQUEST_LINE  256
#define FH_MAX_HEADER_BLOCK  4096
#define FH_MAX_HEADER_LINE   512
#define FH_MAX_HEADERS       32
#define FH_MAX_BODY          1024
#define FH_MAX_PATH          160
#define FH_RESPONSE_MAX      1024

typedef struct {
    char        method[8];            /* "GET" | "POST"                    */
    char        path[FH_MAX_PATH];
    const char *body;                 /* points into the caller's buffer   */
    size_t      body_len;
} faucet_http_req_t;

/** Parse the bytes received so far. @return 1 a complete request in `req`;
 *  0 more bytes are needed; a negative HTTP status when the request is
 *  refused (-400 malformed, -405 method, -411 POST without Content-Length,
 *  -413 body too large, -431 header block too large, -501 any
 *  Transfer-Encoding). Pure: no I/O. */
int faucet_http_parse(const char *buf, size_t len, faucet_http_req_t *req);

/** Strict body parser of POST /faucet/claim: exactly one key "address"
 *  whose value is 128 lowercase hex characters. @return 0 / -1. */
int faucet_json_parse_claim(const char *body, size_t len, char addr_out[129]);

/** JSON encoders. @return the length written, or -1 when `cap` is too small. */
int faucet_json_answer(const faucet_answer_t *a, char *out, size_t cap);
int faucet_json_status(const faucet_status_t *s, char *out, size_t cap);

/** The routing the server calls: fills `*status` and `body`. */
void faucet_http_route(faucet_core_t *core, const faucet_http_req_t *req,
                       int *status, char *body, size_t cap);

/* ── the server ─────────────────────────────────────────────────────── */

typedef void (*faucet_http_handler_fn)(void *ctx, const faucet_http_req_t *req,
                                       int *status, char *body, size_t cap);
typedef struct faucet_http faucet_http_t;

/** Listen on 127.0.0.1:`port` (0 = kernel-chosen, reported in *bound). */
int  faucet_http_open(uint16_t port, int conn_cap, int timeout_ms,
                      faucet_http_handler_fn handler, void *ctx,
                      faucet_http_t **out, uint16_t *bound);
/** One iteration: accept, read, answer, expire. Blocks at most wait_ms. */
int  faucet_http_poll(faucet_http_t *h, int wait_ms);
/** Open connections right now (for the cap test). */
int  faucet_http_connections(const faucet_http_t *h);
void faucet_http_close(faucet_http_t *h);

#endif /* FAUCET_HTTP_H */
