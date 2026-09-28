/* exp_http — DNAC Explorer read-only JSON HTTP API.
 *
 * Minimal single-threaded HTTP/1.1 server: GET-only, 6 endpoints, over the
 * index db (exp_db.h). The endpoint table and the JSON shapes are in
 * explorer/README.md ("HTTP API").
 *
 * The one request that reaches a witness is /api/address's balance: the
 * node's `dnac_balance` query (decision
 * docs/plans/decisions/2026-09-28-scan-v3-query.md 3a — per-token totals
 * of the address's TRANSPARENT unspent coins; dnac_utxo stays session-
 * gated, C11). It is read through an exp_balance_source_t (ctx->balance):
 * production = exp_balance_chain_* below, a SEPARATE chain handle the HTTP
 * thread alone uses (never the sync thread's connection) with a <= 5 s
 * cache; tests = fakes. "balance_status" is "ok" with the node's list
 * (an empty list is a real zero) or "unavailable" with "balances": null
 * when no source is wired or every server failed — never a zero on an
 * error, never a locally replayed sum.
 *
 * `exp_http_route` is the unit-tested seam: given a method + path (path may
 * include a "?query=string" suffix — parsed internally), it dispatches to
 * the matching endpoint handler and fills a JSON body + HTTP status. It does
 * no socket I/O of its own (only a wired ctx->balance source may reach a
 * witness) — tests seed `ctx->db` (an `exp_db_t **`, e.g.
 * `ctx.db = &local_db_var;`) through exp_db_write_height directly. A
 * `*ctx->db == NULL` (or `ctx->db == NULL`) exercises the 503 "index
 * unavailable" degrade path.
 *
 * `exp_http_serve` is the thin, NOT unit-tested (Task 9 smoke only) blocking
 * `poll()` accept loop: parses the raw HTTP request line, calls
 * exp_http_route, writes the JSON response with
 * `Content-Type: application/json` + `Connection: close`.
 *
 * Security (G2, hard rule): binds `127.0.0.1` ONLY — never `INADDR_ANY`.
 * nginx is the only thing that should ever see this port from outside the
 * host, and even that is out of this daemon's control — the daemon itself
 * must never listen on a non-loopback address.
 */
#ifndef EXP_HTTP_H
#define EXP_HTTP_H

#include <stdint.h>

#include <pthread.h>

#include "exp_chain.h"
#include "exp_db.h"
#include "exp_json.h"
#include "nodus/nodus.h"         /* nodus_dnac_balance_result_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Where /api/address reads a balance from. `get` fills `out` (freed by the
 * caller with nodus_client_free_balance_result) and returns 0, or returns
 * non-zero with `out` empty when no answer could be had. */
typedef struct {
    void *ctx;
    int  (*get)(void *ctx, const char *owner_hex,
                nodus_dnac_balance_result_t *out);
} exp_balance_source_t;

/* The production balance source: exp_chain_balance over a chain handle
 * that ONLY the HTTP serve thread uses (main.c opens it apart from the
 * sync thread's), plus a cache of the last EXP_BALANCE_CACHE_SLOTS
 * SUCCESSFUL answers, each reused for at most EXP_BALANCE_CACHE_TTL_MS
 * (CLOCK_MONOTONIC) — a failure is never cached, so an unavailable answer
 * is retried on the next request. No lock: exp_http_serve handles one
 * request at a time on one thread, and nothing else touches the handle or
 * the cache (a second thread calling it would need one). */
#define EXP_BALANCE_CACHE_SLOTS   32
#define EXP_BALANCE_CACHE_TTL_MS  5000u

typedef struct exp_balance_chain exp_balance_chain_t;

/* `chain` stays owned by the caller and must outlive the source.
 * @return 0 / -1 (bad args, allocation) */
int  exp_balance_chain_open(exp_balance_chain_t **out, exp_chain_t *chain);
void exp_balance_chain_close(exp_balance_chain_t *b);   /* NULL-safe */
/* Fill `src` to read through `b`. */
void exp_balance_source_chain(exp_balance_source_t *src,
                              exp_balance_chain_t *b);

typedef struct {
    /* index db (required). Fix round 1, C1: this is exp_db_t** — a pointer
     * to the SAME location the sync thread's handle_confirmed_reset swaps
     * via exp_sync_args_t.db (main.c wires both to `&db`), not a copy of
     * the handle itself. A plain `exp_db_t *db` copy goes stale the moment
     * a confirmed chain reset closes/reopens the real handle — the HTTP
     * thread would then hold a correctly-acquired rdlock guarding a
     * pointer that already points at freed memory. Deref exactly once,
     * inside the rdlock span (exp_http_route), never cache the result
     * across requests. *db may legitimately be NULL (handle_confirmed_reset
     * can leave *db_ptr NULL on its reopen/set_meta failure paths) — every
     * route handler must tolerate that by going through exp_http_route's
     * single NULL check, not by re-deref'ing ctx->db itself. */
    exp_db_t    **db;
    uint16_t      port;
    volatile int *stop;    /* set non-zero to request exp_http_serve to return */

    /* Task 7 (Task 6 security review, db-swap race): guards *db against the
     * sync thread's confirmed-chain-reset close/rename/reopen swap
     * (exp_sync.c handle_confirmed_reset) racing an HTTP request mid-query
     * on the old handle. exp_http_route takes ctx->db_lock for rdlock for
     * exactly the span of a request's db access (the *db deref and the
     * index queries) and releases it before any socket I/O — and before
     * /api/address's balance round trip, which runs with NO lock held so a
     * slow witness never holds the sync thread's writer out. NULL db_lock
     * skips locking entirely — unit tests construct exp_http_ctx_t with
     * `= {0}` and never set this field, exercising exp_http_route
     * single-threaded. */
    pthread_rwlock_t *db_lock;

    /* The address balance source (see exp_balance_source_t). NULL = no
     * source: every address answers "balance_status": "unavailable". */
    const exp_balance_source_t *balance;
} exp_http_ctx_t;

/* Blocking poll() accept loop on 127.0.0.1:ctx->port. Returns when
 * *ctx->stop becomes non-zero (checked once per ~1s poll timeout), or -1 on
 * a setup failure (socket/bind/listen). 0 on a clean stop-requested exit. */
int exp_http_serve(exp_http_ctx_t *ctx);

/* Router (unit-tested seam, no I/O). `path` is the raw HTTP request-target,
 * e.g. "/api/blocks?before=100&limit=10" — query string parsing happens
 * internally. `method` must be exactly "GET"; anything else -> 405.
 * Always fills *body_out (caller must exp_json_freebuf it) and *status_out
 * with SOME valid JSON response (including 4xx/5xx error bodies) and
 * returns 0, EXCEPT when ctx/method/path/body_out/status_out themselves are
 * NULL, in which case it returns -1 without touching those out-params. */
int exp_http_route(exp_http_ctx_t *ctx, const char *method, const char *path,
                    exp_json_t *body_out, int *status_out);

#ifdef __cplusplus
}
#endif

#endif /* EXP_HTTP_H */
