/* exp_http — DNAC Explorer read-only JSON HTTP API.
 *
 * Minimal single-threaded HTTP/1.1 server: GET-only, 6 endpoints, over the
 * index db (exp_db.h) plus an optional live witness passthrough (exp_chain.h)
 * for `/api/address/<fp>?utxos=1`. See
 * docs/plans/2026-07-21-dnac-explorer-design.md §4 for the endpoint table.
 *
 * `exp_http_route` is the unit-tested seam: given a method + path (path may
 * include a "?query=string" suffix — parsed internally), it dispatches to
 * the matching endpoint handler and fills a JSON body + HTTP status. It does
 * no socket I/O and needs no live network — tests seed `ctx->db` (an
 * `exp_db_t **`, e.g. `ctx.db = &local_db_var;`) via the Task 2 API directly
 * and pass `ctx->chain = NULL` to exercise the witness-unavailable degrade
 * path. A `*ctx->db == NULL` (or `ctx->db == NULL`) exercises the 503
 * "index unavailable" degrade path (fix round 1, C1).
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

#ifdef __cplusplus
extern "C" {
#endif

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
    exp_chain_t  *chain;   /* live witness client for ?utxos=1; NULL = degrade gracefully.
                             * Dedicated client, never shared with the sync thread (Task 7,
                             * G-chain-share: a failing utxo query rotating this client must
                             * never race a nodus_client_t the sync thread is mid-call on). */
    uint16_t      port;
    volatile int *stop;    /* set non-zero to request exp_http_serve to return */

    /* Task 7 (Task 6 security review, db-swap race): guards *db against the
     * sync thread's confirmed-chain-reset close/rename/reopen swap
     * (exp_sync.c handle_confirmed_reset) racing an HTTP request mid-query
     * on the old handle. handle_client takes ctx->db_lock for rdlock for
     * the span of a request's db access (exp_http_route call), released
     * before the response is written. NULL db_lock skips locking entirely
     * — unit tests construct exp_http_ctx_t with `= {0}` and never set
     * this field, exercising exp_http_route single-threaded. */
    pthread_rwlock_t *db_lock;
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
