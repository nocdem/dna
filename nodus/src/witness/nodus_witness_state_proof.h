/**
 * @file nodus_witness_state_proof.h
 * @brief HF-9 WP6 - the state proof service `dnac_state_proof` (plan
 *        docs/plans/approved/2026-11-04-hf9.md §10.2, §10.3, §10.4).
 *
 * WHAT IT ANSWERS. For a leg (1..8, plan §4.2) and 1..128 canonical keys: the
 * batch proof of §10.2 (the union of the per-key trie nodes, ascending by
 * SHA3-512 digest, one result per key in request order) and the composition
 * proof of §10.3 from the leg root up to the AppHash of header h + 1, h = the
 * latest committed height of the snapshot. Wire: nodus/include/nodus/nodus.h
 * (`nodus_dnac_state_proof_*`).
 *
 * WHERE IT RUNS (§10.4, D17 report 2 finding 2; the operator's decision 1b of
 * docs/plans/decisions/2026-10-14-kurultay-20-summary.md:92-108, "read RPCs
 * move to their OWN THREADS inside nodus-witness (private read-only SQLite
 * connections, one committed snapshot per answer)"). The witness loop only
 * decodes and validates the request, asks the node-wide admission, and hands
 * the request to an idle READER THREAD; the reader owns a private read-only
 * connection and a private witness context (nothing shared with the loop: no
 * handler state, caches cold), reads ONE committed snapshot (one read
 * transaction) and builds the answer; the finished answer comes back to the
 * loop (nodus_state_proof_poll) to be sent - the 4004 worker pattern (results
 * applied on the loop, nodus_witness_p2p.h:52-56). Nothing here is inside
 * apply: no root, validity, vote or block reads this service, and nothing it
 * keeps reaches one.
 *
 * ADMISSION. One node-wide limiter, whoever asks: above it, or when every
 * reader is busy, the answer is NODUS_ERR_RATE_LIMITED at once, BEFORE any
 * store read, with no queue (the dnac_light_block precedent, decision
 * docs/plans/decisions/2026-10-16-dnac-light-block-rpc.md:8-14: "the bound is
 * NODE-WIDE ... above that it answers NODUS_ERR_RATE_LIMITED before reading
 * the store"). The light block's 4 per second belongs to that endpoint and
 * is not reused.
 *
 * THE NUMERIC LIMITS ARE NOT SET HERE. Plan §17: "the proof service's
 * numeric limits - node-wide rate, number of reader threads, per-request work
 * bound. No operator sentence sets them ... WP6 measures the worst-case build
 * cost per leg ...; the measured values and the proposed limits then go to
 * the operator. Until then the service is not enabled on a live node." So
 * there is NO production literal, NO config key and NO default: the service
 * is created only through nodus_state_proof_service_new with explicit limits
 * (tests do); a witness without one answers every `dnac_state_proof` request
 * NODUS_ERR_RATE_LIMITED before any read - the admission rule above with a
 * limit of zero. A limit of zero readers or zero rate is the same answer.
 *
 * DETERMINISM. Node-local read service: no consensus path calls it. The
 * limiter reads the node's MONOTONIC wait clock through the caller (the
 * handler passes n->mono; tests pass their own), decides only whether THIS
 * node answers now, and nothing it reads or keeps reaches a block, the state,
 * a vote or replication. The build itself reads no clock.
 *
 * ERRORS (§10.2): NODUS_ERR_PROTOCOL_ERROR (a malformed request or a bound
 * exceeded - also a response that would exceed NODUS_MAX_FRAME_TCP: the
 * client splits the request), NODUS_ERR_NOT_FOUND (ONLY after the committed
 * generation was established as below 6: no tries), NODUS_ERR_INTERNAL_ERROR
 * (a read or runtime-resolution fault, a proof that fails its own
 * verification, a composition that disagrees with the committed AppHash),
 * NODUS_ERR_RATE_LIMITED.
 */
#ifndef NODUS_WITNESS_STATE_PROOF_H
#define NODUS_WITNESS_STATE_PROOF_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#include "witness/nodus_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_STATE_PROOF_MAX_KEYS   128u   /* D26 */
#define NODUS_STATE_PROOF_KEY_MAX    64u
#define NODUS_STATE_PROOF_LEGS       8

/** A decoded, validated request. */
typedef struct {
    int      leg;                                        /* 1..8            */
    size_t   n_keys;                                     /* 1..128          */
    size_t   key_len[NODUS_STATE_PROOF_MAX_KEYS];
    uint8_t  keys[NODUS_STATE_PROOF_MAX_KEYS][NODUS_STATE_PROOF_KEY_MAX];
} nodus_state_proof_req_t;

/** Decode and validate the request frame (the T2 query map, "a": {"leg":
 *  uint, "keys": array of bstr}; every key exactly once, an unknown key is
 *  skipped): leg 1..8; 1..128 keys, no duplicate; key length 64 for legs
 *  1/2/3/5, 3..36 for leg 4, 8 for legs 6/7/8 (plan §10.2, A11 / F-19).
 *  @return 0, or -1 with err_code NODUS_ERR_PROTOCOL_ERROR and a message. */
int nodus_state_proof_request_decode(const uint8_t *payload, size_t len,
                                     nodus_state_proof_req_t *out,
                                     int *err_code, char *err_msg,
                                     size_t err_cap);

/** Work done by one build (deterministic counts; no clock). */
typedef struct {
    uint64_t height;          /* the snapshot's committed height          */
    size_t   nodes_loaded;    /* trie nodes read from the store           */
    size_t   nodes;           /* nodes in the bundle (after dedup)        */
    size_t   frame_bytes;     /* the response frame                       */
} nodus_state_proof_stats_t;

/** A private read-only context for one reader: a heap nodus_witness_t whose
 *  only member set is a SQLITE_OPEN_READONLY connection to `db_path`.
 *  NULL on failure. */
nodus_witness_t *nodus_state_proof_ctx_open(const char *db_path);
void nodus_state_proof_ctx_close(nodus_witness_t *ctx);

/** Build the answer for `req` on the context `ctx` inside ONE read
 *  transaction (one committed snapshot). `*frame` is the complete T2
 *  response frame (malloc'd) for `txn_id`. The proof is verified against its
 *  own leg root and composition before it is returned, and the composition's
 *  final value must equal the committed AppHash (v2_blocks.global_root) of
 *  the snapshot - otherwise it is NODUS_ERR_INTERNAL_ERROR, never a proof of
 *  something else. @return 0, or -1 with err_code / err_msg. */
int nodus_state_proof_build(nodus_witness_t *ctx,
                            const nodus_state_proof_req_t *req,
                            uint32_t txn_id, uint8_t **frame,
                            size_t *frame_len,
                            nodus_state_proof_stats_t *stats, int *err_code,
                            char *err_msg, size_t err_cap);

/* ── the service ─────────────────────────────────────────────────────── */

typedef struct nodus_state_proof_service nodus_state_proof_service_t;

typedef struct {
    unsigned readers;        /* reader threads; 0 = not enabled              */
    unsigned rate_per_sec;   /* node-wide builds per second; 0 = not enabled */
} nodus_state_proof_limits_t;

/** Start the service on the database `db_path` with explicit limits: one
 *  private read-only context and one thread per reader. With readers == 0 or
 *  rate_per_sec == 0 no thread starts and every request is refused
 *  RATE_LIMITED. NULL on failure. */
nodus_state_proof_service_t *
nodus_state_proof_service_new(const char *db_path,
                              const nodus_state_proof_limits_t *limits);

/** What the loop did (loop-side counters are plain, loop-thread only; the
 *  reader-side ones are atomics). */
typedef struct {
    uint64_t decoded;         /* requests decoded on the loop              */
    uint64_t refused_protocol;/* malformed / out of bounds, answered at once */
    uint64_t refused_rate;    /* above the node-wide rate                   */
    uint64_t refused_busy;    /* every reader busy                          */
    uint64_t handed_off;      /* given to a reader                          */
    uint64_t builds_started;  /* reader side: store reads begun             */
    uint64_t builds_done;
    uint64_t loop_builds;     /* builds run on the thread that called submit
                               * (must stay 0)                              */
} nodus_state_proof_counters_t;

nodus_state_proof_counters_t
nodus_state_proof_service_counters(nodus_state_proof_service_t *svc);

/** Loop side: decode, admit, hand off. `now_ns` is the node's monotonic
 *  clock. `tag` (`tag_len` <= NODUS_STATE_PROOF_TAG_MAX bytes) is COPIED into
 *  the reader's job slot only after the request was validated and admitted
 *  (nothing is allocated for a refused request) and is handed back to the
 *  poll callback with the answer.
 *  @return 0 handed to a reader (the answer comes through poll); -1 refused
 *  at once, err_code = NODUS_ERR_PROTOCOL_ERROR or NODUS_ERR_RATE_LIMITED. */
#define NODUS_STATE_PROOF_TAG_MAX  64u
int nodus_state_proof_submit(nodus_state_proof_service_t *svc, int64_t now_ns,
                             const uint8_t *payload, size_t len,
                             uint32_t txn_id, const void *tag, size_t tag_len,
                             int *err_code, char *err_msg, size_t err_cap);

/** A finished answer: `frame` (malloc'd, ownership passes to the callee) is
 *  the response frame, or NULL with err_code / err_msg when the build
 *  refused; `dropped` = 1 when the service is being freed and the answer was
 *  not delivered (frame NULL, err_code 0). `tag` points to the copy given to
 *  submit, valid only during the call. */
typedef void (*nodus_state_proof_done_fn)(void *user, void *tag,
                                          uint8_t *frame, size_t frame_len,
                                          int err_code, const char *err_msg,
                                          const nodus_state_proof_stats_t *st,
                                          int dropped);

/** Loop side: deliver every finished answer. @return how many. */
size_t nodus_state_proof_poll(nodus_state_proof_service_t *svc,
                              nodus_state_proof_done_fn done, void *user);

/** Test seam: the thread that ran the most recent build of reader slot 0..n,
 *  as recorded by that reader (compare with pthread_self() of the loop). */
int nodus_state_proof_service_last_builder(nodus_state_proof_service_t *svc,
                                           unsigned reader, pthread_t *out);

/** Stop the readers (a build in progress finishes), join them, hand every
 *  undelivered tag back through `done` with dropped = 1, free. NULL-safe. */
void nodus_state_proof_service_free(nodus_state_proof_service_t *svc,
                                    nodus_state_proof_done_fn done,
                                    void *user);

/* ── the witness binding (the loop) ─────────────────────────────────── */

struct nodus_tcp_conn;

/** Enable the service of witness `w` with explicit limits on `w`'s own
 *  database file (a private read-only connection per reader). Nothing in the
 *  tree calls this in production: plan §17 holds the limits for the
 *  operator. @return 0, -1 (already enabled, an in-memory database, or a
 *  start failure). */
int nodus_witness_state_proof_enable(nodus_witness_t *w,
                                     const nodus_state_proof_limits_t *limits);

/** 1 when the witness has a service (the handler then reads the clock). */
int nodus_witness_state_proof_enabled(const nodus_witness_t *w);

/** The `dnac_state_proof` request on the loop: without a service the answer
 *  is RATE_LIMITED at once (no decode, no read); with one, decode + admit +
 *  hand off, or the refusal on `conn`. The answer is sent by
 *  nodus_witness_state_proof_poll on a later pass. `now_ns` = the node's
 *  monotonic clock (unused without a service). */
void nodus_witness_state_proof_handle(nodus_witness_t *w,
                                      struct nodus_tcp_conn *conn,
                                      const uint8_t *payload, size_t len,
                                      uint32_t txn_id, int64_t now_ns);

/** Who asked: the transport, the slot, the session generation and the serial
 *  the witness IPC listener stamps into conn->user_data at accept (the IPC
 *  transport never runs in session mode, so its generation stays 0). */
typedef struct {
    struct nodus_tcp *tcp;
    int               slot;
    uint64_t          generation;
    uint64_t          serial;
} nodus_state_proof_conn_id_t;

/** @return 0, or -1 when the connection has neither a generation nor a
 *  serial (it cannot be told from a replacement: the request is refused). */
int nodus_state_proof_conn_id_of(struct nodus_tcp_conn *conn,
                                 nodus_state_proof_conn_id_t *id);

/** The live connection of `id`, or NULL when its slot is empty, closing or
 *  now holds another connection (different generation or serial). */
struct nodus_tcp_conn *
nodus_state_proof_conn_alive(const nodus_state_proof_conn_id_t *id);

/** TEST SEAM: a function called inside the read transaction of every build,
 *  after the committed height was read (NULL = none, the production state).
 *  Set by tests only, before any build starts. */
void nodus_state_proof_set_stage_hook(void (*fn)(void *), void *ctx);

/** The loop: send every finished answer whose connection is still the one
 *  that asked (nodus_state_proof_conn_alive), drop the others. NULL-safe. */
void nodus_witness_state_proof_poll(nodus_witness_t *w);

/** Stop and free (nodus_witness_close). NULL-safe. */
void nodus_witness_state_proof_disable(nodus_witness_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_STATE_PROOF_H */
