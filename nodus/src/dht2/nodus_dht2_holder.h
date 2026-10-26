/**
 * Nodus — DHT v2: the holder service (package 6a).
 *
 * Design docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN): §4.4 signed
 * answers and receipts, §13 rows 7, 14, 18, 20, 23. Request format: docs/plans/decisions/2026-10-23-dht-v2-wire-gaps-
 * package2.md (strict DAG-CBOR requests).
 *
 * WHAT IT IS: one transport-free function. It takes the bytes of ONE request
 * from one session ("get", "put" — also read-repair — or the owner-signed
 * "list" envelope), runs it against the holder store (nodus_dht2_store.h)
 * and returns the bytes of ONE signed answer envelope, or "no answer":
 *
 *   get      /nodus/dht/answer/v1   {q, n, c, h, t, r}   r per key: hash,
 *                                    null (not held), code, [18, through]
 *   put      /nodus/dht/receipt/v1  {q, n, c, h, t, r}   as get, never null
 *   list     /nodus/dht/answer/v1   row-18 LIST payload; a request not signed
 *                                    by the inbox owner is answered r.v = 17
 *   refusal  /nodus/dht/refusal/v1  {q, n, c, e}  e = 14 busy | 15 not-caught-up
 *
 * every one sealed (dht2_answer_seal) under the node identity, domain /
 * ctx `nodus.dht.answer.v1`; q = the request's own nonce, n = this node's
 * fp. A refusal carries no h / t (row 18).
 *
 * NO ANSWER (NODUS_DHT2_HOLDER_NO_ANSWER): a malformed request (row 7 "a
 * tier-2 protocol error, no signed answer": nonce, key count, key length,
 * unknown op, a request whose op is not the method it arrived on, any
 * strict-CBOR fault, a LIST envelope that does not decode). Also — a READING,
 * row 23 names only code 17 — a LIST whose chain is not this chain or whose
 * signature does not verify (the signer is not proven, so no signed answer
 * is spent on it), and a LIST whose store read faulted (a LIST answer cannot
 * carry code 16: row 18 allows only a hash or 17 there).
 *
 * THE WORLD comes from a view (snapshot, frozen sets, name answers) behind
 * three function pointers, so a test injects a fixed one; nodus_dht2_holder_
 * view_wview() binds the real package-4 view. Every call takes `now_ms`, the
 * caller's monotonic tick count, and only hands it on to the view: nothing
 * here reads a clock, chain time is the snapshot's `t`.
 *
 * NAME RULE (package 4 ledger note: an unread name fault in the view blocks
 * further name requests until it is reported): the name callback handed to
 * the store maps NAMED / UNNAMED to the store's values, FAULT to FAULT (the
 * store turns it into code 16 for that key, which consumes it), and PENDING
 * / UNAVAILABLE to FAULT for this call (the request has been sent; the
 * client retries). A name answer is therefore always consumed by the call
 * that met it.
 *
 * NO WRITE REFUSAL FOR A SMALL STORAGE SET: the former §2 precondition
 * (|S(H)| >= 2) is INVALID, replaced by docs/plans/decisions/2026-10-26-
 * dht-v2-no-single-node-write-refusal.md. A holder never refuses a put
 * because S(H) is small; a network with one storage node stores records.
 *
 * WORK LIMIT (row 20): at most NODUS_DHT2_HOLDER_QUEUE_MAX (64) queued
 * signing jobs per holder. The caller brackets each answer it has queued
 * with nodus_dht2_holder_job_enter / _leave; at the limit serve() answers
 * the refusal 14 (busy). Keys per call (≤ 8) are enforced by the codec.
 *
 * NOT here (package 6b): sessions, the 16 outstanding calls / 8 MiB per
 * session, forwarding and its fan-out of 8, the 10 s deadline, the repair
 * queue, and the records that travel beside an answer (the caller fetches a
 * held record by the hash in `r` with nodus_dht2_store_get).
 *
 * RULES ADDED IN THE FIX ROUND (each pinned by a test):
 *   · CHAIN GATE (one place, world_load): a snapshot whose chain id is not
 *     the holder's chain is no snapshot — every request, the LIST not-owner
 *     branch included, gets the refusal 15 (no h / t), never an answer that
 *     mixes our `c` with a foreign tip.
 *   · KEY OF A PUT RESULT: k = the envelope's address, taken from the ONE
 *     parse inside the store's admission (nodus_dht2_put_t.address). An
 *     envelope that does not parse as far as an address (the spec has none
 *     for it) gets k = 64 zero bytes and the store's parse code — 1 too-large
 *     (also an envelope above 262,144 B: row 7's malformed list does not
 *     name it, so its siblings are still processed), 2 bad-encoding, 3
 *     bad-chain, or 16 for an allocation / hashing fault. A result is never
 *     given under another key. The whole request is bounded at the row-11
 *     budget (dht2_msg.h DHT2_REQ_MAX_LEN); over that it is malformed.
 *   · INBOX CONTROL VIA GET (row 23): a GET that resolves to a held class-5
 *     record answers per-key 17 — never its hash or bytes. Control records
 *     are read only through the owner-signed LIST path.
 *   · A LIST whose store read faults gets NO ANSWER: §4.4 says a missing
 *     answer is "no answer", never "not found", and row 18 lets a LIST
 *     result carry only a hash or 17.
 *   · The QGP_LOG_* lines of this module carry a log timestamp read from the
 *     clock; no answer field depends on it.
 *
 * NO CALLER YET: nothing in nodus/tools/ or any running loop calls it.
 *
 * @file nodus_dht2_holder.h
 */

#ifndef NODUS_DHT2_HOLDER_H
#define NODUS_DHT2_HOLDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dht/nodus_dht2_wview.h"
#include "dht2/dht2_types.h"
#include "dht2/nodus_dht2_store.h"
#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Row 20: per holder ≤ 64 queued signing jobs. */
#define NODUS_DHT2_HOLDER_QUEUE_MAX     64u

/** `out` of serve() must hold at least this many bytes. */
#define NODUS_DHT2_HOLDER_OUT_MIN       DHT2_ANSWER_ENV_MAX

/** Which request a byte string is (the method it arrived on). */
typedef enum {
    NODUS_DHT2_HOLDER_GET = 0,
    NODUS_DHT2_HOLDER_PUT,      /* also read-repair */
    NODUS_DHT2_HOLDER_LIST
} nodus_dht2_holder_kind_t;

/** serve() results. */
#define NODUS_DHT2_HOLDER_ANSWER     0    /* *out_len bytes of ONE envelope */
#define NODUS_DHT2_HOLDER_NO_ANSWER  1    /* send nothing (see the header)  */
#define NODUS_DHT2_HOLDER_ERR       (-1)  /* NULL / too-small buffer, signing
                                           * or allocation failure: no answer
                                           * could be made */

/** What the holder reads of the witness. The wview binding fills it. */
typedef struct {
    bool (*snap)(void *user, uint64_t now_ms, nodus_witness_dht_snap_t *out);
    const nodus_witness_dht_sets_t *(*sets)(void *user, uint64_t now_ms);
    nodus_dht2_wview_name_t (*name)(void *user, uint64_t now_ms,
                                    const uint8_t fp[64], uint64_t *h_out);
    void *user;
} nodus_dht2_holder_view_t;

/** Bind `v` to the real view of package 4 (borrowed for the holder's life). */
void nodus_dht2_holder_view_wview(nodus_dht2_holder_view_t *v,
                                  nodus_dht2_wview_t *wv);

typedef struct {
    nodus_dht2_store_t       *store;       /* borrowed                       */
    const nodus_identity_t   *id;          /* borrowed: signs every answer   */
    nodus_dht2_holder_view_t  view;
    uint8_t                   chain[DHT2_CHAIN_LEN];
    uint8_t                   self_fp[DHT2_FP_LEN];
    nodus_dht2_limits_t       limits;      /* §6, set to the defaults        */
    uint32_t                  queued;      /* row 20 counter                 */
    bool                      chain_warned; /* the foreign-chain log, once   */
} nodus_dht2_holder_t;

/** Fill `h`: self fp from the identity, limits to the §6 defaults, queue
 *  empty. `chain` is the chain the store was opened for (it names the chain
 *  of a refusal, which has no snapshot to take it from). @return 0 / -1. */
int nodus_dht2_holder_init(nodus_dht2_holder_t *h, nodus_dht2_store_t *store,
                           const nodus_identity_t *id,
                           const uint8_t chain[DHT2_CHAIN_LEN],
                           const nodus_dht2_holder_view_t *view);

/** The store's name callback `user`: the view and this call's tick. */
typedef struct {
    const nodus_dht2_holder_view_t *view;
    uint64_t                        now_ms;
} nodus_dht2_name_user_t;

/** One call's world: the snapshot, the frozen sets and the store context
 *  built from them (see nodus_dht2_holder_world_load). */
typedef struct {
    nodus_witness_dht_snap_t         snap;
    bool                             have_snap;   /* fresh snapshot, cu true */
    const nodus_witness_dht_sets_t  *sets;        /* NULL = not available    */
    nodus_dht2_name_user_t           nu;
    nodus_dht2_ctx_t                 ctx;
} nodus_dht2_world_t;

/** Take the snapshot and sets of one call from `h`'s view and fill `w`,
 *  including the store context (`w->ctx`). A missing, block-syncing or
 *  foreign-chain snapshot leaves `w->have_snap` false and `w->ctx.snap`
 *  NULL. `w` must stay where it is while `w->ctx` is used (the name
 *  callback points into it). The pull-sync module loads its world here. */
void nodus_dht2_holder_world_load(nodus_dht2_holder_t *h, uint64_t now_ms,
                                  nodus_dht2_world_t *w);

/** Row 20: take / release one signing-job slot. enter returns false (and
 *  takes nothing) at the limit; leave of an empty queue is a no-op. */
bool nodus_dht2_holder_job_enter(nodus_dht2_holder_t *h);
void nodus_dht2_holder_job_leave(nodus_dht2_holder_t *h);

/**
 * Answer one request. `out` needs NODUS_DHT2_HOLDER_OUT_MIN bytes.
 * @return NODUS_DHT2_HOLDER_ANSWER (`*out_len` set), _NO_ANSWER, _ERR.
 */
int nodus_dht2_holder_serve(nodus_dht2_holder_t *h,
                            nodus_dht2_holder_kind_t kind, uint64_t now_ms,
                            const uint8_t *req, size_t req_len, uint8_t *out,
                            size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT2_HOLDER_H */
