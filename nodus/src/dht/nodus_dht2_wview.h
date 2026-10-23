/**
 * Nodus — DHT v2: the storage process's view of its local witness
 * (design docs/plans/2026-10-14-dht-v2-design.md rev 5 §2, §6 "Name check",
 * §13 row 13; package plan 2026-10-23 package 4).
 *
 * The nodus-storage side of the `ipc_dht` connection kind of
 * <data_path>/witness.sock (witness/nodus_witness_ipc.h): it dials the
 * socket (same euid), sends {"q":"ipc_dht"}, and then keeps
 *
 *   - a SNAPSHOT {chain id, tip height h, tip time t, consensus latch cu,
 *     epoch boundary e}: asked once per NODUS_DHT2_WVIEW_SNAP_EVERY_MS; an
 *     answer older than NODUS_DHT2_WVIEW_SNAP_STALE_MS, counted from the
 *     tick that SENT its request, is no snapshot (the
 *     caller then refuses writes and answers `not-caught-up`);
 *   - the frozen SETS {S(e), S(e − E), registry fp + status}: requested at
 *     connect and whenever a snapshot's `e` differs from the held sets' `e`;
 *     handed out only while the fresh snapshot carries that same `e`;
 *   - NAME answers: one `ipc_name` outstanding at a time; positives are
 *     cached for good (names are permanent, HF-4), negatives until the
 *     snapshot's `h` moves past the answer's `h`.
 *
 * One request outstanding per call type (snap / sets / name). A request
 * that is not answered within NODUS_DHT2_WVIEW_REQ_TIMEOUT_MS closes the
 * connection (checked before any reply is read, so a late reply is never
 * accepted); a name {err} answer blocks new name requests until it has been
 * reported as NAME_FAULT; so does any malformed, unsolicited or over-long answer. The
 * dial is re-tried with a bounded backoff.
 *
 * Time: nothing here reads a clock. Every call that can act on time takes
 * `now_ms`, a caller-supplied MONOTONIC millisecond count (the caller's
 * own tick clock); it only schedules this node's own polling and ages its
 * own cache — never a consensus input. All state is a function of the
 * answers received and the `now_ms` values passed in.
 *
 * It links transport + CBOR only — no witness object (the nodus-storage
 * link gate, tests/storage_linked.cmake). The witness header it includes
 * carries constants and plain structs.
 *
 * NO CALLER YET: the package-5 holder store takes an injected context
 * (nodus_dht2_store.h); filling it from this view is package 6. Nothing in
 * nodus/tools/ or any running loop calls it today.
 *
 * @file nodus_dht2_wview.h
 */

#ifndef NODUS_DHT2_WVIEW_H
#define NODUS_DHT2_WVIEW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness_ipc.h"   /* nodus_witness_dht_*_t, bounds */

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_DHT2_WVIEW_SNAP_EVERY_MS   1000   /* row 13: polled once per second */
#define NODUS_DHT2_WVIEW_SNAP_STALE_MS   5000   /* row 13: older = no snapshot    */
#define NODUS_DHT2_WVIEW_REQ_TIMEOUT_MS  5000   /* an unanswered request closes   */
#define NODUS_DHT2_WVIEW_DIAL_BACKOFF_MIN_MS   250
#define NODUS_DHT2_WVIEW_DIAL_BACKOFF_MAX_MS  5000
#define NODUS_DHT2_WVIEW_NAME_CACHE_MAX  1024

typedef struct nodus_dht2_wview nodus_dht2_wview_t;

/** Result of nodus_dht2_wview_name(). */
typedef enum {
    NODUS_DHT2_WVIEW_NAME_PENDING = 0,  /* asked / being asked: call again    */
    NODUS_DHT2_WVIEW_NAME_NAMED,        /* the key has a name (permanent)     */
    NODUS_DHT2_WVIEW_NAME_UNNAMED,      /* no name as of *h_out               */
    NODUS_DHT2_WVIEW_NAME_FAULT,        /* the witness answered {err}: refuse
                                         * the admission (`holder-fault`);
                                         * reported once, then asked afresh   */
    NODUS_DHT2_WVIEW_NAME_UNAVAILABLE   /* no connection to the witness       */
} nodus_dht2_wview_name_t;

/** A view of the witness socket at `sock_path` (copied). Not connected yet:
 *  the first nodus_dht2_wview_tick dials. NULL on allocation failure or a
 *  path that does not fit. */
nodus_dht2_wview_t *nodus_dht2_wview_new(const char *sock_path);

/** One pass: dial if down (bounded backoff), read what arrived, close on a
 *  timed-out request, send the snapshot / sets request that is due. */
void nodus_dht2_wview_tick(nodus_dht2_wview_t *wv, uint64_t now_ms);

/** The snapshot, or false when there is none: not connected, never
 *  answered, answered {err}, or older than SNAP_STALE_MS at `now_ms`. */
bool nodus_dht2_wview_snap(const nodus_dht2_wview_t *wv, uint64_t now_ms,
                           nodus_witness_dht_snap_t *out);

/** The frozen sets, or NULL unless a fresh snapshot exists AND carries the
 *  same `e` as these sets. Valid until the next tick. */
const nodus_witness_dht_sets_t *nodus_dht2_wview_sets(
    const nodus_dht2_wview_t *wv, uint64_t now_ms);

/** The name state of `fp` (64 bytes). `*h_out` (may be NULL) is the answer's
 *  tip height for NAMED / UNNAMED. PENDING sends the request when none is
 *  outstanding; the caller asks again on a later tick. */
nodus_dht2_wview_name_t nodus_dht2_wview_name(nodus_dht2_wview_t *wv,
                                              uint64_t now_ms,
                                              const uint8_t fp[64],
                                              uint64_t *h_out);

/** Whether the socket to the witness is up. */
bool nodus_dht2_wview_connected(const nodus_dht2_wview_t *wv);

/** Close and free. */
void nodus_dht2_wview_free(nodus_dht2_wview_t *wv);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT2_WVIEW_H */
