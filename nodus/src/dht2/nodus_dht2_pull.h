/**
 * Nodus — DHT v2: pull-sync, the core of package 7 (§4.5, §13 row 12).
 *
 * Design docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN): §4.5 "Records
 * follow the holder set", §13 row 12 (pull-sync, "Bee pkg/pullsync
 * translated"), row 20 (work limits), row 22 (vectors). Decisions:
 * docs/plans/decisions/2026-10-23-dht-v2-wire-gaps-package2.md and its
 * 2026-10-26 addendum (pull messages are strict DAG-CBOR maps without `op`
 * and `n`; the pull-receipt keys; the pull-receipt is sealed with
 * dht2_env_seal under domain `nodus.dht.answer.v1`, payload type
 * `/nodus/dht/pull-receipt/v1`, and the verifier checks the type as well as
 * the domain).
 *
 * PINNED REFERENCE (Bee v2.8.2, /home/nocdem/refs/bee-v2.8.2): every
 * function and check in nodus_dht2_pull.c names the Bee file:line it
 * translates. Where the design names a deviation (row 12), the design wins
 * and the row is cited.
 *
 * WHAT IT IS: ONE module with both roles, transport-free. It never opens a
 * socket and never reads a clock. The caller supplies
 *   - a send function (kind + payload bytes to one peer, by node fp),
 *   - the injected view of the witness (the holder's view type: snapshot,
 *     frozen sets, name answers),
 *   - the store, the node identity and the chain,
 * and feeds every message it receives back in. `now_ms` (the caller's
 * monotonic tick) is only handed on to the view.
 *
 *   SOURCE (answers a puller):
 *     nodus_dht2_pull_serve(HELLO | GET | WANT | RECEIPT)
 *   PULLER (one exchange in flight per source):
 *     nodus_dht2_pull_start(source) ... nodus_dht2_pull_on_reply(HELLO |
 *     OFFER | DELIVER)
 *
 * The send function must NOT call back into this module (queue the message
 * and deliver it later): the module reuses one outgoing buffer.
 *
 * A message's KIND is the tier-3 method (`dht2_pull_*`, decision item 1);
 * the caller's framing carries it, and tells a request (serve) from a reply
 * (on_reply). The wire framing on 4002 is NOT here.
 *
 * There is NO timer in this module. Bee's puller sets none (puller.go has no
 * exchange timeout): an exchange ends on its last message, on a generation
 * change, or when the caller reports the peer gone (nodus_dht2_pull_
 * disconnect — pullsync.go:`disconnect`, Protocol DisconnectIn / Out).
 *
 * GAPS (the sources are silent or the module has nothing to hang them on —
 * none of these is built):
 *   · how a node learns the network address of a source (PeerRecord
 *     exchange is not specified);
 *   · the 4002 framing of these messages and any caller / event loop;
 *   · Bee's pageTimeout wait (pullsync.go:49, :423-472) — it needs an event
 *     stream of new entries; the source answers a p_get from one scan;
 *   · Bee's 250 chunks / s limiters (pullsync.go:100, :192 source;
 *     puller.go:142, :390 puller) — a wait needs a scheduler;
 *   · live pulling (re-asking when a source stores a new entry) — the
 *     caller decides when to call nodus_dht2_pull_start again.
 *
 * READINGS (in neither Bee nor the design as a sentence — reported as gaps):
 *   · p_hello is sent both ways: the puller's REQUEST is Bee's empty Syn
 *     (pullsync.go:528-529) as the empty DAG-CBOR map (0xa0), the REPLY is
 *     p_hello {g, top}. The module cannot tell a hello request from a reply;
 *     the framing must (serve vs on_reply);
 *   · "responsibility grew" (puller.go:178-189, a scalar radius in Bee) is
 *     decided by a DP over XOR bit positions (responsibility_grew in the .c,
 *     argument there) — JUDGMENT, no reference oracle;
 *   · hand-over retirement: §4.5 (v) says every member of nearest_R(S(H))
 *     must acknowledge, row 12 says a receipt "from a member" retires. Built
 *     to the operator decision 2026-10-27-dht-v2-handover-one-receipt.md
 *     (revised: TWO receipts): the flag ends when min(2, |nearest_R|)
 *     distinct members of the record's current nearest_R have sent a valid
 *     receipt naming it; the acknowledging fps are persisted per record
 *     (store dht2_ack). The source verifies only "the same version"
 *     (receipt hash = held hash), not "or newer";
 *   · §4.5 (v) "then it may drop them": operator decision (same record,
 *     "What happens when the obligation ends"): when the quorum is met the
 *     drop is SCHEDULED for that epoch + NODUS_DHT2_PULL_DROP_WAIT_EPOCHS × E;
 *     at the first epoch check at or after it, with the quorum still met, the
 *     row is DELETED (acknowledgements and schedule with it), in one
 *     transaction, only if still PERMANENT and pending with the hash the
 *     receipts named. Eligible again or a new version cancels the schedule.
 *     A dropped record returns through admission (a pull, a client write,
 *     read-repair) when this node is eligible for it again;
 *   · "transient local failure" (cursor kept) = admission codes 15 / 16 /
 *     negative; "definitively refused" (cursor advances) = codes 1-13, 18.
 *
 * Nothing here is unordered: sources are sorted by fp, entries follow the
 * insertion index, deliveries ascend by offer index.
 *
 * @file nodus_dht2_pull.h
 */

#ifndef NODUS_DHT2_PULL_H
#define NODUS_DHT2_PULL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dht2/dht2_types.h"
#include "dht2/nodus_dht2_holder.h"
#include "dht2/nodus_dht2_store.h"
#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The pull messages (row 12). RECEIPT carries a sealed RFC 0002 envelope;
 *  every other kind a strict DAG-CBOR map (dht2_msg.h). */
typedef enum {
    NODUS_DHT2_PULL_HELLO = 0,   /* p_hello: request = empty Syn (0xa0),
                                  * reply = {g, top}                    */
    NODUS_DHT2_PULL_GET,         /* p_get   {g, s}                      */
    NODUS_DHT2_PULL_OFFER,       /* p_offer {g, top, e}                 */
    NODUS_DHT2_PULL_WANT,        /* p_want  {b}                         */
    NODUS_DHT2_PULL_DELIVER,     /* p_deliver {i, v}                    */
    NODUS_DHT2_PULL_RECEIPT      /* pull-receipt envelope               */
} nodus_dht2_pull_msg_t;

/** Largest message the module may hand to the send function (a p_deliver
 *  with a 262,144 B envelope, and the pull-receipt envelope, are below). */
#define NODUS_DHT2_PULL_MSG_MAX  (DHT2_ENVELOPE_MAX + 64u)

/** Epochs between the hand-over quorum and the drop of the record (decision
 *  2026-10-27-dht-v2-handover-one-receipt.md: operator, "Bekleme 48 epoch
 *  olsun mu?" — "evet"). Node-local; Bee has no such wait. */
#define NODUS_DHT2_PULL_DROP_WAIT_EPOCHS 48u

/** Send `len` bytes of `kind` to the node `peer_fp`. @return 0 sent, other
 *  = the peer is not reachable (the exchange is aborted). */
typedef int (*nodus_dht2_pull_send_fn)(void *user, const uint8_t peer_fp[64],
                                       nodus_dht2_pull_msg_t kind,
                                       const uint8_t *msg, size_t len);

typedef struct nodus_dht2_pull nodus_dht2_pull_t;

/** Everything is borrowed for the module's life (store, identity, view
 *  user). NULL on a bad argument or allocation failure. */
nodus_dht2_pull_t *nodus_dht2_pull_new(nodus_dht2_store_t *store,
                                       const nodus_identity_t *id,
                                       const uint8_t chain[DHT2_CHAIN_LEN],
                                       const nodus_dht2_holder_view_t *view,
                                       nodus_dht2_pull_send_fn send,
                                       void *send_user);
void nodus_dht2_pull_free(nodus_dht2_pull_t *p);

/** This node's fp. */
const uint8_t *nodus_dht2_pull_self_fp(const nodus_dht2_pull_t *p);

/* ── puller ──────────────────────────────────────────────────────────── */

/** §4.5 (iii): the sources — every member of S(H) ∪ S(H − E) but this node,
 *  ascending by fp, each once. `out` holds `cap` fps. @return the number
 *  written, or -1 when there is no fresh snapshot / no sets, or `cap` is
 *  too small (nothing is guessed). */
int nodus_dht2_pull_sources(nodus_dht2_pull_t *p, uint64_t now_ms,
                            uint8_t (*out)[DHT2_FP_LEN], size_t cap);

#define NODUS_DHT2_PULL_STARTED   0
#define NODUS_DHT2_PULL_BUSY      1    /* one exchange per source in flight */
#define NODUS_DHT2_PULL_ERR     (-1)

/** Begin one exchange with `source_fp`: sends the p_hello request (the empty
 *  Syn, 0xa0). */
int nodus_dht2_pull_start(nodus_dht2_pull_t *p, uint64_t now_ms,
                          const uint8_t source_fp[DHT2_FP_LEN]);

#define NODUS_DHT2_PULL_CONTINUE  0    /* waiting for the next reply        */
#define NODUS_DHT2_PULL_DONE      1    /* the exchange ended normally       */
#define NODUS_DHT2_PULL_ABORTED (-1)   /* ended abnormally; the cursor of
                                        * this page was not advanced        */

/** A reply (HELLO, OFFER, DELIVER) from `source_fp`. A reply for no
 *  exchange returns NODUS_DHT2_PULL_ABORTED (there is nothing to drop); a
 *  reply of the wrong kind for the exchange's state drops that exchange and
 *  returns NODUS_DHT2_PULL_ABORTED. */
int nodus_dht2_pull_on_reply(nodus_dht2_pull_t *p, uint64_t now_ms,
                             const uint8_t source_fp[DHT2_FP_LEN],
                             nodus_dht2_pull_msg_t kind, const uint8_t *msg,
                             size_t len);

/** The peer is gone (disconnect / stream close): abort the exchange with it
 *  as puller and forget what the source side held for it. */
void nodus_dht2_pull_disconnect(nodus_dht2_pull_t *p,
                                const uint8_t peer_fp[DHT2_FP_LEN]);

/**
 * Epoch driver (call it when the snapshot's epoch may have changed; it is
 * cheap when the epoch is unchanged since the last check). The epoch the
 * cursors were last checked against is PERSISTED (store meta "pull_e"), so a
 * restart does not forget it. At an epoch that differs from the persisted one:
 *   · Bee puller.go:178-189 — if the persisted epoch is exactly the previous
 *     boundary (e − DNAC_EPOCH_LENGTH) and this node's RESPONSIBILITY GREW (a
 *     key exists that is in nearest_R(S(H)) of this node and was not in
 *     nearest_R(S(H − E))), abort every exchange and reset every cursor to
 *     0, so each source is re-scanned from 0;
 *   · with NO persisted epoch, or one that is not the previous boundary (a
 *     boundary was missed), the responsibility of the cursors is unknown:
 *     the same reset, unconditionally;
 *   · §4.5 (v) — every permanent record this node no longer holds
 *     (this node not in eligible(placement key)) gets the persisted
 *     hand-over flag; every permanent record already flagged is re-counted
 *     against the CURRENT nearest_R (a membership change alone can meet the
 *     quorum): met → its drop is scheduled for this epoch +
 *     NODUS_DHT2_PULL_DROP_WAIT_EPOCHS × E; DROPPED at the first check at or
 *     after that epoch while the quorum is still met; eligible again →
 *     flag, acknowledgements and schedule cleared, nothing dropped.
 * The new epoch is persisted last, after the reset and the scan completed.
 * @return 0 (nothing to do or done), 1 (no fresh snapshot / sets: try
 *         again later), -1 (store fault; the epoch is NOT recorded).
 */
int nodus_dht2_pull_epoch_check(nodus_dht2_pull_t *p, uint64_t now_ms);

/* ── source ──────────────────────────────────────────────────────────── */

/** A request (HELLO, GET, WANT, RECEIPT) from `peer_fp`, an authenticated
 *  storage node of the session. @return 0 handled (replies, if any, went
 *  through the send function), -1 the request was dropped (malformed, a
 *  generation mismatch, no snapshot, a store fault, a send failure) — the
 *  reason is logged. */
int nodus_dht2_pull_serve(nodus_dht2_pull_t *p, uint64_t now_ms,
                          const uint8_t peer_fp[DHT2_FP_LEN],
                          nodus_dht2_pull_msg_t kind, const uint8_t *msg,
                          size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT2_PULL_H */
