/**
 * Nodus — DHT backend (the server's ONE door to its DHT / storage half)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md, step
 * S4 "core/storage in-process seam" (items 2-4, 16, 17): every call the
 * server's core (sessions, 4001 / WebSocket / 4002 / UDP 4000, cluster,
 * presence) makes into the DHT goes through this interface, as a message:
 * a session is an origin slot, a peer is (node id, ip, ports), a frame is
 * bytes. The DHT answers through its host view (dht/nodus_dht.h,
 * nodus_dht_host_t). Each operation below is a call site the server had
 * before the seam; none adds behaviour.
 *
 * Implementations:
 *   - nodus_dht_backend_inproc.c — the DHT in this process (the combined
 *     nodus-server). Calls the dht/nodus_dht.h functions directly.
 *   - split S5 adds the IPC implementation (the `nodus-storage` process).
 *
 * HOT = per client put / get or per replicated value; COLD = periodic,
 * per peer heartbeat, per session open / close, or on failure only.
 *
 * @file nodus_dht_backend.h
 */

#ifndef NODUS_DHT_BACKEND_H
#define NODUS_DHT_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus_types.h"
#include "dht/nodus_dht.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nodus_dht_backend nodus_dht_backend_t;

typedef struct {
    /** HOT — an authenticated client request (after the token check)
     *  whose method is the DHT's (put, get, get_all, get_batch, cnt_batch,
     *  listen, unlisten, ch_list, ch_search, ch_get, m_put, m_meta,
     *  m_chunk). `payload`/`len` is the frame; `msg` its decode (passed
     *  in-process so the frame is not parsed twice). `client_fp` /
     *  `client_pk`: the session's authenticated identity. Replies go to
     *  (CLIENT, slot) through the DHT host's send_to_origin. */
    void (*client_frame)(nodus_dht_backend_t *b, int slot,
                         const nodus_key_t *client_fp,
                         const nodus_pubkey_t *client_pk,
                         const uint8_t *payload, size_t len,
                         nodus_tier2_msg_t *msg);

    /** HOT — a 4002 T2 frame with a DHT method (fv, get_batch, m_sv),
     *  after core's handshake / F3 gates. Replies go to (INTER, slot). */
    void (*inter_frame)(nodus_dht_backend_t *b, int slot,
                        const uint8_t *payload, size_t len,
                        nodus_tier2_msg_t *msg);

    /** HOT (sv = replication) — a 4002 T1 frame (sv, sub, unsub, ntf)
     *  after core's F2 gate. `peer_fp`: core's session identity of that
     *  peer; `peer_ip`: its connection's address ("" when none). */
    void (*inter_t1)(nodus_dht_backend_t *b, int slot,
                     const nodus_key_t *peer_fp, const char *peer_ip,
                     const uint8_t *payload, size_t len,
                     nodus_tier1_msg_t *t1);

    /** HOT in a large cluster, COLD at 7 nodes — a UDP 4000 T1 datagram
     *  that is not ping / pong (fn, fn_r, sv, fv). */
    void (*udp_frame)(nodus_dht_backend_t *b, const char *from_ip,
                      uint16_t from_port, const uint8_t *payload, size_t len,
                      nodus_tier1_msg_t *msg);

    /** COLD — core saw a peer (UDP ping / pong, cluster ALIVE);
     *  nodus_dht_peer_seen_t says which and fixes the order. */
    void (*peer_seen)(nodus_dht_backend_t *b, nodus_dht_peer_seen_t kind,
                      const nodus_key_t *node_id, const char *ip,
                      uint16_t udp_port, uint16_t tcp_port);

    /** COLD — core's cluster marked a member DEAD. */
    void (*peer_dead)(nodus_dht_backend_t *b, const nodus_key_t *node_id);

    /** COLD — core's session in `origin`'s slot got a connection / was
     *  cleared. Opened: `origin.gen` is the new session's generation (fresh
     *  from core's server-wide counter, decision item 29); the DHT records
     *  it and every reply it sends later must carry it. Closed: the shadow
     *  is cleared whatever `origin.gen` (the ended session's) says. */
    void (*session_opened)(nodus_dht_backend_t *b, nodus_dht_origin_t origin);
    void (*session_closed)(nodus_dht_backend_t *b, nodus_dht_origin_t origin);

    /** COLD — core's inter-node transport could not queue a frame
     *  (pending-full): park it in the hinted-handoff table. SYNCHRONOUS
     *  result (nodus_dht_hint_store) — core's log line names it. */
    int  (*hint_store)(nodus_dht_backend_t *b, const nodus_key_t *node_id,
                       const char *ip, uint16_t port,
                       const uint8_t *frame, size_t len);

    /** COLD (presence sync, every NODUS_PRESENCE_SYNC_SEC) — the routing
     *  table's peers, node id + address (nodus_dht_routing_snapshot); the
     *  node id is the identity the presence dial pins (decision item 30).
     *  In-process it
     *  is read at the call, the very moment the server read the routing
     *  buckets before the seam; split S5 answers it from the snapshot the
     *  storage process pushes (decision item 17). @return the count. */
    int  (*routing_snapshot)(nodus_dht_backend_t *b,
                             nodus_dht_peer_addr_t *out, int max);

    /** true while the backend's own transport has input left on its
     *  pending-read list, so the server loop's polls must not block. In-
     *  process: always false (the DHT has no transport of its own; its
     *  batch-forward epoll is polled without waiting inside `tick`), so the
     *  combined binary's poll timings are unchanged. */
    bool (*read_pending)(nodus_dht_backend_t *b);

    /** Ping-before-evict sweep — the loop runs it right after the cluster
     *  tick (nodus_dht_evict_tick). */
    void (*evict_tick)(nodus_dht_backend_t *b);

    /** The DHT's periodic work — the loop runs it right after the presence
     *  tick (nodus_dht_tick). */
    void (*tick)(nodus_dht_backend_t *b);

    /** First step of a shutdown: abandon lookups and batch forwards. */
    void (*stop)(nodus_dht_backend_t *b);

    /** Close the DHT's databases and free the backend (`b` is invalid
     *  afterwards). */
    void (*close)(nodus_dht_backend_t *b);
} nodus_dht_backend_ops_t;

struct nodus_dht_backend {
    const nodus_dht_backend_ops_t *ops;
};

/* ── In-process implementation (nodus_dht_backend_inproc.c) ───────── */

/**
 * Create the DHT in this process — phase one (nodus_dht_init), run where
 * nodus_server_init set this state up before the seam: before the
 * identity is loaded. `host` is copied; `host->identity` must outlive the
 * backend.
 * @return 0 `*out` set; -1 the batch-forward epoll could not be created
 *         (logged), `*out` NULL; -2 out of memory, `*out` NULL.
 */
int nodus_dht_backend_inproc_new(const nodus_dht_host_t *host,
                                 nodus_dht_backend_t **out);

/**
 * Phase two (nodus_dht_open), after the identity is loaded: the
 * databases, the routing table, the hash ring.
 * @return 0, -1 a database did not open (logged; `close` releases what
 *         did).
 */
int nodus_dht_backend_inproc_open(nodus_dht_backend_t *b, const char *data_path,
                                  const char *self_ip, uint16_t self_peer_port);

/**
 * The in-process DHT state behind `b` (an in-process backend only), for
 * the unit tests that set it up or inspect it directly.
 */
nodus_dht_t *nodus_dht_backend_inproc_state(nodus_dht_backend_t *b);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT_BACKEND_H */
