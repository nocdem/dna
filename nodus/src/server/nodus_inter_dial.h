/**
 * Nodus — the 4002 inter-node session (SecretConnection, NODE profile) and
 * the outbound 4002 pool, one shared module
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md items 16,
 * 28: core and the nodus-storage process link the SAME code, so the dial pin
 * cannot be lost in a copy.
 *
 * DHT v2 sub-package 3b-2 (decisions/2026-10-23-kurultay-43-summary.md,
 * 2026-10-23-dht-v2-session-cutover.md, 2026-10-23-dht-v2-session-bytes.md):
 * the old dialer handshake that lived here — T2 hello → challenge → auth →
 * auth_ok (kpk_sig, identity pin) → key_init → key_ack → channel crypto, with
 * its plaintext dial for a node without a Kyber identity — is DELETED. A 4002
 * connection speaks the 4004 SecretConnection (nodus_tcp_sc.h), profile NODE,
 * purpose 0x0D, protocol version NODUS_NSESS_PROTO_VERSION:
 *
 *   dialer     INITIATOR, pinned to the exact node id it meant to dial (the
 *              routing / roster node_id recorded at dial time); the layer
 *              aborts BEFORE the ENCAPS job when the responder's claimed key
 *              hashes to another id (O-4);
 *   acceptor   RESPONDER, any identity that proves its key is admitted
 *              (khan A: per-operation holder authorization comes in packages
 *              6-7);
 *   both       nodus frames travel unchanged inside the sealed stream (O-1);
 *              every send before the session is authenticated waits in the
 *              connection's DIAL QUEUE (plaintext, pre-framed) and is
 *              replayed, sealed and in order, when the owner opens the gate
 *              (nodus_inter_dial_conn_open) at on_session.
 *
 * The module knows no server or session type. A pool OWNER hands it, through
 * the pool's `auth_ctx`, a nodus_inter_session_cfg_t (this node's identity
 * and the way to learn the chain id the sessions are bound to).
 *
 * Single-threaded per pool; no global state; the only clock is the caller's
 * `now` in the sweep.
 *
 * @file nodus_inter_dial.h
 */

#ifndef NODUS_INTER_DIAL_H
#define NODUS_INTER_DIAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_tcp;
struct nodus_tcp_conn;

/* ── The node session of a 4002 connection ──────────────────────────── */

/**
 * What a 4002 pool owner provides, through `pool->auth_ctx`. The struct must
 * outlive the pool; `identity` too (the layer keeps a pointer to its signing
 * key for the life of the connection).
 */
typedef struct {
    /** This node's identity: the signing key; for an ACCEPTED connection
     *  also the ML-KEM-1024 pair (identity->has_mlkem is required). */
    const nodus_identity_t *identity;
    /** Fill out[32] with the chain id the node sessions are bound to; false
     *  while it is not known (core: no chain open yet, or the witness not
     *  answering; storage: no fresh snapshot of its witness). Then the dial is
     *  REFUSED and the accept is closed — fail closed, no session without a
     *  chain. */
    bool (*chain_id)(void *ctx, uint8_t out[32]);
    void *ctx;
} nodus_inter_session_cfg_t;

/**
 * Turn the node session on for `conn` of `pool` (right after
 * nodus_tcp_connect for a dial, from on_accept for an accept).
 *  - the cfg is `pool->auth_ctx`; none, or an unknown chain id → -1;
 *  - initiator: the conn's pin (conn->expected_peer_id) must be set — an
 *    unpinned dial is refused (-1), there is no unpinned 4002 dial;
 *  - on success the conn's send gate is closed until nodus_inter_dial_conn_open
 *    (conn->auth_required = true; a dialed conn is AUTH_HELLO_SENT so the
 *    pool sweep's stuck-handshake close applies to it).
 * @return 0, or -1 with the connection left as it was (the caller closes it).
 */
int nodus_inter_session_enable(struct nodus_tcp *pool, struct nodus_tcp_conn *conn,
                               bool initiator);

/**
 * The session of `conn` just became AUTHENTICATED (tcp->on_session): copy the
 * proven peer identity onto the connection — conn->peer_pk, peer_id (the
 * SHA3-512 fingerprint of that key), peer_id_set, authenticated. A conn we
 * dialed has its pin re-checked here against the proven key (the layer
 * already did before ENCAPS; a second look costs a hash).
 * @return 0, or -1 (no key to read, or the pin differs): close the connection.
 */
int nodus_inter_session_proven(struct nodus_tcp_conn *conn);

/* ── The outbound 4002 pool (split S5b, decision items 16, 28) ─────────
 *
 * The find-or-dial rule, the pre-framed send, the dialed-conn hygiene and
 * the hint filter that core's inter-node pool always used, so that core
 * (presence, circuits) and the nodus-storage process (replication, republish,
 * hinted handoff) run the SAME code on their own pools. Every function works
 * on the pool it is given and on nothing else; none holds state of its own.
 */

/** Idle limit of a 4002 connection in seconds (core's IDLE_TIMEOUT_AUTH). */
#define NODUS_INTER_POOL_IDLE_SEC        180
/** A dialed conn whose session is not authenticated after this many seconds
 *  is closed (its state is still AUTH_HELLO_SENT). */
#define NODUS_INTER_POOL_HELLO_TIMEOUT_SEC 10

/**
 * The find half of find-or-dial: with `expected_node_id` NULL, the first
 * pool entry for ip:port, whatever it is; with a node_id, the first conn
 * (pool slot order) WE dialed whose identity is that node_id — its
 * expected_peer_id and/or its proven peer_id equal it, and neither, when
 * set, differs. Never an AF_UNIX conn. NULL when none qualifies.
 */
struct nodus_tcp_conn *nodus_inter_pool_find(struct nodus_tcp *pool,
                                             const char *ip, uint16_t port,
                                             const nodus_key_t *expected_node_id);

/**
 * Find-or-dial: nodus_inter_pool_find, else a new connection marked
 * is_nodus with `expected_node_id` recorded as the pin
 * (conn->expected_peer_id) and the node session enabled on it as INITIATOR
 * (nodus_inter_session_enable). A dial without a pin (refused BEFORE the
 * find), or whose session cannot be enabled (no config, chain id not known —
 * checked BEFORE nodus_tcp_connect, so no useless TCP connect is made), is not
 * made: NULL, nothing left allocated.
 * @return the connection, or NULL if the dial could not be started.
 */
struct nodus_tcp_conn *nodus_inter_pool_dial(struct nodus_tcp *pool,
                                             const char *ip, uint16_t port,
                                             const nodus_key_t *expected_node_id);

/** Result of nodus_inter_pool_send_framed. */
typedef enum {
    /** The dial was refused LOCALLY, before any connection was made: no pin,
     *  no node-session config, or the chain id not known (yet). Nothing is
     *  queued. Unlike FAILED nothing was attempted against the peer, so a
     *  durable-work retry (the hinted-handoff retry) must NOT count it as a
     *  failed delivery attempt (retry_count). Every caller that only asks
     *  "was it accepted" treats it as a failure (`< 0`), as FAILED. */
    NODUS_INTER_SEND_REFUSED = -2,
    /** The dial / write failed, or the pool refused the dial (no pin, chain
     *  id unknown, session not enable-able): nothing is in memory for this
     *  frame. The caller decides on a hint. */
    NODUS_INTER_SEND_FAILED  = -1,
    /** The frame was handed to an AUTHENTICATED session and sealed into the
     *  connection's write path — and NOT diverted by the transport's
     *  queue-full fallback (tcp->on_pending_full: the frame was parked in the
     *  hint table or dropped instead; the send reports 0 but delivered
     *  nothing, so that case is QUEUED below). The only result that proves
     *  delivery to the peer's transport — a hinted-handoff row may be deleted
     *  on it. */
    NODUS_INTER_SEND_WRITTEN = 0,
    /** The session is not authenticated yet: the frame waits in the
     *  connection's in-memory dial queue and is lost if the handshake fails.
     *  NOT a delivery — a durable row must stay (rolling deploy: the peer may
     *  be an old build that cannot speak the new handshake). */
    NODUS_INTER_SEND_QUEUED  = 1
} nodus_inter_send_t;

/**
 * Send one PRE-FRAMED frame (7-byte header + payload) to a peer's 4002:
 * find-or-dial with the pin; while the session is not authenticated the bytes
 * wait in the conn's dial queue (cap NODUS_TCP_PENDING_MAX) and the result is
 * NODUS_INTER_SEND_QUEUED; on an open session the payload goes through
 * nodus_tcp_send_progress (sealed) and the result is NODUS_INTER_SEND_WRITTEN
 * — unless the transport diverted the frame to its queue-full fallback
 * (tcp->on_pending_full, hint table or drop; the send reports success but
 * nothing was written): then NODUS_INTER_SEND_QUEUED, so a durable row stays.
 * A failed write (slow consumer) disconnects the connection (FAILED). A dial
 * refused locally (no pin, no config, chain id unknown) is
 * NODUS_INTER_SEND_REFUSED.
 */
nodus_inter_send_t nodus_inter_pool_send_framed(struct nodus_tcp *pool,
                                                const char *ip, uint16_t port,
                                                const nodus_key_t *expected_node_id,
                                                const uint8_t *frame, size_t flen);

/**
 * The pool's half of core's idle sweep, at `now` (seconds,
 * nodus_time_now): a connected conn idle longer than
 * NODUS_INTER_POOL_IDLE_SEC is disconnected; a conn in HELLO_SENT for more
 * than NODUS_INTER_POOL_HELLO_TIMEOUT_SEC is marked AUTH_FAILED and
 * disconnected. That bound covers connect + handshake and is measured on the
 * MONOTONIC clock from the dial (conn->dial_mono_ms); a conn still CONNECTING
 * is under it too (its connected_at is 0 until the connect completes). The
 * caller decides how often it runs.
 */
void nodus_inter_pool_sweep(struct nodus_tcp *pool, uint64_t now);

/**
 * The hint filter (decision item 33): is this 4002 payload a DHT
 * REPLICATION frame — a CBOR map whose envelope says query ("y" == "q")
 * and whose method ("q") is "sv" or "m_sv"? Only those may be parked in
 * the hinted-handoff table on pending-full; everything else is dropped.
 */
bool nodus_inter_frame_is_replication(const uint8_t *payload, size_t len);

/**
 * Open a 4002 conn's send gate when its session is authenticated: auth_state
 * OK, then every frame of the dial queue (pre-framed plaintext, never written
 * as it is) is REPLAYED through nodus_tcp_send, in queue order — sealed. A
 * frame that does not parse ends the replay (the rest is dropped, logged).
 * Works on any 4002 conn, dialed or accepted.
 */
void nodus_inter_dial_conn_open(struct nodus_tcp_conn *conn);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_INTER_DIAL_H */
