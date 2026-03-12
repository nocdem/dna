/**
 * Nodus — Witness Peer Mesh
 *
 * Manages TCP connections to peer witnesses for BFT consensus.
 * Handles identification exchange, reconnection with exponential
 * backoff, request forwarding, and roster synchronization.
 *
 * Ported from dnac/src/bft/peer.c and dnac/src/bft/roster.c.
 * Key differences from DNAC:
 *   - No pthreads (reconnection in tick, not separate thread)
 *   - No global state (all in nodus_witness_t)
 *   - Connections via nodus_tcp_connect() (reuses server inter-node TCP pool)
 *   - IDENT exchange via T3 CBOR protocol
 *
 * @file nodus_witness_peer.h
 */

#ifndef NODUS_WITNESS_PEER_H
#define NODUS_WITNESS_PEER_H

#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Lifecycle ───────────────────────────────────────────────────── */

/** Initialize peer mesh: load roster file, connect to all entries. */
int  nodus_witness_peer_init(nodus_witness_t *w);

/** Periodic tick: reconnect peers, send pending IDENTs. */
void nodus_witness_peer_tick(nodus_witness_t *w);

/** Clean up peer references (connections owned by server TCP). */
void nodus_witness_peer_close(nodus_witness_t *w);

/* ── Message handlers (called from nodus_witness_dispatch_t3) ──── */

/** Handle w_ident: map inbound connection to roster entry. */
int nodus_witness_peer_handle_ident(nodus_witness_t *w,
                                    struct nodus_tcp_conn *conn,
                                    const nodus_t3_msg_t *msg);

/** Handle w_fwd_req: accept forwarded client request (leader only). */
int nodus_witness_peer_handle_fwd_req(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg);

/** Handle w_fwd_rsp: receive forward response from leader. */
int nodus_witness_peer_handle_fwd_rsp(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg);

/** Handle w_rost_q: respond with current roster. */
int nodus_witness_peer_handle_rost_q(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     const nodus_t3_msg_t *msg);

/** Handle w_rost_r: merge received roster entries. */
int nodus_witness_peer_handle_rost_r(nodus_witness_t *w,
                                     const nodus_t3_msg_t *msg);

/* ── Utilities ─────────────────────────────────────────────────── */

/** Send w_ident to a specific connection. */
int nodus_witness_peer_send_ident(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn);

/** Load roster entries from file (one IP:port per line). */
int nodus_witness_roster_load_file(nodus_witness_t *w,
                                   const char *filename);

/** Get number of connected, identified witness peers. */
int nodus_witness_peer_connected_count(const nodus_witness_t *w);

/** Clear all peer references to a connection (called on TCP disconnect). */
void nodus_witness_peer_conn_closed(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_PEER_H */
