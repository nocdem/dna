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
 *   - Connections via nodus_tcp_connect() (dedicated witness TCP port 4004)
 *   - IDENT exchange via T3 CBOR protocol
 *
 * @file nodus_witness_peer.h
 */

#ifndef NODUS_WITNESS_PEER_H
#define NODUS_WITNESS_PEER_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_committee.h"   /* nodus_committee_member_t */
#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Lifecycle ───────────────────────────────────────────────────── */

/** Initialize peer mesh: build initial roster, connect seeds on witness port. */
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

/** Ensure peer entry for a roster-verified sender on an inbound conn. */
void nodus_witness_peer_ensure(nodus_witness_t *w,
                                const uint8_t *witness_id,
                                struct nodus_tcp_conn *conn);

/** Send w_ident to a specific connection. */
int nodus_witness_peer_send_ident(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn);

/** Rebuild roster from connected+identified witness peers + DHT registry + self. */
int nodus_witness_rebuild_roster_from_peers(nodus_witness_t *w,
                                            nodus_witness_roster_t *out_roster);

/** Get number of connected, identified witness peers. */
int nodus_witness_peer_connected_count(const nodus_witness_t *w);

/** Clear all peer references to a connection (called on TCP disconnect). */
void nodus_witness_peer_conn_closed(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn);

/* ── Phase 13 / Task 59 — Committee-snapshot BFT roster ─────────── */

/**
 * Return the BFT peer set (committee) authoritative for a given block
 * height. Wraps nodus_committee_get_for_block(), which hits the per-epoch
 * cache populated by Task 53 — so this is a cheap O(committee_size)
 * memcpy for every call within the same epoch.
 *
 * The returned committee is defined by design §3.6:
 *   - frozen per epoch (cache key = e_start = (h / EPOCH) * EPOCH)
 *   - not affected by STAKE / DELEGATE / UNSTAKE mid-epoch
 *   - re-resolved on the first query after block_height crosses an
 *     epoch boundary (cache miss triggers compute_committee_for_epoch)
 *
 * Callers decide which block's committee they need:
 *   - BFT PROPOSAL / PREVOTE / PRECOMMIT quorum for block N:
 *       pass block_height = N (the block being proposed).
 *   - Per-block reward accumulator / attendance record after commit:
 *       pass block_height = N (the block just committed).
 *   - Pre-proposal leader election for "next" block:
 *       pass nodus_witness_block_height(w) + 1.
 *
 * This supersedes the legacy w->roster source (DHT nodus:pk registry +
 * peer mesh) for consensus-roster purposes. The DHT roster is still used
 * for w_ident / w_rost_q peer discovery and TCP-4004 reconnection — it
 * answers "who do I open a BFT socket to" rather than "who has a vote
 * on block N". The two sources converge once the registry and the
 * committee cache both reflect the post-genesis validator set.
 *
 * @param w             Witness context (DB must be open)
 * @param block_height  Block to look up the committee for
 * @param out           Caller-allocated array of >= max_entries members
 * @param max_entries   out[] capacity (usually DNAC_COMMITTEE_SIZE)
 * @param count_out     [out] Number of members populated (may be 0)
 * @return 0 on success, -1 on error
 */
int nodus_witness_peer_current_set(nodus_witness_t *w,
                                     uint64_t block_height,
                                     nodus_committee_member_t *out,
                                     int max_entries,
                                     int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_PEER_H */
