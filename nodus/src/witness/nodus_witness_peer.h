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

/* ── Roster ──────────────────────────────────────────────────────── */

/* R3 W4 — moved verbatim from nodus_witness_bft.h (deleted with the closed
 * consensus lane). Transport-only lookups: witness_id <-> pubkey mapping
 * for the peer mesh, not a consensus authority. */

/** Find witness in roster by ID. Returns index or -1. */
int  nodus_witness_roster_find(const nodus_witness_roster_t *roster,
                                 const uint8_t *witness_id);

/** Add witness to roster (no-op if already present). */
int  nodus_witness_roster_add(nodus_witness_t *w,
                                const nodus_witness_roster_entry_t *entry);

/* ── Lifecycle ───────────────────────────────────────────────────── */

/** Initialize peer mesh: build initial roster, connect seeds on witness port. */
int  nodus_witness_peer_init(nodus_witness_t *w);

/** Periodic tick: reconnect peers, send pending IDENTs. */
void nodus_witness_peer_tick(nodus_witness_t *w);

/** Clean up peer references (connections owned by server TCP). */
void nodus_witness_peer_close(nodus_witness_t *w);

/* PR 3 / F4 — mock nodus_version override for the H-9 mixed-version
 * harness scenario. Set non-zero to make w_ident report the supplied
 * packed (MAJOR<<16|MINOR<<8|PATCH) version instead of the real
 * compile-time value. Zero (default) means real version. */
void     nodus_witness_peer_set_mock_version(uint32_t packed);
uint32_t nodus_witness_peer_get_mock_version(void);

/* ── Message handlers (called from nodus_witness_dispatch_t3) ──── */

/** Handle w_ident: map inbound connection to roster entry. */
int nodus_witness_peer_handle_ident(nodus_witness_t *w,
                                    struct nodus_tcp_conn *conn,
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

/* R3 W4-D — witness_chain_quorum_observe's only prototype site,
 * nodus_witness_bft_internal.h, is deleted with the closed consensus
 * lane. The function itself is NOT deleted (nodus_witness_peer_handle_
 * ident is its one production caller, in this same file); only its
 * test-reachable declaration needed a new home. Gated the same way
 * bft_internal.h gated its whole file, so this declaration is invisible
 * to production translation units that do not opt in — NODUS_WITNESS_
 * INTERNAL_API is defined only by test targets (nodus/CMakeLists.txt's
 * register_witness_test macro / explicit test targets that request it),
 * never by a Release configure.
 *
 * The startup chain-id quorum detector: called from handle_ident for
 * every peer w_ident inside the first 300 s after witness activation,
 * it counts distinct dissenters and agreers and self-quarantines the
 * node on a strict majority of dissent (min 2 dissenters). Sticky —
 * agreement evidence never clears a quarantine. Takes the same
 * (chain_id, db) matrix verify_chain_id used to (that gate is deleted
 * with nodus_witness_bft.c). nodus_witness_peer_handle_ident is the ONLY
 * production caller (one call site, verified tree-wide). Consumed by
 * test_v2_restart_gate.c to pin the DG-2 matrix. */
#ifdef NODUS_WITNESS_INTERNAL_API
void witness_chain_quorum_observe(nodus_witness_t *w,
                                    const uint8_t *peer_id,
                                    const uint8_t *peer_chain_id);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_PEER_H */
