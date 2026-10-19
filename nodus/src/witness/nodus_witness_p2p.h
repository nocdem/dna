/**
 * @file nodus/src/witness/nodus_witness_p2p.h
 * @brief The nodus HOST of the ported cometbft @v0.38.26 p2p layer
 *        (shared/dnac/cmt_p2p_*) — the witness port 4004's ONLY
 *        transport (fleet P2P-PORT phase F5).
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * (K2 — the reference admission model with the chain's bonded identities
 * exempt from the inbound cap; N7 SON — validator addresses leave the DHT
 * and travel as self-signed ADDR records over PEX; the sentry knobs; the
 * "P2P portu bayt/biçim onayları" section — channels 0x70 / 0x71 and the
 * address-book file); docs/plans/2026-09-26-p2p-port-design.md §2 (the
 * glue row), §3 (channels and deletions), §4 (config), §5 (R-P2P-n);
 * docs/plans/2026-09-26-witness-port-session-design.md §2R3 N5 (the bonded
 * set), §2R4 P1 (the chain-quorum quarantine is DELETED), P3 (inbound and
 * outbound handshakes never share a queue), P4 (persistent peers dialed on
 * every start; persisted address book; own record pushed), P5.
 *
 * ── WHAT THE HOST IS ───────────────────────────────────────────────────
 * The shared/dnac p2p layer is socket-free, clock-free and thread-free:
 * it is DRIVEN. This module is what drives it on a live node. Since the
 * net-layer package N3 (design 2026-10-19 §11) the part that needs no
 * witness — the sockets, the worker, the clocks, the identity, the own
 * ADDR record, the address book file, NodeInfo, transport, switch and
 * PEX — is the embedded host net/nodus_p2p_host.{h,c}; this module keeps
 * the bonded set, the consensus seam, the seven reactors and their
 * channel descriptors, M4, the approval-collection tick and the genesis
 * bundle, and hands the host its policy rows. Together:
 *   · the 4004 SOCKETS (`nodus_p2p_io_t`): non-blocking TCP listen /
 *     accept / connect / read / write on its own readiness set
 *     (`nodus_net_poll_t`, nodus/src/net/nodus_net_poll.h: epoll on
 *     Linux, level-triggered), RAW byte
 *     streams into and out of `cmt_p2p_transport_read_buf` /
 *     `_write_buf` — nodus_tcp's frame layer is NOT used on 4004.
 *     `can_accept` is asked before every accept(2) (LimitListener,
 *     transport.go:261-263). Reads and writes are CONTINUOUS within a pass,
 *     as the reference's recvRoutine / sendRoutine goroutines are
 *     (connection.go:590-694, :429-507; R-P2P-17): a socket is read into
 *     `read_buf`, and whenever that is full the connection's step
 *     (`cmt_p2p_transport_pump_conn`) consumes it and the socket is read
 *     again — until recv(2) would block, the step frees no room (true
 *     backpressure: the recv flowrate Monitor, connection.go:598, or the
 *     MConnection refuses), or one recv-Monitor sample's quota was taken
 *     (⚠ NOT GROUNDED per-call cap, nodus_witness_p2p.c io_read_budget);
 *     writes likewise refill `write_buf` from the step — its SEND half
 *     only: the write path delivers no message (decision
 *     2026-09-27-p2p-fix-2.md (4)) — between send(2)s until send would
 *     block or nothing is left. At most NODUS_P2P_ACCEPT_BUDGET accept(2)
 *     calls per pass. EPOLLIN is cleared only
 *     at true backpressure and re-armed before every wait once `read_buf`
 *     has room again. IP literals only (R-P2P-24).
 *   · the WORKER: N pthreads over three bounded queues — outbound
 *     handshakes, inbound handshakes (never the same queue, §2R4 P3) and
 *     received ADDR-record verifications (R-P2P-43). Results come back to
 *     the loop and are applied there by (slot, generation) (R-P2P-3/-8).
 *     Every submitted job is completed or dropped before the transport is
 *     freed.
 *   · the CLOCKS: a MONOTONIC clock for every p2p deadline (D3, R-P2P-15);
 *     WALL time only for the address book's persisted timestamps
 *     (R-P2P-35). Transport-local randomness comes from the OS (D4).
 *   · IDENTITY: the node key is the nodus identity (nodus.pk / nodus.sk,
 *     ML-DSA-87), the KEM key nodus.mlkem_{pk,sk}. Our NodeInfo: network =
 *     the 32-byte version-3 chain id in hex (a joiner that has not adopted
 *     yet puts its genesis pin there — the same 32 bytes), P2P version 8,
 *     channels 0x40 (first, as node/node.go:948-954 lists
 *     BlocksyncChannel first), 0x20-0x23, 0x30, 0x70, 0x71, 0x72, 0x73 and 0x00 when
 *     PEX is on, a non-empty moniker, an IP-literal listen address. A peer
 *     of an older build does not list 0x40; nothing is ever sent to it on
 *     that channel (cmt_p2p_peer.c peer_has_channel, peer.go:309-325).
 *   · the BONDED SET (K2 / N5): the local chain's `validators` rows with
 *     status ACTIVE (0) or ELIGIBLE (4), plus the `node_pk` (from
 *     `v2_storage_nodes`, by node_fp, whatever the row's status) of every
 *     member of the frozen storage sets S(H) and S(H − E), H the boundary
 *     of the committed tip's epoch as the archive derives it
 *     (nodus_stprobe_epoch_for_tip; S(H − E) only when H > E) — khan
 *     decision docs/plans/decisions/2026-10-14-kurultay-22-summary.md
 *     item 3(a) (node-local admission, no chain change) with the
 *     membership rule of docs/plans/2026-10-14-dht-v2-design.md §2
 *     "4004 admission" / "One eligibility function" (operator decision
 *     2026-10-14, "Evet"). Membership decides, not status: an EXITING
 *     member stays until the boundary that drops it; a newly ACTIVE
 *     registry row is not a member until the next boundary freezes it in;
 *     before the storage activation there is no set (each set holds at
 *     most DNA_V2_STORAGE_SET_MAX = 256 members) — plus the
 *     members of the committees for tip + 1 and tip − 1 (the two
 *     committees the deleted B1 IDENT gate consulted) — recomputed
 *     whenever the local tip moves.
 *     (HF-6 slice 6e's pending consensus keys are gone with ROTATE — khan
 *     decision 2026-10-13-kurultay-18-summary.md item 1.)
 *     The FULL set is the switch's `is_bonded` (unconditional, R-P2P-7),
 *     the transport's `bonded_count` (the listener limit, R-P2P-27), the
 *     address book's `bonded_pubkey` (R-P2P-4) and PEX's own-record push
 *     (a bonded node pushes its signed ADDR record).
 *     Only the VALIDATOR subset — the `validators` rows and the tip ± 1
 *     committees, every entry not added SOLELY as a storage-set member (a
 *     key that is both is a validator) — is the 4001 `dnac_roster` reply's
 *     list (nodus_witness_handlers.c handle_dnac_roster) and the 0x71
 *     governance-approval bonded gate (nodus_witness_chain_config.c
 *     nodus_witness_handle_cc_appr_req):
 *     `nodus_witness_p2p_is_validator_bonded`. A storage node gets the
 *     connection-admission treatment and nothing else (the same khan
 *     decision, item 3(a): "node-local admission").
 *     VALIDATOR PRIORITY (operator decision 2026-10-14, "Tamam, muaf
 *     olsun. Dediğin gibi olsun"; docs/plans/2026-10-14-dht-v2-design.md
 *     §2 "4004 admission", the validator-priority paragraph): cap-exempt
 *     storage peers can fill all CMT_CONR_MAX_PEERS consensus / mempool
 *     indices (THE CONSENSUS SEAM below). When they are full and a
 *     validator-bonded peer arrives, a peer that is NOT validator-bonded
 *     is disconnected and its index goes to the validator — the lowest
 *     such index, never a configured persistent peer or a configured
 *     unconditional ID (nodus_witness_p2p.c lane_slot_evict_for). A
 *     non-validator that arrives to a full table is connected without an
 *     index, as before.
 *   · our own signed ADDR record (N7 ADDR bytes, purpose 0x0B): its `seq`
 *     is persisted next to the identity BEFORE anything is signed; at
 *     start seq = max(stored, the highest own seq the book has seen) + 1.
 *   · the address book file, next to the chain database, replaced
 *     atomically (temporary file + fsync + rename).
 *   · the REACTORS: PEX (0x00), the consensus reactor cmt_conr
 *     (0x20-0x23), the mempool reactor cmt_memr (0x30), the block sync
 *     reactor cmt_bsync (0x40; decision 2026-09-29-blocksync-before-
 *     testnet.md), and four nodus reactors — 0x70 the genesis bundle (the
 *     former tier-3 verbs 24/25), 0x71 the governance approval (the
 *     former verbs 40/41), 0x72 the archive probe (storage reward
 *     package B2b-1, nodus_witness_storage_reporter.h; decision K6) and
 *     0x73 the segment fetch (package B2b-2,
 *     nodus_witness_storage_holder.h; the byte awaits operator
 *     approval). Registration order is CONSENSUS, MEMPOOL,
 *     BLOCKSYNC: the consensus shim's InitPeer assigns the peer's index,
 *     so it must run first. The reference registers MEMPOOL, BLOCKSYNC,
 *     CONSENSUS (setup.go:432-435) but runs InitPeer / AddPeer by ranging
 *     over a map (p2p/switch.go:77, :830-832, :859-861), in no fixed
 *     order — this fixed order is one it can take. It decides only which
 *     reactor's AddPeer message a new peer receives first.
 *
 * ── THE BLOCK SYNC SEAM ────────────────────────────────────────────────
 * cmt_bsync names a peer by its p2p ID (`cmt_p2p_peer_id`), never by an
 * index: its pool bans an identity, and a ban must outlive the
 * connection (blocksync/pool.go:494). The shim follows R-P2P-47 like the
 * other two: before `nodus_witness_p2p_lane_live` (no chain yet — a
 * pinned-genesis joiner — or genesis time not reached) a 0x40 message is
 * DROPPED, never answered and never a reason to stop the peer — EXCEPT a
 * StatusResponse: ⚠ DEVIATION (no reference counterpart; the reference's
 * switch starts every reactor before accepting a peer, p2p/switch.go:
 * 234-246, so it has no pre-live window) — the LATEST StatusResponse per
 * peer (its lane slot, keyed by the p2p ID, one small canonical copy) is
 * held and replayed into the reactor at `lane_live`, so the pool knows
 * the peer's height at once instead of at its 10 s status broadcast
 * (blocksync/reactor.go:401); discarded on peer removal and unbind. At `lane_live`
 * every connected peer gets the reactor's AddPeer (our StatusResponse,
 * blocksync/reactor.go:195-208) after the consensus and mempool reactors' own, then
 * its held StatusResponse; the caller starts the block sync reactor
 * BEFORE `lane_live`. After the switch to consensus the reactor stays bound
 * and keeps SERVING (reactor.go:251-305 has no "switched" branch; 709fd12b; at v0.38.26: Receive :348-381 still has none — the new FilterMsgBytes :281-322 does, for a BlockResponse only).
 * Its StopPeerForError is deferred like the others (the peer is found by
 * ID, then by its index); a peer that holds no index (all
 * CMT_CONR_MAX_PEERS in use) cannot be deferred and is only logged.
 *
 * ── THE CONSENSUS SEAM ─────────────────────────────────────────────────
 * cmt_conr / cmt_memr name a peer by an INDEX (0 .. CMT_CONR_MAX_PEERS−1).
 * This host keeps one table of that size: a peer the switch admits gets
 * the lowest free index; the index is released when the switch removes the
 * peer (the switch frees the peer at the end of the next tick — the table
 * drops its pointer at removal). A full table gives a validator-bonded
 * arrival the index of a non-validator peer, which is stopped first
 * (VALIDATOR PRIORITY, the bonded-set bullet above); any other arrival to
 * a full table holds no index (its consensus / mempool messages are
 * dropped). `send` / `try_send` → the peer's
 * Send / TrySend (Send ≡ TrySend, R-P2P-19); `stop_peer_for_error` →
 * `cmt_p2p_switch_stop_peer_for_error`, deferred until the reactor call
 * that raised it has returned (cmt_memr.h: a host row must not re-enter
 * the reactor). The peer id handed to `cmt_conr_init_peer` is
 * SHA3-512(the peer's AUTHENTICATED ML-DSA-87 key)[0..31] — read from the
 * secret connection, never from a message field.
 * DEVIATION R-P2P-47 (proposed): the consensus and mempool reactors are
 * registered on the switch from the start, as SHIMS: before the node holds
 * a chain (a pinned joiner) or before genesis time, a peer is given its
 * index but the two reactors are not told (there is none yet, or it is not
 * running); `nodus_witness_p2p_lane_live` then runs, for every connected
 * peer in index order, the reference's addPeer order — every reactor's
 * InitPeer, then every reactor's AddPeer (switch.go:830-832, :859-861).
 * A consensus / mempool message from a peer the reactors do not know yet
 * is dropped. The reference has no such state: a node starts with its
 * genesis document and its reactors already built.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (p2p-port design §6 D1). The bonded set
 * is read from committed chain state and sorted by ID; peers, indices and
 * reactors are visited in fixed order. The clock reads are the reference's
 * p2p reads (D3). Randomness is transport-local OS randomness (D4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_P2P_H
#define NODUS_WITNESS_P2P_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dnac/cmt_p2p_netaddr.h"
#include "dnac/cmt_p2p_transport.h"
#include "dnac/cmt_p2p_switch.h"
#include "dnac/cmt_conr.h"
#include "dnac/cmt_memr.h"
#include "dnac/cmt_bsync_reactor.h"
#include "dnac/cmt_time.h"

#include "nodus/nodus_types.h"
#include "net/nodus_net_poll.h"
#include "net/nodus_p2p_host.h"      /* the witness-free host (N3)      */
#include "witness/nodus_witness_cmt_store.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_witness;

/* ══ the nodus channels (R-P2P-5, OPERATOR-APPROVED 2026-09-26) ═══════ */

/** Genesis bundle — the former tier-3 verbs 24 (request) / 25 (response).
 *  The message is the verb's former `a` body, unchanged
 *  (nodus_tier3.h). */
#define NODUS_P2P_CH_GBUNDLE  0x70
/** Governance approval — the former tier-3 verbs 40 (request) / 41
 *  (response); the same rule. */
#define NODUS_P2P_CH_CC_APPR  0x71

/* The two nodus channels' descriptors (ChannelDescriptor fields,
 * connection.go:752-760). ⚠ NOT GROUNDED — no reference channel carries
 * these messages; each value is a choice, recorded for its register row.
 * RecvMessageCapacity is each channel's largest message
 * (NODUS_T3_GBUNDLE_MSG_MAX / NODUS_T3_CC_APPR_MSG_MAX, nodus_tier3.h). */
/** 1 = the lowest priority the reference uses (VoteSetBits,
 *  consensus/reactor.go:175): a bundle chunk must never starve votes. */
#define NODUS_P2P_GBUNDLE_PRIORITY     1
/** 4 chunks: a joiner asks for one 48 KB chunk per request interval, so a
 *  few queued chunks cover every joiner a node serves at once. */
#define NODUS_P2P_GBUNDLE_SEND_QUEUE   4
/** 1, as the bundle: a governance approval is rare and not latency-bound. */
#define NODUS_P2P_CCAPPR_PRIORITY      1
/** 2 messages: one request / one reply per approval collection (decision
 *  2026-09-26-cc-approval-via-own-node.md — a node asks each seat once),
 *  plus one slot of slack. */
#define NODUS_P2P_CCAPPR_SEND_QUEUE    2

/** Archive probe — the storage reward's off-chain probe request / answer
 *  (package B2b-1; design docs/plans/2026-10-05-archive-reward-design.md
 *  rev 4 §4, request bytes docs/plans/2026-10-05-archive-reward-bytes.md
 *  §6; message layout nodus_witness_storage_probe.h). ⚠ NOT IN THE
 *  OPERATOR-APPROVED CHANNEL LIST above (decision 2026-09-26-witness-
 *  port-session.md "bayt/biçim onayları" item 3 names 0x70 and 0x71
 *  only): 0x72 is this package's choice, pending the operator's approval
 *  of the byte. It collides with no reference channel (0x00, 0x20-0x23,
 *  0x30, 0x38, 0x40, 0x60, 0x61 — the same item). A peer of an older
 *  build does not list it and is never sent to on it
 *  (cmt_p2p_peer.c peer_has_channel). */
#define NODUS_P2P_CH_STPROBE  0x72
/** 1, as the other nodus channels: a probe answer (~200 KB) must never
 *  starve votes. */
#define NODUS_P2P_STPROBE_PRIORITY     1
/** 4 messages: a reporter sends at most NODUS_STPROBE_SENDS_PER_TICK
 *  requests per pass, a server one answer per request. ⚠ NOT GROUNDED. */
#define NODUS_P2P_STPROBE_SEND_QUEUE   4

/** Segment fetch — a storage holder fetches an archive segment it must
 *  hold, one part per request (package B2b-2; design docs/plans/2026-10-
 *  05-archive-reward-design.md rev 4 §3; message layout
 *  nodus_witness_storage_fetch.h). In the operator-approved channel list
 *  (decision 2026-09-26-witness-port-session.md item 3 names 0x70 /
 *  0x71; decision 2026-10-05-storage-reward-is-for-archive.md K6 adds
 *  0x72, K6b — 2026-10-07 — adds 0x73 as built). It collides with no reference channel (the same
 *  list as 0x72). A peer of an older build does not list it and is never
 *  sent to on it (cmt_p2p_peer.c peer_has_channel). */
#define NODUS_P2P_CH_STFETCH  0x73
/** 1, as the other nodus channels: an answer (≤ ~610 KB) must never
 *  starve votes. */
#define NODUS_P2P_STFETCH_PRIORITY     1
/** 4 messages: a fetching node keeps ONE request outstanding, a server
 *  one answer per request. ⚠ NOT GROUNDED. */
#define NODUS_P2P_STFETCH_SEND_QUEUE   4

/* The config (nodus_p2p_config_t and its helpers), the socket host
 * (nodus_p2p_io_t, NODUS_P2P_ACCEPT_BUDGET), the host clocks and the
 * 0x0A sign / verify are the witness-free host's: net/nodus_p2p_host.h
 * (net-layer design 2026-10-19 §11, package N3), included above. */

/* ══ the witness host ═════════════════════════════════════════════════ */

typedef struct nodus_witness_p2p nodus_witness_p2p_t;

/** What the host is built from. Every pointer is borrowed and must outlive
 *  the host. */
typedef struct {
    const nodus_identity_t   *identity;      /* has_mlkem required        */
    const uint8_t            *chain_id;      /* 32 bytes: chain id or pin */
    const nodus_p2p_config_t *cfg;
    const char *listen_ip;                   /* IP literal (bind)         */
    uint16_t    listen_port;
    const char *external_ip;                 /* "" = none                 */
    const char *data_path;                   /* the address book file     */
    const char *seq_dir;                     /* the own-record seq file   */
    bool        open_listener;               /* false: no accept (tests)  */
    int         n_workers;                   /* 0 = the default (2)       */
} nodus_witness_p2p_params_t;

/**
 * Build the host for `w` (the chain, the bonded set, the 0x70 / 0x71
 * handlers) and start it: node/node.go:283-421's p2p half — transport,
 * switch, the reactors, the address book (loaded, R-P2P-38), PEX; then
 * OnStart (node.go:547-579): switch start, persistent peers dialed.
 * @return the host, or NULL (logged) — then nothing is left running.
 */
nodus_witness_p2p_t *nodus_witness_p2p_new(struct nodus_witness *w,
                                           const nodus_witness_p2p_params_t *prm);

/** Stop the switch (the book is saved), finish or drop every worker job,
 *  close every socket, free everything. NULL-safe. The consensus lane must
 *  be unbound first. */
void nodus_witness_p2p_free(nodus_witness_p2p_t *p);

/**
 * One pass of the host (the witness tick calls it every iteration):
 * worker results, the socket wait (at most `timeout_ms`) and I/O, the
 * switch's tick (handshakes, every peer's MConnection, accepts, dials,
 * reconnects), the PEX tick, the bonded-set and own-record refresh, and a
 * final write of everything the pass produced.
 */
void nodus_witness_p2p_poll(nodus_witness_p2p_t *p, int timeout_ms);

/** The port actually listened on (0 = none) — tests bind port 0. */
uint16_t nodus_witness_p2p_listen_port(const nodus_witness_p2p_t *p);
/** This node's p2p ID. */
const char *nodus_witness_p2p_id(const nodus_witness_p2p_t *p);
/** The switch (tests, the 0x70 joiner). */
cmt_p2p_switch_t *nodus_witness_p2p_switch(nodus_witness_p2p_t *p);

/** Connected peers, in the switch's peer-set order. */
int  nodus_witness_p2p_peer_count(const nodus_witness_p2p_t *p);
/** The ID of the i-th connected peer. @return false outside the set. */
bool nodus_witness_p2p_peer_id_at(const nodus_witness_p2p_t *p, int i,
                                  char out[CMT_P2P_ID_CAP]);
/** Whether `peer_id` is in the switch's peer set now (a connected peer). */
bool nodus_witness_p2p_has_peer(const nodus_witness_p2p_t *p, const char *peer_id);
/** The consensus / mempool index (0 .. CMT_CONR_MAX_PEERS−1) the connected
 *  peer `peer_id` holds, or -1 (not connected, or connected without an
 *  index — THE CONSENSUS SEAM's full table). Read-only (tests). */
int  nodus_witness_p2p_lane_index(const nodus_witness_p2p_t *p, const char *peer_id);
/** Send `msg` to the connected peer `peer_id` on channel `ch` (Send ≡
 *  TrySend, R-P2P-19). @return true when the channel's queue took it. */
bool nodus_witness_p2p_send(nodus_witness_p2p_t *p, const char *peer_id,
                            uint8_t ch, const uint8_t *msg, size_t len);

/* ── channel 0x70 (red-team H2; no reference counterpart, R-P2P-5) ──── */

/** The joiner's genesis-bundle request: send `msg` to `peer_id` on 0x70
 *  and remember (peer_id, offset) as the ONE outstanding request (any
 *  earlier one is forgotten first). @return true when queued. */
bool nodus_witness_p2p_gb_request(nodus_witness_p2p_t *p, const char *peer_id,
                                  uint64_t offset, const uint8_t *msg,
                                  size_t len);
/** A 0x70 response from `peer_id` for `offset`: true — and the
 *  outstanding request is consumed — only when it answers exactly that
 *  request; false for everything else (the caller DROPS it, never stops
 *  the sender: a late honest chunk looks the same). */
bool nodus_witness_p2p_gb_take(nodus_witness_p2p_t *p, const char *peer_id,
                               uint64_t offset);
/** The serving side's per-requester gate: true (and the requester's slot
 *  stamped `now_ms`, monotonic) when `peer_id` was not served within the
 *  last 100 ms; false otherwise, or when the bounded table is full of
 *  requesters all served inside that gap. */
bool nodus_witness_p2p_gb_serve_allow(nodus_witness_p2p_t *p, const char *peer_id,
                                      uint64_t now_ms);
/** The serving side's in-memory copy of the genesis bundle of `chain`
 *  (RT2 B-F2): true and `*out` / `*len` (owned by the host, valid until
 *  the host is freed or the copy replaced) when it is held; false when
 *  nothing is held for that chain — the caller reads the database once
 *  and hands the bytes to nodus_witness_p2p_gb_bundle_keep. */
bool nodus_witness_p2p_gb_bundle(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                 const uint8_t **out, size_t *len);
/** Keep `bytes` (malloc'd, `len` > 0; ownership passes to the host in
 *  every case — freed at once on refusal) as the bundle copy of `chain`,
 *  replacing any other. @return true kept; false refused (NULL / empty). */
bool nodus_witness_p2p_gb_bundle_keep(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                      uint8_t *bytes, size_t len);

/** K2 / N5 — the bonded set (file header): the FULL set, storage-set
 *  members included. Connection admission only. */
bool nodus_witness_p2p_is_bonded(nodus_witness_p2p_t *p, const char *id);
/** `id` is bonded AND in the validator subset (file header): a
 *  `validators` row or a tip ± 1 committee member — never an identity
 *  bonded only as a member of the frozen storage set S(H) or S(H − E).
 *  The 4001
 *  `dnac_roster` list and the 0x71 approval gate use this. */
bool nodus_witness_p2p_is_validator_bonded(nodus_witness_p2p_t *p, const char *id);
int  nodus_witness_p2p_bonded_count(nodus_witness_p2p_t *p);
/** The FULL bonded set, sorted by ID: the i-th entry's ID and chain
 *  pubkey. A caller that wants only the validator subset (the
 *  `dnac_roster` reply) takes the ID and asks
 *  nodus_witness_p2p_is_validator_bonded.
 *  @return false outside the set. */
bool nodus_witness_p2p_bonded_at(nodus_witness_p2p_t *p, int i,
                                 char id[CMT_P2P_ID_CAP],
                                 uint8_t pk[NODUS_PK_BYTES]);

/**
 * The address the signed ADDR record of the bonded identity with chain
 * key `pk` names, as "ip:port" (R-P2P-4: only a verified record is
 * believed). Our own identity answers from our own record.
 * @return true and `out`, or false (no record held).
 */
bool nodus_witness_p2p_signed_addr(nodus_witness_p2p_t *p,
                                   const uint8_t pk[NODUS_PK_BYTES],
                                   char *out, size_t cap);

/** Recompute the bonded set now (the tip moved; a chain was adopted).
 *  Only the IDs that JOINED the set since the last refresh are handed to
 *  the address book's purge (cmt_p2p_addrbook_purge_bonded_ids; RT2
 *  D-F1): an unchanged set purges nothing. */
void nodus_witness_p2p_refresh_bonded(nodus_witness_p2p_t *p);
/** Diagnostic: the number of IDs that joined the bonded set, summed over
 *  every refresh since the host was built (what the purge was given; a
 *  refresh that found the same set adds 0). */
uint64_t nodus_witness_p2p_bonded_joined_total(const nodus_witness_p2p_t *p);

/* ══ the consensus lane (file header, "THE CONSENSUS SEAM") ═══════════ */

/**
 * Prepare the host rows the two reactors are built with: the block-store
 * rows read `store`; `now` is the consensus WALL clock (the SAME callback
 * as the state machine's, cmt_conr.h) and reaches the consensus reactor's
 * stamp sites and the block sync reactor's ban/rate state only; `mono` is
 * the WAIT clock (CLOCK_MONOTONIC) every reactor sleep, ticker and
 * timeout is armed on (decision 2026-09-30-monotonic-waits.md). Call
 * before cmt_conr_init / cmt_memr_init. @return CMT_OK; CMT_FAULT (NULL —
 * including a NULL `now` or `mono` — / memory / already prepared).
 */
int nodus_witness_p2p_lane_prepare(nodus_witness_p2p_t *p,
                                   nodus_cmt_store_t *store,
                                   cmt_now_fn now, void *now_ctx,
                                   cmt_mono_fn mono, void *mono_ctx);
/** The host tables and the receive arena for cmt_conr_init /
 *  cmt_memr_init (valid for the host's life). */
const cmt_conr_host_t *nodus_witness_p2p_conr_host(nodus_witness_p2p_t *p);
const cmt_memr_host_t *nodus_witness_p2p_memr_host(nodus_witness_p2p_t *p);
cmt_pb_arena_t        *nodus_witness_p2p_recv_arena(nodus_witness_p2p_t *p);
/** The reactors the shims now feed (both constructed, not yet started). */
void nodus_witness_p2p_lane_bind(nodus_witness_p2p_t *p, cmt_conr_t *conr,
                                 cmt_memr_t *memr);
/** The reactors are running: admit every connected peer (R-P2P-47) —
 *  consensus and mempool InitPeer / AddPeer, then the block sync
 *  reactor's AddPeer when one is bound.
 *  @return CMT_OK; CMT_FAULT on NULL / unbound reactors, or when a reactor
 *  call made here or from an earlier p2p callback returned CMT_FAULT (the
 *  sticky lane fault, below). */
int  nodus_witness_p2p_lane_live(nodus_witness_p2p_t *p);
/** cmt_conr_tick + cmt_memr_tick (+ cmt_bsync_reactor_tick when bound),
 *  then the deferred StopPeerForErrors.
 *
 *  THE STICKY LANE FAULT: the p2p callbacks (Receive of 0x20-0x23, 0x30,
 *  0x40 and the replayed held StatusResponse; the reactors' InitPeer,
 *  AddPeer and RemovePeer) return nothing, so a CMT_FAULT from a reactor
 *  inside one — node-local by the W1.7 rule — is logged and remembered by
 *  the host, and from then on this call returns CMT_FAULT before ticking
 *  anything; the caller stops consensus participation on it
 *  (nodus_witness.c witness_cmt_tick). It is never cleared. A CMT_REJECT
 *  there is a peer's fault and is handled where it arises, not here.
 *  @return CMT_OK or CMT_FAULT; `*next_deadline_ns` the earliest of the
 *  reactors' deadlines, on the lane's MONOTONIC clock (INT64_MAX = none).
 *  Every reactor reports its deadlines on that one clock, so the minimum
 *  is well defined. */
int  nodus_witness_p2p_lane_tick(nodus_witness_p2p_t *p,
                                 int64_t *next_deadline_ns);
/** The sticky lane fault (above) is set: a reactor call made from a p2p
 *  callback returned CMT_FAULT. Read by witness_cmt_tick BEFORE its
 *  state-machine drain, so a fault raised inside this poll's callbacks is
 *  not followed by one more drain that could sign and broadcast
 *  (decision 2026-09-30-chain-config-int64-bounds.md, "Ek"). NULL reads
 *  as not faulted. */
bool nodus_witness_p2p_lane_faulted(const nodus_witness_p2p_t *p);
/** Detach the reactors (before they are freed): every peer leaves them;
 *  the block sync reactor is unbound too (not freed — its owner frees
 *  it). */
void nodus_witness_p2p_lane_unbind(nodus_witness_p2p_t *p);

/**
 * The block sync reactor's p2p rows (file header, "THE BLOCK SYNC SEAM"):
 * `try_send` / `send` / `broadcast` on channel 0x40 and the deferred
 * `stop_peer_for_error`, all with `ctx` = this host, `now` = the lane's
 * WALL clock and `mono` = the lane's MONOTONIC clock, both as given to
 * `nodus_witness_p2p_lane_prepare` (decision 2026-09-30-monotonic-
 * waits.md). The store / executor rows (`exec_ctx`) are the caller's. Requires a
 * prepared lane. @return CMT_OK; CMT_FAULT on NULL / unprepared lane.
 */
int  nodus_witness_p2p_bsync_host_fill(nodus_witness_p2p_t *p,
                                       cmt_bsync_host_t *out);
/** Bind the block sync reactor the 0x40 shim feeds (constructed, not yet
 *  started); NULL unbinds. The host never frees it. */
void nodus_witness_p2p_bsync_bind(nodus_witness_p2p_t *p,
                                  cmt_bsync_reactor_t *bsync);
/** The bound block sync reactor, or NULL. */
cmt_bsync_reactor_t *nodus_witness_p2p_bsync(const nodus_witness_p2p_t *p);
/** Test/diagnostic accessor: true while a StatusResponse `peer_id` sent
 *  before the lane went live is held for replay (file header, "THE BLOCK
 *  SYNC SEAM", the DEVIATION); `*out_height` (may be NULL) receives the
 *  held message's height. */
bool nodus_witness_p2p_bsync_status_held(const nodus_witness_p2p_t *p,
                                         const char *peer_id,
                                         int64_t *out_height);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_P2P_H */
