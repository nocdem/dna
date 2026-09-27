/**
 * @file shared/dnac/cmt_p2p_pex.h
 * @brief cometbft @709fd12b `p2p/pex/pex_reactor.go` (+ the PEX messages
 *        of `proto/tendermint/p2p/pex.proto`) ported to C — the PEX
 *        reactor on channel 0x00, plus the signed ADDR records of
 *        R-P2P-4.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F4 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "p2p/pex/ *", §9). Only its tests construct one; the nodus glue (F5)
 * registers it on the switch and calls `cmt_p2p_pex_tick` every pass.
 * Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * "N7 SON" (reference PEX + the validator-signed address record; an
 * unrequested list is refused, pex_reactor.go:356-358) and "N7 ADDR bayt
 * düzeni" (the record bytes — cmt_p2p_addrbook.h); session design §2R4 P4
 * (push our own record once after start and on any change) and P5
 * (request rate limit; a response split so each part fits the channel).
 *
 * ── GOROUTINES → ONE EVENT LOOP ────────────────────────────────────────
 * `cmt_p2p_pex_tick` is one pass of `ensurePeersRoutine` (:406-436): the
 * first run waits `jitter` = rand.Int63n(ensurePeersPeriod) only when the
 * node already has a peer or a dial (:415-417), then `ensurePeers(true)`
 * every period (the ticker) and `ensurePeers(false)` when ReceiveAddrs
 * signalled `ensurePeersCh` — delivered only while the routine waits in
 * its select (:380-383 `default:` drops it otherwise). The tick also
 * drives the book's save ticker (cmt_p2p_addrbook_tick), the response
 * parts still to send, and the own-record push. The clock is the host's
 * MONOTONIC clock (design §6 D3: lastReceivedRequests, attemptsToDial's
 * lastDialed and the ticker are `time.Now()` monotonic readings in the
 * reference).
 * The goroutine per dial (:487-499) is the switch's asynchronous dial;
 * its outcome arrives through the switch's dial observer
 * (cmt_p2p_switch_set_dial_observer) and is booked as :554-573 books it.
 * `dialSeeds` (:610-628) blocks the ensure routine until a seed dial
 * succeeds or all fail; here the seed chain advances on each dial outcome
 * and ensurePeers does not run while it is active.
 *
 * ── MESSAGES (channel 0x00, descriptor :179-189) ───────────────────────
 * pex.proto: Message { oneof sum { PexRequest pex_request = 1;
 * PexAddrs pex_addrs = 2; } }, PexAddrs { repeated NetAddress addrs = 1; }
 * — byte-exact to the generated code (R-P2P-2). ADDED, ⚠ NOT GROUNDED
 * (no reference line; operator to confirm, all three together):
 *   PexAddrs.signed_addrs = 2   `repeated bytes` — one ADDR record per
 *                               element (`payload ‖ signature`,
 *                               CMT_P2P_ADDR_REC_SIZE bytes).
 *   PexAddrs.more = 3           `bool` — true on every part of a split
 *                               response but the last (omitted = false).
 *   Message.pex_addr_push = 3   `PexAddrPush { bytes signed_addr = 1; }` —
 *                               the SENDER's own record, pushed after
 *                               connect and on change (P4).
 * A reference peer skips the unknown fields (skipPex) and logs an unknown
 * message type for the push; nothing it does is affected.
 *
 * ── DEVIATIONS (proposed register rows) ────────────────────────────────
 *   R-P2P-4  (approved) signed records: a response carries, beside each
 *            NetAddress, the book's record for that ID; an address whose
 *            ID is BONDED and has no record is not gossiped at all (the
 *            relay half of "believed only if that identity signed it",
 *            G7). Received records go to cmt_p2p_addrbook_add_signed
 *            (verified against the CHAIN key); unsigned addresses to
 *            AddAddress, which refuses a bonded ID.
 *   R-P2P-40 (split, P5) a response whose Message would exceed the
 *            channel's RecvMessageCapacity (maxMsgSize = 64 000,
 *            :27-31) is split into parts of at most that size, `more` set
 *            on all but the last. The requester keeps its `requestsSent`
 *            entry open until a part without `more` arrives or
 *            CMT_P2P_PEX_MAX_PARTS parts have arrived (a bound derived
 *            from the constants below: the most a honest responder can
 *            ever need); one more is unsolicited (ErrUnsolicitedList →
 *            stop + ban, :288-293). The parts wait in a per-peer queue and
 *            leave while the channel can take them (the channel's send
 *            queue holds 10, :184) — the reference sends one message with
 *            `p.Send` and cannot lose half a response.
 *   R-P2P-41 (push, P4) our own record, when the host has one, is pushed
 *            to every peer once after AddPeer and again after
 *            `cmt_p2p_pex_own_record_changed`, as its own message kind —
 *            never a PexAddrs, so it can never trip the unsolicited-list
 *            ban. The receiver accepts a push ONLY if the record's ID is
 *            the sending connection's ID (a foreign record → stop, no
 *            ban) and at most one per minReceiveRequestInterval (a faster
 *            one → stop, no ban — the shape of receiveRequest, :303-334,
 *            with no free pass); the sender spaces its pushes to one peer
 *            by ensurePeersPeriod (the reference's own 3× margin between
 *            the request period and the request limit, :101-105).
 *   R-P2P-42 (order) the addresses ensurePeers picked are dialed in the
 *            order they were picked (the reference ranges over a map,
 *            :487, and dials each in its own goroutine).
 *   R-P2P-43 (verify off the loop — closed in F5) a received record's
 *            ML-DSA-87 verification runs on the host's bounded worker
 *            when the book's host sets `verify_addr_submit`
 *            (cmt_p2p_addrbook.h): `add_signed` then answers
 *            CMT_P2P_AB_PENDING and the entry is added when the verdict
 *            returns (§2R4 P5, G4). A host without a worker keeps the F4
 *            synchronous path through `verify_addr`.
 *   R-P2P-6  seed/crawler mode is not ported (crawlPeersRoutine,
 *            attemptDisconnects, crawlPeerInfos, the seed branch of
 *            Receive :252-269). The `seeds` LIST and `dialSeeds` are
 *            ported (ensurePeers' fallback).
 * Reference facts kept as they are: `markAddrInBookBasedOnErr`'s MarkBad
 * branch (:562, :750) matches `p2p.ErrSwitchAuthenticationFailure`, which
 * no code of the pinned tree constructs (declared at p2p/errors.go:128,
 * the transport returns ErrRejected{isAuthFailure}, transport.go:421-444)
 * — ported literally (CMT_P2P_ERR_SWITCH_AUTH_FAILURE, which this port's
 * transport does not produce either), so every failed dial is a
 * MarkAttempt. A failed Unmarshal / Unwrap of a message stops the peer
 * (peer.go:410-421 panics into onPeerError).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local transport (design §6 D1). Randomness is the host's (D4):
 * jitter, PickAddress, the peer asked, the seed order. Nothing here
 * enters a block, a vote or a root.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_PEX_H
#define CMT_P2P_PEX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_p2p_netaddr.h"
#include "cmt_p2p_peer.h"
#include "cmt_p2p_switch.h"
#include "cmt_p2p_addrbook.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ pex_reactor.go:20-53 — constants ═════════════════════════════════ */

#define CMT_P2P_PEX_CHANNEL                0x00                   /* :22 */
#define CMT_P2P_PEX_MAX_ADDRESS_SIZE       256                    /* :27 */
#define CMT_P2P_PEX_MAX_MSG_SIZE \
    (CMT_P2P_PEX_MAX_ADDRESS_SIZE * CMT_P2P_AB_MAX_GET_SELECTION) /* :31 = 64000 */
#define CMT_P2P_PEX_DEFAULT_ENSURE_PEERS_PERIOD_NS \
    (30LL * 1000 * 1000 * 1000)                                   /* :34 */
#define CMT_P2P_PEX_MAX_ATTEMPTS_TO_DIAL   16                     /* :44 */
#define CMT_P2P_PEX_BIAS_TO_SELECT_NEW_PEERS 30                   /* :49 */
#define CMT_P2P_PEX_DEFAULT_BAN_TIME_NS \
    (24LL * 3600 * 1000 * 1000 * 1000)                            /* :52 */

/* ══ the split bound (R-P2P-40) ═══════════════════════════════════════ */

/** One `addrs` element: tag + 1-byte length + the largest NetAddress. */
#define CMT_P2P_PEX_ADDR_ELEM_MAX  (2 + CMT_P2P_NETADDR_PROTO_MAX)
/** One `signed_addrs` element: tag + 2-byte length + the record. */
#define CMT_P2P_PEX_REC_ELEM       (3 + CMT_P2P_ADDR_REC_SIZE)
/** The Message wrapper (tag + ≤ 3-byte length) and `more` (2 bytes). */
#define CMT_P2P_PEX_PART_OVERHEAD  8
/** Room for elements in one part. */
#define CMT_P2P_PEX_PART_ROOM (CMT_P2P_PEX_MAX_MSG_SIZE - CMT_P2P_PEX_PART_OVERHEAD)
/** Greedy packing leaves less than one element unused per part, so a
 *  full selection (maxGetSelection addresses, each with a record) needs
 *  at most this many parts. */
#define CMT_P2P_PEX_MAX_PARTS \
    ((CMT_P2P_AB_MAX_GET_SELECTION * \
      (CMT_P2P_PEX_ADDR_ELEM_MAX + CMT_P2P_PEX_REC_ELEM) + \
      (CMT_P2P_PEX_PART_ROOM - CMT_P2P_PEX_REC_ELEM) - 1) / \
     (CMT_P2P_PEX_PART_ROOM - CMT_P2P_PEX_REC_ELEM))

/* ══ StopPeerForError reasons (the reference's error values) ══════════ */

#define CMT_P2P_PEX_ERR_DECODE           300  /* peer.go:410-421 Unmarshal / Unwrap */
#define CMT_P2P_PEX_ERR_REQUEST_TOO_SOON 301  /* :324-331                            */
#define CMT_P2P_PEX_ERR_BAD_ADDRS        302  /* :282-287 NetAddressesFromProto      */
#define CMT_P2P_PEX_ERR_UNSOLICITED      303  /* errors.go:89 ErrUnsolicitedList     */
#define CMT_P2P_PEX_ERR_NODE_ADDR        304  /* :361-364 src NodeInfo NetAddress    */
#define CMT_P2P_PEX_ERR_PUSH_FOREIGN     305  /* R-P2P-41                            */
#define CMT_P2P_PEX_ERR_PUSH_TOO_SOON    306  /* R-P2P-41                            */

/* ══ the message codec (pex.proto + the NOT GROUNDED additions) ═══════ */

/** Message{pex_request: {}} — `0a 00`. @return CMT_OK / CMT_REJECT (cap). */
int cmt_p2p_pex_marshal_request(uint8_t *out, size_t cap, size_t *out_len);

/** Message{pex_addrs: {addrs, signed_addrs, more}}. NULL addresses are
 *  skipped (NetAddressesToProto, netaddress.go:167-175).
 *  @return CMT_OK; CMT_REJECT (cap); CMT_FAULT on NULL. */
int cmt_p2p_pex_marshal_addrs(const cmt_p2p_netaddr_t *const *addrs, int n_addrs,
                              const uint8_t *const *recs, int n_recs,
                              bool more, uint8_t *out, size_t cap,
                              size_t *out_len);

/** Message{pex_addr_push: {signed_addr}}. */
int cmt_p2p_pex_marshal_push(const uint8_t *rec, size_t rec_len, uint8_t *out,
                             size_t cap, size_t *out_len);

/* ══ the reactor ══════════════════════════════════════════════════════ */

typedef struct {
    void *ctx;
    /** MONOTONIC clock, ns. Required. */
    int64_t (*now_ns)(void *ctx);
    /** [0, n) (cmtrand). Required. */
    int64_t (*rand_int63n)(void *ctx, int64_t n);
    /** Our own signed ADDR record (`payload ‖ signature`, signed by the
     *  host with its counter persisted BEFORE signing, §2R4 P5). false =
     *  none (this node is not bonded, or has no routable address). NULL =
     *  never. */
    bool (*own_record)(void *ctx, uint8_t rec[CMT_P2P_ADDR_REC_SIZE]);
} cmt_p2p_pex_host_t;

/** pex_reactor.go:108-123 ReactorConfig (SeedMode /
 *  SeedDisconnectWaitPeriod: R-P2P-6). */
typedef struct {
    const char *const *seeds;               /* config.go `seeds`            */
    int     n_seeds;
    int64_t persistent_peers_max_dial_period_ns;   /* config.go:573, 0 = off */
    int64_t ensure_peers_period_ns;         /* 0 = the default (:34)        */
} cmt_p2p_pex_config_t;

typedef struct cmt_p2p_pex cmt_p2p_pex_t;

/** pex_reactor.go:131-143 NewReactor. `book` and `sw` must outlive it;
 *  the reactor installs itself as the switch's dial observer.
 *  @return NULL on a missing host row or memory. */
cmt_p2p_pex_t *cmt_p2p_pex_new(const cmt_p2p_pex_config_t *cfg,
                               const cmt_p2p_pex_host_t *host,
                               cmt_p2p_addrbook_t *book, cmt_p2p_switch_t *sw);

void cmt_p2p_pex_free(cmt_p2p_pex_t *r);

/** The reactor's table for cmt_p2p_switch_add_reactor (name "PEX",
 *  node/setup.go:490). */
void cmt_p2p_pex_reactor(cmt_p2p_pex_t *r, cmt_p2p_reactor_t *out);

/** One pass of the reactor's goroutines (file header). */
void cmt_p2p_pex_tick(cmt_p2p_pex_t *r);

/** pex_reactor.go:338-349 RequestAddrs. */
void cmt_p2p_pex_request_addrs(cmt_p2p_pex_t *r, cmt_p2p_peer_t *p);

/** pex_reactor.go:392-398 SendAddrs (+ R-P2P-4 records, R-P2P-40 split). */
void cmt_p2p_pex_send_addrs(cmt_p2p_pex_t *r, cmt_p2p_peer_t *p,
                            const cmt_p2p_netaddr_t *addrs, int n);

/** pex_reactor.go:401-403 SetEnsurePeersPeriod. */
void cmt_p2p_pex_set_ensure_peers_period(cmt_p2p_pex_t *r, int64_t ns);

/** pex_reactor.go:632-638 AttemptsToDial. */
int  cmt_p2p_pex_attempts_to_dial(const cmt_p2p_pex_t *r,
                                  const cmt_p2p_netaddr_t *addr);

/** R-P2P-41: the host's own record changed — push it to every peer. */
void cmt_p2p_pex_own_record_changed(cmt_p2p_pex_t *r);

/** True while a PexRequest to `id` is unanswered (requestsSent). */
bool cmt_p2p_pex_request_outstanding(const cmt_p2p_pex_t *r, const char *id);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_PEX_H */
