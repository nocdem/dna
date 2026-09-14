/**
 * @file shared/dnac/cmt_conr.c
 * @brief cometbft @709fd12b `consensus/reactor.go` ported to C. See
 *        cmt_conr.h for the module contract, the threads → ticks
 *        substitution and the deviations R3-A-1/2/3.
 *
 * Every function names the reference range it ports. Every dropped lock,
 * every `time.Sleep` turned into a deadline and every `false` from a send
 * that ends a pass is marked at its site with the Go line.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "cmt_conr.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "cmt_hvs.h"
#include "cmt_params.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "CMT_CONR"

/* Go's `time.Second` in nanoseconds — the unit of :504 and :1379. */
#define CONR_SECOND_NS ((int64_t)1000000000)

/* reactor.go:30 `maxMsgSize` is named twice in this tree — cmt_wal.h:95
 * for the WAL record bound and cmt_ps.h for the send buffer; one value. */
_Static_assert((int)CMT_CONR_MAX_MSG_SIZE == (int)CMT_MAX_MSG_SIZE,
               "CMT_CONR_MAX_MSG_SIZE must equal cmt_wal.h's CMT_MAX_MSG_SIZE "
               "(both are reactor.go:30 maxMsgSize)");

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:143-180 — GetChannels
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/reactor.go:146-179 — the four descriptors. */
static const cmt_conr_channel_desc_t conr_channels[CMT_CONR_NUM_CHANNELS] = {
    /* :147-153 */
    { CMT_CONR_STATE_CHANNEL,         6, 100, 0,         CMT_CONR_MAX_MSG_SIZE },
    /* :154-162 — "maybe split between gossiping current block and catchup
     * stuff; once we gossip the whole block there's nothing left to send
     * until next height or round" */
    { CMT_CONR_DATA_CHANNEL,         10, 100, 50 * 4096, CMT_CONR_MAX_MSG_SIZE },
    /* :163-170 */
    { CMT_CONR_VOTE_CHANNEL,          7, 100, 100 * 100, CMT_CONR_MAX_MSG_SIZE },
    /* :171-178 */
    { CMT_CONR_VOTE_SET_BITS_CHANNEL, 1,   2, 1024,      CMT_CONR_MAX_MSG_SIZE }
};

/* cometbft@709fd12b consensus/reactor.go:144-180 — GetChannels() */
const cmt_conr_channel_desc_t *cmt_conr_get_channels(size_t *out_n)
{
    if (out_n != NULL) {
        *out_n = (size_t)CMT_CONR_NUM_CHANNELS;
    }
    return conr_channels;
}

/* ══════════════════════════════════════════════════════════════════════
 * small helpers
 * ══════════════════════════════════════════════════════════════════════ */

/** The slot for a host index, NULL outside the table. */
static cmt_conr_peer_slot_t *conr_slot(cmt_conr_t *conR, int peer_idx)
{
    if (peer_idx < 0 || peer_idx >= (int)CMT_CONR_MAX_PEERS) {
        return NULL;
    }
    return &conR->peers[peer_idx];
}

/** The host clock — THE clock (cmt_conr.h "DETERMINISM"). */
static int conr_now(const cmt_conr_t *conR, cmt_time_t *out)
{
    if (conR->host.now == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "host row `now` is NULL");
        return CMT_FAULT;
    }
    return conR->host.now(conR->host_ctx, out);
}

/** A `time.Sleep(d)` site (cmt_conr.h "THREADS → TICKS"): record the
 *  deadline for `routine` of `slot`; the caller returns from the pass.
 *  `d` is one of the two config durations, nanoseconds. */
static void conr_sleep(cmt_conr_peer_slot_t *slot, cmt_conr_routine_t routine,
                       int64_t now_ns, int64_t d)
{
    int64_t deadline;

    if (d < 0) {
        d = 0;
    }
    if (now_ns > INT64_MAX - d) {
        deadline = INT64_MAX;
    } else {
        deadline = now_ns + d;
    }
    slot->not_before_ns[routine] = deadline;
    slot->asleep[routine]        = true;
}

/** Reset the send-side message scratch to one kind. */
static cmt_msg_t *conr_msg_begin(cmt_conr_t *conR, cmt_msg_kind_t kind)
{
    cmt_msg_t *m = conR->scratch.msg;

    memset(m, 0, sizeof(*m));
    m->kind = kind;
    return m;
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:499-517 — the NewRoundStep message
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:499-508 — makeRoundStepMessage().
 * :504 `int64(time.Since(rs.StartTime).Seconds())` — `now` is the host
 * clock (the reference's `time.Now()` inside `time.Since`); the
 * difference is formed exactly, in whole seconds, truncated toward zero,
 * which is what `int64(float64)` yields for every difference below 2^52
 * seconds. Go's `Time.Sub` saturates at the Duration range (±292 years)
 * — standard library, not in the pinned tree, NOT VERIFIED here; the
 * clamp below reproduces a saturating result and is unreachable for any
 * StartTime `updateToState` sets from the same clock.
 */
static int conr_make_round_step_message(cmt_conr_t *conR,
                                        const cmt_round_state_t *rs,
                                        cmt_new_round_step_msg_t *out)
{
    cmt_time_t now;
    int64_t    q;
    int32_t    r;
    int        rc;

    rc = conr_now(conR, &now);                                    /* :504 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* Both instants are valid Timestamps (seconds within ±62e9), so the
     * seconds difference cannot overflow an int64. */
    q = now.seconds - rs->start_time.seconds;
    r = now.nanos - rs->start_time.nanos;            /* in (-1e9, 1e9) */
    if (q > 0 && r < 0) {
        q -= 1;                                     /* e.g. 1 s - 0.5 s */
    } else if (q < 0 && r > 0) {
        q += 1;                                     /* e.g. -1 s + 0.5 s */
    }
    if (q > INT64_MAX / CONR_SECOND_NS) {
        q = INT64_MAX / CONR_SECOND_NS;             /* see the note above */
    } else if (q < INT64_MIN / CONR_SECOND_NS) {
        q = INT64_MIN / CONR_SECOND_NS;
    }
    memset(out, 0, sizeof(*out));
    out->height                   = rs->height;                   /* :501 */
    out->round                    = rs->round;                    /* :502 */
    out->step                     = rs->step;                     /* :503 */
    out->seconds_since_start_time = q;                            /* :504 */
    /* :505 — rs.LastCommit.GetRound(): -1 for a nil set
     * (types/vote_set.go:124-126), which cmt_vote_set_get_round gives. */
    out->last_commit_round        = cmt_vote_set_get_round(rs->last_commit);
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:510-517 — sendNewRoundStepMessage() */
static int conr_send_new_round_step_message(cmt_conr_t *conR,
                                            cmt_conr_peer_slot_t *slot)
{
    cmt_round_state_t rs;
    cmt_msg_t        *msg;
    bool              sent;
    int               rc;

    rc = cmt_conr_get_round_state(conR, &rs);                     /* :511 */
    if (rc != CMT_OK) {
        return rc;
    }
    msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_NEW_ROUND_STEP);
    rc = conr_make_round_step_message(conR, &rs, &msg->u.new_round_step); /* :512 */
    if (rc != CMT_OK) {
        return rc;
    }
    sent = false;
    /* :513-516 — peer.Send on the StateChannel; the result is unused. */
    return cmt_ps_peer_send(&slot->ps, false, CMT_CONR_STATE_CHANNEL, msg,
                            &sent);
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:408-497 — the event subscriptions and the three broadcasts
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * p2p/switch.go:274-296 — `Broadcast(e)`: `sw.peers.List()` (:277) in
 * SLOT INDEX ORDER (the reference's order is unspecified, :273), one
 * `Send` each (:285). The success channel (:280, :295) is discarded by
 * every caller in reactor.go (:442, :457, :471), so nothing is returned;
 * a per-peer false is the reference's false. Only a NODE-LOCAL fault of
 * our own message (cmt_ps_peer_send) is reported.
 */
static int conr_broadcast(cmt_conr_t *conR, uint8_t channel_id,
                          const cmt_msg_t *msg)
{
    size_t i;
    bool   sent;
    int    rc;

    for (i = 0u; i < (size_t)CMT_CONR_MAX_PEERS; i++) {
        cmt_conr_peer_slot_t *slot = &conR->peers[i];

        if (!slot->in_set) {
            continue;
        }
        sent = false;
        rc = cmt_ps_peer_send(&slot->ps, false, channel_id, msg, &sent); /* :285 */
        if (rc != CMT_OK) {
            return rc;
        }
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:440-446 —
 * broadcastNewRoundStepMessage(), reached from the listener of
 * :412-416. Runs INSIDE the state machine (cmt_cs.h, cmt_cs_listener_t):
 * it reads `rs` and sends; it never calls back into `cs`. */
static void conr_on_new_round_step(void *ctx, const cmt_round_state_t *rs)
{
    cmt_conr_t *conR = (cmt_conr_t *)ctx;
    cmt_msg_t  *msg;
    int         rc;

    if (conR == NULL || rs == NULL) {
        return;
    }
    msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_NEW_ROUND_STEP);
    rc = conr_make_round_step_message(conR, rs, &msg->u.new_round_step); /* :441 */
    if (rc == CMT_OK) {
        rc = conr_broadcast(conR, CMT_CONR_STATE_CHANNEL, msg);   /* :442-445 */
    }
    if (rc != CMT_OK) {
        /* The listener returns nothing (events.go:204); a fault in a
         * broadcast of our own NewRoundStep is logged. Its only sources
         * are a NULL clock row and a NODE-LOCAL marshal fault. */
        QGP_LOG_ERROR(LOG_TAG, "broadcastNewRoundStepMessage failed (%d)", rc);
    }
}

/* cometbft@709fd12b consensus/reactor.go:448-461 —
 * broadcastNewValidBlockMessage(), from the listener of :419-423. */
static void conr_on_valid_block(void *ctx, const cmt_round_state_t *rs)
{
    cmt_conr_t                *conR = (cmt_conr_t *)ctx;
    cmt_msg_t                 *msg;
    cmt_new_valid_block_msg_t *m;
    int                        rc;

    if (conR == NULL || rs == NULL) {
        return;
    }
    msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_NEW_VALID_BLOCK);
    m   = &msg->u.new_valid_block;
    /* :449 psh := rs.ProposalBlockParts.Header() — the zero header for a
     * nil part set (part_set.go:237-239). */
    rc = cmt_part_set_header(rs->proposal_block_parts, &m->block_part_set_header);
    if (rc == CMT_OK) {
        m->height = rs->height;                                   /* :451 */
        m->round  = rs->round;                                    /* :452 */
        /* :454 rs.ProposalBlockParts.BitArray().ToProto() — nil for an
         * empty set (bit_array.go:476-478), which is `has_block_parts`
         * false and an omitted field 4 (cmt_pb.h:777-779). */
        rc = cmt_part_set_bit_array(rs->proposal_block_parts, &m->block_parts);
        if (rc == CMT_BITS_NIL) {
            m->has_block_parts = false;
            rc = CMT_OK;
        } else if (rc == CMT_OK) {
            m->has_block_parts = true;
        }
    }
    if (rc == CMT_OK) {
        m->is_commit = (rs->step == CMT_ROUND_STEP_COMMIT);       /* :455 */
        rc = conr_broadcast(conR, CMT_CONR_STATE_CHANNEL, msg);   /* :457-460 */
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "broadcastNewValidBlockMessage failed (%d)", rc);
    }
}

/* cometbft@709fd12b consensus/reactor.go:464-497 —
 * broadcastHasVoteMessage(), from the listener of :426-430.
 * "Broadcasts HasVoteMessage to peers that care." The LIVE code
 * broadcasts (:471-474); :475-496 is the reference's own commented-out
 * peer-by-peer branch, left exactly as it leaves it:
 *
 *     // TODO: Make this broadcast more selective.
 *     for _, peer := range conR.Switch.Peers().List() {
 *         ps, ok := peer.Get(PeerStateKey).(*PeerState)
 *         if !ok {
 *             panic(fmt.Sprintf("Peer %v has no state", peer))
 *         }
 *         prs := ps.GetRoundState()
 *         if prs.Height == vote.Height {
 *             // TODO: Also filter on round?
 *             e := p2p.Envelope{
 *                 ChannelID: StateChannel, struct{ ConsensusMessage }{msg},
 *                 Message: p,
 *             }
 *             peer.TrySend(e)
 *         } else {
 *             // Height doesn't match
 *             // TODO: check a field, maybe CatchupCommitRound?
 *             // TODO: But that requires changing the struct field comment.
 *         }
 *     }
 */
static void conr_on_vote(void *ctx, const cmt_vote_t *vote)
{
    cmt_conr_t         *conR = (cmt_conr_t *)ctx;
    cmt_msg_t          *msg;
    cmt_has_vote_msg_t *m;
    int                 rc;

    if (conR == NULL || vote == NULL) {
        return;
    }
    msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_HAS_VOTE);
    m   = &msg->u.has_vote;
    m->height = vote->height;                                     /* :466 */
    m->round  = vote->round;                                      /* :467 */
    m->type   = vote->type;                                       /* :468 */
    m->index  = vote->validator_index;                            /* :469 */
    rc = conr_broadcast(conR, CMT_CONR_STATE_CHANNEL, msg);       /* :471-474 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "broadcastHasVoteMessage failed (%d)", rc);
    }
}

/* cometbft@709fd12b consensus/reactor.go:411-433 —
 * subscribeToBroadcastEvents(): the three listeners of "consensus-reactor"
 * (:412), one call here because cmt_cs_add_listener takes all three. The
 * :417/:424/:431 error logs are the AddListenerForEvent errors of a
 * removed listener id (events.go:225-227), which cannot occur here. */
static int conr_subscribe_to_broadcast_events(cmt_conr_t *conR)
{
    cmt_cs_listener_t l;

    memset(&l, 0, sizeof(l));
    l.on_new_round_step = conr_on_new_round_step;                 /* :413-416 */
    l.on_valid_block    = conr_on_valid_block;                    /* :420-423 */
    l.on_vote           = conr_on_vote;                           /* :427-430 */
    return cmt_cs_add_listener(conR->cs, &l, conR);
}

/* cometbft@709fd12b consensus/reactor.go:435-438 —
 * unsubscribeFromBroadcastEvents() */
static void conr_unsubscribe_from_broadcast_events(cmt_conr_t *conR)
{
    cmt_cs_remove_listener(conR->cs);                             /* :437 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:54-141 — construction and lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/reactor.go:56-70 — NewReactor() */
int cmt_conr_init(cmt_conr_t *conR, cmt_cs_t *cs, bool wait_sync,
                  const cmt_conr_host_t *host, void *host_ctx,
                  cmt_pb_arena_t *recv_arena)
{
    if (conR == NULL || cs == NULL || host == NULL || recv_arena == NULL) {
        return CMT_FAULT;
    }
    memset(conR, 0, sizeof(*conR));
    conR->cs         = cs;                                        /* :58 */
    conR->wait_sync  = wait_sync;                                 /* :59 */
    conR->host       = *host;
    conR->host_ctx   = host_ctx;
    conR->recv_arena = recv_arena;
    /* :60 rs: consensusState.GetRoundState() — live reads instead.
     * :61 Metrics: NopMetrics() — YOK. :63 BaseReactor — `running`.
     * :65-67 options — YOK. */

    conR->peers = (cmt_conr_peer_slot_t *)calloc((size_t)CMT_CONR_MAX_PEERS,
                                                 sizeof(cmt_conr_peer_slot_t));
    conR->scratch.buf = (uint8_t *)calloc((size_t)CMT_CONR_MAX_MSG_SIZE, 1u);
    conR->scratch.cap = (size_t)CMT_CONR_MAX_MSG_SIZE;
    conR->scratch.pb  = (cmt_pb_cons_message_t *)calloc(
            1u, sizeof(cmt_pb_cons_message_t));
    conR->scratch.msg = (cmt_msg_t *)calloc(1u, sizeof(cmt_msg_t));
    conR->recv_pb     = (cmt_pb_cons_message_t *)calloc(
            1u, sizeof(cmt_pb_cons_message_t));
    conR->recv_msg    = (cmt_msg_t *)calloc(1u, sizeof(cmt_msg_t));
    conR->ecsigs_cap  = (size_t)CMT_VALSET_MAX;
    conR->ecsigs      = (cmt_extended_commit_sig_t *)calloc(
            conR->ecsigs_cap, sizeof(cmt_extended_commit_sig_t));
    if (conR->peers == NULL || conR->scratch.buf == NULL ||
        conR->scratch.pb == NULL || conR->scratch.msg == NULL ||
        conR->recv_pb == NULL || conR->recv_msg == NULL ||
        conR->ecsigs == NULL) {
        cmt_conr_free(conR);
        return CMT_FAULT;
    }
    return CMT_OK;
}

void cmt_conr_free(cmt_conr_t *conR)
{
    if (conR == NULL) {
        return;
    }
    free(conR->peers);
    free(conR->scratch.buf);
    free(conR->scratch.pb);
    free(conR->scratch.msg);
    free(conR->recv_pb);
    free(conR->recv_msg);
    free(conR->ecsigs);
    memset(conR, 0, sizeof(*conR));
}

/* cometbft@709fd12b consensus/reactor.go:74-91 — OnStart(), through
 * service.go:130-158 Start(). */
int cmt_conr_start(cmt_conr_t *conR)
{
    int rc;

    if (conR == NULL) {
        return CMT_FAULT;
    }
    conR->running = true;                            /* service.go:131 */
    /* :78 go conR.peerStatsRoutine() — YOK (cmt_conr.h). */
    rc = conr_subscribe_to_broadcast_events(conR);               /* :80 */
    if (rc != CMT_OK) {
        conR->running = false;                       /* service.go:147 */
        return rc;
    }
    /* :81 go conR.updateRoundStateRoutine() — live reads, nothing to
     * start (cmt_conr.h "THREADS → TICKS"). */
    if (!conR->wait_sync) {                                      /* :83 */
        rc = cmt_cs_start(conR->cs);                             /* :84 */
        if (rc != CMT_OK) {                                      /* :85-87 */
            conR->running = false;                   /* service.go:147 */
            return rc;
        }
    }
    return CMT_OK;                                               /* :90 */
}

/* cometbft@709fd12b consensus/reactor.go:95-103 — OnStop(), through
 * service.go:167-190 Stop(). */
int cmt_conr_stop(cmt_conr_t *conR)
{
    int rc;

    if (conR == NULL) {
        return CMT_FAULT;
    }
    conR->running = false;                           /* service.go:168 */
    conr_unsubscribe_from_broadcast_events(conR);                /* :96 */
    rc = cmt_cs_stop(conR->cs);                                  /* :97 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Error stopping consensus state (%d)", rc); /* :98 */
    }
    /* :100-102 conR.conS.Wait() — no goroutine to wait for. */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:107-141 — SwitchToConsensus() */
int cmt_conr_switch_to_consensus(cmt_conr_t *conR, const cmt_state_t *state,
                                 bool skip_wal)
{
    int rc;

    if (conR == NULL || state == NULL) {
        return CMT_FAULT;
    }
    /* :110-122 — the conS.mtx lock of :112-113 is dropped: single thread,
     * and we are not inside handleMsg/handleTimeout either. */
    if (state->last_block_height > 0) {                          /* :115 */
        /* :114 "We have no votes, so reconstruct LastCommit from
         * SeenCommit". The reference panics inside on failure
         * (state.go:588, :605); anything but OK is that stop. */
        rc = cmt_cs_reconstruct_last_commit(conR->cs, state);    /* :116 */
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "reconstructLastCommit failed (%d)", rc);
            return CMT_FAULT;
        }
    }
    /* :119-121 "NOTE: The line below causes broadcastNewRoundStepRoutine()
     * to broadcast a NewRoundStepMessage." — through the listener. */
    rc = cmt_cs_update_to_state(conR->cs, state);                /* :121 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "updateToState failed (%d)", rc);
        return CMT_FAULT;
    }

    /* :124-126 — conR.mtx dropped. */
    conR->wait_sync = false;                                     /* :125 */

    if (skip_wal) {                                              /* :128 */
        conR->cs->do_wal_catchup = false;                        /* :129 */
    }
    rc = cmt_cs_start(conR->cs);                                 /* :131 */
    if (rc != CMT_OK) {
        /* :132-140 — panic("Failed to start consensus state: …").
         * NODE-LOCAL → CMT_FAULT: the reference dumps conS and conR and
         * dies on ANY error here. */
        QGP_LOG_ERROR(LOG_TAG, "Failed to start consensus state (%d)", rc);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:400-404 — WaitSync().
 * :401-402 conR.mtx.RLock — dropped. */
bool cmt_conr_wait_sync(const cmt_conr_t *conR)
{
    return conR != NULL && conR->wait_sync;                      /* :403 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:182-223 — peers
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/reactor.go:183-187 — InitPeer() */
int cmt_conr_init_peer(cmt_conr_t *conR, int peer_idx,
                       const uint8_t id[CMT_PB_PEER_ID_MAX])
{
    cmt_conr_peer_slot_t *slot;
    cmt_ps_peer_t         peer;
    int                   rc;

    if (conR == NULL || id == NULL) {
        return CMT_FAULT;
    }
    slot = conr_slot(conR, peer_idx);
    if (slot == NULL) {
        return CMT_REJECT;
    }
    if (slot->in_set) {
        /* The switch never InitPeers a peer already in its set
         * (switch.go:845 "we already checked peers.Has()"); refusing keeps
         * a live slot's state from being wiped by a host wiring error. */
        return CMT_REJECT;
    }
    memset(&peer, 0, sizeof(peer));
    peer.idx      = peer_idx;
    memcpy(peer.id, id, (size_t)CMT_PB_PEER_ID_MAX);
    peer.send     = conR->host.send;
    peer.try_send = conR->host.try_send;
    peer.ctx      = conR->host_ctx;
    peer.scratch  = &conR->scratch;
    memset(slot, 0, sizeof(*slot));
    rc = cmt_ps_init(&slot->ps, &peer);   /* :184 NewPeerState(peer); SetLogger YOK */
    if (rc != CMT_OK) {
        return rc;
    }
    slot->in_set = true;                  /* :185 peer.Set(PeerStateKey, …) and
                                           * switch.go:846 sw.peers.Add(p) */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:191-210 — AddPeer() */
int cmt_conr_add_peer(cmt_conr_t *conR, int peer_idx)
{
    cmt_conr_peer_slot_t *slot;

    if (conR == NULL) {
        return CMT_FAULT;
    }
    if (!conR->running) {                                        /* :192 */
        return CMT_OK;                                           /* :193 */
    }
    slot = conr_slot(conR, peer_idx);
    if (slot == NULL) {
        return CMT_REJECT;
    }
    if (!slot->in_set) {
        /* :196-199 — panic("peer %v has no state"). NODE-LOCAL →
         * CMT_FAULT: the host called AddPeer for a slot InitPeer never
         * filled — its wiring, not a peer's input. */
        QGP_LOG_ERROR(LOG_TAG, "peer %d has no state", peer_idx);
        return CMT_FAULT;
    }
    /* :200-203 — "Begin routines for this peer." The three goroutines are
     * cmt_conr_tick's passes; `started` makes the tick run them. */
    slot->started = true;
    memset(slot->asleep, 0, sizeof(slot->asleep));
    slot->sleeping = 0;                                          /* :702 */
    slot->maj23_pc = 0;

    /* :205-209 — "Send our state to peer. If we're block_syncing,
     * broadcast a RoundStepMessage later upon SwitchToConsensus()." */
    if (!cmt_conr_wait_sync(conR)) {                             /* :207 */
        return conr_send_new_round_step_message(conR, slot);     /* :208 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:213-223 — RemovePeer(), the
 * no-op quoted in cmt_conr.h, plus switch.go:381 sw.peers.Remove(peer):
 * the slot leaves the set and its routines stop (DEVIATION R3-A-3: not
 * gated on `running`, see the header). */
int cmt_conr_remove_peer(cmt_conr_t *conR, int peer_idx)
{
    cmt_conr_peer_slot_t *slot;

    if (conR == NULL) {
        return CMT_FAULT;
    }
    slot = conr_slot(conR, peer_idx);
    if (slot == NULL) {
        return CMT_REJECT;
    }
    if (!slot->in_set) {
        return CMT_OK;                          /* switch.go:381-386 */
    }
    /* :217-222 — the reference's TODO body does nothing to the state. */
    memset(slot, 0, sizeof(*slot));             /* peers.Remove :381 */
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:225-391 — Receive
 * ══════════════════════════════════════════════════════════════════════ */

/** The 32-byte peer id of a slot as the vote sets want it. */
static cmt_peer_id_t conr_peer_id_of(const cmt_conr_peer_slot_t *slot)
{
    cmt_peer_id_t p;

    memcpy(p.id, slot->ps.peer.id, sizeof(p.id));
    return p;
}

/** :288-298 and :369-378 — `ourVotes`: the bit array of our votes for the
 *  BlockID a peer named, from the prevotes or precommits of `round`.
 *  `*out` is NULL for the reference's nil (an untracked round or block). */
static int conr_our_votes(cmt_cs_t *cs, int32_t round, int32_t vote_type,
                          const cmt_block_id_t *block_id,
                          cmt_bit_array_t *storage, cmt_bit_array_t **out)
{
    cmt_vote_set_t *vs;
    int             rc;

    *out = NULL;
    switch (vote_type) {
    case (int32_t)CMT_PB_MSG_TYPE_PREVOTE:
        vs = cmt_hvs_prevotes(cs->rs.votes, round);          /* :293, :373 */
        break;
    case (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT:
        vs = cmt_hvs_precommits(cs->rs.votes, round);        /* :295, :375 */
        break;
    default:
        /* :297 / :377 — panic("Bad VoteSetBitsMessage field Type. Forgot
         * to add a check in ValidateBasic?"). Unreachable once
         * cmt_msg_validate_basic has run (:1769, :1799); NODE-LOCAL →
         * CMT_FAULT. */
        QGP_LOG_ERROR(LOG_TAG, "Bad VoteSetBitsMessage field Type. Forgot to "
                               "add a check in ValidateBasic?");
        return CMT_FAULT;
    }
    rc = cmt_vote_set_bit_array_by_block_id(vs, block_id, storage);
    if (rc == CMT_BITS_NIL) {
        return CMT_OK;                                          /* nil */
    }
    if (rc == CMT_REJECT) {
        /* A BlockID that passed ValidateBasic always fits the set's key
         * (cmt_vote_set.h:535-536); reaching this is NODE-LOCAL. */
        QGP_LOG_ERROR(LOG_TAG, "BitArrayByBlockID refused a validated BlockID");
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        return rc;
    }
    *out = storage;
    return CMT_OK;
}

/* cometbft@709fd12b consensus/reactor.go:231-391 — Receive() */
int cmt_conr_receive(cmt_conr_t *conR, int peer_idx, uint8_t channel_id,
                     const uint8_t *bytes, size_t len)
{
    cmt_conr_peer_slot_t *slot;
    cmt_cs_t             *cs;
    cmt_msg_t            *msg;
    cmt_ps_t             *ps;
    cmt_bit_array_t       our_votes_storage;
    cmt_bit_array_t      *our_votes;
    int                   rc;

    if (conR == NULL || (bytes == NULL && len != 0u)) {
        return CMT_FAULT;
    }
    if (!conR->running) {                                        /* :232 */
        return CMT_OK;                                           /* :234 */
    }
    cs  = conR->cs;
    msg = conR->recv_msg;

    /* :236 — MsgFromProto(e.Message): here the p2p layer's decode of the
     * envelope's bytes (cmt_pb_cons_message_unmarshal into recv_arena)
     * and msgs.go:121-231's conversion, as one step. */
    cmt_pb_cons_message_init(conR->recv_pb);
    rc = cmt_pb_cons_message_unmarshal(bytes, len, conR->recv_pb,
                                       conR->recv_arena);
    if (rc == CMT_OK) {
        rc = cmt_msg_from_proto(conR->recv_pb, msg);
    }
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {                                          /* :237 */
        /* ⚠ Also reached when `recv_arena` is EXHAUSTED (r_copy_arena →
         * CMT_REJECT), which the reference cannot hit and which blames the
         * wrong peer — register R3-A-5; R3-C2 separates the two. */
        QGP_LOG_ERROR(LOG_TAG, "Error decoding message from peer %d on chId %02x",
                      peer_idx, (unsigned)channel_id);           /* :238 */
        if (conR->host.stop_peer_for_error == NULL) {
            return CMT_FAULT;
        }
        conR->host.stop_peer_for_error(conR->host_ctx, peer_idx,
                                       (int)CMT_CONR_STOP_DECODE); /* :239 */
        return CMT_OK;                                           /* :240 */
    }

    /* :243-247 — `msg.ValidateBasic()`. LABELLED DEVIATION (register
     * R3-A-6): in the reference `MsgFromProto` already ran
     * `pb.ValidateBasic()` (msgs.go:232-234), so every ValidateBasic
     * failure fires at :239 with the DECODE reason and :243-247 is dead
     * for a message that reached it; `cmt_msg_from_proto` stops before
     * that call (cmt_msgs.h:28-35), so here the gate runs as its own step
     * and reports the VALIDATE_BASIC reason. The disconnect is identical;
     * only the host-visible reason code differs. */
    rc = cmt_msg_validate_basic(msg);                            /* :243 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Peer %d sent us invalid msg (kind %d)",
                      peer_idx, (int)msg->kind);                 /* :244 */
        if (conR->host.stop_peer_for_error == NULL) {
            return CMT_FAULT;
        }
        conR->host.stop_peer_for_error(conR->host_ctx, peer_idx,
                                       (int)CMT_CONR_STOP_VALIDATE_BASIC); /* :245 */
        return CMT_OK;                                           /* :246 */
    }

    /* :251-255 — "Get peer states". */
    slot = conr_slot(conR, peer_idx);
    if (slot == NULL || !slot->in_set) {
        /* :254 — panic("Peer %v has no state"). NODE-LOCAL → CMT_FAULT:
         * the host delivered on a connection it never InitPeer'd
         * (reactor_test.go:278-305 expects exactly this panic). */
        QGP_LOG_ERROR(LOG_TAG, "Peer %d has no state", peer_idx);
        return CMT_FAULT;
    }
    ps = &slot->ps;

    switch (channel_id) {                                        /* :257 */
    case CMT_CONR_STATE_CHANNEL:                                 /* :258 */
        switch (msg->kind) {
        case CMT_PB_CONS_MSG_NEW_ROUND_STEP: {                   /* :260 */
            cmt_time_t now;
            /* :261-263 — conS.mtx dropped; the initial height read live. */
            int64_t initial_height = cs->state.initial_height;   /* :262 */

            rc = cmt_new_round_step_msg_validate_height(&msg->u.new_round_step,
                                                        initial_height); /* :264 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            if (rc != CMT_OK) {
                QGP_LOG_ERROR(LOG_TAG, "Peer %d sent us invalid NewRoundStep "
                                       "height", peer_idx);      /* :265 */
                if (conR->host.stop_peer_for_error == NULL) {
                    return CMT_FAULT;
                }
                conR->host.stop_peer_for_error(conR->host_ctx, peer_idx,
                        (int)CMT_CONR_STOP_VALIDATE_HEIGHT);     /* :266 */
                return CMT_OK;                                   /* :267 */
            }
            /* :1379 — cmttime.Now(), read HERE and handed to cmt_ps. */
            rc = conr_now(conR, &now);
            if (rc != CMT_OK) {
                return rc;
            }
            rc = cmt_ps_apply_new_round_step_message(ps, &msg->u.new_round_step,
                                                     now);       /* :269 */
            return (rc == CMT_FAULT) ? CMT_FAULT : CMT_OK;
        }
        case CMT_PB_CONS_MSG_NEW_VALID_BLOCK:                    /* :270 */
            /* A CMT_REJECT from an Apply* row is a bit-array bound the
             * decoder already enforced (cmt_bits_from_proto); unreachable
             * here and, if reached, not the queue-full REJECT of R3-A-2. */
            rc = cmt_ps_apply_new_valid_block_message(ps,
                                                      &msg->u.new_valid_block); /* :271 */
            return (rc == CMT_FAULT) ? CMT_FAULT : CMT_OK;
        case CMT_PB_CONS_MSG_HAS_VOTE:                           /* :272 */
            rc = cmt_ps_apply_has_vote_message(ps, &msg->u.has_vote); /* :273 */
            return (rc == CMT_FAULT) ? CMT_FAULT : CMT_OK;
        case CMT_PB_CONS_MSG_VOTE_SET_MAJ23: {                   /* :274 */
            const cmt_vote_set_maj23_msg_t *m = &msg->u.vote_set_maj23;
            cmt_vote_set_bits_msg_t        *reply;
            cmt_msg_t                      *reply_msg;
            cmt_vote_set_err_t              err;
            bool                            sent;
            /* :275-278 — cs.mtx dropped; height and votes read live. */
            int64_t                         height = cs->rs.height;
            cmt_hvs_t                      *votes  = cs->rs.votes;

            if (height != m->height) {                           /* :279 */
                return CMT_OK;                                   /* :280 */
            }
            /* :282-287 — "Peer claims to have a maj23 for some BlockID at
             * H,R,S," */
            err = CMT_VOTE_SET_ERR_NONE;
            rc = cmt_hvs_set_peer_maj23(votes, m->round, m->type,
                                        conr_peer_id_of(slot), &m->block_id,
                                        &err);                   /* :283 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            if (rc != CMT_OK) {                                  /* :284 */
                if (conR->host.stop_peer_for_error == NULL) {
                    return CMT_FAULT;
                }
                conR->host.stop_peer_for_error(conR->host_ctx, peer_idx,
                        (int)CMT_CONR_STOP_PEER_MAJ23);          /* :285 */
                return CMT_OK;                                   /* :286 */
            }
            /* :288-298 — "Respond with a VoteSetBitsMessage showing which
             * votes we have. (and consequently shows which we don't have)" */
            our_votes = NULL;
            rc = conr_our_votes(cs, m->round, m->type, &m->block_id,
                                &our_votes_storage, &our_votes);
            if (rc != CMT_OK) {
                return rc;
            }
            /* :299-307 — the reply; :305-307 `if votes := ourVotes.ToProto();
             * votes != nil` — nil for a nil array or one with no words
             * (bit_array.go:476-478), which leaves the zero BitArray in
             * field 5 (always emitted, cmt_pb.h:839-840). */
            reply_msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_VOTE_SET_BITS);
            reply     = &reply_msg->u.vote_set_bits;
            reply->height   = m->height;                         /* :300 */
            reply->round    = m->round;                          /* :301 */
            reply->type     = m->type;                           /* :302 */
            reply->block_id = m->block_id;                       /* :303 */
            if (our_votes != NULL && our_votes->n_elems > 0u) {  /* :305 */
                reply->has_votes = true;
                reply->votes     = *our_votes;                   /* :306 */
            }
            sent = false;
            /* :308-311 — e.Src.TrySend on the VoteSetBitsChannel; the
             * result is unused. */
            return cmt_ps_peer_send(ps, true, CMT_CONR_VOTE_SET_BITS_CHANNEL,
                                    reply_msg, &sent);
        }
        default:                                                 /* :312 */
            QGP_LOG_ERROR(LOG_TAG, "Unknown message type %d on StateChannel",
                          (int)msg->kind);                       /* :313 */
            return CMT_OK;
        }

    case CMT_CONR_DATA_CHANNEL:                                  /* :316 */
        if (cmt_conr_wait_sync(conR)) {                          /* :317 */
            QGP_LOG_INFO(LOG_TAG, "Ignoring message received during sync"); /* :318 */
            return CMT_OK;                                       /* :319 */
        }
        switch (msg->kind) {
        case CMT_PB_CONS_MSG_PROPOSAL:                           /* :322 */
            rc = cmt_ps_set_has_proposal(ps, &msg->u.proposal.proposal); /* :323 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            /* A CMT_REJECT here is `bits.NewBitArray(Total)` refusing a
             * Total above the derived bound (cmt_bits.h:21-32) where Go
             * would allocate it; the peer state keeps the flag and header
             * :1108/:1115 set before that line and no array, and the
             * state machine refuses the same proposal one step later
             * (state.go:1935-1936, cmt_cs.c "ErrProposalTooManyParts"). */
            rc = cmt_cs_set_proposal_input(cs, &msg->u.proposal.proposal,
                                           ps->peer.id,
                                           (size_t)CMT_PB_PEER_ID_MAX); /* :324 */
            return rc;   /* CMT_REJECT = the peer queue is full, R3-A-2 */
        case CMT_PB_CONS_MSG_PROPOSAL_POL:                       /* :325 */
            rc = cmt_ps_apply_proposal_pol_message(ps, &msg->u.proposal_pol); /* :326 */
            return (rc == CMT_FAULT) ? CMT_FAULT : CMT_OK;
        case CMT_PB_CONS_MSG_BLOCK_PART: {                       /* :327 */
            const cmt_block_part_msg_t *m = &msg->u.block_part;
            /* :328 `int(msg.Part.Index)` — a uint32 widened to Go's 64-bit
             * int stays positive and, past the array's width, is a no-op
             * (bit_array.go:93-95). C's `int` is 32-bit: an index above
             * INT_MAX is held at INT_MAX, which is past any width too,
             * rather than wrapping negative into cmt_bits_set_index's
             * CMT_FAULT. PEER-REACHABLE (the index passed ValidateBasic
             * because it equals the proof's). */
            int index = (m->part.index > (uint32_t)INT_MAX)
                        ? INT_MAX : (int)m->part.index;

            rc = cmt_ps_set_has_proposal_block_part(ps, m->height, m->round,
                                                    index);      /* :328 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            /* :329 — conR.Metrics.BlockParts, YOK. */
            rc = cmt_cs_add_proposal_block_part_input(cs, m->height, m->round,
                                                      &m->part, ps->peer.id,
                                                      (size_t)CMT_PB_PEER_ID_MAX); /* :330 */
            return rc;   /* CMT_REJECT = the peer queue is full, R3-A-2 */
        }
        default:                                                 /* :331 */
            QGP_LOG_ERROR(LOG_TAG, "Unknown message type %d on DataChannel",
                          (int)msg->kind);                       /* :332 */
            return CMT_OK;
        }

    case CMT_CONR_VOTE_CHANNEL:                                  /* :335 */
        if (cmt_conr_wait_sync(conR)) {                          /* :336 */
            QGP_LOG_INFO(LOG_TAG, "Ignoring message received during sync"); /* :337 */
            return CMT_OK;                                       /* :338 */
        }
        switch (msg->kind) {
        case CMT_PB_CONS_MSG_VOTE: {                             /* :341 */
            /* :342-345 — cs.mtx.RLock dropped; the three values read live.
             * `cs.Validators.Size()` on a nil set would panic in Go;
             * `rs.validators` is set by updateToState before any peer can
             * be added, and a NULL here answers 0 rather than crashing. */
            int64_t height           = cs->rs.height;
            int     val_size         = (cs->rs.validators != NULL)
                    ? (int)cmt_validator_set_size(cs->rs.validators) : 0;
            int     last_commit_size = cmt_vote_set_size(cs->rs.last_commit);

            rc = cmt_ps_ensure_vote_bit_arrays(ps, height, val_size); /* :346 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            rc = cmt_ps_ensure_vote_bit_arrays(ps, height - 1, last_commit_size); /* :347 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            rc = cmt_ps_set_has_vote(ps, &msg->u.vote.vote);     /* :348 */
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            rc = cmt_cs_add_vote(cs, &msg->u.vote.vote, ps->peer.id,
                                 (size_t)CMT_PB_PEER_ID_MAX);   /* :350 */
            return rc;   /* CMT_REJECT = the peer queue is full, R3-A-2 */
        }
        default:                                                 /* :352 */
            /* :353 "don't punish (leave room for soft upgrades)" */
            QGP_LOG_ERROR(LOG_TAG, "Unknown message type %d on VoteChannel",
                          (int)msg->kind);                       /* :354 */
            return CMT_OK;
        }

    case CMT_CONR_VOTE_SET_BITS_CHANNEL:                         /* :357 */
        if (cmt_conr_wait_sync(conR)) {                          /* :358 */
            QGP_LOG_INFO(LOG_TAG, "Ignoring message received during sync"); /* :359 */
            return CMT_OK;                                       /* :360 */
        }
        switch (msg->kind) {
        case CMT_PB_CONS_MSG_VOTE_SET_BITS: {                    /* :363 */
            const cmt_vote_set_bits_msg_t *m = &msg->u.vote_set_bits;
            /* :364-367 — cs.mtx dropped. */
            int64_t                        height = cs->rs.height;

            if (height == m->height) {                           /* :369 */
                our_votes = NULL;
                rc = conr_our_votes(cs, m->round, m->type, &m->block_id,
                                    &our_votes_storage, &our_votes); /* :370-378 */
                if (rc != CMT_OK) {
                    return rc;
                }
                rc = cmt_ps_apply_vote_set_bits_message(ps, m, our_votes); /* :379 */
            } else {
                rc = cmt_ps_apply_vote_set_bits_message(ps, m, NULL); /* :381 */
            }
            return (rc == CMT_FAULT) ? CMT_FAULT : CMT_OK;
        }
        default:                                                 /* :383 */
            /* :384 "don't punish (leave room for soft upgrades)" */
            QGP_LOG_ERROR(LOG_TAG, "Unknown message type %d on "
                                   "VoteSetBitsChannel", (int)msg->kind); /* :385 */
            return CMT_OK;
        }

    default:                                                     /* :388 */
        QGP_LOG_ERROR(LOG_TAG, "Unknown chId %02X", (unsigned)channel_id); /* :389 */
        return CMT_OK;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:519-537 — the round state
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/reactor.go:519-531 updateRoundStateRoutine()
 * and :533-537 getRoundState(): the 100 µs snapshot and its reader,
 * collapsed into a live read (cmt_conr.h). :527-529 and :534-535 are the
 * conR.mtx, dropped. */
int cmt_conr_get_round_state(const cmt_conr_t *conR, cmt_round_state_t *out)
{
    if (conR == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return cmt_cs_get_round_state(conR->cs, out);                /* :526 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:539-696 — gossipDataRoutine and gossipDataForCatchup
 * ══════════════════════════════════════════════════════════════════════ */

/** What a routine pass reports back to the tick. */
typedef enum {
    CONR_PASS_CONTINUE = 0,   /* a send happened: `continue OUTER_LOOP` */
    CONR_PASS_END      = 1    /* slept, or a send returned false       */
} conr_pass_t;

/**
 * cometbft@709fd12b consensus/reactor.go:646-696 — gossipDataForCatchup().
 * Every path either sends a part (and returns to :593's `continue`) or
 * sleeps; :673-677's `part.ToProto()` error cannot occur here because a
 * part the host row returned IS the proto shape (cmt_part_set.h:134).
 */
static int conr_gossip_data_for_catchup(cmt_conr_t *conR,
                                        cmt_conr_peer_slot_t *slot,
                                        const cmt_round_state_t *rs,
                                        const cmt_prs_t *prs, int64_t now_ns,
                                        conr_pass_t *out_pass)
{
    cmt_bit_array_t      not_ba;
    cmt_block_id_t       block_id;
    cmt_part_t           part;
    cmt_msg_t           *msg;
    int64_t              sleep_d = conR->cs->config->peer_gossip_sleep_duration;
    int                  index;
    bool                 found;
    bool                 sent;
    int                  rc;

    (void)rs;   /* :653-654 reads rs.Height for a log line only */
    *out_pass = CONR_PASS_END;

    /* :649 — prs.ProposalBlockParts.Not().PickRandom() */
    rc = cmt_bits_not(prs->proposal_block_parts, &not_ba);
    if (rc == CMT_BITS_NIL) {
        rc = CMT_REJECT;                          /* nil.PickRandom() false */
    } else if (rc == CMT_OK) {
        index = 0;
        rc = cmt_bits_pick_random(&not_ba, &index);
    }
    if (rc == CMT_REJECT) {
        /* :694-695 — "No parts to send in catch-up, sleeping" */
        conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d);  /* :695 */
        return CMT_OK;
    }
    if (rc != CMT_OK) {
        return rc;
    }

    /* :650-662 — "Ensure that the peer's PartSetHeader is correct" */
    found = false;
    rc = conR->host.bs_load_block_meta_block_id(conR->host_ctx, prs->height,
                                                &block_id, &found); /* :651 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!found) {                                                /* :652 */
        QGP_LOG_ERROR(LOG_TAG, "Failed to load block meta (catchup, height "
                               "%lld)", (long long)prs->height); /* :653 */
        conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d);  /* :655 */
        return CMT_OK;                                           /* :656 */
    }
    if (!cmt_psh_equals(&block_id.part_set_header,
                        &prs->proposal_block_part_set_header)) { /* :657 */
        QGP_LOG_INFO(LOG_TAG, "Peer ProposalBlockPartSetHeader mismatch, "
                              "sleeping");                       /* :658 */
        conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d);  /* :660 */
        return CMT_OK;                                           /* :661 */
    }
    /* :663-670 — "Load the part" */
    memset(&part, 0, sizeof(part));
    found = false;
    rc = conR->host.bs_load_block_part(conR->host_ctx, prs->height, index,
                                       &part, &found);           /* :664 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!found) {                                                /* :665 */
        QGP_LOG_ERROR(LOG_TAG, "Could not load part %d (height %lld)", index,
                      (long long)prs->height);                   /* :666 */
        conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d);  /* :668 */
        return CMT_OK;                                           /* :669 */
    }
    /* :671-691 — "Send the part" */
    msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_BLOCK_PART);
    msg->u.block_part.height = prs->height;   /* :681 "Not our height, so it doesn't matter." */
    msg->u.block_part.round  = prs->round;    /* :682 */
    msg->u.block_part.part   = part;          /* :683 */
    sent = false;
    rc = cmt_ps_peer_send(&slot->ps, false, CMT_CONR_DATA_CHANNEL, msg, &sent); /* :678 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (sent) {
        rc = cmt_ps_set_has_proposal_block_part(&slot->ps, prs->height,
                                                prs->round, index); /* :686 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        *out_pass = CONR_PASS_CONTINUE;                          /* :692 → :593 */
        return CMT_OK;
    }
    /* :687-691 — "Sending block part for catchup failed" — "sleep to
     * avoid retrying too fast" */
    conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d);      /* :690 */
    return CMT_OK;                                               /* :692 */
}

/**
 * cometbft@709fd12b consensus/reactor.go:539-644 — gossipDataRoutine(),
 * one pass (cmt_conr.h "THREADS → TICKS"). :540 is the logger.
 */
static int conr_gossip_data_pass(cmt_conr_t *conR, cmt_conr_peer_slot_t *slot,
                                 int64_t now_ns)
{
    cmt_round_state_t rs;
    cmt_prs_t         prs;
    cmt_bit_array_t   ba_storage;
    cmt_bit_array_t   copy_storage;
    cmt_bit_array_t   sub_storage;
    cmt_bit_array_t  *ba;
    cmt_bit_array_t  *copy;
    cmt_msg_t        *msg;
    int64_t           sleep_d = conR->cs->config->peer_gossip_sleep_duration;
    int64_t           store_base;
    int               index;
    bool              sent;
    conr_pass_t       pass;
    int               rc;

    for (;;) {                                        /* :542 OUTER_LOOP */
        /* :544-547 — "Manage disconnects from self or peer." */
        if (!slot->started || !conR->running) {                  /* :545 */
            return CMT_OK;
        }
        rc = cmt_conr_get_round_state(conR, &rs);                /* :548 */
        if (rc != CMT_OK) {
            return rc;
        }
        cmt_ps_get_round_state(&slot->ps, &prs);                 /* :549 */

        /* :551-572 — "Send proposal Block parts?" */
        if (cmt_part_set_has_header(rs.proposal_block_parts,
                                    &prs.proposal_block_part_set_header)) { /* :552 */
            /* :553 — rs.ProposalBlockParts.BitArray().Sub(
             *            prs.ProposalBlockParts.Copy()).PickRandom() */
            ba = NULL;
            rc = cmt_part_set_bit_array(rs.proposal_block_parts, &ba_storage);
            if (rc == CMT_OK) {
                ba = &ba_storage;
            } else if (rc != CMT_BITS_NIL) {
                return rc;
            }
            copy = NULL;
            rc = cmt_bits_copy(prs.proposal_block_parts, &copy_storage);
            if (rc == CMT_OK) {
                copy = &copy_storage;
            } else if (rc != CMT_BITS_NIL) {
                return rc;
            }
            rc = cmt_bits_sub(ba, copy, &sub_storage);
            if (rc == CMT_OK) {
                index = 0;
                rc = cmt_bits_pick_random(&sub_storage, &index);
            } else if (rc == CMT_BITS_NIL) {
                rc = CMT_REJECT;                      /* nil.PickRandom() */
            }
            if (rc == CMT_OK) {                                  /* ok */
                const cmt_part_t *part =
                        cmt_part_set_get_part(rs.proposal_block_parts,
                                              (size_t)index);    /* :554 */

                if (part == NULL) {
                    /* :555-557 — part.ToProto() on a nil part is an error
                     * the reference PANICS on. NODE-LOCAL → CMT_FAULT: our
                     * own part set's bit says the part is held and the
                     * slot is empty. */
                    QGP_LOG_ERROR(LOG_TAG, "proposal part %d is set but absent",
                                  index);
                    return CMT_FAULT;
                }
                msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_BLOCK_PART);
                msg->u.block_part.height = rs.height;  /* :563 "This tells peer that this part applies to us." */
                msg->u.block_part.round  = rs.round;   /* :564 */
                msg->u.block_part.part   = *part;      /* :565 */
                sent = false;
                rc = cmt_ps_peer_send(&slot->ps, false, CMT_CONR_DATA_CHANNEL,
                                      msg, &sent);               /* :560 */
                if (rc != CMT_OK) {
                    return rc;
                }
                if (sent) {                                      /* :567 */
                    rc = cmt_ps_set_has_proposal_block_part(&slot->ps,
                            prs.height, prs.round, index);       /* :568 */
                    if (rc == CMT_FAULT) {
                        return rc;
                    }
                    continue;                                    /* :570 */
                }
                /* Send false: not marked (:568 skipped); the reference
                 * `continue`s and retries — here the pass ENDS (R3-A-1). */
                return CMT_OK;
            }
            if (rc != CMT_REJECT) {
                return rc;
            }
            /* !ok — fall through to the next check, as the reference. */
        }

        /* :574-594 — "If the peer is on a previous height that we have,
         * help catch up." */
        store_base = 0;
        rc = conR->host.bs_base(conR->host_ctx, &store_base);    /* :575 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        if (store_base > 0 && 0 < prs.height && prs.height < rs.height &&
            prs.height >= store_base) {                          /* :576 */
            /* :579-591 — "if we never received the commit message from
             * the peer, the block parts wont be initialized" */
            if (prs.proposal_block_parts == NULL) {              /* :580 */
                cmt_block_id_t block_id;
                bool           found = false;

                rc = conR->host.bs_load_block_meta_block_id(conR->host_ctx,
                        prs.height, &block_id, &found);          /* :581 */
                if (rc != CMT_OK) {
                    return CMT_FAULT;
                }
                if (!found) {                                    /* :582 */
                    QGP_LOG_ERROR(LOG_TAG, "Failed to load block meta (height "
                                           "%lld)", (long long)prs.height); /* :583 */
                    conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d); /* :585 */
                    return CMT_OK;
                }
                rc = cmt_ps_init_proposal_block_parts(&slot->ps,
                        &block_id.part_set_header);              /* :587 */
                if (rc == CMT_FAULT) {
                    return rc;
                }
                if (slot->ps.prs.proposal_block_parts == NULL) {
                    /* A BlockMeta whose Total is 0 (or above the derived
                     * bound): `bits.NewBitArray(0)` is nil, the array
                     * stays nil and the reference loops here forever.
                     * C-only bound under R3-A-1: end the pass; the next
                     * tick asks the store again. */
                    QGP_LOG_ERROR(LOG_TAG, "block meta at height %lld has no "
                                           "parts to gossip",
                                  (long long)prs.height);
                    return CMT_OK;
                }
                /* :589 "continue the loop since prs is a copy and not
                 * effected by this initialization" */
                continue;                                        /* :590 */
            }
            pass = CONR_PASS_END;
            rc = conr_gossip_data_for_catchup(conR, slot, &rs, &prs, now_ns,
                                              &pass);            /* :592 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (pass == CONR_PASS_CONTINUE) {
                continue;                                        /* :593 */
            }
            return CMT_OK;                          /* it slept (R3-A-1) */
        }

        /* :596-602 — "If height and round don't match, sleep." */
        if (rs.height != prs.height || rs.round != prs.round) {  /* :597 */
            conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d); /* :600 */
            return CMT_OK;                                       /* :601 */
        }

        /* :604-607 — "By here, height and round match. Proposal block
         * parts were already matched and sent if any were wanted. (These
         * can match on hash so the round doesn't matter) Now consider
         * sending other things, like the Proposal itself." */

        /* :609-638 — "Send Proposal && ProposalPOL BitArray?" */
        if (rs.proposal != NULL && !prs.proposal) {              /* :610 */
            bool proposal_sent;

            /* :611-621 — "Proposal: share the proposal metadata with peer." */
            msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_PROPOSAL);
            msg->u.proposal.proposal = *rs.proposal;             /* :616 */
            sent = false;
            rc = cmt_ps_peer_send(&slot->ps, false, CMT_CONR_DATA_CHANNEL,
                                  msg, &sent);                   /* :614 */
            if (rc != CMT_OK) {
                return rc;
            }
            proposal_sent = sent;
            if (sent) {
                /* :618 "NOTE[ZM]: A peer might have received different
                 * proposal msg so this Proposal msg will be rejected!" */
                rc = cmt_ps_set_has_proposal(&slot->ps, rs.proposal); /* :619 */
                if (rc == CMT_FAULT) {
                    return rc;
                }
            }
            /* :622-636 — "ProposalPOL: lets peer know which POL votes we
             * have so far. Peer must receive ProposalMessage first.
             * rs.Proposal was validated, so rs.Proposal.POLRound <=
             * rs.Round, so we definitely have
             * rs.Votes.Prevotes(rs.Proposal.POLRound)." */
            if (0 <= rs.proposal->pol_round) {                   /* :626 */
                cmt_vote_set_t *pol_prevotes =
                        cmt_hvs_prevotes(rs.votes, rs.proposal->pol_round); /* :633 */

                msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_PROPOSAL_POL);
                msg->u.proposal_pol.height             = rs.height; /* :631 */
                msg->u.proposal_pol.proposal_pol_round =
                        rs.proposal->pol_round;                  /* :632 */
                /* :633 — `*rs.Votes.Prevotes(POLRound).BitArray().ToProto()`;
                 * a nil array is the nil dereference cmt_msgs.h:274-281
                 * classes NODE-LOCAL, reported by cmt_ps_peer_send. */
                rc = cmt_vote_set_bit_array(pol_prevotes,
                                            &msg->u.proposal_pol.proposal_pol);
                msg->u.proposal_pol.has_proposal_pol = (rc == CMT_OK);
                if (rc != CMT_OK && rc != CMT_BITS_NIL) {
                    return rc;
                }
                sent = false;
                rc = cmt_ps_peer_send(&slot->ps, false, CMT_CONR_DATA_CHANNEL,
                                      msg, &sent);   /* :628, result unused */
                if (rc != CMT_OK) {
                    return rc;
                }
            }
            if (!proposal_sent) {
                /* The reference `continue`s and retries the proposal;
                 * here the pass ENDS (R3-A-1). */
                return CMT_OK;
            }
            continue;                                            /* :637 */
        }

        /* :640-642 — "Nothing to do. Sleep." */
        conr_sleep(slot, CMT_CONR_ROUTINE_DATA, now_ns, sleep_d);  /* :641 */
        return CMT_OK;                                           /* :642 */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:698-844 — gossipVotesRoutine and gossipVotesForHeight
 * ══════════════════════════════════════════════════════════════════════ */

/** One `ps.PickSendVote(votes)` with the reference's "sent → true". */
static int conr_pick_send(cmt_conr_peer_slot_t *slot, cmt_vote_set_t *vs,
                          bool *out_sent)
{
    cmt_vote_set_reader_t r = cmt_vote_set_reader_of(vs);

    return cmt_ps_pick_send_vote(&slot->ps, &r, out_sent);
}

/**
 * cometbft@709fd12b consensus/reactor.go:788-844 — gossipVotesForHeight().
 * `*out_sent` is the reference's return value. :789 is the logger.
 */
static int conr_gossip_votes_for_height(cmt_conr_peer_slot_t *slot,
                                        const cmt_round_state_t *rs,
                                        const cmt_prs_t *prs, bool *out_sent)
{
    cmt_vote_set_t *pol_prevotes;
    int             rc;

    *out_sent = false;
    /* :794-800 — "If there are lastCommits to send..." */
    if (prs->step == CMT_ROUND_STEP_NEW_HEIGHT) {                /* :795 */
        rc = conr_pick_send(slot, rs->last_commit, out_sent);    /* :796 */
        if (rc != CMT_OK || *out_sent) {
            return rc;                                           /* :798 */
        }
    }
    /* :801-810 — "If there are POL prevotes to send..." */
    if (prs->step <= CMT_ROUND_STEP_PROPOSE && prs->round != -1 &&
        prs->round <= rs->round && prs->proposal_pol_round != -1) { /* :802 */
        pol_prevotes = cmt_hvs_prevotes(rs->votes, prs->proposal_pol_round); /* :803 */
        if (pol_prevotes != NULL) {
            rc = conr_pick_send(slot, pol_prevotes, out_sent);   /* :804 */
            if (rc != CMT_OK || *out_sent) {
                return rc;                                       /* :807 */
            }
        }
    }
    /* :811-817 — "If there are prevotes to send..." */
    if (prs->step <= CMT_ROUND_STEP_PREVOTE_WAIT && prs->round != -1 &&
        prs->round <= rs->round) {                               /* :812 */
        rc = conr_pick_send(slot, cmt_hvs_prevotes(rs->votes, prs->round),
                            out_sent);                           /* :813 */
        if (rc != CMT_OK || *out_sent) {
            return rc;                                           /* :815 */
        }
    }
    /* :818-824 — "If there are precommits to send..." */
    if (prs->step <= CMT_ROUND_STEP_PRECOMMIT_WAIT && prs->round != -1 &&
        prs->round <= rs->round) {                               /* :819 */
        rc = conr_pick_send(slot, cmt_hvs_precommits(rs->votes, prs->round),
                            out_sent);                           /* :820 */
        if (rc != CMT_OK || *out_sent) {
            return rc;                                           /* :822 */
        }
    }
    /* :825-831 — "If there are prevotes to send...Needed because of
     * validBlock mechanism" */
    if (prs->round != -1 && prs->round <= rs->round) {           /* :826 */
        rc = conr_pick_send(slot, cmt_hvs_prevotes(rs->votes, prs->round),
                            out_sent);                           /* :827 */
        if (rc != CMT_OK || *out_sent) {
            return rc;                                           /* :829 */
        }
    }
    /* :832-841 — "If there are POLPrevotes to send..." */
    if (prs->proposal_pol_round != -1) {                         /* :833 */
        pol_prevotes = cmt_hvs_prevotes(rs->votes, prs->proposal_pol_round); /* :834 */
        if (pol_prevotes != NULL) {
            rc = conr_pick_send(slot, pol_prevotes, out_sent);   /* :835 */
            if (rc != CMT_OK || *out_sent) {
                return rc;                                       /* :838 */
            }
        }
    }
    return CMT_OK;                                               /* :843 */
}

/**
 * cometbft@709fd12b consensus/reactor.go:698-786 — gossipVotesRoutine(),
 * one pass. :699 is the logger; :701-702 the `sleeping` log throttle,
 * carried in the slot.
 */
static int conr_gossip_votes_pass(cmt_conr_t *conR, cmt_conr_peer_slot_t *slot,
                                  int64_t now_ns)
{
    cmt_round_state_t     rs;
    cmt_prs_t             prs;
    cmt_extended_commit_t ec;
    cmt_commit_t          commit;
    cmt_vote_set_reader_t reader;
    int64_t               sleep_d = conR->cs->config->peer_gossip_sleep_duration;
    int64_t               store_base;
    bool                  sent;
    bool                  found;
    bool                  ve_enabled;
    int                   rc;

    for (;;) {                                        /* :704 OUTER_LOOP */
        /* :706-709 — "Manage disconnects from self or peer." */
        if (!slot->started || !conR->running) {                  /* :707 */
            return CMT_OK;
        }
        rc = cmt_conr_get_round_state(conR, &rs);                /* :710 */
        if (rc != CMT_OK) {
            return rc;
        }
        cmt_ps_get_round_state(&slot->ps, &prs);                 /* :711 */

        switch (slot->sleeping) {                                /* :713 */
        case 1:                                    /* :714 First sleep   */
            slot->sleeping = 2;                                  /* :715 */
            break;
        case 2:                                    /* :716 No more sleep */
            slot->sleeping = 0;                                  /* :717 */
            break;
        default:
            break;
        }

        /* :723-729 — "If height matches, then send LastCommit, Prevotes,
         * Precommits." */
        if (rs.height == prs.height) {                           /* :724 */
            sent = false;
            rc = conr_gossip_votes_for_height(slot, &rs, &prs, &sent); /* :726 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (sent) {
                continue;                                        /* :727 */
            }
        }

        /* :731-738 — "Special catchup logic. If peer is lagging by height
         * 1, send LastCommit." */
        if (prs.height != 0 && rs.height == prs.height + 1) {    /* :733 */
            sent = false;
            rc = conr_pick_send(slot, rs.last_commit, &sent);    /* :734 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (sent) {
                continue;                                        /* :736 */
            }
        }

        /* :740-769 — "Catchup logic. If peer is lagging by more than 1,
         * send Commit." */
        store_base = 0;
        rc = conR->host.bs_base(conR->host_ctx, &store_base);    /* :742 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        /* :743 `rs.Height >= prs.Height+2`, written without the addition
         * so it cannot overflow (prs.height > 0 here; Go's own expression
         * wraps only for prs.Height ≥ INT64_MAX-1). */
        if (store_base > 0 && prs.height != 0 && rs.height - 2 >= prs.height &&
            prs.height >= store_base) {                          /* :743 */
            /* :744-752 — "Load the block's extended commit for prs.Height,
             * which contains precommit signatures for prs.Height."
             * :748-752 the conS.mtx.RLock — dropped. */
            ve_enabled = false;
            rc = cmt_abci_params_vote_extensions_enabled(
                    conR->cs->state.consensus_params.abci, prs.height,
                    &ve_enabled);                                /* :751 */
            if (rc != CMT_OK) {
                return CMT_FAULT;   /* h < 1 is impossible here (:743) */
            }
            found = false;
            memset(&ec, 0, sizeof(ec));
            if (ve_enabled) {                                    /* :753 */
                rc = conR->host.bs_load_block_extended_commit(conR->host_ctx,
                        prs.height, &ec, &found);                /* :754 */
                if (rc != CMT_OK) {
                    return CMT_FAULT;
                }
            } else {
                memset(&commit, 0, sizeof(commit));
                rc = conR->host.bs_load_block_commit(conR->host_ctx, prs.height,
                                                     &commit, &found); /* :756 */
                if (rc != CMT_OK) {
                    return CMT_FAULT;
                }
                if (!found) {                                    /* :757 */
                    /* :758 — `continue`: the reference busy-loops until the
                     * store answers; within one tick it cannot, so the
                     * pass ENDS (R3-A-1). */
                    return CMT_OK;
                }
                rc = cmt_commit_wrapped_extended_commit(&commit, conR->ecsigs,
                                                        conR->ecsigs_cap, &ec); /* :760 */
                if (rc != CMT_OK) {
                    /* Our own store's commit does not wrap: NODE-LOCAL. */
                    QGP_LOG_ERROR(LOG_TAG, "WrappedExtendedCommit failed (%d)", rc);
                    return CMT_FAULT;
                }
            }
            if (!found) {                                        /* :762 */
                return CMT_OK;                          /* :763, as :758 */
            }
            reader = cmt_extended_commit_reader_of(&ec);
            sent   = false;
            rc = cmt_ps_pick_send_vote(&slot->ps, &reader, &sent); /* :765 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (sent) {
                continue;                                        /* :767 */
            }
        }

        switch (slot->sleeping) {                                /* :771 */
        case 0:
            /* :773-777 — "We sent nothing. Sleep..." (a debug log) */
            slot->sleeping = 1;                                  /* :774 */
            break;
        case 2:
            /* :779 — "Continued sleep..." */
            slot->sleeping = 1;                                  /* :780 */
            break;
        default:
            break;
        }

        conr_sleep(slot, CMT_CONR_ROUTINE_VOTES, now_ns, sleep_d); /* :783 */
        return CMT_OK;                                           /* :784 */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:846-945 — queryMaj23Routine
 * ══════════════════════════════════════════════════════════════════════ */

/** :863-871, :883-891, :904-912, :927-935 — one VoteSetMaj23 by TrySend
 *  on the StateChannel; the result is unused by the reference. */
static int conr_try_send_maj23(cmt_conr_t *conR, cmt_conr_peer_slot_t *slot,
                               int64_t height, int32_t round, int32_t type,
                               const cmt_block_id_t *block_id)
{
    cmt_msg_t *msg = conr_msg_begin(conR, CMT_PB_CONS_MSG_VOTE_SET_MAJ23);
    bool       sent = false;

    msg->u.vote_set_maj23.height   = height;
    msg->u.vote_set_maj23.round    = round;
    msg->u.vote_set_maj23.type     = type;
    msg->u.vote_set_maj23.block_id = *block_id;
    return cmt_ps_peer_send(&slot->ps, true, CMT_CONR_STATE_CHANNEL, msg,
                            &sent);
}

/**
 * cometbft@709fd12b consensus/reactor.go:848-945 — queryMaj23Routine(),
 * one pass. "NOTE: `queryMaj23Routine` has a simple crude design since it
 * only comes into play for liveness when there's a signature DDoS attack
 * happening." Four blocks, each sleeping AFTER its send and then falling
 * to the next; `maj23_pc` resumes the pass at the block after the sleep
 * (cmt_conr.h).
 */
static int conr_query_maj23_pass(cmt_conr_t *conR, cmt_conr_peer_slot_t *slot,
                                 int64_t now_ns)
{
    cmt_round_state_t rs;
    cmt_prs_t         prs;
    cmt_block_id_t    maj23;
    int64_t           sleep_d = conR->cs->config->peer_query_maj23_sleep_duration;
    bool              ok;
    int               rc;

    /* :851-854 — "Manage disconnects from self or peer." */
    if (!slot->started || !conR->running) {                      /* :852 */
        return CMT_OK;
    }
    switch (slot->maj23_pc) {
    case 0:
        /* :856-875 — "Maybe send Height/Round/Prevotes" */
        rc = cmt_conr_get_round_state(conR, &rs);                /* :858 */
        if (rc != CMT_OK) {
            return rc;
        }
        cmt_ps_get_round_state(&slot->ps, &prs);                 /* :859 */
        if (rs.height == prs.height) {                           /* :860 */
            ok = false;
            rc = cmt_vote_set_two_thirds_majority(
                    cmt_hvs_prevotes(rs.votes, prs.round), &maj23, &ok); /* :861 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (ok) {
                rc = conr_try_send_maj23(conR, slot, prs.height, prs.round,
                        (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &maj23); /* :863-871 */
                if (rc != CMT_OK) {
                    return rc;
                }
                slot->maj23_pc = 1;
                conr_sleep(slot, CMT_CONR_ROUTINE_MAJ23, now_ns, sleep_d); /* :872 */
                return CMT_OK;
            }
        }
        slot->maj23_pc = 1;
        /* fall through */
    case 1:
        /* :877-895 — "Maybe send Height/Round/Precommits" */
        rc = cmt_conr_get_round_state(conR, &rs);                /* :879 */
        if (rc != CMT_OK) {
            return rc;
        }
        cmt_ps_get_round_state(&slot->ps, &prs);                 /* :880 */
        if (rs.height == prs.height) {                           /* :881 */
            ok = false;
            rc = cmt_vote_set_two_thirds_majority(
                    cmt_hvs_precommits(rs.votes, prs.round), &maj23, &ok); /* :882 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (ok) {
                rc = conr_try_send_maj23(conR, slot, prs.height, prs.round,
                        (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, &maj23); /* :883-891 */
                if (rc != CMT_OK) {
                    return rc;
                }
                slot->maj23_pc = 2;
                conr_sleep(slot, CMT_CONR_ROUTINE_MAJ23, now_ns, sleep_d); /* :892 */
                return CMT_OK;
            }
        }
        slot->maj23_pc = 2;
        /* fall through */
    case 2:
        /* :897-916 — "Maybe send Height/Round/ProposalPOL" */
        rc = cmt_conr_get_round_state(conR, &rs);                /* :899 */
        if (rc != CMT_OK) {
            return rc;
        }
        cmt_ps_get_round_state(&slot->ps, &prs);                 /* :900 */
        if (rs.height == prs.height && prs.proposal_pol_round >= 0) { /* :901 */
            ok = false;
            rc = cmt_vote_set_two_thirds_majority(
                    cmt_hvs_prevotes(rs.votes, prs.proposal_pol_round),
                    &maj23, &ok);                                /* :902 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (ok) {
                rc = conr_try_send_maj23(conR, slot, prs.height,
                        prs.proposal_pol_round,
                        (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &maj23); /* :904-912 */
                if (rc != CMT_OK) {
                    return rc;
                }
                slot->maj23_pc = 3;
                conr_sleep(slot, CMT_CONR_ROUTINE_MAJ23, now_ns, sleep_d); /* :913 */
                return CMT_OK;
            }
        }
        slot->maj23_pc = 3;
        /* fall through */
    case 3: {
        /* :918-919 — "Little point sending LastCommitRound/LastCommit,
         * These are fleeting and non-blocking."
         * :921-939 — "Maybe send Height/CatchupCommitRound/CatchupCommit." */
        int64_t store_height = 0;
        int64_t store_base   = 0;

        cmt_ps_get_round_state(&slot->ps, &prs);                 /* :923 */
        rc = conR->host.bs_height(conR->host_ctx, &store_height); /* :924 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        rc = conR->host.bs_base(conR->host_ctx, &store_base);    /* :925 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        if (prs.catchup_commit_round != -1 && prs.height > 0 &&
            prs.height <= store_height && prs.height >= store_base) { /* :924-925 */
            cmt_commit_t commit;
            bool         found = false;

            memset(&commit, 0, sizeof(commit));
            rc = cmt_cs_load_commit(conR->cs, prs.height, &commit, &found); /* :926 */
            if (rc != CMT_OK) {
                return CMT_FAULT;
            }
            if (found) {
                rc = conr_try_send_maj23(conR, slot, prs.height, commit.round,
                        (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                        &commit.block_id);                       /* :927-935 */
                if (rc != CMT_OK) {
                    return rc;
                }
                slot->maj23_pc = 4;
                conr_sleep(slot, CMT_CONR_ROUTINE_MAJ23, now_ns, sleep_d); /* :936 */
                return CMT_OK;
            }
        }
        slot->maj23_pc = 4;
    }
    /* fall through */
    case 4:
    default:
        slot->maj23_pc = 0;                                      /* :943 */
        conr_sleep(slot, CMT_CONR_ROUTINE_MAJ23, now_ns, sleep_d); /* :941 */
        return CMT_OK;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * the tick (C only) — cmt_conr.h "THREADS → TICKS"
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_conr_tick(cmt_conr_t *conR, int64_t *out_next_deadline_ns)
{
    cmt_time_t now;
    int64_t    now_ns;
    int64_t    deadline = INT64_MAX;
    size_t     i;
    int        r;
    int        rc;

    if (conR == NULL) {
        return CMT_FAULT;
    }
    if (out_next_deadline_ns != NULL) {
        *out_next_deadline_ns = INT64_MAX;
    }
    if (!conR->running) {
        return CMT_OK;              /* every routine returns (:545, :707, :852) */
    }
    rc = conr_now(conR, &now);                          /* once per tick */
    if (rc != CMT_OK) {
        return rc;
    }
    now_ns = cmt_time_unix_nano(now);

    for (i = 0u; i < (size_t)CMT_CONR_MAX_PEERS; i++) {
        cmt_conr_peer_slot_t *slot = &conR->peers[i];

        if (!slot->started) {
            continue;
        }
        /* :201-203 — the goroutine start order: data, votes, maj23. */
        for (r = 0; r < (int)CMT_CONR_NUM_ROUTINES; r++) {
            if (slot->asleep[r] && now_ns < slot->not_before_ns[r]) {
                continue;                              /* still sleeping */
            }
            slot->asleep[r] = false;
            switch ((cmt_conr_routine_t)r) {
            case CMT_CONR_ROUTINE_DATA:
                rc = conr_gossip_data_pass(conR, slot, now_ns);
                break;
            case CMT_CONR_ROUTINE_VOTES:
                rc = conr_gossip_votes_pass(conR, slot, now_ns);
                break;
            case CMT_CONR_ROUTINE_MAJ23:
            default:
                rc = conr_query_maj23_pass(conR, slot, now_ns);
                break;
            }
            if (rc != CMT_OK) {
                return rc;
            }
        }
    }
    for (i = 0u; i < (size_t)CMT_CONR_MAX_PEERS; i++) {
        cmt_conr_peer_slot_t *slot = &conR->peers[i];

        if (!slot->started) {
            continue;
        }
        for (r = 0; r < (int)CMT_CONR_NUM_ROUTINES; r++) {
            if (slot->asleep[r] && slot->not_before_ns[r] < deadline) {
                deadline = slot->not_before_ns[r];
            }
        }
    }
    if (out_next_deadline_ns != NULL) {
        *out_next_deadline_ns = deadline;
    }
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * msgs.go:232-234 and reactor.go:1536-1810 — ValidateBasic
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/reactor.go:1536-1557 —
 * NewRoundStepMessage.ValidateBasic() */
int cmt_new_round_step_msg_validate_basic(const cmt_new_round_step_msg_t *m)
{
    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1537 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (m->round < 0) {                                          /* :1540 */
        return CMT_REJECT;                             /* "negative Round" */
    }
    if (!cmt_round_step_is_valid(m->step)) {                     /* :1543 */
        return CMT_REJECT;                             /* "invalid Step" */
    }
    /* :1547 "NOTE: SecondsSinceStartTime may be negative" */
    /* :1549-1551 "LastCommitRound will be -1 for the initial height, but
     * we don't know what height this is since it can be specified in
     * genesis. The reactor will have to validate this via
     * ValidateHeight()." */
    if (m->last_commit_round < -1) {                             /* :1552 */
        return CMT_REJECT;       /* "invalid LastCommitRound (cannot be < -1)" */
    }
    return CMT_OK;                                               /* :1556 */
}

/* cometbft@709fd12b consensus/reactor.go:1560-1574 —
 * NewRoundStepMessage.ValidateHeight() */
int cmt_new_round_step_msg_validate_height(const cmt_new_round_step_msg_t *m,
                                           int64_t initial_height)
{
    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < initial_height) {                            /* :1561 */
        return CMT_REJECT;      /* "invalid Height (lower than initial height)" */
    }
    if (m->height == initial_height && m->last_commit_round != -1) { /* :1565 */
        return CMT_REJECT;      /* "invalid LastCommitRound (must be -1 for
                                 *  initial height)" */
    }
    if (m->height > initial_height && m->last_commit_round < 0) { /* :1569 */
        return CMT_REJECT;      /* "LastCommitRound can only be negative for
                                 *  initial height" */
    }
    return CMT_OK;                                               /* :1573 */
}

/* cometbft@709fd12b consensus/reactor.go:1596-1618 —
 * NewValidBlockMessage.ValidateBasic() */
int cmt_new_valid_block_msg_validate_basic(const cmt_new_valid_block_msg_t *m)
{
    int size;

    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1597 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (m->round < 0) {                                          /* :1600 */
        return CMT_REJECT;                             /* "negative Round" */
    }
    if (cmt_psh_validate_basic(&m->block_part_set_header) != CMT_OK) { /* :1603 */
        return CMT_REJECT;                     /* "wrong BlockPartSetHeader" */
    }
    /* :1606 — m.BlockParts.Size(): 0 for a nil array (bit_array.go:57-59). */
    size = m->has_block_parts ? cmt_bits_size(&m->block_parts) : 0;
    if (size == 0) {                                             /* :1606 */
        return CMT_REJECT;                             /* "empty blockParts" */
    }
    if ((int64_t)size != (int64_t)m->block_part_set_header.total) { /* :1609 */
        return CMT_REJECT;   /* "blockParts bit array size %d not equal to
                              *  BlockPartSetHeader.Total %d" */
    }
    if (size > (int)CMT_MAX_BLOCK_PARTS_COUNT) {                 /* :1614 */
        return CMT_REJECT;                /* "blockParts bit array is too big" */
    }
    return CMT_OK;                                               /* :1617 */
}

/* cometbft@709fd12b consensus/reactor.go:1634-1636 —
 * ProposalMessage.ValidateBasic() */
int cmt_proposal_msg_validate_basic(const cmt_proposal_msg_t *m)
{
    int rc;

    if (m == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_proposal_validate_basic(&m->proposal);              /* :1635 */
    return (rc == CMT_OK) ? CMT_OK : ((rc == CMT_FAULT) ? CMT_FAULT : CMT_REJECT);
}

/* cometbft@709fd12b consensus/reactor.go:1653-1667 —
 * ProposalPOLMessage.ValidateBasic() */
int cmt_proposal_pol_msg_validate_basic(const cmt_proposal_pol_msg_t *m)
{
    int size;

    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1654 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (m->proposal_pol_round < 0) {                             /* :1657 */
        return CMT_REJECT;                    /* "negative ProposalPOLRound" */
    }
    size = m->has_proposal_pol ? cmt_bits_size(&m->proposal_pol) : 0;
    if (size == 0) {                                             /* :1660 */
        return CMT_REJECT;                   /* "empty ProposalPOL bit array" */
    }
    if (size > (int)CMT_MAX_VOTES_COUNT) {                       /* :1663 */
        return CMT_REJECT;               /* "proposalPOL bit array is too big" */
    }
    return CMT_OK;                                               /* :1666 */
}

/* cometbft@709fd12b consensus/reactor.go:1684-1695 —
 * BlockPartMessage.ValidateBasic() */
int cmt_block_part_msg_validate_basic(const cmt_block_part_msg_t *m)
{
    int rc;

    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1685 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (m->round < 0) {                                          /* :1688 */
        return CMT_REJECT;                             /* "negative Round" */
    }
    rc = cmt_part_validate_basic(&m->part);                      /* :1691 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    return (rc == CMT_OK) ? CMT_OK : CMT_REJECT;       /* "wrong Part" */
}

/* cometbft@709fd12b consensus/reactor.go:1710-1712 —
 * VoteMessage.ValidateBasic() */
int cmt_vote_msg_validate_basic(const cmt_vote_msg_t *m)
{
    int rc;

    if (m == NULL) {
        return CMT_FAULT;
    }
    if (!m->has_vote) {
        /* :1711 `m.Vote.ValidateBasic()` on a nil Vote dereferences it at
         * types/vote.go:278 and panics; a wire message without field 1
         * reaches here (cmt_msgs.h:157-163). PEER-REACHABLE → CMT_REJECT. */
        return CMT_REJECT;
    }
    rc = cmt_vote_validate_basic(&m->vote);                      /* :1711 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    return (rc == CMT_OK) ? CMT_OK : CMT_REJECT;
}

/* cometbft@709fd12b consensus/reactor.go:1730-1744 —
 * HasVoteMessage.ValidateBasic() */
int cmt_has_vote_msg_validate_basic(const cmt_has_vote_msg_t *m)
{
    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1731 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (m->round < 0) {                                          /* :1734 */
        return CMT_REJECT;                             /* "negative Round" */
    }
    if (!cmt_is_vote_type_valid(m->type)) {                      /* :1737 */
        return CMT_REJECT;                             /* "invalid Type" */
    }
    if (m->index < 0) {                                          /* :1740 */
        return CMT_REJECT;                             /* "negative Index" */
    }
    return CMT_OK;                                               /* :1743 */
}

/* cometbft@709fd12b consensus/reactor.go:1762-1776 —
 * VoteSetMaj23Message.ValidateBasic() */
int cmt_vote_set_maj23_msg_validate_basic(const cmt_vote_set_maj23_msg_t *m)
{
    int rc;

    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1763 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (m->round < 0) {                                          /* :1766 */
        return CMT_REJECT;                             /* "negative Round" */
    }
    if (!cmt_is_vote_type_valid(m->type)) {                      /* :1769 */
        return CMT_REJECT;                             /* "invalid Type" */
    }
    rc = cmt_block_id_validate_basic(&m->block_id);              /* :1772 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    return (rc == CMT_OK) ? CMT_OK : CMT_REJECT;       /* "wrong BlockID" */
}

/* cometbft@709fd12b consensus/reactor.go:1795-1810 —
 * VoteSetBitsMessage.ValidateBasic() */
int cmt_vote_set_bits_msg_validate_basic(const cmt_vote_set_bits_msg_t *m)
{
    int size;
    int rc;

    if (m == NULL) {
        return CMT_FAULT;
    }
    if (m->height < 0) {                                         /* :1796 */
        return CMT_REJECT;                             /* "negative Height" */
    }
    if (!cmt_is_vote_type_valid(m->type)) {                      /* :1799 */
        return CMT_REJECT;                             /* "invalid Type" */
    }
    rc = cmt_block_id_validate_basic(&m->block_id);              /* :1802 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        return CMT_REJECT;                             /* "wrong BlockID" */
    }
    /* :1805 "NOTE: Votes.Size() can be zero if the node does not have any" */
    size = m->has_votes ? cmt_bits_size(&m->votes) : 0;
    if (size > (int)CMT_MAX_VOTES_COUNT) {                       /* :1806 */
        return CMT_REJECT;                  /* "votes bit array is too big" */
    }
    return CMT_OK;                                               /* :1809 */
}

/* cometbft@709fd12b consensus/msgs.go:232-234 — `pb.ValidateBasic()` over
 * the nine Message implementations (reactor.go:1507-1509). */
int cmt_msg_validate_basic(const cmt_msg_t *msg)
{
    if (msg == NULL) {
        return CMT_FAULT;
    }
    switch (msg->kind) {
    case CMT_PB_CONS_MSG_NEW_ROUND_STEP:
        return cmt_new_round_step_msg_validate_basic(&msg->u.new_round_step);
    case CMT_PB_CONS_MSG_NEW_VALID_BLOCK:
        return cmt_new_valid_block_msg_validate_basic(&msg->u.new_valid_block);
    case CMT_PB_CONS_MSG_PROPOSAL:
        return cmt_proposal_msg_validate_basic(&msg->u.proposal);
    case CMT_PB_CONS_MSG_PROPOSAL_POL:
        return cmt_proposal_pol_msg_validate_basic(&msg->u.proposal_pol);
    case CMT_PB_CONS_MSG_BLOCK_PART:
        return cmt_block_part_msg_validate_basic(&msg->u.block_part);
    case CMT_PB_CONS_MSG_VOTE:
        return cmt_vote_msg_validate_basic(&msg->u.vote);
    case CMT_PB_CONS_MSG_HAS_VOTE:
        return cmt_has_vote_msg_validate_basic(&msg->u.has_vote);
    case CMT_PB_CONS_MSG_VOTE_SET_MAJ23:
        return cmt_vote_set_maj23_msg_validate_basic(&msg->u.vote_set_maj23);
    case CMT_PB_CONS_MSG_VOTE_SET_BITS:
        return cmt_vote_set_bits_msg_validate_basic(&msg->u.vote_set_bits);
    default:
        return CMT_REJECT;          /* msgs.go:228-229 "message not recognized" */
    }
}
