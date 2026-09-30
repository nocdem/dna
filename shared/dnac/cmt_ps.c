/**
 * @file shared/dnac/cmt_ps.c
 * @brief cometbft @v0.38.26 `consensus/reactor.go:1026-1491` (`PeerState`)
 *        ported to C. See cmt_ps.h for the module contract.
 *
 * Every function names the reference range it ports; every dropped lock
 * is named in cmt_ps.h's substitution list rather than at each site.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "cmt_ps.h"

#include <string.h>

#include "cmt_cs.h"                  /* cmt_compare_hrs (state.go:2593) */
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "CMT_PS"

/* ══════════════════════════════════════════════════════════════════════
 * The bit-array pool — C only, Go's heap for the six PRS pointers
 * ══════════════════════════════════════════════════════════════════════ */

/** Is `slot` named by any of the six PRS pointers? */
static bool ps_slot_named(const cmt_ps_t *ps, const cmt_bit_array_t *slot)
{
    const cmt_prs_t *p = &ps->prs;

    return p->proposal_block_parts == slot || p->proposal_pol == slot ||
           p->prevotes == slot || p->precommits == slot ||
           p->last_commit == slot || p->catchup_commit == slot;
}

/**
 * Take a slot no name points at. The caller has ALREADY cleared the name
 * it is about to assign, so at most five names hold slots and one of the
 * six is free; a miss is a broken invariant of this module, CMT_FAULT.
 */
static int ps_slot_take(cmt_ps_t *ps, cmt_bit_array_t **out)
{
    size_t i;

    for (i = 0u; i < (size_t)CMT_PS_BITS_SLOTS; i++) {
        if (!ps_slot_named(ps, &ps->pool[i])) {
            memset(&ps->pool[i], 0, sizeof(ps->pool[i]));
            *out = &ps->pool[i];
            return CMT_OK;
        }
    }
    /* NODE-LOCAL → CMT_FAULT: six names, six slots, one name cleared —
     * a free slot exists by construction (cmt_ps.h, "THE BIT ARRAYS ARE
     * POINTERS"). */
    QGP_LOG_ERROR(LOG_TAG, "peer-state bit-array pool exhausted");
    return CMT_FAULT;
}

/**
 * `bits.NewBitArray(n)` (libs/bits/bit_array.go:25-33) into a fresh slot.
 * `*out` MUST be a PRS pointer field the caller has just set to NULL.
 * A non-positive width is the reference's nil (:26-28): `*out` stays NULL
 * and the result is CMT_OK.
 */
static int ps_bits_new(cmt_ps_t *ps, int bits, cmt_bit_array_t **out)
{
    cmt_bit_array_t *slot;
    int              rc;

    *out = NULL;
    if (bits <= 0) {
        return CMT_OK;                                    /* nil, :26-28 */
    }
    rc = ps_slot_take(ps, &slot);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_bits_new(slot, bits);
    if (rc == CMT_BITS_NIL) {
        return CMT_OK;                                    /* nil, :26-28 */
    }
    if (rc != CMT_OK) {
        return rc;                        /* CMT_REJECT above the bound */
    }
    *out = slot;
    return CMT_OK;
}

/**
 * A message's `*bits.BitArray` becoming a PRS pointer (:1439, :1456): Go
 * stores the pointer to the decoded message's array; here the message
 * dies with its caller, so the value is copied into a slot. `has` false
 * is the nil pointer. `*out` MUST be a PRS field already set to NULL.
 */
static int ps_bits_copy_in(cmt_ps_t *ps, bool has, const cmt_bit_array_t *src,
                           cmt_bit_array_t **out)
{
    cmt_bit_array_t *slot;
    int              rc;

    *out = NULL;
    if (!has) {
        return CMT_OK;
    }
    if (src->n_elems > (size_t)CMT_BITS_MAX_ELEMS) {
        /* INVARIANT atlas-dec-7495d337…: a decoded array is checked by
         * cmt_bits_from_proto; a hand-built one is checked here before it
         * is copied word for word. */
        return CMT_REJECT;
    }
    rc = ps_slot_take(ps, &slot);
    if (rc != CMT_OK) {
        return rc;
    }
    *slot = *src;
    *out  = slot;
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * VoteSetReader — the seven methods over the two arms
 * ══════════════════════════════════════════════════════════════════════ */

/** vote_set.go:138-144 `Size()` / block.go:1183-1190 `Size()`. */
static int reader_size(const cmt_vote_set_reader_t *r)
{
    if (r->ec != NULL) {
        return (int)cmt_extended_commit_size(r->ec);
    }
    return cmt_vote_set_size(r->vs);           /* NULL → 0, :140-142 */
}

/** vote_set.go:114-120 / block.go:1175-1177 `GetHeight()`. */
static int64_t reader_height(const cmt_vote_set_reader_t *r)
{
    if (r->ec != NULL) {
        return cmt_extended_commit_get_height(r->ec);
    }
    return cmt_vote_set_get_height(r->vs);
}

/** vote_set.go:122-128 / block.go:1179-1181 `GetRound()`. */
static int32_t reader_round(const cmt_vote_set_reader_t *r)
{
    if (r->ec != NULL) {
        return cmt_extended_commit_get_round(r->ec);
    }
    return cmt_vote_set_get_round(r->vs);
}

/** vote_set.go:130-136 / block.go:1170-1173 `Type()`. */
static int32_t reader_type(const cmt_vote_set_reader_t *r)
{
    if (r->ec != NULL) {
        return (int32_t)cmt_extended_commit_type(r->ec);
    }
    return (int32_t)cmt_vote_set_type(r->vs);
}

/** vote_set.go:439-450 / block.go:1214-1218 `IsCommit()`. */
static bool reader_is_commit(const cmt_vote_set_reader_t *r)
{
    if (r->ec != NULL) {
        return cmt_extended_commit_is_commit(r->ec);
    }
    return cmt_vote_set_is_commit(r->vs);
}

/** vote_set.go:369-377 / block.go:1192-1205 `BitArray()`. `*out_ba` is
 *  NULL for the reference's nil result. */
static int reader_bit_array(const cmt_vote_set_reader_t *r,
                            cmt_bit_array_t *storage, cmt_bit_array_t **out_ba)
{
    int rc;

    *out_ba = NULL;
    if (r->ec != NULL) {
        rc = cmt_extended_commit_bit_array(r->ec, storage);
    } else {
        rc = cmt_vote_set_bit_array(r->vs, storage);
    }
    if (rc == CMT_BITS_NIL) {
        return CMT_OK;
    }
    if (rc != CMT_OK) {
        return rc;
    }
    *out_ba = storage;
    return CMT_OK;
}

/** vote_set.go:392-401 / block.go:1207-1212 `GetByIndex()`, copied out.
 *  `*out_present` false is the reference's nil vote. */
static int reader_get_by_index(const cmt_vote_set_reader_t *r, int32_t index,
                               cmt_vote_t *out, bool *out_present)
{
    const cmt_vote_t *borrowed;
    int               rc;

    *out_present = false;
    if (r->ec != NULL) {
        rc = cmt_extended_commit_get_by_index(r->ec, index, out);
        if (rc != CMT_OK) {
            return rc;
        }
        *out_present = true;
        return CMT_OK;
    }
    borrowed = NULL;
    rc = cmt_vote_set_get_by_index(r->vs, index, &borrowed);
    if (rc != CMT_OK) {
        return rc;
    }
    if (borrowed == NULL) {
        return CMT_OK;                                       /* :395-397 */
    }
    *out         = *borrowed;
    *out_present = true;
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:1055-1102 — construction and accessors
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 consensus/reactor.go:1056-1068 — NewPeerState() */
int cmt_ps_init(cmt_ps_t *ps, const cmt_ps_peer_t *peer)
{
    if (ps == NULL || peer == NULL || peer->scratch == NULL) {
        return CMT_FAULT;
    }
    memset(ps, 0, sizeof(*ps));
    ps->peer                     = *peer;                        /* :1058 */
    /* :1060-1065 — the PeerRoundState literal: four -1s, the rest zero.
     * Go's zero time.Time is CMT_TIME_ZERO, not {0,0}. */
    ps->prs.start_time           = CMT_TIME_ZERO;
    ps->prs.round                = -1;                           /* :1061 */
    ps->prs.proposal_pol_round   = -1;                           /* :1062 */
    ps->prs.last_commit_round    = -1;                           /* :1063 */
    ps->prs.catchup_commit_round = -1;                           /* :1064 */
    /* :1066 — &peerStateStats{}: zero, already. */
    return CMT_OK;
}

/* cometbft@v0.38.26 consensus/reactor.go:1079-1085 — GetRoundState() */
void cmt_ps_get_round_state(const cmt_ps_t *ps, cmt_prs_t *out)
{
    if (ps == NULL || out == NULL) {
        return;
    }
    *out = ps->prs;                                              /* :1083 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1098-1102 — GetHeight() */
int64_t cmt_ps_get_height(const cmt_ps_t *ps)
{
    if (ps == NULL) {
        return 0;
    }
    return ps->prs.height;                                       /* :1101 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:1104-1153 — what the peer has
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@v0.38.26 consensus/reactor.go:1105-1128 — SetHasProposal()
 *
 * ORDER DEVIATION, and it is the point of it: the reference assigns
 * `Proposal = true` (:1117), the header (:1124) and the bit array (:1125)
 * in that order, because `bits.NewBitArray` cannot fail — it allocates
 * whatever `Total` asks. `ps_bits_new` CAN refuse (a `Total` above the bit
 * array's capacity, or a pool with no free slot), and doing it in the
 * reference's order left the PeerState HALF APPLIED: the proposal flag
 * and the header written, the array, the POL round and the POL not —
 * so this peer looked like it had announced a proposal whose POL round was
 * whatever the previous height left behind (deviation register R3-AUD-21).
 *
 * Here NOTHING is written until the array exists. The observable order is
 * unchanged for every input the reference can also handle, because on
 * those the constructor never refuses.
 */
int cmt_ps_set_has_proposal(cmt_ps_t *ps, const cmt_proposal_t *proposal)
{
    cmt_bit_array_t *parts;
    int              rc;

    if (ps == NULL || proposal == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.height != proposal->height ||
        ps->prs.round != proposal->round) {                      /* :1109 */
        return CMT_OK;
    }
    if (ps->prs.proposal) {                                      /* :1113 */
        return CMT_OK;
    }

    /* :1119-1122 — set by NewValidBlockMessage already: the flag is the
     * only thing this call has left to do. */
    if (ps->prs.proposal_block_parts != NULL) {
        ps->prs.proposal = true;                                 /* :1117 */
        return CMT_OK;
    }

    parts = NULL;
    rc = ps_bits_new(ps, (int)proposal->block_id.part_set_header.total,
                     &parts);                                    /* :1125 */
    if (rc != CMT_OK) {
        /* Apply NOTHING. The peer state is exactly what it was. */
        return rc;
    }
    ps->prs.proposal = true;                                     /* :1117 */
    ps->prs.proposal_block_part_set_header =
            proposal->block_id.part_set_header;                  /* :1124 */
    ps->prs.proposal_block_parts = parts;                        /* :1125 */
    ps->prs.proposal_pol_round   = proposal->pol_round;          /* :1126 */
    ps->prs.proposal_pol         = NULL; /* :1127 nil until POL received */
    return CMT_OK;
}

/* cometbft@v0.38.26 consensus/reactor.go:1131-1141 — InitProposalBlockParts() */
int cmt_ps_init_proposal_block_parts(cmt_ps_t *ps,
                                     const cmt_part_set_header_t *psh)
{
    if (ps == NULL || psh == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.proposal_block_parts != NULL) {                  /* :1135 */
        return CMT_OK;
    }
    ps->prs.proposal_block_part_set_header = *psh;               /* :1139 */
    return ps_bits_new(ps, (int)psh->total,
                       &ps->prs.proposal_block_parts);           /* :1140 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1144-1153 — SetHasProposalBlockPart() */
int cmt_ps_set_has_proposal_block_part(cmt_ps_t *ps, int64_t height,
                                       int32_t round, int index)
{
    int rc;

    if (ps == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.height != height || ps->prs.round != round) {    /* :1148 */
        return CMT_OK;
    }
    /* :1152 — SetIndex on a nil array is a no-op (bit_array.go:84-86). */
    rc = cmt_bits_set_index(ps->prs.proposal_block_parts, index, true);
    return (rc < 0) ? rc : CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:1155-1308 — picking votes and the bit arrays behind them
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@v0.38.26 consensus/reactor.go:1203-1247 — getVoteBitArray().
 * The pointer into the pool the reference returns, or NULL for its nil.
 */
static cmt_bit_array_t *ps_get_vote_bit_array(cmt_ps_t *ps, int64_t height,
                                              int32_t round, int32_t vote_type)
{
    if (!cmt_is_vote_type_valid(vote_type)) {                    /* :1204 */
        return NULL;
    }
    if (ps->prs.height == height) {                              /* :1208 */
        if (ps->prs.round == round) {                            /* :1209 */
            switch (vote_type) {
            case (int32_t)CMT_PB_MSG_TYPE_PREVOTE:
                return ps->prs.prevotes;                         /* :1212 */
            case (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT:
                return ps->prs.precommits;                       /* :1214 */
            default:
                break;
            }
        }
        if (ps->prs.catchup_commit_round == round) {             /* :1217 */
            switch (vote_type) {
            case (int32_t)CMT_PB_MSG_TYPE_PREVOTE:
                return NULL;                                     /* :1220 */
            case (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT:
                return ps->prs.catchup_commit;                   /* :1222 */
            default:
                break;
            }
        }
        if (ps->prs.proposal_pol_round == round) {               /* :1225 */
            switch (vote_type) {
            case (int32_t)CMT_PB_MSG_TYPE_PREVOTE:
                return ps->prs.proposal_pol;                     /* :1228 */
            case (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT:
                return NULL;                                     /* :1230 */
            default:
                break;
            }
        }
        return NULL;                                             /* :1233 */
    }
    if (ps->prs.height == height + 1) {                          /* :1235 */
        if (ps->prs.last_commit_round == round) {                /* :1236 */
            switch (vote_type) {
            case (int32_t)CMT_PB_MSG_TYPE_PREVOTE:
                return NULL;                                     /* :1239 */
            case (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT:
                return ps->prs.last_commit;                      /* :1241 */
            default:
                break;
            }
        }
        return NULL;                                             /* :1244 */
    }
    return NULL;                                                 /* :1246 */
}

/**
 * cometbft@v0.38.26 consensus/reactor.go:1250-1276 —
 * ensureCatchupCommitRound(). "'round': A round for which we have a +2/3
 * commit." The commented-out conflict panic of :1254-1266 is the
 * reference's own dead code and is not carried.
 */
static int ps_ensure_catchup_commit_round(cmt_ps_t *ps, int64_t height,
                                          int32_t round, int num_validators)
{
    if (ps->prs.height != height) {                              /* :1251 */
        return CMT_OK;
    }
    if (ps->prs.catchup_commit_round == round) {                 /* :1267 */
        return CMT_OK;                                    /* nothing to do */
    }
    ps->prs.catchup_commit_round = round;                        /* :1270 */
    if (round == ps->prs.round) {                                /* :1271 */
        ps->prs.catchup_commit = ps->prs.precommits;             /* :1272 */
        return CMT_OK;
    }
    ps->prs.catchup_commit = NULL;
    return ps_bits_new(ps, num_validators, &ps->prs.catchup_commit); /* :1274 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1282-1286 EnsureVoteBitArrays()
 * and :1288-1308 ensureVoteBitArrays() — one function. */
int cmt_ps_ensure_vote_bit_arrays(cmt_ps_t *ps, int64_t height,
                                  int num_validators)
{
    int rc;

    if (ps == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.height == height) {                              /* :1290 */
        if (ps->prs.prevotes == NULL) {                          /* :1291 */
            rc = ps_bits_new(ps, num_validators, &ps->prs.prevotes);
            if (rc != CMT_OK) {
                return rc;
            }
        }
        if (ps->prs.precommits == NULL) {                        /* :1294 */
            rc = ps_bits_new(ps, num_validators, &ps->prs.precommits);
            if (rc != CMT_OK) {
                return rc;
            }
        }
        if (ps->prs.catchup_commit == NULL) {                    /* :1297 */
            rc = ps_bits_new(ps, num_validators, &ps->prs.catchup_commit);
            if (rc != CMT_OK) {
                return rc;
            }
        }
        if (ps->prs.proposal_pol == NULL) {                      /* :1300 */
            rc = ps_bits_new(ps, num_validators, &ps->prs.proposal_pol);
            if (rc != CMT_OK) {
                return rc;
            }
        }
        return CMT_OK;
    }
    if (ps->prs.height == height + 1) {                          /* :1303 */
        if (ps->prs.last_commit == NULL) {                       /* :1304 */
            return ps_bits_new(ps, num_validators, &ps->prs.last_commit);
        }
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 consensus/reactor.go:1177-1201 — PickVoteToSend() */
int cmt_ps_pick_vote_to_send(cmt_ps_t *ps, const cmt_vote_set_reader_t *votes,
                             cmt_vote_t *out_vote, bool *out_ok)
{
    cmt_bit_array_t  votes_ba_storage;
    cmt_bit_array_t  sub;
    cmt_bit_array_t *votes_ba;
    cmt_bit_array_t *ps_votes;
    int64_t          height;
    int32_t          round;
    int32_t          votes_type;
    int              size;
    int              index;
    bool             present;
    int              rc;

    if (ps == NULL || votes == NULL || out_vote == NULL || out_ok == NULL) {
        return CMT_FAULT;
    }
    *out_ok = false;
    if (reader_size(votes) == 0) {                               /* :1181 */
        return CMT_OK;
    }
    height     = reader_height(votes);                           /* :1185 */
    round      = reader_round(votes);
    votes_type = reader_type(votes);
    size       = reader_size(votes);

    /* :1187-1191 — "Lazily set data using 'votes'." */
    if (reader_is_commit(votes)) {                               /* :1188 */
        rc = ps_ensure_catchup_commit_round(ps, height, round, size);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    rc = cmt_ps_ensure_vote_bit_arrays(ps, height, size);        /* :1191 */
    if (rc != CMT_OK) {
        return rc;
    }

    ps_votes = ps_get_vote_bit_array(ps, height, round, votes_type); /* :1193 */
    if (ps_votes == NULL) {                                      /* :1194 */
        return CMT_OK;                          /* Not something worth sending */
    }
    /* :1197 — votes.BitArray().Sub(psVotes).PickRandom() */
    rc = reader_bit_array(votes, &votes_ba_storage, &votes_ba);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_bits_sub(votes_ba, ps_votes, &sub);
    if (rc == CMT_BITS_NIL) {
        return CMT_OK;                    /* nil.PickRandom() is (0, false) */
    }
    if (rc != CMT_OK) {
        return rc;
    }
    index = 0;
    rc = cmt_bits_pick_random(&sub, &index);
    if (rc == CMT_REJECT) {
        return CMT_OK;                                    /* :1197 !ok */
    }
    if (rc != CMT_OK) {
        return rc;
    }
    rc = reader_get_by_index(votes, (int32_t)index, out_vote, &present); /* :1198 */
    if (rc != CMT_OK) {
        return rc;
    }
    *out_ok = present;
    return CMT_OK;
}

/* p2p/peer.go:258-262 Send(), :264-268 TrySend(), :270-295 send():
 * marshal (:277-280) and hand the bytes to the chosen row (:285). */
int cmt_ps_peer_send(cmt_ps_t *ps, bool use_try_send, uint8_t channel_id,
                     const cmt_msg_t *msg, bool *out_sent)
{
    cmt_ps_scratch_t *s;
    cmt_ps_send_fn    fn;
    size_t            len;
    int               rc;

    if (ps == NULL || msg == NULL || out_sent == NULL ||
        ps->peer.scratch == NULL) {
        return CMT_FAULT;
    }
    *out_sent = false;
    s  = ps->peer.scratch;
    fn = use_try_send ? ps->peer.try_send : ps->peer.send;   /* :261 / :267 */
    if (fn == NULL) {
        return CMT_OK;        /* the reference's !p.IsRunning() (:271-272) */
    }
    rc = cmt_msg_to_proto(msg, s->pb);                           /* :278 */
    if (rc == CMT_FAULT) {
        /* cmt_msgs.h:274-281 — OUR OWN message is inconsistent (the :59
         * nil dereference of MsgToProto). NODE-LOCAL, not a "false". */
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "marshaling message to send: MsgToProto");
        return CMT_OK;                                       /* :281-283 */
    }
    len = 0u;
    if (cmt_pb_cons_message_marshal(s->pb, s->buf, s->cap, &len)
            != CMT_OK) {                                         /* :280 */
        QGP_LOG_ERROR(LOG_TAG, "marshaling message to send: Marshal");
        return CMT_OK;                                       /* :281-283 */
    }
    *out_sent = fn(ps->peer.ctx, ps->peer.idx, channel_id, s->buf, len); /* :285 */
    return CMT_OK;
}

/* cometbft@v0.38.26 consensus/reactor.go:1157-1172 — PickSendVote() */
int cmt_ps_pick_send_vote(cmt_ps_t *ps, const cmt_vote_set_reader_t *votes,
                          bool *out_sent)
{
    cmt_msg_t *msg;
    bool       ok;
    bool       sent;
    int        rc;

    if (ps == NULL || votes == NULL || out_sent == NULL ||
        ps->peer.scratch == NULL) {
        return CMT_FAULT;
    }
    *out_sent = false;
    msg = ps->peer.scratch->msg;
    memset(msg, 0, sizeof(*msg));
    msg->kind            = CMT_PB_CONS_MSG_VOTE;                 /* :1162 */
    msg->u.vote.has_vote = true;
    cmt_pb_vote_init(&msg->u.vote.vote);
    ok = false;
    rc = cmt_ps_pick_vote_to_send(ps, votes, &msg->u.vote.vote, &ok); /* :1158 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!ok) {
        return CMT_OK;                                           /* :1171 */
    }
    /* :1160-1165 — peer.Send on the VoteChannel; :1163 vote.ToProto() is
     * the identity on this representation (cmt_vote.h:170-172). */
    sent = false;
    rc = cmt_ps_peer_send(ps, false, CMT_CONR_VOTE_CHANNEL, msg, &sent);
    if (rc != CMT_OK) {
        return rc;
    }
    if (sent) {
        rc = cmt_ps_set_has_vote(ps, &msg->u.vote.vote);         /* :1166 */
        if (rc != CMT_OK) {
            return rc;
        }
        *out_sent = true;                                        /* :1167 */
    }
    return CMT_OK;                                               /* :1169 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:1310-1346 — statistics (ported; no caller in this port)
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 consensus/reactor.go:1312-1319 — RecordVote() */
int cmt_ps_record_vote(cmt_ps_t *ps)
{
    if (ps == NULL) {
        return 0;
    }
    ps->stats.votes++;                                           /* :1316 */
    return ps->stats.votes;                                      /* :1318 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1323-1328 — VotesSent() */
int cmt_ps_votes_sent(const cmt_ps_t *ps)
{
    if (ps == NULL) {
        return 0;
    }
    return ps->stats.votes;                                      /* :1327 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1332-1338 — RecordBlockPart() */
int cmt_ps_record_block_part(cmt_ps_t *ps)
{
    if (ps == NULL) {
        return 0;
    }
    ps->stats.block_parts++;                                     /* :1336 */
    return ps->stats.block_parts;                                /* :1337 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1341-1346 — BlockPartsSent() */
int cmt_ps_block_parts_sent(const cmt_ps_t *ps)
{
    if (ps == NULL) {
        return 0;
    }
    return ps->stats.block_parts;                                /* :1345 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:1348-1369 — marking votes
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 consensus/reactor.go:1356-1369 — setHasVote().
 * :1357-1362 is a log line, not ported. */
static int ps_set_has_vote_fields(cmt_ps_t *ps, int64_t height, int32_t round,
                                  int32_t vote_type, int32_t index)
{
    cmt_bit_array_t *ps_votes;
    int              rc;

    /* :1364 "NOTE: some may be nil BitArrays -> no side effects." */
    ps_votes = ps_get_vote_bit_array(ps, height, round, vote_type); /* :1365 */
    if (ps_votes == NULL) {
        return CMT_OK;
    }
    rc = cmt_bits_set_index(ps_votes, (int)index, true);         /* :1367 */
    return (rc < 0) ? rc : CMT_OK;
}

/* cometbft@v0.38.26 consensus/reactor.go:1349-1354 — SetHasVote() */
int cmt_ps_set_has_vote(cmt_ps_t *ps, const cmt_vote_t *vote)
{
    if (ps == NULL || vote == NULL) {
        return CMT_FAULT;
    }
    return ps_set_has_vote_fields(ps, vote->height, vote->round, vote->type,
                                  vote->validator_index);        /* :1353 */
}

/* ══════════════════════════════════════════════════════════════════════
 * reactor.go:1371-1490 — applying the peer's messages
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 consensus/reactor.go:1372-1423 — ApplyNewRoundStepMessage() */
int cmt_ps_apply_new_round_step_message(cmt_ps_t *ps,
                                        const cmt_new_round_step_msg_t *msg,
                                        cmt_time_t now)
{
    int64_t          ps_height;
    int32_t          ps_round;
    int32_t          ps_catchup_commit_round;
    cmt_bit_array_t *ps_catchup_commit;
    cmt_bit_array_t *last_precommits;
    cmt_time_t       start_time;

    if (ps == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    /* :1376-1379 — ignore duplicates or decreases. */
    if (cmt_compare_hrs(msg->height, msg->round, msg->step,
                        ps->prs.height, ps->prs.round, ps->prs.step) <= 0) {
        return CMT_OK;
    }

    /* :1381-1386 — just remember these values. */
    ps_height               = ps->prs.height;
    ps_round                = ps->prs.round;
    ps_catchup_commit_round = ps->prs.catchup_commit_round;
    ps_catchup_commit       = ps->prs.catchup_commit;
    last_precommits         = ps->prs.precommits;

    /* :1388 — cmttime.Now().Add(-SecondsSinceStartTime seconds). `now` is
     * the caller's clock read; the seconds are moved with a guard against
     * signed overflow (the peer chooses the number). See cmt_ps.h. */
    start_time = now;
    if (msg->seconds_since_start_time >= 0) {
        if (start_time.seconds >= INT64_MIN + msg->seconds_since_start_time) {
            start_time.seconds -= msg->seconds_since_start_time;
        } else {
            start_time.seconds = INT64_MIN;
        }
    } else {
        if (start_time.seconds <= INT64_MAX + msg->seconds_since_start_time) {
            start_time.seconds -= msg->seconds_since_start_time;
        } else {
            start_time.seconds = INT64_MAX;
        }
    }
    ps->prs.height     = msg->height;                            /* :1389 */
    ps->prs.round      = msg->round;                             /* :1390 */
    ps->prs.step       = msg->step;                              /* :1391 */
    ps->prs.start_time = start_time;                             /* :1392 */
    if (ps_height != msg->height || ps_round != msg->round) {    /* :1393 */
        ps->prs.proposal = false;                                /* :1394 */
        memset(&ps->prs.proposal_block_part_set_header, 0,
               sizeof(ps->prs.proposal_block_part_set_header)); /* :1395 */
        ps->prs.proposal_block_parts = NULL;                     /* :1396 */
        ps->prs.proposal_pol_round   = -1;                       /* :1397 */
        ps->prs.proposal_pol         = NULL;                     /* :1398 */
        /* :1399 "We'll update the BitArray capacity later." */
        ps->prs.prevotes   = NULL;                               /* :1400 */
        ps->prs.precommits = NULL;                               /* :1401 */
    }
    if (ps_height == msg->height && ps_round != msg->round &&
        msg->round == ps_catchup_commit_round) {                 /* :1403 */
        /* :1404-1407 — peer caught up to CatchupCommitRound; preserve
         * psCatchupCommit. */
        ps->prs.precommits = ps_catchup_commit;                  /* :1408 */
    }
    if (ps_height != msg->height) {                              /* :1410 */
        /* :1411 — shift Precommits to LastCommit. */
        if (ps_height + 1 == msg->height &&
            ps_round == msg->last_commit_round) {                /* :1412 */
            ps->prs.last_commit_round = msg->last_commit_round;  /* :1413 */
            ps->prs.last_commit       = last_precommits;         /* :1414 */
        } else {
            ps->prs.last_commit_round = msg->last_commit_round;  /* :1416 */
            ps->prs.last_commit       = NULL;                    /* :1417 */
        }
        /* :1419 "We'll update the BitArray capacity later." */
        ps->prs.catchup_commit_round = -1;                       /* :1420 */
        ps->prs.catchup_commit       = NULL;                     /* :1421 */
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 consensus/reactor.go:1426-1440 — ApplyNewValidBlockMessage() */
int cmt_ps_apply_new_valid_block_message(cmt_ps_t *ps,
                                         const cmt_new_valid_block_msg_t *msg)
{
    if (ps == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.height != msg->height) {                         /* :1430 */
        return CMT_OK;
    }
    if (ps->prs.round != msg->round && !msg->is_commit) {        /* :1434 */
        return CMT_OK;
    }
    ps->prs.proposal_block_part_set_header =
            msg->block_part_set_header;                          /* :1438 */
    ps->prs.proposal_block_parts = NULL;
    return ps_bits_copy_in(ps, msg->has_block_parts, &msg->block_parts,
                           &ps->prs.proposal_block_parts);       /* :1439 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1443-1457 — ApplyProposalPOLMessage() */
int cmt_ps_apply_proposal_pol_message(cmt_ps_t *ps,
                                      const cmt_proposal_pol_msg_t *msg)
{
    if (ps == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.height != msg->height) {                         /* :1447 */
        return CMT_OK;
    }
    if (ps->prs.proposal_pol_round != msg->proposal_pol_round) { /* :1450 */
        return CMT_OK;
    }
    /* :1454-1456 — the reference's TODO says merge; it replaces. */
    ps->prs.proposal_pol = NULL;
    return ps_bits_copy_in(ps, msg->has_proposal_pol, &msg->proposal_pol,
                           &ps->prs.proposal_pol);               /* :1456 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1460-1469 — ApplyHasVoteMessage() */
int cmt_ps_apply_has_vote_message(cmt_ps_t *ps, const cmt_has_vote_msg_t *msg)
{
    if (ps == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    if (ps->prs.height != msg->height) {                         /* :1464 */
        return CMT_OK;
    }
    return ps_set_has_vote_fields(ps, msg->height, msg->round, msg->type,
                                  msg->index);                   /* :1468 */
}

/* cometbft@v0.38.26 consensus/reactor.go:1476-1490 — ApplyVoteSetBitsMessage() */
int cmt_ps_apply_vote_set_bits_message(cmt_ps_t *ps,
                                       const cmt_vote_set_bits_msg_t *msg,
                                       const cmt_bit_array_t *our_votes)
{
    cmt_bit_array_t        other_votes;
    cmt_bit_array_t        has_votes;
    cmt_bit_array_t       *votes;
    const cmt_bit_array_t *msg_votes;
    int                    rc;

    if (ps == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    votes = ps_get_vote_bit_array(ps, msg->height, msg->round, msg->type); /* :1480 */
    if (votes == NULL) {                                         /* :1481 */
        return CMT_OK;
    }
    msg_votes = msg->has_votes ? &msg->votes : NULL;             /* nil ptr */
    if (our_votes == NULL) {                                     /* :1482 */
        return cmt_bits_update(votes, msg_votes);                /* :1483 */
    }
    /* :1485-1487 — votes.Sub(ourVotes).Or(msg.Votes), then Update. */
    rc = cmt_bits_sub(votes, our_votes, &other_votes);
    if (rc == CMT_BITS_NIL) {
        /* votes is non-NULL here, so Sub is nil only through the NULL
         * `o` branch, which cmt_bits_sub also folds to nil (:204-207);
         * nil.Or(x) is a copy of x (:139-141). */
        rc = cmt_bits_or(NULL, msg_votes, &has_votes);
    } else if (rc == CMT_OK) {
        rc = cmt_bits_or(&other_votes, msg_votes, &has_votes);
    }
    if (rc == CMT_BITS_NIL) {
        return cmt_bits_update(votes, NULL);                     /* no-op */
    }
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_bits_update(votes, &has_votes);                   /* :1487 */
}
