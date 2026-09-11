/**
 * @file shared/dnac/cmt_wal.c
 * @brief cometbft @709fd12b's WAL record codec in C — see cmt_wal.h for
 *        the contract and the taşınmadı list.
 *
 * Every function carries the `// cometbft@709fd12b <file>:<from>-<to>`
 * line of the Go function it ports.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_wal.h"
#include "dnac/cmt_safemath.h"   /* SafeConvertUint8 — msgs.go:326 */

#include <stdlib.h>              /* the two codec temporaries are heap    */
#include <string.h>

/* cometbft@709fd12b consensus/msgs.go:240-295 — WALToProto() */
int cmt_wal_to_proto(const cmt_wal_message_t *msg, cmt_pb_wal_message_t *out)
{
    int rc;

    if (msg == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_wal_message_init(out);

    switch (msg->kind) {
    case CMT_PB_WAL_EVENT_DATA_ROUND_STATE: {        /* :244-253 */
        const cmt_event_data_round_state_t *m =
            &msg->u.event_data_round_state;

        if (m->step_len > (size_t)CMT_PB_ROUND_STEP_STR_MAX) {
            return CMT_REJECT;
        }
        out->sum = CMT_PB_WAL_EVENT_DATA_ROUND_STATE;
        cmt_pb_event_data_round_state_init(&out->u.event_data_round_state);
        out->u.event_data_round_state = *m;                  /* :248-250 */
        break;
    }
    case CMT_PB_WAL_MSG_INFO: {                      /* :254-270 */
        const cmt_msg_info_t *m = &msg->u.msg_info;

        if (m->peer_id_len != 0u &&
            m->peer_id_len != (size_t)CMT_PB_PEER_ID_MAX) {
            return CMT_REJECT;             /* the peer-id substitution */
        }
        out->sum = CMT_PB_WAL_MSG_INFO;
        cmt_pb_msg_info_init(&out->u.msg_info);
        /* :255-262 — MsgToProto, then the p2p `Wrap()` that puts the
         * result in the Message oneof (proto/tendermint/consensus/
         * message.go:21-74). cmt_msg_to_proto's output IS that oneof, so
         * the two steps are one and the `.(*cmtcons.Message)` type
         * assertion of :262 has no C counterpart to fail. */
        rc = cmt_msg_to_proto(&m->msg, &out->u.msg_info.msg);
        if (rc != CMT_OK) {
            return rc;                                       /* :256-258 */
        }
        memcpy(out->u.msg_info.peer_id, m->peer_id, m->peer_id_len);
        out->u.msg_info.peer_id_len = m->peer_id_len;        /* :267 */
        break;
    }
    case CMT_PB_WAL_TIMEOUT_INFO: {                  /* :271-281 */
        const cmt_timeout_info_t *m = &msg->u.timeout_info;
        cmt_pb_timeout_info_t    *pb = &out->u.timeout_info;

        out->sum = CMT_PB_WAL_TIMEOUT_INFO;
        cmt_pb_timeout_info_init(pb);
        pb->duration = m->duration;                          /* :275 */
        pb->height   = m->height;                            /* :276 */
        pb->round    = m->round;                             /* :277 */
        pb->step     = (uint32_t)m->step;                    /* :278 */
        break;
    }
    case CMT_PB_WAL_END_HEIGHT: {                    /* :282-289 */
        out->sum = CMT_PB_WAL_END_HEIGHT;
        cmt_pb_end_height_init(&out->u.end_height);
        out->u.end_height.height = msg->u.end_height.height; /* :286 */
        break;
    }
    default:
        /* :290-291 — "wal message not recognized", which is also where a
         * nil interface value lands. */
        return CMT_REJECT;
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/msgs.go:298-347 — WALFromProto() */
int cmt_wal_from_proto(const cmt_pb_wal_message_t *msg,
                       cmt_wal_message_t *out)
{
    int rc;

    /* A NULL C argument is a CALLER bug, and every one of those is FAULT
     * in this port. It is NOT the reference's :299-301, which is a decoded
     * record whose message field was absent — that case lives on the wire
     * and is refused in `cmt_timed_wal_message_decode`. */
    if (msg == NULL || out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));

    switch (msg->sum) {
    case CMT_PB_WAL_EVENT_DATA_ROUND_STATE: {        /* :305-310 */
        const cmt_pb_event_data_round_state_t *pb =
            &msg->u.event_data_round_state;

        if (pb->step_len > (size_t)CMT_PB_ROUND_STEP_STR_MAX) {
            return CMT_REJECT;
        }
        out->kind = CMT_PB_WAL_EVENT_DATA_ROUND_STATE;
        out->u.event_data_round_state = *pb;                 /* :307-309 */
        break;
    }
    case CMT_PB_WAL_MSG_INFO: {                      /* :311-323 */
        const cmt_pb_msg_info_t *pb = &msg->u.msg_info;

        out->kind = CMT_PB_WAL_MSG_INFO;
        /* :312-315 — `Unwrap()` (proto/tendermint/consensus/
         * message.go:78-109) refuses a Message whose Sum is unset; that is
         * `cmt_msg_from_proto`'s own NONE case (msgs.go:122-124), so the
         * two steps are one here. :316-319 is MsgFromProto. */
        rc = cmt_msg_from_proto(&pb->msg, &out->u.msg_info.msg);
        if (rc != CMT_OK) {
            return rc;
        }
        if (pb->peer_id_len != 0u &&
            pb->peer_id_len != (size_t)CMT_PB_PEER_ID_MAX) {
            return CMT_REJECT;             /* the peer-id substitution */
        }
        memcpy(out->u.msg_info.peer_id, pb->peer_id, pb->peer_id_len);
        out->u.msg_info.peer_id_len = pb->peer_id_len;       /* :322 */
        break;
    }
    case CMT_PB_WAL_TIMEOUT_INFO: {                  /* :325-337 */
        const cmt_pb_timeout_info_t *pb = &msg->u.timeout_info;
        cmt_timeout_info_t          *m = &out->u.timeout_info;
        uint8_t                      tis;

        /* :326-330 — SafeConvertUint8 denies the message on overflow. */
        rc = cmt_safe_convert_uint8((int64_t)pb->step, &tis);
        if (rc != CMT_OK) {
            return rc;
        }
        out->kind   = CMT_PB_WAL_TIMEOUT_INFO;
        m->duration = pb->duration;                          /* :332 */
        m->height   = pb->height;                            /* :333 */
        m->round    = pb->round;                             /* :334 */
        m->step     = tis;                                   /* :335 */
        break;                                               /* :337 */
    }
    case CMT_PB_WAL_END_HEIGHT: {                    /* :338-342 */
        out->kind = CMT_PB_WAL_END_HEIGHT;
        out->u.end_height.height = msg->u.end_height.height; /* :340 */
        break;
    }
    default:
        return CMT_REJECT;                 /* :343-344 not recognised */
    }
    return CMT_OK;
}

/* The message half of cometbft@709fd12b consensus/wal.go:301-314 —
 * WALEncoder.Encode, up to and including proto.Marshal. The crc32c and
 * length frame of :316-326 is the file container's; see cmt_wal.h. */
int cmt_timed_wal_message_encode(const cmt_timed_wal_message_t *v,
                                 uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_timed_wal_message_t *pv;
    int                         rc;

    if (v == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    /* HEAP, not a stack local: a TimedWALMessage holds a whole Message
     * union, whose widest branch is a BlockPart carrying a 64 KiB part and
     * a 100-aunt proof (cmt_pb.h:865-871, cmt_msgs.h:206-212). */
    pv = (cmt_pb_timed_wal_message_t *)malloc(sizeof(*pv));
    if (pv == NULL) {
        return CMT_FAULT;                    /* allocation failure = FAULT */
    }
    cmt_pb_timed_wal_message_init(pv);
    rc = cmt_wal_to_proto(&v->msg, &pv->msg);                /* :302 */
    if (rc != CMT_OK) {
        free(pv);
        return rc;                                           /* :303-305 */
    }
    pv->has_msg = true;                                      /* :308 */
    pv->time    = v->time;                                   /* :307 */
    /* :311-314 — proto.Marshal; the reference PANICS on a marshal error.
     * CMT_REJECT under the panic rule
     * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8 rev 4): a WAL record is
     * not always this node's own content — the msgInfo branch carries a
     * message that ARRIVED FROM A PEER, so an over-long field here is
     * peer-reachable and belongs at the message boundary. The other half
     * of the failure, a caller buffer too small, is node-local; it is
     * folded into the same REJECT rather than split, because the encoder
     * cannot tell the two apart and the caller retries with a full-size
     * buffer either way. */
    rc = cmt_pb_timed_wal_message_marshal(pv, out, cap, out_len);
    free(pv);
    return rc;
}

/* The message half of cometbft@709fd12b consensus/wal.go:404-419 —
 * WALDecoder.Decode, from proto.Unmarshal onward. */
int cmt_timed_wal_message_decode(const uint8_t *in, size_t len,
                                 cmt_timed_wal_message_t *out,
                                 cmt_pb_arena_t *arena)
{
    cmt_pb_timed_wal_message_t *res;
    int                         rc;

    if (out == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    /* HEAP, for the reason `cmt_timed_wal_message_encode` gives above. */
    res = (cmt_pb_timed_wal_message_t *)malloc(sizeof(*res));
    if (res == NULL) {
        return CMT_FAULT;                    /* allocation failure = FAULT */
    }
    rc = cmt_pb_timed_wal_message_unmarshal(in, len, res, arena);
    if (rc != CMT_OK) {
        free(res);
        return rc;                                           /* :405-408 */
    }
    /* :410-413 — WALFromProto(res.Msg). An ABSENT field 2 is Go's nil
     * pointer, which WALFromProto refuses at :299-301; here that is a
     * `sum` of NONE, and it is a stored row that cannot be replayed, so it
     * is CMT_REJECT and not FAULT — the host's digest check has already
     * proved the bytes are the ones this node wrote. */
    if (!res->has_msg) {
        free(res);
        return CMT_REJECT;
    }
    rc = cmt_wal_from_proto(&res->msg, &out->msg);
    if (rc != CMT_OK) {
        free(res);
        return rc;
    }
    out->time = res->time;                                   /* :415 */
    free(res);
    return CMT_OK;
}
