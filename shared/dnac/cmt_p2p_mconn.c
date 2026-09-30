/**
 * @file shared/dnac/cmt_p2p_mconn.c
 * @brief cometbft @v0.38.26 `p2p/conn/connection.go` in C (+ the Packet
 *        codec of proto/tendermint/p2p/conn.pb.go and
 *        libs/timer/throttle_timer.go inline).
 *
 * Functions in the reference's order; each names its Go lines. Contract,
 * the goroutine → tick mapping, deviations R-P2P-15..21 and the kept
 * reference quirks are in cmt_p2p_mconn.h.
 *
 * NOTE cmt_pb_wire.h: its header says only `shared/dnac/cmt_pb*.c`
 * includes it (cmt_pb_wire.h:7-8). The Packet codec below needs exactly
 * its helpers (backward writer, r_tag, pb_skip, r_ld — the generated
 * encoder / decoder rules); copying them is what that header exists to
 * prevent (:14-23), so this file includes it. Reported to the
 * ORCHESTRATOR for the header's scope sentence.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_mconn.h"
#include "dnac/cmt_p2p_protoio.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_wire.h"
#include "crypto/utils/qgp_log.h"

#include <float.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_P2P_MCONN"

/* ══ Packet codec — conn.pb.go ════════════════════════════════════════ */

/* conn.pb.go:604-621 `PacketMsg.Size`. `uint64(m.ChannelID)` widens the
 * int32 with its sign (:614), as w_uvarint below writes it. */
static size_t packet_msg_body_size(int32_t channel_id, bool eof,
                                   size_t data_len)
{
    size_t n = 0;

    if (channel_id != 0) {
        n += 1 + cmt_pb_uvarint_size((uint64_t)(int64_t)channel_id);
    }
    if (eof) {
        n += 2;
    }
    if (data_len > 0) {
        n += 1 + data_len + cmt_pb_uvarint_size((uint64_t)data_len);
    }
    return n;
}

/* conn.pb.go:659-670 `Packet_PacketMsg.Size` over :604-621. */
size_t cmt_p2p_packet_msg_size(int32_t channel_id, bool eof, size_t data_len)
{
    size_t l = packet_msg_body_size(channel_id, eof, data_len);

    return 1 + l + cmt_pb_uvarint_size((uint64_t)l);
}

/* conn.pb.go:440-534 Packet.MarshalToSizedBuffer + the oneof wrappers;
 * connection.go:925-954 mustWrapPacket. */
int cmt_p2p_packet_marshal(const cmt_p2p_packet_t *p, uint8_t *out, size_t cap,
                           size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (p == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    before = w.i;
    switch (p->kind) {
    case CMT_P2P_PACKET_PING:
        /* :477-491 — PacketPing has no fields (:364-370); the wrapper
         * writes `tag ‖ len 0` unconditionally. */
        wf_close_msg(&w, 1, before);
        break;
    case CMT_P2P_PACKET_PONG:
        wf_close_msg(&w, 2, before);                          /* :498-512 */
        break;
    case CMT_P2P_PACKET_MSG:
        /* :410-437 PacketMsg, backward: data (3), eof (2), channel_id (1),
         * each omit-zero. */
        wf_bytes(&w, 3, p->data, p->data_len);                /* :416-422 */
        if (p->eof) {
            wf_varint(&w, 2, 1);                              /* :423-431 */
        }
        wf_varint(&w, 1, (uint64_t)(int64_t)p->channel_id);   /* :432-436 */
        wf_close_msg(&w, 3, before);                          /* :519-534 */
        break;
    case CMT_P2P_PACKET_NONE:
    default:
        return CMT_FAULT;                                      /* :949-951 */
    }
    return w_finish(&w, out_len);
}

/* conn.pb.go:692-741 / :742-791 — PacketPing / PacketPong.Unmarshal: no
 * known field, every field skipped. */
static int packet_empty_unmarshal(const uint8_t *in, size_t len)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {    /* :698-718 */
            return CMT_REJECT;
        }
        i = start;                                             /* :721-733 */
        if (pb_skip(in, len, &i) != CMT_OK) {
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* conn.pb.go:792-913 — PacketMsg.Unmarshal into a FRESH PacketMsg
 * (:1027 `v := &PacketMsg{}`). */
static int packet_msg_unmarshal(const uint8_t *in, size_t len,
                                cmt_p2p_packet_t *m)
{
    size_t i = 0;

    m->channel_id = 0;
    m->eof = false;
    m->data = NULL;
    m->data_len = 0;
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {    /* :798-818 */
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:                                                /* :820-835 */
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            /* `m.ChannelID |= int32(b&0x7F) << shift` keeps the low 32
             * bits of the varint (header "quirks"). */
            m->channel_id = (int32_t)(uint32_t)(v & 0xFFFFFFFFu);
            break;
        case 2:                                                /* :836-855 */
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->eof = (v != 0);
            break;
        case 3: {                                              /* :856-889 */
            const uint8_t *p;
            size_t n;

            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            m->data = p;                /* :882 append(m.Data[:0], ...) */
            m->data_len = n;
            break;
        }
        default:                                               /* :890-902 */
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* conn.pb.go:915-1068 — Packet.Unmarshal. */
int cmt_p2p_packet_unmarshal(const uint8_t *in, size_t len,
                             cmt_p2p_packet_t *out)
{
    size_t i = 0;

    if (out == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->kind = CMT_P2P_PACKET_NONE;
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {    /* :921-941 */
            return CMT_REJECT;
        }
        if (fieldnum >= 1 && fieldnum <= 3) {
            const uint8_t *p;
            size_t n;

            if (wt != 2u) {                                    /* :944, :979, :1014 */
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {         /* msglen, postIndex */
                return CMT_REJECT;
            }
            if (fieldnum == 3) {
                cmt_p2p_packet_t m;

                if (packet_msg_unmarshal(p, n, &m) != CMT_OK) { /* :1027-1030 */
                    return CMT_REJECT;
                }
                out->channel_id = m.channel_id;
                out->eof = m.eof;
                out->data = m.data;
                out->data_len = m.data_len;
                out->kind = CMT_P2P_PACKET_MSG;                /* :1031 */
            } else {
                if (packet_empty_unmarshal(p, n) != CMT_OK) {  /* :957-960, :992-995 */
                    return CMT_REJECT;
                }
                out->kind = (fieldnum == 1) ? CMT_P2P_PACKET_PING  /* :961 */
                                            : CMT_P2P_PACKET_PONG; /* :996 */
            }
        } else {                                               /* :1033-1045 */
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* ══ libs/timer/throttle_timer.go, inline ═════════════════════════════ */

/* throttle_timer.go:26-35 NewThrottleTimer — created stopped. */
static void throttle_init(cmt_p2p_mconn_throttle_t *t, int64_t dur)
{
    t->running = true;
    t->is_set = false;
    t->deadline = 0;
    t->dur = dur;
}

/* throttle_timer.go:50-57 Set — arms only when not already set. A Set on
 * a stopped timer can never be delivered (:43-44), so it is a no-op. */
static void throttle_set(cmt_p2p_mconn_throttle_t *t, int64_t now)
{
    if (!t->running) {
        return;
    }
    if (!t->is_set) {
        t->is_set = true;
        t->deadline = now + t->dur;
    }
}

/* The fire is due (throttle_timer.go:37 fireRoutine runs at deadline). */
static bool throttle_due(const cmt_p2p_mconn_throttle_t *t, int64_t now)
{
    return t->running && t->is_set && now >= t->deadline;
}

/* throttle_timer.go:45-46 — the routine was not in its select when the
 * timer fired: `default: t.timer.Reset(t.dur)`. */
static void throttle_missed(cmt_p2p_mconn_throttle_t *t, int64_t now)
{
    if (throttle_due(t, now)) {
        t->deadline = now + t->dur;
    }
}

/* ══ connection.go ════════════════════════════════════════════════════ */

static int64_t mc_now(const cmt_p2p_mconn_t *mc)
{
    return mc->host.now_ns(mc->host.ctx);
}

/* connection.go:146-155 DefaultMConnConfig. */
void cmt_p2p_mconn_default_config(cmt_p2p_mconn_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cfg->send_rate = CMT_P2P_MCONN_DEFAULT_SEND_RATE;
    cfg->recv_rate = CMT_P2P_MCONN_DEFAULT_RECV_RATE;
    cfg->max_packet_msg_payload_size = CMT_P2P_MCONN_DEFAULT_MAX_PACKET_MSG_PAYLOAD_SIZE;
    cfg->flush_throttle_ns = CMT_P2P_MCONN_DEFAULT_FLUSH_THROTTLE_NS;
    cfg->ping_interval_ns = CMT_P2P_MCONN_DEFAULT_PING_INTERVAL_NS;
    cfg->pong_timeout_ns = CMT_P2P_MCONN_DEFAULT_PONG_TIMEOUT_NS;
}

/* p2p/switch.go:37-46 MConnConfig(DefaultP2PConfig()) — config.go:633-636. */
void cmt_p2p_mconn_p2p_default_config(cmt_p2p_mconn_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cmt_p2p_mconn_default_config(cfg);                          /* :37 */
    cfg->flush_throttle_ns = CMT_P2P_CONFIG_DEFAULT_FLUSH_THROTTLE_NS; /* :38 */
    cfg->send_rate = CMT_P2P_CONFIG_DEFAULT_SEND_RATE;         /* :39 */
    cfg->recv_rate = CMT_P2P_CONFIG_DEFAULT_RECV_RATE;         /* :40 */
    cfg->max_packet_msg_payload_size =
        CMT_P2P_CONFIG_DEFAULT_MAX_PACKET_MSG_PAYLOAD_SIZE;    /* :41 */
}

/* connection.go:762-774 FillDefaults. */
cmt_p2p_ch_desc_t cmt_p2p_ch_desc_fill_defaults(cmt_p2p_ch_desc_t d)
{
    if (d.send_queue_capacity == 0) {
        d.send_queue_capacity = CMT_P2P_MCONN_DEFAULT_SEND_QUEUE_CAPACITY;
    }
    if (d.recv_buffer_capacity == 0) {
        d.recv_buffer_capacity = CMT_P2P_MCONN_DEFAULT_RECV_BUFFER_CAPACITY;
    }
    if (d.recv_message_capacity == 0) {
        d.recv_message_capacity = CMT_P2P_MCONN_DEFAULT_RECV_MESSAGE_CAPACITY;
    }
    return d;
}

/* connection.go:203-204 — `channelsIdx[id] = channel` in descriptor
 * order: the LAST descriptor with an id owns it. */
static cmt_p2p_mconn_channel_t *mc_channel(const cmt_p2p_mconn_t *mc,
                                           uint8_t id)
{
    int i;

    for (i = mc->n_channels - 1; i >= 0; i--) {
        if (mc->channels[i].desc.id == id) {
            return &mc->channels[i];
        }
    }
    return NULL;
}

/* connection.go:792-804 newChannel. */
static int channel_init(cmt_p2p_mconn_channel_t *ch, cmt_p2p_ch_desc_t desc,
                        int max_payload)
{
    desc = cmt_p2p_ch_desc_fill_defaults(desc);                /* :793 */
    if (desc.priority <= 0) {                                  /* :794-796 */
        QGP_LOG_ERROR(LOG_TAG, "Channel default priority must be a positive integer");
        return CMT_FAULT;
    }
    /* make(chan []byte, <0) / make([]byte, 0, <0) panic (:800-801). */
    if (desc.send_queue_capacity < 0 || desc.recv_buffer_capacity < 0) {
        return CMT_FAULT;
    }
    memset(ch, 0, sizeof(*ch));
    ch->desc = desc;
    ch->send_queue = (cmt_p2p_mconn_qmsg_t *)calloc(
        (size_t)desc.send_queue_capacity, sizeof(*ch->send_queue));
    ch->recving_cap = (size_t)desc.recv_buffer_capacity;
    ch->recving = (uint8_t *)malloc(ch->recving_cap > 0 ? ch->recving_cap : 1);
    ch->max_packet_msg_payload_size = max_payload;             /* :802 */
    if (ch->send_queue == NULL || ch->recving == NULL) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

static void channel_free(cmt_p2p_mconn_channel_t *ch)
{
    int k;

    if (ch->send_queue != NULL) {
        for (k = 0; k < ch->sq_len; k++) {
            int slot = (ch->sq_head + k) % ch->desc.send_queue_capacity;

            free(ch->send_queue[slot].bytes);
        }
        free(ch->send_queue);
    }
    free(ch->sending);
    free(ch->recving);
    memset(ch, 0, sizeof(*ch));
}

/* connection.go:157-216 NewMConnection / NewMConnectionWithConfig. */
int cmt_p2p_mconn_init(cmt_p2p_mconn_t *mc, const cmt_p2p_mconn_host_t *host,
                       const cmt_p2p_ch_desc_t *descs, int n_descs,
                       const cmt_p2p_mconn_config_t *cfg)
{
    cmt_p2p_mconn_config_t config;
    size_t max_pkt;
    size_t wire_max;
    int64_t now;
    int i;

    if (mc == NULL || host == NULL || host->now_ns == NULL ||
        host->on_receive == NULL || n_descs < 0 ||
        (descs == NULL && n_descs != 0)) {
        return CMT_FAULT;
    }
    if (cfg != NULL) {
        config = *cfg;
    } else {
        cmt_p2p_mconn_default_config(&config);                 /* :164-169 */
    }
    if (config.pong_timeout_ns >= config.ping_interval_ns) {   /* :180-182 */
        QGP_LOG_ERROR(LOG_TAG, "pongTimeout must be less than pingInterval");
        return CMT_FAULT;
    }
    /* time.NewTicker panics on a non-positive interval (:231); a payload
     * < 1 is R-P2P-21. */
    if (config.ping_interval_ns <= 0 || config.max_packet_msg_payload_size < 1) {
        return CMT_FAULT;
    }

    memset(mc, 0, sizeof(*mc));
    mc->host = *host;
    mc->config = config;
    now = mc_now(mc);

    cmt_flowrate_init(&mc->send_monitor, 0, 0, now);           /* :188 */
    cmt_flowrate_init(&mc->recv_monitor, 0, 0, now);           /* :189 */
    mc->created = now;                                          /* :195 */

    /* :212-213 maxPacketMsgSize() — computed once. */
    max_pkt = cmt_p2p_packet_msg_size(0x01, true,
                                      (size_t)config.max_packet_msg_payload_size);
    if (max_pkt > (size_t)INT_MAX) {
        return CMT_FAULT;
    }
    mc->max_packet_msg_size = (int)max_pkt;

    /* R-P2P-17 staging buffer: 65536 staged + one case's writes (a batch of
     * NUM_BATCH packets on the widest channel id, each uvarint-delimited). */
    wire_max = cmt_p2p_packet_msg_size(0xFF, true,
                                       (size_t)config.max_packet_msg_payload_size);
    wire_max += cmt_pb_uvarint_size((uint64_t)wire_max);
    if (wire_max > (SIZE_MAX - CMT_P2P_MCONN_MIN_WRITE_BUFFER_SIZE) /
                   CMT_P2P_MCONN_NUM_BATCH_PACKET_MSGS) {
        return CMT_FAULT;
    }
    mc->wbuf_cap = CMT_P2P_MCONN_MIN_WRITE_BUFFER_SIZE +
                   CMT_P2P_MCONN_NUM_BATCH_PACKET_MSGS * wire_max;
    mc->rbuf_cap = max_pkt + CMT_P2P_PROTOIO_MAX_VARINT_LEN;
    mc->wbuf = (uint8_t *)malloc(mc->wbuf_cap);
    mc->rbuf = (uint8_t *)malloc(mc->rbuf_cap);
    /* :199-200 — any number of descriptors, zero included (calloc(0) may
     * return NULL, so at least one slot is allocated). */
    mc->channels = (cmt_p2p_mconn_channel_t *)calloc(
        (size_t)(n_descs > 0 ? n_descs : 1), sizeof(*mc->channels));
    if (mc->wbuf == NULL || mc->rbuf == NULL || mc->channels == NULL) {
        cmt_p2p_mconn_free(mc);
        return CMT_FAULT;
    }
    for (i = 0; i < n_descs; i++) {                            /* :202-206 */
        mc->n_channels = i + 1;
        if (channel_init(&mc->channels[i], descs[i],
                         config.max_packet_msg_payload_size) != CMT_OK) {
            cmt_p2p_mconn_free(mc);
            return CMT_FAULT;
        }
    }
    return CMT_OK;
}

void cmt_p2p_mconn_free(cmt_p2p_mconn_t *mc)
{
    int i;

    if (mc == NULL) {
        return;
    }
    if (mc->channels != NULL) {
        for (i = 0; i < mc->n_channels; i++) {
            channel_free(&mc->channels[i]);
        }
        free(mc->channels);
    }
    free(mc->wbuf);
    free(mc->rbuf);
    mc->channels = NULL;
    mc->n_channels = 0;
    mc->wbuf = NULL;
    mc->rbuf = NULL;
    mc->w_len = 0;
    mc->w_flushed = 0;
    mc->rbuf_len = 0;
}

bool cmt_p2p_mconn_is_running(const cmt_p2p_mconn_t *mc)
{
    return mc != NULL && mc->started && !mc->stopped;
}

/* connection.go:226-240 OnStart. */
int cmt_p2p_mconn_start(cmt_p2p_mconn_t *mc)
{
    int64_t now;

    if (mc == NULL || mc->channels == NULL) {
        return CMT_FAULT;
    }
    if (mc->started || mc->stopped) {       /* service.go Start */
        return CMT_REJECT;
    }
    mc->started = true;
    now = mc_now(mc);
    throttle_init(&mc->flush_timer, mc->config.flush_throttle_ns); /* :230 */
    mc->ping_next = now + mc->config.ping_interval_ns;          /* :231 */
    mc->pong_timeout_has = false;                               /* :232 */
    mc->stats_next = now + CMT_P2P_MCONN_UPDATE_STATS_NS;       /* :233 */
    return CMT_OK;
}

/* connection.go:245-272 stopServices. Returns true when already stopped. */
static bool mc_stop_services(cmt_p2p_mconn_t *mc)
{
    if (mc->quit) {                                             /* :249-261 */
        return true;
    }
    mc->flush_timer.running = false;                            /* :264 */
    mc->ping_ready = false;                                     /* :265 */
    mc->stats_ready = false;                                    /* :266 */
    mc->quit = true;                                            /* :269-270 */
    return false;
}

/* connection.go:697-702 stopPongTimer. */
static void mc_stop_pong_timer(cmt_p2p_mconn_t *mc)
{
    mc->pong_timer_armed = false;
}

/* conn.Close() (:302, :318): nothing more is read or written. OnStop's
 * close (`keep_out` false) also drops the bytes the caller has not
 * written yet — the reference's conn is gone. FlushStop's close
 * (`keep_out` true) comes after its flush wrote everything (:297-302),
 * so what `out` holds is still the caller's to write. */
static void mc_close(cmt_p2p_mconn_t *mc, bool keep_out)
{
    mc->closed = true;
    if (!keep_out) {
        mc->w_len = 0;
        mc->w_flushed = 0;
    }
}

/* connection.go:313-324 OnStop, via service.go BaseService.Stop. */
void cmt_p2p_mconn_stop(cmt_p2p_mconn_t *mc)
{
    if (mc == NULL || !mc->started || mc->stopped) {
        return;                     /* ErrNotStarted / ErrAlreadyStopped */
    }
    mc->stopped = true;
    if (mc_stop_services(mc)) {                                 /* :314-316 */
        return;
    }
    mc_close(mc, false);                                        /* :318 */
}

/* connection.go:278-310 FlushStop — its blocking part (:284-298) is run
 * by cmt_p2p_mconn_tick (mc_flush_stop_step). */
void cmt_p2p_mconn_flush_stop(cmt_p2p_mconn_t *mc)
{
    if (mc == NULL || !mc->started) {
        return;
    }
    if (mc_stop_services(mc)) {                                 /* :279-281 */
        return;
    }
    mc->flush_stopping = true;
}

bool cmt_p2p_mconn_flush_stop_done(const cmt_p2p_mconn_t *mc)
{
    return mc != NULL && mc->flush_stop_done;
}

/* connection.go:346-355 stopForError. */
static void mc_stop_for_error(cmt_p2p_mconn_t *mc, int reason)
{
    cmt_p2p_mconn_stop(mc);                                     /* :347-349 */
    if (!mc->errored) {                                         /* :350 */
        mc->errored = true;
        if (mc->host.on_error != NULL) {
            mc->host.on_error(mc->host.ctx, reason);            /* :351-353 */
        }
    }
}

/* ══ Channel (connection.go:810-919) ══════════════════════════════════ */

/* connection.go:813-821 sendBytes / :826-834 trySendBytes — the same
 * here (R-P2P-19); the queue holds a copy (R-P2P-20). */
static bool channel_try_send_bytes(cmt_p2p_mconn_channel_t *ch,
                                   const uint8_t *bytes, size_t len)
{
    uint8_t *copy;
    int slot;

    if (ch->sq_len >= ch->desc.send_queue_capacity) {
        return false;                                           /* :831-832 */
    }
    copy = (uint8_t *)malloc(len > 0 ? len : 1);
    if (copy == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "send queue copy of %zu bytes: out of memory", len);
        return false;
    }
    if (len > 0) {
        memcpy(copy, bytes, len);
    }
    slot = (ch->sq_head + ch->sq_len) % ch->desc.send_queue_capacity;
    ch->send_queue[slot].bytes = copy;
    ch->send_queue[slot].len = len;
    ch->sq_len++;
    ch->send_queue_size++;                                      /* :829 */
    return true;
}

/* connection.go:843-845 canSend — against the CONSTANT capacity. */
static bool channel_can_send(const cmt_p2p_mconn_channel_t *ch)
{
    return ch->send_queue_size < CMT_P2P_MCONN_DEFAULT_SEND_QUEUE_CAPACITY;
}

/* connection.go:850-858 isSendPending. `len(ch.sending) == 0` is "no byte
 * of `sending` left" — an empty message dequeued earlier and not sent is
 * overwritten here (header "quirks"). */
static bool channel_is_send_pending(cmt_p2p_mconn_channel_t *ch)
{
    if (ch->sending_off >= ch->sending_len) {                   /* :851 */
        cmt_p2p_mconn_qmsg_t m;

        if (ch->sq_len == 0) {                                  /* :852-854 */
            return false;
        }
        m = ch->send_queue[ch->sq_head];                        /* :855 */
        ch->send_queue[ch->sq_head].bytes = NULL;
        ch->send_queue[ch->sq_head].len = 0;
        ch->sq_head = (ch->sq_head + 1) % ch->desc.send_queue_capacity;
        ch->sq_len--;
        free(ch->sending);
        ch->sending = m.bytes;
        ch->sending_len = m.len;
        ch->sending_off = 0;
    }
    return true;
}

/* connection.go:862-876 nextPacketMsg. On EOF the caller frees `sending`
 * once the packet is written (the data points into it). */
static void channel_next_packet_msg(cmt_p2p_mconn_channel_t *ch,
                                    cmt_p2p_packet_t *p)
{
    size_t max_size = (size_t)ch->max_packet_msg_payload_size; /* :864 */
    size_t remaining = ch->sending_len - ch->sending_off;

    memset(p, 0, sizeof(*p));
    p->kind = CMT_P2P_PACKET_MSG;
    p->channel_id = (int32_t)ch->desc.id;                       /* :863 */
    p->data = (remaining > 0) ? ch->sending + ch->sending_off : NULL;
    if (remaining <= max_size) {                                /* :865 */
        p->data_len = remaining;                                /* :866 */
        p->eof = true;                                          /* :867 */
        ch->sending_off = ch->sending_len;                      /* :868 */
        ch->send_queue_size--;                                  /* :869 */
    } else {
        p->data_len = max_size;                                 /* :871 */
        p->eof = false;                                         /* :872 */
        ch->sending_off += max_size;                            /* :873 */
    }
}

/* connection.go:893-911 recvPacketMsg. `*msg_len` is set and `*complete`
 * true when the packet ends a message; the bytes are `ch->recving`. */
static int channel_recv_packet_msg(cmt_p2p_mconn_channel_t *ch,
                                   const cmt_p2p_packet_t *p,
                                   bool *complete, size_t *msg_len)
{
    int    recv_cap = ch->desc.recv_message_capacity;           /* :895 */
    size_t recv_received;

    *complete = false;
    if (p->data_len > SIZE_MAX - ch->recving_len) {
        return CMT_REJECT;
    }
    recv_received = ch->recving_len + p->data_len;
    if (recv_cap < 0 || (size_t)recv_cap < recv_received) {     /* :896-898 */
        QGP_LOG_DEBUG(LOG_TAG, "received message exceeds available capacity: %d < %zu",
                      recv_cap, recv_received);
        return CMT_REJECT;
    }
    if (recv_received > ch->recving_cap) {                      /* :899 append */
        size_t ncap = ch->recving_cap > 0 ? ch->recving_cap : 1;
        uint8_t *nb;

        while (ncap < recv_received) {
            ncap = (ncap > SIZE_MAX / 2) ? recv_received : ncap * 2;
        }
        nb = (uint8_t *)realloc(ch->recving, ncap);
        if (nb == NULL) {
            return CMT_FAULT;
        }
        ch->recving = nb;
        ch->recving_cap = ncap;
    }
    if (p->data_len > 0) {
        memcpy(ch->recving + ch->recving_len, p->data, p->data_len);
    }
    ch->recving_len = recv_received;
    if (p->eof) {                                               /* :900-908 */
        *msg_len = ch->recving_len;
        ch->recving_len = 0;                                    /* :907 */
        *complete = true;
    }
    return CMT_OK;
}

/* connection.go:915-919 updateStats (float64, then int64 truncation). */
void cmt_p2p_mconn_update_stats(cmt_p2p_mconn_t *mc)
{
    int i;

    if (mc == NULL) {
        return;
    }
    for (i = 0; i < mc->n_channels; i++) {
        mc->channels[i].recently_sent =
            (int64_t)((double)mc->channels[i].recently_sent * 0.8);
    }
}

/* ══ Send / TrySend / CanSend (connection.go:357-426) ═════════════════ */

static bool mc_queue(cmt_p2p_mconn_t *mc, uint8_t ch_id, const uint8_t *msg,
                     size_t len)
{
    cmt_p2p_mconn_channel_t *ch;

    if (!cmt_p2p_mconn_is_running(mc)) {                        /* :359-361 */
        return false;
    }
    if (msg == NULL && len != 0) {
        return false;
    }
    ch = mc_channel(mc, ch_id);                                 /* :366 */
    if (ch == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot send bytes, unknown channel %X", ch_id);
        return false;                                           /* :367-370 */
    }
    if (!channel_try_send_bytes(ch, msg, len)) {                /* :372 */
        return false;
    }
    mc->send_token = true;                                      /* :375-378 */
    return true;
}

bool cmt_p2p_mconn_send(cmt_p2p_mconn_t *mc, uint8_t ch_id,
                        const uint8_t *msg, size_t len)
{
    return mc_queue(mc, ch_id, msg, len);                       /* :358-383 */
}

bool cmt_p2p_mconn_try_send(cmt_p2p_mconn_t *mc, uint8_t ch_id,
                            const uint8_t *msg, size_t len)
{
    return mc_queue(mc, ch_id, msg, len);                       /* :387-411 */
}

bool cmt_p2p_mconn_can_send(const cmt_p2p_mconn_t *mc, uint8_t ch_id)
{
    const cmt_p2p_mconn_channel_t *ch;

    if (!cmt_p2p_mconn_is_running(mc)) {                        /* :416-418 */
        return false;
    }
    ch = mc_channel(mc, ch_id);
    if (ch == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "Unknown channel %X", ch_id);    /* :421-423 */
        return false;
    }
    return channel_can_send(ch);                                /* :425 */
}

/* ══ the write path: protoio writer + bufConnWriter (R-P2P-17) ════════ */

/* connection.go:330-336 flush — bufio.Writer.Flush: every staged byte
 * goes to `out`. */
static void mc_flush(cmt_p2p_mconn_t *mc)
{
    mc->w_flushed = mc->w_len;
}

/* protoio writer.go:54-68 WriteMsg — ONE bufio Write of uvarint(size) ‖
 * packet — and bufio.Writer.Write's accounting (Go src/bufio/bufio.go:
 * 676-698): what does not fit the 65536 staged bytes flushes the buffer
 * (or, into an empty buffer, goes out directly). Returns the bytes
 * written (the reference's n), or -1 on a capacity bug. */
static int mc_write_msg(cmt_p2p_mconn_t *mc, const cmt_p2p_packet_t *p)
{
    size_t start = mc->w_len;
    size_t off = start;
    size_t body = 0;
    size_t size;
    size_t total;
    size_t rem;
    size_t buffered;

    if (p->kind == CMT_P2P_PACKET_MSG) {
        size = cmt_p2p_packet_msg_size(p->channel_id, p->eof, p->data_len);
    } else {
        size = 2;                               /* `0a 00` / `12 00` */
    }
    total = cmt_pb_uvarint_size((uint64_t)size) + size;
    if (total > mc->wbuf_cap - mc->w_len || total > (size_t)INT_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "write buffer overrun (%zu + %zu > %zu)",
                      mc->w_len, total, mc->wbuf_cap);
        return -1;
    }
    if (cmt_pb_put_uvarint(mc->wbuf, mc->wbuf_cap, &off, (uint64_t)size) != CMT_OK ||
        cmt_p2p_packet_marshal(p, mc->wbuf + off, mc->wbuf_cap - off, &body) != CMT_OK ||
        body != size) {
        QGP_LOG_ERROR(LOG_TAG, "packet marshal failed");
        return -1;
    }

    /* bufio.go:677-697 */
    rem = total;
    buffered = start - mc->w_flushed;
    off = start;
    while (rem > CMT_P2P_MCONN_MIN_WRITE_BUFFER_SIZE - buffered) {
        if (buffered == 0) {                    /* :679-682 direct write */
            off += rem;
            rem = 0;
        } else {                                /* :683-687 fill + Flush */
            size_t take = CMT_P2P_MCONN_MIN_WRITE_BUFFER_SIZE - buffered;

            off += take;
            rem -= take;
            buffered = 0;
        }
        mc->w_flushed = off;
    }
    mc->w_len = start + total;                  /* :694-696 */
    return (int)total;
}

/* connection.go:880-888 writePacketMsgTo. */
static int channel_write_packet_msg_to(cmt_p2p_mconn_t *mc,
                                       cmt_p2p_mconn_channel_t *ch)
{
    cmt_p2p_packet_t p;
    int n;

    channel_next_packet_msg(ch, &p);                            /* :881 */
    n = mc_write_msg(mc, &p);                                   /* :882 */
    if (p.eof) {
        free(ch->sending);                                      /* :868 nil */
        ch->sending = NULL;
        ch->sending_len = 0;
        ch->sending_off = 0;
    }
    if (n < 0) {
        return -1;                                              /* :883-885 */
    }
    ch->recently_sent += (int64_t)n;                            /* :886 */
    return n;
}

/* connection.go:549-570 selectChannelToGossipOn. */
int cmt_p2p_mconn_select_channel(cmt_p2p_mconn_t *mc)
{
    float least_ratio = FLT_MAX;                                /* :552 */
    int   least = -1;
    int   i;

    if (mc == NULL) {
        return -1;
    }
    for (i = 0; i < mc->n_channels; i++) {                      /* :554 */
        cmt_p2p_mconn_channel_t *ch = &mc->channels[i];
        float ratio;

        if (!channel_is_send_pending(ch)) {                     /* :557-559 */
            continue;
        }
        ratio = (float)ch->recently_sent / (float)ch->desc.priority; /* :563 */
        if (ratio < least_ratio) {                              /* :564-567 */
            least_ratio = ratio;
            least = i;
        }
    }
    return least;
}

/* connection.go:522-543 sendBatchPacketMsgs (+ :573-584
 * sendPacketMsgOnChannel). Returns true when the channels ran dry. */
static bool mc_send_batch_packet_msgs(cmt_p2p_mconn_t *mc, int batch_size,
                                      int64_t now)
{
    int  total = 0;
    bool eof = false;
    int  i;

    for (i = 0; i < batch_size; i++) {                          /* :530 */
        int idx = cmt_p2p_mconn_select_channel(mc);             /* :531 */
        int n;

        if (idx < 0) {                                          /* :533-535 */
            eof = true;
            break;
        }
        n = channel_write_packet_msg_to(mc, &mc->channels[idx]); /* :575 */
        if (n < 0) {                                            /* :576-580 */
            QGP_LOG_ERROR(LOG_TAG, "Failed to write PacketMsg");
            mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_CONN);
            eof = true;
            break;
        }
        throttle_set(&mc->flush_timer, now);                    /* :582 */
        total += n;                                             /* :540 */
    }
    if (total > 0) {                                            /* :525-529 */
        cmt_flowrate_update(&mc->send_monitor, total, now);
    }
    return eof;
}

/* :515 — sendMonitor.Limit(_maxPacketMsgSize, SendRate, true). */
static bool mc_send_limit_passes(cmt_p2p_mconn_t *mc, int64_t now)
{
    bool wb = false;
    int64_t retry = 0;

    (void)cmt_flowrate_limit(&mc->send_monitor, mc->max_packet_msg_size,
                             mc->config.send_rate, true, now, &wb, &retry);
    if (wb) {
        mc->send_retry_at = retry;
        return false;
    }
    return true;
}

/* A ping / pong (:450, :473): write, Update(_n), then the case goes on. */
static int mc_write_control(cmt_p2p_mconn_t *mc, cmt_p2p_packet_kind_t kind,
                            int64_t now)
{
    cmt_p2p_packet_t p;
    int n;

    memset(&p, 0, sizeof(p));
    p.kind = kind;
    n = mc_write_msg(mc, &p);
    if (n < 0) {
        return -1;
    }
    cmt_flowrate_update(&mc->send_monitor, n, now);             /* :455, :478 */
    return 0;
}

/* The routine leaves FOR_LOOP (:481, :495, :500): cleanup :504-506. */
static void mc_send_routine_exit(cmt_p2p_mconn_t *mc)
{
    mc_stop_pong_timer(mc);                                     /* :505 */
    mc->send_routine_done = true;                               /* :506 */
}

/* :494-501 — after every case. Returns false when the routine ended. */
static bool mc_after_case(cmt_p2p_mconn_t *mc, int err)
{
    if (!cmt_p2p_mconn_is_running(mc)) {                        /* :494-496 */
        mc_send_routine_exit(mc);
        return false;
    }
    if (err != 0) {                                             /* :497-501 */
        QGP_LOG_ERROR(LOG_TAG, "Connection failed @ sendRoutine (reason %d)", err);
        mc_stop_for_error(mc, err);
        mc_send_routine_exit(mc);
        return false;
    }
    return true;
}

/* The timers that fire whatever the routine is doing: the two Tickers'
 * one-slot channels (:231, :233) and the pong AfterFunc (:457-462). */
static void mc_fire_timers(cmt_p2p_mconn_t *mc, int64_t now)
{
    if (!mc->quit) {
        if (now >= mc->ping_next) {
            int64_t p = mc->config.ping_interval_ns;

            mc->ping_ready = true;
            mc->ping_next += p * (1 + (now - mc->ping_next) / p);
        }
        if (now >= mc->stats_next) {
            int64_t p = CMT_P2P_MCONN_UPDATE_STATS_NS;

            mc->stats_ready = true;
            mc->stats_next += p * (1 + (now - mc->stats_next) / p);
        }
    }
    if (mc->pong_timer_armed && now >= mc->pong_deadline) {
        mc->pong_timer_armed = false;
        if (!mc->pong_timeout_has) {                            /* :458-461 */
            mc->pong_timeout_has = true;
            mc->pong_timeout_val = true;
        }
    }
}

/* connection.go:284-298 — FlushStop's send-everything-then-flush, one
 * step at a time. */
static void mc_flush_stop_step(cmt_p2p_mconn_t *mc, int64_t now)
{
    while (!mc->flush_stop_done) {
        bool eof;

        if (mc->w_flushed > 0) {                /* blocked in conn.Write */
            return;
        }
        if (!mc_send_limit_passes(mc, now)) {   /* :515 inside :293-296 */
            return;
        }
        eof = mc_send_batch_packet_msgs(mc, CMT_P2P_MCONN_NUM_BATCH_PACKET_MSGS,
                                        now);   /* :518 */
        if (eof) {
            mc_flush(mc);                                       /* :297 */
            mc->flush_stop_done = true;
            mc_close(mc, true);                                 /* :302 */
        }
    }
}

/* connection.go:429-507 sendRoutine — one pass (header). */
void cmt_p2p_mconn_tick(cmt_p2p_mconn_t *mc)
{
    int64_t now;

    if (mc == NULL || !mc->started || mc->closed) {
        return;
    }
    now = mc_now(mc);
    mc_fire_timers(mc, now);

    for (;;) {
        int err = 0;

        if (mc->w_flushed > 0) {
            /* blocked in conn.Write (R-P2P-17): a flush fire now finds
             * the routine outside its select. */
            throttle_missed(&mc->flush_timer, now);
            return;
        }
        if (mc->send_routine_done) {
            if (mc->flush_stopping) {
                mc_flush_stop_step(mc, now);
            }
            return;
        }

        if (mc->send_in_limit) {
            /* parked inside the send case (:515) */
            bool eof;

            if (!mc_send_limit_passes(mc, now)) {
                throttle_missed(&mc->flush_timer, now);
                return;
            }
            mc->send_in_limit = false;
            eof = mc_send_batch_packet_msgs(mc, CMT_P2P_MCONN_NUM_BATCH_PACKET_MSGS,
                                            now);               /* :518 */
            if (!eof) {
                mc->send_token = true;                          /* :485-491 */
            }
            (void)mc_after_case(mc, 0);
            continue;
        }

        /* ── the select (:439-492), R-P2P-18 order ── */
        if (mc->quit) {                                         /* :480-481 */
            mc_send_routine_exit(mc);
            continue;
        }
        if (mc->pong_timeout_has) {                             /* :464-470 */
            bool timeout = mc->pong_timeout_val;

            mc->pong_timeout_has = false;
            if (timeout) {
                QGP_LOG_DEBUG(LOG_TAG, "Pong timeout");
                err = CMT_P2P_MCONN_ERR_PONG_TIMEOUT;
            } else {
                mc_stop_pong_timer(mc);
            }
        } else if (mc->pong_token) {                            /* :471-479 */
            mc->pong_token = false;
            if (mc_write_control(mc, CMT_P2P_PACKET_PONG, now) != 0) {
                err = CMT_P2P_MCONN_ERR_CONN;
            } else {
                mc_flush(mc);
            }
        } else if (mc->ping_ready) {                            /* :448-463 */
            mc->ping_ready = false;
            if (mc_write_control(mc, CMT_P2P_PACKET_PING, now) != 0) {
                err = CMT_P2P_MCONN_ERR_CONN;
            } else {
                mc->pong_timer_armed = true;                    /* :457-462 */
                mc->pong_deadline = now + mc->config.pong_timeout_ns;
                mc_flush(mc);                                   /* :463 */
            }
        } else if (throttle_due(&mc->flush_timer, now)) {       /* :440-443 */
            mc->flush_timer.is_set = false;     /* throttle_timer.go:42 */
            mc_flush(mc);
        } else if (mc->stats_ready) {                           /* :444-447 */
            mc->stats_ready = false;
            cmt_p2p_mconn_update_stats(mc);
        } else if (mc->send_token) {                            /* :482-491 */
            bool eof;

            mc->send_token = false;
            if (!mc_send_limit_passes(mc, now)) {               /* :515 */
                mc->send_in_limit = true;
                return;
            }
            eof = mc_send_batch_packet_msgs(mc, CMT_P2P_MCONN_NUM_BATCH_PACKET_MSGS,
                                            now);
            if (!eof) {
                mc->send_token = true;
            }
        } else {
            return;                             /* nothing ready */
        }
        (void)mc_after_case(mc, err);
    }
}

const uint8_t *cmt_p2p_mconn_out(const cmt_p2p_mconn_t *mc, size_t *len)
{
    if (len != NULL) {
        *len = 0;
    }
    if (mc == NULL || len == NULL || mc->w_flushed == 0) {
        return NULL;
    }
    *len = mc->w_flushed;
    return mc->wbuf;
}

void cmt_p2p_mconn_out_consume(cmt_p2p_mconn_t *mc, size_t n)
{
    if (mc == NULL || n == 0) {
        return;
    }
    if (n > mc->w_flushed) {
        n = mc->w_flushed;
    }
    memmove(mc->wbuf, mc->wbuf + n, mc->w_len - n);
    mc->w_len -= n;
    mc->w_flushed -= n;
}

/* ══ recvRoutine (connection.go:590-694) ══════════════════════════════ */

/* The routine leaves FOR_LOOP. */
static int mc_recv_exit(cmt_p2p_mconn_t *mc)
{
    mc->recv_routine_done = true;
    mc->rbuf_len = 0;
    return CMT_REJECT;
}

/* :617-637 — ReadMsg returned an error. */
static int mc_recv_read_error(cmt_p2p_mconn_t *mc)
{
    if (mc->quit) {                                             /* :620-626 */
        return mc_recv_exit(mc);
    }
    if (cmt_p2p_mconn_is_running(mc)) {                         /* :628-635 */
        QGP_LOG_DEBUG(LOG_TAG, "Connection failed @ recvRoutine (reading byte)");
        mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_READ);
    }
    return mc_recv_exit(mc);
}

int cmt_p2p_mconn_recv(cmt_p2p_mconn_t *mc, const uint8_t *in, size_t len,
                       size_t *consumed)
{
    return cmt_p2p_mconn_recv_n(mc, in, len, consumed, SIZE_MAX, NULL);
}

int cmt_p2p_mconn_recv_n(cmt_p2p_mconn_t *mc, const uint8_t *in, size_t len,
                         size_t *consumed, size_t max_msgs, size_t *delivered)
{
    int64_t now;
    size_t  used = 0;
    size_t  n_msgs = 0;

    if (consumed != NULL) {
        *consumed = 0;
    }
    if (delivered != NULL) {
        *delivered = 0;
    }
    if (mc == NULL || consumed == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    if (max_msgs == 0) {
        return CMT_OK;                  /* nothing may be delivered: read nothing */
    }
    if (!mc->started || mc->closed || mc->recv_routine_done) {
        return CMT_REJECT;
    }
    now = mc_now(mc);

    for (;;) {                                                  /* :595 */
        cmt_p2p_packet_t pkt;
        size_t boff = 0, blen = 0, nread = 0;
        int rc;

        memset(&pkt, 0, sizeof(pkt));
        if (!mc->recv_limit_passed) {                           /* :598 */
            bool wb = false;

            (void)cmt_flowrate_limit(&mc->recv_monitor, mc->max_packet_msg_size,
                                     mc->config.recv_rate, true, now, &wb, NULL);
            if (wb) {
                *consumed = used;
                return CMT_OK;
            }
            mc->recv_limit_passed = true;
        }

        /* :617 protoReader.ReadMsg — gather exactly one delimited packet:
         * the prefix a byte at a time, then exactly the body. */
        for (;;) {
            size_t   poff = 0;
            uint64_t l = 0;
            size_t   want;
            size_t   take;

            rc = cmt_p2p_protoio_read_msg(mc->rbuf, mc->rbuf_len,
                                          (size_t)mc->max_packet_msg_size,
                                          &boff, &blen, &nread);
            if (rc != CMT_P2P_PROTOIO_MORE) {
                break;
            }
            if (used == len) {
                *consumed = used;
                return CMT_OK;                  /* the rest has not arrived */
            }
            if (cmt_p2p_protoio_read_uvarint(mc->rbuf, mc->rbuf_len, &poff, &l) ==
                CMT_OK) {
                want = poff + (size_t)l - mc->rbuf_len;
            } else {
                want = 1;
            }
            take = (want < len - used) ? want : (len - used);
            if (take > mc->rbuf_cap - mc->rbuf_len) {
                *consumed = used;
                return CMT_FAULT;               /* unreachable: read_msg bounds l */
            }
            memcpy(mc->rbuf + mc->rbuf_len, in + used, take);
            mc->rbuf_len += take;
            used += take;
        }
        *consumed = used;

        if (rc == CMT_OK &&
            cmt_p2p_packet_unmarshal(mc->rbuf + boff, blen, &pkt) != CMT_OK) {
            rc = CMT_REJECT;                    /* reader.go:94 proto.Unmarshal */
        }
        cmt_flowrate_update(&mc->recv_monitor, (int)nread, now); /* :618 */
        if (rc != CMT_OK) {                                     /* :619 */
            return mc_recv_read_error(mc);
        }
        mc->recv_limit_passed = false;

        switch (pkt.kind) {                                     /* :640 */
        case CMT_P2P_PACKET_PING:                               /* :641-649 */
            mc->pong_token = true;
            break;
        case CMT_P2P_PACKET_PONG:                               /* :650-656 */
            if (!mc->pong_timeout_has) {
                mc->pong_timeout_has = true;
                mc->pong_timeout_val = false;
            }
            break;
        case CMT_P2P_PACKET_MSG: {                              /* :657-679 */
            cmt_p2p_mconn_channel_t *ch = NULL;
            bool   complete = false;
            size_t mlen = 0;
            int    crc;

            if (pkt.channel_id >= 0 && pkt.channel_id <= 255) {
                ch = mc_channel(mc, (uint8_t)pkt.channel_id);   /* :658-659 */
            }
            if (ch == NULL) {                                   /* :660-665 */
                QGP_LOG_DEBUG(LOG_TAG, "unknown channel %X", (unsigned)pkt.channel_id);
                mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_UNKNOWN_CHANNEL);
                return mc_recv_exit(mc);
            }
            crc = channel_recv_packet_msg(ch, &pkt, &complete, &mlen); /* :667 */
            if (crc == CMT_FAULT) {
                QGP_LOG_ERROR(LOG_TAG, "receive buffer: out of memory");
                mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_CONN);
                mc_recv_exit(mc);
                return CMT_FAULT;
            }
            if (crc != CMT_OK) {                                /* :668-674 */
                if (cmt_p2p_mconn_is_running(mc)) {
                    mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_RECV_CAPACITY);
                }
                return mc_recv_exit(mc);
            }
            mc->rbuf_len = 0;
            if (complete) {                                     /* :675-679 */
                mc->host.on_receive(mc->host.ctx, ch->desc.id, ch->recving, mlen);
                n_msgs++;
                if (delivered != NULL) {
                    *delivered = n_msgs;
                }
            }
            break;
        }
        case CMT_P2P_PACKET_NONE:
        default:                                                /* :680-684 */
            QGP_LOG_ERROR(LOG_TAG, "Connection failed @ recvRoutine: unknown message type");
            mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_UNKNOWN_MSG);
            return mc_recv_exit(mc);
        }
        mc->rbuf_len = 0;

        /* A stop inside on_receive closed the conn: stop delivering.
         * R-P2P-22 — STRICTER than the reference: there the conn is wrapped
         * in bufio (:186) and bufio serves bytes it already buffered before
         * it touches the closed conn, so the reference can still hand a
         * buffered packet to onReceive after Stop; here nothing is
         * delivered once closed (:622-624's quiet exit). */
        if (mc->closed) {
            return mc_recv_exit(mc);
        }
        /* recv_n's bound (header): the caller re-asks its reactor's room
         * before the next message. `*consumed` already names every byte
         * up to and including the packet that completed this one. */
        if (n_msgs >= max_msgs) {
            return CMT_OK;
        }
    }
}

/* The recvRoutine's read-error path (:619-637): quiet when the services
 * were already stopped (:622-624), stopForError when still running. */
void cmt_p2p_mconn_conn_failed(cmt_p2p_mconn_t *mc)
{
    if (mc == NULL || !mc->started || mc->recv_routine_done) {
        return;
    }
    if (!mc->quit && cmt_p2p_mconn_is_running(mc)) {            /* :628-635 */
        QGP_LOG_INFO(LOG_TAG, "Connection is closed @ recvRoutine");
        mc_stop_for_error(mc, CMT_P2P_MCONN_ERR_CONN);
    }
    mc->recv_routine_done = true;
}

/* ══ Status (connection.go:732-749) ═══════════════════════════════════ */

void cmt_p2p_mconn_status(cmt_p2p_mconn_t *mc, cmt_p2p_mconn_status_t *out,
                          cmt_p2p_mconn_channel_status_t *channels_out,
                          int cap_channels)
{
    int64_t now;
    int i;

    if (mc == NULL || out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    now = mc_now(mc);
    out->duration_ns = now - mc->created;                       /* :734 */
    cmt_flowrate_status(&mc->send_monitor, now, &out->send_monitor); /* :735 */
    cmt_flowrate_status(&mc->recv_monitor, now, &out->recv_monitor); /* :736 */
    out->channels = channels_out;
    for (i = 0; i < mc->n_channels && channels_out != NULL && i < cap_channels; i++) {
        const cmt_p2p_mconn_channel_t *ch = &mc->channels[i];

        channels_out[i].id = ch->desc.id;                       /* :741 */
        channels_out[i].send_queue_capacity = ch->desc.send_queue_capacity;
        channels_out[i].send_queue_size = (int)ch->send_queue_size;
        channels_out[i].priority = ch->desc.priority;
        channels_out[i].recently_sent = ch->recently_sent;
        out->n_channels = i + 1;
    }
}
