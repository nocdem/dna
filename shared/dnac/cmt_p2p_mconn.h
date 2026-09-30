/**
 * @file shared/dnac/cmt_p2p_mconn.h
 * @brief cometbft @v0.38.26 `p2p/conn/connection.go` ported to C — the
 *        MConnection: several prioritized channels multiplexed over one
 *        SecretConnection, with packet split / reassembly, ping / pong,
 *        a throttled flush and send / receive rate limits.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F2 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row 2, §9). Nothing in the running node constructs a `cmt_p2p_mconn_t`
 * yet — the peer (F3, cmt_p2p_peer) is its first consumer. Additive only;
 * 4001/4002 and today's 4004 path are untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHERE IT SITS ──────────────────────────────────────────────────────
 * The reference wraps a `net.Conn` — the SecretConnection (F1,
 * cmt_p2p_secret.h). Here nothing touches a socket or the secret
 * connection; the CALLER moves PLAINTEXT:
 *
 *   socket → cmt_p2p_sc_read → plaintext → `cmt_p2p_mconn_recv`
 *   `cmt_p2p_mconn_out` → plaintext → cmt_p2p_sc_write → socket
 *   `cmt_p2p_mconn_out_consume` once the caller has taken the bytes
 *
 * and calls `cmt_p2p_mconn_tick` on every pass of its event loop (after
 * `recv`, so a received ping is answered in the same pass).
 *
 * ── GOROUTINES → ONE EVENT LOOP (design §1) ────────────────────────────
 * `sendRoutine` (:429-507) is `cmt_p2p_mconn_tick`: it runs the
 * reference's `select` (:439-492) as a loop over the cases that are READY
 * at `now`, and stops where the goroutine would block:
 *   · in `conn.Write` — here: flushed bytes the caller has not taken yet
 *     (`out`); the routine resumes once `out` is drained (DEVIATION
 *     R-P2P-17, below);
 *   · in `sendMonitor.Limit(…, true)` (:515) — here: a retry instant; the
 *     routine is PARKED inside the send case and no other case runs until
 *     the Monitor lets it through, exactly as the blocked goroutine runs
 *     no other case (R-P2P-16, cmt_flowrate.h);
 *   · in the `select` with nothing ready — the tick returns.
 * `recvRoutine` (:590-694) is `cmt_p2p_mconn_recv`: it reads as many whole
 * packets out of the offered bytes as `recvMonitor.Limit` (:598) lets it,
 * and consumes NOTHING it cannot yet use — a Limit refusal, like the
 * blocked goroutine, leaves the bytes where they are (TCP backpressure).
 * Its bounded form `cmt_p2p_mconn_recv_n` also stops after N delivered
 * messages — the caller's "room for one" question before each, the
 * single-loop form of onReceive blocking (:676-678, red-team H3).
 * Channels of capacity 1 (`send` :190, `pong` :191, `pongTimeoutCh` :232)
 * are one-slot flags with the reference's non-blocking `select default`
 * (:375-378, :404-407, :645-649, :652-656, :458-461): three pings that
 * arrive before the next tick are answered with ONE pong, as in the
 * reference.
 *
 * Timers, on the host's MONOTONIC clock (`now_ns`, design §6 D3):
 *   · flushTimer — `libs/timer/throttle_timer.go` ported inline
 *     (`cmt_p2p_mconn_throttle_t`): `Set` arms only when unset (:50-57);
 *     the fire is delivered only to a routine that is in its select, else
 *     the timer re-arms for `dur` (:37-48);
 *   · pingTimer / chStatsTimer — `time.Ticker` (:231, :233): a one-slot
 *     channel; missed ticks are dropped and the next tick is the next
 *     multiple of the period after `now` (Go runtime ticker behaviour);
 *   · pongTimer — `time.AfterFunc` (:457-462).
 *
 * Select ORDER (DEVIATION R-P2P-18): Go picks uniformly at random among
 * the ready cases of a `select`; one loop needs an order. It is:
 *   quit, pongTimeoutCh, pong, ping, flush, stats, send.
 * Every order is one of the schedules the reference can take; this one
 * serves a pong timeout and the keep-alives before bulk data.
 *
 * ── DEVIATIONS (each a p2p-port design §5 row, numbered after F1's) ────
 *   R-P2P-15  flowrate reads the host's monotonic clock (cmt_flowrate.h).
 *   R-P2P-16  Limit(block) returns a retry instant (cmt_flowrate.h).
 *   R-P2P-17  conn.Write blocking → the `out` buffer: the reference's
 *             `bufConnWriter` (bufio, 65536 bytes, :187) is kept as the
 *             STAGING buffer (bytes appear in `out` only at `flush`, :330,
 *             or when a write overflows the 65536 bytes — bufio's own
 *             auto-flush, Go src/bufio/bufio.go:676-698); a flushed byte
 *             the caller has not taken yet parks the send routine.
 *   R-P2P-18  select order (above).
 *   R-P2P-19  `Send` does not block (:813-821 waits up to
 *             `defaultSendTimeout` = 10 s for queue room): `Send` ≡
 *             `TrySend` here — false at once on a full queue — the same
 *             rule the consensus port's host rows already state
 *             (cmt_ps.h:203-206, R3-A-1).
 *   R-P2P-20  the send queue holds a COPY of the message (the reference
 *             queues the caller's slice, :815); a full queue copies
 *             nothing.
 *   R-P2P-21  `NewMConnectionWithConfig`'s panics (:180-182, :794-796,
 *             and `make(chan, <0)`) are CMT_FAULT from init; so is a
 *             `max_packet_msg_payload_size` < 1 (the reference refuses
 *             only < 0, config.go:677-679, and at 0 `nextPacketMsg`
 *             (:862-876) would emit empty non-EOF packets forever).
 * NOT ported: `SetLogger` / `String` (:218-223, :326-328), `_recover`
 * (:339-344 — no panics in C), `TestFuzz` / `TestFuzzConfig` (:141-142,
 * test-only), `ChannelDescriptor.MessageType` (:759 — the switch's, F3).
 *
 * ── REFERENCE QUIRKS KEPT (each pinned by a test) ──────────────────────
 *   · `canSend` compares with the CONSTANT defaultSendQueueCapacity (1),
 *     not the channel's own capacity (:843-845).
 *   · `sendQueueSize` counts a message until its EOF packet is built
 *     (:816, :869), so a message being split still counts.
 *   · `isSendPending` (:850-858) dequeues into `sending` on EVERY channel
 *     it inspects, and tests "nothing being sent" as `len(sending) == 0` —
 *     an EMPTY message dequeued on a channel that is then not selected is
 *     overwritten by that channel's next message on the next inspection
 *     (never sent, and its `sendQueueSize` count is never returned).
 *   · `FlushStop` (:278-310) does not stop the BaseService: `IsRunning`
 *     stays true and `Send` keeps queueing into a connection that will not
 *     send again.
 *   · a PacketMsg's `channel_id` is decoded with the generated int32
 *     truncation (conn.pb.go:812-826) BEFORE the :660 range check, so an
 *     encoding whose low 32 bits name a known channel is ACCEPTED.
 *   · channel ids: a later descriptor with the same id replaces the
 *     earlier in the lookup map (:203-204) while both stay in the list.
 *   · `maxPacketMsgSize` (:705-715) is computed for channel 0x01; a full
 *     packet on a channel id >= 0x80 is one byte longer and exceeds it —
 *     the reference's own channels are all < 0x80.
 *
 * ── PACKETS (DEVIATION R-P2P-2, design) ────────────────────────────────
 * `tendermint.p2p.Packet` (proto/tendermint/p2p/conn.proto:9-25) encoded
 * with the tree's cmt_pb wire helpers (cmt_pb_wire.h) as conn.pb.go does:
 *   Packet   { oneof sum { PacketPing packet_ping = 1;
 *                          PacketPong packet_pong = 2;
 *                          PacketMsg  packet_msg  = 3; } }
 *   PacketMsg{ int32 channel_id = 1; bool eof = 2; bytes data = 3; }
 * The oneof member is ALWAYS written, even empty (`0a 00`, `12 00` —
 * conn.pb.go:477-491, :498-512); PacketMsg's fields are omit-zero
 * (:410-437), so a packet on channel 0x00 carries no field 1. Every
 * packet goes on the wire uvarint-delimited (protoio writer.go:54-68).
 *
 * ── ERRORS ─────────────────────────────────────────────────────────────
 * CMT_OK; CMT_REJECT = the connection is stopped (the peer broke the
 * protocol, or it was stopped before) — `on_error` has been called once
 * with the reason, as `stopForError` does (:346-355); CMT_FAULT = a NULL
 * argument, an inconsistent descriptor / config, or an allocation
 * failure.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (design §6 D1). Per connection, each
 * channel's messages reach `on_receive` whole, in the order they were
 * sent, never reordered; a malformed packet stops the connection, it is
 * never skipped (D2). The clock reads are the reference's p2p reads
 * (flush throttle, ping / pong, stats, flowrate — D3), taken through the
 * host's `now_ns`; no clock is read inside. The gossip selection uses
 * float32 (:552, :563) — transport-local, allowed.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_MCONN_H
#define CMT_P2P_MCONN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"                    /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "cmt_flowrate.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ connection.go:27-48 — constants ══════════════════════════════════ */

#define CMT_P2P_MCONN_NS_PER_MS  (1000LL * 1000)

#define CMT_P2P_MCONN_DEFAULT_MAX_PACKET_MSG_PAYLOAD_SIZE 1024       /* :28 */
#define CMT_P2P_MCONN_NUM_BATCH_PACKET_MSGS               10         /* :30 */
#define CMT_P2P_MCONN_MIN_WRITE_BUFFER_SIZE               65536      /* :32 */
#define CMT_P2P_MCONN_UPDATE_STATS_NS      (2000LL * CMT_P2P_MCONN_NS_PER_MS) /* :33 */
#define CMT_P2P_MCONN_DEFAULT_FLUSH_THROTTLE_NS (100LL * CMT_P2P_MCONN_NS_PER_MS) /* :38 */
#define CMT_P2P_MCONN_DEFAULT_SEND_QUEUE_CAPACITY         1          /* :40 */
#define CMT_P2P_MCONN_DEFAULT_RECV_BUFFER_CAPACITY        4096       /* :41 */
#define CMT_P2P_MCONN_DEFAULT_RECV_MESSAGE_CAPACITY       22020096   /* :42 */
#define CMT_P2P_MCONN_DEFAULT_SEND_RATE                   512000LL   /* :43 */
#define CMT_P2P_MCONN_DEFAULT_RECV_RATE                   512000LL   /* :44 */
#define CMT_P2P_MCONN_DEFAULT_PING_INTERVAL_NS (60000LL * CMT_P2P_MCONN_NS_PER_MS) /* :46 */
#define CMT_P2P_MCONN_DEFAULT_PONG_TIMEOUT_NS  (45000LL * CMT_P2P_MCONN_NS_PER_MS) /* :47 */

/** config/config.go:633-636 — DefaultP2PConfig's values that
 *  p2p/switch.go:37-46 `MConnConfig` writes over DefaultMConnConfig: the
 *  configuration a node actually runs with. */
#define CMT_P2P_CONFIG_DEFAULT_FLUSH_THROTTLE_NS (100LL * CMT_P2P_MCONN_NS_PER_MS)
#define CMT_P2P_CONFIG_DEFAULT_MAX_PACKET_MSG_PAYLOAD_SIZE 1024
#define CMT_P2P_CONFIG_DEFAULT_SEND_RATE          5120000LL
#define CMT_P2P_CONFIG_DEFAULT_RECV_RATE          5120000LL

/** `maxPacketMsgSize()` (:705-715) at the default payload size 1024:
 *  PacketMsg{channel_id 1, eof, data[1024]} = (1+1) + 2 + (1+2+1024) =
 *  1031 bytes (conn.pb.go:604-621), wrapped in Packet field 3 =
 *  1 + 2 + 1031 = 1034 (conn.pb.go:659-670). */
#define CMT_P2P_MCONN_DEFAULT_MAX_PACKET_MSG_SIZE 1034

/* ══ Packet (conn.proto:9-25) ═════════════════════════════════════════ */

typedef enum {
    CMT_P2P_PACKET_NONE = 0,   /* Sum == nil                         */
    CMT_P2P_PACKET_PING = 1,   /* packet_ping = 1                    */
    CMT_P2P_PACKET_PONG = 2,   /* packet_pong = 2                    */
    CMT_P2P_PACKET_MSG  = 3    /* packet_msg  = 3                    */
} cmt_p2p_packet_kind_t;

/** A decoded Packet. For MSG, `data` points INTO the buffer that was
 *  decoded and is valid only while that buffer is. */
typedef struct {
    cmt_p2p_packet_kind_t kind;
    int32_t        channel_id;   /* PacketMsg field 1 (int32) */
    bool           eof;          /* PacketMsg field 2         */
    const uint8_t *data;         /* PacketMsg field 3         */
    size_t         data_len;
} cmt_p2p_packet_t;

/** conn.pb.go:604-621 + :659-670 — the encoded size of
 *  Packet{PacketMsg{channel_id, eof, data[data_len]}} (without the
 *  delimiting uvarint). */
size_t cmt_p2p_packet_msg_size(int32_t channel_id, bool eof, size_t data_len);

/**
 * `proto.Marshal(mustWrapPacket(p))` — conn.pb.go:440-534 (Packet and its
 * oneof wrappers), :364-437 (the three bodies); connection.go:925-954
 * mustWrapPacket. Bare message bytes (no length prefix).
 * @return CMT_OK; CMT_REJECT if it does not fit `cap`; CMT_FAULT on NULL
 *         or an unknown kind.
 */
int cmt_p2p_packet_marshal(const cmt_p2p_packet_t *p, uint8_t *out, size_t cap,
                           size_t *out_len);

/**
 * conn.pb.go:915-1068 `Packet.Unmarshal` (+ :692-913 for the bodies): any
 * field order, unknown fields skipped (skipConn :1187-1265), the last
 * oneof member wins, a PacketMsg's scalars last-one-wins, its channel_id
 * the generated int32 truncation (:812-826). A Packet with no known member
 * decodes to kind NONE (the reference errors on it only later,
 * connection.go:680-684).
 * @return CMT_OK; CMT_REJECT (malformed); CMT_FAULT on NULL.
 */
int cmt_p2p_packet_unmarshal(const uint8_t *in, size_t len,
                             cmt_p2p_packet_t *out);

/* ══ connection.go:123-155 — MConnConfig ══════════════════════════════ */

typedef struct {
    int64_t send_rate;                   /* :125 bytes/s               */
    int64_t recv_rate;                   /* :126 bytes/s               */
    int     max_packet_msg_payload_size; /* :129                       */
    int64_t flush_throttle_ns;           /* :132                       */
    int64_t ping_interval_ns;            /* :135                       */
    int64_t pong_timeout_ns;             /* :138                       */
} cmt_p2p_mconn_config_t;

/** connection.go:146-155 `DefaultMConnConfig()` — 512000 B/s. */
void cmt_p2p_mconn_default_config(cmt_p2p_mconn_config_t *cfg);

/** p2p/switch.go:37-46 `MConnConfig(DefaultP2PConfig())` — the flush,
 *  rates and payload of config/config.go:633-636 (100 ms, 5 120 000 B/s,
 *  1024) over DefaultMConnConfig's ping 60 s / pong 45 s. THE default a
 *  node runs with. */
void cmt_p2p_mconn_p2p_default_config(cmt_p2p_mconn_config_t *cfg);

/* ══ connection.go:753-774 — ChannelDescriptor ════════════════════════ */

typedef struct {
    uint8_t id;                     /* :754 */
    int     priority;               /* :755 */
    int     send_queue_capacity;    /* :756 */
    int     recv_buffer_capacity;   /* :757 */
    int     recv_message_capacity;  /* :758 */
} cmt_p2p_ch_desc_t;

/** connection.go:762-774 `FillDefaults` — every capacity that is 0 takes
 *  its default (1, 4096, 22020096). */
cmt_p2p_ch_desc_t cmt_p2p_ch_desc_fill_defaults(cmt_p2p_ch_desc_t d);

/* ══ the host ═════════════════════════════════════════════════════════ */

/** The reason `on_error` is given — one per reference site. */
typedef enum {
    /** :466-468 — no pong within PongTimeout. */
    CMT_P2P_MCONN_ERR_PONG_TIMEOUT    = 1,
    /** :617-635 — protoio ReadMsg failed: varint overflow, out-of-range
     *  length, "message exceeds max size", or `proto.Unmarshal` refused
     *  the Packet. */
    CMT_P2P_MCONN_ERR_READ            = 2,
    /** :658-665 — a PacketMsg for a channel id outside 0..255 or not
     *  registered. */
    CMT_P2P_MCONN_ERR_UNKNOWN_CHANNEL = 3,
    /** :667-674 via :895-898 — the reassembled message would exceed the
     *  channel's RecvMessageCapacity. */
    CMT_P2P_MCONN_ERR_RECV_CAPACITY   = 4,
    /** :680-684 — a Packet with no known oneof member. */
    CMT_P2P_MCONN_ERR_UNKNOWN_MSG     = 5,
    /** :497-500 / :628-635 — the CONNECTION failed under the MConnection
     *  (socket EOF / error, secret connection refused a frame); reported
     *  by the caller through `cmt_p2p_mconn_conn_failed`. */
    CMT_P2P_MCONN_ERR_CONN            = 6
} cmt_p2p_mconn_err_t;

/**
 * The reference's constructor arguments `onReceive` / `onError`
 * (:50-53, :161-162) and the clock.
 *
 * Both callbacks MAY call `cmt_p2p_mconn_send` / `_try_send` / `_can_send`
 * / `_stop` on the same connection (a reactor's Receive sends; the
 * switch's StopPeerForError stops); neither may FREE it.
 */
typedef struct {
    void *ctx;
    /** A MONOTONIC clock in nanoseconds (design §6 D3). NOT the consensus
     *  host's `cmt_now_fn` (cmt_time.h:125, canonical UTC): the peer layer
     *  (F3) carries both. */
    int64_t (*now_ns)(void *ctx);
    /** :678 `onReceive(chID, msgBytes)` — `msg` is valid only during the
     *  call (:891 "message bytes may change on next call"). */
    void (*on_receive)(void *ctx, uint8_t ch_id, const uint8_t *msg,
                       size_t len);
    /** :352 `onError(r)` — at most once per connection (:350). May be
     *  NULL (:351). */
    void (*on_error)(void *ctx, int reason);
} cmt_p2p_mconn_host_t;

/* ══ connection.go:776-790 — Channel ══════════════════════════════════ */

typedef struct {
    uint8_t *bytes;
    size_t   len;
} cmt_p2p_mconn_qmsg_t;

typedef struct {
    cmt_p2p_ch_desc_t desc;             /* :780 (defaults filled)         */

    /* :781 sendQueue — a ring of desc.send_queue_capacity copies (R-P2P-20) */
    cmt_p2p_mconn_qmsg_t *send_queue;
    int      sq_head;
    int      sq_len;
    int32_t  send_queue_size;           /* :782 */

    /* :783 recving — grows up to RecvMessageCapacity (:895-899) */
    uint8_t *recving;
    size_t   recving_len;
    size_t   recving_cap;

    /* :784 sending — the message being split, and how much is left */
    uint8_t *sending;
    size_t   sending_len;
    size_t   sending_off;

    int64_t  recently_sent;             /* :785 EMA, bytes */
    int      max_packet_msg_payload_size; /* :787 */
} cmt_p2p_mconn_channel_t;

/* ══ libs/timer/throttle_timer.go — ThrottleTimer, inline ═════════════ */

typedef struct {
    bool    running;    /* created and not Stop()ped (:26-35, :68-76)  */
    bool    is_set;     /* :23 isSet                                    */
    int64_t deadline;   /* the armed timer's fire instant (:31, :46, :55) */
    int64_t dur;        /* :19 */
} cmt_p2p_mconn_throttle_t;

/* ══ connection.go:80-121 — MConnection ═══════════════════════════════ */

typedef struct {
    cmt_p2p_mconn_host_t   host;
    cmt_p2p_mconn_config_t config;              /* :95 */

    /* BaseService (libs/service/service.go) */
    bool started;
    bool stopped;
    bool errored;                               /* :94 */

    cmt_flowrate_t send_monitor;                /* :86 */
    cmt_flowrate_t recv_monitor;                /* :87 */

    cmt_p2p_mconn_channel_t *channels;          /* :90, :91 (lookup: last
                                                   descriptor with the id) */
    int n_channels;

    /* one-slot channels */
    bool send_token;                            /* :88  send          */
    bool pong_token;                            /* :89  pong          */
    bool pong_timeout_has;                      /* :114 pongTimeoutCh */
    bool pong_timeout_val;                      /*      true=timeout  */

    /* :97-103 quitSendRoutine / doneSendRoutine / quitRecvRoutine */
    bool quit;
    bool send_routine_done;
    bool recv_routine_done;     /* recvRoutine left its loop (:636, :664, …) */
    bool closed;                /* conn.Close() (:302, :318) happened      */
    /* FlushStop (:278-310) in progress / finished */
    bool flush_stopping;
    bool flush_stop_done;

    /* :109-116 timers */
    cmt_p2p_mconn_throttle_t flush_timer;
    int64_t ping_next;          /* pingTimer: next tick instant        */
    bool    ping_ready;         /*            its one-slot channel     */
    int64_t stats_next;         /* chStatsTimer                        */
    bool    stats_ready;
    bool    pong_timer_armed;   /* pongTimer != nil and not yet fired  */
    int64_t pong_deadline;

    /* sendRoutine parked inside sendSomePacketMsgs's Limit (:515) */
    bool    send_in_limit;
    int64_t send_retry_at;

    int64_t created;            /* :118 */
    int     max_packet_msg_size; /* :120 */

    /* :85 bufConnWriter: [0, w_flushed) is in `out` for the caller,
     * [w_flushed, w_len) is staged (at most 65536 bytes) — R-P2P-17 */
    uint8_t *wbuf;
    size_t   wbuf_cap;
    size_t   w_len;
    size_t   w_flushed;

    /* :84 bufConnReader + the delimited reader: one packet being read */
    uint8_t *rbuf;
    size_t   rbuf_cap;
    size_t   rbuf_len;
    bool     recv_limit_passed;   /* :598 passed for the packet in rbuf */
} cmt_p2p_mconn_t;

/* ══ lifecycle ════════════════════════════════════════════════════════ */

/**
 * connection.go:157-216 `NewMConnection` / `NewMConnectionWithConfig`.
 * Copies `host`, `cfg` and the descriptors; allocates the channels and
 * buffers (free with `cmt_p2p_mconn_free`). Reads `now_ns` once (:195
 * `created`, :188-189 the Monitors).
 * @param cfg NULL = `cmt_p2p_mconn_default_config` (:164-169)
 * @return CMT_OK; CMT_FAULT — NULL, `host->now_ns` or `host->on_receive`
 *         NULL, PongTimeout >= PingInterval (:180-182), a descriptor's
 *         priority <= 0 (:794-796) or a negative capacity, payload < 1,
 *         a negative `n_descs`, or out of memory (R-P2P-21). Any number of
 *         descriptors is accepted, zero included, as the reference does.
 */
int cmt_p2p_mconn_init(cmt_p2p_mconn_t *mc, const cmt_p2p_mconn_host_t *host,
                       const cmt_p2p_ch_desc_t *descs, int n_descs,
                       const cmt_p2p_mconn_config_t *cfg);

/** Release every buffer (after stop, or instead of it). */
void cmt_p2p_mconn_free(cmt_p2p_mconn_t *mc);

/** connection.go:226-240 `OnStart` (via BaseService.Start): arms the
 *  flush throttle (stopped), the ping ticker, the stats ticker.
 *  @return CMT_OK; CMT_REJECT if already started or stopped
 *  (ErrAlreadyStarted / ErrAlreadyStopped); CMT_FAULT on NULL. */
int cmt_p2p_mconn_start(cmt_p2p_mconn_t *mc);

/** connection.go:313-324 `OnStop` (via BaseService.Stop): every routine
 *  quits, nothing more is written or read, `out` is dropped (the
 *  reference closes the conn). The caller closes the socket. */
void cmt_p2p_mconn_stop(cmt_p2p_mconn_t *mc);

/**
 * connection.go:278-310 `FlushStop`: the routines quit, then every packet
 * of every queued message is written and flushed; `cmt_p2p_mconn_tick`
 * does that work (rate limit and `out` drain included) until
 * `cmt_p2p_mconn_flush_stop_done`. The caller then drains `out` and
 * closes the socket (:302). A connection already stopped is left as is
 * (:279-281).
 */
void cmt_p2p_mconn_flush_stop(cmt_p2p_mconn_t *mc);

/** FlushStop's send-and-flush (:284-298) has finished: no byte beyond what
 *  `out` now holds will ever be produced. */
bool cmt_p2p_mconn_flush_stop_done(const cmt_p2p_mconn_t *mc);

/** BaseService.IsRunning (service.go): started and not stopped. */
bool cmt_p2p_mconn_is_running(const cmt_p2p_mconn_t *mc);

/* ══ Send side ════════════════════════════════════════════════════════ */

/** connection.go:357-383 `Send` — non-blocking here (R-P2P-19): queues a
 *  copy of `msg` on channel `ch_id`. @return false when not running, the
 *  channel is unknown, the queue is full, or out of memory — and then
 *  nothing is queued. */
bool cmt_p2p_mconn_send(cmt_p2p_mconn_t *mc, uint8_t ch_id,
                        const uint8_t *msg, size_t len);

/** connection.go:385-411 `TrySend`. Same as `send` (R-P2P-19). */
bool cmt_p2p_mconn_try_send(cmt_p2p_mconn_t *mc, uint8_t ch_id,
                            const uint8_t *msg, size_t len);

/** connection.go:413-426 `CanSend` (→ :843-845, the constant-1 quirk). */
bool cmt_p2p_mconn_can_send(const cmt_p2p_mconn_t *mc, uint8_t ch_id);

/**
 * connection.go:429-507 `sendRoutine`, one event-loop pass at the host's
 * `now_ns` (file header). No-op when not started, or once the routine has
 * quit and FlushStop (if any) has finished.
 */
void cmt_p2p_mconn_tick(cmt_p2p_mconn_t *mc);

/** Bytes the caller must write into the secret connection (0 = none). */
const uint8_t *cmt_p2p_mconn_out(const cmt_p2p_mconn_t *mc, size_t *len);

/** The caller took `n` of them. */
void cmt_p2p_mconn_out_consume(cmt_p2p_mconn_t *mc, size_t n);

/* ══ Receive side ═════════════════════════════════════════════════════ */

/**
 * connection.go:590-694 `recvRoutine` over the plaintext bytes the caller
 * read out of the secret connection. Consumes whole packets (and the
 * start of the next one) as far as `recvMonitor.Limit` allows; a byte it
 * cannot use yet is left unconsumed — the caller offers it again.
 * `on_receive` runs inside this call.
 * @param consumed always set
 * @return CMT_OK; CMT_REJECT — the connection is (now) stopped: a
 *         malformed / oversized packet, an unknown channel or message
 *         type, a message over RecvMessageCapacity (each → `on_error`
 *         once), or it was already stopped; CMT_FAULT on NULL.
 */
int cmt_p2p_mconn_recv(cmt_p2p_mconn_t *mc, const uint8_t *in, size_t len,
                       size_t *consumed);

/**
 * `cmt_p2p_mconn_recv` that RETURNS right after its `max_msgs`-th
 * `on_receive` (a whole message handed to a reactor), consuming nothing
 * beyond the packet that completed it. `cmt_p2p_mconn_recv` is this with
 * no limit (SIZE_MAX).
 *
 * WHY: the reference's `onReceive` (connection.go:676-678) runs on the
 * recvRoutine goroutine and BLOCKS it when a reactor's queue is full
 * (consensus/reactor.go:333, :339, :359 `peerMsgQueue <-`) — every
 * message waits for its own slot, and the Go runtime hands freed slots to
 * the blocked senders in FIFO order. One event loop cannot block inside
 * `on_receive`, so the caller asks "is there room for ONE message?"
 * before each call with `max_msgs` = 1 (cmt_p2p_peer_pump). The
 * MConnection cannot see a reactor's queue; it counts deliveries — every
 * message handed to `on_receive`, whether or not a reactor queues it.
 * @param delivered may be NULL; set to the number of `on_receive` calls.
 */
int cmt_p2p_mconn_recv_n(cmt_p2p_mconn_t *mc, const uint8_t *in, size_t len,
                         size_t *consumed, size_t max_msgs, size_t *delivered);

/** The connection under the MConnection failed (socket EOF / error, the
 *  secret connection refused a frame): the recvRoutine's / sendRoutine's
 *  error path (:497-500, :628-635) — `stopForError` if still running. */
void cmt_p2p_mconn_conn_failed(cmt_p2p_mconn_t *mc);

/* ══ Status (connection.go:717-749) ═══════════════════════════════════ */

typedef struct {
    uint8_t id;                  /* :725 */
    int     send_queue_capacity; /* :726 */
    int     send_queue_size;     /* :727 */
    int     priority;            /* :728 */
    int64_t recently_sent;       /* :729 */
} cmt_p2p_mconn_channel_status_t;

typedef struct {
    int64_t duration_ns;                  /* :718 */
    cmt_flowrate_status_t send_monitor;   /* :719 */
    cmt_flowrate_status_t recv_monitor;   /* :720 */
    int n_channels;
    cmt_p2p_mconn_channel_status_t *channels; /* :721 — caller's array */
} cmt_p2p_mconn_status_t;

/** connection.go:732-749 `Status()`. Fills up to `cap_channels` entries
 *  of `channels_out` (sets `out->channels` to it). */
void cmt_p2p_mconn_status(cmt_p2p_mconn_t *mc, cmt_p2p_mconn_status_t *out,
                          cmt_p2p_mconn_channel_status_t *channels_out,
                          int cap_channels);

/* ══ Channel internals, exposed for the tests ═════════════════════════ */

/** connection.go:549-570 `selectChannelToGossipOn`: the channel whose
 *  recentlySent / priority (float32) is least, among those with a send
 *  pending; ties go to the earlier channel. @return index or -1. */
int cmt_p2p_mconn_select_channel(cmt_p2p_mconn_t *mc);

/** connection.go:915-919 `updateStats` on every channel (the
 *  chStatsTimer case, :444-447). */
void cmt_p2p_mconn_update_stats(cmt_p2p_mconn_t *mc);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_MCONN_H */
