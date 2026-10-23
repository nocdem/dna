/**
 * Nodus — SecretConnection layer of the TCP / WebSocket transport
 * (DHT v2 sub-package 3b-1: the transport layer only).
 *
 * @file nodus_tcp_sc.h
 *
 * ═══ STATUS (3b-2) ═════════════════════════════════════════════════════
 * ENABLED on 4001 / WebSocket accept (CLIENT profile, nodus_server.c
 * on_tcp_accept), on 4002 accept and dial (NODE profile,
 * server/nodus_inter_dial.c), on the DHT's batch forwards and on the client
 * SDK's connect (nodus_client.c). The hello / auth / key_init /
 * channel-crypto session path is deleted. Only the Unix-socket IPC
 * connections (is_unix) carry no layer. Consumers (nodus-cli, explorer, ...)
 * and the browser build lists are 3c.
 * Governing records: docs/plans/2026-10-23-dht-v2-session-package-design.md
 * rev 1 (O-1 a, O-3 b), decisions/2026-10-23-kurultay-43-summary.md,
 * decisions/2026-10-23-dht-v2-session-bytes.md.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IT IS ─────────────────────────────────────────────────────────
 * An OPTIONAL per-connection cmt_p2p_sc_t (the 4004 secret connection,
 * shared/dnac/cmt_p2p_secret.h) between the socket and the nodus frame
 * parser:
 *
 *   plain TCP   socket bytes ─▶ machine ─▶ plaintext ─▶ nodus frames
 *   WebSocket   WS payload   ─▶ machine ─▶ plaintext ─▶ nodus frames
 *               (the WS layer — Upgrade, ping/pong, close — stays outside
 *               the sealed stream; session design rev 1 / Kurultay #43)
 *
 * and the reverse on the way out: nodus frame ─▶ pending FIFO (plaintext) ─▶
 * drain: seal a portion ─▶ (WS frame) ─▶ wbuf. Nodus frames travel UNCHANGED
 * inside the sealed stream (O-1 a).
 * The sealed stream is cut into WS binary frames of one portion each, at most
 * NODUS_TCP_SC_PORTION_FRAMES sealed frames (a whole sealed 5 MiB nodus
 * frame, 5,346,324 bytes, is more than NODUS_WS_MAX_PAYLOAD, 5,242,887, which
 * the server enforces per WS frame — close 1009). A client of 3c must cut its
 * own sealed stream the same way (any cut at or below NODUS_WS_MAX_PAYLOAD is
 * accepted; the stream is a byte stream).
 *
 * Nothing reaches the nodus frame parser before the machine is
 * AUTHENTICATED. Plaintext the machine already opened (the tail of the
 * AUTHSIG frame, cmt_p2p_secret.h cmt_p2p_sc_read_pending) is drained even
 * when no new socket byte arrives. A nodus_tcp_send before AUTHENTICATED is
 * refused (-1): nothing is queued, nothing is sealed.
 *
 * ── PROFILES, PURPOSES, THE PIN ────────────────────────────────────────
 * The caller names a profile; the layer binds the host's signing purpose to
 * it (cmt_p2p_secret.h "Obligations for DHT v2 sub-package 3b"):
 *   &CMT_P2P_SC_PROFILE_CLIENT  ─ purpose 0x0C  (nodus_sign_client_session_auth)
 *   &CMT_P2P_SC_PROFILE_NODE    ─ purpose 0x0D  (nodus_sign_node_session_auth)
 * Any other profile (WITNESS included — 4004 owns that one) is refused.
 * The INITIATOR must carry the exact identity it meant to dial
 * (cfg.expected_peer, a SHA3-512 fingerprint of the peer's public key, i.e.
 * its node id; stored in conn->expected_peer_id). The layer compares the
 * responder's CLAIMED key with it BEFORE the ENCAPS job is run and aborts
 * on a mismatch (pattern: cmt_p2p_transport.c:205-219, decision
 * 2026-09-26-witness-port-session.md). An unpinned initiator is refused at
 * enable.
 *
 * ── HANDSHAKE JOBS (O-3 b) ─────────────────────────────────────────────
 * The machine's asymmetric steps (ENCAPS / DECAPS / SIGN / VERIFY) run on a
 * worker owned by the nodus_tcp_t, separate from 4004's host:
 *   · started by the first nodus_tcp_sc_enable, stopped (threads joined,
 *     queues dropped) by nodus_tcp_close;
 *   · NODUS_TCP_SC_WORKERS threads, two classes: OUTBOUND (we dialed) is
 *     served before INBOUND (we accepted);
 *   · each class is bounded: QUEUED + RUNNING + COMPLETED-NOT-DELIVERED
 *     jobs together never exceed NODUS_TCP_SC_JOBQ_OUT / _IN; a job that
 *     does not fit closes its connection (inbound: the handshake is dropped
 *     under load; outbound: the dial fails);
 *   · a job is a self-contained COPY of the machine's job (4004 pattern);
 *     the worker never touches a connection;
 *   · a result is applied on the poll loop, by (slot, generation): if the
 *     pool slot no longer holds the connection that generation was given to
 *     (closed, or reused), the result is discarded and its copy freed.
 * Browser / single-thread builds (__EMSCRIPTEN__, or NODUS_SC_INLINE) run
 * every job inline on the loop and apply it at once — no thread, no queue;
 * the caller yields to the browser between polls as it does today.
 *
 * COMPLETION DELIVERY (explicit polling, written down as the record asks):
 * nodus_tcp has no wake descriptor and this package does not add one. A
 * finished job is noticed at the START of the next nodus_tcp_poll. While any
 * job is outstanding on a transport, nodus_tcp_poll never waits longer than
 * NODUS_TCP_SC_POLL_MS, so a result is applied at most that long after it is
 * ready (plus the loop's own work); with no job outstanding the caller's
 * timeout is untouched. Latency bound of one handshake step =
 * NODUS_TCP_SC_POLL_MS; a handshake has three jobs per side (ENCAPS or
 * DECAPS, SIGN, VERIFY), so at most 3 * NODUS_TCP_SC_POLL_MS added by the
 * delivery, on top of the jobs' own run time. The loop that owns the
 * transport must call nodus_tcp_poll regularly — a caller that stops
 * polling stops its handshakes.
 * SCOPE OF THE BOUND: the 5 ms cap is TRANSPORT-WIDE (it applies to every
 * connection of the transport while ANY job is outstanding) and it holds only
 * for an owner that polls THIS transport alone. An owner that polls several
 * transports in one loop (nodus_server.c polls tcp, then inter_tcp, with a
 * 50 ms wait, :3215-3238) must include nodus_tcp_sc_busy() of EVERY transport
 * in its own wait, or a result on the other transport sits for that wait.
 * That is a 3b-2 obligation. The same predicate also covers a loop-owned
 * teardown that is due (a fatal sealing failure, below).
 *
 * ── 3b-2 OBLIGATIONS (done) ─────────────────────────────────────────────
 *  · The auth gate: a 4002 connection (nodus_inter_session_enable) closes the
 *    send gate (auth_required, auth_state NONE / HELLO_SENT); a send before
 *    the session is authenticated waits in the DIAL QUEUE (the auth pending
 *    buffer, plaintext) and nodus_inter_dial_conn_open, at on_session,
 *    replays it through nodus_tcp_send — sealed, in order. The queue is never
 *    flushed as bytes (nodus_tcp_pending_flush refuses a layer connection).
 *  · An owner of several transports includes nodus_tcp_sc_busy() of each in
 *    its poll wait (nodus_server.c run loop, nodus_dht_ipc_poll).
 *  · nodus_tcp_sc_enable refuses a connection that has carried any byte
 *    (sticky conn->io_started), has auth_state != NONE, a peer id, an auth
 *    nonce or a session token: enable at accept / right after connect.
 *
 * ── FAILURES ───────────────────────────────────────────────────────────
 *  · A sealing (cipher) failure is FATAL, not backpressure: the send returns
 *    -1, on_pending_full is NOT called, the connection is marked, and the
 *    next nodus_tcp_poll closes it (on_disconnect, free) after the write
 *    lock is released. Admission refusals (not authenticated, counter
 *    exhausted, queue full) stay distinct: -1 / on_pending_full as before.
 *  · A WebSocket Close that arrives while a handshake job is outstanding
 *    does not discard the input before it: the close is recorded, the job
 *    finishes, the held input is opened and its frames dispatched in order
 *    after on_session, and only then the connection closes.
 *  · INCREMENTAL SEALING (operator, 2026-10-24, "Şimdi artımlı yap" —
 *    addendum to decisions/2026-10-23-kurultay-43-summary.md): a send does
 *    not seal. It decides ADMISSION for the whole frame (the pending caps,
 *    NODUS_PENDING_MAX_FRAMES / _BYTES, counted in PLAINTEXT bytes) and
 *    queues the PLAINTEXT nodus frame, owned, in the pending FIFO with a
 *    cursor (nodus_pending_frame_t.sc_off). Only the DRAIN seals — at send
 *    time and then from nodus_tcp_poll's write handling as the socket takes
 *    bytes — in portions of NODUS_TCP_SC_PORTION_FRAMES (32) sealed frames,
 *    each only when its ciphertext fits the write buffer's fill target
 *    (NODUS_TCP_SC_WBUF_FILL), in FIFO order. So a refused send seals
 *    nothing and moves no counter; counter order = wire order (one sealer,
 *    one order); a cipher failure (or an exhausted counter) mid-frame is
 *    fatal — the connection is marked and the loop closes it, and the
 *    plaintext is never handed to on_pending_full. Each portion is its own
 *    WS binary frame on a WS connection.
 *
 * ── LIFETIMES (caller's obligations) ───────────────────────────────────
 * cfg.id (the signing key, and for a responder the ML-KEM key pair) must
 * outlive nodus_tcp_close: a queued or running job holds a pointer to it
 * and may run after the connection is gone. The machine's responder KEM key
 * is NOT copied (cmt_p2p_sc_init), same rule.
 *
 * ── BUFFER BOUNDS (derived; see the _Static_asserts below) ─────────────
 * The largest nodus frame is NODUS_FRAME_HEADER_SIZE + NODUS_MAX_FRAME_TCP
 * = 5,242,887 bytes = 5,121 sealed frames of 1,044 bytes = 5,346,324 bytes
 * on the wire (more than today's 5,246,983-byte write buffer) — but it is
 * sealed in 161 portions, never whole. A portion is at most 32 sealed frames
 * = 33,408 bytes (+ a 4-byte WS header) = NODUS_TCP_SC_PORTION_WIRE
 * 33,412; the drain seals a portion only while the write buffer stays at or
 * below NODUS_TCP_SC_WBUF_FILL = 2 portions = 66,824 bytes; the buffer's
 * bound NODUS_TCP_SC_WBUF_MAX = 131,072 bytes leaves 64,248 for the
 * handshake output, a 101, pongs and a close. That is about 40 times LESS
 * than the plain bound of 5,246,983 (5,246,983 / 131,072 = 40.03). The pending queue keeps its existing caps
 * (NODUS_PENDING_MAX_FRAMES frames, NODUS_PENDING_MAX_BYTES bytes) — they
 * count PLAINTEXT bytes (the frames are queued unsealed). The read
 * buffer holds plaintext and may grow to NODUS_TCP_SC_RBUF_MAX = 5,246,983 +
 * 16,384 = 5,263,367 bytes (+0.31%). Per layer-enabled connection
 * add the machine (sizeof(cmt_p2p_sc_t), about 42 KB, heap) and, only while
 * a handshake job blocks input, up to NODUS_TCP_SC_RAW_CHUNK (16 KiB) of
 * held socket bytes. Jobs: at most NODUS_TCP_SC_JOBQ_OUT + _IN copies of
 * about 17 KB each.
 *
 * ── THREADING ──────────────────────────────────────────────────────────
 * Same model as the rest of nodus_tcp: one thread polls; with a write lock
 * installed (nodus_tcp_set_write_lock) other threads may send. The machine
 * is touched under that lock by BOTH sides (reads/feeds, completions, and
 * seals), so its send half and receive half never race; enable checks the
 * connection and publishes conn->sc under it; every PUBLIC query
 * (nodus_tcp_sc_authenticated, _peer_pubkey, _send_counter, _generation)
 * takes it and returns a COPY — a pointer into the machine would dangle once
 * conn_free wipes it. The "transport-internal" functions below that touch the
 * machine run with the lock held by the caller, except the ones marked
 * poll-thread-only. on_session is invoked after the lock is released.
 * CALLBACK RULE: the progress callback of nodus_tcp_send_progress and
 * tcp->on_pending_full run UNDER the write lock (nodus_tcp.h); they must not
 * call any nodus_tcp_sc_* query (non-recursive lock: self-deadlock). No
 * in-tree callback does (git grep of the public queries finds only
 * transport/ and tests/test_tcp_sc.c). All other callbacks run unlocked. The
 * worker threads touch only their private job copies.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_TCP_SC_H
#define NODUS_TCP_SC_H

#include "transport/nodus_tcp.h"
#include "dnac/cmt_p2p_secret.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Inline (threadless) jobs in the browser and in any single-thread build. */
#if defined(__EMSCRIPTEN__) && !defined(NODUS_SC_INLINE)
  #define NODUS_SC_INLINE 1
#endif

/* ── Per-port protocol versions (Kurultay #43 O-6) ───────────────────── */

/** Protocol version of the client session (4001 / WebSocket, profile CLIENT,
 *  purpose 0x0C). Own symbol, never CMT_P2P_PROTOCOL_VERSION (4004's, 8): a
 *  future change of this number is a flag day for every client (the
 *  all-at-once rule). decisions/2026-10-23-dht-v2-session-bytes.md addendum
 *  2026-10-24, operator "İkisi de 1". */
#define NODUS_CSESS_PROTO_VERSION 1u
/** Protocol version of the node session (4002, profile NODE, purpose 0x0D);
 *  same rule, same addendum. */
#define NODUS_NSESS_PROTO_VERSION 1u

/* ── Constants (NOT in the records: sizes; derivations in the comments) ── */

/** Worker threads. Mirrors NODUS_P2P_WORKERS_DEFAULT (nodus_p2p_host.h:310). */
#define NODUS_TCP_SC_WORKERS     2
/** Outstanding handshake jobs per class (queued + running + completed and
 *  not yet delivered). Mirrors NODUS_P2P_JOBQ_DEPTH (nodus_p2p_host.c:882,
 *  "a size" there too). Each live connection has at most ONE job out, so
 *  this is also the number of handshakes a class advances at once. */
#define NODUS_TCP_SC_JOBQ_OUT    64
#define NODUS_TCP_SC_JOBQ_IN     64
/** Longest nodus_tcp_poll wait while a job is outstanding (ms). */
#define NODUS_TCP_SC_POLL_MS     5
/** Socket bytes read per step of the SC read path; also the capacity of the
 *  hold buffer. One WS payload run handed to the layer by one read is at
 *  most this long, so the hold never overflows for an honest peer. */
#define NODUS_TCP_SC_RAW_CHUNK   16384
/** Sealed frames per PORTION: the unit the drain seals into the write buffer
 *  at once, and (on a WS connection) the payload of exactly one WS binary
 *  frame. 32 * 1044 = 33,408 bytes: below 65,536, so every WS header is the
 *  4-byte form, and far below NODUS_WS_MAX_PAYLOAD. A portion covers 32 KiB of
 *  plaintext (a multiple of the 1024-byte sealed chunk, so the per-frame
 *  cursor stays frame-aligned). */
#define NODUS_TCP_SC_PORTION_FRAMES 32
#define NODUS_TCP_SC_WS_GROUP_FRAMES NODUS_TCP_SC_PORTION_FRAMES   /* the WS cut = the portion */

/* Derived bounds. */
#define NODUS_TCP_SC_PLAIN_MAX \
    ((size_t)NODUS_FRAME_HEADER_SIZE + (size_t)NODUS_MAX_FRAME_TCP)
#define NODUS_TCP_SC_FRAMES_MAX \
    ((NODUS_TCP_SC_PLAIN_MAX + CMT_P2P_SC_DATA_MAX_SIZE - 1) / CMT_P2P_SC_DATA_MAX_SIZE)
#define NODUS_TCP_SC_SEALED_MAX \
    (NODUS_TCP_SC_FRAMES_MAX * (size_t)CMT_P2P_SC_SEALED_FRAME_SIZE)
/** Portions a maximal nodus frame is drained in: ceil(5,121 / 32) = 161. */
#define NODUS_TCP_SC_PORTIONS_MAX \
    ((NODUS_TCP_SC_FRAMES_MAX + NODUS_TCP_SC_PORTION_FRAMES - 1) / NODUS_TCP_SC_PORTION_FRAMES)
#define NODUS_TCP_SC_WS_HDR 4   /* header of a 126..65535-byte WS payload */
/** Plaintext of one full portion (32 * 1024). */
#define NODUS_TCP_SC_PORTION_PLAIN \
    ((size_t)NODUS_TCP_SC_PORTION_FRAMES * CMT_P2P_SC_DATA_MAX_SIZE)
/** Write-buffer bytes of one full portion, WS header included. */
#define NODUS_TCP_SC_PORTION_WIRE \
    ((size_t)NODUS_TCP_SC_PORTION_FRAMES * CMT_P2P_SC_SEALED_FRAME_SIZE + NODUS_TCP_SC_WS_HDR)
/** The drain seals a portion only while the write buffer would stay at or
 *  below this: two portions (the one the socket is taking, the next ready). */
#define NODUS_TCP_SC_WBUF_FILL (2 * NODUS_TCP_SC_PORTION_WIRE)
/** The write buffer's bound for a layer connection: 128 KiB. FILL
 *  (66,824) leaves 64,248 bytes for what is NOT sealed data — the handshake
 *  output (at most CMT_P2P_SC_OUT_CAP = 13,684 + a WS header), a 101 response,
 *  pongs and a close frame. (Today's plain bound is 5,246,983: a layer
 *  connection needs about 40 times LESS, since a frame is no longer sealed
 *  whole.) */
#define NODUS_TCP_SC_WBUF_MAX (128 * 1024)
/** Read buffer bound: the plain bound (one nodus frame + 4096) + one raw
 *  chunk of plaintext. A chunk is fed to the machine whole and parsed after,
 *  and it opens to at most NODUS_TCP_SC_RAW_CHUNK bytes (16 sealed frames:
 *  a partial one carried over + 15 new), so the bytes of the NEXT frame that
 *  ride in the chunk that completes this one must fit too. */
#define NODUS_TCP_SC_RBUF_MAX \
    ((size_t)NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE + 4096 + NODUS_TCP_SC_RAW_CHUNK)

_Static_assert(NODUS_TCP_SC_FRAMES_MAX == 5121,
               "a 5 MiB nodus frame is 5,121 sealed frames (Kurultay #43)");
_Static_assert(NODUS_TCP_SC_SEALED_MAX == 5346324,
               "5,121 x 1,044 = 5,346,324 bytes (Kurultay #43)");
_Static_assert(NODUS_TCP_SC_PORTIONS_MAX == 161, "a 5 MiB frame drains in 161 portions");
_Static_assert((size_t)NODUS_TCP_SC_PORTION_FRAMES * CMT_P2P_SC_SEALED_FRAME_SIZE <= 65535 &&
               (size_t)NODUS_TCP_SC_PORTION_FRAMES * CMT_P2P_SC_SEALED_FRAME_SIZE >= 126,
               "a portion's WS header must be the 4-byte form");
_Static_assert(NODUS_TCP_SC_PORTION_PLAIN % CMT_P2P_SC_DATA_MAX_SIZE == 0,
               "the per-frame cursor must stay aligned to the sealed chunk");
_Static_assert(NODUS_TCP_SC_PORTION_WIRE <= NODUS_WS_MAX_PAYLOAD,
               "a portion must fit one WS frame");
_Static_assert(NODUS_TCP_SC_WBUF_FILL >= NODUS_TCP_SC_PORTION_WIRE &&
               NODUS_TCP_SC_WBUF_FILL + CMT_P2P_SC_OUT_CAP + NODUS_WS_SERVER_HDR_MAX +
               NODUS_WS_CTRL_MAX * 8 <= NODUS_TCP_SC_WBUF_MAX,
               "the fill target must leave room for handshake output and WS control frames");

/* ── Enable ──────────────────────────────────────────────────────────── */

typedef struct {
    cmt_p2p_sc_role_t           role;       /* who dialed: INITIATOR / RESPONDER */
    const cmt_p2p_sc_profile_t *profile;    /* &..._CLIENT or &..._NODE only     */
    /** Signing key (and, for a RESPONDER, the ML-KEM-1024 pair, so
     *  id->has_mlkem is required). Must outlive nodus_tcp_close. */
    const nodus_identity_t     *id;
    uint32_t                    proto_ver;  /* per-PORT symbol, never 4004's     */
    uint8_t                     chain_id[CMT_P2P_SC_CHAIN_ID_SIZE];
    /** INITIATOR: the node id (SHA3-512 of the public key) the caller meant
     *  to dial. RESPONDER: ignored. Copied. */
    const nodus_key_t          *expected_peer;
    /** INITIATOR: a SET of acceptable node ids (the client SDK's
     *  pinned_server_fps: a client that may connect to any of several
     *  servers). The responder's claimed key must hash to expected_peer or to
     *  one of these, checked before the ENCAPS job. At least one of
     *  expected_peer / (expected_set, expected_set_n > 0) is required.
     *  RESPONDER: ignored. NOT copied: caller-owned, must outlive
     *  nodus_tcp_close (same rule as cfg.id). */
    const nodus_key_t          *expected_set;
    size_t                      expected_set_n;
} nodus_tcp_sc_cfg_t;

/**
 * Turn the SecretConnection on for `conn`. Allowed exactly once, on a
 * connection that has carried no byte yet in either direction (nothing in
 * rbuf / wbuf / the auth pending buffer / the pending queue), not closing,
 * not AF_UNIX:
 *   · RESPONDER: from on_accept (before the first read) — plain or WS
 *     (on a WS connection the machine starts after the Upgrade);
 *   · INITIATOR: right after nodus_tcp_connect returns, or from on_connect.
 *     Its HELLO is put in the write buffer here (sent as soon as the socket
 *     is connected).
 * @return 0; -1 on a bad argument, a refused profile / pin / role, a
 *         connection that is not clean, or an allocation / worker failure
 *         (the connection is left exactly as it was).
 */
int nodus_tcp_sc_enable(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                        const nodus_tcp_sc_cfg_t *cfg);

/** Layer enabled AND the machine is AUTHENTICATED. */
bool nodus_tcp_sc_authenticated(const nodus_tcp_conn_t *conn);

/**
 * The pre-session deadline of an ACCEPTED connection (Kurultay #43 O-5: 15 s
 * idle / 30 s absolute for 4001 and 4002 accept): close every connection of
 * `tcp` that carries the layer, was accepted (not dialed by us), is not
 * AUTHENTICATED yet, and has gone `idle_ms` without a socket byte
 * (last_activity_mono_ms) or `abs_ms` since it connected
 * (connected_mono_ms) — whichever comes first — as of `now_mono_ms`.
 * `now_mono_ms` is on the nodus_time_mono_ms() scale: a monotonic clock, so a
 * wall-clock step cannot stretch or cut a deadline (the old sweep ran on
 * CLOCK_REALTIME every 30 s and was effective at 45 / 60 s). Taking the time
 * as an argument lets a test drive it. Call it from the owner's loop, outside
 * nodus_tcp_poll, often enough for the deadline to be met (once a second).
 * An authenticated connection and a connection without the layer are never
 * touched. @return the number of connections closed. */
int nodus_tcp_sc_presession_sweep(nodus_tcp_t *tcp, uint64_t now_mono_ms,
                                  uint64_t idle_ms, uint64_t abs_ms);

/** Copy the peer's public key (CMT_P2P_SC_DSA_PK_SIZE bytes) into `out`,
 *  once AUTHENTICATED. @return 0; -1 before that, without the layer, or on a
 *  NULL argument (`out` untouched). A copy, never a pointer into the machine
 *  (conn_free wipes it). */
int nodus_tcp_sc_peer_pubkey(const nodus_tcp_conn_t *conn,
                             uint8_t out[CMT_P2P_SC_DSA_PK_SIZE]);

/** The machine's send counter (tests: a refused send must not move it);
 *  0 without the layer. */
uint64_t nodus_tcp_sc_send_counter(const nodus_tcp_conn_t *conn);

/** The generation this connection's layer was given at enable (0 without the
 *  layer). Generations are never reused within a transport; with the pool
 *  slot they identify one connection for the life of a job. */
uint64_t nodus_tcp_sc_generation(const nodus_tcp_conn_t *conn);

/** Jobs outstanding (queued + running + completed-not-delivered) on this
 *  transport, both classes; 0 without a worker. */
int nodus_tcp_sc_outstanding(const nodus_tcp_t *tcp);

/* ═══ transport-internal (used by nodus_tcp.c; tests may call the job
 * entry points marked so) ═══════════════════════════════════════════════ */

/** One handshake job: a self-contained copy of the machine's job. */
typedef struct nodus_sc_job {
    struct nodus_sc_job *next;
    int                  slot;
    uint64_t             gen;
    int                  cls;            /* 0 OUTBOUND, 1 INBOUND */
    cmt_p2p_sc_job_kind_t kind;
    int                  rc;             /* cmt_p2p_sc_job_run's result */
    bool                 charged;        /* counted in the worker's bound until applied */
    cmt_p2p_sc_host_t    host;          /* by value: the job outlives its conn */
    cmt_p2p_sc_job_t     job;            /* pointers into this struct */
    uint8_t kem_pk[CMT_P2P_SC_KEM_PK_SIZE];
    uint8_t kem_ct[CMT_P2P_SC_KEM_CT_SIZE];
    const uint8_t *kem_sk;               /* DECAPS: the responder's key, caller-owned */
    uint8_t msg[CMT_P2P_SC_CHALLENGE_SIZE];
    size_t  msg_len;
    uint8_t dsa_pk[CMT_P2P_SC_DSA_PK_SIZE];
    uint8_t sig[CMT_P2P_SC_SIG_SIZE];
    uint8_t kem_ct_out[CMT_P2P_SC_KEM_CT_SIZE];
    uint8_t kem_ss_out[CMT_P2P_SC_KEM_SS_SIZE];
    uint8_t sig_out[CMT_P2P_SC_SIG_SIZE];
} nodus_sc_job_t;

typedef enum {
    NODUS_SC_APPLY_DISCARDED = 0,  /* stale (slot, generation): job freed, nothing done */
    NODUS_SC_APPLY_OK,             /* applied; *conn_out is the connection to resume    */
    NODUS_SC_APPLY_FAIL            /* applied and the connection must close (*conn_out) */
} nodus_sc_apply_t;

/** Take the finished jobs off the worker, oldest first (caller applies and
 *  frees each with nodus_tcp_sc_job_apply). NULL when none. */
nodus_sc_job_t *nodus_tcp_sc_take_done(nodus_tcp_t *tcp);

/**
 * Apply one finished job by (slot, generation) and FREE it in every case.
 * `tcp->pool[job->slot]` must still hold the connection whose layer was
 * given `job->gen`, and that layer must be waiting for exactly this job;
 * otherwise NODUS_SC_APPLY_DISCARDED. On OK / FAIL the machine has been
 * advanced (the next job, if any, is already submitted) and *conn_out names
 * the connection. Callable by tests with a fabricated stale job (it must be
 * malloc'd).
 */
nodus_sc_apply_t nodus_tcp_sc_job_apply(nodus_tcp_t *tcp, nodus_sc_job_t *job,
                                        nodus_tcp_conn_t **conn_out);

/** The longest wait nodus_tcp_poll may use now (see COMPLETION DELIVERY). */
int nodus_tcp_sc_poll_timeout(const nodus_tcp_t *tcp, int timeout_ms);

/** True while jobs are outstanding (queued + running + finished-not-yet-
 *  applied) or a loop-owned teardown is due. nodus_tcp_poll must not return
 *  early then, and an owner polling several transports in one loop must
 *  include this predicate of EVERY transport in its wait (see COMPLETION
 *  DELIVERY, "SCOPE OF THE BOUND"). Takes the write lock. */
bool nodus_tcp_sc_busy(const nodus_tcp_t *tcp);

/** nodus_tcp_close: stop the threads, drop every queued / finished job. */
void nodus_tcp_sc_worker_stop(nodus_tcp_t *tcp);

/** conn_free: zero and release the machine and the hold buffer. */
void nodus_tcp_sc_free(nodus_tcp_conn_t *conn);

/**
 * IMPLEMENTED BY nodus_tcp.c (it owns the buffers): move the machine's
 * pending output (handshake messages — they are not nodus frames) into the
 * write buffer, WebSocket-framed on a WS connection, then push what the
 * socket takes if the connection is connected. Takes the write lock itself.
 * @return 0; -1 only if the bytes could not be buffered.
 */
int nodus_tcp_sc_flush_hs(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn);

/** Receives plaintext the machine opened. Return 0, or -1 to fail the feed. */
typedef int (*nodus_tcp_sc_plain_fn)(void *ctx, const uint8_t *data, size_t len);

/**
 * Hand `n` raw bytes (socket bytes, or the payload of a WS frame) to the
 * layer — n may be 0: that resumes held input and drains plaintext the
 * machine already holds (the AUTHSIG-tail hold). Drives the machine as far
 * as the input allows; plaintext goes to `plain`. Handshake jobs are
 * submitted here. Bytes the machine cannot take while a job is outstanding
 * are held (at most NODUS_TCP_SC_RAW_CHUNK).
 * The caller holds the write lock (if one is installed).
 * @return 0; -1 = fail the connection (handshake rejected, bad frame,
 *         pin mismatch, queue full, hold overflow, `plain` refused).
 */
int nodus_tcp_sc_feed(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                      const uint8_t *raw, size_t n,
                      nodus_tcp_sc_plain_fn plain, void *plain_ctx);

/** A job is outstanding or socket bytes are held: do not read the socket
 *  (the held bytes come first; the completion resumes the connection).
 *  POLL-THREAD-ONLY, no lock: job_out / the hold are written only by the
 *  feed and the completion apply, which run on the polling thread. */
bool nodus_tcp_sc_blocked(const nodus_tcp_conn_t *conn);

/** The bytes the machine wants written (handshake messages); consume what
 *  was copied out. */
const uint8_t *nodus_tcp_sc_out(const nodus_tcp_conn_t *conn, size_t *len);
void nodus_tcp_sc_out_consume(nodus_tcp_conn_t *conn, size_t n);

/** True ONCE after the machine became AUTHENTICATED (then false again):
 *  the cue to fire tcp->on_session. */
bool nodus_tcp_sc_take_ready(nodus_tcp_conn_t *conn);

/** Sealed size of a nodus wire unit of `plain_len` bytes, without any WS
 *  framing. */
size_t nodus_tcp_sc_sealed_size(size_t plain_len);

/** Can `nframes` more frames be sealed (authenticated, counter room)?
 *  Write lock held by the caller. */
bool nodus_tcp_sc_can_seal(const nodus_tcp_conn_t *conn, size_t nframes);

/** The machine is DEAD (a cipher failure, a reject): sealing failed for good,
 *  as opposed to a refusal that leaves the session intact. Write lock held
 *  by the caller. */
bool nodus_tcp_sc_dead(const nodus_tcp_conn_t *conn);

/**
 * Seal frames [first, first + nframes) of the logical byte stream `a || b`
 * into `out` (nframes * CMT_P2P_SC_SEALED_FRAME_SIZE bytes, caller-reserved),
 * one cmt_p2p_sc_write per frame. The caller (the drain) checked
 * nodus_tcp_sc_can_seal for this PORTION first, so a refusal cannot happen
 * half-way through it.
 * @return 0; -1 on a cipher failure (the machine is dead — close).
 */
int nodus_tcp_sc_seal(nodus_tcp_conn_t *conn,
                      const uint8_t *a, size_t alen,
                      const uint8_t *b, size_t blen,
                      size_t first, size_t nframes, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TCP_SC_H */
