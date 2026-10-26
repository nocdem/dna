/**
 * Nodus — Witness IPC (the nodus-witness process's local socket)
 *
 * Component split S3 (decision docs/plans/decisions/2026-10-01-nodus-
 * component-split.md items 5, 7, 10, 11, 19, 20): the witness runs as its
 * own process and the core server (nodus-server with "witness_external")
 * reaches it over ONE Unix domain socket, <data_path>/witness.sock
 * (mode 0600, both ends checked with SO_PEERCRED — nodus_tcp_unix_listen /
 * nodus_tcp_unix_connect). Frames are ordinary nodus wire frames (the
 * transport's 7-byte header), plaintext; no handshake method exists here.
 *
 * Three kinds of connection, told apart by their FIRST frame:
 *
 *   session (one per core client session that has sent a `dnac_*`):
 *     first frame  {"q":"ipc_hello","pk":<bstr NODUS_PK_BYTES>,
 *                   "tk":<bstr NODUS_SESSION_TOKEN_LEN>}
 *                  — the client session's key and session token;
 *     then         the client's tier-2 `dnac_*` payloads, unchanged; each
 *                  is decoded with nodus_t2_decode (the decoder the
 *                  server's dispatch_t2 uses) and handed to the witness
 *                  with THIS connection as `conn`, so the witness's own
 *                  nodus_tcp_send(conn, ...) replies travel back on it and
 *                  core relays them to the client unchanged. The session
 *                  ends when core closes the connection; from then on
 *                  find_session_conn no longer returns it (the delayed
 *                  dnac_cc_collect reply is dropped, as in the combined
 *                  binary).
 *   control (one per core):
 *     first frame  {"q":"ipc_ctl"}
 *     then         {"q":"ipc_status"} queries, each answered with
 *                  {"q":"ipc_status","co":bool chain open,"h":uint height,
 *                   "sr":bstr 64 state root,"ci":bstr 32 chain id,
 *                   "po":bool p2p host exists,"lp":uint 4004 port}.
 *
 * A THIRD kind (DHT v2, docs/plans/2026-10-14-dht-v2-design.md rev 5 §13
 * row 13), the nodus-storage process's read-only view of the chain:
 *
 *   dht (one per nodus-storage, same euid):
 *     first frame  {"q":"ipc_dht"}
 *     then         three requests, each answered with a frame that echoes
 *                  the request's "q" (so the asker can tell the answers
 *                  apart) and, on a node-local fault, {"q":…,"err":tstr}
 *                  instead of the fields below (a name answer keeps "fp"):
 *       {"q":"ipc_dht_snap"} →
 *           {"q","ci":bstr 32 chain id,"h":uint committed tip,
 *            "t":uint tip block time (seconds),"cu":bool consensus latch,
 *            "e":uint last epoch boundary the tip has passed}
 *       {"q":"ipc_dht_sets"} →
 *           {"q","e":uint,"s0":[bstr 64 …] S(e),"s1":[bstr 64 …] S(e−E),
 *            "rg":[{"f":bstr 64,"st":uint 1|2} …] registry fp + status}
 *       {"q":"ipc_name","fp":bstr 64} →
 *           {"q","fp":bstr 64,"h":uint committed tip,"n":uint 0|1}
 *     Frames of this kind other than those three close the connection,
 *     as does a request frame longer than NODUS_WITNESS_IPC_CTL_FRAME_MAX.
 *
 * Anything else as a first frame — or a frame a connection's kind does not
 * serve — closes that connection. So does any frame that arrives while
 * that connection's own queue toward core is at
 * NODUS_WITNESS_IPC_REPLY_QUEUE_MAX (core has stopped reading it).
 *
 * This file includes no server header: the nodus-witness binary must not
 * link nodus_server.c (tests/split_linked.cmake).
 *
 * @file nodus_witness_ipc.h
 */

#ifndef NODUS_WITNESS_IPC_H
#define NODUS_WITNESS_IPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "nodus/nodus_types.h"
#include "protocol/nodus_tier2.h"           /* nodus_t2_status_info_t */
#include "dnac/ledger_roots_v2.h"           /* DNA_V2_STORAGE_SET_MAX */

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_tcp_conn;
struct nodus_witness;

/** The socket file, under the node's data_path. */
#define NODUS_WITNESS_IPC_SOCK_NAME   "witness.sock"

/** Frame methods ("q"). */
#define NODUS_WITNESS_IPC_Q_HELLO     "ipc_hello"
#define NODUS_WITNESS_IPC_Q_CTL       "ipc_ctl"
#define NODUS_WITNESS_IPC_Q_STATUS    "ipc_status"
#define NODUS_WITNESS_IPC_Q_DHT       "ipc_dht"
#define NODUS_WITNESS_IPC_Q_DHT_SNAP  "ipc_dht_snap"
#define NODUS_WITNESS_IPC_Q_DHT_SETS  "ipc_dht_sets"
#define NODUS_WITNESS_IPC_Q_NAME      "ipc_name"

/**
 * The ONE routing rule for client tier-2 methods the chain serves: the
 * `dnac_*` family and — Nodus EVM Faz 4 (design docs/plans/2026-10-04-nodus-evm-
 * chain-integration-design.md rev 3 §18) — the `evm_*` read RPC. The core
 * server (nodus_server.c dispatch_t2), the witness IPC session reader
 * (nodus_witness_ipc.c) and the witness dispatcher
 * (nodus_witness_handlers.c) all test THIS predicate, so a method family
 * cannot be routed by one hop and refused by the next.
 */
static inline bool nodus_chain_method_routed(const char *method) {
    if (!method) return false;
    return (method[0] == 'd' && method[1] == 'n' && method[2] == 'a' &&
            method[3] == 'c' && method[4] == '_') ||
           (method[0] == 'e' && method[1] == 'v' && method[2] == 'm' &&
            method[3] == '_');
}

/** Largest control frame either side builds (status answer ≈ 150 B). */
#define NODUS_WITNESS_IPC_CTL_FRAME_MAX  512

/*
 * Largest frame of the `ipc_dht` kind: the `ipc_dht_sets` answer, built with
 * N = DNA_V2_STORAGE_SET_MAX members in S(e), S(e − E) and the registry
 * (never a literal 256 — the cap moves with the chain, decision
 * 2026-10-22-storage-cap-1024-in-hf9.md). Bytes of the CBOR encoding:
 *
 *   map(5) header                                   1
 *   "q"  key 2 + tstr "ipc_dht_sets" 1 + 12        15
 *   "e"  key 2 + uint, 8-byte form 1 + 8           11
 *   "s0" key 3 + array header ≤ 65535 members 3     6
 *   "s1" key 3 + array header 3                     6
 *   "rg" key 3 + array header 3                     6
 *                                           fixed  45
 *   per member: s0 entry bstr(64) = 2 + 64         66
 *               s1 entry                           66
 *               rg row map(2) 1 + "f" 2 + bstr 66
 *                     + "st" 3 + uint 1..23 → 1    73
 *                                           total 205 per member
 *
 * DERIVED = 45 + 205·N  (N = 256: 52 525 B, the "≈ 52 KB" of row 13).
 * The bound is twice DERIVED rounded up to a whole 64 KiB — at N = 256
 * that is 128 KiB, row 13's figure; at N = 1024 it is 448 KiB. The
 * assertions below keep it ≥ DERIVED and inside the transport's frame cap.
 * The snap and name answers are far smaller (≈ 150 B) and fit it too.
 */
#define NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX \
    ((size_t)45 + (size_t)205 * (size_t)DNA_V2_STORAGE_SET_MAX)
#define NODUS_WITNESS_IPC_DHT_FRAME_MAX \
    ((((size_t)2 * NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX + 65535u) / 65536u) \
     * 65536u)

_Static_assert(DNA_V2_STORAGE_SET_MAX <= 65535u,
               "array headers above are the 3-byte form");
_Static_assert(NODUS_WITNESS_IPC_DHT_FRAME_MAX >=
                   NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX,
               "the ipc_dht frame bound is below the derived maximum");
_Static_assert(NODUS_WITNESS_IPC_DHT_FRAME_MAX <= NODUS_MAX_FRAME_TCP,
               "the ipc_dht frame bound exceeds the transport's frame cap");

/*
 * Per-connection queue bounds. "Queued" = the bytes one IPC connection
 * has for its peer that the kernel has not yet taken: the unsent part of
 * its write buffer plus its pending FIFO (nodus_tcp_conn_t
 * `wlen - wpos + pending_bytes`). Each bound is checked BEFORE a frame is
 * queued, never with the new frame's length added, so one frame of the
 * transport's largest size (NODUS_MAX_FRAME_TCP, 5 MiB) still goes onto
 * an idle connection.
 */

/**
 * Core side (server/nodus_chain_backend_ipc.c): a client `dnac_*` request
 * whose session socket has this much or more queued toward the witness is
 * answered NODUS_CHAIN_NO_WITNESS_MSG and NOT queued; the session socket
 * stays open and what it already carries is still delivered.
 *
 * Why 4 MiB: the transport grows a write buffer to one maximum frame
 * (~5 MiB, nodus_tcp.c buf_ensure) before it spills to the pending FIFO.
 * With the bound below that, a frame reaches the FIFO only while fewer
 * than 4 MiB are queued, and the next check then refuses — the FIFO holds
 * at most one frame, never NODUS_PENDING_MAX_FRAMES (20), so a send on a
 * session socket fails only on a real transport fault (allocation, peer
 * gone), never on capacity. Worst case per session: the bound plus one
 * maximum frame (~9 MiB) instead of the transport's ~37 MiB (5 MiB write
 * buffer + NODUS_PENDING_MAX_BYTES). At the size of today's `dnac_*`
 * requests (bytes to kilobytes) that is still hundreds of requests in
 * flight per session.
 */
#define NODUS_WITNESS_IPC_QUEUE_MAX        ((size_t)4 * 1024 * 1024)

/**
 * Witness side (nodus_witness_ipc.c): a frame read from a connection that
 * has this much or more of its replies queued toward core closes the
 * connection instead of being dispatched (see that file's "Bound" note).
 *
 * Why 16 MiB, larger than the core bound: requests are small but replies
 * are not — one `dnac_block` reply is up to NODUS_DNAC_V3_BLOCK_BUDGET_MAX
 * (1 MiB) of items, and a syncing client may pipeline several. Core reads
 * its IPC transport once per loop pass, so a burst of replies produced
 * within one witness poll must not trip the close; about 16 one-MiB
 * replies between two core reads still pass. It stays below the transport's own
 * per-connection ceiling (~5 MiB write buffer + 20 pending frames /
 * NODUS_PENDING_MAX_BYTES), past which the transport drops replies one by
 * one with only a log line.
 */
#define NODUS_WITNESS_IPC_REPLY_QUEUE_MAX  ((size_t)16 * 1024 * 1024)

/**
 * The socket path for `data_path` ("/tmp" when empty — where the server
 * puts its databases then). @return 0, or -1 when it does not fit `cap`.
 */
static inline int nodus_witness_ipc_sock_path(const char *data_path,
                                              char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/%s",
                     (data_path && data_path[0]) ? data_path : "/tmp",
                     NODUS_WITNESS_IPC_SOCK_NAME);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/** What the witness answers on the control connection. */
typedef struct {
    bool     chain_open;                 /* a chain database is open      */
    uint64_t height;                     /* status block_height           */
    uint8_t  state_root[64];             /* status state_root             */
    uint8_t  chain_id[32];               /* status chain_id (LEGACY: 16
                                          * bytes padded with zeros — the
                                          * T2 status RPC reports it)      */
    uint8_t  chain_id_v3[32];            /* c3 — the 32-byte v3 chain id
                                          * (nodus_witness_dht_chain_id),
                                          * all zero when there is none;
                                          * the session's chain id         */
    bool     p2p_opened;                 /* the 4004 p2p host exists      */
    uint16_t listen_port;                /* its bound port (0 = none)     */
} nodus_witness_ipc_status_t;

/** `ipc_dht_snap` (row 13). */
typedef struct {
    uint8_t  chain_id[32];               /* ci                            */
    uint64_t height;                     /* h  — committed tip            */
    uint64_t tip_time;                   /* t  — tip block time, seconds  */
    bool     consensus_up;               /* cu — latch: the witness
                                          * switched to consensus (or
                                          * started in it)                */
    uint64_t epoch_start;                /* e  — last boundary H the tip
                                          * has passed (tip − tip mod E)  */
} nodus_witness_dht_snap_t;

/** One registry row of `ipc_dht_sets` `rg`: fp + status, no public key. */
typedef struct {
    uint8_t fp[64];
    uint8_t status;                      /* DNA_V2_STORAGE_ACTIVE / _EXITING */
} nodus_witness_dht_row_t;

/** `ipc_dht_sets` (row 13). ~200 KB at 1024 members: heap-allocate it. */
typedef struct {
    uint64_t                e;
    uint32_t                n0;          /* members of s0                 */
    uint32_t                n1;          /* members of s1                 */
    uint32_t                nrg;         /* rows of rg                    */
    uint8_t                 s0[DNA_V2_STORAGE_SET_MAX][64];  /* S(e)     */
    uint8_t                 s1[DNA_V2_STORAGE_SET_MAX][64];  /* S(e − E) */
    nodus_witness_dht_row_t rg[DNA_V2_STORAGE_SET_MAX];
} nodus_witness_dht_sets_t;

/** `ipc_name` answer. */
typedef struct {
    uint64_t height;                     /* h — committed tip             */
    bool     named;                      /* n — the key has a name        */
} nodus_witness_dht_name_t;

/** Where the IPC listener hands its work. Production binds them to a
 *  witness (nodus_witness_ipc_handlers_for); tests bind their own. The
 *  three dht_* callbacks return 0 (answer filled) or -1 (node-local fault:
 *  the asker gets {err}); one left NULL closes the connection that sends
 *  that request. */
typedef struct {
    void (*dispatch_dnac)(void *ctx, struct nodus_tcp_conn *conn,
                          const uint8_t *payload, size_t len,
                          const char *method, uint32_t txn_id);
    void (*cc_collect)(void *ctx, struct nodus_tcp_conn *conn,
                       const uint8_t client_pk[NODUS_PK_BYTES],
                       const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                       const uint8_t *payload, size_t len,
                       uint32_t txn_id);
    void (*status)(void *ctx, nodus_witness_ipc_status_t *out);
    int  (*dht_snap)(void *ctx, nodus_witness_dht_snap_t *out);
    int  (*dht_sets)(void *ctx, nodus_witness_dht_sets_t *out);
    int  (*dht_name)(void *ctx, const uint8_t fp[64],
                     nodus_witness_dht_name_t *out);
    void  *ctx;
} nodus_witness_ipc_handlers_t;

typedef struct nodus_witness_ipc nodus_witness_ipc_t;

/**
 * The chain fields of a `status` reply (block_height, state_root,
 * chain_id) from witness `w`; `info` untouched when no chain is open.
 * The ONE fill both the in-process backend (inproc_status) and the
 * `ipc_status` answer use.
 */
void nodus_witness_status_fill(struct nodus_witness *w,
                               nodus_t2_status_info_t *info);

/**
 * The witness-side answers of the `ipc_dht` kind, as plain functions: the
 * IPC handlers call them, and so can an in-process caller (the combined
 * nodus-server has no witness.sock — compare nodus_witness_status_fill).
 * Each returns 0 (`out` filled) or -1 (no chain open, or a store fault:
 * never a partial answer). Reads only the committed tables; no clock.
 *
 *  snap: tip height, tip block time (nodus_witness_v2_tip_block_time),
 *        `cu` = the consensus node's cs_started (set exactly when
 *        cmt_cs_start has run, never cleared before release), `e` = tip −
 *        tip mod DNAC_EPOCH_LENGTH.
 *  sets: e as above; e = 0 → no members; e ≤ E → s1 empty; else S(e) and,
 *        for e > E, S(e − E) via nodus_witness_storage_set_get (absent or
 *        failing its hash check = -1); rg = registry rows ACTIVE and
 *        EXITING, node_fp ascending.
 *  name: the v2_names row of `fp` (handle_dnac_name_of's lookup): absent →
 *        named = false; present and valid → named = true; present but
 *        malformed, or the store unreadable → -1.
 */
/** The chain id the node sessions and the DHT v2 readers use: the 32-byte v3
 *  chain id (nodus_witness_v2_chain_id), NOT the legacy 16-byte id padded to
 *  32 that `status` reports. 0 and `out` filled; -1 when there is no open
 *  chain or no v3 id (never a zero id). The `ci` of ipc_dht_snap and the `c3`
 *  of ipc_status carry it. */
int nodus_witness_dht_chain_id(struct nodus_witness *w, uint8_t out[32]);
int nodus_witness_dht_snap_fill(struct nodus_witness *w,
                                nodus_witness_dht_snap_t *out);
int nodus_witness_dht_sets_fill(struct nodus_witness *w,
                                nodus_witness_dht_sets_t *out);
int nodus_witness_dht_name_fill(struct nodus_witness *w, const uint8_t fp[64],
                                nodus_witness_dht_name_t *out);

/** Handlers that serve witness `w` (it need not be initialised yet;
 *  it must be by the first nodus_witness_ipc_poll). */
void nodus_witness_ipc_handlers_for(struct nodus_witness *w,
                                    nodus_witness_ipc_handlers_t *out);

/** A listener not yet listening. NULL on allocation failure. */
nodus_witness_ipc_t *nodus_witness_ipc_new(const nodus_witness_ipc_handlers_t *h);

/** Open the socket (nodus_tcp_unix_listen, this euid only). 0 / -1. */
int nodus_witness_ipc_listen(nodus_witness_ipc_t *ipc, const char *path);

/** One pass of the socket's events, waiting up to `timeout_ms`. */
void nodus_witness_ipc_poll(nodus_witness_ipc_t *ipc, int timeout_ms);

/**
 * nodus_witness_host_t.find_session_conn for a witness served over IPC
 * (`ctx` = the nodus_witness_ipc_t): the session connection whose
 * preface named `pk` and `token`, or NULL once core has closed it.
 */
struct nodus_tcp_conn *nodus_witness_ipc_find_session_conn(
    void *ctx,
    const uint8_t pk[NODUS_PK_BYTES],
    const uint8_t token[NODUS_SESSION_TOKEN_LEN]);

/** Close every connection and the socket (its file is removed), free. */
void nodus_witness_ipc_free(nodus_witness_ipc_t *ipc);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_IPC_H */
