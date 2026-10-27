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
 * Two kinds of connection, told apart by their FIRST frame:
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
    uint8_t  chain_id[32];               /* status chain_id               */
    bool     p2p_opened;                 /* the 4004 p2p host exists      */
    uint16_t listen_port;                /* its bound port (0 = none)     */
} nodus_witness_ipc_status_t;

/** Where the IPC listener hands its work. Production binds them to a
 *  witness (nodus_witness_ipc_handlers_for); tests bind their own. */
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
