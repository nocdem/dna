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
 * serve — closes that connection.
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

/** Largest control frame either side builds (status answer ≈ 150 B). */
#define NODUS_WITNESS_IPC_CTL_FRAME_MAX  512

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
