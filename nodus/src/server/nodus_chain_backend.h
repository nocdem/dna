/**
 * Nodus — Chain backend (the server's ONE door to the witness)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md, step
 * S1 "witness seam": every call nodus_server.c makes into the witness
 * module goes through this interface, so the server's translation unit
 * references no witness symbol. Each operation below is one call site
 * the server had before the seam; none adds behaviour.
 *
 * Implementations:
 *   - nodus_chain_backend_inproc.c — the witness in this process (the
 *     combined nodus-server). Calls the witness functions directly.
 *   - nodus_chain_backend_ipc.c — split S3: the witness is the separate
 *     `nodus-witness` process, reached over the Unix socket
 *     <data_path>/NODUS_WITNESS_IPC_SOCK_NAME (witness/nodus_witness_ipc.h;
 *     nodus.json "witness_external": true).
 *
 * A server with no chain backend (`srv->chain == NULL`: the witness
 * failed to initialise) serves no `dnac_*` method and reports no chain
 * in `status`, exactly as a server with no witness did.
 *
 * @file nodus_chain_backend.h
 */

#ifndef NODUS_CHAIN_BACKEND_H
#define NODUS_CHAIN_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus_types.h"
#include "protocol/nodus_tier2.h"           /* nodus_t2_status_info_t */
#include "witness/nodus_witness_host.h"
#include "witness/nodus_witness.h"          /* nodus_witness_config_t */

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_tcp_conn;

/* The error text (code NODUS_ERR_PROTOCOL_ERROR) a `dnac_*` request gets
 * when no witness can serve it (decision 2026-10-01-nodus-component-split
 * item 20): a server without a chain backend (nodus_server.c dispatch_t2)
 * and the IPC backend when nodus-witness cannot be reached answer the
 * same bytes. */
#define NODUS_CHAIN_NO_WITNESS_MSG  "witness module not enabled"

typedef struct nodus_chain_backend nodus_chain_backend_t;

typedef struct {
    /** One pass of the chain's own work (the 4004 p2p host and the
     *  consensus lane) — once per server loop iteration. */
    void (*tick)(nodus_chain_backend_t *b);

    /** Fill the chain fields of a `status` reply (block_height,
     *  state_root, chain_id); untouched when no chain is open. */
    void (*status)(nodus_chain_backend_t *b, nodus_t2_status_info_t *info);

    /** true when a chain database is open (arms the partial-wipe gate). */
    bool (*chain_open)(nodus_chain_backend_t *b);

    /** The bound 4004 port (0 when none); `*opened` = the p2p host exists. */
    int  (*listen_port)(nodus_chain_backend_t *b, bool *opened);

    /** A `dnac_*` client method (post-auth). `client_pk` / `token` are
     *  the requesting session's key and session token: the in-process
     *  witness does not read them (it reads `conn`); the IPC backend
     *  sends them in the session socket's preface. */
    void (*dispatch_dnac)(nodus_chain_backend_t *b,
                          struct nodus_tcp_conn *conn,
                          const uint8_t client_pk[NODUS_PK_BYTES],
                          const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                          const uint8_t *payload, size_t len,
                          const char *method, uint32_t txn_id);

    /** `dnac_cc_collect`, with the requesting session's identity. */
    void (*cc_collect)(nodus_chain_backend_t *b,
                       struct nodus_tcp_conn *conn,
                       const uint8_t client_pk[NODUS_PK_BYTES],
                       const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                       const uint8_t *payload, size_t len,
                       uint32_t txn_id);

    /** The client session in `conn`'s slot ended (disconnect, eviction,
     *  idle sweep) or that slot starts a new session — called where the
     *  server clears a session. Requests the witness answers later
     *  (dnac_cc_collect) must then find no session (`find_session_conn`
     *  → NULL). In-process: nothing to do (the witness looks the session
     *  up in the server's own table). IPC: closes that session's socket. */
    void (*session_closed)(nodus_chain_backend_t *b,
                           struct nodus_tcp_conn *conn);

    /** Stop the chain and free the backend (`b` is invalid afterwards). */
    void (*close)(nodus_chain_backend_t *b);
} nodus_chain_backend_ops_t;

struct nodus_chain_backend {
    const nodus_chain_backend_ops_t *ops;
};

/* ── In-process implementation (nodus_chain_backend_inproc.c) ─────── */

/**
 * The network file's pin-at-start check (nodus_witness_check_chain_pin),
 * for the server to run before it opens any database or socket.
 * @return 0 no chain database present, or it matches; -1 refuse to start.
 */
int nodus_chain_backend_inproc_check_pin(const char *data_path,
                                         const uint8_t pin[32]);

/**
 * Start the witness in this process. `host` is copied into the backend
 * (the witness keeps a pointer to that copy); `host->identity` must
 * outlive the backend.
 * @return  0 started, `*out` set;
 *         -1 the witness refused to initialise (its own log says why) —
 *            nothing is left allocated, `*out` is NULL;
 *         -2 out of memory, `*out` is NULL.
 */
int nodus_chain_backend_inproc_open(const nodus_witness_host_t *host,
                                    const nodus_witness_config_t *config,
                                    nodus_chain_backend_t **out);

/* ── IPC implementation (nodus_chain_backend_ipc.c) — split S3 ─────── */

/**
 * The most client sessions that hold a socket to nodus-witness at once.
 * Both ends' transport pools hold NODUS_TCP_MAX_CONNS (1024) connections;
 * the witness end must also fit the control connection and the session
 * sockets this server has closed but the witness has not yet seen close
 * (it notices on its next poll). 64 slots are kept for those; a session
 * beyond the cap gets the NODUS_CHAIN_NO_WITNESS_MSG error instead of a
 * socket the witness would drop unaccepted.
 */
#define NODUS_CHAIN_IPC_MAX_SESSION_CONNS  (NODUS_TCP_MAX_CONNS - 64)

/**
 * Reach the witness of the separate `nodus-witness` process over the Unix
 * socket <data_path>/NODUS_WITNESS_IPC_SOCK_NAME ("/tmp" when data_path is
 * empty, as the server's own databases). Opens no socket yet: the control
 * connection is dialled on the first `tick` and re-dialled with bounded
 * backoff whenever it is down; a session's socket is dialled on that
 * session's first `dnac_*` request. A witness that is not running costs
 * nothing but the NODUS_CHAIN_NO_WITNESS_MSG error to the requester.
 * @return 0 `*out` set; -1 bad argument or socket path too long;
 *         -2 out of memory.
 */
int nodus_chain_backend_ipc_open(const char *data_path,
                                 nodus_chain_backend_t **out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHAIN_BACKEND_H */
