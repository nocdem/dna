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
#include <string.h>

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

/* The active-role set a backend keeps (the node ids of every identity with an
 * active on-chain role). A set older than NODUS_ROLE_SET_STALE_MS is unknown:
 * nothing is exempted from it (fail safe). */
#define NODUS_ROLE_SET_MAX       2048u
#define NODUS_ROLE_SET_STALE_MS  30000u
#define NODUS_ROLE_SET_EVERY_MS  10000u
typedef struct {
    uint8_t (*fps)[64];     /* NODUS_ROLE_SET_MAX entries, heap, owned */
    uint32_t n;
    bool     known;
    uint64_t at_ms;         /* nodus_time_mono_ms() when it was taken */
} nodus_role_set_t;

/** `s` is a known, fresh set as of `now_ms` (monotonic). */
static inline bool nodus_role_set_known(const nodus_role_set_t *s, uint64_t now_ms) {
    return s && s->known && s->fps && now_ms - s->at_ms <= NODUS_ROLE_SET_STALE_MS;
}

/** `node_id` is in a known, fresh `s` as of `now_ms` (monotonic). */
static inline bool nodus_role_set_has(const nodus_role_set_t *s,
                                      const nodus_key_t *node_id,
                                      uint64_t now_ms) {
    if (!s || !s->known || !s->fps || !node_id) return false;
    if (now_ms - s->at_ms > NODUS_ROLE_SET_STALE_MS) return false;
    for (uint32_t i = 0; i < s->n; i++)
        if (memcmp(s->fps[i], node_id->bytes, 64) == 0) return true;
    return false;
}

typedef struct {
    /** One pass of the chain's own work (the 4004 p2p host and the
     *  consensus lane) — once per server loop iteration. */
    void (*tick)(nodus_chain_backend_t *b);

    /** true while the backend's own transport has connections left on its
     *  pending-read list (nodus_tcp_read_pending): the server's loop then
     *  waits 0 ms in its other polls, so that input is not held behind a
     *  50 ms wait (the nodus_tcp.h read-budget rule). In-process: always
     *  false — the witness polls its 4004 host inside `tick`, and the
     *  server's poll timings stay exactly what they were. IPC: the
     *  backend's Unix-socket transport. */
    bool (*read_pending)(nodus_chain_backend_t *b);

    /** Fill the chain fields of a `status` reply (block_height,
     *  state_root, chain_id); untouched when no chain is open. */
    void (*status)(nodus_chain_backend_t *b, nodus_t2_status_info_t *info);

    /** The 32-byte v3 chain id the node's sessions (4001 / WS / 4002) are
     *  bound to — the id 4004's HELLO carries and every client knows — NOT
     *  the legacy 16-byte id padded with zeros that `status` reports (the T2
     *  `status` RPC keeps reporting that one, unchanged). true with `out`
     *  filled; false while there is none (no chain open, no genesis document
     *  yet, the witness not answering): sessions are then refused. May be NULL
     *  (= false). */
    bool (*chain_id_v3)(nodus_chain_backend_t *b, uint8_t out[32]);

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

    /** true when `node_id` (the SHA3-512 fingerprint of a PROVEN public key)
     *  has an active on-chain role — the bonded set plus the storage
     *  registry rows ACTIVE / EXITING (nodus_witness_p2p_roles_fill). Used to
     *  exempt that node from the per-IP limits of 4001 / WS / 4002
     *  (decisions/2026-10-24-dht-v2-handshake-rate.md addendum 2026-10-26).
     *  FAIL SAFE: false whenever the set is not known (no chain, witness not
     *  answering, set older than NODUS_ROLE_SET_STALE_MS, set over its
     *  bound). May be NULL (= false). */
    bool (*has_role)(nodus_chain_backend_t *b, const nodus_key_t *node_id);

    /** true when the role set is KNOWN and fresh right now (the same
     *  condition has_role answers from). Lets the caller tell "this identity
     *  has no role" from "the set is unknown": core revalidates the
     *  exemptions of live connections only against a known set, so an IPC
     *  hiccup does not drop every node at once. May be NULL (= false). */
    bool (*roles_known)(nodus_chain_backend_t *b);

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
 * session's first `dnac_*` request, and only while the control connection
 * is up. A witness that is not running costs nothing but the
 * NODUS_CHAIN_NO_WITNESS_MSG error to the requester. Each session socket
 * holds at most NODUS_WITNESS_IPC_QUEUE_MAX queued bytes; a request past
 * that gets the same error and the socket stays open.
 * @return 0 `*out` set; -1 bad argument or socket path too long;
 *         -2 out of memory.
 */
int nodus_chain_backend_ipc_open(const char *data_path,
                                 nodus_chain_backend_t **out);

/** TEST SEAM (not an API): send an ipc_roles query on the control connection
 *  now, instead of waiting NODUS_ROLE_SET_EVERY_MS. No-op without a control
 *  connection. */
void nodus_chain_backend_ipc_test_ask_roles(nodus_chain_backend_t *b);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHAIN_BACKEND_H */
