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

    /** A `dnac_*` client method (post-auth). */
    void (*dispatch_dnac)(nodus_chain_backend_t *b,
                          struct nodus_tcp_conn *conn,
                          const uint8_t *payload, size_t len,
                          const char *method, uint32_t txn_id);

    /** `dnac_cc_collect`, with the requesting session's identity. */
    void (*cc_collect)(nodus_chain_backend_t *b,
                       struct nodus_tcp_conn *conn,
                       const uint8_t client_pk[NODUS_PK_BYTES],
                       const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                       const uint8_t *payload, size_t len,
                       uint32_t txn_id);

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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHAIN_BACKEND_H */
