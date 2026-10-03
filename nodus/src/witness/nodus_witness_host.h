/**
 * Nodus — Witness host interface
 *
 * The ONE view the witness module has of the process it runs in
 * (decision docs/plans/decisions/2026-10-01-nodus-component-split.md,
 * step S1 "witness seam"): this node's identity, the subset of the node
 * configuration the witness reads, and the lookup of a still-open client
 * session. The witness takes no nodus_server_t and includes no server
 * header; whoever hosts it fills this struct before nodus_witness_init.
 *
 * The combined nodus-server fills it from its own server
 * (nodus_server_witness_host, nodus_server.c): `identity` points at the
 * server's identity, `config` is copied from the server config — which
 * nodus_server_init sets once and never changes in any field below — and
 * `find_session_conn` is the server's session-table lookup.
 *
 * @file nodus_witness_host.h
 */

#ifndef NODUS_WITNESS_HOST_H
#define NODUS_WITNESS_HOST_H

#include <stdbool.h>
#include <stdint.h>

#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include "witness/nodus_witness_p2p.h"      /* nodus_p2p_config_t */

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_tcp_conn;

/**
 * Marker file written by the witness module when the chain DB is first
 * created (nodus_witness_create_chain_db on genesis commit). Its
 * presence under <data_path> means "this node has crossed the genesis
 * boundary at least once" and is the signal that allows the
 * partial-wipe gate (nodus_server_check_partial_wipe) to enforce its
 * strict invariant.
 *
 * Without this marker, the gate cannot distinguish two file-level
 * indistinguishable states:
 *   - fresh node mid-bootstrap (storage opens populated nodus.db +
 *     channels.db before FETCH_GENESIS lands the first witness DB)
 *   - post-genesis node where the operator wiped only witness_*.db
 * Both look like (nodus=Y, channels=Y, witness=N) on disk.
 *
 * The marker is itself wipeable. Threat model: catches operator
 * MISTAKES (rm of one DB by accident), not a determined adversary
 * (who would just wipe everything → fresh state → bootstrap, the
 * intended recovery path).
 *
 * Defined here, on the witness side, because the witness writes it too;
 * the server (which also writes it at the end of nodus_server_init and
 * reads it in the gate) includes it from here — the name is unchanged.
 */
#define NODUS_PARTIAL_WIPE_GENESIS_MARKER  ".witness_db_seen"

/** The node configuration the witness reads — nothing else. */
typedef struct {
    char                bind_ip[64];        /* 4004 listen address        */
    char                external_ip[64];    /* advertised; "" = bind_ip   */
    uint16_t            witness_port;       /* 0 = NODUS_DEFAULT_WITNESS_PORT */
    char                data_path[256];     /* chain DBs, cs.wal, sentinels */
    /* Directory of the p2p address-record sequence file
     * (NODUS_P2P_ADDR_SEQ_FILE); "" = data_path. The combined binary
     * fills it with its identity_path, where the file lives today. */
    char                seq_dir[256];
    nodus_p2p_config_t  p2p;                /* the 4004 p2p section       */
    /* Joiner pin (operator-supplied, never wire-settable). */
    bool                has_v2_genesis_pin;
    uint8_t             v2_genesis_pin[32];
    /* Node-local address history index (default OFF). */
    bool                addr_history_index;
} nodus_witness_host_config_t;

/**
 * The connection of the client session authenticated as `pk` with session
 * token `token`, or NULL when that session is gone, re-authenticated or
 * never existed. Used for replies the witness sends later than the
 * request (dnac_cc_collect).
 */
typedef struct nodus_tcp_conn *(*nodus_witness_find_session_conn_fn)(
    void *ctx,
    const uint8_t pk[NODUS_PK_BYTES],
    const uint8_t token[NODUS_SESSION_TOKEN_LEN]);

typedef struct nodus_witness_host {
    /* This node's identity (non-owning; outlives the witness). */
    const nodus_identity_t             *identity;
    nodus_witness_host_config_t         config;
    nodus_witness_find_session_conn_fn  find_session_conn;
    void                               *ctx;     /* find_session_conn's */
} nodus_witness_host_t;

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_HOST_H */
