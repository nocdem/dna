/**
 * Nodus — Circuit Table (per-session, VPN mesh Faz 1)
 *
 * Each TCP 4001 session owns a fixed-size circuit table.
 * Circuits are either "local bridge" (peer user on same nodus) or
 * "inter-node" (peer user on different nodus, forwarded via TCP 4002).
 *
 * @file nodus_circuit.h
 */

#ifndef NODUS_CIRCUIT_H
#define NODUS_CIRCUIT_H

#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decls to avoid header coupling */
struct nodus_session;
struct nodus_inter_circuit;

typedef struct {
    uint64_t                    local_cid;
    bool                        in_use;
    bool                        is_local_bridge;

    /* Local bridge fields (peer user on same nodus) */
    struct nodus_session       *bridge_peer_sess;
    uint64_t                    bridge_peer_cid;

    /* Inter-node fields (peer user on remote nodus) */
    struct nodus_inter_circuit *inter;

    uint64_t                    created_at_ms;
} nodus_circuit_t;

typedef struct {
    nodus_circuit_t entries[NODUS_MAX_CIRCUITS_PER_SESSION];
    int             count;
    uint64_t        next_cid_gen;   /* Monotonic local_cid generator */
} nodus_circuit_table_t;

/** Zero table and initialize generator. */
void nodus_circuit_table_init(nodus_circuit_table_t *t);

/** Allocate a free slot; returns NULL if full. Assigns unique local_cid. */
nodus_circuit_t *nodus_circuit_alloc(nodus_circuit_table_t *t);

/** Look up circuit by local_cid. Returns NULL if not found. */
nodus_circuit_t *nodus_circuit_lookup(nodus_circuit_table_t *t, uint64_t local_cid);

/** Free a circuit entry (by local_cid). No-op if not found. */
void nodus_circuit_free(nodus_circuit_table_t *t, uint64_t local_cid);

/** Current number of in-use entries. */
int nodus_circuit_count(const nodus_circuit_table_t *t);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CIRCUIT_H */
