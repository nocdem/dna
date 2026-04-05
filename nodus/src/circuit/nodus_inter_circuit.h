/**
 * Nodus — Inter-Node Circuit Table (global, VPN mesh Faz 1)
 *
 * Tracks cross-nodus circuits this server participates in.
 * Originator side: we hold upstream cid, forward to local user session.
 * Target side: we receive ri_open, attach to target user's local session.
 *
 * @file nodus_inter_circuit.h
 */

#ifndef NODUS_INTER_CIRCUIT_H
#define NODUS_INTER_CIRCUIT_H

#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_session;
struct nodus_tcp_conn;

typedef struct nodus_inter_circuit {
    uint64_t              our_cid;         /* ID the peer uses to address us */
    uint64_t              peer_cid;        /* ID we use when forwarding to peer */
    struct nodus_tcp_conn *peer_conn;      /* Inter-node TCP 4002 link */
    struct nodus_session  *local_sess;     /* Attached local user session (may be NULL) */
    uint64_t              local_cid;       /* cid on local session */
    bool                  is_originator;   /* true = we opened the circuit outbound */
    bool                  in_use;
    /* Originator-side pending state (T8b) */
    bool                  pending_open;    /* true while awaiting ri_open_ok */
    uint32_t              client_txn_id;   /* client's txn_id for the circ_open */
} nodus_inter_circuit_t;

typedef struct {
    nodus_inter_circuit_t entries[NODUS_INTER_CIRCUITS_MAX];
    int                   count;
    uint64_t              next_our_cid_gen;
} nodus_inter_circuit_table_t;

void nodus_inter_circuit_table_init(nodus_inter_circuit_table_t *t);

/** Allocate a free entry; assigns unique our_cid. Returns NULL if full. */
nodus_inter_circuit_t *nodus_inter_circuit_alloc(nodus_inter_circuit_table_t *t);

/** Lookup by our_cid (what peer uses to address us). */
nodus_inter_circuit_t *nodus_inter_circuit_lookup(nodus_inter_circuit_table_t *t,
                                                    uint64_t our_cid);

/** Free entry by our_cid. */
void nodus_inter_circuit_free(nodus_inter_circuit_table_t *t, uint64_t our_cid);

int nodus_inter_circuit_count(const nodus_inter_circuit_table_t *t);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_INTER_CIRCUIT_H */
