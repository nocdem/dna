/**
 * Nodus — Server-Side Presence Table
 *
 * Tracks which clients are connected to this node and across the cluster.
 * Local entries (peer_index=0) are set on auth, cleared on disconnect.
 * Remote entries come from inter-node p_sync messages and expire after TTL.
 *
 * @file nodus_presence.h
 */

#ifndef NODUS_PRESENCE_H
#define NODUS_PRESENCE_H

#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_PRESENCE_MAX_ENTRIES  2048
#define NODUS_PRESENCE_REMOTE_TTL   45   /* seconds — remote entry expiry */
#define NODUS_PRESENCE_SYNC_SEC     30   /* inter-node sync interval */

typedef struct {
    nodus_key_t  client_fp;       /* 64-byte fingerprint */
    uint8_t      peer_index;      /* 0 = local, 1..N = cluster peer index + 1 */
    uint64_t     last_seen;       /* Unix timestamp */
    bool         active;
} nodus_presence_entry_t;

typedef struct {
    nodus_presence_entry_t entries[NODUS_PRESENCE_MAX_ENTRIES];
    int      count;
    uint64_t last_sync;           /* Last time we broadcast to peers */
} nodus_presence_table_t;

struct nodus_server;
struct nodus_tcp_conn;

/** Add a locally-connected client to the presence table. */
void nodus_presence_add_local(struct nodus_server *srv, const nodus_key_t *fp);

/** Remove a locally-connected client from the presence table. */
void nodus_presence_remove_local(struct nodus_server *srv, const nodus_key_t *fp);

/** Merge remote fingerprints received from a peer node. */
void nodus_presence_merge_remote(struct nodus_server *srv, const nodus_key_t *fps,
                                   int count, uint8_t peer_index);

/** Check if a fingerprint is online anywhere in the cluster. */
bool nodus_presence_is_online(struct nodus_server *srv, const nodus_key_t *fp,
                                uint8_t *peer_index_out);

/** Batch query: check online status + last_seen for N fingerprints. */
int nodus_presence_query_batch(struct nodus_server *srv, const nodus_key_t *fps,
                                 int fp_count, bool *online_out, uint8_t *peers_out,
                                 uint64_t *last_seen_out);

/** Expire stale remote entries. */
void nodus_presence_expire(struct nodus_server *srv, uint64_t now);

/** Get all locally-connected fingerprints. */
int nodus_presence_get_local(struct nodus_server *srv, nodus_key_t *fps_out,
                               int max_count);

/** Periodic tick: expire + broadcast local list to peers. */
void nodus_presence_tick(struct nodus_server *srv);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_PRESENCE_H */
