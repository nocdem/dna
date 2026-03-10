/**
 * Nodus — Async Channel Replication
 *
 * After a Primary stores a channel post, replicate to Backup nodes.
 * Uses hinted handoff when backups are unreachable.
 * Retry every 30s, max 1000 pending posts, 24h TTL.
 *
 * @file nodus_replication.h
 */

#ifndef NODUS_REPLICATION_H
#define NODUS_REPLICATION_H

#include "nodus/nodus_types.h"
#include "channel/nodus_hashring.h"
#include "channel/nodus_channel_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nodus_server nodus_server_t;

typedef struct {
    nodus_server_t       *srv;           /* Back-reference to server */
    uint64_t              last_retry;    /* Last hinted handoff retry (unix ts) */
} nodus_replication_t;

/**
 * Initialize the replication module.
 * @param rep  Replication context
 * @param srv  Server (provides ring, ch_store, identity)
 */
void nodus_replication_init(nodus_replication_t *rep, nodus_server_t *srv);

/**
 * Replicate a channel post to backup nodes.
 * Called after Primary stores the post. Sends to each backup;
 * on failure queues to hinted handoff.
 *
 * @param rep   Replication context
 * @param uuid  Channel UUID (16 bytes)
 * @param post  Post to replicate (body must be valid)
 */
void nodus_replication_send(nodus_replication_t *rep,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             const nodus_channel_post_t *post);

/**
 * Retry hinted handoff entries. Called periodically from server loop.
 * Attempts to send queued posts to their target nodes.
 */
void nodus_replication_retry(nodus_replication_t *rep);

/**
 * Handle a received ch_rep message (on the receiving/backup side).
 * Creates channel table if needed and stores the post.
 *
 * @param ch_store  Channel storage
 * @param post      Post to store (from decoded ch_rep message)
 * @return 0 on success, 1 on duplicate, -1 on error
 */
int nodus_replication_receive(nodus_channel_store_t *ch_store,
                               nodus_channel_post_t *post);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_REPLICATION_H */
