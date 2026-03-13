/**
 * Nodus -- Channel Replication (TCP 4003)
 *
 * PRIMARY -> BACKUP replication over TCP 4003.
 * Hinted handoff for failed replications (SQLite queue, 30s retry, 24h TTL).
 * Incremental sync for new nodes joining the ring (last 1 day of posts).
 *
 * @file nodus_channel_replication.h
 */

#ifndef NODUS_CHANNEL_REPLICATION_H
#define NODUS_CHANNEL_REPLICATION_H

#include "channel/nodus_channel_server.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    nodus_channel_server_t *cs;
    uint64_t                last_retry_ms;
} nodus_ch_replication_t;

/** Initialize replication module. */
void nodus_ch_replication_init(nodus_ch_replication_t *rep,
                                nodus_channel_server_t *cs);

/**
 * Replicate a post to BACKUP nodes.
 * Called by PRIMARY after storing post locally and pushing to subscribers.
 * Sends ch_replicate to each authenticated BACKUP node session.
 * On failure: queues to hinted handoff.
 */
int nodus_ch_replication_send(nodus_ch_replication_t *rep,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES],
                               const nodus_channel_post_t *post,
                               const nodus_pubkey_t *author_pk);

/**
 * Handle incoming ch_replicate on BACKUP node.
 * Store post locally (dedup by post_uuid via INSERT OR IGNORE).
 */
int nodus_ch_replication_receive(nodus_ch_replication_t *rep,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post);

/**
 * Retry hinted handoff entries. Call periodically (every 30s).
 * Cleans up expired entries, retries delivery to BACKUP node sessions.
 */
void nodus_ch_replication_retry(nodus_ch_replication_t *rep, uint64_t now_ms);

/**
 * Handle ch_sync_request from new node joining ring.
 * Sends last 1 day of posts for the requested channel.
 */
int nodus_ch_replication_handle_sync_request(nodus_ch_replication_t *rep,
                                              nodus_ch_node_session_t *from,
                                              const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                              uint64_t since_ms);

/**
 * Handle ch_sync_response (received posts from PRIMARY during sync).
 * Store each post locally (INSERT OR IGNORE for dedup).
 */
int nodus_ch_replication_handle_sync_response(nodus_ch_replication_t *rep,
                                               const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                               const nodus_channel_post_t *posts,
                                               size_t count);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHANNEL_REPLICATION_H */
