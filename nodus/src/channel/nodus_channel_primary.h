/**
 * Nodus -- Channel Primary Role Logic
 *
 * Handles all operations when this node is PRIMARY for a channel:
 * accepting posts, verifying signatures, storing, pushing to
 * subscribers, triggering replication, and announcing to DHT.
 *
 * Flow: Client -> TCP 4003 -> PRIMARY
 *   1. Verify Dilithium5 signature
 *   2. Store in local SQLite
 *   3. Send ch_post_ok to client
 *   4. Push to ALL subscribed clients (ch_post_notify)  <- FIRST
 *   5. Trigger replication to BACKUPs                   <- AFTER (via callback)
 *
 * @file nodus_channel_primary.h
 */

#ifndef NODUS_CHANNEL_PRIMARY_H
#define NODUS_CHANNEL_PRIMARY_H

#include "channel/nodus_channel_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Handle ch_create from client.
 * Create channel table, track in ring, announce to DHT.
 */
int nodus_ch_primary_handle_create(nodus_channel_server_t *cs,
                                    nodus_ch_client_session_t *sess,
                                    const nodus_tier2_msg_t *msg);

/**
 * Handle ch_post from client.
 * Verify sig -> store -> respond -> push subscribers -> trigger replication callback.
 */
int nodus_ch_primary_handle_post(nodus_channel_server_t *cs,
                                  nodus_ch_client_session_t *sess,
                                  const nodus_tier2_msg_t *msg);

/**
 * Handle ch_get from client.
 * Return posts since received_at.
 */
int nodus_ch_primary_handle_get(nodus_channel_server_t *cs,
                                 nodus_ch_client_session_t *sess,
                                 const nodus_tier2_msg_t *msg);

/**
 * Handle ch_sub from client.
 */
int nodus_ch_primary_handle_subscribe(nodus_channel_server_t *cs,
                                       nodus_ch_client_session_t *sess,
                                       const nodus_tier2_msg_t *msg);

/**
 * Handle ch_unsub from client.
 */
int nodus_ch_primary_handle_unsubscribe(nodus_channel_server_t *cs,
                                         nodus_ch_client_session_t *sess,
                                         const nodus_tier2_msg_t *msg);

/**
 * Announce channel's responsible set to DHT (ordered list).
 * DHT key: SHA3-512("dna:channel:nodes:" + channel_uuid)
 * Value: CBOR {version, nodes: [{ip, port, nid}, ...]}
 * List order: [PRIMARY, BACKUP-1, BACKUP-2] (hashring deterministic order)
 */
int nodus_ch_primary_announce_to_dht(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/**
 * Ensure channel table exists locally. Create if self is in responsible set.
 * Returns true if channel is ready for operations.
 */
bool nodus_ch_primary_ensure_channel(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHANNEL_PRIMARY_H */
