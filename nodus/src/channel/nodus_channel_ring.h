/**
 * Nodus -- Channel Ring Management via TCP 4003 Heartbeat
 *
 * Dead detection uses TCP 4003 heartbeat only.
 * Hashring always wins -- deterministic, no election.
 *
 * Flow:
 *   BACKUP-1 detects PRIMARY heartbeat timeout (45s)
 *   -> Sends ring_check to BACKUP-2
 *   -> BACKUP-2 confirms (ring_ack agree=true)
 *   -> Dead node removed, hashring recalculated
 *   -> ring_version++, announce to DHT, notify clients
 *
 * Rejoin:
 *   Returning node sends ring_rejoin
 *   -> Hashring recalculated with returning node
 *   -> Deterministic result decides positions
 *   -> ring_version++, announce + notify
 *
 * @file nodus_channel_ring.h
 */

#ifndef NODUS_CHANNEL_RING_H
#define NODUS_CHANNEL_RING_H

#include "channel/nodus_channel_server.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_CH_RING_MAX_TRACKED      256
#define NODUS_CH_RING_CHECK_TIMEOUT_MS 10000  /* 10 seconds for ring_check response */

/* Tracked channel with ring state */
typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint32_t    ring_version;
    bool        active;

    /* Dead detection state */
    bool        check_pending;       /* Waiting for ring_ack */
    nodus_key_t check_node_id;       /* Node being checked */
    uint64_t    check_sent_at_ms;    /* When ring_check was sent */
} nodus_ch_ring_channel_t;

typedef struct {
    nodus_channel_server_t     *cs;
    nodus_ch_ring_channel_t     channels[NODUS_CH_RING_MAX_TRACKED];
    int                         channel_count;
    uint64_t                    last_tick_ms;
} nodus_ch_ring_t;

/** Initialize ring management. */
void nodus_ch_ring_init(nodus_ch_ring_t *rm, nodus_channel_server_t *cs);

/** Track a channel this node is responsible for. */
int nodus_ch_ring_track(nodus_ch_ring_t *rm,
                         const uint8_t channel_uuid[NODUS_UUID_BYTES],
                         uint32_t ring_version);

/** Untrack a channel. */
void nodus_ch_ring_untrack(nodus_ch_ring_t *rm,
                            const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/** Check if channel is tracked. */
bool nodus_ch_ring_is_tracked(const nodus_ch_ring_t *rm,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/**
 * Periodic tick (call every ~5s from main loop).
 * - Check heartbeat timeouts on node sessions
 * - If node dead (no heartbeat for >HEARTBEAT_TIMEOUT):
 *   For each tracked channel where dead node is responsible:
 *   Send ring_check to other responsible node
 * - Handle check timeouts (no ring_ack response)
 */
void nodus_ch_ring_tick(nodus_ch_ring_t *rm, uint64_t now_ms);

/**
 * Handle ring_check from peer: "Is node X dead?"
 * Check own heartbeat state for node X.
 * Respond with ring_ack(agree=true/false).
 */
int nodus_ch_ring_handle_check(nodus_ch_ring_t *rm,
                                nodus_ch_node_session_t *from,
                                const nodus_key_t *node_id,
                                const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/**
 * Handle ring_ack from peer.
 * If agree=true: remove dead node from hashring, recalculate,
 * ring_version++, announce to DHT, notify clients.
 */
int nodus_ch_ring_handle_ack(nodus_ch_ring_t *rm,
                              const uint8_t channel_uuid[NODUS_UUID_BYTES],
                              bool agree);

/**
 * Handle ring_evict: this node removed from channel responsibility.
 * Notify subscribed clients (ch_ring_changed), untrack channel.
 */
int nodus_ch_ring_handle_evict(nodus_ch_ring_t *rm,
                                const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                uint32_t new_version);

/**
 * Handle ring_rejoin: a returning node wants back in.
 * Recalculate hashring with returning node.
 * Hashring always wins -- deterministic positions.
 */
int nodus_ch_ring_handle_rejoin(nodus_ch_ring_t *rm,
                                 nodus_ch_node_session_t *from,
                                 const nodus_key_t *rejoining_node_id,
                                 uint32_t their_ring_version);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHANNEL_RING_H */
