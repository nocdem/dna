/**
 * Nodus — Channel Ring Management
 *
 * Handles ring_check/ring_ack protocol for channel responsibility changes.
 * When PBFT detects a node going DEAD, remaining responsible nodes confirm
 * and update the ring + DHT announcement.
 *
 * @file nodus_ring_mgmt.h
 */

#ifndef NODUS_RING_MGMT_H
#define NODUS_RING_MGMT_H

#include "nodus/nodus_types.h"
#include "channel/nodus_hashring.h"
#include "transport/nodus_tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_RING_MGMT_MAX_CHANNELS 256  /* Max tracked channels */
#define NODUS_RING_MGMT_TICK_SEC     5    /* Seconds between ring checks */
#define NODUS_RING_CHECK_TIMEOUT_SEC 10   /* Timeout for pending ring_check */

struct nodus_server;

/** Per-channel ring tracking */
typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint32_t    ring_version;
    bool        active;
    /* Pending ring_check state */
    bool        check_pending;
    nodus_key_t check_node_id;      /* Node being checked */
    bool        check_is_dead;      /* true = checking if dead, false = alive */
    uint64_t    check_sent_at;      /* For timeout */
} nodus_ring_channel_t;

/** Ring management state */
typedef struct {
    struct nodus_server     *srv;
    nodus_ring_channel_t     channels[NODUS_RING_MGMT_MAX_CHANNELS];
    int                      channel_count;
    uint64_t                 last_check_tick;
} nodus_ring_mgmt_t;

/** Initialize ring management */
void nodus_ring_mgmt_init(nodus_ring_mgmt_t *mgmt, struct nodus_server *srv);

/** Register a channel this node is responsible for */
int nodus_ring_mgmt_track(nodus_ring_mgmt_t *mgmt,
                            const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/** Untrack a channel (no longer responsible) */
void nodus_ring_mgmt_untrack(nodus_ring_mgmt_t *mgmt,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/** Check if a channel is tracked */
bool nodus_ring_mgmt_is_tracked(const nodus_ring_mgmt_t *mgmt,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/** Called on PBFT tick — check for dead peers, initiate ring_check if needed */
void nodus_ring_mgmt_tick(nodus_ring_mgmt_t *mgmt);

/** Handle incoming ring_check from a peer */
void nodus_ring_mgmt_handle_check(nodus_ring_mgmt_t *mgmt,
                                    nodus_tcp_conn_t *conn,
                                    const nodus_key_t *node_id,
                                    const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                    const char *status,
                                    uint32_t txn_id);

/** Handle incoming ring_ack response */
void nodus_ring_mgmt_handle_ack(nodus_ring_mgmt_t *mgmt,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  bool agree,
                                  uint32_t txn_id);

/** Handle incoming ring_evict — this node is being removed from a channel */
void nodus_ring_mgmt_handle_evict(nodus_ring_mgmt_t *mgmt,
                                    const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                    uint32_t version,
                                    uint32_t txn_id,
                                    nodus_tcp_conn_t *conn);

/** Announce responsible nodes to DHT for a channel */
int nodus_ring_announce_to_dht(nodus_ring_mgmt_t *mgmt,
                                 const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                 uint32_t version);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_RING_MGMT_H */
