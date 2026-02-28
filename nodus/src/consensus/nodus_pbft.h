/**
 * Nodus v5 — Simplified PBFT Consensus
 *
 * For a 3-node cluster (f=0):
 * - Heartbeat-based failure detection via UDP PING/PONG
 * - Deterministic leader election (lowest node_id)
 * - Automatic hash ring membership (add/remove on state change)
 * - View changes when leader fails
 *
 * @file nodus_pbft.h
 */

#ifndef NODUS_PBFT_H
#define NODUS_PBFT_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_PBFT_MAX_PEERS 16

typedef enum {
    NODUS_NODE_ALIVE   = 0,
    NODUS_NODE_SUSPECT = 1,
    NODUS_NODE_DEAD    = 2
} nodus_node_state_t;

typedef struct {
    nodus_key_t         node_id;
    char                ip[64];
    uint16_t            udp_port;
    uint16_t            tcp_port;
    uint64_t            last_seen;     /* Last heartbeat received (unix ts) */
    nodus_node_state_t  state;
} nodus_cluster_peer_t;

struct nodus_server;

typedef struct {
    struct nodus_server  *srv;
    nodus_cluster_peer_t  peers[NODUS_PBFT_MAX_PEERS];
    int                   peer_count;
    nodus_key_t           leader_id;
    bool                  is_leader;
    uint32_t              view;         /* View number (increments on leader change) */
    uint64_t              last_tick;    /* Last heartbeat send time */
} nodus_pbft_t;

/**
 * Initialize PBFT consensus module.
 * Adds self to the hash ring.
 */
void nodus_pbft_init(nodus_pbft_t *pbft, struct nodus_server *srv);

/**
 * Add a known peer to the cluster.
 * Also adds to the hash ring.
 */
void nodus_pbft_add_peer(nodus_pbft_t *pbft,
                           const nodus_key_t *node_id,
                           const char *ip,
                           uint16_t udp_port, uint16_t tcp_port);

/**
 * Called from server run loop every iteration.
 * Sends heartbeats (every NODUS_PBFT_HEARTBEAT_SEC),
 * checks peer health, updates ring membership.
 */
void nodus_pbft_tick(nodus_pbft_t *pbft);

/**
 * Called when a PONG is received from a peer.
 * Updates last_seen, may promote DEAD/SUSPECT → ALIVE.
 */
void nodus_pbft_on_heartbeat(nodus_pbft_t *pbft,
                               const nodus_key_t *node_id);

/**
 * Called when a PONG is received from a peer.
 * Uses IP to match seed peers whose node_id was a placeholder,
 * then updates to the real node_id from the PONG.
 */
void nodus_pbft_on_pong(nodus_pbft_t *pbft,
                           const nodus_key_t *real_node_id,
                           const char *from_ip, uint16_t from_port);

/**
 * Get the current leader's node_id.
 */
const nodus_key_t *nodus_pbft_leader(const nodus_pbft_t *pbft);

/**
 * Check if this node is the leader.
 */
bool nodus_pbft_is_leader(const nodus_pbft_t *pbft);

/**
 * Get the number of alive nodes in the cluster.
 */
int nodus_pbft_alive_count(const nodus_pbft_t *pbft);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_PBFT_H */
