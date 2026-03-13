/**
 * Nodus — Cluster Membership & Heartbeat
 *
 * Heartbeat-based failure detection and leader election:
 * - UDP PING every 10s, suspect after 30s, dead after 60s
 * - Deterministic leader election (lowest alive node_id)
 * - View changes when leader fails
 *
 * @file nodus_cluster.h
 */

#ifndef NODUS_CLUSTER_H
#define NODUS_CLUSTER_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_CLUSTER_MAX_PEERS 16

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
    nodus_cluster_peer_t  peers[NODUS_CLUSTER_MAX_PEERS];
    int                   peer_count;
    nodus_key_t           leader_id;
    bool                  is_leader;
    uint32_t              view;         /* View number (increments on leader change) */
    uint64_t              last_tick;    /* Last heartbeat send time */
} nodus_cluster_t;

/**
 * Initialize cluster membership module.
 */
void nodus_cluster_init(nodus_cluster_t *cluster, struct nodus_server *srv);

/**
 * Add a known peer to the cluster.
 */
void nodus_cluster_add_peer(nodus_cluster_t *cluster,
                              const nodus_key_t *node_id,
                              const char *ip,
                              uint16_t udp_port, uint16_t tcp_port);

/**
 * Called from server run loop every iteration.
 * Sends heartbeats (every NODUS_CLUSTER_HEARTBEAT_SEC),
 * checks peer health.
 */
void nodus_cluster_tick(nodus_cluster_t *cluster);

/**
 * Called when a PONG is received from a peer.
 * Updates last_seen, may promote DEAD/SUSPECT -> ALIVE.
 */
void nodus_cluster_on_heartbeat(nodus_cluster_t *cluster,
                                  const nodus_key_t *node_id);

/**
 * Called when a PONG is received from a peer.
 * Uses IP to match seed peers whose node_id was a placeholder,
 * then updates to the real node_id from the PONG.
 */
void nodus_cluster_on_pong(nodus_cluster_t *cluster,
                             const nodus_key_t *real_node_id,
                             const char *from_ip, uint16_t from_port);

/**
 * Get the current leader's node_id.
 */
const nodus_key_t *nodus_cluster_leader(const nodus_cluster_t *cluster);

/**
 * Check if this node is the leader.
 */
bool nodus_cluster_is_leader(const nodus_cluster_t *cluster);

/**
 * Get the number of alive nodes in the cluster.
 */
int nodus_cluster_alive_count(const nodus_cluster_t *cluster);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CLUSTER_H */
