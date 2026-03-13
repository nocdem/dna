/**
 * Nodus — Cluster Membership & Heartbeat Implementation
 *
 * Heartbeat-based cluster management.
 * Nodes send UDP PING every 10s, suspect after 30s, dead after 60s.
 * Leader is lowest alive node_id.
 */

#include "consensus/nodus_cluster.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier1.h"
#include "core/nodus_routing.h"

#include <stdio.h>
#include <string.h>

/* ── Internal helpers ────────────────────────────────────────────── */

static nodus_cluster_peer_t *find_peer(nodus_cluster_t *cluster,
                                         const nodus_key_t *node_id) {
    for (int i = 0; i < cluster->peer_count; i++) {
        if (nodus_key_cmp(&cluster->peers[i].node_id, node_id) == 0)
            return &cluster->peers[i];
    }
    return NULL;
}

/**
 * Re-elect leader: lowest node_id among ALIVE nodes.
 */
static void elect_leader(nodus_cluster_t *cluster) {
    nodus_server_t *srv = (nodus_server_t *)cluster->srv;

    /* Self is always a candidate */
    nodus_key_t best = srv->identity.node_id;

    for (int i = 0; i < cluster->peer_count; i++) {
        if (cluster->peers[i].state != NODUS_NODE_ALIVE)
            continue;
        if (nodus_key_cmp(&cluster->peers[i].node_id, &best) < 0)
            best = cluster->peers[i].node_id;
    }

    bool leader_changed = (nodus_key_cmp(&cluster->leader_id, &best) != 0);
    cluster->leader_id = best;
    cluster->is_leader = (nodus_key_cmp(&best, &srv->identity.node_id) == 0);

    if (leader_changed) {
        cluster->view++;
        fprintf(stderr, "CLUSTER: leader changed to %s (view %u, %s)\n",
                cluster->is_leader ? "self" : "peer",
                cluster->view,
                cluster->is_leader ? "I am leader" : "following");
    }
}

/**
 * Log peer state transitions.
 */
static void sync_ring(nodus_cluster_t *cluster, nodus_cluster_peer_t *peer,
                        nodus_node_state_t old_state) {
    (void)cluster;
    if (old_state == NODUS_NODE_ALIVE && peer->state != NODUS_NODE_ALIVE) {
        fprintf(stderr, "CLUSTER: peer %s:%d state changed to %d\n",
                peer->ip, peer->tcp_port, peer->state);
    } else if (old_state != NODUS_NODE_ALIVE && peer->state == NODUS_NODE_ALIVE) {
        fprintf(stderr, "CLUSTER: peer %s:%d now ALIVE\n",
                peer->ip, peer->tcp_port);
    }
}

/* ── Public API ──────────────────────────────────────────────────── */

void nodus_cluster_init(nodus_cluster_t *cluster, struct nodus_server *srv) {
    memset(cluster, 0, sizeof(*cluster));
    cluster->srv = srv;
    cluster->last_tick = nodus_time_now();

    nodus_server_t *s = (nodus_server_t *)srv;

    /* Self is initial leader */
    cluster->leader_id = s->identity.node_id;
    cluster->is_leader = true;
    cluster->view = 1;
}

void nodus_cluster_add_peer(nodus_cluster_t *cluster,
                              const nodus_key_t *node_id,
                              const char *ip,
                              uint16_t udp_port, uint16_t tcp_port) {
    if (!cluster || !node_id || !ip) return;
    if (cluster->peer_count >= NODUS_CLUSTER_MAX_PEERS) return;

    /* Check duplicate */
    if (find_peer(cluster, node_id)) return;

    nodus_server_t *srv = (nodus_server_t *)cluster->srv;

    /* Don't add self as peer */
    if (nodus_key_cmp(node_id, &srv->identity.node_id) == 0)
        return;

    nodus_cluster_peer_t *peer = &cluster->peers[cluster->peer_count++];
    peer->node_id = *node_id;
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0';
    peer->udp_port = udp_port;
    peer->tcp_port = tcp_port;
    peer->last_seen = 0;  /* Not yet seen — will be set to alive on first pong */
    peer->state = NODUS_NODE_SUSPECT;  /* Unknown until first heartbeat */

    /* Re-elect leader */
    elect_leader(cluster);
}

void nodus_cluster_tick(nodus_cluster_t *cluster) {
    nodus_server_t *srv = (nodus_server_t *)cluster->srv;
    uint64_t now = nodus_time_now();

    /* Send heartbeats every NODUS_CLUSTER_HEARTBEAT_SEC */
    if (now - cluster->last_tick >= NODUS_CLUSTER_HEARTBEAT_SEC) {
        cluster->last_tick = now;

        uint8_t buf[256];
        size_t len = 0;

        for (int i = 0; i < cluster->peer_count; i++) {
            nodus_cluster_peer_t *peer = &cluster->peers[i];
            if (peer->state == NODUS_NODE_DEAD)
                continue;  /* Don't ping dead nodes (save bandwidth) */

            len = 0;
            nodus_t1_ping(0, &srv->identity.node_id, &srv->identity.pk, buf, sizeof(buf), &len);
            nodus_udp_send(&srv->udp, buf, len, peer->ip, peer->udp_port);
        }
    }

    /* Check peer health */
    bool state_changed = false;
    for (int i = 0; i < cluster->peer_count; i++) {
        nodus_cluster_peer_t *peer = &cluster->peers[i];
        nodus_node_state_t old_state = peer->state;

        if (peer->last_seen == 0) {
            /* Never seen — stay suspect */
            continue;
        }

        uint64_t age = now - peer->last_seen;

        if (age < NODUS_CLUSTER_SUSPECT_SEC) {
            peer->state = NODUS_NODE_ALIVE;
        } else if (age < NODUS_CLUSTER_SUSPECT_SEC * 2) {
            peer->state = NODUS_NODE_SUSPECT;
        } else {
            peer->state = NODUS_NODE_DEAD;
        }

        if (old_state != peer->state) {
            sync_ring(cluster, peer, old_state);
            state_changed = true;

            /* Remove dead nodes from routing table to prevent stale replication */
            if (peer->state == NODUS_NODE_DEAD) {
                nodus_routing_remove(&srv->routing, &peer->node_id);
            }
        }
    }

    if (state_changed)
        elect_leader(cluster);
}

void nodus_cluster_on_heartbeat(nodus_cluster_t *cluster,
                                  const nodus_key_t *node_id) {
    nodus_cluster_peer_t *peer = find_peer(cluster, node_id);
    if (!peer) return;

    nodus_node_state_t old_state = peer->state;
    peer->last_seen = nodus_time_now();

    if (old_state != NODUS_NODE_ALIVE) {
        peer->state = NODUS_NODE_ALIVE;
        sync_ring(cluster, peer, old_state);
        elect_leader(cluster);
    }
}

void nodus_cluster_on_pong(nodus_cluster_t *cluster,
                             const nodus_key_t *real_node_id,
                             const char *from_ip, uint16_t from_port) {
    /* First try exact node_id match (already-discovered peer) */
    nodus_cluster_peer_t *peer = find_peer(cluster, real_node_id);

    /* If not found, search by IP + port (seed with placeholder node_id) */
    if (!peer) {
        for (int i = 0; i < cluster->peer_count; i++) {
            if (strcmp(cluster->peers[i].ip, from_ip) == 0 &&
                cluster->peers[i].udp_port == from_port) {
                peer = &cluster->peers[i];

                /* Update placeholder node_id to real one */
                peer->node_id = *real_node_id;

                fprintf(stderr, "CLUSTER: discovered real node_id for %s:%d\n",
                        from_ip, from_port);
                break;
            }
        }
    }

    if (!peer) return;

    nodus_node_state_t old_state = peer->state;
    peer->last_seen = nodus_time_now();

    if (old_state != NODUS_NODE_ALIVE) {
        peer->state = NODUS_NODE_ALIVE;
        sync_ring(cluster, peer, old_state);
        elect_leader(cluster);
    }
}

const nodus_key_t *nodus_cluster_leader(const nodus_cluster_t *cluster) {
    return &cluster->leader_id;
}

bool nodus_cluster_is_leader(const nodus_cluster_t *cluster) {
    return cluster->is_leader;
}

int nodus_cluster_alive_count(const nodus_cluster_t *cluster) {
    int count = 1;  /* Self is always alive */
    for (int i = 0; i < cluster->peer_count; i++) {
        if (cluster->peers[i].state == NODUS_NODE_ALIVE)
            count++;
    }
    return count;
}
