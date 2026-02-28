/**
 * Nodus v5 — Simplified PBFT Consensus Implementation
 *
 * Heartbeat-based cluster management for a 3-node ring.
 * Nodes send UDP PING every 10s, suspect after 30s, dead after 60s.
 * Leader is lowest alive node_id. Ring membership updates automatically.
 */

#include "consensus/nodus_pbft.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier1.h"
#include "channel/nodus_hashring.h"

#include <stdio.h>
#include <string.h>

/* ── Internal helpers ────────────────────────────────────────────── */

static nodus_cluster_peer_t *find_peer(nodus_pbft_t *pbft,
                                         const nodus_key_t *node_id) {
    for (int i = 0; i < pbft->peer_count; i++) {
        if (nodus_key_cmp(&pbft->peers[i].node_id, node_id) == 0)
            return &pbft->peers[i];
    }
    return NULL;
}

/**
 * Re-elect leader: lowest node_id among ALIVE nodes.
 */
static void elect_leader(nodus_pbft_t *pbft) {
    nodus_server_t *srv = (nodus_server_t *)pbft->srv;

    /* Self is always a candidate */
    nodus_key_t best = srv->identity.node_id;

    for (int i = 0; i < pbft->peer_count; i++) {
        if (pbft->peers[i].state != NODUS_NODE_ALIVE)
            continue;
        if (nodus_key_cmp(&pbft->peers[i].node_id, &best) < 0)
            best = pbft->peers[i].node_id;
    }

    bool leader_changed = (nodus_key_cmp(&pbft->leader_id, &best) != 0);
    pbft->leader_id = best;
    pbft->is_leader = (nodus_key_cmp(&best, &srv->identity.node_id) == 0);

    if (leader_changed) {
        pbft->view++;
        fprintf(stderr, "PBFT: leader changed to %s (view %u, %s)\n",
                pbft->is_leader ? "self" : "peer",
                pbft->view,
                pbft->is_leader ? "I am leader" : "following");
    }
}

/**
 * Update hash ring membership based on peer state.
 */
static void sync_ring(nodus_pbft_t *pbft, nodus_cluster_peer_t *peer,
                        nodus_node_state_t old_state) {
    nodus_server_t *srv = (nodus_server_t *)pbft->srv;

    if (old_state == NODUS_NODE_ALIVE && peer->state != NODUS_NODE_ALIVE) {
        /* Remove from ring */
        nodus_hashring_remove(&srv->ring, &peer->node_id);
        fprintf(stderr, "PBFT: removed %s:%d from ring (state=%d)\n",
                peer->ip, peer->tcp_port, peer->state);
    } else if (old_state != NODUS_NODE_ALIVE && peer->state == NODUS_NODE_ALIVE) {
        /* Add to ring */
        nodus_hashring_add(&srv->ring, &peer->node_id,
                            peer->ip, peer->tcp_port);
        fprintf(stderr, "PBFT: added %s:%d to ring\n",
                peer->ip, peer->tcp_port);
    }
}

/* ── Public API ──────────────────────────────────────────────────── */

void nodus_pbft_init(nodus_pbft_t *pbft, struct nodus_server *srv) {
    memset(pbft, 0, sizeof(*pbft));
    pbft->srv = srv;
    pbft->last_tick = nodus_time_now();

    nodus_server_t *s = (nodus_server_t *)srv;

    /* Add self to the hash ring */
    nodus_hashring_add(&s->ring, &s->identity.node_id,
                        s->config.bind_ip, s->config.tcp_port);

    /* Self is initial leader */
    pbft->leader_id = s->identity.node_id;
    pbft->is_leader = true;
    pbft->view = 1;
}

void nodus_pbft_add_peer(nodus_pbft_t *pbft,
                           const nodus_key_t *node_id,
                           const char *ip,
                           uint16_t udp_port, uint16_t tcp_port) {
    if (!pbft || !node_id || !ip) return;
    if (pbft->peer_count >= NODUS_PBFT_MAX_PEERS) return;

    /* Check duplicate */
    if (find_peer(pbft, node_id)) return;

    nodus_server_t *srv = (nodus_server_t *)pbft->srv;

    /* Don't add self as peer */
    if (nodus_key_cmp(node_id, &srv->identity.node_id) == 0)
        return;

    nodus_cluster_peer_t *peer = &pbft->peers[pbft->peer_count++];
    peer->node_id = *node_id;
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0';
    peer->udp_port = udp_port;
    peer->tcp_port = tcp_port;
    peer->last_seen = 0;  /* Not yet seen — will be set to alive on first pong */
    peer->state = NODUS_NODE_SUSPECT;  /* Unknown until first heartbeat */

    /* Add to hash ring (optimistic — will be removed if no heartbeat) */
    nodus_hashring_add(&srv->ring, node_id, ip, tcp_port);

    /* Re-elect leader */
    elect_leader(pbft);
}

void nodus_pbft_tick(nodus_pbft_t *pbft) {
    nodus_server_t *srv = (nodus_server_t *)pbft->srv;
    uint64_t now = nodus_time_now();

    /* Send heartbeats every NODUS_PBFT_HEARTBEAT_SEC */
    if (now - pbft->last_tick >= NODUS_PBFT_HEARTBEAT_SEC) {
        pbft->last_tick = now;

        uint8_t buf[256];
        size_t len = 0;

        for (int i = 0; i < pbft->peer_count; i++) {
            nodus_cluster_peer_t *peer = &pbft->peers[i];
            if (peer->state == NODUS_NODE_DEAD)
                continue;  /* Don't ping dead nodes (save bandwidth) */

            len = 0;
            nodus_t1_ping(0, &srv->identity.node_id, buf, sizeof(buf), &len);
            nodus_udp_send(&srv->udp, buf, len, peer->ip, peer->udp_port);
        }
    }

    /* Check peer health */
    bool state_changed = false;
    for (int i = 0; i < pbft->peer_count; i++) {
        nodus_cluster_peer_t *peer = &pbft->peers[i];
        nodus_node_state_t old_state = peer->state;

        if (peer->last_seen == 0) {
            /* Never seen — stay suspect */
            continue;
        }

        uint64_t age = now - peer->last_seen;

        if (age < NODUS_PBFT_SUSPECT_SEC) {
            peer->state = NODUS_NODE_ALIVE;
        } else if (age < NODUS_PBFT_SUSPECT_SEC * 2) {
            peer->state = NODUS_NODE_SUSPECT;
        } else {
            peer->state = NODUS_NODE_DEAD;
        }

        if (old_state != peer->state) {
            sync_ring(pbft, peer, old_state);
            state_changed = true;
        }
    }

    if (state_changed)
        elect_leader(pbft);
}

void nodus_pbft_on_heartbeat(nodus_pbft_t *pbft,
                               const nodus_key_t *node_id) {
    nodus_cluster_peer_t *peer = find_peer(pbft, node_id);
    if (!peer) return;

    nodus_node_state_t old_state = peer->state;
    peer->last_seen = nodus_time_now();

    if (old_state != NODUS_NODE_ALIVE) {
        peer->state = NODUS_NODE_ALIVE;
        sync_ring(pbft, peer, old_state);
        elect_leader(pbft);
    }
}

void nodus_pbft_on_pong(nodus_pbft_t *pbft,
                           const nodus_key_t *real_node_id,
                           const char *from_ip, uint16_t from_port) {
    /* First try exact node_id match (already-discovered peer) */
    nodus_cluster_peer_t *peer = find_peer(pbft, real_node_id);

    /* If not found, search by IP + port (seed with placeholder node_id) */
    if (!peer) {
        for (int i = 0; i < pbft->peer_count; i++) {
            if (strcmp(pbft->peers[i].ip, from_ip) == 0 &&
                pbft->peers[i].udp_port == from_port) {
                peer = &pbft->peers[i];

                /* Update placeholder node_id to real one */
                nodus_server_t *srv = (nodus_server_t *)pbft->srv;
                nodus_key_t old_id = peer->node_id;
                peer->node_id = *real_node_id;

                /* Update hash ring: remove old placeholder, add real */
                nodus_hashring_remove(&srv->ring, &old_id);
                nodus_hashring_add(&srv->ring, real_node_id,
                                    peer->ip, peer->tcp_port);

                fprintf(stderr, "PBFT: discovered real node_id for %s:%d\n",
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
        sync_ring(pbft, peer, old_state);
        elect_leader(pbft);
    }
}

const nodus_key_t *nodus_pbft_leader(const nodus_pbft_t *pbft) {
    return &pbft->leader_id;
}

bool nodus_pbft_is_leader(const nodus_pbft_t *pbft) {
    return pbft->is_leader;
}

int nodus_pbft_alive_count(const nodus_pbft_t *pbft) {
    int count = 1;  /* Self is always alive */
    for (int i = 0; i < pbft->peer_count; i++) {
        if (pbft->peers[i].state == NODUS_NODE_ALIVE)
            count++;
    }
    return count;
}
