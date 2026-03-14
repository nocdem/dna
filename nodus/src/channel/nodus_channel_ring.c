/**
 * Nodus -- Channel Ring Management via TCP 4003 Heartbeat
 *
 * Dead detection uses TCP 4003 heartbeat only.
 * Hashring always wins -- deterministic, no election.
 *
 * @file nodus_channel_ring.c
 */

#include "channel/nodus_channel_ring.h"
#include "channel/nodus_channel_primary.h"
#include "protocol/nodus_tier2.h"
#include "transport/nodus_tcp.h"

#include "crypto/utils/qgp_log.h"

#include <string.h>

#define LOG_TAG "CH_RING"

/* ---- Init / Track / Untrack -------------------------------------------- */

void nodus_ch_ring_init(nodus_ch_ring_t *rm, nodus_channel_server_t *cs)
{
    memset(rm, 0, sizeof(*rm));
    rm->cs = cs;
}

int nodus_ch_ring_track(nodus_ch_ring_t *rm,
                         const uint8_t channel_uuid[NODUS_UUID_BYTES],
                         uint32_t ring_version)
{
    /* Check if already tracked */
    for (int i = 0; i < rm->channel_count; i++) {
        if (rm->channels[i].active &&
            memcmp(rm->channels[i].channel_uuid, channel_uuid,
                   NODUS_UUID_BYTES) == 0) {
            return 0;  /* Already tracked */
        }
    }

    /* Find empty slot: first try reusing inactive entry */
    for (int i = 0; i < rm->channel_count; i++) {
        if (!rm->channels[i].active) {
            nodus_ch_ring_channel_t *ch = &rm->channels[i];
            memset(ch, 0, sizeof(*ch));
            memcpy(ch->channel_uuid, channel_uuid, NODUS_UUID_BYTES);
            ch->ring_version = ring_version;
            ch->active = true;
            return 0;
        }
    }

    /* Append if space remains */
    if (rm->channel_count >= NODUS_CH_RING_MAX_TRACKED) {
        QGP_LOG_WARN(LOG_TAG, "Cannot track channel: max %d reached",
                     NODUS_CH_RING_MAX_TRACKED);
        return -1;
    }

    nodus_ch_ring_channel_t *ch = &rm->channels[rm->channel_count++];
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->channel_uuid, channel_uuid, NODUS_UUID_BYTES);
    ch->ring_version = ring_version;
    ch->active = true;
    return 0;
}

void nodus_ch_ring_untrack(nodus_ch_ring_t *rm,
                            const uint8_t channel_uuid[NODUS_UUID_BYTES])
{
    for (int i = 0; i < rm->channel_count; i++) {
        if (rm->channels[i].active &&
            memcmp(rm->channels[i].channel_uuid, channel_uuid,
                   NODUS_UUID_BYTES) == 0) {
            rm->channels[i].active = false;
            rm->channels[i].check_pending = false;
            QGP_LOG_DEBUG(LOG_TAG, "Untracked channel slot %d", i);
            return;
        }
    }
}

bool nodus_ch_ring_is_tracked(const nodus_ch_ring_t *rm,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES])
{
    for (int i = 0; i < rm->channel_count; i++) {
        if (rm->channels[i].active &&
            memcmp(rm->channels[i].channel_uuid, channel_uuid,
                   NODUS_UUID_BYTES) == 0) {
            return true;
        }
    }
    return false;
}

/* ---- Helper: find node session by node_id ------------------------------ */

static nodus_ch_node_session_t *find_node_session(
    nodus_channel_server_t *cs, const nodus_key_t *node_id)
{
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        nodus_ch_node_session_t *ns = &cs->nodes[i];
        if (!ns->conn || !ns->authenticated) continue;
        if (nodus_key_cmp(&ns->node_id, node_id) == 0)
            return ns;
    }
    return NULL;
}

/* ---- Helper: evict dead node and announce ------------------------------ */

static void evict_and_announce(nodus_ch_ring_t *rm,
                               nodus_ch_ring_channel_t *ch,
                               const nodus_key_t *dead_id)
{
    nodus_channel_server_t *cs = rm->cs;

    nodus_hashring_remove(cs->ring, dead_id);
    /* nodus_hashring_remove() already increments ring->version */
    ch->ring_version = cs->ring->version;

    /* Announce new ring to DHT */
    nodus_ch_primary_announce_to_dht(cs, ch->channel_uuid);

    /* Notify connected clients */
    nodus_ch_notify_ring_changed(cs, ch->channel_uuid, cs->ring->version);

    /* Best-effort ring_evict to dead node, then disconnect + clear session */
    nodus_ch_node_session_t *dead_ns = find_node_session(cs, dead_id);
    if (dead_ns) {
        uint8_t buf[256];
        size_t len = 0;
        if (nodus_t2_ring_evict(0, ch->channel_uuid, cs->ring->version,
                                buf, sizeof(buf), &len) == 0) {
            nodus_tcp_send(dead_ns->conn, buf, len);
        }
        /* Clean up the dead node session — ring_tick owns dead detection,
         * so we disconnect here after eviction is complete */
        nodus_tcp_disconnect(&cs->tcp, dead_ns->conn);
        memset(dead_ns, 0, sizeof(*dead_ns));
    }
}

/* ---- Tick: periodic dead detection ------------------------------------- */

void nodus_ch_ring_tick(nodus_ch_ring_t *rm, uint64_t now_ms)
{
    if (now_ms - rm->last_tick_ms < 5000)
        return;
    rm->last_tick_ms = now_ms;

    nodus_channel_server_t *cs = rm->cs;
    if (!cs || !cs->ring || !cs->identity)
        return;

    const nodus_key_t *self_id = &cs->identity->node_id;

    /* 1. Check for dead node sessions (heartbeat timeout) */
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        nodus_ch_node_session_t *ns = &cs->nodes[i];
        if (!ns->conn || !ns->authenticated)
            continue;
        if (ns->last_heartbeat_recv == 0)
            continue;
        if (now_ms - ns->last_heartbeat_recv <= NODUS_CH_HEARTBEAT_TIMEOUT_MS)
            continue;

        /* This node is suspected dead */
        QGP_LOG_WARN(LOG_TAG, "Node heartbeat timeout, suspected dead");

        /* If no channels are tracked, just disconnect the stale session */
        if (rm->channel_count == 0) {
            QGP_LOG_INFO(LOG_TAG, "No tracked channels, disconnecting stale node");
            nodus_tcp_disconnect(&cs->tcp, ns->conn);
            memset(ns, 0, sizeof(*ns));
            continue;
        }

        bool any_responsible = false;
        for (int c = 0; c < rm->channel_count; c++) {
            nodus_ch_ring_channel_t *ch = &rm->channels[c];
            if (!ch->active || ch->check_pending)
                continue;

            /* Check if dead node is in responsible set for this channel */
            nodus_responsible_set_t rset;
            if (nodus_hashring_responsible(cs->ring, ch->channel_uuid,
                                           &rset) != 0)
                continue;

            bool dead_is_responsible = false;
            for (int r = 0; r < rset.count; r++) {
                if (nodus_key_cmp(&rset.nodes[r].node_id,
                                  &ns->node_id) == 0) {
                    dead_is_responsible = true;
                    break;
                }
            }
            if (!dead_is_responsible)
                continue;

            any_responsible = true;

            /* Find the OTHER responsible node (not self, not dead) */
            bool sent = false;
            for (int r = 0; r < rset.count && !sent; r++) {
                if (nodus_key_cmp(&rset.nodes[r].node_id, self_id) == 0)
                    continue;
                if (nodus_key_cmp(&rset.nodes[r].node_id,
                                  &ns->node_id) == 0)
                    continue;

                nodus_ch_node_session_t *other =
                    find_node_session(cs, &rset.nodes[r].node_id);
                if (!other) {
                    /* No session to peer — try connecting (async) */
                    nodus_ch_server_connect_to_peer(cs, rset.nodes[r].ip,
                                                    cs->port,
                                                    &rset.nodes[r].node_id);
                    continue;
                }

                /* Send ring_check */
                uint8_t buf[256];
                size_t len = 0;
                if (nodus_t2_ring_check(0, &ns->node_id,
                                        ch->channel_uuid, "dead",
                                        buf, sizeof(buf), &len) == 0) {
                    nodus_tcp_send(other->conn, buf, len);

                    ch->check_pending = true;
                    memcpy(&ch->check_node_id, &ns->node_id,
                           sizeof(nodus_key_t));
                    ch->check_sent_at_ms = now_ms;
                    sent = true;
                }
            }

            /* No peer session available to confirm — start unilateral
             * eviction timer. Uses check_pending with timeout. */
            if (!sent) {
                ch->check_pending = true;
                memcpy(&ch->check_node_id, &ns->node_id,
                       sizeof(nodus_key_t));
                ch->check_sent_at_ms = now_ms;
                QGP_LOG_WARN(LOG_TAG,
                    "No peer session for ring_check, "
                    "will evict unilaterally in %ds",
                    NODUS_CH_RING_CHECK_TIMEOUT_MS / 1000);
            }
        }

        /* Dead node not responsible for any tracked channel — just disconnect */
        if (!any_responsible) {
            QGP_LOG_INFO(LOG_TAG, "Dead node not responsible for any channel, disconnecting");
            nodus_tcp_disconnect(&cs->tcp, ns->conn);
            memset(ns, 0, sizeof(*ns));
        }
    }

    /* 2. Check for timed-out ring_checks (no ack received) */
    for (int c = 0; c < rm->channel_count; c++) {
        nodus_ch_ring_channel_t *ch = &rm->channels[c];
        if (!ch->active || !ch->check_pending)
            continue;

        if (now_ms - ch->check_sent_at_ms > NODUS_CH_RING_CHECK_TIMEOUT_MS) {
            QGP_LOG_WARN(LOG_TAG,
                         "ring_check timeout, proceeding with eviction");
            ch->check_pending = false;
            evict_and_announce(rm, ch, &ch->check_node_id);
            QGP_LOG_INFO(LOG_TAG,
                         "Dead node evicted (timeout), ring_version=%u",
                         cs->ring->version);
        }
    }
}

/* ---- Handle ring_check from peer --------------------------------------- */

int nodus_ch_ring_handle_check(nodus_ch_ring_t *rm,
                                nodus_ch_node_session_t *from,
                                const nodus_key_t *node_id,
                                const uint8_t channel_uuid[NODUS_UUID_BYTES])
{
    nodus_channel_server_t *cs = rm->cs;
    if (!cs || !from || !from->conn)
        return -1;

    /* Check our own heartbeat state for the questioned node */
    bool is_dead = true;
    uint64_t now = nodus_time_now_ms();

    nodus_ch_node_session_t *ns = find_node_session(cs, node_id);
    if (ns && ns->last_heartbeat_recv > 0 &&
        now - ns->last_heartbeat_recv < NODUS_CH_HEARTBEAT_TIMEOUT_MS) {
        is_dead = false;
    }

    /* Send ring_ack */
    uint8_t buf[256];
    size_t len = 0;
    if (nodus_t2_ring_ack(0, channel_uuid, is_dead,
                          buf, sizeof(buf), &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode ring_ack");
        return -1;
    }
    nodus_tcp_send(from->conn, buf, len);

    QGP_LOG_INFO(LOG_TAG, "ring_check handled, agree=%s",
                 is_dead ? "true" : "false");
    return 0;
}

/* ---- Handle ring_ack from peer ----------------------------------------- */

int nodus_ch_ring_handle_ack(nodus_ch_ring_t *rm,
                              const uint8_t channel_uuid[NODUS_UUID_BYTES],
                              bool agree)
{
    /* Find the tracked channel with a pending check */
    nodus_ch_ring_channel_t *ch = NULL;
    for (int i = 0; i < rm->channel_count; i++) {
        if (rm->channels[i].active && rm->channels[i].check_pending &&
            memcmp(rm->channels[i].channel_uuid, channel_uuid,
                   NODUS_UUID_BYTES) == 0) {
            ch = &rm->channels[i];
            break;
        }
    }
    if (!ch) {
        QGP_LOG_WARN(LOG_TAG, "ring_ack for unknown/unpending channel");
        return -1;
    }

    ch->check_pending = false;

    if (agree) {
        /* Both nodes agree: remove dead node from ring */
        evict_and_announce(rm, ch, &ch->check_node_id);
        QGP_LOG_INFO(LOG_TAG, "Dead node evicted (confirmed), ring_version=%u",
                     rm->cs->ring->version);
    } else {
        /* Disagree: peer says node is alive. Reset heartbeat timer
         * to give it a fresh 45s grace period. Without this reset,
         * ring_tick would re-detect the same stale timestamp every
         * 5s and loop forever (log spam). */
        nodus_ch_node_session_t *ns = find_node_session(rm->cs, &ch->check_node_id);
        if (ns) {
            ns->last_heartbeat_recv = nodus_time_now_ms();
        }
        QGP_LOG_INFO(LOG_TAG,
                     "ring_ack disagree -- node not confirmed dead, heartbeat reset");
    }

    return 0;
}

/* ---- Handle ring_evict: we've been removed ----------------------------- */

int nodus_ch_ring_handle_evict(nodus_ch_ring_t *rm,
                                const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                uint32_t new_version)
{
    /* Notify subscribed clients that ring changed */
    nodus_ch_notify_ring_changed(rm->cs, channel_uuid, new_version);

    /* Stop tracking this channel */
    nodus_ch_ring_untrack(rm, channel_uuid);

    QGP_LOG_INFO(LOG_TAG, "Evicted from channel, new ring_version=%u",
                 new_version);
    return 0;
}

/* ---- Handle ring_rejoin: returning node -------------------------------- */

int nodus_ch_ring_handle_rejoin(nodus_ch_ring_t *rm,
                                 nodus_ch_node_session_t *from,
                                 const nodus_key_t *rejoining_node_id,
                                 uint32_t their_ring_version)
{
    nodus_channel_server_t *cs = rm->cs;
    if (!cs || !cs->ring)
        return -1;

    (void)their_ring_version;  /* Informational only; hashring is recalculated */

    /* Add returning node to hashring (if not already present) */
    if (!nodus_hashring_contains(cs->ring, rejoining_node_id)) {
        const char *ip = "0.0.0.0";
        uint16_t port = cs->port;

        /* Use the node session's connection IP if available */
        if (from && from->conn && from->conn->ip[0] != '\0') {
            ip = from->conn->ip;
        }

        if (nodus_hashring_add(cs->ring, rejoining_node_id,
                               ip, port) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to add rejoining node to hashring");
            return -1;
        }
    }

    /* nodus_hashring_add() already increments ring->version */

    /* Update all tracked channels and announce */
    for (int i = 0; i < rm->channel_count; i++) {
        nodus_ch_ring_channel_t *ch = &rm->channels[i];
        if (!ch->active)
            continue;

        ch->ring_version = cs->ring->version;

        /* Announce updated ring to DHT */
        nodus_ch_primary_announce_to_dht(cs, ch->channel_uuid);

        /* Notify clients of ring change */
        nodus_ch_notify_ring_changed(cs, ch->channel_uuid,
                                     cs->ring->version);
    }

    QGP_LOG_INFO(LOG_TAG, "Node rejoin processed, ring_version=%u",
                 cs->ring->version);
    return 0;
}
