/**
 * Nodus — Server-Side Presence Table
 *
 * Tracks connected clients locally and across the cluster via p_sync.
 * Single-threaded (called from server event loop only).
 *
 * @file nodus_presence.c
 */

#include "server/nodus_presence.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "core/nodus_routing.h"

#include <string.h>
#include <stdio.h>

/* ── Internal helpers ─────────────────────────────────────────────── */

static int find_entry(nodus_presence_table_t *tbl, const nodus_key_t *fp,
                        uint8_t peer_index) {
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].active &&
            tbl->entries[i].peer_index == peer_index &&
            nodus_key_cmp(&tbl->entries[i].client_fp, fp) == 0)
            return i;
    }
    return -1;
}

static int find_any(nodus_presence_table_t *tbl, const nodus_key_t *fp) {
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].active &&
            nodus_key_cmp(&tbl->entries[i].client_fp, fp) == 0)
            return i;
    }
    return -1;
}

static int find_inactive(nodus_presence_table_t *tbl, const nodus_key_t *fp) {
    int best = -1;
    uint64_t best_ts = 0;
    for (int i = 0; i < tbl->count; i++) {
        if (!tbl->entries[i].active && tbl->entries[i].last_seen > 0 &&
            nodus_key_cmp(&tbl->entries[i].client_fp, fp) == 0) {
            if (tbl->entries[i].last_seen > best_ts) {
                best = i;
                best_ts = tbl->entries[i].last_seen;
            }
        }
    }
    return best;
}

static int alloc_slot(nodus_presence_table_t *tbl) {
    /* Reuse inactive slot that has no last_seen (fully expired/unused) */
    for (int i = 0; i < tbl->count; i++) {
        if (!tbl->entries[i].active && tbl->entries[i].last_seen == 0)
            return i;
    }
    /* Append */
    if (tbl->count < NODUS_PRESENCE_MAX_ENTRIES)
        return tbl->count++;
    /* Last resort: reuse oldest inactive slot */
    int oldest = -1;
    uint64_t oldest_ts = UINT64_MAX;
    for (int i = 0; i < tbl->count; i++) {
        if (!tbl->entries[i].active && tbl->entries[i].last_seen < oldest_ts) {
            oldest = i;
            oldest_ts = tbl->entries[i].last_seen;
        }
    }
    return oldest;
}

/* ── Public API ───────────────────────────────────────────────────── */

void nodus_presence_add_local(struct nodus_server *srv, const nodus_key_t *fp) {
    if (!srv || !fp) return;
    nodus_presence_table_t *tbl = &srv->presence;

    /* Already exists as local active? Just update timestamp */
    int idx = find_entry(tbl, fp, 0);
    if (idx >= 0) {
        tbl->entries[idx].last_seen = nodus_time_now();
        return;
    }

    /* Reuse inactive entry for same fingerprint (reconnect scenario) */
    idx = find_inactive(tbl, fp);
    if (idx < 0)
        idx = alloc_slot(tbl);
    if (idx < 0) return;  /* Table full */

    tbl->entries[idx].client_fp = *fp;
    tbl->entries[idx].peer_index = 0;
    tbl->entries[idx].last_seen = nodus_time_now();
    tbl->entries[idx].active = true;
}

void nodus_presence_remove_local(struct nodus_server *srv, const nodus_key_t *fp) {
    if (!srv || !fp) return;
    nodus_presence_table_t *tbl = &srv->presence;

    int idx = find_entry(tbl, fp, 0);
    if (idx >= 0) {
        tbl->entries[idx].last_seen = nodus_time_now();
        tbl->entries[idx].active = false;
    }
}

void nodus_presence_merge_remote(struct nodus_server *srv, const nodus_key_t *fps,
                                   int count, uint8_t peer_index) {
    if (!srv || !fps || peer_index == 0) return;
    nodus_presence_table_t *tbl = &srv->presence;
    uint64_t now = nodus_time_now();

    for (int i = 0; i < count; i++) {
        int idx = find_entry(tbl, &fps[i], peer_index);
        if (idx >= 0) {
            tbl->entries[idx].last_seen = now;
        } else {
            idx = alloc_slot(tbl);
            if (idx < 0) return;  /* Table full */
            tbl->entries[idx].client_fp = fps[i];
            tbl->entries[idx].peer_index = peer_index;
            tbl->entries[idx].last_seen = now;
            tbl->entries[idx].active = true;
        }
    }
}

bool nodus_presence_is_online(struct nodus_server *srv, const nodus_key_t *fp,
                                uint8_t *peer_index_out) {
    if (!srv || !fp) return false;
    int idx = find_any(&srv->presence, fp);
    if (idx >= 0) {
        if (peer_index_out)
            *peer_index_out = srv->presence.entries[idx].peer_index;
        return true;
    }
    return false;
}

int nodus_presence_query_batch(struct nodus_server *srv, const nodus_key_t *fps,
                                 int fp_count, bool *online_out, uint8_t *peers_out,
                                 uint64_t *last_seen_out) {
    if (!srv || !fps || !online_out) return -1;

    int online_count = 0;
    for (int i = 0; i < fp_count; i++) {
        uint8_t pi = 0;
        online_out[i] = nodus_presence_is_online(srv, &fps[i], &pi);
        if (peers_out)
            peers_out[i] = pi;
        if (online_out[i]) {
            online_count++;
            if (last_seen_out) {
                int idx = find_any(&srv->presence, &fps[i]);
                last_seen_out[i] = (idx >= 0) ? srv->presence.entries[idx].last_seen : 0;
            }
        } else if (last_seen_out) {
            int idx = find_inactive(&srv->presence, &fps[i]);
            last_seen_out[i] = (idx >= 0) ? srv->presence.entries[idx].last_seen : 0;
        }
    }
    return online_count;
}

void nodus_presence_expire(struct nodus_server *srv, uint64_t now) {
    if (!srv) return;
    nodus_presence_table_t *tbl = &srv->presence;

    for (int i = 0; i < tbl->count; i++) {
        if (!tbl->entries[i].active) continue;
        /* Only expire remote entries */
        if (tbl->entries[i].peer_index == 0) continue;
        if (now - tbl->entries[i].last_seen > NODUS_PRESENCE_REMOTE_TTL)
            tbl->entries[i].active = false;
    }
}

int nodus_presence_get_local(struct nodus_server *srv, nodus_key_t *fps_out,
                               int max_count) {
    if (!srv || !fps_out) return 0;
    nodus_presence_table_t *tbl = &srv->presence;

    int n = 0;
    for (int i = 0; i < tbl->count && n < max_count; i++) {
        if (tbl->entries[i].active && tbl->entries[i].peer_index == 0)
            fps_out[n++] = tbl->entries[i].client_fp;
    }
    return n;
}

/* ── Tick: expire + broadcast ─────────────────────────────────────── */

/* Broadcast buffer: 7-byte frame header + CBOR payload.
 * Max payload: 5(header) + 64*2048 fps ≈ 131KB.
 * We cap at 256 fps per sync = ~16KB. */
#define PRESENCE_SYNC_MAX_FPS  256

/* Max routing table peers: 512 buckets × K entries */
#define PRESENCE_MAX_PEERS     (NODUS_BUCKETS * NODUS_K)

void nodus_presence_tick(struct nodus_server *srv) {
    if (!srv) return;

    uint64_t now = nodus_time_now();

    /* Expire stale remote entries */
    nodus_presence_expire(srv, now);

    /* Sync to peers every NODUS_PRESENCE_SYNC_SEC */
    if (now - srv->presence.last_sync < NODUS_PRESENCE_SYNC_SEC)
        return;
    srv->presence.last_sync = now;

    /* Collect local fingerprints */
    nodus_key_t local_fps[PRESENCE_SYNC_MAX_FPS];
    int local_count = nodus_presence_get_local(srv, local_fps, PRESENCE_SYNC_MAX_FPS);
    if (local_count == 0)
        return;

    /* Encode p_sync message */
    uint8_t sync_buf[32768];
    size_t sync_len = 0;
    if (nodus_t2_presence_sync(0, local_fps, local_count,
                                 sync_buf, sizeof(sync_buf), &sync_len) != 0)
        return;

    /* Collect all peers from routing table */
    nodus_peer_t peers[PRESENCE_MAX_PEERS];
    int peer_count = 0;
    for (int b = 0; b < NODUS_BUCKETS && peer_count < PRESENCE_MAX_PEERS; b++) {
        const nodus_bucket_t *bkt = &srv->routing.buckets[b];
        for (int e = 0; e < bkt->count && peer_count < PRESENCE_MAX_PEERS; e++) {
            if (bkt->entries[e].active)
                peers[peer_count++] = bkt->entries[e].peer;
        }
    }

    /* Send to all peers in routing table using persistent connections.
     * Non-blocking connect: data is buffered in write buffer and flushed
     * by the event loop once the connection completes (handle_connect_complete
     * sets EPOLLOUT when wlen > wpos). Connection stays in pool for reuse. */
    int sent = 0;
    for (int i = 0; i < peer_count; i++) {
        nodus_peer_t *peer = &peers[i];
        if (peer->tcp_port == 0) continue;

        /* Reuse existing persistent connection */
        nodus_tcp_conn_t *pconn = nodus_tcp_find_by_addr(
            (nodus_tcp_t *)&srv->tcp, peer->ip, peer->tcp_port);
        if (pconn) {
            nodus_tcp_send(pconn, sync_buf, sync_len);
            sent++;
            continue;
        }

        /* Open new persistent connection — do NOT disconnect.
         * Event loop flushes buffered data once connect completes. */
        pconn = nodus_tcp_connect(
            (nodus_tcp_t *)&srv->tcp, peer->ip, peer->tcp_port);
        if (!pconn) continue;
        pconn->is_nodus = true;  /* Mark as inter-node connection */
        nodus_tcp_send(pconn, sync_buf, sync_len);
        sent++;
    }

    if (sent > 0 || peer_count > 0)
        fprintf(stderr, "P_SYNC: broadcast %d local fps to %d/%d routing peers\n",
                local_count, sent, peer_count);

    /* Clean up stale outgoing p_sync connections: disconnect any is_nodus
     * connection whose IP:port is no longer in the routing table. */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = srv->tcp.pool[i];
        if (!c || !c->is_nodus) continue;

        bool found = false;
        for (int p = 0; p < peer_count; p++) {
            if (strcmp(peers[p].ip, c->ip) == 0 && peers[p].tcp_port == c->port) {
                found = true;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "P_SYNC: closing stale connection to %s:%d\n",
                    c->ip, c->port);
            nodus_tcp_disconnect((nodus_tcp_t *)&srv->tcp, c);
        }
    }
}
