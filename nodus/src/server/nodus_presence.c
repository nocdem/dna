/**
 * Nodus v5 — Server-Side Presence Table
 *
 * Tracks connected clients locally and across the cluster via p_sync.
 * Single-threaded (called from server event loop only).
 *
 * @file nodus_presence.c
 */

#include "server/nodus_presence.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "consensus/nodus_pbft.h"

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

static int alloc_slot(nodus_presence_table_t *tbl) {
    /* Reuse inactive slot */
    for (int i = 0; i < tbl->count; i++) {
        if (!tbl->entries[i].active)
            return i;
    }
    /* Append */
    if (tbl->count < NODUS_PRESENCE_MAX_ENTRIES)
        return tbl->count++;
    return -1;
}

/* ── Public API ───────────────────────────────────────────────────── */

void nodus_presence_add_local(struct nodus_server *srv, const nodus_key_t *fp) {
    if (!srv || !fp) return;
    nodus_presence_table_t *tbl = &srv->presence;

    /* Already exists as local? Just update timestamp */
    int idx = find_entry(tbl, fp, 0);
    if (idx >= 0) {
        tbl->entries[idx].last_seen = nodus_time_now();
        return;
    }

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
    if (idx >= 0)
        tbl->entries[idx].active = false;
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
                                 int fp_count, bool *online_out, uint8_t *peers_out) {
    if (!srv || !fps || !online_out) return -1;

    int online_count = 0;
    for (int i = 0; i < fp_count; i++) {
        uint8_t pi = 0;
        online_out[i] = nodus_presence_is_online(srv, &fps[i], &pi);
        if (peers_out)
            peers_out[i] = pi;
        if (online_out[i])
            online_count++;
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

    /* Send to all alive PBFT peers */
    for (int i = 0; i < srv->pbft.peer_count; i++) {
        nodus_cluster_peer_t *peer = &srv->pbft.peers[i];
        if (peer->state != NODUS_NODE_ALIVE) continue;

        nodus_tcp_conn_t *pconn = nodus_tcp_connect(
            (nodus_tcp_t *)&srv->tcp, peer->ip, peer->tcp_port);
        if (pconn) {
            nodus_tcp_send(pconn, sync_buf, sync_len);
            /* Fire-and-forget — connection managed by TCP layer */
        }
    }
}
