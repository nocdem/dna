/**
 * @file nodus/src/witness/nodus_witness_v2_join.c
 * @brief Ledger V2 O15E Faz D — pinned-genesis joiner bootstrap.
 *
 * Contract and the trust model are in the header. The joiner pulls the
 * canonical genesis bundle, re-derives the genesis in a scratch DB, and
 * adopts it in place ONLY when the derived BlockID equals the local pin.
 * There is ONE derivation engine (nodus_witness_v2_bundle_apply →
 * nodus_witness_v2_genesis_ex); this module is transport + lifecycle.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_v2_join.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_db.h"
#include "server/nodus_server.h"
#include "nodus/nodus_chain_config.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2JOIN"

#define V2JOIN_REQ_INTERVAL_MS  4000u   /* bundle-chunk request cadence   */

static uint64_t join_mono_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Remove a scratch derivation directory and its files (best effort — a
 * crashed prior attempt or a completed one). Only the two files the
 * derivation can create are unlinked; the seam uses the same shape. */
static void join_scratch_clear(const char *dir) {
    if (!dir || !dir[0]) return;
    /* the derivation creates witness_*.db (+ -wal/-shm) under `dir`;
     * unlink by globbing is avoided — rmdir fails if non-empty, so
     * remove the known artifacts first. A leftover unknown file only
     * makes rmdir fail, which is harmless (next run reuses the dir). */
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char p[600];
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

int nodus_witness_v2_join_arm(nodus_witness_t *w) {
    if (!w || !w->server) return -1;
    if (!w->server->config.has_v2_genesis_pin) return 0;   /* not a joiner */

    /* If a chain is already open (successor scan found one), this node is
     * NOT a fresh joiner — the pin is inert. */
    if (w->db) return 0;

    memcpy(w->v2_join.pin, w->server->config.v2_genesis_pin, 64);
    w->v2_join.active    = 1;
    w->v2_join.acc       = NULL;
    w->v2_join.acc_len   = 0;
    w->v2_join.acc_total = 0;
    w->v2_join.last_req_ms = 0;
    QGP_LOG_INFO(LOG_TAG, "%s", "fresh successor joiner armed with a local "
                 "genesis pin — will pull the genesis bundle");
    return 1;
}

int nodus_witness_v2_join_active(nodus_witness_t *w) {
    return w && w->v2_join.active;
}

static void join_reset_acc(nodus_witness_t *w) {
    free(w->v2_join.acc);
    w->v2_join.acc = NULL;
    w->v2_join.acc_len = 0;
    w->v2_join.acc_total = 0;
}

/* Adopt the fully-received bundle: re-derive the genesis in a scratch DB
 * against the local pin and, on a match, rename it into the real data
 * path and open the main witness on it. Returns 0 adopted, -1 not (the
 * joiner stays active and retries). */
static int join_adopt(nodus_witness_t *w) {
    const uint8_t *bytes = w->v2_join.acc;
    size_t len = w->v2_join.acc_len;

    nodus_witness_t *w2 = calloc(1, sizeof(*w2));
    if (!w2) return -1;
    w2->cached_committee_epoch_start = UINT64_MAX;
    w2->server = w->server;               /* identity only; no signing here */

    snprintf(w2->data_path, sizeof(w2->data_path), "%s/.v2join.tmp",
             w->data_path);
    join_scratch_clear(w2->data_path);
    if (mkdir(w2->data_path, 0700) != 0 && errno != EEXIST) {
        w2->server = NULL; free(w2); return -1;
    }

    /* Provisional deterministic name; renamed to the real chain id after
     * a COMPLETE, pin-matched derivation. */
    uint8_t prov16[16];
    memcpy(prov16, w->v2_join.pin, 16);   /* pin[0..15] — deterministic   */
    char prov_path[512];
    {
        char hex[33];
        for (int i = 0; i < 16; i++)
            snprintf(hex + i * 2, 3, "%02x", prov16[i]);
        snprintf(prov_path, sizeof(prov_path), "%s/witness_%s.db",
                 w2->data_path, hex);
    }

    int adopted = -1;
    do {
        if (nodus_witness_create_chain_db(w2, prov16) != 0) break;
        /* O15F Task 5 (defence-in-depth): mark the scratch handle a V2
         * chain before its genesis re-derivation (bundle_apply →
         * vset_commit_genesis → genesis_ex), the same way every chain
         * builder does immediately after create_chain_db. This makes the
         * D1 max-30 target clamp fire during the joiner's re-derivation
         * too; correctness is already backstopped by the byte-identical
         * pin check below, but the guard is now uniform across the
         * builder and the joiner. */
        w2->v2_successor = 1;
        /* O15F Task 4: the joiner re-derives its OWN V2 database and MUST
         * land at the same schema the chain builder produces (S12,
         * nodus_witness_v2_gen.c) — otherwise it would lack
         * v2_claim_counts and could serve no height under the
         * count-row-driven serving seam. */
        if (nodus_witness_db_migrate_v2s12(w2) != 0) break;
        if (nodus_chain_config_db_migrate(w2) != 0) break;

        if (nodus_witness_v2_bundle_apply(w2, bytes, len,
                                          w->v2_join.pin) != 0) {
            QGP_LOG_WARN(LOG_TAG, "%s", "bundle did not re-derive to the "
                         "local pin — rejecting (will retry)");
            break;
        }

        uint8_t chain32[32];
        if (nodus_witness_v2_chain_id(w2, chain32) != 0) break;
        /* chain id = genesis BlockID[0..31] = pin[0..31] (genesis_ex
         * asserted the full id). Verify the coupling explicitly. */
        if (memcmp(chain32, w->v2_join.pin, 32) != 0) break;

        sqlite3_close(w2->db);
        w2->db = NULL;

        char real_path[512];
        {
            char hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(hex + i * 2, 3, "%02x", chain32[i]);
            snprintf(real_path, sizeof(real_path), "%s/witness_%s.db",
                     w->data_path, hex);
        }
        if (rename(prov_path, real_path) != 0) break;
        adopted = 0;
    } while (0);

    if (w2->db) { sqlite3_close(w2->db); w2->db = NULL; }
    join_scratch_clear(w2->data_path);
    w2->server = NULL;
    free(w2);

    if (adopted != 0) return -1;

    /* Open the main witness on the adopted successor — the SAME path a
     * restart takes (scan → open → post-open gate arms ingress). */
    if (nodus_witness_scan_chain_db(w) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "adopted successor did not open — "
                      "fatal joiner state");
        return -1;
    }
    w->v2_join.active = 0;
    join_reset_acc(w);
    QGP_LOG_INFO(LOG_TAG, "%s", "successor genesis adopted from a peer "
                 "bundle (pin matched) — now catching up to head");
    return 0;
}

void nodus_witness_v2_join_handle_gbundle_r(nodus_witness_t *w,
                                            struct nodus_tcp_conn *conn,
                                            const nodus_t3_msg_t *msg) {
    (void)conn;
    if (!w || !msg || !w->v2_join.active) return;

    const nodus_t3_w_v2_gbundle_r_t *r = &msg->w_v2_gbundle_r;

    /* The bundle is FOR our pin, and its chain field must equal
     * pin[0..31] (chain id derives from the genesis id). A response for
     * anything else is ignored — the pin is the only anchor. */
    if (memcmp(r->pin, w->v2_join.pin, 64) != 0) return;
    if (memcmp(r->chain, w->v2_join.pin, 32) != 0) return;
    if (r->total == 0 || r->total > (64u * 1024u * 1024u)) return;
    if (r->chunk_len == 0) return;

    /* Contiguous append only: a chunk must start exactly where we are.
     * Out-of-order or overlapping chunks are dropped (the next request
     * re-asks from acc_len), so no peer can scramble the buffer. */
    if (r->offset != w->v2_join.acc_len) return;
    if ((uint64_t)w->v2_join.acc_len + r->chunk_len > r->total) return;

    if (w->v2_join.acc_total == 0) {
        w->v2_join.acc = malloc((size_t)r->total);
        if (!w->v2_join.acc) return;
        w->v2_join.acc_total = (size_t)r->total;
    } else if (w->v2_join.acc_total != (size_t)r->total) {
        /* the total changed mid-transfer — a different bundle; restart */
        join_reset_acc(w);
        return;
    }

    memcpy(w->v2_join.acc + w->v2_join.acc_len, r->chunk, r->chunk_len);
    w->v2_join.acc_len += r->chunk_len;

    if (w->v2_join.acc_len < w->v2_join.acc_total) return;   /* more chunks */

    QGP_LOG_INFO(LOG_TAG, "genesis bundle fully received (%zu bytes) — "
                 "re-deriving against the local pin", w->v2_join.acc_len);
    if (join_adopt(w) != 0) {
        /* Rejected / faulted — drop the buffer and let the tick re-pull
         * from a fresh offset (possibly from a different peer). */
        join_reset_acc(w);
    }
}

void nodus_witness_v2_join_tick(nodus_witness_t *w) {
    if (!w || !w->v2_join.active) return;
    if (w->peer_count <= 0) return;

    uint64_t now = join_mono_ms();
    if (w->v2_join.last_req_ms != 0 &&
        now - w->v2_join.last_req_ms < V2JOIN_REQ_INTERVAL_MS)
        return;

    /* One request to one identified peer per interval, at the current
     * accumulated offset. The response accumulates; when complete, the
     * handler adopts. A dead/mismatched peer simply yields nothing and
     * the next tick asks again (round-robin over peers by tick timing). */
    struct nodus_tcp_conn *conn = NULL;
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn && w->peers[i].identified) {
            conn = w->peers[i].conn;
            break;
        }
    }
    if (!conn) return;

    nodus_t3_msg_t req;
    memset(&req, 0, sizeof(req));
    req.type = NODUS_T3_V2_GBUNDLE_REQ;
    memcpy(req.w_v2_gbundle_q.chain, w->v2_join.pin, 32);
    memcpy(req.w_v2_gbundle_q.pin, w->v2_join.pin, 64);
    req.w_v2_gbundle_q.offset = (uint64_t)w->v2_join.acc_len;

    const char *method = nodus_t3_type_to_method(req.type);
    if (method) snprintf(req.method, sizeof(req.method), "%s", method);
    req.header.version = 1;
    memcpy(req.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    req.header.timestamp = (uint64_t)time(NULL);
    /* A joiner has no chain_id yet — leave the header chain_id zero. This
     * is safe: verify_chain_id() runs ONLY inside the BFT round handlers
     * (nodus_witness_bft.c handle_propose/vote/commit/viewchg/newview),
     * never on the sync/serve dispatch path, so a zero chain_id in a
     * gbundle request is not rejected. The serve side authenticates the
     * request by the sender's roster pubkey (the joiner is admitted to
     * committee members' TRANSPORT rosters via the DHT nodus:pk registry
     * — rebuild_roster_from_peers, which applies NO committee filter —
     * with the O15B.1 ~2-minute visibility latency) and authorizes it by
     * the pin equalling the committed genesis. */

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) return;
    size_t len = 0;
    if (nodus_t3_encode(&req, &w->server->identity.sk, buf,
                        NODUS_W_MAX_SYNC_RSP_SIZE, &len) == 0)
        (void)nodus_tcp_send(conn, buf, len);
    free(buf);
    w->v2_join.last_req_ms = now;
}
