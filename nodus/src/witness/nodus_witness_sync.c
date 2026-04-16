/**
 * Nodus — Witness State Sync Implementation
 *
 * Block-by-block catch-up from peers with fork detection.
 */

#include "witness/nodus_witness_sync.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_peer.h"
#include "protocol/nodus_tier3.h"
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-SYNC"

/* Rate limiting */
#define SYNC_MIN_INTERVAL_SEC   30
#define SYNC_MAX_BLOCKS         1000

/* ── Helper: send w_sync_req to a peer ──────────────────────────── */

static int send_sync_req(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                          uint64_t height) {
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_SYNC_REQ;
    msg.txn_id = ++w->next_txn_id;

    msg.sync_req.height = height;

    /* Fill header */
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(msg.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&msg.header.nonce, sizeof(msg.header.nonce));
    memcpy(msg.header.chain_id, w->chain_id, 32);

    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode w_sync_req\n", LOG_TAG);
        return -1;
    }

    return nodus_tcp_send((nodus_tcp_conn_t *)conn, buf, len);
}

/* ── Helper: compute expected prev_hash from a block ────────────── */

static void compute_prev_hash(nodus_witness_t *w,
                                const nodus_witness_block_t *blk,
                                uint8_t *prev_hash_out) {
    /* Load chain_def_blob for genesis blocks so prev_hash of block 1
     * matches the anchored genesis block hash. */
    const uint8_t *cd_blob = NULL;
    size_t cd_len = 0;
    uint8_t *cd_alloc = NULL;
    if (blk->height == 0 && w && w->db) {
        sqlite3_stmt *cdst;
        if (sqlite3_prepare_v2(w->db,
                "SELECT chain_def_blob FROM blocks WHERE height = 0",
                -1, &cdst, NULL) == SQLITE_OK) {
            if (sqlite3_step(cdst) == SQLITE_ROW) {
                const void *blob = sqlite3_column_blob(cdst, 0);
                int blen = sqlite3_column_bytes(cdst, 0);
                if (blob && blen > 0) {
                    cd_alloc = malloc((size_t)blen);
                    if (cd_alloc) {
                        memcpy(cd_alloc, blob, (size_t)blen);
                        cd_blob = cd_alloc;
                        cd_len = (size_t)blen;
                    }
                }
            }
            sqlite3_finalize(cdst);
        }
    }
    nodus_witness_compute_block_hash_ex(blk->height,
                                          blk->prev_hash,
                                          blk->state_root,
                                          blk->tx_root,
                                          blk->tx_count,
                                          blk->timestamp,
                                          blk->proposer_id,
                                          cd_blob, cd_len,
                                          prev_hash_out);
    free(cd_alloc);
}

/* ── Helper: drop witness DB for fork rebuild ───────────────────── */

static int drop_witness_db(nodus_witness_t *w) {
    if (!w->db) return 0;  /* Already in pre-genesis state */

    /* Build DB file path from chain_id */
    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", w->chain_id[i]);

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/witness_%s.db",
             w->data_path, hex);

    /* Close DB */
    sqlite3_close(w->db);
    w->db = NULL;

    /* Delete file */
    if (unlink(db_path) != 0) {
        fprintf(stderr, "%s: failed to delete %s: %s\n",
                LOG_TAG, db_path, strerror(errno));
        return -1;
    }

    /* Clear chain_id */
    memset(w->chain_id, 0, 32);
    w->cached_state_root_valid = false;

    fprintf(stderr, "%s: dropped witness DB %s for fork rebuild\n",
            LOG_TAG, db_path);
    return 0;
}

/* ── Find best sync peer ────────────────────────────────────────── */

static int find_sync_peer(nodus_witness_t *w) {
    uint64_t local_height = nodus_witness_block_height(w);
    int best = -1;
    uint64_t best_height = local_height;

    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified || !w->peers[i].conn) continue;
        if (w->peers[i].conn->state != NODUS_CONN_CONNECTED) continue;
        if (w->peers[i].remote_height > best_height) {
            best_height = w->peers[i].remote_height;
            best = i;
        }
    }
    return best;
}

/* ── Sync check + initiate ──────────────────────────────────────── */

void nodus_witness_sync_check(nodus_witness_t *w) {
    if (!w || !w->running) return;

    /* Only sync during IDLE phase */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE) return;

    /* Already syncing */
    if (w->sync_state.syncing) return;

    /* Rate limit */
    uint64_t now = (uint64_t)time(NULL);
    if (now - w->sync_state.last_sync_attempt < SYNC_MIN_INTERVAL_SEC) return;

    /* Check for height gap — find peer with higher chain */
    int peer_idx = find_sync_peer(w);
    if (peer_idx < 0) return;  /* No peer ahead of us */

    uint64_t local_height = nodus_witness_block_height(w);
    uint64_t peer_height = w->peers[peer_idx].remote_height;

    /* Also check UTXO checksum mismatch at same height (fork detection) */
    if (peer_height == local_height && local_height > 0) {
        /* Same-height fork detection via checksum quorum */
        uint8_t local_cksum[NODUS_KEY_BYTES];
        if (w->cached_state_root_valid) {
            memcpy(local_cksum, w->cached_state_root, NODUS_KEY_BYTES);
        } else if (nodus_witness_merkle_compute_utxo_root(w, local_cksum) != 0) {
            return;  /* Can't compute checksum */
        }

        /* Count peers per checksum to find majority */
        int agree_count = 0;  /* peers that match our checksum */
        int disagree_count = 0;
        uint8_t zero[NODUS_KEY_BYTES];
        memset(zero, 0, sizeof(zero));

        for (int i = 0; i < w->peer_count; i++) {
            if (!w->peers[i].identified) continue;
            if (memcmp(w->peers[i].remote_checksum, zero, NODUS_KEY_BYTES) == 0) continue;
            if (w->peers[i].remote_height != local_height) continue;

            if (memcmp(w->peers[i].remote_checksum, local_cksum, NODUS_KEY_BYTES) == 0)
                agree_count++;
            else
                disagree_count++;
        }

        /* If majority disagrees, we're on wrong fork */
        if (disagree_count >= (int)w->bft_config.quorum && disagree_count > agree_count) {
            fprintf(stderr, "%s: UTXO checksum quorum disagrees (%d vs %d) — "
                    "fork at same height %llu, dropping DB\n",
                    LOG_TAG, disagree_count, agree_count,
                    (unsigned long long)local_height);

            w->sync_state.last_sync_attempt = now;
            if (drop_witness_db(w) != 0) return;

            /* Recalculate — now we're at height 0, peer is ahead */
            local_height = 0;
        } else {
            return;  /* No fork, nothing to sync */
        }
    }

    if (peer_height <= local_height) return;

    /* Don't sync until roster has quorum — cert verification needs roster peers */
    if (w->bft_config.quorum == 0) {
        fprintf(stderr, "%s: sync deferred — roster quorum not yet established\n", LOG_TAG);
        return;
    }

    fprintf(stderr, "%s: sync needed: local=%llu peer=%llu (peer_idx=%d)\n",
            LOG_TAG, (unsigned long long)local_height,
            (unsigned long long)peer_height, peer_idx);

    /* Start sync */
    w->sync_state.syncing = true;
    w->sync_state.sync_peer_idx = peer_idx;
    w->sync_state.sync_target_height = peer_height;
    w->sync_state.last_sync_attempt = now;

    /* Start from block 1 (genesis is height=1 in DB).
     * If local_height > 0: fork detection from block 1.
     * If local_height == 0: full sync from genesis (block 1). */
    w->sync_state.sync_current_height = 1;

    nodus_witness_sync_request_next(w);
}

/* ── Request next block ─────────────────────────────────────────── */

int nodus_witness_sync_request_next(nodus_witness_t *w) {
    if (!w->sync_state.syncing) return -1;

    int pi = w->sync_state.sync_peer_idx;
    if (pi < 0 || pi >= w->peer_count || !w->peers[pi].conn) {
        fprintf(stderr, "%s: sync peer lost, aborting\n", LOG_TAG);
        w->sync_state.syncing = false;
        return -1;
    }

    uint64_t h = w->sync_state.sync_current_height;

    fprintf(stderr, "%s: requesting block %llu from peer %d\n",
            LOG_TAG, (unsigned long long)h, pi);

    return send_sync_req(w, w->peers[pi].conn, h);
}

/* ── Handle incoming w_sync_req (server side) ───────────────────── */

int nodus_witness_sync_handle_req(nodus_witness_t *w,
                                   struct nodus_tcp_conn *conn,
                                   const nodus_t3_msg_t *msg) {
    if (!w || !conn || !msg) return -1;

    uint64_t height = msg->sync_req.height;

    /* Genesis is block height 0 in the request but stored as height 1 */
    uint64_t db_height = (height == 0) ? 1 : height;

    nodus_witness_block_t blk;
    if (nodus_witness_block_get(w, db_height, &blk) != 0) {
        /* Block not found — send empty response */
        nodus_t3_msg_t rsp;
        memset(&rsp, 0, sizeof(rsp));
        rsp.type = NODUS_T3_SYNC_RSP;
        rsp.txn_id = ++w->next_txn_id;
        rsp.sync_rsp.found = false;
        rsp.sync_rsp.height = height;

        rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
        memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
        rsp.header.timestamp = (uint64_t)time(NULL);
        nodus_random((uint8_t *)&rsp.header.nonce, sizeof(rsp.header.nonce));
        memcpy(rsp.header.chain_id, w->chain_id, 32);

        uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
        size_t len = 0;
        if (nodus_t3_encode(&rsp, &w->server->identity.sk,
                             buf, sizeof(buf), &len) != 0)
            return -1;
        return nodus_tcp_send((nodus_tcp_conn_t *)conn, buf, len);
    }

    /* Phase 11 / Task 11.1 — fetch ALL committed TXs in this block
     * via nodus_witness_block_txs_get. */
    nodus_witness_block_tx_row_t rows[NODUS_W_MAX_BLOCK_TXS];
    memset(rows, 0, sizeof(rows));
    int row_count = 0;
    if (nodus_witness_block_txs_get(w, db_height, rows,
                                      NODUS_W_MAX_BLOCK_TXS, &row_count) != 0 ||
        row_count == 0) {
        return -1;
    }

    /* Per-TX nullifier scratch — pointers into the row tx_data parse. */
    uint8_t nullifier_bufs[NODUS_W_MAX_BLOCK_TXS]
                          [NODUS_T3_MAX_TX_INPUTS]
                          [NODUS_T3_NULLIFIER_LEN];

    /* Get commit certificates */
    nodus_witness_vote_record_t certs[NODUS_T3_MAX_WITNESSES];
    int cert_count = 0;
    nodus_witness_cert_get(w, db_height, certs, NODUS_T3_MAX_WITNESSES, &cert_count);

    /* Build response */
    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_SYNC_RSP;
    rsp.txn_id = ++w->next_txn_id;

    rsp.sync_rsp.found = true;
    rsp.sync_rsp.height = height;
    rsp.sync_rsp.timestamp = blk.timestamp;
    memcpy(rsp.sync_rsp.proposer_id, blk.proposer_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(rsp.sync_rsp.prev_hash, blk.prev_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(rsp.sync_rsp.tx_root, blk.tx_root, NODUS_T3_TX_HASH_LEN);
    rsp.sync_rsp.tx_count = row_count;

    /* Phase 11 follow-up — committed_transactions now stores
     * client_pubkey and client_sig (migration v13 client-fields). Use
     * the real values when present; fall back to zero pad on rows that
     * predate the migration. The wire encoder requires non-NULL bstr
     * pointers either way. */
    static const uint8_t zero_pk[NODUS_PK_BYTES] = {0};
    static const uint8_t zero_sig[NODUS_SIG_BYTES] = {0};

    for (int i = 0; i < row_count; i++) {
        nodus_t3_batch_tx_t *btx = &rsp.sync_rsp.batch_txs[i];
        memcpy(btx->tx_hash, rows[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        btx->tx_type = rows[i].tx_type;
        btx->tx_data = rows[i].tx_data;
        btx->tx_len = rows[i].tx_len;
        btx->client_pubkey = rows[i].client_pubkey ?
                              rows[i].client_pubkey : zero_pk;
        btx->client_sig = rows[i].client_sig ?
                            rows[i].client_sig : zero_sig;
        btx->fee = 0;
        /* Parse input nullifiers from tx_data for the wire, mirrors
         * the existing batch-propose pattern. */
        if (rows[i].tx_data && rows[i].tx_len > 75 &&
            rows[i].tx_type != NODUS_W_TX_GENESIS) {
            size_t off = 74;
            uint8_t nc = rows[i].tx_data[off++];
            if (nc > NODUS_T3_MAX_TX_INPUTS) nc = NODUS_T3_MAX_TX_INPUTS;
            btx->nullifier_count = nc;
            for (int j = 0; j < nc; j++) {
                if (off + NODUS_T3_NULLIFIER_LEN > rows[i].tx_len) break;
                memcpy(nullifier_bufs[i][j], rows[i].tx_data + off,
                       NODUS_T3_NULLIFIER_LEN);
                btx->nullifiers[j] = nullifier_bufs[i][j];
                off += NODUS_T3_NULLIFIER_LEN + 8 + 64;
            }
        }
    }

    /* Convert vote records to sync certs */
    rsp.sync_rsp.cert_count = (uint32_t)cert_count;
    for (int i = 0; i < cert_count && i < NODUS_T3_MAX_WITNESSES; i++) {
        memcpy(rsp.sync_rsp.certs[i].voter_id, certs[i].voter_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(rsp.sync_rsp.certs[i].signature, certs[i].signature,
               NODUS_SIG_BYTES);
    }

    /* Encode and send — use heap buffer for large responses */
    rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    rsp.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&rsp.header.nonce, sizeof(rsp.header.nonce));
    memcpy(rsp.header.chain_id, w->chain_id, 32);

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) {
        for (int i = 0; i < row_count; i++)
            nodus_witness_block_tx_row_free(&rows[i]);
        return -1;
    }
    size_t len = 0;

    int rc = nodus_t3_encode(&rsp, &w->server->identity.sk,
                              buf, NODUS_W_MAX_SYNC_RSP_SIZE, &len);
    /* Phase 11 / Task 11.3 — tier 3 aggregate guard. */
    if (rc == 0 && len > NODUS_W_MAX_SYNC_RSP_SIZE) {
        fprintf(stderr, "%s: sync_rsp encode size %zu > 1 MB cap\n",
                LOG_TAG, len);
        rc = -1;
    }
    if (rc == 0)
        nodus_tcp_send((nodus_tcp_conn_t *)conn, buf, len);

    free(buf);
    for (int i = 0; i < row_count; i++)
        nodus_witness_block_tx_row_free(&rows[i]);
    return rc;
}

/* ── Handle incoming w_sync_rsp (client side) ───────────────────── */

int nodus_witness_sync_handle_rsp(nodus_witness_t *w,
                                   const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;
    if (!w->sync_state.syncing) {
        fprintf(stderr, "%s: received w_sync_rsp but not syncing\n", LOG_TAG);
        return -1;
    }

    const nodus_t3_sync_rsp_t *rsp = &msg->sync_rsp;

    if (!rsp->found) {
        fprintf(stderr, "%s: peer does not have block %llu, aborting sync\n",
                LOG_TAG, (unsigned long long)rsp->height);
        w->sync_state.syncing = false;
        return -1;
    }

    uint64_t local_height = nodus_witness_block_height(w);
    uint64_t expected_height = w->sync_state.sync_current_height;

    fprintf(stderr, "%s: received block %llu (local=%llu, target=%llu)\n",
            LOG_TAG, (unsigned long long)rsp->height,
            (unsigned long long)local_height,
            (unsigned long long)w->sync_state.sync_target_height);

    /* Phase 1: Fork detection — compare block hashes for existing blocks */
    /* Map height: request height 0 = genesis = DB height 1 */
    uint64_t db_height = (rsp->height == 0) ? 1 : rsp->height;

    if (db_height <= local_height) {
        /* We have this block — compare tx_root values for fork detection. */
        nodus_witness_block_t local_blk;
        if (nodus_witness_block_get(w, db_height, &local_blk) == 0) {
            if (memcmp(local_blk.tx_root, rsp->tx_root,
                       NODUS_T3_TX_HASH_LEN) != 0) {
                /* Fork detected! */
                if (db_height == 1) {
                    /* Genesis mismatch — different chain, abort */
                    fprintf(stderr, "%s: GENESIS MISMATCH — different chain, "
                            "aborting sync\n", LOG_TAG);
                    w->sync_state.syncing = false;
                    return -1;
                }

                fprintf(stderr, "%s: FORK DETECTED at height %llu — "
                        "dropping DB for full resync\n",
                        LOG_TAG, (unsigned long long)db_height);

                if (drop_witness_db(w) != 0) {
                    w->sync_state.syncing = false;
                    return -1;
                }

                /* Reset sync to start from genesis (height=1 in DB) */
                w->sync_state.sync_current_height = 1;
                return nodus_witness_sync_request_next(w);
            }

            /* Block matches — continue fork check with next block */
            w->sync_state.sync_current_height = expected_height + 1;

            /* If we've verified all local blocks, switch to replay mode */
            if (w->sync_state.sync_current_height > local_height) {
                /* Fork check complete, no fork found. Start replay. */
                fprintf(stderr, "%s: fork check complete — no fork, "
                        "replaying from %llu\n", LOG_TAG,
                        (unsigned long long)w->sync_state.sync_current_height);
            }

            /* Check if done */
            if (w->sync_state.sync_current_height > w->sync_state.sync_target_height) {
                fprintf(stderr, "%s: sync complete (verified all blocks)\n", LOG_TAG);
                w->sync_state.syncing = false;
                return 0;
            }

            return nodus_witness_sync_request_next(w);
        }
    }

    /* Phase 3: Block replay — verify and commit */

    /* Check: prevent duplicate blocks */
    if (local_height >= db_height) {
        fprintf(stderr, "%s: already have block %llu, skipping\n",
                LOG_TAG, (unsigned long long)db_height);
        w->sync_state.sync_current_height = expected_height + 1;
        goto next;
    }

    /* Verify prev_hash chain continuity */
    if (db_height == 1) {
        /* Genesis: prev_hash must be all zeros */
        uint8_t zeros[NODUS_T3_TX_HASH_LEN];
        memset(zeros, 0, sizeof(zeros));
        if (memcmp(rsp->prev_hash, zeros, NODUS_T3_TX_HASH_LEN) != 0) {
            fprintf(stderr, "%s: genesis prev_hash not zero, rejecting\n", LOG_TAG);
            w->sync_state.syncing = false;
            return -1;
        }
    } else {
        /* Non-genesis: verify prev_hash matches our latest block */
        nodus_witness_block_t latest;
        if (nodus_witness_block_get_latest(w, &latest) == 0) {
            uint8_t expected_prev[NODUS_T3_TX_HASH_LEN];
            compute_prev_hash(w, &latest, expected_prev);

            if (memcmp(rsp->prev_hash, expected_prev, NODUS_T3_TX_HASH_LEN) != 0) {
                fprintf(stderr, "%s: prev_hash mismatch at height %llu, "
                        "aborting sync\n", LOG_TAG,
                        (unsigned long long)db_height);
                w->sync_state.syncing = false;
                return -1;
            }
        }
    }

    /* Phase 11 / Task 11.4 — three-step receiver recomputation. */
    if (rsp->tx_count <= 0 || rsp->tx_count > NODUS_W_MAX_BLOCK_TXS) {
        fprintf(stderr, "%s: sync_rsp tx_count %d out of range\n",
                LOG_TAG, rsp->tx_count);
        w->sync_state.syncing = false;
        return -1;
    }

    /* Step a — recompute tx_root locally and check vs wire claim */
    uint8_t local_tx_root[NODUS_T3_TX_HASH_LEN];
    {
        uint8_t flat[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
        for (int i = 0; i < rsp->tx_count; i++) {
            memcpy(flat + i * NODUS_T3_TX_HASH_LEN,
                   rsp->batch_txs[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        }
        if (nodus_witness_merkle_tx_root(flat, (uint32_t)rsp->tx_count,
                                           local_tx_root) != 0) {
            fprintf(stderr, "%s: local tx_root compute failed\n", LOG_TAG);
            w->sync_state.syncing = false;
            return -1;
        }
    }
    if (memcmp(local_tx_root, rsp->tx_root, NODUS_T3_TX_HASH_LEN) != 0) {
        fprintf(stderr, "%s: tx_root divergence — sender lied at height %llu\n",
                LOG_TAG, (unsigned long long)db_height);
        w->sync_state.syncing = false;
        return -1;
    }

    /* Step b — recompute block_hash with the locally-derived tx_root.
     * state_root is unknown until replay so pass NULL; the helper
     * accepts a NULL state_root for the cert-preimage path. */
    uint8_t local_block_hash[NODUS_T3_TX_HASH_LEN];
    nodus_witness_compute_block_hash(db_height, rsp->prev_hash,
                                       NULL,
                                       local_tx_root,
                                       (uint32_t)rsp->tx_count,
                                       rsp->timestamp,
                                       rsp->proposer_id,
                                       local_block_hash);

    /* Step c — verify cert sigs against the LOCAL block_hash */
    {
        int verified = nodus_witness_verify_sync_certs(local_block_hash,
                                                         db_height,
                                                         w->chain_id,
                                                         &w->roster,
                                                         rsp->certs,
                                                         rsp->cert_count,
                                                         w->bft_config.quorum);
        if (verified < 0) {
            fprintf(stderr, "%s: cert verify FAILED at height %llu "
                    "(< quorum %u)\n", LOG_TAG,
                    (unsigned long long)db_height, w->bft_config.quorum);
            w->sync_state.syncing = false;
            return -1;
        }
        fprintf(stderr, "%s: block %llu certs verified: %d/%u (quorum=%u)\n",
                LOG_TAG, (unsigned long long)db_height,
                verified, rsp->cert_count, w->bft_config.quorum);
    }

    /* Step d — replay every TX in the block via Phase 6 wrappers */
    {
        nodus_witness_mempool_entry_t entries[NODUS_W_MAX_BLOCK_TXS];
        nodus_witness_mempool_entry_t *entry_ptrs[NODUS_W_MAX_BLOCK_TXS];
        memset(entries, 0, sizeof(entries));

        for (int i = 0; i < rsp->tx_count; i++) {
            const nodus_t3_batch_tx_t *btx = &rsp->batch_txs[i];
            nodus_witness_mempool_entry_t *e = &entries[i];
            memcpy(e->tx_hash, btx->tx_hash, NODUS_T3_TX_HASH_LEN);
            e->tx_type = btx->tx_type;
            e->nullifier_count = btx->nullifier_count;
            for (int j = 0; j < btx->nullifier_count; j++) {
                if (btx->nullifiers[j])
                    memcpy(e->nullifiers[j], btx->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
            }
            e->tx_data = (uint8_t *)btx->tx_data;
            e->tx_len = btx->tx_len;
            entry_ptrs[i] = e;
        }

        int rc;
        if (rsp->tx_count == 1 &&
            entries[0].tx_type == NODUS_W_TX_GENESIS) {
            rc = nodus_witness_commit_genesis(w, entries[0].tx_hash,
                                                entries[0].tx_data,
                                                entries[0].tx_len,
                                                rsp->timestamp,
                                                rsp->proposer_id);
        } else {
            rc = nodus_witness_replay_block(w, db_height, entry_ptrs,
                                              rsp->tx_count,
                                              rsp->timestamp,
                                              rsp->proposer_id);
        }
        if (rc != 0) {
            fprintf(stderr, "%s: block replay failed at height %llu\n",
                    LOG_TAG, (unsigned long long)db_height);
            w->sync_state.syncing = false;
            return -1;
        }
    }

    /* Store commit certificates */
    {
        uint64_t stored_bh = nodus_witness_block_height(w);
        nodus_witness_vote_record_t votes[NODUS_T3_MAX_WITNESSES];
        for (uint32_t i = 0; i < rsp->cert_count && i < NODUS_T3_MAX_WITNESSES; i++) {
            memcpy(votes[i].voter_id, rsp->certs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN);
            votes[i].vote = NODUS_W_VOTE_APPROVE;
            memcpy(votes[i].signature, rsp->certs[i].signature,
                   NODUS_SIG_BYTES);
        }
        nodus_witness_cert_store(w, stored_bh, votes, (int)rsp->cert_count);
    }

    /* Update cached UTXO checksum */
    if (nodus_witness_merkle_compute_utxo_root(w, w->cached_state_root) == 0)
        w->cached_state_root_valid = true;

    fprintf(stderr, "%s: replayed block %llu OK\n",
            LOG_TAG, (unsigned long long)db_height);

    w->sync_state.sync_current_height = expected_height + 1;

next:
    /* Check if sync is complete */
    if (w->sync_state.sync_current_height > w->sync_state.sync_target_height) {
        uint64_t final_height = nodus_witness_block_height(w);
        fprintf(stderr, "%s: SYNC COMPLETE — height now %llu\n",
                LOG_TAG, (unsigned long long)final_height);
        w->sync_state.syncing = false;

        /* Update cached UTXO checksum */
        if (nodus_witness_merkle_compute_utxo_root(w, w->cached_state_root) == 0)
            w->cached_state_root_valid = true;

        return 0;
    }

    /* Enforce max blocks per sync session */
    uint64_t blocks_synced = w->sync_state.sync_current_height;
    if (blocks_synced > SYNC_MAX_BLOCKS) {
        fprintf(stderr, "%s: max blocks per session (%d) reached, pausing\n",
                LOG_TAG, SYNC_MAX_BLOCKS);
        w->sync_state.syncing = false;
        return 0;
    }

    /* Request next block */
    return nodus_witness_sync_request_next(w);
}
