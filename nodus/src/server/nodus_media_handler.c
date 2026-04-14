/**
 * Nodus — Server-side Media Request Handlers
 *
 * Handles chunked media upload (m_put), metadata retrieval (m_meta),
 * and chunk download (m_chunk) for authenticated clients.
 *
 * @file nodus_media_handler.c
 */

#include "server/nodus_media_handler.h"
#include "core/nodus_media_storage.h"
#include "protocol/nodus_tier2.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#define LOG_TAG "MEDIA_HDL"

/* Response buffer — per-thread to avoid contention with server's resp_buf.
 * Must accommodate max chunk (4MB) + CBOR overhead. */
static __thread uint8_t media_resp_buf[NODUS_MAX_VALUE_SIZE + 65536];

/** Convert binary fingerprint to hex string */
static void fp_to_hex(const nodus_key_t *fp, char hex_out[NODUS_KEY_HEX_LEN]) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++)
        snprintf(hex_out + i * 2, NODUS_KEY_HEX_LEN - i * 2, "%02x", fp->bytes[i]);
    hex_out[128] = '\0';
}

void handle_t2_media_put(nodus_server_t *srv, nodus_session_t *sess,
                         nodus_tier2_msg_t *msg) {
    size_t rlen = 0;

    /* Validate chunk data size */
    if (msg->data_len > NODUS_MEDIA_MAX_CHUNK_SIZE) {
        QGP_LOG_WARN(LOG_TAG, "m_put: chunk too large (%zu > %d)",
                     msg->data_len, NODUS_MEDIA_MAX_CHUNK_SIZE);
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                       "chunk exceeds max size",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    /* Validate total size */
    if (msg->media_total_size > NODUS_MEDIA_MAX_TOTAL_SIZE) {
        QGP_LOG_WARN(LOG_TAG, "m_put: total size too large (%llu > %llu)",
                     (unsigned long long)msg->media_total_size,
                     (unsigned long long)NODUS_MEDIA_MAX_TOTAL_SIZE);
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                       "media exceeds max total size",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    /* Validate chunk count */
    if (msg->media_chunk_count > NODUS_MEDIA_MAX_CHUNKS) {
        QGP_LOG_WARN(LOG_TAG, "m_put: too many chunks (%u > %d)",
                     msg->media_chunk_count, NODUS_MEDIA_MAX_CHUNKS);
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                       "too many chunks",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    /* Check dedup: if media already exists and is complete, short-circuit */
    bool exists = false, complete = false;
    if (nodus_media_exists(&srv->media_storage, msg->media_hash,
                           &exists, &complete) == 0 && exists && complete) {
        QGP_LOG_DEBUG(LOG_TAG, "m_put: dedup hit, chunk_idx=%u already complete",
                      msg->media_chunk_idx);
        nodus_t2_media_put_ok(msg->txn_id, msg->media_chunk_idx, true,
                              media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    /* First chunk (index 0): check per-owner quota and create metadata */
    if (msg->media_chunk_idx == 0) {
        char owner_hex[NODUS_KEY_HEX_LEN];
        fp_to_hex(&sess->client_fp, owner_hex);

        int owner_count = nodus_media_count_per_owner(&srv->media_storage, owner_hex);
        if (owner_count >= NODUS_MEDIA_MAX_PER_USER) {
            QGP_LOG_WARN(LOG_TAG, "m_put: owner quota exceeded (%d >= %d)",
                         owner_count, NODUS_MEDIA_MAX_PER_USER);
            nodus_t2_error(msg->txn_id, NODUS_ERR_QUOTA_EXCEEDED,
                           "media quota exceeded",
                           media_resp_buf, sizeof(media_resp_buf), &rlen);
            nodus_tcp_send(sess->conn, media_resp_buf, rlen);
            return;
        }

        /* Create metadata record */
        nodus_media_meta_t meta;
        memset(&meta, 0, sizeof(meta));
        memcpy(meta.content_hash, msg->media_hash, 64);
        memcpy(meta.owner_fp, owner_hex, NODUS_KEY_HEX_LEN);
        meta.media_type = msg->media_type;
        meta.total_size = msg->media_total_size;
        meta.chunk_count = msg->media_chunk_count;
        meta.encrypted = msg->media_encrypted;
        meta.ttl = msg->ttl;
        meta.created_at = (uint64_t)time(NULL);
        meta.expires_at = (meta.ttl > 0) ? meta.created_at + meta.ttl : 0;
        meta.complete = false;

        int rc = nodus_media_put_meta(&srv->media_storage, &meta);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "m_put: put_meta failed rc=%d", rc);
            nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                           "media meta storage failed",
                           media_resp_buf, sizeof(media_resp_buf), &rlen);
            nodus_tcp_send(sess->conn, media_resp_buf, rlen);
            return;
        }
    }

    /* Store chunk data */
    int rc = nodus_media_put_chunk(&srv->media_storage, msg->media_hash,
                                   msg->media_chunk_idx,
                                   msg->data, msg->data_len);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "m_put: put_chunk failed idx=%u rc=%d",
                      msg->media_chunk_idx, rc);
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                       "chunk storage failed",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    /* Check if all chunks are now present */
    bool is_complete = false;
    int chunk_count = nodus_media_count_chunks(&srv->media_storage, msg->media_hash);

    /* Retrieve meta to get expected chunk_count */
    nodus_media_meta_t stored_meta;
    if (nodus_media_get_meta(&srv->media_storage, msg->media_hash, &stored_meta) == 0) {
        if (chunk_count >= (int)stored_meta.chunk_count) {
            nodus_media_mark_complete(&srv->media_storage, msg->media_hash);
            is_complete = true;
            QGP_LOG_INFO(LOG_TAG, "m_put: media complete (%d/%u chunks)",
                         chunk_count, stored_meta.chunk_count);
        }

        /* Replicate this chunk to K-closest nodes */
        nodus_server_replicate_media_chunk(srv, &stored_meta, msg->media_chunk_idx,
                                            msg->data, msg->data_len);
    }

    /* Respond OK */
    nodus_t2_media_put_ok(msg->txn_id, msg->media_chunk_idx, is_complete,
                          media_resp_buf, sizeof(media_resp_buf), &rlen);
    nodus_tcp_send(sess->conn, media_resp_buf, rlen);
}

void handle_t2_media_get_meta(nodus_server_t *srv, nodus_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    size_t rlen = 0;

    nodus_media_meta_t meta;
    int rc = nodus_media_get_meta(&srv->media_storage, msg->media_hash, &meta);
    if (rc != 0 || !meta.complete) {
        QGP_LOG_DEBUG(LOG_TAG, "m_meta: not found or incomplete rc=%d complete=%d",
                      rc, meta.complete);
        nodus_t2_error(msg->txn_id, NODUS_ERR_NOT_FOUND,
                       "media not found",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    nodus_t2_media_meta_result(msg->txn_id, &meta,
                               media_resp_buf, sizeof(media_resp_buf), &rlen);
    nodus_tcp_send(sess->conn, media_resp_buf, rlen);
}

void handle_t2_media_get_chunk(nodus_server_t *srv, nodus_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    size_t rlen = 0;

    /* Check media exists and is complete */
    bool exists = false, complete = false;
    nodus_media_exists(&srv->media_storage, msg->media_hash, &exists, &complete);
    if (!exists || !complete) {
        QGP_LOG_DEBUG(LOG_TAG, "m_chunk: media not found or incomplete");
        nodus_t2_error(msg->txn_id, NODUS_ERR_NOT_FOUND,
                       "media not found",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    /* Retrieve chunk */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int rc = nodus_media_get_chunk(&srv->media_storage, msg->media_hash,
                                   msg->media_chunk_idx, &data, &data_len);
    if (rc != 0 || !data) {
        QGP_LOG_DEBUG(LOG_TAG, "m_chunk: chunk %u not found rc=%d",
                      msg->media_chunk_idx, rc);
        nodus_t2_error(msg->txn_id, NODUS_ERR_NOT_FOUND,
                       "chunk not found",
                       media_resp_buf, sizeof(media_resp_buf), &rlen);
        nodus_tcp_send(sess->conn, media_resp_buf, rlen);
        return;
    }

    nodus_t2_media_chunk_result(msg->txn_id, msg->media_chunk_idx,
                                data, data_len,
                                media_resp_buf, sizeof(media_resp_buf), &rlen);
    nodus_tcp_send(sess->conn, media_resp_buf, rlen);
    free(data);
}
