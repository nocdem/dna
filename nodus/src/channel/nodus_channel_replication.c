/**
 * Nodus -- Channel Replication (TCP 4003)
 *
 * PRIMARY -> BACKUP replication, hinted handoff, incremental sync.
 * All replication traffic goes over TCP 4003 (never 4002).
 *
 * @file nodus_channel_replication.c
 */

#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_hashring.h"
#include "protocol/nodus_tier2.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Portable strndup (missing on Windows — both MSVC and MinGW) */
#ifdef _WIN32
static char *portable_strndup(const char *s, size_t n) {
    size_t len = 0;
    while (len < n && s[len]) len++;
    char *p = (char *)malloc(len + 1);
    if (p) { memcpy(p, s, len); p[len] = '\0'; }
    return p;
}
#define strndup portable_strndup
#endif

#define LOG_TAG "CH_REPL"

/* Max encoded replication message size (post + Dilithium5 sig ~10KB) */
#define REPL_BUF_SIZE 16384

/* ---- H-08: Post signature verification helpers (shared with primary.c) -- */

static void repl_uuid_to_string(const uint8_t uuid[NODUS_UUID_BYTES], char out[37]) {
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);
}

static void repl_fp_to_hex(const nodus_key_t *fp, char out[NODUS_KEY_HEX_LEN]) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++)
        snprintf(out + i * 2, 3, "%02x", fp->bytes[i]);
}

static int repl_json_escape(const char *src, size_t src_len,
                             char *dst, size_t dst_cap) {
    size_t w = 0;
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\'; dst[w++] = (char)c;
        } else if (c == '\n') { if (w+2>dst_cap) return -1; dst[w++]='\\'; dst[w++]='n';
        } else if (c == '\r') { if (w+2>dst_cap) return -1; dst[w++]='\\'; dst[w++]='r';
        } else if (c == '\t') { if (w+2>dst_cap) return -1; dst[w++]='\\'; dst[w++]='t';
        } else if (c < 0x20) {
            if (w + 6 > dst_cap) return -1;
            w += (size_t)snprintf(dst + w, dst_cap - w, "\\u%04x", c);
        } else {
            if (w + 1 > dst_cap) return -1;
            dst[w++] = (char)c;
        }
    }
    if (w >= dst_cap) return -1;
    dst[w] = '\0';
    return (int)w;
}

static int repl_verify_post_sig(const nodus_channel_post_t *post,
                                 const nodus_pubkey_t *author_pk) {
    char post_uuid_str[37], ch_uuid_str[37], author_hex[NODUS_KEY_HEX_LEN];
    repl_uuid_to_string(post->post_uuid, post_uuid_str);
    repl_uuid_to_string(post->channel_uuid, ch_uuid_str);
    repl_fp_to_hex(&post->author_fp, author_hex);

    size_t esc_cap = (post->body_len * 6) + 1;
    char *esc_body = malloc(esc_cap);
    if (!esc_body) return -1;

    int esc_len = repl_json_escape(post->body ? post->body : "",
                                    post->body ? post->body_len : 0,
                                    esc_body, esc_cap);
    if (esc_len < 0) { free(esc_body); return -1; }

    size_t json_cap = 256 + 37 + 37 + 129 + (size_t)esc_len + 32;
    char *json_buf = malloc(json_cap);
    if (!json_buf) { free(esc_body); return -1; }

    int json_len = snprintf(json_buf, json_cap,
        "{\"post_uuid\":\"%s\","
        "\"channel_uuid\":\"%s\","
        "\"author\":\"%s\","
        "\"body\":\"%s\","
        "\"created_at\":%llu}",
        post_uuid_str, ch_uuid_str, author_hex, esc_body,
        (unsigned long long)post->timestamp);
    free(esc_body);

    if (json_len < 0 || (size_t)json_len >= json_cap) { free(json_buf); return -1; }

    int rc = nodus_verify(&post->signature,
                           (const uint8_t *)json_buf, (size_t)json_len,
                           author_pk);
    free(json_buf);
    return rc;
}

/* ---- Init --------------------------------------------------------------- */

void nodus_ch_replication_init(nodus_ch_replication_t *rep,
                                nodus_channel_server_t *cs)
{
    memset(rep, 0, sizeof(*rep));
    rep->cs = cs;
    rep->last_retry_ms = 0;
}

/* ---- Replicate post to BACKUP nodes ------------------------------------- */

int nodus_ch_replication_send(nodus_ch_replication_t *rep,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES],
                               const nodus_channel_post_t *post,
                               const nodus_pubkey_t *author_pk)
{
    nodus_channel_server_t *cs = rep->cs;

    /* 1. Get responsible set for this channel */
    nodus_responsible_set_t rset;
    if (nodus_hashring_responsible(cs->ring, channel_uuid, &rset) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Cannot get responsible set for replication (ring=%p, count=%d)",
                     (void*)cs->ring, cs->ring ? cs->ring->count : -1);
        return -1;
    }

    /* 2. Encode the replication message once */
    uint8_t *buf = malloc(REPL_BUF_SIZE);
    if (!buf) return -1;

    size_t len = 0;
    int rc = nodus_t2_ch_replicate(0, channel_uuid, post, author_pk,
                                    buf, REPL_BUF_SIZE, &len);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode ch_replicate message");
        free(buf);
        return -1;
    }

    /* 3. Send to each BACKUP node (skip self) */
    for (int i = 0; i < rset.count; i++) {
        /* Skip self */
        if (nodus_key_cmp(&rset.nodes[i].node_id,
                           &cs->identity->node_id) == 0)
            continue;

        /* Find authenticated node session for this backup */
        nodus_ch_node_session_t *ns = NULL;
        for (int j = 0; j < NODUS_CH_MAX_NODE_SESSIONS; j++) {
            nodus_ch_node_session_t *candidate = &cs->nodes[j];
            if (candidate->conn && candidate->authenticated &&
                nodus_key_cmp(&candidate->node_id,
                               &rset.nodes[i].node_id) == 0) {
                ns = candidate;
                break;
            }
        }

        if (ns) {
            /* Send replication directly */
            QGP_LOG_DEBUG(LOG_TAG, "Sending ch_rep to %s:%u (session exists)",
                         ns->conn->ip, (unsigned)ns->conn->port);
            int send_rc = nodus_tcp_send(ns->conn, buf, len);
            if (send_rc != 0) {
                QGP_LOG_WARN(LOG_TAG,
                    "Replication send failed, queuing hinted handoff");
                nodus_hinted_insert(cs->ch_store, &rset.nodes[i].node_id,
                                     channel_uuid, buf, len);
            }
        } else {
            /* No active session -- initiate connection and queue to hinted handoff.
             * The connection completes async; hinted handoff retry will deliver. */
            nodus_ch_server_connect_to_peer(cs, rset.nodes[i].ip, cs->port,
                                                &rset.nodes[i].node_id);
            QGP_LOG_INFO(LOG_TAG,
                "No session for backup %s:%u, connecting + queuing hinted handoff",
                rset.nodes[i].ip, (unsigned)cs->port);
            nodus_hinted_insert(cs->ch_store, &rset.nodes[i].node_id,
                                 channel_uuid, buf, len);
        }
    }

    free(buf);
    return 0;
}

/* ---- Receive replicated post (BACKUP side) ------------------------------ */

int nodus_ch_replication_receive(nodus_ch_replication_t *rep,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post,
                                  const nodus_pubkey_t *author_pk)
{
    nodus_channel_server_t *cs = rep->cs;

    /* H-08: Verify post signature on BACKUP for non-encrypted channels.
     * Encrypted channels: sig is inside the encrypted blob, skip verify. */
    if (author_pk && !nodus_channel_is_encrypted(cs->ch_store, channel_uuid)) {
        if (repl_verify_post_sig(post, author_pk) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Replicated post rejected: invalid signature");
            return -1;
        }
    }

    /* Ensure channel table exists */
    nodus_channel_create(cs->ch_store, channel_uuid, false, NULL, NULL, false);

    /* Store post (INSERT OR IGNORE -- dedup by post_uuid) */
    nodus_channel_post_t mutable_post = *post;
    /* Preserve original body pointer for the caller; strdup for store */
    if (post->body && post->body_len > 0) {
        mutable_post.body = strndup(post->body, post->body_len);
        if (!mutable_post.body) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate body for replicated post");
            return -1;
        }
    }

    int rc = nodus_channel_post(cs->ch_store, &mutable_post);
    free(mutable_post.body);

    if (rc < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store replicated post");
        return -1;
    }

    return 0;
}

/* ---- Retry hinted handoff entries --------------------------------------- */

void nodus_ch_replication_retry(nodus_ch_replication_t *rep, uint64_t now_ms)
{
    /* Only retry every 30 seconds */
    if (now_ms - rep->last_retry_ms < (uint64_t)NODUS_HINTED_RETRY_SEC * 1000)
        return;
    rep->last_retry_ms = now_ms;

    nodus_channel_server_t *cs = rep->cs;

    /* Clean up expired entries first */
    nodus_hinted_cleanup(cs->ch_store);

    /* For each authenticated node session, try to deliver pending entries */
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        nodus_ch_node_session_t *ns = &cs->nodes[i];
        if (!ns->conn || !ns->authenticated)
            continue;

        nodus_hinted_entry_t *entries = NULL;
        size_t count = 0;
        int rc = nodus_hinted_get(cs->ch_store, &ns->node_id,
                                   100, &entries, &count);
        if (rc != 0 || count == 0)
            continue;

        for (size_t j = 0; j < count; j++) {
            int send_rc = nodus_tcp_send(ns->conn,
                                          entries[j].post_data,
                                          entries[j].post_data_len);
            if (send_rc == 0) {
                nodus_hinted_delete(cs->ch_store, entries[j].id);
            } else {
                nodus_hinted_retry(cs->ch_store, entries[j].id);
                break;  /* Peer still down, stop trying this node */
            }
        }

        nodus_hinted_entries_free(entries, count);
    }
}

/* ---- Handle sync request (send posts to new node) ----------------------- */

int nodus_ch_replication_handle_sync_request(nodus_ch_replication_t *rep,
                                              nodus_ch_node_session_t *from,
                                              const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                              uint64_t since_ms)
{
    nodus_channel_server_t *cs = rep->cs;

    /* Get posts since requested time (0 = unlimited count) */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    int rc = nodus_channel_get_posts(cs->ch_store, channel_uuid,
                                      since_ms, 0, &posts, &count);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get posts for sync response");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Sync request: sending %zu posts", count);

    /* Encode sync response */
    size_t bufcap = 64 * 1024 + count * 8192;
    uint8_t *buf = malloc(bufcap);
    if (!buf) {
        nodus_channel_posts_free(posts, count);
        return -1;
    }

    size_t len = 0;
    rc = nodus_t2_ch_sync_response(0, channel_uuid, posts, count,
                                    buf, bufcap, &len);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode sync response");
        free(buf);
        nodus_channel_posts_free(posts, count);
        return -1;
    }

    int send_rc = nodus_tcp_send(from->conn, buf, len);
    if (send_rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to send sync response");
    }

    free(buf);
    nodus_channel_posts_free(posts, count);
    return send_rc;
}

/* ---- Handle sync response (store received posts) ------------------------ */

int nodus_ch_replication_handle_sync_response(nodus_ch_replication_t *rep,
                                               const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                               const nodus_channel_post_t *posts,
                                               size_t count)
{
    nodus_channel_server_t *cs = rep->cs;

    /* Ensure channel table exists (bulk sync — no name/desc available) */
    nodus_channel_create(cs->ch_store, channel_uuid, false, NULL, NULL, false);

    /* Store each post (INSERT OR IGNORE for dedup) */
    int stored = 0;
    for (size_t i = 0; i < count; i++) {
        nodus_channel_post_t mutable_post = posts[i];
        /* strdup body so nodus_channel_post can own it */
        if (posts[i].body && posts[i].body_len > 0) {
            mutable_post.body = strndup(posts[i].body, posts[i].body_len);
            if (!mutable_post.body) continue;
        }

        int rc = nodus_channel_post(cs->ch_store, &mutable_post);
        free(mutable_post.body);
        if (rc == 0) stored++;
    }

    QGP_LOG_INFO(LOG_TAG, "Sync complete: %d/%zu posts stored",
                 stored, count);
    return 0;
}
