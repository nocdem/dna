/**
 * Nodus -- Channel Primary Role Logic
 *
 * Implements PRIMARY handlers for channel operations:
 * create, post (with signature verification), get, subscribe, unsubscribe.
 *
 * Post flow: verify sig -> store -> respond -> push -> replicate (callback).
 *
 * @file nodus_channel_primary.c
 */

#include "channel/nodus_channel_primary.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_channel_ring.h"
#include "channel/nodus_hashring.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LOG_TAG "CH_PRIMARY"

/* ---- Internal helpers -------------------------------------------------- */

/**
 * Convert 16-byte binary UUID to hyphenated string (36 chars + NUL).
 * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 */
static void uuid_to_string(const uint8_t uuid[NODUS_UUID_BYTES], char out[37]) {
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);
}

/**
 * Convert nodus_key_t (64 bytes) to hex string (128 chars + NUL).
 */
static void fp_to_hex(const nodus_key_t *fp, char out[NODUS_KEY_HEX_LEN]) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++)
        snprintf(out + i * 2, 3, "%02x", fp->bytes[i]);
}

/**
 * Escape a string for JSON embedding.
 * @return length written (excluding NUL), or -1 on overflow.
 */
static int json_escape_string(const char *src, size_t src_len,
                               char *dst, size_t dst_cap) {
    size_t w = 0;
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\';
            dst[w++] = (char)c;
        } else if (c == '\n') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\'; dst[w++] = 'n';
        } else if (c == '\r') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\'; dst[w++] = 'r';
        } else if (c == '\t') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\'; dst[w++] = 't';
        } else if (c == '\b') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\'; dst[w++] = 'b';
        } else if (c == '\f') {
            if (w + 2 > dst_cap) return -1;
            dst[w++] = '\\'; dst[w++] = 'f';
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

/**
 * Verify a channel post signature against the author's public key.
 *
 * Reconstructs the JSON signing payload that the messenger client signed:
 *   {"post_uuid":"...","channel_uuid":"...","author":"...","body":"...","created_at":...}
 *
 * @param post       Channel post with signature
 * @param author_pk  Author's Dilithium5 public key
 * @return 0 if valid, -1 if invalid or error
 */
static int verify_channel_post_sig(const nodus_channel_post_t *post,
                                    const nodus_pubkey_t *author_pk) {
    char post_uuid_str[37];
    char ch_uuid_str[37];
    char author_hex[NODUS_KEY_HEX_LEN];

    uuid_to_string(post->post_uuid, post_uuid_str);
    uuid_to_string(post->channel_uuid, ch_uuid_str);
    fp_to_hex(&post->author_fp, author_hex);

    /* Escape body for JSON (worst case: 6x expansion for \uXXXX) */
    size_t esc_cap = (post->body_len * 6) + 1;
    char *esc_body = malloc(esc_cap);
    if (!esc_body) return -1;

    int esc_len = json_escape_string(post->body ? post->body : "",
                                      post->body ? post->body_len : 0,
                                      esc_body, esc_cap);
    if (esc_len < 0) { free(esc_body); return -1; }

    /* Build the JSON signing payload (json-c JSON_C_TO_STRING_PLAIN format) */
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

    if (json_len < 0 || (size_t)json_len >= json_cap) {
        free(json_buf);
        return -1;
    }

    int rc = nodus_verify(&post->signature,
                           (const uint8_t *)json_buf, (size_t)json_len,
                           author_pk);
    free(json_buf);
    return rc;
}

/* ---- Public API -------------------------------------------------------- */

bool nodus_ch_primary_ensure_channel(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    if (!cs->ch_store || !cs->ring || !cs->identity)
        return false;

    if (nodus_channel_exists(cs->ch_store, channel_uuid))
        return true;

    /* Check if we're responsible for this channel */
    nodus_responsible_set_t rset;
    if (nodus_hashring_responsible(cs->ring, channel_uuid, &rset) != 0)
        return false;

    for (int i = 0; i < rset.count; i++) {
        if (memcmp(rset.nodes[i].node_id.bytes,
                   cs->identity->node_id.bytes, NODUS_KEY_BYTES) == 0) {
            /* We're responsible -- create the table */
            nodus_channel_create(cs->ch_store, channel_uuid, false, NULL, NULL, false);
            /* Track for ring management */
            if (cs->ch_ring_ptr) {
                nodus_ch_ring_t *rm = (nodus_ch_ring_t *)cs->ch_ring_ptr;
                nodus_ch_ring_track(rm, channel_uuid,
                                     cs->ring ? cs->ring->version : 0);
            }
            return true;
        }
    }
    return false;  /* Not responsible */
}

int nodus_ch_primary_announce_to_dht(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    if (!cs->ring)
        return -1;

    /* 1. Get responsible set (ordered by hashring -- deterministic) */
    nodus_responsible_set_t rset;
    if (nodus_hashring_responsible(cs->ring, channel_uuid, &rset) != 0)
        return -1;

    /* 2. Build DHT key: SHA3-512("dna:channel:nodes:" + raw_uuid) */
    uint8_t key_input[256];
    const char *prefix = "dna:channel:nodes:";
    size_t plen = strlen(prefix);
    memcpy(key_input, prefix, plen);
    memcpy(key_input + plen, channel_uuid, NODUS_UUID_BYTES);

    nodus_key_t key_hash;
    nodus_hash(key_input, plen + NODUS_UUID_BYTES, &key_hash);

    /* 3. Encode CBOR value: {version, nodes: [{ip, port, nid}, ...]} */
    uint8_t val_buf[4096];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, val_buf, sizeof(val_buf));
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "version");
    cbor_encode_uint(&enc, cs->ring->version);
    cbor_encode_cstr(&enc, "nodes");
    cbor_encode_array(&enc, (size_t)rset.count);
    for (int i = 0; i < rset.count; i++) {
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "ip");
        cbor_encode_cstr(&enc, rset.nodes[i].ip);
        cbor_encode_cstr(&enc, "port");
        cbor_encode_uint(&enc, cs->port);
        cbor_encode_cstr(&enc, "nid");
        cbor_encode_bstr(&enc, rset.nodes[i].node_id.bytes, NODUS_KEY_BYTES);
    }
    size_t val_len = cbor_encoder_len(&enc);
    if (val_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "CBOR encode overflow for DHT announce");
        return -1;
    }

    /* 4. Store via DHT callback (if set) */
    if (cs->dht_put_signed) {
        return cs->dht_put_signed(key_hash.bytes, NODUS_KEY_BYTES,
                                   val_buf, val_len, 0, cs->dht_ctx);
    }
    return 0;
}

int nodus_ch_primary_handle_create(nodus_channel_server_t *cs,
                                    nodus_ch_client_session_t *sess,
                                    const nodus_tier2_msg_t *msg) {
    uint8_t buf[256];
    size_t len = 0;

    if (!cs->ch_store) {
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "store unavailable", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* 1. Create channel table (idempotent)
     * name/description/is_public come from extended ch_create protocol */
    nodus_channel_create(cs->ch_store, msg->channel_uuid, msg->ch_encrypted,
                         msg->ch_name, msg->ch_description, msg->ch_is_public);

    /* H-07: Store the creator's fingerprint (only sets if not already set) */
    nodus_channel_set_creator(cs->ch_store, msg->channel_uuid, &sess->client_fp);

    /* 2. Track in ring management for heartbeat monitoring */
    if (cs->ch_ring_ptr) {
        nodus_ch_ring_t *rm = (nodus_ch_ring_t *)cs->ch_ring_ptr;
        nodus_ch_ring_track(rm, msg->channel_uuid,
                             cs->ring ? cs->ring->version : 0);
    }

    /* 3. Announce to DHT (ordered node list) */
    nodus_ch_primary_announce_to_dht(cs, msg->channel_uuid);

    /* 3. Send ch_create_ok */
    nodus_t2_ch_create_ok(msg->txn_id, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);

    QGP_LOG_INFO(LOG_TAG, "Channel created: slot=%d", sess->conn->slot);
    return 0;
}

int nodus_ch_primary_handle_post(nodus_channel_server_t *cs,
                                  nodus_ch_client_session_t *sess,
                                  const nodus_tier2_msg_t *msg) {
    uint8_t buf[256];
    size_t len = 0;

    /* 1. Rate limit check (window in seconds, matching nodus_server.c) */
    uint64_t now = nodus_time_now();
    if (now - sess->rate_window_start >= 60) {
        sess->rate_window_start = now;
        sess->posts_this_minute = 0;
    }
    if (sess->posts_this_minute >= NODUS_CH_RATE_POSTS_PER_MIN) {
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many posts", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* 2. Ensure channel exists */
    if (!nodus_ch_primary_ensure_channel(cs, msg->channel_uuid)) {
        nodus_t2_error(msg->txn_id, NODUS_ERR_CHANNEL_NOT_FOUND,
                        "channel not found", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* 3. Validate body size */
    if (msg->data_len > NODUS_MAX_POST_BODY) {
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                        "post body too large", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* 4. Build post struct */
    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, msg->channel_uuid, NODUS_UUID_BYTES);
    memcpy(post.post_uuid, msg->post_uuid_ch, NODUS_UUID_BYTES);
    post.author_fp = sess->client_fp;
    post.timestamp = msg->ch_timestamp;
    post.body = (char *)msg->data;   /* Borrowed, not owned */
    post.body_len = msg->data_len;
    memcpy(post.signature.bytes, msg->sig.bytes, NODUS_SIG_BYTES);

    /* 5. VERIFY SIGNATURE (SECURITY: CRIT-01)
     * Skip for encrypted channels — signature is inside the encrypted blob,
     * only group members with GEK can verify. Nodus has zero knowledge. */
    if (!nodus_channel_is_encrypted(cs->ch_store, msg->channel_uuid)) {
        if (verify_channel_post_sig(&post, &sess->client_pk) != 0) {
            post.body = NULL;
            nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                            "invalid post signature", buf, sizeof(buf), &len);
            nodus_tcp_send(sess->conn, buf, len);
            QGP_LOG_WARN(LOG_TAG, "ch_post rejected: invalid signature, slot=%d",
                         sess->conn->slot);
            return -1;
        }
    } else {
        /* C-05: For encrypted channels, verify the session's fingerprint is a
         * registered push target (channel member). Can't verify Dilithium5 sig
         * (it's inside the encrypted blob), but we can verify membership. */
        if (!nodus_push_target_has(cs->ch_store, msg->channel_uuid,
                                    &sess->client_fp)) {
            post.body = NULL;
            nodus_t2_error(msg->txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                            "not a member of this encrypted channel",
                            buf, sizeof(buf), &len);
            nodus_tcp_send(sess->conn, buf, len);
            QGP_LOG_WARN(LOG_TAG, "ch_post rejected: non-member on encrypted channel, slot=%d",
                         sess->conn->slot);
            return -1;
        }
    }

    /* 6. Store in SQLite */
    int rc = nodus_channel_post(cs->ch_store, &post);
    if (rc < 0) {
        post.body = NULL;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "post failed", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* 7. Send ch_post_ok to posting client */
    nodus_t2_ch_post_ok(msg->txn_id, post.received_at, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
    sess->posts_this_minute++;

    /* 8. Push to ALL subscribed clients FIRST (user experience before replication) */
    if (rc == 0) {  /* rc==0 means new post (not duplicate) */
        nodus_ch_notify_subscribers(cs, msg->channel_uuid, &post);

        /* Step 1.6: For encrypted channels, queue for offline push targets.
         * For each push target NOT currently subscribed, add to pending_push. */
        if (nodus_channel_is_encrypted(cs->ch_store, msg->channel_uuid)) {
            nodus_push_target_t *targets = NULL;
            size_t target_count = 0;
            if (nodus_push_target_get(cs->ch_store, msg->channel_uuid,
                                       &targets, &target_count) == 0 && target_count > 0) {
                /* Build the notification frame to queue for offline targets */
                size_t ntf_cap = 256 + post.body_len + NODUS_SIG_BYTES + NODUS_KEY_BYTES;
                uint8_t *ntf_buf = malloc(ntf_cap);
                size_t ntf_len = 0;
                bool ntf_ok = false;
                if (ntf_buf) {
                    ntf_ok = (nodus_t2_ch_post_notify(0, msg->channel_uuid, &post,
                                                       ntf_buf, ntf_cap, &ntf_len) == 0);
                }

                uint64_t expires = nodus_time_now() + NODUS_CHANNEL_RETENTION;

                for (size_t t = 0; t < target_count; t++) {
                    /* Check if this target is currently subscribed */
                    bool subscribed = false;
                    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
                        nodus_ch_client_session_t *cl = &cs->clients[i];
                        if (!cl->conn || !cl->authenticated) continue;
                        if (nodus_key_cmp(&cl->client_fp, &targets[t].target_fp) != 0)
                            continue;
                        for (int j = 0; j < cl->ch_sub_count; j++) {
                            if (memcmp(cl->ch_subs[j], msg->channel_uuid,
                                       NODUS_UUID_BYTES) == 0) {
                                subscribed = true;
                                break;
                            }
                        }
                        if (subscribed) break;
                    }

                    if (!subscribed && ntf_ok) {
                        nodus_pending_push_add(cs->ch_store, msg->channel_uuid,
                                                &targets[t].target_fp,
                                                ntf_buf, ntf_len, expires);
                    }
                }

                free(ntf_buf);
                free(targets);
            }
        }
    }

    /* 9. Trigger replication to BACKUPs (via callback) */
    if (rc == 0 && cs->on_post) {
        cs->on_post(cs, msg->channel_uuid, &post, &sess->client_pk);
    }

    post.body = NULL;  /* Borrowed from msg, don't double-free */
    return 0;
}

int nodus_ch_primary_handle_get(nodus_channel_server_t *cs,
                                 nodus_ch_client_session_t *sess,
                                 const nodus_tier2_msg_t *msg) {
    uint8_t err_buf[256];
    size_t len = 0;

    if (!nodus_ch_primary_ensure_channel(cs, msg->channel_uuid)) {
        nodus_t2_error(msg->txn_id, NODUS_ERR_CHANNEL_NOT_FOUND,
                        "channel not found", err_buf, sizeof(err_buf), &len);
        nodus_tcp_send(sess->conn, err_buf, len);
        return -1;
    }

    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    int max = msg->ch_max_count > 0 ? msg->ch_max_count : 100;

    int rc = nodus_channel_get_posts(cs->ch_store, msg->channel_uuid,
                                      msg->ch_received_at, max, &posts, &count);
    if (rc != 0) {
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "get posts failed", err_buf, sizeof(err_buf), &len);
        nodus_tcp_send(sess->conn, err_buf, len);
        return -1;
    }

    /* Encode and send response -- use large buffer for posts */
    size_t bufcap = 64 * 1024 + count * 8192;
    uint8_t *buf = malloc(bufcap);
    if (!buf) {
        nodus_channel_posts_free(posts, count);
        QGP_LOG_ERROR(LOG_TAG, "OOM allocating get response buffer");
        return -1;
    }
    len = 0;
    nodus_t2_ch_posts(msg->txn_id, posts, count, buf, bufcap, &len);
    nodus_tcp_send(sess->conn, buf, len);

    free(buf);
    nodus_channel_posts_free(posts, count);
    return 0;
}

int nodus_ch_primary_handle_subscribe(nodus_channel_server_t *cs,
                                       nodus_ch_client_session_t *sess,
                                       const nodus_tier2_msg_t *msg) {
    nodus_ch_client_add_sub(sess, msg->channel_uuid);

    uint8_t buf[128];
    size_t len = 0;
    nodus_t2_ch_sub_ok(msg->txn_id, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);

    QGP_LOG_DEBUG(LOG_TAG, "Subscribed: slot=%d subs=%d",
                  sess->conn->slot, sess->ch_sub_count);

    /* Step 1.7: For encrypted channels, drain pending push queue.
     * Check if subscriber is a push target, then send queued posts. */
    if (cs->ch_store &&
        nodus_channel_is_encrypted(cs->ch_store, msg->channel_uuid) &&
        nodus_push_target_has(cs->ch_store, msg->channel_uuid, &sess->client_fp)) {

        nodus_pending_push_t *entries = NULL;
        size_t count = 0;
        if (nodus_pending_push_get(cs->ch_store, msg->channel_uuid,
                                    &sess->client_fp, 1000,
                                    &entries, &count) == 0 && count > 0) {
            QGP_LOG_INFO(LOG_TAG, "Draining %zu pending push entries for subscriber",
                         count);
            for (size_t i = 0; i < count; i++) {
                nodus_tcp_send(sess->conn, entries[i].post_data,
                               entries[i].post_data_len);
                nodus_pending_push_delete(cs->ch_store, entries[i].id);
            }
            nodus_pending_push_free(entries, count);
        }

        /* Also cleanup expired entries while we're at it */
        nodus_pending_push_cleanup(cs->ch_store);
    }

    return 0;
}

int nodus_ch_primary_handle_unsubscribe(nodus_channel_server_t *cs,
                                         nodus_ch_client_session_t *sess,
                                         const nodus_tier2_msg_t *msg) {
    (void)cs;
    nodus_ch_client_remove_sub(sess, msg->channel_uuid);

    uint8_t buf[128];
    size_t len = 0;
    nodus_t2_ch_sub_ok(msg->txn_id, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);

    QGP_LOG_DEBUG(LOG_TAG, "Unsubscribed: slot=%d subs=%d",
                  sess->conn->slot, sess->ch_sub_count);
    return 0;
}
