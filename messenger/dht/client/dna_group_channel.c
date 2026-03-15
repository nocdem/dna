/**
 * @file dna_group_channel.c
 * @brief Group Channel Connector — bridges groups and nodus channel system
 *
 * Copyright (c) 2025-2026 CPUNK Project (cpunk.io) — MIT License
 *
 * Part of DNA Connect - Group Channel System (Phase 2)
 */

#include "dna_group_channel.h"
#include "dna_group_channel_crypto.h"
#include "../shared/nodus_ops.h"
#include "../../messenger/gek.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define LOG_TAG "GROUP_CHANNEL"

/* ============================================================================
 * Internal State
 * ============================================================================ */

typedef struct {
    char     group_uuid[37];     /* UUID string */
    uint8_t  ch_uuid[16];       /* derived channel UUID */
    int      connected;
    int      subscribed;
} group_channel_entry_t;

static group_channel_entry_t g_channels[DNA_GROUP_CHANNEL_MAX];
static int g_channel_count = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static dna_group_channel_msg_cb g_msg_cb = NULL;
static void *g_msg_cb_data = NULL;

static int g_initialized = 0;

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static int find_channel(const char *group_uuid) {
    for (int i = 0; i < g_channel_count; i++) {
        if (strcmp(g_channels[i].group_uuid, group_uuid) == 0)
            return i;
    }
    return -1;
}

/**
 * Push callback from nodus_ops — fired when a post arrives on any channel.
 * We check if it's one of our group channels, decrypt, and deliver.
 */
static void internal_push_callback(const uint8_t channel_uuid[16],
                                    const nodus_channel_post_t *post,
                                    void *user_data) {
    (void)user_data;

    if (!post || !post->body || post->body_len == 0)
        return;

    pthread_mutex_lock(&g_mutex);

    /* Find which group this channel belongs to */
    int idx = -1;
    for (int i = 0; i < g_channel_count; i++) {
        if (memcmp(g_channels[i].ch_uuid, channel_uuid, 16) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0 || !g_msg_cb) {
        pthread_mutex_unlock(&g_mutex);
        return;
    }

    char group_uuid[37];
    strncpy(group_uuid, g_channels[idx].group_uuid, sizeof(group_uuid));
    dna_group_channel_msg_cb cb = g_msg_cb;
    void *cb_data = g_msg_cb_data;

    pthread_mutex_unlock(&g_mutex);

    /* Try to decrypt with active GEK */
    uint8_t gek[GEK_KEY_SIZE];
    uint32_t gek_version = 0;
    if (gek_get_active_key(group_uuid, gek, &gek_version) != 0) {
        QGP_LOG_WARN(LOG_TAG, "No active GEK for group %.8s..., cannot decrypt push",
                     group_uuid);
        return;
    }

    char sender_fp[129] = {0};
    uint64_t timestamp = 0;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    int rc = dna_group_channel_decrypt(
        (const uint8_t *)post->body, post->body_len,
        gek, NULL, /* skip sig verify for now — need sender pubkey lookup */
        sender_fp, &timestamp,
        &plaintext, &plaintext_len);

    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to decrypt group channel message: %d", rc);
        return;
    }

    /* Deliver to app */
    cb(group_uuid, sender_fp, timestamp, plaintext, plaintext_len, cb_data);

    free(plaintext);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int dna_group_channel_uuid(const char *group_uuid, uint8_t ch_uuid_out[16]) {
    if (!group_uuid || !ch_uuid_out) return -1;

    /* channel_uuid = SHA3-512("dna:group:channel:" + group_uuid)[0:16] */
    const char *prefix = "dna:group:channel:";
    size_t prefix_len = strlen(prefix);
    size_t uuid_len = strlen(group_uuid);
    size_t total = prefix_len + uuid_len;

    uint8_t *data = malloc(total);
    if (!data) return -1;

    memcpy(data, prefix, prefix_len);
    memcpy(data + prefix_len, group_uuid, uuid_len);

    uint8_t hash[64]; /* SHA3-512 */
    int rc = qgp_sha3_512(data, total, hash);
    free(data);

    if (rc != 0) return -1;

    memcpy(ch_uuid_out, hash, 16);
    return 0;
}

int dna_group_channel_init(void) {
    pthread_mutex_lock(&g_mutex);
    if (g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }

    memset(g_channels, 0, sizeof(g_channels));
    g_channel_count = 0;
    g_initialized = 1;

    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Group channel subsystem initialized");
    return 0;
}

void dna_group_channel_shutdown(void) {
    pthread_mutex_lock(&g_mutex);

    for (int i = 0; i < g_channel_count; i++) {
        if (g_channels[i].subscribed)
            nodus_ops_ch_unsubscribe(g_channels[i].ch_uuid);
    }

    g_channel_count = 0;
    g_initialized = 0;
    g_msg_cb = NULL;
    g_msg_cb_data = NULL;

    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Group channel subsystem shutdown");
}

void dna_group_channel_set_callback(dna_group_channel_msg_cb cb, void *user_data) {
    pthread_mutex_lock(&g_mutex);
    g_msg_cb = cb;
    g_msg_cb_data = user_data;
    pthread_mutex_unlock(&g_mutex);
}

int dna_group_channel_connect(void *dna_engine, const char *group_uuid) {
    (void)dna_engine;
    if (!group_uuid) return DNA_GROUP_CH_ERR_PARAM;

    pthread_mutex_lock(&g_mutex);

    /* Already connected? */
    int idx = find_channel(group_uuid);
    if (idx >= 0 && g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_OK;
    }

    if (idx < 0) {
        if (g_channel_count >= DNA_GROUP_CHANNEL_MAX) {
            pthread_mutex_unlock(&g_mutex);
            return DNA_GROUP_CH_ERR_FULL;
        }
        idx = g_channel_count++;
        memset(&g_channels[idx], 0, sizeof(g_channels[idx]));
        strncpy(g_channels[idx].group_uuid, group_uuid, 36);
        g_channels[idx].group_uuid[36] = '\0';
    }

    /* Derive channel UUID */
    if (dna_group_channel_uuid(group_uuid, g_channels[idx].ch_uuid) != 0) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_ERR_CHANNEL;
    }

    pthread_mutex_unlock(&g_mutex);

    /* Create channel on nodus (idempotent — if exists, returns OK) */
    int rc = nodus_ops_ch_create(g_channels[idx].ch_uuid);
    if (rc != 0 && rc != -2 /* already exists */) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create channel for group %.8s...: %d",
                      group_uuid, rc);
        return DNA_GROUP_CH_ERR_CHANNEL;
    }

    pthread_mutex_lock(&g_mutex);
    g_channels[idx].connected = 1;
    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Connected group %.8s... to channel", group_uuid);
    return DNA_GROUP_CH_OK;
}

int dna_group_channel_subscribe(void *dna_engine, const char *group_uuid) {
    (void)dna_engine;
    if (!group_uuid) return DNA_GROUP_CH_ERR_PARAM;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel(group_uuid);
    if (idx < 0 || !g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_ERR_NOT_FOUND;
    }
    if (g_channels[idx].subscribed) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_OK;
    }

    uint8_t ch_uuid[16];
    memcpy(ch_uuid, g_channels[idx].ch_uuid, 16);
    pthread_mutex_unlock(&g_mutex);

    int rc = nodus_ops_ch_subscribe(ch_uuid);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to subscribe group %.8s...: %d",
                      group_uuid, rc);
        return DNA_GROUP_CH_ERR_CHANNEL;
    }

    pthread_mutex_lock(&g_mutex);
    g_channels[idx].subscribed = 1;
    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Subscribed to group %.8s... channel push", group_uuid);
    return DNA_GROUP_CH_OK;
}

int dna_group_channel_send(void *dna_engine, const char *group_uuid,
                            const uint8_t *plaintext, size_t plaintext_len) {
    if (!dna_engine || !group_uuid || !plaintext || plaintext_len == 0)
        return DNA_GROUP_CH_ERR_PARAM;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel(group_uuid);
    if (idx < 0 || !g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_ERR_NOT_FOUND;
    }
    uint8_t ch_uuid[16];
    memcpy(ch_uuid, g_channels[idx].ch_uuid, 16);
    pthread_mutex_unlock(&g_mutex);

    /* Get active GEK */
    uint8_t gek[GEK_KEY_SIZE];
    uint32_t gek_version = 0;
    if (gek_get_active_key(group_uuid, gek, &gek_version) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "No active GEK for group %.8s...", group_uuid);
        return DNA_GROUP_CH_ERR_NO_GEK;
    }

    /* Get sender identity */
    extern const char *dna_engine_get_fingerprint(void *engine);
    extern const uint8_t *dna_engine_get_sign_sk(void *engine);

    const char *sender_fp = dna_engine_get_fingerprint(dna_engine);
    const uint8_t *sign_sk = dna_engine_get_sign_sk(dna_engine);
    if (!sender_fp || !sign_sk) {
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded");
        return DNA_GROUP_CH_ERR_SIGN;
    }

    /* Encrypt + sign */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = dna_group_channel_encrypt(
        group_uuid, plaintext, plaintext_len,
        gek, gek_version, sender_fp, sign_sk,
        &blob, &blob_len);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Encrypt failed for group %.8s...: %d",
                      group_uuid, rc);
        return DNA_GROUP_CH_ERR_ENCRYPT;
    }

    /* Generate post UUID */
    uint8_t post_uuid[16];
    qgp_randombytes(post_uuid, 16);

    /* Post to channel */
    uint64_t received_at = 0;
    nodus_sig_t dummy_sig = {0}; /* encrypted channels skip nodus-level sig */

    rc = nodus_ops_ch_post(ch_uuid, post_uuid,
                            blob, blob_len,
                            (uint64_t)time(NULL),
                            &dummy_sig, &received_at);

    free(blob);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Channel post failed for group %.8s...: %d",
                      group_uuid, rc);
        return DNA_GROUP_CH_ERR_CHANNEL;
    }

    QGP_LOG_INFO(LOG_TAG, "Sent encrypted message to group %.8s... (blob=%zu bytes)",
                 group_uuid, blob_len);
    return DNA_GROUP_CH_OK;
}

int dna_group_channel_disconnect(void *dna_engine, const char *group_uuid) {
    (void)dna_engine;
    if (!group_uuid) return DNA_GROUP_CH_ERR_PARAM;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel(group_uuid);
    if (idx < 0) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_ERR_NOT_FOUND;
    }

    if (g_channels[idx].subscribed) {
        nodus_ops_ch_unsubscribe(g_channels[idx].ch_uuid);
        g_channels[idx].subscribed = 0;
    }
    g_channels[idx].connected = 0;

    /* Remove entry by swapping with last */
    if (idx < g_channel_count - 1)
        g_channels[idx] = g_channels[g_channel_count - 1];
    g_channel_count--;

    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Disconnected group %.8s...", group_uuid);
    return DNA_GROUP_CH_OK;
}

int dna_group_channel_sync(void *dna_engine, const char *group_uuid,
                            uint64_t since_received_at, size_t *count_out) {
    (void)dna_engine;
    if (!group_uuid) return DNA_GROUP_CH_ERR_PARAM;
    if (count_out) *count_out = 0;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel(group_uuid);
    if (idx < 0 || !g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_GROUP_CH_ERR_NOT_FOUND;
    }
    uint8_t ch_uuid[16];
    memcpy(ch_uuid, g_channels[idx].ch_uuid, 16);
    pthread_mutex_unlock(&g_mutex);

    /* Fetch posts from nodus */
    nodus_channel_post_t *posts = NULL;
    size_t post_count = 0;
    int rc = nodus_ops_ch_get_posts(ch_uuid, since_received_at, 100,
                                     &posts, &post_count);
    if (rc != 0 || !posts || post_count == 0) {
        return (rc != 0) ? DNA_GROUP_CH_ERR_CHANNEL : DNA_GROUP_CH_OK;
    }

    /* Get GEK for decryption */
    uint8_t gek[GEK_KEY_SIZE];
    uint32_t gek_version = 0;
    if (gek_get_active_key(group_uuid, gek, &gek_version) != 0) {
        /* TODO: try multiple GEK versions */
        free(posts);
        return DNA_GROUP_CH_ERR_NO_GEK;
    }

    size_t delivered = 0;
    for (size_t i = 0; i < post_count; i++) {
        if (!posts[i].body || posts[i].body_len == 0) continue;

        char sender_fp[129] = {0};
        uint64_t timestamp = 0;
        uint8_t *plaintext = NULL;
        size_t plaintext_len = 0;

        rc = dna_group_channel_decrypt(
            (const uint8_t *)posts[i].body, posts[i].body_len,
            gek, NULL, sender_fp, &timestamp,
            &plaintext, &plaintext_len);

        if (rc == 0 && g_msg_cb) {
            g_msg_cb(group_uuid, sender_fp, timestamp,
                     plaintext, plaintext_len, g_msg_cb_data);
            delivered++;
        }

        free(plaintext);
    }

    free(posts);
    if (count_out) *count_out = delivered;

    QGP_LOG_INFO(LOG_TAG, "Synced group %.8s...: %zu/%zu messages",
                 group_uuid, delivered, post_count);
    return DNA_GROUP_CH_OK;
}

int dna_group_channel_is_connected(const char *group_uuid) {
    if (!group_uuid) return 0;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel(group_uuid);
    int connected = (idx >= 0 && g_channels[idx].connected) ? 1 : 0;
    pthread_mutex_unlock(&g_mutex);

    return connected;
}
