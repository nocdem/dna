/**
 * @file dna_dm_channel.c
 * @brief DM Channel Connector — push-based 1-to-1 direct message delivery
 *
 * Copyright (c) 2025-2026 CPUNK Project (cpunk.io) — MIT License
 *
 * Part of DNA Connect - DM Channel System
 */

#include "dna_dm_channel.h"
#include "../shared/nodus_ops.h"
/* Forward declaration — avoids DLL import issues on Windows */
extern const char* dna_engine_get_fingerprint(void *engine);
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_log.h"
#include "../../database/contacts_db.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define LOG_TAG "DM_CHANNEL"

/* ============================================================================
 * Internal State
 * ============================================================================ */

typedef struct {
    char     peer_fp[129];      /* Peer fingerprint (128 hex + null) */
    uint8_t  ch_uuid[16];       /* Derived channel UUID */
    int      connected;
    int      subscribed;
} dm_channel_entry_t;

static dm_channel_entry_t g_channels[DNA_DM_CHANNEL_MAX];
static int g_channel_count = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static dna_dm_channel_msg_cb g_msg_cb = NULL;
static void *g_msg_cb_data = NULL;

static int g_initialized = 0;

/* My fingerprint — cached after first subscribe_all_contacts */
static char g_my_fp[129] = {0};

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static int find_channel_by_fp(const char *peer_fp) {
    for (int i = 0; i < g_channel_count; i++) {
        if (strcmp(g_channels[i].peer_fp, peer_fp) == 0)
            return i;
    }
    return -1;
}

static int find_channel_by_uuid(const uint8_t ch_uuid[16]) {
    for (int i = 0; i < g_channel_count; i++) {
        if (memcmp(g_channels[i].ch_uuid, ch_uuid, 16) == 0)
            return i;
    }
    return -1;
}

/**
 * Push callback — fired when a post arrives on any channel.
 * Check if it matches a DM channel, deliver raw blob to callback.
 */
static void internal_push_callback(const uint8_t channel_uuid[16],
                                    const nodus_channel_post_t *post,
                                    void *user_data) {
    (void)user_data;

    if (!post || !post->body || post->body_len == 0)
        return;

    pthread_mutex_lock(&g_mutex);

    int idx = find_channel_by_uuid(channel_uuid);
    if (idx < 0 || !g_msg_cb) {
        pthread_mutex_unlock(&g_mutex);
        return;
    }

    char peer_fp[129];
    strncpy(peer_fp, g_channels[idx].peer_fp, sizeof(peer_fp));
    peer_fp[128] = '\0';
    dna_dm_channel_msg_cb cb = g_msg_cb;
    void *cb_data = g_msg_cb_data;

    pthread_mutex_unlock(&g_mutex);

    /* Deliver raw encrypted blob — caller decrypts via existing DM path */
    QGP_LOG_INFO(LOG_TAG, "DM push received from %.16s... (%zu bytes)",
                 peer_fp, post->body_len);

    cb(peer_fp, (const uint8_t *)post->body, post->body_len, cb_data);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int dna_dm_channel_uuid(const char *my_fp, const char *peer_fp,
                         uint8_t ch_uuid_out[16]) {
    if (!my_fp || !peer_fp || !ch_uuid_out) return -1;

    /* Sort fingerprints alphabetically for determinism */
    const char *fp_a, *fp_b;
    if (strcmp(my_fp, peer_fp) <= 0) {
        fp_a = my_fp;
        fp_b = peer_fp;
    } else {
        fp_a = peer_fp;
        fp_b = my_fp;
    }

    /* channel_uuid = SHA3-512("dna:dm:channel:" + fp_a + fp_b)[0:16] */
    const char *prefix = "dna:dm:channel:";
    size_t prefix_len = strlen(prefix);
    size_t fa_len = strlen(fp_a);
    size_t fb_len = strlen(fp_b);
    size_t total = prefix_len + fa_len + fb_len;

    uint8_t *data = malloc(total);
    if (!data) return -1;

    memcpy(data, prefix, prefix_len);
    memcpy(data + prefix_len, fp_a, fa_len);
    memcpy(data + prefix_len + fa_len, fp_b, fb_len);

    uint8_t hash[64]; /* SHA3-512 */
    int rc = qgp_sha3_512(data, total, hash);
    free(data);

    if (rc != 0) return -1;

    memcpy(ch_uuid_out, hash, 16);
    return 0;
}

int dna_dm_channel_init(void) {
    pthread_mutex_lock(&g_mutex);
    if (g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }

    memset(g_channels, 0, sizeof(g_channels));
    g_channel_count = 0;
    g_my_fp[0] = '\0';
    g_initialized = 1;

    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "DM channel subsystem initialized");
    return 0;
}

void dna_dm_channel_shutdown(void) {
    pthread_mutex_lock(&g_mutex);

    for (int i = 0; i < g_channel_count; i++) {
        if (g_channels[i].subscribed)
            nodus_ops_ch_unsubscribe(g_channels[i].ch_uuid);
    }

    g_channel_count = 0;
    g_initialized = 0;
    g_msg_cb = NULL;
    g_msg_cb_data = NULL;
    g_my_fp[0] = '\0';

    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "DM channel subsystem shutdown");
}

void dna_dm_channel_set_callback(dna_dm_channel_msg_cb cb, void *user_data) {
    pthread_mutex_lock(&g_mutex);
    g_msg_cb = cb;
    g_msg_cb_data = user_data;
    pthread_mutex_unlock(&g_mutex);
}

int dna_dm_channel_connect(void *dna_engine, const char *peer_fp) {
    if (!dna_engine || !peer_fp) return DNA_DM_CH_ERR_PARAM;

    /* Get own fingerprint */
    const char *my_fp = dna_engine_get_fingerprint((void *)dna_engine);
    if (!my_fp) {
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded");
        return DNA_DM_CH_ERR_PARAM;
    }

    pthread_mutex_lock(&g_mutex);

    /* Already connected? */
    int idx = find_channel_by_fp(peer_fp);
    if (idx >= 0 && g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_DM_CH_OK;
    }

    if (idx < 0) {
        if (g_channel_count >= DNA_DM_CHANNEL_MAX) {
            pthread_mutex_unlock(&g_mutex);
            return DNA_DM_CH_ERR_FULL;
        }
        idx = g_channel_count++;
        memset(&g_channels[idx], 0, sizeof(g_channels[idx]));
        strncpy(g_channels[idx].peer_fp, peer_fp, 128);
        g_channels[idx].peer_fp[128] = '\0';
    }

    /* Derive channel UUID */
    if (dna_dm_channel_uuid(my_fp, peer_fp, g_channels[idx].ch_uuid) != 0) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_DM_CH_ERR_CHANNEL;
    }

    pthread_mutex_unlock(&g_mutex);

    /* Create channel on nodus (idempotent — if exists, returns OK) */
    int rc = nodus_ops_ch_create(g_channels[idx].ch_uuid);
    if (rc != 0 && rc != -2 /* already exists */) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DM channel for %.16s...: %d",
                      peer_fp, rc);
        return DNA_DM_CH_ERR_CHANNEL;
    }

    pthread_mutex_lock(&g_mutex);
    g_channels[idx].connected = 1;
    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Connected DM channel for %.16s...", peer_fp);
    return DNA_DM_CH_OK;
}

int dna_dm_channel_subscribe(void *dna_engine, const char *peer_fp) {
    (void)dna_engine;
    if (!peer_fp) return DNA_DM_CH_ERR_PARAM;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel_by_fp(peer_fp);
    if (idx < 0 || !g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_DM_CH_ERR_NOT_FOUND;
    }
    if (g_channels[idx].subscribed) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_DM_CH_OK;
    }

    uint8_t ch_uuid[16];
    memcpy(ch_uuid, g_channels[idx].ch_uuid, 16);
    pthread_mutex_unlock(&g_mutex);

    int rc = nodus_ops_ch_subscribe(ch_uuid);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to subscribe DM channel for %.16s...: %d",
                      peer_fp, rc);
        return DNA_DM_CH_ERR_CHANNEL;
    }

    pthread_mutex_lock(&g_mutex);
    g_channels[idx].subscribed = 1;
    pthread_mutex_unlock(&g_mutex);

    QGP_LOG_INFO(LOG_TAG, "Subscribed to DM channel for %.16s...", peer_fp);
    return DNA_DM_CH_OK;
}

int dna_dm_channel_send(void *dna_engine, const char *peer_fp,
                         const uint8_t *blob, size_t blob_len) {
    if (!dna_engine || !peer_fp || !blob || blob_len == 0)
        return DNA_DM_CH_ERR_PARAM;

    /* Ensure connected (auto-connect if needed) */
    int rc = dna_dm_channel_connect(dna_engine, peer_fp);
    if (rc != DNA_DM_CH_OK) return rc;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel_by_fp(peer_fp);
    if (idx < 0 || !g_channels[idx].connected) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_DM_CH_ERR_NOT_FOUND;
    }
    uint8_t ch_uuid[16];
    memcpy(ch_uuid, g_channels[idx].ch_uuid, 16);
    pthread_mutex_unlock(&g_mutex);

    /* Generate post UUID */
    uint8_t post_uuid[16];
    qgp_randombytes(post_uuid, 16);

    /* Post to channel — body is the already-encrypted DM blob */
    uint64_t received_at = 0;
    nodus_sig_t dummy_sig = {0}; /* encrypted channels skip nodus-level sig */

    rc = nodus_ops_ch_post(ch_uuid, post_uuid,
                            blob, blob_len,
                            (uint64_t)time(NULL),
                            &dummy_sig, &received_at);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Channel post failed for DM to %.16s...: %d",
                      peer_fp, rc);
        return DNA_DM_CH_ERR_CHANNEL;
    }

    QGP_LOG_INFO(LOG_TAG, "Sent DM via channel to %.16s... (%zu bytes)",
                 peer_fp, blob_len);
    return DNA_DM_CH_OK;
}

int dna_dm_channel_disconnect(void *dna_engine, const char *peer_fp) {
    (void)dna_engine;
    if (!peer_fp) return DNA_DM_CH_ERR_PARAM;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel_by_fp(peer_fp);
    if (idx < 0) {
        pthread_mutex_unlock(&g_mutex);
        return DNA_DM_CH_ERR_NOT_FOUND;
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

    QGP_LOG_INFO(LOG_TAG, "Disconnected DM channel for %.16s...", peer_fp);
    return DNA_DM_CH_OK;
}

int dna_dm_channel_subscribe_all_contacts(void *dna_engine) {
    if (!dna_engine) return -1;

    void *engine = dna_engine;
    const char *my_fp = dna_engine_get_fingerprint((void *)engine);
    if (!my_fp) {
        QGP_LOG_WARN(LOG_TAG, "Cannot subscribe DM channels — no identity loaded");
        return -1;
    }

    /* Cache own fingerprint */
    pthread_mutex_lock(&g_mutex);
    strncpy(g_my_fp, my_fp, 128);
    g_my_fp[128] = '\0';
    pthread_mutex_unlock(&g_mutex);

    /* Get all contacts */
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts || contacts->count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No contacts — no DM channels to subscribe");
        if (contacts) contacts_db_free_list(contacts);
        return 0;
    }

    int subscribed = 0;
    for (size_t i = 0; i < contacts->count; i++) {
        const char *identity = contacts->contacts[i].identity;

        /* identity is fingerprint (128 hex chars) or name — we need fingerprint */
        /* If identity is already a fingerprint (128 hex chars), use directly */
        const char *peer_fp = identity;
        if (strlen(identity) != 128) {
            /* Short name — skip, we need fingerprints for channel derivation */
            QGP_LOG_DEBUG(LOG_TAG, "Skipping non-fingerprint contact: %s", identity);
            continue;
        }

        int rc = dna_dm_channel_connect(dna_engine, peer_fp);
        if (rc != DNA_DM_CH_OK) {
            QGP_LOG_WARN(LOG_TAG, "DM channel connect failed for %.16s...: %d",
                         peer_fp, rc);
            continue;
        }

        rc = dna_dm_channel_subscribe(dna_engine, peer_fp);
        if (rc != DNA_DM_CH_OK) {
            QGP_LOG_WARN(LOG_TAG, "DM channel subscribe failed for %.16s...: %d",
                         peer_fp, rc);
            continue;
        }

        subscribed++;
    }

    contacts_db_free_list(contacts);

    QGP_LOG_INFO(LOG_TAG, "Subscribed to %d DM channel(s)", subscribed);
    return subscribed;
}

void dna_dm_channel_handle_push(const uint8_t channel_uuid[16],
                                 const void *post,
                                 void *user_data) {
    internal_push_callback(channel_uuid, (const nodus_channel_post_t *)post, user_data);
}

int dna_dm_channel_is_connected(const char *peer_fp) {
    if (!peer_fp) return 0;

    pthread_mutex_lock(&g_mutex);
    int idx = find_channel_by_fp(peer_fp);
    int connected = (idx >= 0 && g_channels[idx].connected) ? 1 : 0;
    pthread_mutex_unlock(&g_mutex);

    return connected;
}
