/**
 * DHT Channel Subscriptions Sync Implementation
 * Multi-device sync for channel subscriptions
 *
 * @file dht_channel_subscriptions.c
 * @author DNA Connect Team
 * @date 2026-02-26
 */

#include "dht_channel_subscriptions.h"
#include "nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LOG_TAG "DHT_CHAN_SUBS"

/* Platform-specific network byte order functions */
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

/* Fixed value_id for subscription list (single owner per key) */
#define CHAN_SUBS_VALUE_ID 1

/**
 * Generate DHT key for channel subscription list
 */
int dht_channel_subscriptions_make_key(
    const char *fingerprint,
    uint8_t *key_out,
    size_t *key_len_out)
{
    if (!fingerprint || !key_out || !key_len_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to make_key");
        return -1;
    }

    if (strlen(fingerprint) < 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length: %zu", strlen(fingerprint));
        return -1;
    }

    /* Key format: SHA3-512("dna:channels:subs:" + fingerprint) */
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s%s", DHT_CHANNEL_SUBS_NS, fingerprint);

    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), key_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SHA3-512 failed");
        return -1;
    }

    *key_len_out = 64;  /* SHA3-512 = 64 bytes */
    return 0;
}

/**
 * Serialize channel subscriptions to binary format
 *
 * Format:
 * [1-byte version]
 * [4-byte count (big-endian uint32)]
 * For each subscription:
 *   [36-byte channel_uuid (no null terminator)]
 *   [8-byte subscribed_at (big-endian, split 2x4)]
 *   [8-byte last_synced (big-endian, split 2x4)]
 *   [8-byte last_read_at (big-endian, split 2x4)]
 */
static int serialize_subscriptions(
    const dht_channel_subscription_entry_t *subs,
    size_t count,
    uint8_t **out,
    size_t *len_out)
{
    if (!out || !len_out) {
        return -1;
    }

    if (count > DHT_CHANNEL_SUBS_MAX_COUNT) {
        QGP_LOG_ERROR(LOG_TAG, "Too many subscriptions: %zu (max %d)",
                      count, DHT_CHANNEL_SUBS_MAX_COUNT);
        return -2;
    }

    /* Calculate size: header + (entry_size * count) */
    size_t header_size = 1 + 4;  /* version + count */
    size_t entry_size = 36 + 8 + 8 + 8;  /* uuid + subscribed_at + last_synced + last_read_at */
    size_t total_size = header_size + (entry_size * count);

    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate %zu bytes", total_size);
        return -1;
    }

    uint8_t *ptr = buffer;

    /* Write version */
    *ptr++ = DHT_CHANNEL_SUBS_VERSION;

    /* Write count (big-endian uint32) */
    uint32_t count_network = htonl((uint32_t)count);
    memcpy(ptr, &count_network, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* Write each subscription */
    for (size_t i = 0; i < count; i++) {
        /* channel_uuid (36 bytes, no null terminator) */
        memset(ptr, 0, 36);
        if (subs) {
            memcpy(ptr, subs[i].channel_uuid, 36);
        }
        ptr += 36;

        /* subscribed_at (8 bytes, split into 2x4 for network order) */
        uint64_t ts = subs ? subs[i].subscribed_at : 0;
        uint32_t ts_high = htonl((uint32_t)(ts >> 32));
        uint32_t ts_low = htonl((uint32_t)(ts & 0xFFFFFFFF));
        memcpy(ptr, &ts_high, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &ts_low, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        /* last_synced (8 bytes, split into 2x4 for network order) */
        uint64_t ls = subs ? subs[i].last_synced : 0;
        uint32_t ls_high = htonl((uint32_t)(ls >> 32));
        uint32_t ls_low = htonl((uint32_t)(ls & 0xFFFFFFFF));
        memcpy(ptr, &ls_high, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &ls_low, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        /* last_read_at (8 bytes, split into 2x4 for network order) */
        uint64_t lr = subs ? subs[i].last_read_at : 0;
        uint32_t lr_high = htonl((uint32_t)(lr >> 32));
        uint32_t lr_low = htonl((uint32_t)(lr & 0xFFFFFFFF));
        memcpy(ptr, &lr_high, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &lr_low, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
    }

    *out = buffer;
    *len_out = total_size;
    return 0;
}

/**
 * Deserialize channel subscriptions from binary format
 */
static int deserialize_subscriptions(
    const uint8_t *data,
    size_t data_len,
    dht_channel_subscription_entry_t **out,
    size_t *count_out)
{
    if (!data || !out || !count_out) {
        return -1;
    }

    /* Minimum size: header only */
    size_t header_size = 1 + 4;  /* version + count */
    if (data_len < header_size) {
        QGP_LOG_ERROR(LOG_TAG, "Data too small: %zu bytes", data_len);
        return -1;
    }

    const uint8_t *ptr = data;

    /* Read version */
    uint8_t version = *ptr++;
    if (version != DHT_CHANNEL_SUBS_VERSION) {
        QGP_LOG_WARN(LOG_TAG, "Unknown version %u (expected %u), attempting parse",
                     version, DHT_CHANNEL_SUBS_VERSION);
    }

    /* Read count (big-endian uint32) */
    uint32_t count_network;
    memcpy(&count_network, ptr, sizeof(uint32_t));
    uint32_t count = ntohl(count_network);
    ptr += sizeof(uint32_t);

    if (count > DHT_CHANNEL_SUBS_MAX_COUNT) {
        QGP_LOG_ERROR(LOG_TAG, "Count too large: %u (max %d)", count, DHT_CHANNEL_SUBS_MAX_COUNT);
        return -1;
    }

    /* Verify data has enough bytes for all entries */
    size_t entry_size = 36 + 8 + 8 + 8;  /* 60 bytes per entry */
    size_t expected_size = header_size + (entry_size * count);
    if (data_len < expected_size) {
        QGP_LOG_ERROR(LOG_TAG, "Data truncated: %zu bytes (expected %zu)",
                      data_len, expected_size);
        return -1;
    }

    /* Handle empty list */
    if (count == 0) {
        *out = NULL;
        *count_out = 0;
        return 0;
    }

    /* Allocate output array */
    dht_channel_subscription_entry_t *subs = (dht_channel_subscription_entry_t *)
        calloc(count, sizeof(dht_channel_subscription_entry_t));
    if (!subs) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate %u entries", count);
        return -1;
    }

    /* Read each subscription */
    for (uint32_t i = 0; i < count; i++) {
        /* channel_uuid (36 bytes, no null terminator in wire format) */
        memcpy(subs[i].channel_uuid, ptr, 36);
        subs[i].channel_uuid[36] = '\0';
        ptr += 36;

        /* subscribed_at */
        uint32_t ts_high, ts_low;
        memcpy(&ts_high, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(&ts_low, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        subs[i].subscribed_at = ((uint64_t)ntohl(ts_high) << 32) | ntohl(ts_low);

        /* last_synced */
        uint32_t ls_high, ls_low;
        memcpy(&ls_high, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(&ls_low, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        subs[i].last_synced = ((uint64_t)ntohl(ls_high) << 32) | ntohl(ls_low);

        /* last_read_at */
        uint32_t lr_high, lr_low;
        memcpy(&lr_high, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(&lr_low, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        subs[i].last_read_at = ((uint64_t)ntohl(lr_high) << 32) | ntohl(lr_low);
    }

    *out = subs;
    *count_out = count;

    QGP_LOG_DEBUG(LOG_TAG, "Deserialized %u channel subscriptions", count);
    return 0;
}

/**
 * Sync channel subscription list TO DHT
 */
int dht_channel_subscriptions_sync_to_dht(
    const char *fingerprint,
    const dht_channel_subscription_entry_t *subscriptions,
    size_t count)
{
    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sync_to_dht");
        return -1;
    }

    if (count > DHT_CHANNEL_SUBS_MAX_COUNT) {
        QGP_LOG_ERROR(LOG_TAG, "Too many subscriptions: %zu", count);
        return -2;
    }

    /* Generate DHT key */
    uint8_t dht_key[64];
    size_t key_len;
    if (dht_channel_subscriptions_make_key(fingerprint, dht_key, &key_len) != 0) {
        return -1;
    }

    /* Serialize subscriptions */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = serialize_subscriptions(subscriptions, count, &data, &data_len);
    if (ret != 0) {
        return ret;
    }

    /* Put to DHT using nodus_ops */
    ret = nodus_ops_put(dht_key, key_len, data, data_len,
                        DHT_CHANNEL_SUBS_TTL_SECONDS, CHAN_SUBS_VALUE_ID);

    free(data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT put failed: %d", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %zu channel subscriptions to DHT for %.16s...",
                 count, fingerprint);
    return 0;
}

/**
 * Sync channel subscription list FROM DHT
 */
int dht_channel_subscriptions_sync_from_dht(
    const char *fingerprint,
    dht_channel_subscription_entry_t **subscriptions_out,
    size_t *count_out)
{
    if (!fingerprint || !subscriptions_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sync_from_dht");
        return -1;
    }

    *subscriptions_out = NULL;
    *count_out = 0;

    /* Generate DHT key */
    uint8_t dht_key[64];
    size_t key_len;
    if (dht_channel_subscriptions_make_key(fingerprint, dht_key, &key_len) != 0) {
        return -1;
    }

    /* Get from DHT via nodus_ops */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = nodus_ops_get(dht_key, key_len, &data, &data_len);

    if (ret != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No channel subscriptions found in DHT for %.16s...", fingerprint);
        return -2;  /* Not found */
    }

    /* Deserialize */
    ret = deserialize_subscriptions(data, data_len, subscriptions_out, count_out);
    free(data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize channel subscriptions");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved %zu channel subscriptions from DHT for %.16s...",
                 *count_out, fingerprint);
    return 0;
}

/**
 * Free channel subscription array
 */
void dht_channel_subscriptions_free(dht_channel_subscription_entry_t *subscriptions, size_t count)
{
    (void)count;  /* Unused - included for API consistency */
    if (subscriptions) {
        free(subscriptions);
    }
}
