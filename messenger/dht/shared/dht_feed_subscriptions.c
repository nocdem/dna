/**
 * DHT Feed Subscriptions Sync Implementation
 * Multi-device sync for feed topic subscriptions
 *
 * @file dht_feed_subscriptions.c
 * @author DNA Messenger Team
 * @date 2026-01-30
 */

#include "dht_feed_subscriptions.h"
#include "../core/dht_context.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LOG_TAG "FEED_SUBS_DHT"

/* Platform-specific network byte order functions */
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

/* Magic number for format validation */
#define FEED_SUBS_MAGIC 0x46454544  /* "FEED" */

/* DHT key prefix */
#define DHT_KEY_PREFIX "dna:feeds:subscriptions:"

/* Fixed value_id for subscription list (single owner per key) */
#define SUBS_VALUE_ID 1

/**
 * Generate DHT key for subscription list
 */
int dht_feed_subscriptions_make_key(
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

    /* Key format: SHA3-512("dna:feeds:subscriptions:" + fingerprint) */
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s%s", DHT_KEY_PREFIX, fingerprint);

    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), key_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SHA3-512 failed");
        return -1;
    }

    *key_len_out = 64;  /* SHA3-512 = 64 bytes */
    return 0;
}

/**
 * Serialize subscriptions to binary format
 *
 * Format:
 * [4-byte magic (network order)]
 * [1-byte version]
 * [2-byte count (network order)]
 * For each subscription:
 *   [36-byte topic_uuid (null-terminated)]
 *   [8-byte subscribed_at (network order, split 2x4)]
 *   [8-byte last_synced (network order, split 2x4)]
 */
static int serialize_subscriptions(
    const dht_feed_subscription_entry_t *subs,
    size_t count,
    uint8_t **out,
    size_t *len_out)
{
    if (!out || !len_out) {
        return -1;
    }

    if (count > DHT_FEED_SUBS_MAX_COUNT) {
        QGP_LOG_ERROR(LOG_TAG, "Too many subscriptions: %zu (max %d)",
                      count, DHT_FEED_SUBS_MAX_COUNT);
        return -2;
    }

    /* Calculate size: header + (entry_size * count) */
    size_t header_size = 4 + 1 + 2;  /* magic + version + count */
    size_t entry_size = 37 + 8 + 8;  /* uuid + subscribed_at + last_synced */
    size_t total_size = header_size + (entry_size * count);

    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate %zu bytes", total_size);
        return -1;
    }

    uint8_t *ptr = buffer;

    /* Write magic (network order) */
    uint32_t magic_network = htonl(FEED_SUBS_MAGIC);
    memcpy(ptr, &magic_network, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* Write version */
    *ptr++ = DHT_FEED_SUBS_VERSION;

    /* Write count (network order) */
    uint16_t count_network = htons((uint16_t)count);
    memcpy(ptr, &count_network, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* Write each subscription */
    for (size_t i = 0; i < count; i++) {
        /* topic_uuid (37 bytes, null-terminated) */
        memset(ptr, 0, 37);
        if (subs) {
            strncpy((char *)ptr, subs[i].topic_uuid, 36);
        }
        ptr += 37;

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
    }

    *out = buffer;
    *len_out = total_size;
    return 0;
}

/**
 * Deserialize subscriptions from binary format
 */
static int deserialize_subscriptions(
    const uint8_t *data,
    size_t data_len,
    dht_feed_subscription_entry_t **out,
    size_t *count_out)
{
    if (!data || !out || !count_out) {
        return -1;
    }

    /* Minimum size: header only */
    size_t header_size = 4 + 1 + 2;
    if (data_len < header_size) {
        QGP_LOG_ERROR(LOG_TAG, "Data too small: %zu bytes", data_len);
        return -1;
    }

    const uint8_t *ptr = data;

    /* Read and verify magic */
    uint32_t magic_network;
    memcpy(&magic_network, ptr, sizeof(uint32_t));
    uint32_t magic = ntohl(magic_network);
    if (magic != FEED_SUBS_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X (expected 0x%08X)",
                      magic, FEED_SUBS_MAGIC);
        return -1;
    }
    ptr += sizeof(uint32_t);

    /* Read version */
    uint8_t version = *ptr++;
    if (version != DHT_FEED_SUBS_VERSION) {
        QGP_LOG_WARN(LOG_TAG, "Unknown version %u (expected %u), attempting parse",
                     version, DHT_FEED_SUBS_VERSION);
    }

    /* Read count */
    uint16_t count_network;
    memcpy(&count_network, ptr, sizeof(uint16_t));
    uint16_t count = ntohs(count_network);
    ptr += sizeof(uint16_t);

    if (count > DHT_FEED_SUBS_MAX_COUNT) {
        QGP_LOG_ERROR(LOG_TAG, "Count too large: %u (max %d)", count, DHT_FEED_SUBS_MAX_COUNT);
        return -1;
    }

    /* Verify data has enough bytes for all entries */
    size_t entry_size = 37 + 8 + 8;
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
    dht_feed_subscription_entry_t *subs = (dht_feed_subscription_entry_t *)
        calloc(count, sizeof(dht_feed_subscription_entry_t));
    if (!subs) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate %u entries", count);
        return -1;
    }

    /* Read each subscription */
    for (uint16_t i = 0; i < count; i++) {
        /* topic_uuid */
        memcpy(subs[i].topic_uuid, ptr, 36);
        subs[i].topic_uuid[36] = '\0';
        ptr += 37;

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
    }

    *out = subs;
    *count_out = count;

    QGP_LOG_DEBUG(LOG_TAG, "Deserialized %u subscriptions", count);
    return 0;
}

/**
 * Sync subscription list TO DHT
 */
int dht_feed_subscriptions_sync_to_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dht_feed_subscription_entry_t *subscriptions,
    size_t count)
{
    if (!dht_ctx || !fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sync_to_dht");
        return -1;
    }

    if (count > DHT_FEED_SUBS_MAX_COUNT) {
        QGP_LOG_ERROR(LOG_TAG, "Too many subscriptions: %zu", count);
        return -2;
    }

    /* Generate DHT key */
    uint8_t dht_key[64];
    size_t key_len;
    if (dht_feed_subscriptions_make_key(fingerprint, dht_key, &key_len) != 0) {
        return -1;
    }

    /* Serialize subscriptions */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = serialize_subscriptions(subscriptions, count, &data, &data_len);
    if (ret != 0) {
        return ret;
    }

    /* Put to DHT using signed put */
    ret = dht_put_signed(dht_ctx, dht_key, key_len, data, data_len,
                         SUBS_VALUE_ID, DHT_FEED_SUBS_TTL_SECONDS, "feed_subs");

    free(data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT put failed: %d", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %zu subscriptions to DHT for %.16s...",
                 count, fingerprint);
    return 0;
}

/**
 * Sync subscription list FROM DHT
 */
int dht_feed_subscriptions_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dht_feed_subscription_entry_t **subscriptions_out,
    size_t *count_out)
{
    if (!dht_ctx || !fingerprint || !subscriptions_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sync_from_dht");
        return -1;
    }

    *subscriptions_out = NULL;
    *count_out = 0;

    /* Generate DHT key */
    uint8_t dht_key[64];
    size_t key_len;
    if (dht_feed_subscriptions_make_key(fingerprint, dht_key, &key_len) != 0) {
        return -1;
    }

    /* Get from DHT */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_get(dht_ctx, dht_key, key_len, &data, &data_len);

    if (ret != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No subscriptions found in DHT for %.16s...", fingerprint);
        return -2;  /* Not found */
    }

    /* Deserialize */
    ret = deserialize_subscriptions(data, data_len, subscriptions_out, count_out);
    free(data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize subscriptions");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved %zu subscriptions from DHT for %.16s...",
                 *count_out, fingerprint);
    return 0;
}

/**
 * Free subscription array
 */
void dht_feed_subscriptions_free(dht_feed_subscription_entry_t *subscriptions, size_t count)
{
    (void)count;  /* Unused - included for API consistency */
    if (subscriptions) {
        free(subscriptions);
    }
}
