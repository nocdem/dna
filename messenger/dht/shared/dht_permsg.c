/**
 * DHT Per-Message Storage Implementation
 *
 * Each message gets a unique DHT key - no GET-MODIFY-PUT pattern.
 * Eliminates the blocking GET that was causing slow message sending.
 */

#include "dht_permsg.h"
#include "../crypto/utils/qgp_sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

// For random nonce generation
#include <fcntl.h>
#include <unistd.h>

/**
 * Generate random bytes for nonce
 */
static int get_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t result = read(fd, buf, len);
    close(fd);
    return (result == (ssize_t)len) ? 0 : -1;
}

/**
 * Generate notification key for recipient
 */
void dht_permsg_make_notification_key(
    const char *recipient_fp,
    uint8_t *key_out
) {
    // Build input: recipient_fp + ":msg_notifications"
    char input[256];
    snprintf(input, sizeof(input), "%s:msg_notifications", recipient_fp);

    // SHA3-512 hash
    uint8_t hash[64];
    qgp_sha3_512((const uint8_t*)input, strlen(input), hash);

    // Truncate to 32 bytes for DHT key
    memcpy(key_out, hash, DHT_PERMSG_KEY_SIZE);
}

/**
 * Generate unique message key
 */
void dht_permsg_make_message_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t timestamp,
    uint8_t *key_out
) {
    // Generate random nonce
    uint8_t nonce[16];
    if (get_random_bytes(nonce, sizeof(nonce)) != 0) {
        // Fallback: use address as entropy (not ideal but better than nothing)
        memset(nonce, 0, sizeof(nonce));
        uintptr_t addr = (uintptr_t)key_out;
        memcpy(nonce, &addr, sizeof(addr));
    }

    // Build input: sender_fp + recipient_fp + timestamp_hex + nonce_hex
    char input[512];
    char nonce_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(nonce_hex + i*2, "%02x", nonce[i]);
    }

    snprintf(input, sizeof(input), "%s%s%016lx%s",
             sender_fp, recipient_fp, (unsigned long)timestamp, nonce_hex);

    // SHA3-512 hash
    uint8_t hash[64];
    qgp_sha3_512((const uint8_t*)input, strlen(input), hash);

    // Truncate to 32 bytes
    memcpy(key_out, hash, DHT_PERMSG_KEY_SIZE);
}

/**
 * Serialize message to binary format
 */
int dht_permsg_serialize(
    const dht_permsg_t *msg,
    uint8_t **data_out,
    size_t *len_out
) {
    if (!msg || !data_out || !len_out) return -1;

    // Calculate total size
    // magic(4) + version(1) + timestamp(8) + sender(128) + recipient(128) + ciphertext_len(4) + ciphertext
    size_t total_len = 4 + 1 + 8 + DHT_PERMSG_FINGERPRINT_SIZE + DHT_PERMSG_FINGERPRINT_SIZE + 4 + msg->ciphertext_len;

    uint8_t *data = (uint8_t*)malloc(total_len);
    if (!data) return -1;

    uint8_t *ptr = data;

    // Magic (network byte order)
    uint32_t magic = htonl(DHT_PERMSG_MAGIC);
    memcpy(ptr, &magic, 4);
    ptr += 4;

    // Version
    *ptr++ = DHT_PERMSG_VERSION;

    // Timestamp (network byte order, 64-bit)
    uint64_t ts_net = htobe64(msg->timestamp);
    memcpy(ptr, &ts_net, 8);
    ptr += 8;

    // Sender fingerprint (fixed 128 bytes)
    memcpy(ptr, msg->sender_fp, DHT_PERMSG_FINGERPRINT_SIZE);
    ptr += DHT_PERMSG_FINGERPRINT_SIZE;

    // Recipient fingerprint (fixed 128 bytes)
    memcpy(ptr, msg->recipient_fp, DHT_PERMSG_FINGERPRINT_SIZE);
    ptr += DHT_PERMSG_FINGERPRINT_SIZE;

    // Ciphertext length (network byte order)
    uint32_t ct_len = htonl((uint32_t)msg->ciphertext_len);
    memcpy(ptr, &ct_len, 4);
    ptr += 4;

    // Ciphertext
    memcpy(ptr, msg->ciphertext, msg->ciphertext_len);

    *data_out = data;
    *len_out = total_len;
    return 0;
}

/**
 * Deserialize message from binary format
 */
int dht_permsg_deserialize(
    const uint8_t *data,
    size_t len,
    dht_permsg_t *msg_out
) {
    if (!data || !msg_out) return -1;

    // Minimum size check
    size_t min_size = 4 + 1 + 8 + DHT_PERMSG_FINGERPRINT_SIZE + DHT_PERMSG_FINGERPRINT_SIZE + 4;
    if (len < min_size) {
        fprintf(stderr, "[PerMsg] Data too short: %zu < %zu\n", len, min_size);
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + len;

    // Magic
    uint32_t magic;
    memcpy(&magic, ptr, 4);
    magic = ntohl(magic);
    if (magic != DHT_PERMSG_MAGIC) {
        fprintf(stderr, "[PerMsg] Invalid magic: 0x%08x\n", magic);
        return -1;
    }
    ptr += 4;

    // Version
    uint8_t version = *ptr++;
    if (version != DHT_PERMSG_VERSION) {
        fprintf(stderr, "[PerMsg] Unknown version: %u\n", version);
        return -1;
    }

    // Timestamp
    uint64_t ts_net;
    memcpy(&ts_net, ptr, 8);
    msg_out->timestamp = be64toh(ts_net);
    ptr += 8;

    // Sender fingerprint
    memcpy(msg_out->sender_fp, ptr, DHT_PERMSG_FINGERPRINT_SIZE);
    msg_out->sender_fp[DHT_PERMSG_FINGERPRINT_SIZE] = '\0';
    ptr += DHT_PERMSG_FINGERPRINT_SIZE;

    // Recipient fingerprint
    memcpy(msg_out->recipient_fp, ptr, DHT_PERMSG_FINGERPRINT_SIZE);
    msg_out->recipient_fp[DHT_PERMSG_FINGERPRINT_SIZE] = '\0';
    ptr += DHT_PERMSG_FINGERPRINT_SIZE;

    // Ciphertext length
    uint32_t ct_len_net;
    memcpy(&ct_len_net, ptr, 4);
    msg_out->ciphertext_len = ntohl(ct_len_net);
    ptr += 4;

    // Validate remaining data
    if (ptr + msg_out->ciphertext_len > end) {
        fprintf(stderr, "[PerMsg] Truncated ciphertext\n");
        return -1;
    }

    // Allocate and copy ciphertext
    msg_out->ciphertext = (uint8_t*)malloc(msg_out->ciphertext_len);
    if (!msg_out->ciphertext) return -1;
    memcpy(msg_out->ciphertext, ptr, msg_out->ciphertext_len);

    return 0;
}

/**
 * Serialize notification to binary format
 */
int dht_permsg_serialize_notification(
    const dht_permsg_notification_t *ntf,
    uint8_t **data_out,
    size_t *len_out
) {
    if (!ntf || !data_out || !len_out) return -1;

    // Size: magic(4) + version(1) + timestamp(8) + sender(128) + message_key(32)
    size_t total_len = 4 + 1 + 8 + DHT_PERMSG_FINGERPRINT_SIZE + DHT_PERMSG_KEY_SIZE;

    uint8_t *data = (uint8_t*)malloc(total_len);
    if (!data) return -1;

    uint8_t *ptr = data;

    // Magic
    uint32_t magic = htonl(DHT_PERMSG_NTF_MAGIC);
    memcpy(ptr, &magic, 4);
    ptr += 4;

    // Version
    *ptr++ = DHT_PERMSG_VERSION;

    // Timestamp
    uint64_t ts_net = htobe64(ntf->timestamp);
    memcpy(ptr, &ts_net, 8);
    ptr += 8;

    // Sender fingerprint
    memcpy(ptr, ntf->sender_fp, DHT_PERMSG_FINGERPRINT_SIZE);
    ptr += DHT_PERMSG_FINGERPRINT_SIZE;

    // Message key
    memcpy(ptr, ntf->message_key, DHT_PERMSG_KEY_SIZE);

    *data_out = data;
    *len_out = total_len;
    return 0;
}

/**
 * Deserialize notification from binary format
 */
int dht_permsg_deserialize_notification(
    const uint8_t *data,
    size_t len,
    dht_permsg_notification_t *ntf_out
) {
    if (!data || !ntf_out) return -1;

    size_t expected_len = 4 + 1 + 8 + DHT_PERMSG_FINGERPRINT_SIZE + DHT_PERMSG_KEY_SIZE;
    if (len < expected_len) {
        fprintf(stderr, "[PerMsg] Notification too short: %zu < %zu\n", len, expected_len);
        return -1;
    }

    const uint8_t *ptr = data;

    // Magic
    uint32_t magic;
    memcpy(&magic, ptr, 4);
    magic = ntohl(magic);
    if (magic != DHT_PERMSG_NTF_MAGIC) {
        fprintf(stderr, "[PerMsg] Invalid notification magic: 0x%08x\n", magic);
        return -1;
    }
    ptr += 4;

    // Version
    uint8_t version = *ptr++;
    if (version != DHT_PERMSG_VERSION) {
        fprintf(stderr, "[PerMsg] Unknown notification version: %u\n", version);
        return -1;
    }

    // Timestamp
    uint64_t ts_net;
    memcpy(&ts_net, ptr, 8);
    ntf_out->timestamp = be64toh(ts_net);
    ptr += 8;

    // Sender fingerprint
    memcpy(ntf_out->sender_fp, ptr, DHT_PERMSG_FINGERPRINT_SIZE);
    ntf_out->sender_fp[DHT_PERMSG_FINGERPRINT_SIZE] = '\0';
    ptr += DHT_PERMSG_FINGERPRINT_SIZE;

    // Message key
    memcpy(ntf_out->message_key, ptr, DHT_PERMSG_KEY_SIZE);

    return 0;
}

/**
 * Free a single message
 */
void dht_permsg_free(dht_permsg_t *msg) {
    if (msg) {
        free(msg->ciphertext);
        msg->ciphertext = NULL;
        msg->ciphertext_len = 0;
    }
}

/**
 * Free message array
 */
void dht_permsg_free_messages(dht_permsg_t *messages, size_t count) {
    if (messages) {
        for (size_t i = 0; i < count; i++) {
            dht_permsg_free(&messages[i]);
        }
        free(messages);
    }
}

/**
 * Free notification array
 */
void dht_permsg_free_notifications(dht_permsg_notification_t *notifications, size_t count) {
    (void)count;  // Notifications don't have dynamic members
    free(notifications);
}

/**
 * Store a single message in DHT (NO GET REQUIRED - instant PUT)
 */
int dht_permsg_put(
    dht_context_t *ctx,
    const char *sender_fp,
    const char *recipient_fp,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_seconds,
    uint8_t *message_key_out
) {
    if (!ctx || !sender_fp || !recipient_fp || !ciphertext || ciphertext_len == 0) {
        fprintf(stderr, "[PerMsg] Invalid parameters\n");
        return -1;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = DHT_PERMSG_DEFAULT_TTL;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t timestamp = (uint64_t)time(NULL);

    // 1. Generate unique message key
    uint8_t message_key[DHT_PERMSG_KEY_SIZE];
    dht_permsg_make_message_key(sender_fp, recipient_fp, timestamp, message_key);

    printf("[PerMsg] PUT message: %.16s...→%.16s... (key: %02x%02x%02x%02x...)\n",
           sender_fp, recipient_fp,
           message_key[0], message_key[1], message_key[2], message_key[3]);

    // 2. Build message structure
    dht_permsg_t msg = {
        .timestamp = timestamp,
        .ciphertext = (uint8_t*)ciphertext,  // Temporary, won't free
        .ciphertext_len = ciphertext_len
    };
    strncpy(msg.sender_fp, sender_fp, DHT_PERMSG_FINGERPRINT_SIZE);
    msg.sender_fp[DHT_PERMSG_FINGERPRINT_SIZE] = '\0';
    strncpy(msg.recipient_fp, recipient_fp, DHT_PERMSG_FINGERPRINT_SIZE);
    msg.recipient_fp[DHT_PERMSG_FINGERPRINT_SIZE] = '\0';
    memcpy(msg.message_key, message_key, DHT_PERMSG_KEY_SIZE);

    // 3. Serialize message
    uint8_t *msg_data = NULL;
    size_t msg_len = 0;
    if (dht_permsg_serialize(&msg, &msg_data, &msg_len) != 0) {
        fprintf(stderr, "[PerMsg] Failed to serialize message\n");
        return -1;
    }

    // 4. PUT message to DHT (async, returns immediately)
    // Use unique value_id based on timestamp+random to allow multiple messages
    uint64_t value_id = timestamp ^ ((uint64_t)message_key[0] << 56);
    int put_result = dht_put_signed(ctx, message_key, DHT_PERMSG_KEY_SIZE,
                                     msg_data, msg_len, value_id, ttl_seconds);
    free(msg_data);

    if (put_result != 0) {
        fprintf(stderr, "[PerMsg] Failed to PUT message to DHT\n");
        return -1;
    }

    // 5. Build and PUT notification
    dht_permsg_notification_t ntf = {
        .timestamp = timestamp
    };
    strncpy(ntf.sender_fp, sender_fp, DHT_PERMSG_FINGERPRINT_SIZE);
    ntf.sender_fp[DHT_PERMSG_FINGERPRINT_SIZE] = '\0';
    memcpy(ntf.message_key, message_key, DHT_PERMSG_KEY_SIZE);

    uint8_t *ntf_data = NULL;
    size_t ntf_len = 0;
    if (dht_permsg_serialize_notification(&ntf, &ntf_data, &ntf_len) != 0) {
        fprintf(stderr, "[PerMsg] Failed to serialize notification\n");
        // Message was PUT successfully, just notification failed
        // Still return success but log warning
    } else {
        // PUT notification to recipient's notification key
        uint8_t ntf_key[DHT_PERMSG_KEY_SIZE];
        dht_permsg_make_notification_key(recipient_fp, ntf_key);

        // Notifications accumulate - use unique value_id for each
        int ntf_result = dht_put_signed(ctx, ntf_key, DHT_PERMSG_KEY_SIZE,
                                         ntf_data, ntf_len, value_id, ttl_seconds);
        free(ntf_data);

        if (ntf_result != 0) {
            fprintf(stderr, "[PerMsg] Warning: Failed to PUT notification\n");
        }
    }

    // 6. Return message key if requested
    if (message_key_out) {
        memcpy(message_key_out, message_key, DHT_PERMSG_KEY_SIZE);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                      (end.tv_nsec - start.tv_nsec) / 1000000;

    printf("[PerMsg] ✓ Message PUT complete (%ld ms, %zu bytes)\n", elapsed_ms, ciphertext_len);
    return 0;
}

/**
 * Fetch a single message from DHT by its key
 */
int dht_permsg_get(
    dht_context_t *ctx,
    const uint8_t *message_key,
    dht_permsg_t *msg_out
) {
    if (!ctx || !message_key || !msg_out) return -1;

    memset(msg_out, 0, sizeof(*msg_out));

    printf("[PerMsg] GET message (key: %02x%02x%02x%02x...)\n",
           message_key[0], message_key[1], message_key[2], message_key[3]);

    uint8_t *data = NULL;
    size_t data_len = 0;

    int result = dht_get(ctx, message_key, DHT_PERMSG_KEY_SIZE, &data, &data_len);
    if (result != 0 || !data) {
        return -2;  // Not found
    }

    result = dht_permsg_deserialize(data, data_len, msg_out);
    free(data);

    if (result == 0) {
        memcpy(msg_out->message_key, message_key, DHT_PERMSG_KEY_SIZE);
    }

    return result;
}

/**
 * Fetch all notifications for a recipient
 */
int dht_permsg_get_notifications(
    dht_context_t *ctx,
    const char *recipient_fp,
    dht_permsg_notification_t **notifications_out,
    size_t *count_out
) {
    if (!ctx || !recipient_fp || !notifications_out || !count_out) return -1;

    *notifications_out = NULL;
    *count_out = 0;

    // Generate notification key
    uint8_t ntf_key[DHT_PERMSG_KEY_SIZE];
    dht_permsg_make_notification_key(recipient_fp, ntf_key);

    printf("[PerMsg] GET notifications for %.16s... (key: %02x%02x%02x%02x...)\n",
           recipient_fp, ntf_key[0], ntf_key[1], ntf_key[2], ntf_key[3]);

    // Get all values at notification key (OpenDHT accumulates them)
    uint8_t **all_values = NULL;
    size_t *all_lengths = NULL;
    size_t value_count = 0;

    int result = dht_get_all(ctx, ntf_key, DHT_PERMSG_KEY_SIZE,
                              &all_values, &all_lengths, &value_count);

    if (result != 0 || value_count == 0) {
        printf("[PerMsg] No notifications found\n");
        return 0;  // Not an error, just no notifications
    }

    printf("[PerMsg] Found %zu notification values\n", value_count);

    // Allocate notification array
    dht_permsg_notification_t *notifications = (dht_permsg_notification_t*)
        calloc(value_count, sizeof(dht_permsg_notification_t));
    if (!notifications) {
        for (size_t i = 0; i < value_count; i++) free(all_values[i]);
        free(all_values);
        free(all_lengths);
        return -1;
    }

    // Deserialize each notification
    size_t valid_count = 0;
    for (size_t i = 0; i < value_count; i++) {
        if (dht_permsg_deserialize_notification(all_values[i], all_lengths[i],
                                                  &notifications[valid_count]) == 0) {
            valid_count++;
        }
        free(all_values[i]);
    }
    free(all_values);
    free(all_lengths);

    printf("[PerMsg] Deserialized %zu valid notifications\n", valid_count);

    *notifications_out = notifications;
    *count_out = valid_count;
    return 0;
}

/**
 * Fetch all messages for recipient from contacts
 */
int dht_permsg_fetch_from_contacts(
    dht_context_t *ctx,
    const char *recipient_fp,
    const char **sender_list,
    size_t sender_count,
    dht_permsg_t **messages_out,
    size_t *count_out
) {
    if (!ctx || !recipient_fp || !messages_out || !count_out) return -1;

    *messages_out = NULL;
    *count_out = 0;

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // 1. Get all notifications
    dht_permsg_notification_t *notifications = NULL;
    size_t ntf_count = 0;

    if (dht_permsg_get_notifications(ctx, recipient_fp, &notifications, &ntf_count) != 0) {
        return -1;
    }

    if (ntf_count == 0) {
        printf("[PerMsg] No messages to fetch\n");
        return 0;
    }

    // 2. Filter by sender list (if provided)
    size_t filtered_count = 0;
    for (size_t i = 0; i < ntf_count; i++) {
        bool include = true;

        if (sender_list && sender_count > 0) {
            include = false;
            for (size_t j = 0; j < sender_count; j++) {
                if (strcmp(notifications[i].sender_fp, sender_list[j]) == 0) {
                    include = true;
                    break;
                }
            }
        }

        if (include) {
            if (filtered_count != i) {
                notifications[filtered_count] = notifications[i];
            }
            filtered_count++;
        }
    }

    printf("[PerMsg] Filtered to %zu notifications from contacts\n", filtered_count);

    if (filtered_count == 0) {
        dht_permsg_free_notifications(notifications, ntf_count);
        return 0;
    }

    // 3. Fetch each message
    dht_permsg_t *messages = (dht_permsg_t*)calloc(filtered_count, sizeof(dht_permsg_t));
    if (!messages) {
        dht_permsg_free_notifications(notifications, ntf_count);
        return -1;
    }

    size_t fetched_count = 0;
    for (size_t i = 0; i < filtered_count; i++) {
        if (dht_permsg_get(ctx, notifications[i].message_key, &messages[fetched_count]) == 0) {
            fetched_count++;
        }
    }

    dht_permsg_free_notifications(notifications, ntf_count);

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                      (end.tv_nsec - start.tv_nsec) / 1000000;

    printf("[PerMsg] ✓ Fetched %zu/%zu messages (%ld ms)\n",
           fetched_count, filtered_count, elapsed_ms);

    *messages_out = messages;
    *count_out = fetched_count;
    return 0;
}
