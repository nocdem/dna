/**
 * DHT Contact Request System Implementation
 *
 * ICQ-style contact request system for DNA Messenger.
 *
 * @file dht_contact_request.c
 * @author DNA Messenger Team
 * @date 2025-12-10
 */

#include "dht_contact_request.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define LOG_TAG "DHT_REQUEST"

/* Platform-specific network byte order functions */
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

/**
 * Generate DHT key for user's contact requests inbox
 */
void dht_generate_requests_inbox_key(const char *fingerprint, uint8_t *key_out) {
    if (!fingerprint || !key_out) {
        return;
    }

    /* Key format: SHA3-512(fingerprint + ":requests") */
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:requests", fingerprint);

    qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), key_out);
}

/**
 * Generate value_id for DHT signed put from fingerprint
 */
uint64_t dht_fingerprint_to_value_id(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) < 16) {
        return 1;  /* Default value_id if fingerprint invalid */
    }

    /* Use first 16 hex chars (8 bytes) as value_id */
    uint64_t value_id = 0;
    for (int i = 0; i < 16; i++) {
        char c = fingerprint[i];
        uint8_t nibble;
        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            nibble = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            nibble = c - 'A' + 10;
        } else {
            nibble = 0;
        }
        value_id = (value_id << 4) | nibble;
    }

    /* Ensure non-zero (value_id=0 has special meaning in DHT) */
    if (value_id == 0) {
        value_id = 1;
    }

    return value_id;
}

/**
 * Serialize contact request to binary format
 *
 * Format:
 * [4-byte magic (network order)]
 * [1-byte version]
 * [8-byte timestamp (network order)]
 * [8-byte expiry (network order)]
 * [129-byte sender_fingerprint (null-terminated)]
 * [64-byte sender_name (null-terminated)]
 * [2592-byte sender_dilithium_pubkey]
 * [256-byte message (null-terminated)]
 * [2-byte signature_len (network order)]
 * [signature bytes (variable)]
 */
int dht_serialize_contact_request(
    const dht_contact_request_t *request,
    uint8_t **out,
    size_t *len_out)
{
    if (!request || !out || !len_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for serialization\n");
        return -1;
    }

    /* Calculate total size */
    size_t total_size =
        sizeof(uint32_t) +                    /* magic */
        1 +                                   /* version */
        sizeof(uint64_t) +                    /* timestamp */
        sizeof(uint64_t) +                    /* expiry */
        129 +                                 /* sender_fingerprint */
        64 +                                  /* sender_name */
        DHT_DILITHIUM5_PUBKEY_SIZE +          /* sender_dilithium_pubkey */
        256 +                                 /* message */
        sizeof(uint16_t) +                    /* signature_len */
        request->signature_len;               /* signature */

    /* Allocate buffer */
    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate %zu bytes for serialization\n", total_size);
        return -1;
    }

    uint8_t *ptr = buffer;

    /* Write magic (network order) */
    uint32_t magic_network = htonl(request->magic);
    memcpy(ptr, &magic_network, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* Write version */
    *ptr++ = request->version;

    /* Write timestamp (8 bytes, split into 2x4 bytes for network order) */
    uint32_t ts_high = htonl((uint32_t)(request->timestamp >> 32));
    uint32_t ts_low = htonl((uint32_t)(request->timestamp & 0xFFFFFFFF));
    memcpy(ptr, &ts_high, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &ts_low, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* Write expiry (8 bytes, split into 2x4 bytes for network order) */
    uint32_t exp_high = htonl((uint32_t)(request->expiry >> 32));
    uint32_t exp_low = htonl((uint32_t)(request->expiry & 0xFFFFFFFF));
    memcpy(ptr, &exp_high, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &exp_low, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* Write sender_fingerprint (fixed 129 bytes) */
    memset(ptr, 0, 129);
    strncpy((char *)ptr, request->sender_fingerprint, 128);
    ptr += 129;

    /* Write sender_name (fixed 64 bytes) */
    memset(ptr, 0, 64);
    strncpy((char *)ptr, request->sender_name, 63);
    ptr += 64;

    /* Write sender_dilithium_pubkey (fixed 2592 bytes) */
    memcpy(ptr, request->sender_dilithium_pubkey, DHT_DILITHIUM5_PUBKEY_SIZE);
    ptr += DHT_DILITHIUM5_PUBKEY_SIZE;

    /* Write message (fixed 256 bytes) */
    memset(ptr, 0, 256);
    strncpy((char *)ptr, request->message, 255);
    ptr += 256;

    /* Write signature_len (network order) */
    uint16_t sig_len_network = htons((uint16_t)request->signature_len);
    memcpy(ptr, &sig_len_network, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* Write signature */
    memcpy(ptr, request->signature, request->signature_len);
    ptr += request->signature_len;

    *out = buffer;
    *len_out = total_size;

    return 0;
}

/**
 * Deserialize contact request from binary format
 */
int dht_deserialize_contact_request(
    const uint8_t *data,
    size_t len,
    dht_contact_request_t *request_out)
{
    if (!data || !request_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for deserialization\n");
        return -1;
    }

    /* Minimum size check */
    size_t min_size =
        sizeof(uint32_t) +                    /* magic */
        1 +                                   /* version */
        sizeof(uint64_t) +                    /* timestamp */
        sizeof(uint64_t) +                    /* expiry */
        129 +                                 /* sender_fingerprint */
        64 +                                  /* sender_name */
        DHT_DILITHIUM5_PUBKEY_SIZE +          /* sender_dilithium_pubkey */
        256 +                                 /* message */
        sizeof(uint16_t);                     /* signature_len */

    if (len < min_size) {
        QGP_LOG_ERROR(LOG_TAG, "Data too short for deserialization: %zu < %zu\n", len, min_size);
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + len;

    /* Read magic (network order) */
    uint32_t magic_network;
    memcpy(&magic_network, ptr, sizeof(uint32_t));
    request_out->magic = ntohl(magic_network);
    ptr += sizeof(uint32_t);

    /* Verify magic */
    if (request_out->magic != DHT_CONTACT_REQUEST_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic bytes: 0x%08X (expected 0x%08X)\n",
                request_out->magic, DHT_CONTACT_REQUEST_MAGIC);
        return -1;
    }

    /* Read version */
    request_out->version = *ptr++;

    /* Read timestamp (8 bytes from 2x4 bytes) */
    uint32_t ts_high, ts_low;
    memcpy(&ts_high, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(&ts_low, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    request_out->timestamp = ((uint64_t)ntohl(ts_high) << 32) | ntohl(ts_low);

    /* Read expiry (8 bytes from 2x4 bytes) */
    uint32_t exp_high, exp_low;
    memcpy(&exp_high, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(&exp_low, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    request_out->expiry = ((uint64_t)ntohl(exp_high) << 32) | ntohl(exp_low);

    /* Read sender_fingerprint (fixed 129 bytes) */
    memcpy(request_out->sender_fingerprint, ptr, 129);
    request_out->sender_fingerprint[128] = '\0';  /* Ensure null-terminated */
    ptr += 129;

    /* Read sender_name (fixed 64 bytes) */
    memcpy(request_out->sender_name, ptr, 64);
    request_out->sender_name[63] = '\0';  /* Ensure null-terminated */
    ptr += 64;

    /* Read sender_dilithium_pubkey (fixed 2592 bytes) */
    memcpy(request_out->sender_dilithium_pubkey, ptr, DHT_DILITHIUM5_PUBKEY_SIZE);
    ptr += DHT_DILITHIUM5_PUBKEY_SIZE;

    /* Read message (fixed 256 bytes) */
    memcpy(request_out->message, ptr, 256);
    request_out->message[255] = '\0';  /* Ensure null-terminated */
    ptr += 256;

    /* Read signature_len (network order) */
    uint16_t sig_len_network;
    memcpy(&sig_len_network, ptr, sizeof(uint16_t));
    request_out->signature_len = ntohs(sig_len_network);
    ptr += sizeof(uint16_t);

    /* Bounds check for signature */
    if (ptr + request_out->signature_len > end) {
        QGP_LOG_ERROR(LOG_TAG, "Truncated signature data\n");
        return -1;
    }

    if (request_out->signature_len > DHT_DILITHIUM5_SIG_MAX_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Signature too large: %zu > %d\n",
                request_out->signature_len, DHT_DILITHIUM5_SIG_MAX_SIZE);
        return -1;
    }

    /* Read signature */
    memcpy(request_out->signature, ptr, request_out->signature_len);

    return 0;
}

/**
 * Verify a contact request signature
 */
int dht_verify_contact_request(const dht_contact_request_t *request) {
    if (!request) {
        QGP_LOG_ERROR(LOG_TAG, "NULL request\n");
        return -1;
    }

    /* Check magic */
    if (request->magic != DHT_CONTACT_REQUEST_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X\n", request->magic);
        return -1;
    }

    /* Check version */
    if (request->version != DHT_CONTACT_REQUEST_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %u\n", request->version);
        return -1;
    }

    /* Check expiry */
    uint64_t now = (uint64_t)time(NULL);
    if (request->expiry < now) {
        QGP_LOG_WARN(LOG_TAG, "Request expired (expiry=%llu, now=%llu)\n",
                (unsigned long long)request->expiry, (unsigned long long)now);
        return -1;
    }

    /* Verify fingerprint matches SHA3-512(pubkey) */
    uint8_t computed_fingerprint[64];
    qgp_sha3_512(request->sender_dilithium_pubkey, DHT_DILITHIUM5_PUBKEY_SIZE, computed_fingerprint);

    /* Convert to hex string for comparison */
    char computed_hex[129];
    for (int i = 0; i < 64; i++) {
        snprintf(computed_hex + (i * 2), 3, "%02x", computed_fingerprint[i]);
    }
    computed_hex[128] = '\0';

    if (strcmp(computed_hex, request->sender_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Fingerprint mismatch!\n");
        QGP_LOG_ERROR(LOG_TAG, "  Claimed: %s\n", request->sender_fingerprint);
        QGP_LOG_ERROR(LOG_TAG, "  Computed: %s\n", computed_hex);
        return -1;
    }

    /* Build the data that was signed (everything except signature) */
    size_t signed_data_len =
        sizeof(uint32_t) +                    /* magic */
        1 +                                   /* version */
        sizeof(uint64_t) +                    /* timestamp */
        sizeof(uint64_t) +                    /* expiry */
        129 +                                 /* sender_fingerprint */
        64 +                                  /* sender_name */
        DHT_DILITHIUM5_PUBKEY_SIZE +          /* sender_dilithium_pubkey */
        256;                                  /* message */

    uint8_t *signed_data = (uint8_t *)malloc(signed_data_len);
    if (!signed_data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate signed data buffer\n");
        return -1;
    }

    uint8_t *ptr = signed_data;

    /* Reconstruct signed data (same order as serialization) */
    uint32_t magic_network = htonl(request->magic);
    memcpy(ptr, &magic_network, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    *ptr++ = request->version;

    uint32_t ts_high = htonl((uint32_t)(request->timestamp >> 32));
    uint32_t ts_low = htonl((uint32_t)(request->timestamp & 0xFFFFFFFF));
    memcpy(ptr, &ts_high, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &ts_low, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    uint32_t exp_high = htonl((uint32_t)(request->expiry >> 32));
    uint32_t exp_low = htonl((uint32_t)(request->expiry & 0xFFFFFFFF));
    memcpy(ptr, &exp_high, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &exp_low, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    memset(ptr, 0, 129);
    strncpy((char *)ptr, request->sender_fingerprint, 128);
    ptr += 129;

    memset(ptr, 0, 64);
    strncpy((char *)ptr, request->sender_name, 63);
    ptr += 64;

    memcpy(ptr, request->sender_dilithium_pubkey, DHT_DILITHIUM5_PUBKEY_SIZE);
    ptr += DHT_DILITHIUM5_PUBKEY_SIZE;

    memset(ptr, 0, 256);
    strncpy((char *)ptr, request->message, 255);
    ptr += 256;

    /* Verify Dilithium5 signature */
    int verify_result = qgp_dsa87_verify(
        request->signature,
        request->signature_len,
        signed_data,
        signed_data_len,
        request->sender_dilithium_pubkey
    );

    free(signed_data);

    if (verify_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature verification failed\n");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Request signature verified successfully\n");
    return 0;
}

/**
 * Send a contact request to recipient
 */
int dht_send_contact_request(
    dht_context_t *ctx,
    const char *sender_fingerprint,
    const char *sender_name,
    const uint8_t *sender_dilithium_pubkey,
    const uint8_t *sender_dilithium_privkey,
    const char *recipient_fingerprint,
    const char *optional_message)
{
    if (!ctx || !sender_fingerprint || !sender_dilithium_pubkey ||
        !sender_dilithium_privkey || !recipient_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for sending contact request\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Sending contact request from %.20s... to %.20s...\n",
           sender_fingerprint, recipient_fingerprint);

    /* Build request structure */
    dht_contact_request_t request;
    memset(&request, 0, sizeof(request));

    request.magic = DHT_CONTACT_REQUEST_MAGIC;
    request.version = DHT_CONTACT_REQUEST_VERSION;
    request.timestamp = (uint64_t)time(NULL);
    request.expiry = request.timestamp + DHT_CONTACT_REQUEST_DEFAULT_TTL;

    strncpy(request.sender_fingerprint, sender_fingerprint, 128);
    request.sender_fingerprint[128] = '\0';

    if (sender_name) {
        strncpy(request.sender_name, sender_name, 63);
        request.sender_name[63] = '\0';
    } else {
        request.sender_name[0] = '\0';
    }

    memcpy(request.sender_dilithium_pubkey, sender_dilithium_pubkey, DHT_DILITHIUM5_PUBKEY_SIZE);

    if (optional_message) {
        strncpy(request.message, optional_message, 255);
        request.message[255] = '\0';
    } else {
        request.message[0] = '\0';
    }

    /* Build data to sign (everything except signature) */
    size_t signed_data_len =
        sizeof(uint32_t) +                    /* magic */
        1 +                                   /* version */
        sizeof(uint64_t) +                    /* timestamp */
        sizeof(uint64_t) +                    /* expiry */
        129 +                                 /* sender_fingerprint */
        64 +                                  /* sender_name */
        DHT_DILITHIUM5_PUBKEY_SIZE +          /* sender_dilithium_pubkey */
        256;                                  /* message */

    uint8_t *signed_data = (uint8_t *)malloc(signed_data_len);
    if (!signed_data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate signed data buffer\n");
        return -1;
    }

    uint8_t *ptr = signed_data;

    /* Build signed data */
    uint32_t magic_network = htonl(request.magic);
    memcpy(ptr, &magic_network, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    *ptr++ = request.version;

    uint32_t ts_high = htonl((uint32_t)(request.timestamp >> 32));
    uint32_t ts_low = htonl((uint32_t)(request.timestamp & 0xFFFFFFFF));
    memcpy(ptr, &ts_high, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &ts_low, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    uint32_t exp_high = htonl((uint32_t)(request.expiry >> 32));
    uint32_t exp_low = htonl((uint32_t)(request.expiry & 0xFFFFFFFF));
    memcpy(ptr, &exp_high, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &exp_low, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    memset(ptr, 0, 129);
    strncpy((char *)ptr, request.sender_fingerprint, 128);
    ptr += 129;

    memset(ptr, 0, 64);
    strncpy((char *)ptr, request.sender_name, 63);
    ptr += 64;

    memcpy(ptr, request.sender_dilithium_pubkey, DHT_DILITHIUM5_PUBKEY_SIZE);
    ptr += DHT_DILITHIUM5_PUBKEY_SIZE;

    memset(ptr, 0, 256);
    strncpy((char *)ptr, request.message, 255);
    ptr += 256;

    /* Sign with Dilithium5 */
    size_t sig_len = DHT_DILITHIUM5_SIG_MAX_SIZE;
    int sign_result = qgp_dsa87_sign(
        request.signature,
        &sig_len,
        signed_data,
        signed_data_len,
        sender_dilithium_privkey
    );

    free(signed_data);

    if (sign_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign contact request\n");
        return -1;
    }

    request.signature_len = sig_len;

    QGP_LOG_DEBUG(LOG_TAG, "Signed request with %zu byte signature\n", sig_len);

    /* Serialize request */
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;

    if (dht_serialize_contact_request(&request, &serialized, &serialized_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize contact request\n");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Serialized request: %zu bytes\n", serialized_len);

    /* Generate recipient's inbox key */
    uint8_t inbox_key[64];
    dht_generate_requests_inbox_key(recipient_fingerprint, inbox_key);

    /* Log key for debugging */
    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&key_hex[i*2], "%02x", inbox_key[i]);
    }
    key_hex[32] = '\0';
    QGP_LOG_INFO(LOG_TAG, "Recipient inbox key (first 16 bytes): %s\n", key_hex);

    /* Generate value_id from sender's fingerprint (ensures unique per-sender) */
    uint64_t value_id = dht_fingerprint_to_value_id(sender_fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Publishing request to inbox with value_id=0x%llX\n", (unsigned long long)value_id);

    /* Publish to DHT with signed put */
    int put_result = dht_put_signed(
        ctx,
        inbox_key,
        64,
        serialized,
        serialized_len,
        value_id,
        DHT_CONTACT_REQUEST_DEFAULT_TTL,
        "contact_request_send"
    );

    free(serialized);

    if (put_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish contact request to DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Contact request sent successfully\n");
    return 0;
}

/**
 * Fetch all pending contact requests from my inbox
 */
int dht_fetch_contact_requests(
    dht_context_t *ctx,
    const char *my_fingerprint,
    dht_contact_request_t **requests_out,
    size_t *count_out)
{
    if (!ctx || !my_fingerprint || !requests_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetching contact requests\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching contact requests for %.20s...\n", my_fingerprint);

    /* Generate my inbox key */
    uint8_t inbox_key[64];
    dht_generate_requests_inbox_key(my_fingerprint, inbox_key);

    /* Log key for debugging */
    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&key_hex[i*2], "%02x", inbox_key[i]);
    }
    key_hex[32] = '\0';
    QGP_LOG_DEBUG(LOG_TAG, "Inbox key (first 16 bytes): %s\n", key_hex);

    /* Get all values at this key (from multiple requesters) */
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t values_count = 0;

    int get_result = dht_get_all(ctx, inbox_key, 64, &values, &values_len, &values_count);

    if (get_result != 0 || values_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No pending contact requests found\n");
        *requests_out = NULL;
        *count_out = 0;
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu raw values in inbox\n", values_count);

    /* Allocate array for parsed requests */
    dht_contact_request_t *requests = (dht_contact_request_t *)calloc(
        values_count, sizeof(dht_contact_request_t));

    if (!requests) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate requests array\n");
        /* Free values */
        for (size_t i = 0; i < values_count; i++) {
            free(values[i]);
        }
        free(values);
        free(values_len);
        return -1;
    }

    size_t valid_count = 0;
    uint64_t now = (uint64_t)time(NULL);

    /* Parse and verify each value */
    for (size_t i = 0; i < values_count; i++) {
        dht_contact_request_t request;
        memset(&request, 0, sizeof(request));

        /* Deserialize */
        if (dht_deserialize_contact_request(values[i], values_len[i], &request) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to deserialize request %zu, skipping\n", i);
            continue;
        }

        /* Verify signature and validity */
        if (dht_verify_contact_request(&request) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Request %zu failed verification, skipping\n", i);
            continue;
        }

        /* Check expiry */
        if (request.expiry < now) {
            QGP_LOG_WARN(LOG_TAG, "Request %zu expired, skipping\n", i);
            continue;
        }

        /* Valid request - add to array */
        requests[valid_count++] = request;

        QGP_LOG_INFO(LOG_TAG, "Valid request from: %.20s... (%s)\n",
               request.sender_fingerprint,
               request.sender_name[0] ? request.sender_name : "no name");
    }

    /* Free raw values */
    for (size_t i = 0; i < values_count; i++) {
        free(values[i]);
    }
    free(values);
    free(values_len);

    /* Resize array to actual count */
    if (valid_count < values_count && valid_count > 0) {
        dht_contact_request_t *resized = (dht_contact_request_t *)realloc(
            requests, valid_count * sizeof(dht_contact_request_t));
        if (resized) {
            requests = resized;
        }
    }

    if (valid_count == 0) {
        free(requests);
        requests = NULL;
    }

    *requests_out = requests;
    *count_out = valid_count;

    QGP_LOG_INFO(LOG_TAG, "Returning %zu valid contact requests\n", valid_count);
    return 0;
}

/**
 * Cancel a previously sent contact request
 */
int dht_cancel_contact_request(
    dht_context_t *ctx,
    const char *sender_fingerprint,
    const char *recipient_fingerprint)
{
    if (!ctx || !sender_fingerprint || !recipient_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for canceling contact request\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Canceling contact request from %.20s... to %.20s...\n",
           sender_fingerprint, recipient_fingerprint);

    /* Generate recipient's inbox key */
    uint8_t inbox_key[64];
    dht_generate_requests_inbox_key(recipient_fingerprint, inbox_key);

    /* Generate value_id from sender's fingerprint */
    uint64_t value_id = dht_fingerprint_to_value_id(sender_fingerprint);

    /* Publish empty value with very short TTL to effectively "delete" */
    /* Note: DHT doesn't support true deletion, so we publish expired data */
    uint8_t empty_data[1] = {0};

    int put_result = dht_put_signed(
        ctx,
        inbox_key,
        64,
        empty_data,
        1,
        value_id,
        1,  /* 1 second TTL - effectively immediate expiry */
        "contact_request_clear"
    );

    if (put_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to cancel contact request\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Contact request canceled successfully\n");
    return 0;
}

/**
 * Free array of contact requests
 */
void dht_contact_requests_free(dht_contact_request_t *requests, size_t count) {
    if (requests) {
        /* No dynamic allocations inside dht_contact_request_t (all fixed-size arrays) */
        free(requests);
    }
}
