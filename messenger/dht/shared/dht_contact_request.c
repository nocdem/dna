/**
 * DHT Contact Request System Implementation
 *
 * ICQ-style contact request system for DNA Connect.
 *
 * @file dht_contact_request.c
 * @author DNA Connect Team
 * @date 2025-12-10
 */

#include "dht_contact_request.h"
#include "codec/contact_request_codec.h"
#include "nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* Platform network headers MUST precede qgp_safe_string.h. winsock2.h
 * transitively pulls windows.h, whose rpcndr.h/stralign.h reference
 * strcpy in macro bodies — the poison pragma rejects them otherwise. */
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#include "crypto/utils/qgp_safe_string.h"

#define LOG_TAG "DHT_REQUEST"

/* NC-1: dht_generate_requests_inbox_key / dht_fingerprint_to_value_id /
 * dht_serialize_contact_request / dht_deserialize_contact_request /
 * dht_verify_contact_request (the contact-request codec) moved verbatim to
 * codec/contact_request_codec.c; declarations unchanged in
 * dht_contact_request.h. NC-1b: the signing preimage the send path built
 * inline is dht_contact_request_signing_preimage there
 * (codec/contact_request_codec.h). */

/**
 * Send a contact request to recipient
 */
int dht_send_contact_request(
    const char *sender_fingerprint,
    const char *sender_name,
    const uint8_t *sender_dilithium_pubkey,
    const uint8_t *sender_dilithium_privkey,
    const char *recipient_fingerprint,
    const char *optional_message,
    const uint8_t *dht_salt)
{
    if (!sender_fingerprint || !sender_dilithium_pubkey ||
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
    request.timestamp = (uint64_t)time(NULL);
    request.expiry = request.timestamp + DHT_CONTACT_REQUEST_DEFAULT_TTL;

    /* Set version based on salt presence */
    if (dht_salt) {
        request.version = DHT_CONTACT_REQUEST_VERSION_SALT;
        memcpy(request.dht_salt, dht_salt, DHT_CONTACT_SALT_SIZE_CR);
        request.has_dht_salt = true;
    } else {
        request.version = DHT_CONTACT_REQUEST_VERSION;
        memset(request.dht_salt, 0, DHT_CONTACT_SALT_SIZE_CR);
        request.has_dht_salt = false;
    }

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

    /* Build data to sign (everything except signature) — NC-1b:
     * dht_contact_request_signing_preimage (codec/contact_request_codec.c),
     * the same builder dht_verify_contact_request checks against. */
    uint8_t *signed_data = NULL;
    size_t signed_data_len = 0;
    if (dht_contact_request_signing_preimage(&request, &signed_data, &signed_data_len) != 0) {
        return -1;
    }

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
        snprintf(&key_hex[i*2], sizeof(key_hex) - (i*2), "%02x", inbox_key[i]);
    }
    key_hex[32] = '\0';
    QGP_LOG_INFO(LOG_TAG, "Recipient inbox key (first 16 bytes): %s\n", key_hex);

    /* Generate value_id from sender's fingerprint (ensures unique per-sender) */
    uint64_t value_id = dht_fingerprint_to_value_id(sender_fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Publishing request to inbox with value_id=0x%llX\n", (unsigned long long)value_id);

    /* Publish to DHT via nodus_ops */
    int put_result = nodus_ops_put(
        inbox_key,
        64,
        serialized,
        serialized_len,
        DHT_CONTACT_REQUEST_DEFAULT_TTL,
        value_id
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
    const char *my_fingerprint,
    dht_contact_request_t **requests_out,
    size_t *count_out)
{
    if (!my_fingerprint || !requests_out || !count_out) {
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
        snprintf(&key_hex[i*2], sizeof(key_hex) - (i*2), "%02x", inbox_key[i]);
    }
    key_hex[32] = '\0';
    QGP_LOG_DEBUG(LOG_TAG, "Inbox key (first 16 bytes): %s\n", key_hex);

    /* Get all values at this key (from multiple requesters) via nodus_ops */
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t values_count = 0;

    int get_result = nodus_ops_get_all(inbox_key, 64, &values, &values_len, &values_count);

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
    const char *sender_fingerprint,
    const char *recipient_fingerprint)
{
    if (!sender_fingerprint || !recipient_fingerprint) {
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

    int put_result = nodus_ops_put(
        inbox_key,
        64,
        empty_data,
        1,
        1,  /* 1 second TTL - effectively immediate expiry */
        value_id
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
