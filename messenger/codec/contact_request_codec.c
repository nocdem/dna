/**
 * Contact request codec (key, value_id, serialize, deserialize, verify)
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * dht_generate_requests_inbox_key / dht_fingerprint_to_value_id /
 * dht_serialize_contact_request / dht_deserialize_contact_request /
 * dht_verify_contact_request moved verbatim out of
 * dht/shared/dht_contact_request.c (which also does the DHT I/O) so the
 * native library and the web thin core compile the same code. Declarations
 * stay in dht_contact_request.h. No network I/O, no database.
 *
 * dht_fingerprint_to_value_id (first 16 hex chars of the fingerprint, read
 * big-endian) is a DIFFERENT derivation from nodus_identity_value_id (first
 * 8 bytes of node_id, little-endian); the two are deliberately not merged
 * (design §6.4 F6).
 */

#include "dht/shared/dht_contact_request.h"
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
        (request->version >= DHT_CONTACT_REQUEST_VERSION_SALT ? DHT_CONTACT_SALT_SIZE_CR : 0) + /* v2: dht_salt */
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

    /* Write dht_salt (v2 only: 32 bytes) */
    if (request->version >= DHT_CONTACT_REQUEST_VERSION_SALT) {
        memcpy(ptr, request->dht_salt, DHT_CONTACT_SALT_SIZE_CR);
        ptr += DHT_CONTACT_SALT_SIZE_CR;
    }

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

    /* Read dht_salt (v2 only: 32 bytes) */
    if (request_out->version >= DHT_CONTACT_REQUEST_VERSION_SALT) {
        if (ptr + DHT_CONTACT_SALT_SIZE_CR > end) {
            QGP_LOG_ERROR(LOG_TAG, "Truncated salt data in v2 request\n");
            return -1;
        }
        memcpy(request_out->dht_salt, ptr, DHT_CONTACT_SALT_SIZE_CR);
        request_out->has_dht_salt = true;
        ptr += DHT_CONTACT_SALT_SIZE_CR;
    } else {
        memset(request_out->dht_salt, 0, DHT_CONTACT_SALT_SIZE_CR);
        request_out->has_dht_salt = false;
    }

    /* Read signature_len (network order). The v2 salt above can use up the
     * bytes the initial minimum-size check reserved for this field, so check
     * the 2 bytes are there (2026-09-30: a v2 request of length min+30/31
     * read 1-2 bytes past the buffer here, on every word size). */
    if ((size_t)(end - ptr) < sizeof(uint16_t)) {
        QGP_LOG_ERROR(LOG_TAG, "Truncated signature length in request\n");
        return -1;
    }
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

    /* Check version (accept v1 and v2) */
    if (request->version < DHT_CONTACT_REQUEST_VERSION ||
        request->version > DHT_CONTACT_REQUEST_VERSION_SALT) {
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
        256 +                                 /* message */
        (request->version >= DHT_CONTACT_REQUEST_VERSION_SALT ? DHT_CONTACT_SALT_SIZE_CR : 0); /* v2: salt */

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

    /* v2: include salt in signed data */
    if (request->version >= DHT_CONTACT_REQUEST_VERSION_SALT) {
        memcpy(ptr, request->dht_salt, DHT_CONTACT_SALT_SIZE_CR);
        ptr += DHT_CONTACT_SALT_SIZE_CR;
    }

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
