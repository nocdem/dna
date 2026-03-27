/**
 * DHT Follow List Synchronization Implementation
 * Per-identity encrypted follow list with DHT storage
 *
 * Uses nodus_ops layer for DHT storage operations.
 * Same encryption pattern as dht_contactlist but simpler (no salts).
 */

#include "dht_followlist.h"
#include "../shared/nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "../dna_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_FOLLOW"

#ifdef _WIN32
#include <winsock2.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#endif

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

/* Kyber/Dilithium sizes (NIST Category 5) */
#define KYBER_PUBKEY_SIZE    1568
#define KYBER_PRIVKEY_SIZE   3168
#define DILITHIUM_PUBKEY_SIZE  2592
#define DILITHIUM_PRIVKEY_SIZE 4896
#define DILITHIUM_SIG_SIZE     4627

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================ */

static int make_base_key(const char *identity, char *key_out, size_t key_out_size) {
    if (!identity || !key_out) return -1;
    int ret = snprintf(key_out, key_out_size, "%s:followlist", identity);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small");
        return -1;
    }
    return 0;
}

static char *serialize_to_json(const char *identity, const char **fingerprints,
                                size_t count, uint64_t timestamp) {
    if (!identity) return NULL;

    json_object *root = json_object_new_object();
    if (!root) return NULL;

    json_object_object_add(root, "identity", json_object_new_string(identity));
    json_object_object_add(root, "version", json_object_new_int(DHT_FOLLOWLIST_VERSION));
    json_object_object_add(root, "timestamp", json_object_new_int64((int64_t)timestamp));

    json_object *arr = json_object_new_array();
    if (!arr) {
        json_object_put(root);
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if (fingerprints[i]) {
            json_object_array_add(arr, json_object_new_string(fingerprints[i]));
        }
    }

    json_object_object_add(root, "following", arr);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);
    json_object_put(root);
    return result;
}

static int deserialize_from_json(const char *json_str, char ***fingerprints_out,
                                  size_t *count_out) {
    if (!json_str || !fingerprints_out || !count_out) return -1;

    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON");
        return -1;
    }

    json_object *arr = NULL;
    if (!json_object_object_get_ex(root, "following", &arr)) {
        QGP_LOG_ERROR(LOG_TAG, "No 'following' array in JSON");
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(arr);
    *count_out = count;

    if (count == 0) {
        *fingerprints_out = NULL;
        json_object_put(root);
        return 0;
    }

    char **fps = malloc(count * sizeof(char *));
    if (!fps) {
        json_object_put(root);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        json_object *elem = json_object_array_get_idx(arr, i);
        const char *fp_str = json_object_get_string(elem);
        fps[i] = strdup(fp_str ? fp_str : "");
        if (!fps[i]) {
            for (size_t j = 0; j < i; j++) free(fps[j]);
            free(fps);
            json_object_put(root);
            return -1;
        }
    }

    *fingerprints_out = fps;
    json_object_put(root);
    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int dht_followlist_publish(
    const char *identity,
    const char **fingerprints,
    size_t count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds)
{
    if (!identity || !kyber_pubkey || !kyber_privkey || !dilithium_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for publish");
        return -1;
    }

    if (ttl_seconds == 0) ttl_seconds = DHT_FOLLOWLIST_DEFAULT_TTL;

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + ttl_seconds;

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu followed users for %.16s... (TTL=%u)",
                 count, identity, ttl_seconds);

    /* Step 1: Serialize to JSON */
    char *json_str = serialize_to_json(identity, fingerprints, count, timestamp);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize to JSON");
        return -1;
    }

    size_t json_len = strlen(json_str);

    /* Step 2: Sign JSON with Dilithium5 */
    uint8_t signature[DILITHIUM_SIG_SIZE];
    size_t sig_len = sizeof(signature);

    if (qgp_dsa87_sign(signature, &sig_len, (const uint8_t *)json_str, json_len,
                        dilithium_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign JSON");
        free(json_str);
        return -1;
    }

    /* Step 3: Encrypt JSON with Kyber1024 (self-encryption) */
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        free(json_str);
        return -1;
    }

    uint8_t *encrypted_data = NULL;
    size_t encrypted_len = 0;

    dna_error_t enc_result = dna_encrypt_message_raw(
        dna_ctx,
        (const uint8_t *)json_str, json_len,
        kyber_pubkey,        /* recipient = self */
        dilithium_pubkey,    /* sender = self */
        dilithium_privkey,   /* sender sign key */
        timestamp,
        &encrypted_data, &encrypted_len
    );

    dna_context_free(dna_ctx);
    free(json_str);

    if (enc_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt JSON: %s", dna_error_string(enc_result));
        return -1;
    }

    /* Step 4: Build binary blob */
    /* [magic:4][version:1][timestamp:8][expiry:8][enc_len:4][enc_data][sig_len:4][signature] */
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        free(encrypted_data);
        return -1;
    }

    size_t offset = 0;

    uint32_t magic = htonl(DHT_FOLLOWLIST_MAGIC);
    memcpy(blob + offset, &magic, 4); offset += 4;

    blob[offset++] = DHT_FOLLOWLIST_VERSION;

    uint64_t ts_net = htonll(timestamp);
    memcpy(blob + offset, &ts_net, 8); offset += 8;

    uint64_t exp_net = htonll(expiry);
    memcpy(blob + offset, &exp_net, 8); offset += 8;

    uint32_t enc_len_net = htonl((uint32_t)encrypted_len);
    memcpy(blob + offset, &enc_len_net, 4); offset += 4;

    memcpy(blob + offset, encrypted_data, encrypted_len); offset += encrypted_len;

    uint32_t sig_len_net = htonl((uint32_t)sig_len);
    memcpy(blob + offset, &sig_len_net, 4); offset += 4;

    memcpy(blob + offset, signature, sig_len);

    free(encrypted_data);

    /* Step 5: Store in DHT */
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        free(blob);
        return -1;
    }

    int result = nodus_ops_put_str(base_key, blob, blob_size, (365 * 24 * 3600), nodus_ops_value_id());
    free(blob);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store follow list in DHT");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published follow list to DHT (%zu entries)", count);
    return 0;
}

int dht_followlist_fetch(
    const char *identity,
    char ***fingerprints_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey)
{
    if (!identity || !fingerprints_out || !count_out || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching follow list for %.16s...", identity);

    /* Step 1: Generate base key */
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) return -1;

    /* Step 2: Fetch from DHT */
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = nodus_ops_get_str(base_key, &blob, &blob_size);
    if (result != 0 || !blob) {
        QGP_LOG_INFO(LOG_TAG, "Follow list not found in DHT");
        return -2;
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved blob: %zu bytes", blob_size);

    /* Step 3: Parse blob header */
    /* Minimum size: magic(4) + version(1) + timestamp(8) + expiry(8) + enc_len(4) + sig_len(4) */
    if (blob_size < 29) {
        QGP_LOG_ERROR(LOG_TAG, "Blob too small: %zu", blob_size);
        free(blob);
        return -1;
    }

    size_t offset = 0;

    uint32_t magic;
    memcpy(&magic, blob + offset, 4); magic = ntohl(magic); offset += 4;

    if (magic != DHT_FOLLOWLIST_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X (expected 0x%08X)", magic, DHT_FOLLOWLIST_MAGIC);
        free(blob);
        return -1;
    }

    uint8_t version = blob[offset++];
    if (version < 1 || version > DHT_FOLLOWLIST_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %d", version);
        free(blob);
        return -1;
    }

    uint64_t timestamp;
    memcpy(&timestamp, blob + offset, 8); timestamp = ntohll(timestamp); offset += 8;

    uint64_t expiry;
    memcpy(&expiry, blob + offset, 8); expiry = ntohll(expiry); offset += 8;

    uint64_t now = (uint64_t)time(NULL);
    if (expiry < now) {
        QGP_LOG_INFO(LOG_TAG, "Follow list expired");
        free(blob);
        return -2;
    }

    uint32_t encrypted_len;
    memcpy(&encrypted_len, blob + offset, 4); encrypted_len = ntohl(encrypted_len); offset += 4;

    if (offset + encrypted_len + 4 > blob_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted length");
        free(blob);
        return -1;
    }

    uint8_t *encrypted_data = blob + offset;
    offset += encrypted_len;

    uint32_t sig_len;
    memcpy(&sig_len, blob + offset, 4); sig_len = ntohl(sig_len); offset += 4;

    if (offset + sig_len != blob_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature length");
        free(blob);
        return -1;
    }

    /* Step 4: Decrypt JSON */
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        free(blob);
        return -1;
    }

    uint8_t *decrypted_data = NULL;
    size_t decrypted_len = 0;
    uint8_t *sender_pubkey_out = NULL;
    size_t sender_pubkey_len_out = 0;
    uint8_t *signature_out = NULL;
    size_t signature_out_len = 0;
    uint64_t sender_timestamp = 0;

    dna_error_t dec_result = dna_decrypt_message_raw(
        dna_ctx,
        encrypted_data, encrypted_len,
        kyber_privkey,
        &decrypted_data, &decrypted_len,
        &sender_pubkey_out, &sender_pubkey_len_out,
        &signature_out, &signature_out_len,
        &sender_timestamp
    );

    dna_context_free(dna_ctx);

    if (dec_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt: %s", dna_error_string(dec_result));
        free(blob);
        if (signature_out) free(signature_out);
        return -1;
    }

    /* Step 5: Verify sender key matches (self-encryption check) */
    if (sender_pubkey_len_out == DILITHIUM_PUBKEY_SIZE) {
        if (memcmp(sender_pubkey_out, dilithium_pubkey, DILITHIUM_PUBKEY_SIZE) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Sender public key mismatch (not self-encrypted)");
            free(decrypted_data);
            free(sender_pubkey_out);
            if (signature_out) free(signature_out);
            free(blob);
            return -1;
        }
    }

    free(sender_pubkey_out);
    if (signature_out) free(signature_out);
    free(blob);

    /* Step 6: Parse JSON */
    char *json_str = malloc(decrypted_len + 1);
    if (!json_str) {
        free(decrypted_data);
        return -1;
    }
    memcpy(json_str, decrypted_data, decrypted_len);
    json_str[decrypted_len] = '\0';
    free(decrypted_data);

    if (deserialize_from_json(json_str, fingerprints_out, count_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON");
        free(json_str);
        return -1;
    }

    free(json_str);

    QGP_LOG_INFO(LOG_TAG, "Successfully fetched %zu followed users", *count_out);
    return 0;
}

void dht_followlist_free(char **fingerprints, size_t count) {
    if (!fingerprints) return;
    for (size_t i = 0; i < count; i++) {
        free(fingerprints[i]);
    }
    free(fingerprints);
}
