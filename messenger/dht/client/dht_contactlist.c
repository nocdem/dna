/**
 * DHT Contact List Synchronization Implementation
 * Per-identity encrypted contact lists with DHT storage
 *
 * Uses nodus_ops layer for DHT storage operations.
 */

#include "dht_contactlist.h"
#include "codec/contactlist_codec.h"
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

#define LOG_TAG "DHT_CONTACTS"

#ifdef _WIN32
#include <winsock2.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#endif

// Network byte order functions (may not be available on all systems)
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * Generate base key string for contact list storage
 * Format: "identity:contactlist"
 * The nodus_ops layer handles hashing internally
 */
static int make_base_key(const char *identity, char *key_out, size_t key_out_size) {
    if (!identity || !key_out) {
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:contactlist", identity);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/* NC-1: serialize_to_json / hex_to_bytes / deserialize_from_json (the
 * contact-list JSON codec) moved verbatim to codec/contactlist_codec.c as
 * dht_contactlist_serialize_to_json / dht_contactlist_deserialize_from_json. */

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * Initialize DHT contact list subsystem
 */
int dht_contactlist_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Initialized\n");
    return 0;
}

/**
 * Cleanup DHT contact list subsystem
 */
void dht_contactlist_cleanup(void) {
    // Currently nothing to cleanup
    QGP_LOG_INFO(LOG_TAG, "Cleaned up\n");
}

/**
 * Publish contact list to DHT
 */
int dht_contactlist_publish(
    const char *identity,
    const char **contacts,
    size_t contact_count,
    const uint8_t **salts,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds)
{
    if (!identity || !kyber_pubkey || !kyber_privkey || !dilithium_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for publish\n");
        return -1;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = DHT_CONTACTLIST_DEFAULT_TTL;
    }

    uint64_t timestamp = (uint64_t)time(NULL);
    uint64_t expiry = timestamp + ttl_seconds;

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu contacts for '%s' (TTL=%u)\n",
           contact_count, identity, ttl_seconds);

    // Step 1: Serialize to JSON (v2 with salt objects)
    char *json_str = dht_contactlist_serialize_to_json(identity, contacts, salts, contact_count, timestamp);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize to JSON\n");
        return -1;
    }

    size_t json_len = strlen(json_str);
    QGP_LOG_INFO(LOG_TAG, "JSON length: %zu bytes\n", json_len);

    // Step 2: Sign JSON with Dilithium5
    uint8_t signature[DHT_CONTACTLIST_DILITHIUM_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (qgp_dsa87_sign(signature, &sig_len, (const uint8_t*)json_str, json_len, dilithium_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign JSON\n");
        free(json_str);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Signature length: %zu bytes\n", sig_len);

    // Step 3: Encrypt JSON with Kyber1024 (self-encryption)
    // For self-encryption: user is both sender (signs) and recipient (encrypts for self)
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context\n");
        free(json_str);
        return -1;
    }

    uint8_t *encrypted_data = NULL;
    size_t encrypted_len = 0;

    // Self-encryption: encrypt with own public key, sign with own private key
    uint64_t sync_timestamp = (uint64_t)time(NULL);
    dna_error_t enc_result = dna_encrypt_message_raw(
        dna_ctx,
        (const uint8_t*)json_str,
        json_len,
        kyber_pubkey,           // recipient_enc_pubkey (self)
        dilithium_pubkey,       // sender_sign_pubkey (self)
        dilithium_privkey,      // sender_sign_privkey (self)
        sync_timestamp,         // v0.08: contact list sync timestamp
        &encrypted_data,        // output ciphertext (allocated by function)
        &encrypted_len          // output length
    );

    dna_context_free(dna_ctx);
    free(json_str);

    if (enc_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt JSON: %s\n", dna_error_string(enc_result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Encrypted length: %zu bytes\n", encrypted_len);

    // Step 4: Build binary blob
    // Format: [magic][version][timestamp][expiry][json_len][encrypted_json][sig_len][signature]
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blob\n");
        free(encrypted_data);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic = htonl(DHT_CONTACTLIST_MAGIC);
    memcpy(blob + offset, &magic, 4);
    offset += 4;

    // Version
    blob[offset++] = DHT_CONTACTLIST_VERSION;

    // Timestamp (network byte order)
    uint64_t ts_net = htonll(timestamp);
    memcpy(blob + offset, &ts_net, 8);
    offset += 8;

    // Expiry (network byte order)
    uint64_t exp_net = htonll(expiry);
    memcpy(blob + offset, &exp_net, 8);
    offset += 8;

    // Encrypted JSON length
    uint32_t json_len_net = htonl((uint32_t)encrypted_len);
    memcpy(blob + offset, &json_len_net, 4);
    offset += 4;

    // Encrypted JSON data
    memcpy(blob + offset, encrypted_data, encrypted_len);
    offset += encrypted_len;

    // Signature length
    uint32_t sig_len_net = htonl((uint32_t)sig_len);
    memcpy(blob + offset, &sig_len_net, 4);
    offset += 4;

    // Signature
    memcpy(blob + offset, signature, sig_len);

    free(encrypted_data);

    QGP_LOG_INFO(LOG_TAG, "Total blob size: %zu bytes\n", blob_size);

    // Step 5: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        free(blob);
        return -1;
    }

    // Step 6: Store in DHT using nodus_ops layer
    int result = nodus_ops_put_str_exclusive(base_key, blob, blob_size, nodus_ops_value_id());
    free(blob);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store in DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published contact list to DHT\n");
    return 0;
}

/**
 * Fetch contact list from DHT
 */
int dht_contactlist_fetch(
    const char *identity,
    char ***contacts_out,
    size_t *count_out,
    uint8_t ***salts_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey)
{
    if (!identity || !contacts_out || !count_out || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching contact list for '%s'\n", identity);

    // Step 1: Generate base key for chunked storage
    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    // Step 2: Fetch from DHT using nodus_ops layer
    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = nodus_ops_get_str(base_key, &blob, &blob_size);
    if (result != 0 || !blob) {
        QGP_LOG_INFO(LOG_TAG, "Contact list not found in DHT\n");
        return -2;  // Not found
    }

    QGP_LOG_INFO(LOG_TAG, "Retrieved blob: %zu bytes\n", blob_size);

    // Step 3: Parse blob header
    if (blob_size < 4 + 1 + 8 + 8 + 4 + 4) {
        QGP_LOG_ERROR(LOG_TAG, "Blob too small\n");
        free(blob);
        return -1;
    }

    size_t offset = 0;

    // Magic
    uint32_t magic;
    memcpy(&magic, blob + offset, 4);
    magic = ntohl(magic);
    offset += 4;

    if (magic != DHT_CONTACTLIST_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X\n", magic);
        free(blob);
        return -1;
    }

    // Version (accept v1 and v2)
    uint8_t version = blob[offset++];
    if (version < 1 || version > DHT_CONTACTLIST_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %d\n", version);
        free(blob);
        return -1;
    }

    // Timestamp
    uint64_t timestamp;
    memcpy(&timestamp, blob + offset, 8);
    timestamp = ntohll(timestamp);
    offset += 8;

    // Expiry
    uint64_t expiry;
    memcpy(&expiry, blob + offset, 8);
    expiry = ntohll(expiry);
    offset += 8;

    // Embedded expiry is informational only: DHT storage is permanent
    // (EXCLUSIVE, ttl=0), so a stale expiry must not block seed-phrase restore.
    uint64_t now = (uint64_t)time(NULL);
    if (expiry < now) {
        QGP_LOG_INFO(LOG_TAG, "Contact list past embedded expiry (expiry=%lu, now=%lu), accepting anyway\n",
                     (unsigned long)expiry, (unsigned long)now);
    }

    // Encrypted JSON length
    uint32_t encrypted_len;
    memcpy(&encrypted_len, blob + offset, 4);
    encrypted_len = ntohl(encrypted_len);
    offset += 4;

    // Remaining-length form: "offset + encrypted_len + 4 > blob_size" wraps
    // with a 32-bit size_t (wasm32) for a large wire encrypted_len and passes
    // (BUGS.md, NC-5 fuzz, 2026-09-30). offset (25) + 4 <= blob_size (>= 29,
    // checked above), so the subtraction cannot underflow.
    if (encrypted_len > blob_size - offset - 4) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted length\n");
        free(blob);
        return -1;
    }

    uint8_t *encrypted_data = blob + offset;
    offset += encrypted_len;

    // Signature length
    uint32_t sig_len;
    memcpy(&sig_len, blob + offset, 4);
    sig_len = ntohl(sig_len);
    offset += 4;

    // offset <= blob_size (encrypted_len check above)
    if (sig_len != blob_size - offset) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature length\n");
        free(blob);
        return -1;
    }

    // Note: signature at (blob + offset) is validated during decryption

    QGP_LOG_INFO(LOG_TAG, "Parsed header: timestamp=%lu, expiry=%lu, encrypted_len=%u, sig_len=%u\n",
           (unsigned long)timestamp, (unsigned long)expiry, encrypted_len, sig_len);

    // Step 4: Decrypt JSON
    dna_context_t *dna_ctx = dna_context_new();
    if (!dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context\n");
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

    // Decrypt with own private key (self-decryption)
    dna_error_t dec_result = dna_decrypt_message_raw(
        dna_ctx,
        encrypted_data,
        encrypted_len,
        kyber_privkey,              // recipient_enc_privkey (self)
        &decrypted_data,            // output plaintext (allocated by function)
        &decrypted_len,             // output length
        &sender_pubkey_out,         // v0.07: sender's fingerprint (64 bytes)
        &sender_pubkey_len_out,     // sender fingerprint length
        &signature_out,             // signature bytes (from v0.07 message)
        &signature_out_len,         // signature length
        &sender_timestamp           // v0.08: sender's timestamp
    );

    dna_context_free(dna_ctx);

    if (dec_result != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt JSON: %s\n", dna_error_string(dec_result));
        free(blob);
        if (signature_out) free(signature_out);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Decrypted JSON: %zu bytes\n", decrypted_len);

    // Null-terminate for JSON parsing
    char *json_str = malloc(decrypted_len + 1);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate JSON buffer\n");
        free(decrypted_data);
        free(sender_pubkey_out);
        if (signature_out) free(signature_out);
        free(blob);
        return -1;
    }
    memcpy(json_str, decrypted_data, decrypted_len);
    json_str[decrypted_len] = '\0';

    // Step 5: Verify authorship (self-sealed record).
    // dna_decrypt_message_raw() returns the sender's 64-byte FINGERPRINT and does
    // NOT verify the signature (dna_api.c). The record must be sealed by the
    // user's own key: SHA3-512(dilithium_pubkey) == sender fingerprint AND the
    // Dilithium5 signature over the plaintext verifies under dilithium_pubkey.
    if (sender_pubkey_len_out != 64 || !signature_out || signature_out_len == 0 ||
        dna_verify_seal_authorship(decrypted_data, decrypted_len,
                                   signature_out, signature_out_len,
                                   dilithium_pubkey, DHT_CONTACTLIST_DILITHIUM_PUBKEY_SIZE,
                                   sender_pubkey_out, NULL) != DNA_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Contact list authorship check failed (not sealed by own key)\n");
        free(json_str);
        free(decrypted_data);
        free(sender_pubkey_out);
        if (signature_out) free(signature_out);
        free(blob);
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "Contact list authorship verified (sealed by own key)\n");

    free(decrypted_data);
    free(sender_pubkey_out);
    if (signature_out) free(signature_out);
    free(blob);

    // Step 6: Parse JSON (v2 extracts salts alongside fingerprints)
    uint64_t parsed_timestamp = 0;
    if (dht_contactlist_deserialize_from_json(json_str, contacts_out, count_out, salts_out, &parsed_timestamp) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON\n");
        free(json_str);
        return -1;
    }

    free(json_str);

    QGP_LOG_INFO(LOG_TAG, "Successfully fetched %zu contacts\n", *count_out);

    // Debug: Log each contact fingerprint
    if (*contacts_out && *count_out > 0) {
        for (size_t i = 0; i < *count_out; i++) {
            const char *fp = (*contacts_out)[i];
            size_t len = fp ? strlen(fp) : 0;
            if (len == 128) {
                QGP_LOG_DEBUG(LOG_TAG, "  Contact[%zu]: %.20s... (len=%zu)\n", i, fp, len);
            } else {
                QGP_LOG_WARN(LOG_TAG, "  Contact[%zu]: INVALID (len=%zu, first bytes: %02x %02x %02x %02x)\n",
                             i, len,
                             fp && len > 0 ? (unsigned char)fp[0] : 0,
                             fp && len > 1 ? (unsigned char)fp[1] : 0,
                             fp && len > 2 ? (unsigned char)fp[2] : 0,
                             fp && len > 3 ? (unsigned char)fp[3] : 0);
            }
        }
    }

    return 0;
}

/**
 * Free contacts array
 */
void dht_contactlist_free_contacts(char **contacts, size_t count) {
    if (!contacts) return;

    for (size_t i = 0; i < count; i++) {
        free(contacts[i]);
    }
    free(contacts);
}

/**
 * Free salt array from dht_contactlist_fetch
 */
void dht_contactlist_free_salts(uint8_t **salts, size_t count) {
    if (!salts) return;
    for (size_t i = 0; i < count; i++) {
        free(salts[i]);
    }
    free(salts);
}

/**
 * Free contact list structure
 */
void dht_contactlist_free(dht_contactlist_t *list) {
    if (!list) return;

    if (list->contacts) {
        dht_contactlist_free_contacts(list->contacts, list->contact_count);
    }
    free(list);
}

/**
 * Check if contact list exists in DHT
 */
bool dht_contactlist_exists(const char *identity) {
    if (!identity) {
        return false;
    }

    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        return false;
    }

    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = nodus_ops_get_str(base_key, &blob, &blob_size);
    if (result == 0 && blob) {
        free(blob);
        return true;
    }

    return false;
}

/**
 * Get contact list timestamp from DHT
 */
int dht_contactlist_get_timestamp(const char *identity, uint64_t *timestamp_out) {
    if (!identity || !timestamp_out) {
        return -1;
    }

    char base_key[512];
    if (make_base_key(identity, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    uint8_t *blob = NULL;
    size_t blob_size = 0;

    int result = nodus_ops_get_str(base_key, &blob, &blob_size);
    if (result != 0 || !blob) {
        return -2;  // Not found
    }

    // Parse just the timestamp from header
    if (blob_size < 4 + 1 + 8) {
        free(blob);
        return -1;
    }

    size_t offset = 4 + 1;  // Skip magic and version
    uint64_t timestamp;
    memcpy(&timestamp, blob + offset, 8);
    timestamp = ntohll(timestamp);

    *timestamp_out = timestamp;

    free(blob);
    return 0;
}
