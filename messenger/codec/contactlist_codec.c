/**
 * @file contactlist_codec.c
 * @brief Contact-list JSON codec — codec unit
 *
 * NC-1: moved verbatim out of dht/client/dht_contactlist.c. The only changes
 * are `static` dropped and the `dht_contactlist_` name prefix on
 * serialize_to_json / deserialize_from_json (see contactlist_codec.h);
 * hex_to_bytes stays static here (its only caller moved with it).
 *
 * NC-1b: the CLST blob build (dht_contactlist_publish "Step 4") and the
 * blob header parse (dht_contactlist_fetch "Step 3") moved here as
 * dht_contactlist_blob_encode / dht_contactlist_blob_parse; statement
 * sequences unchanged, plumbing listed at each function. The htonll/ntohll
 * macros and the platform block are copied from dht_contactlist.c, which
 * still needs its own copy (dht_contactlist_get_timestamp).
 * No network I/O, no database. blob_parse reads time(NULL) for one
 * informational log line only; no output depends on it.
 */

#include "codec/contactlist_codec.h"
#include "dht/client/dht_contactlist.h"
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

/**
 * Serialize contact list to JSON string (v2: contacts as objects with salt)
 */
char* dht_contactlist_serialize_to_json(const char *identity, const char **contacts,
                               const uint8_t **salts, size_t contact_count,
                               uint64_t timestamp) {
    if (!identity || (!contacts && contact_count > 0)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for JSON serialization\n");
        return NULL;
    }

    json_object *root = json_object_new_object();
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create JSON object\n");
        return NULL;
    }

    json_object_object_add(root, "identity", json_object_new_string(identity));
    json_object_object_add(root, "version", json_object_new_int(DHT_CONTACTLIST_VERSION));
    json_object_object_add(root, "timestamp", json_object_new_int64(timestamp));

    json_object *contacts_array = json_object_new_array();
    if (!contacts_array) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create contacts array\n");
        json_object_put(root);
        return NULL;
    }

    /* v2: Each contact is an object {"fp":"...", "salt":"hex64"} */
    for (size_t i = 0; i < contact_count; i++) {
        json_object *entry = json_object_new_object();
        if (!entry) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create contact object\n");
            json_object_put(root);
            return NULL;
        }

        json_object_object_add(entry, "fp",
                               json_object_new_string(contacts[i] ? contacts[i] : ""));

        /* Add salt as hex string if available */
        if (salts && salts[i]) {
            char salt_hex[65];
            for (int j = 0; j < 32; j++) {
                snprintf(salt_hex + (j * 2), 3, "%02x", salts[i][j]);
            }
            salt_hex[64] = '\0';
            json_object_object_add(entry, "salt", json_object_new_string(salt_hex));
        }

        QGP_LOG_DEBUG(LOG_TAG, "Serializing contact[%zu]: '%.20s...' (salt=%s)\n",
                      i, contacts[i] ? contacts[i] : "(null)",
                      (salts && salts[i]) ? "yes" : "no");

        json_object_array_add(contacts_array, entry);
    }

    json_object_object_add(root, "contacts", contacts_array);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    QGP_LOG_DEBUG(LOG_TAG, "Serialized JSON (first 200 chars): %.200s\n", json_str);
    char *result = strdup(json_str);

    json_object_put(root);
    return result;
}

/**
 * Parse hex string to bytes. Returns 0 on success, -1 on error.
 */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/**
 * Deserialize JSON string to contact list (v1 + v2 compatible)
 */
int dht_contactlist_deserialize_from_json(const char *json_str, char ***contacts_out,
                                 size_t *count_out, uint8_t ***salts_out,
                                 uint64_t *timestamp_out) {
    if (!json_str || !contacts_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for JSON deserialization\n");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Deserializing JSON (first 200 chars): %.200s\n", json_str);

    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON\n");
        return -1;
    }

    if (timestamp_out) {
        json_object *timestamp_obj = NULL;
        if (json_object_object_get_ex(root, "timestamp", &timestamp_obj)) {
            *timestamp_out = json_object_get_int64(timestamp_obj);
        } else {
            *timestamp_out = 0;
        }
    }

    /* Check JSON version to determine format */
    int json_version = 1;
    json_object *version_obj = NULL;
    if (json_object_object_get_ex(root, "version", &version_obj)) {
        json_version = json_object_get_int(version_obj);
    }

    json_object *contacts_array = NULL;
    if (!json_object_object_get_ex(root, "contacts", &contacts_array)) {
        QGP_LOG_ERROR(LOG_TAG, "No contacts array in JSON\n");
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(contacts_array);
    *count_out = count;

    if (count == 0) {
        *contacts_out = NULL;
        if (salts_out) *salts_out = NULL;
        json_object_put(root);
        return 0;
    }

    char **contacts = malloc(count * sizeof(char*));
    uint8_t **salts = salts_out ? calloc(count, sizeof(uint8_t*)) : NULL;
    if (!contacts || (salts_out && !salts)) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate contacts/salts arrays\n");
        free(contacts);
        free(salts);
        json_object_put(root);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        json_object *element = json_object_array_get_idx(contacts_array, i);

        if (json_version >= 2 && json_object_is_type(element, json_type_object)) {
            /* v2 format: {"fp": "...", "salt": "hex64"} */
            json_object *fp_obj = NULL;
            const char *fp_str = NULL;
            if (json_object_object_get_ex(element, "fp", &fp_obj)) {
                fp_str = json_object_get_string(fp_obj);
            }
            contacts[i] = strdup(fp_str ? fp_str : "");

            /* Extract salt if present */
            if (salts) {
                json_object *salt_obj = NULL;
                if (json_object_object_get_ex(element, "salt", &salt_obj)) {
                    const char *salt_hex = json_object_get_string(salt_obj);
                    if (salt_hex && strlen(salt_hex) == 64) {
                        salts[i] = malloc(DHT_CONTACTLIST_SALT_SIZE);
                        if (salts[i]) {
                            if (hex_to_bytes(salt_hex, salts[i], DHT_CONTACTLIST_SALT_SIZE) != 0) {
                                QGP_LOG_WARN(LOG_TAG, "Invalid salt hex at index %zu\n", i);
                                free(salts[i]);
                                salts[i] = NULL;
                            }
                        }
                    }
                }
            }
        } else {
            /* v1 format: plain string */
            const char *contact_str = json_object_get_string(element);
            if (!contact_str) {
                QGP_LOG_WARN(LOG_TAG, "Skipping NULL contact at index %zu\n", i);
                contacts[i] = strdup("");
            } else {
                contacts[i] = strdup(contact_str);
            }
            if (salts) salts[i] = NULL;
        }

        if (!contacts[i]) {
            for (size_t j = 0; j < i; j++) {
                free(contacts[j]);
                if (salts) free(salts[j]);
            }
            free(contacts);
            free(salts);
            json_object_put(root);
            return -1;
        }
    }

    *contacts_out = contacts;
    if (salts_out) *salts_out = salts;
    json_object_put(root);
    return 0;
}

/**
 * Build the CLST blob (dht_contactlist_publish "Step 4", moved by NC-1b).
 *
 * Plumbing added around the unchanged statements: the argument check; the
 * malloc-failure path returns -1 without `free(encrypted_data)` (the caller
 * still owns encrypted_data and frees it on every path, as before); the
 * blob is handed out through blob_out / blob_size_out.
 */
int dht_contactlist_blob_encode(uint64_t timestamp, uint64_t expiry,
                                const uint8_t *encrypted_data, size_t encrypted_len,
                                const uint8_t *signature, size_t sig_len,
                                uint8_t **blob_out, size_t *blob_size_out)
{
    if (!blob_out || !blob_size_out ||
        (!encrypted_data && encrypted_len > 0) || (!signature && sig_len > 0)) {
        return -1;
    }

    // Step 4: Build binary blob
    // Format: [magic][version][timestamp][expiry][json_len][encrypted_json][sig_len][signature]
    size_t blob_size = 4 + 1 + 8 + 8 + 4 + encrypted_len + 4 + sig_len;
    uint8_t *blob = malloc(blob_size);
    if (!blob) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate blob\n");
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

    *blob_out = blob;
    *blob_size_out = blob_size;
    return 0;
}

/**
 * Parse the CLST blob header (dht_contactlist_fetch "Step 3", moved by
 * NC-1b).
 *
 * Plumbing added around the unchanged statements: the argument check; every
 * `free(blob); return -1;` became `return -1;` (the caller owns and frees
 * the blob); `encrypted_data` is `const` (the blob is const here); the
 * results go out through the pointers at the end (timestamp_out /
 * expiry_out may be NULL). *encrypted_out points INTO `blob`.
 */
int dht_contactlist_blob_parse(const uint8_t *blob, size_t blob_size,
                               uint64_t *timestamp_out, uint64_t *expiry_out,
                               const uint8_t **encrypted_out,
                               uint32_t *encrypted_len_out)
{
    if (!blob || !encrypted_out || !encrypted_len_out) {
        return -1;
    }

    // Step 3: Parse blob header
    if (blob_size < 4 + 1 + 8 + 8 + 4 + 4) {
        QGP_LOG_ERROR(LOG_TAG, "Blob too small\n");
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
        return -1;
    }

    // Version (accept v1 and v2)
    uint8_t version = blob[offset++];
    if (version < 1 || version > DHT_CONTACTLIST_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %d\n", version);
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
        return -1;
    }

    const uint8_t *encrypted_data = blob + offset;
    offset += encrypted_len;

    // Signature length
    uint32_t sig_len;
    memcpy(&sig_len, blob + offset, 4);
    sig_len = ntohl(sig_len);
    offset += 4;

    // offset <= blob_size (encrypted_len check above)
    if (sig_len != blob_size - offset) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature length\n");
        return -1;
    }

    // Note: signature at (blob + offset) is validated during decryption

    QGP_LOG_INFO(LOG_TAG, "Parsed header: timestamp=%lu, expiry=%lu, encrypted_len=%u, sig_len=%u\n",
           (unsigned long)timestamp, (unsigned long)expiry, encrypted_len, sig_len);

    if (timestamp_out) *timestamp_out = timestamp;
    if (expiry_out) *expiry_out = expiry;
    *encrypted_out = encrypted_data;
    *encrypted_len_out = encrypted_len;
    return 0;
}
