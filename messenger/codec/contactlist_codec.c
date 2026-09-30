/**
 * @file contactlist_codec.c
 * @brief Contact-list JSON codec — codec unit
 *
 * NC-1: moved verbatim out of dht/client/dht_contactlist.c. The only changes
 * are `static` dropped and the `dht_contactlist_` name prefix on
 * serialize_to_json / deserialize_from_json (see contactlist_codec.h);
 * hex_to_bytes stays static here (its only caller moved with it).
 * No network I/O, no database.
 */

#include "codec/contactlist_codec.h"
#include "dht/client/dht_contactlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_CONTACTS"

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
