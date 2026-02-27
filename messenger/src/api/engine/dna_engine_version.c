/*
 * DNA Engine - Version Module
 *
 * Version string and DHT-based version publishing/checking.
 *
 * Functions:
 *   - dna_engine_get_version()        // Get local version string
 *   - dna_engine_publish_version()    // Publish version to DHT
 *   - dna_engine_check_version_dht()  // Check DHT for latest version
 */

#define DNA_ENGINE_VERSION_IMPL
#include "engine_includes.h"

/* ============================================================================
 * VERSION API
 * ============================================================================ */

const char* dna_engine_get_version(void) {
    return DNA_VERSION_STRING;
}

/* ============================================================================
 * VERSION CHECK API
 * ============================================================================ */

/* Well-known DHT key for version info */
#define VERSION_DHT_KEY_BASE "dna:system:version"
#define VERSION_VALUE_ID 1  /* Fixed value ID for replacement */

/**
 * Compare semantic version strings (returns: -1 if a<b, 0 if a==b, 1 if a>b)
 */
static int compare_versions(const char *a, const char *b) {
    if (!a || !b) return 0;

    int a_major = 0, a_minor = 0, a_patch = 0;
    int b_major = 0, b_minor = 0, b_patch = 0;

    sscanf(a, "%d.%d.%d", &a_major, &a_minor, &a_patch);
    sscanf(b, "%d.%d.%d", &b_major, &b_minor, &b_patch);

    if (a_major != b_major) return (a_major > b_major) ? 1 : -1;
    if (a_minor != b_minor) return (a_minor > b_minor) ? 1 : -1;
    if (a_patch != b_patch) return (a_patch > b_patch) ? 1 : -1;
    return 0;
}

int dna_engine_publish_version(
    dna_engine_t *engine,
    const char *library_version,
    const char *library_minimum,
    const char *app_version,
    const char *app_minimum,
    const char *nodus_version,
    const char *nodus_minimum
) {
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: engine is NULL");
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }

    if (engine->fingerprint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: no identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    if (!library_version || !app_version || !nodus_version) {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: version parameters required");
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "publish_version: DHT not available");
        return DNA_ENGINE_ERROR_NETWORK;
    }

    /* Build JSON payload */
    json_object *root = json_object_new_object();
    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "published_at", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(root, "publisher", json_object_new_string(engine->fingerprint));

    /* Library version */
    json_object *lib_obj = json_object_new_object();
    json_object_object_add(lib_obj, "current", json_object_new_string(library_version));
    json_object_object_add(lib_obj, "minimum", json_object_new_string(library_minimum ? library_minimum : library_version));
    json_object_object_add(root, "library", lib_obj);

    /* App version */
    json_object *app_obj = json_object_new_object();
    json_object_object_add(app_obj, "current", json_object_new_string(app_version));
    json_object_object_add(app_obj, "minimum", json_object_new_string(app_minimum ? app_minimum : app_version));
    json_object_object_add(root, "app", app_obj);

    /* Nodus version */
    json_object *nodus_obj = json_object_new_object();
    json_object_object_add(nodus_obj, "current", json_object_new_string(nodus_version));
    json_object_object_add(nodus_obj, "minimum", json_object_new_string(nodus_minimum ? nodus_minimum : nodus_version));
    json_object_object_add(root, "nodus", nodus_obj);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    size_t json_len = strlen(json_str);

    /* Compute DHT key: SHA3-512(VERSION_DHT_KEY_BASE) */
    uint8_t dht_key[64];
    qgp_sha3_512((const uint8_t *)VERSION_DHT_KEY_BASE, strlen(VERSION_DHT_KEY_BASE), dht_key);

    QGP_LOG_INFO(LOG_TAG, "Publishing version info to DHT: lib=%s app=%s nodus=%s",
                 library_version, app_version, nodus_version);

    /* Publish with signed permanent (first writer owns the key) */
    int result = dht_put_signed_permanent(
        dht_ctx,
        dht_key, sizeof(dht_key),
        (const uint8_t *)json_str, json_len,
        VERSION_VALUE_ID,
        "version_publish"
    );

    json_object_put(root);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish version to DHT: %d", result);
        return DNA_ENGINE_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "Version info published successfully");
    return 0;
}

int dna_engine_check_version_dht(
    dna_engine_t *engine,
    dna_version_check_result_t *result_out
) {
    (void)engine;  /* Engine not required for reading - uses singleton */

    if (!result_out) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }

    memset(result_out, 0, sizeof(dna_version_check_result_t));

    /* Get DHT context - can work without identity for reading */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "check_version: DHT not available");
        return DNA_ENGINE_ERROR_NETWORK;
    }

    /* Compute DHT key: SHA3-512(VERSION_DHT_KEY_BASE) */
    uint8_t dht_key[64];
    qgp_sha3_512((const uint8_t *)VERSION_DHT_KEY_BASE, strlen(VERSION_DHT_KEY_BASE), dht_key);

    /* Fetch from DHT */
    uint8_t *value = NULL;
    size_t value_len = 0;
    int fetch_result = dht_get(dht_ctx, dht_key, sizeof(dht_key), &value, &value_len);

    if (fetch_result != 0 || !value || value_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No version info found in DHT");
        return -2;  /* Not found */
    }

    /* Parse JSON */
    json_object *root = json_tokener_parse((const char *)value);
    free(value);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse version JSON from DHT");
        return -1;
    }

    /* Extract version info */
    json_object *pub_at_obj, *pub_obj, *lib_obj, *app_obj, *nodus_obj;

    if (json_object_object_get_ex(root, "published_at", &pub_at_obj)) {
        result_out->info.published_at = (uint64_t)json_object_get_int64(pub_at_obj);
    }

    if (json_object_object_get_ex(root, "publisher", &pub_obj)) {
        strncpy(result_out->info.publisher, json_object_get_string(pub_obj),
                sizeof(result_out->info.publisher) - 1);
    }

    /* Library versions */
    if (json_object_object_get_ex(root, "library", &lib_obj)) {
        json_object *cur_obj, *min_obj;
        if (json_object_object_get_ex(lib_obj, "current", &cur_obj)) {
            strncpy(result_out->info.library_current, json_object_get_string(cur_obj),
                    sizeof(result_out->info.library_current) - 1);
        }
        if (json_object_object_get_ex(lib_obj, "minimum", &min_obj)) {
            strncpy(result_out->info.library_minimum, json_object_get_string(min_obj),
                    sizeof(result_out->info.library_minimum) - 1);
        }
    }

    /* App versions */
    if (json_object_object_get_ex(root, "app", &app_obj)) {
        json_object *cur_obj, *min_obj;
        if (json_object_object_get_ex(app_obj, "current", &cur_obj)) {
            strncpy(result_out->info.app_current, json_object_get_string(cur_obj),
                    sizeof(result_out->info.app_current) - 1);
        }
        if (json_object_object_get_ex(app_obj, "minimum", &min_obj)) {
            strncpy(result_out->info.app_minimum, json_object_get_string(min_obj),
                    sizeof(result_out->info.app_minimum) - 1);
        }
    }

    /* Nodus versions */
    if (json_object_object_get_ex(root, "nodus", &nodus_obj)) {
        json_object *cur_obj, *min_obj;
        if (json_object_object_get_ex(nodus_obj, "current", &cur_obj)) {
            strncpy(result_out->info.nodus_current, json_object_get_string(cur_obj),
                    sizeof(result_out->info.nodus_current) - 1);
        }
        if (json_object_object_get_ex(nodus_obj, "minimum", &min_obj)) {
            strncpy(result_out->info.nodus_minimum, json_object_get_string(min_obj),
                    sizeof(result_out->info.nodus_minimum) - 1);
        }
    }

    json_object_put(root);

    /* Compare with local version (library) */
    const char *local_lib_version = DNA_VERSION_STRING;
    if (compare_versions(result_out->info.library_current, local_lib_version) > 0) {
        result_out->library_update_available = true;
    }

    /* App and nodus comparisons would need their versions passed in or queried differently */
    /* For now, caller can compare manually using the info struct */

    QGP_LOG_INFO(LOG_TAG, "Version check: lib=%s (local=%s) app=%s nodus=%s",
                 result_out->info.library_current, local_lib_version,
                 result_out->info.app_current, result_out->info.nodus_current);

    return 0;
}
