/*
 * cellframe_tx_json.c - Cellframe Transaction JSON Builder
 *
 * Builds JSON transactions for submission to Cellframe RPC
 */

#include "cellframe_tx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// JSON transaction builder (opaque type for external use)
typedef struct {
    char *json;
    size_t size;
    size_t capacity;
    bool first_item;
} json_tx_builder_t;

json_tx_builder_t* json_tx_builder_new(void) {
    json_tx_builder_t *builder = calloc(1, sizeof(json_tx_builder_t));
    if (!builder) return NULL;

    builder->capacity = 4096;
    builder->json = malloc(builder->capacity);
    if (!builder->json) {
        free(builder);
        return NULL;
    }

    // Start JSON with items array (timestamp and datum_type added at finalize)
    builder->size = snprintf(builder->json, builder->capacity, "{\"items\":[");
    builder->first_item = true;

    return builder;
}

void json_tx_builder_free(json_tx_builder_t *builder) {
    if (builder) {
        free(builder->json);
        free(builder);
    }
}

static int json_append(json_tx_builder_t *builder, const char *str) {
    size_t len = strlen(str);
    if (builder->size + len + 10 >= builder->capacity) {
        size_t new_cap = builder->capacity * 2;
        char *new_json = realloc(builder->json, new_cap);
        if (!new_json) return -1;
        builder->json = new_json;
        builder->capacity = new_cap;
    }

    if (!builder->first_item) {
        builder->json[builder->size++] = ',';
    }
    builder->first_item = false;

    strcpy(builder->json + builder->size, str);
    builder->size += len;
    return 0;
}

int cellframe_tx_json_add_in(json_tx_builder_t *builder, const cellframe_hash_t *prev_hash, uint32_t prev_idx) {
    if (!builder || !prev_hash) return -1;

    // Convert hash to hex string (UPPERCASE to match Cellframe)
    char hash_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash_hex + i*2, "%02X", prev_hash->raw[i]);
    }
    hash_hex[64] = '\0';

    char item[256];
    snprintf(item, sizeof(item),
             "{\"type\":\"in\",\"prev_hash\":\"0x%s\",\"out_prev_idx\":%u}",
             hash_hex, prev_idx);

    return json_append(builder, item);
}

int cellframe_tx_json_add_out(json_tx_builder_t *builder, const char *addr_str,
                                const char *value_str, const char *token) {
    if (!builder || !addr_str || !value_str) return -1;

    // CRITICAL: Do NOT include token field in JSON
    // Cellframe RPC expects: {"type":"out","addr":"...","value":"..."}
    // NOT: {"type":"out","addr":"...","value":"...","token":"CELL"}
    char item[512];
    snprintf(item, sizeof(item),
             "{\"type\":\"out\",\"addr\":\"%s\",\"value\":\"%s\"}",
             addr_str, value_str);

    return json_append(builder, item);
}

int cellframe_tx_json_add_fee(json_tx_builder_t *builder, const char *fee_str) {
    if (!builder || !fee_str) return -1;

    char item[256];
    snprintf(item, sizeof(item),
             "{\"type\":\"out_cond\",\"ts_expires\":\"never\",\"value\":\"%s\","
             "\"service_id\":\"0x0000000000000000\",\"subtype\":\"fee\"}",
             fee_str);

    return json_append(builder, item);
}

char* cellframe_tx_json_finalize(json_tx_builder_t *builder) {
    if (!builder) return NULL;

    // Close items array, add ts_created and datum_type
    // CRITICAL: Cellframe uses "ts_created" not "timestamp"
    uint64_t ts = time(NULL);
    char suffix[128];
    snprintf(suffix, sizeof(suffix), "],\"ts_created\":%lu,\"datum_type\":\"tx\"}", ts);

    size_t suffix_len = strlen(suffix);
    if (builder->size + suffix_len + 10 >= builder->capacity) {
        size_t new_cap = builder->size + suffix_len + 100;
        char *new_json = realloc(builder->json, new_cap);
        if (!new_json) return NULL;
        builder->json = new_json;
        builder->capacity = new_cap;
    }

    strcpy(builder->json + builder->size, suffix);
    builder->size += suffix_len;

    char *result = builder->json;
    builder->json = NULL;  // Don't free in json_tx_builder_free
    return result;
}

// Helper: Base64 encode (URL-safe variant)
static char* base64_encode_urlsafe(const uint8_t *data, size_t len) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t b64_size = ((len + 2) / 3) * 4 + 1;
    char *b64 = malloc(b64_size);
    if (!b64) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t triple = (data[i] << 16) |
                          ((i + 1 < len ? data[i + 1] : 0) << 8) |
                          (i + 2 < len ? data[i + 2] : 0);

        b64[j++] = base64_chars[(triple >> 18) & 0x3F];
        b64[j++] = base64_chars[(triple >> 12) & 0x3F];
        b64[j++] = (i + 1 < len) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        b64[j++] = (i + 2 < len) ? base64_chars[triple & 0x3F] : '=';
    }
    b64[j] = '\0';
    return b64;
}

int cellframe_tx_json_add_sign(json_tx_builder_t *builder,
                                const uint8_t *pub_key, size_t pub_key_size,
                                const uint8_t *signature, size_t sig_size) {
    if (!builder || !pub_key || !signature || pub_key_size == 0 || sig_size == 0) {
        return -1;
    }

    // Base64 encode public key and signature
    char *pub_key_b64 = base64_encode_urlsafe(pub_key, pub_key_size);
    char *sig_b64 = base64_encode_urlsafe(signature, sig_size);

    if (!pub_key_b64 || !sig_b64) {
        free(pub_key_b64);
        free(sig_b64);
        return -1;
    }

    // Create signature JSON item matching Cellframe format
    char *item = malloc(strlen(pub_key_b64) + strlen(sig_b64) + 512);
    if (!item) {
        free(pub_key_b64);
        free(sig_b64);
        return -1;
    }

    snprintf(item, strlen(pub_key_b64) + strlen(sig_b64) + 512,
             "{\"type\":\"sign\",\"sig_type\":\"sig_dil\","
             "\"pub_key_size\":%zu,\"sig_size\":%zu,\"hash_type\":1,"
             "\"pub_key_b64\":\"%s\",\"sig_b64\":\"%s\"}",
             pub_key_size, sig_size, pub_key_b64, sig_b64);

    int ret = json_append(builder, item);

    free(pub_key_b64);
    free(sig_b64);
    free(item);

    return ret;
}

// Public API for building JSON transaction
int cellframe_build_json_tx(const cellframe_utxo_list_t *utxos,
                              const char *recipient_addr,
                              const char *amount,
                              const char *network_fee,
                              const char *network_fee_addr,
                              const char *validator_fee,
                              const char *change_addr,
                              const char *change_amount,
                              const char *token,
                              char **json_out) {
    if (!utxos || !recipient_addr || !amount || !token || !json_out) {
        return -1;
    }

    json_tx_builder_t *builder = json_tx_builder_new();
    if (!builder) return -1;

    // Add IN items
    for (size_t i = 0; i < utxos->count; i++) {
        if (cellframe_tx_json_add_in(builder, &utxos->utxos[i].prev_hash,
                                       utxos->utxos[i].out_prev_idx) != 0) {
            json_tx_builder_free(builder);
            return -1;
        }
    }

    // Add OUT item for recipient
    if (cellframe_tx_json_add_out(builder, recipient_addr, amount, token) != 0) {
        json_tx_builder_free(builder);
        return -1;
    }

    // Add network fee if provided
    if (network_fee && network_fee_addr) {
        if (cellframe_tx_json_add_out(builder, network_fee_addr, network_fee, token) != 0) {
            json_tx_builder_free(builder);
            return -1;
        }
    }

    // Add validator fee
    if (validator_fee) {
        if (cellframe_tx_json_add_fee(builder, validator_fee) != 0) {
            json_tx_builder_free(builder);
            return -1;
        }
    }

    // Add change output if provided
    if (change_addr && change_amount) {
        if (cellframe_tx_json_add_out(builder, change_addr, change_amount, token) != 0) {
            json_tx_builder_free(builder);
            return -1;
        }
    }

    *json_out = cellframe_tx_json_finalize(builder);
    json_tx_builder_free(builder);

    return *json_out ? 0 : -1;
}
