/*
 * cellframe_tx.c - Cellframe Transaction Binary Serialization
 */

#include "cellframe_tx.h"
#include "crypto/dilithium/api.h"       // Dilithium3
#include "crypto/dilithium2/api.h"      // Dilithium2 (standard)
#include "crypto/dilithium_mode0/api.h" // MODE_0 (Cellframe K=3, L=2)
#include "crypto/cellframe_dilithium/cellframe_dilithium_api.h" // Cellframe Dilithium MODE_1
#include "crypto/cellframe_dilithium/dap_crypto_common.h"  // SHA3_256
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <json-c/json.h>

// Initial capacity for transaction builder
#define TX_BUILDER_INITIAL_CAPACITY 4096

cellframe_tx_builder_t* cellframe_tx_builder_new(void) {
    cellframe_tx_builder_t *builder = calloc(1, sizeof(cellframe_tx_builder_t));
    if (!builder) {
        return NULL;
    }

    builder->capacity = TX_BUILDER_INITIAL_CAPACITY;
    builder->data = malloc(builder->capacity);
    if (!builder->data) {
        free(builder);
        return NULL;
    }

    // Initialize with transaction header
    cellframe_tx_header_t header = {0};
    header.ts_created = (uint64_t)time(NULL);
    header.tx_items_size = 0;

    memcpy(builder->data, &header, sizeof(header));
    builder->size = sizeof(header);
    builder->items_size = 0;

    return builder;
}

void cellframe_tx_builder_free(cellframe_tx_builder_t *builder) {
    if (!builder) {
        return;
    }
    if (builder->data) {
        free(builder->data);
    }
    free(builder);
}

// Helper: Ensure builder has enough capacity
static int ensure_capacity(cellframe_tx_builder_t *builder, size_t additional) {
    size_t required = builder->size + additional;
    if (required <= builder->capacity) {
        return 0;
    }

    size_t new_capacity = builder->capacity * 2;
    while (new_capacity < required) {
        new_capacity *= 2;
    }

    uint8_t *new_data = realloc(builder->data, new_capacity);
    if (!new_data) {
        return -1;
    }

    builder->data = new_data;
    builder->capacity = new_capacity;
    return 0;
}

// Helper: Append data to builder
static int append_data(cellframe_tx_builder_t *builder, const void *data, size_t size) {
    if (ensure_capacity(builder, size) != 0) {
        return -1;
    }

    // DEBUG: Print what we're about to append
    fprintf(stderr, "[APPEND] Appending %zu bytes at offset %zu\n", size, builder->size);
    fprintf(stderr, "[APPEND] First 32 bytes of data:\n");
    const uint8_t *bytes = (const uint8_t*)data;
    for (size_t i = 0; i < 32 && i < size; i++) {
        fprintf(stderr, "%02x ", bytes[i]);
    }
    fprintf(stderr, "\n");

    memcpy(builder->data + builder->size, data, size);
    builder->size += size;
    builder->items_size += size;

    // DEBUG: Print what was actually written
    fprintf(stderr, "[APPEND] After append, checking transaction at offset %zu:\n", builder->size - size);
    const uint8_t *tx_bytes = builder->data + (builder->size - size);
    for (size_t i = 0; i < 32 && i < size; i++) {
        fprintf(stderr, "%02x ", tx_bytes[i]);
    }
    fprintf(stderr, "\n\n");

    // Update tx_items_size in header
    cellframe_tx_header_t *header = (cellframe_tx_header_t *)builder->data;
    header->tx_items_size = builder->items_size;

    return 0;
}

int cellframe_tx_add_in(cellframe_tx_builder_t *builder, const cellframe_hash_t *prev_hash, uint32_t prev_idx) {
    if (!builder || !prev_hash) {
        return -1;
    }

    cellframe_tx_in_t item = {0};
    item.type = TX_ITEM_TYPE_IN;
    memcpy(&item.tx_prev_hash, prev_hash, sizeof(cellframe_hash_t));
    item.tx_out_prev_idx = prev_idx;

    return append_data(builder, &item, sizeof(item));
}

int cellframe_tx_add_out_ext(cellframe_tx_builder_t *builder, const cellframe_addr_t *addr,
                              const char *value_str, const char *token) {
    if (!builder || !addr || !value_str || !token) {
        return -1;
    }

    // CRITICAL: Use TX_ITEM_TYPE_OUT (0x12) - matches what Cellframe RPC creates when parsing signed JSON
    // RPC parses "type":"out" from signed JSON and creates dap_chain_tx_out_t (NO token field!)
    cellframe_tx_out_t item = {0};
    item.header.type = TX_ITEM_TYPE_OUT;

    // Parse value
    if (cellframe_uint256_from_str(value_str, &item.header.value) != 0) {
        return -1;
    }

    // Copy address
    memcpy(&item.addr, addr, sizeof(cellframe_addr_t));

    // DEBUG: Print hex dump of OUT item
    fprintf(stderr, "[DEBUG] OUT item (%zu bytes):\n", sizeof(item));
    fprintf(stderr, "  type=0x%02x\n", item.header.type);
    fprintf(stderr, "  value=%lu (0x%016lx)\n", item.header.value.lo[0], item.header.value.lo[0]);

    // Hex dump ALL bytes
    uint8_t *bytes = (uint8_t*)&item;
    fprintf(stderr, "  hex (%zu bytes):\n", sizeof(item));
    for (size_t i = 0; i < sizeof(item); i++) {
        fprintf(stderr, "%02x ", bytes[i]);
        if ((i+1) % 32 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    return append_data(builder, &item, sizeof(item));
}

int cellframe_tx_add_fee(cellframe_tx_builder_t *builder, const char *fee_str) {
    if (!builder || !fee_str) {
        return -1;
    }

    cellframe_tx_out_cond_t item = {0};
    item.item_type = TX_ITEM_TYPE_OUT_COND;
    item.subtype = TX_OUT_COND_SUBTYPE_FEE;

    // Parse fee value
    if (cellframe_uint256_from_str(fee_str, &item.value) != 0) {
        return -1;
    }

    // Fee never expires
    item.ts_expires = 0;

    // Service UID for fee is 0
    item.srv_uid = 0;

    // No TSD data for simple fee
    item.tsd_size = 0;

    return append_data(builder, &item, sizeof(item));
}

const uint8_t* cellframe_tx_get_data(cellframe_tx_builder_t *builder, size_t *size_out) {
    if (!builder || !size_out) {
        return NULL;
    }

    *size_out = builder->size;
    return builder->data;
}

/**
 * Sign transaction data with Dilithium and return RAW signature
 * (NOT in dap_sign_t format - use cellframe_build_dap_sign_t for that)
 *
 * INTERNAL FUNCTION - use cellframe_build_dap_sign_t instead
 */
static int cellframe_tx_sign_raw(const uint8_t *tx_data, size_t tx_size,
                                  const uint8_t *priv_key, size_t priv_key_size,
                                  uint8_t **sig_out, size_t *sig_size_out,
                                  int *mode_out) {
    if (!tx_data || !priv_key || !sig_out || !sig_size_out) {
        return -1;
    }

    // Cellframe wallet format: private key has 12-byte serialization header
    // MODE_1: 2800 bytes secret -> 2812 bytes with header (Cellframe Dilithium)
    const uint8_t *actual_priv_key = priv_key;
    size_t actual_priv_key_size = priv_key_size;

    if (priv_key_size == 2812) {
        // Cellframe MODE_1 format - skip 12 byte header
        actual_priv_key = priv_key + 12;
        actual_priv_key_size = 2800;
        fprintf(stderr, "[TX] Detected Cellframe MODE_1 format, stripping 12 byte header\n");
    } else if (priv_key_size == 2800) {
        // Raw MODE_1 (no header)
        fprintf(stderr, "[TX] Raw MODE_1 key (no header)\n");
    } else {
        fprintf(stderr, "[TX] Unsupported private key size: %zu (expected 2812 or 2800 for MODE_1)\n", priv_key_size);
        return -1;
    }

    // Allocate signature buffer for MODE_1 (DETACHED signature size = 2044 bytes)
    size_t sig_len = pqcrystals_cellframe_dilithium_BYTES;  // 2044 bytes

    uint8_t *signature = malloc(sig_len + 100);  // Extra space for safety
    if (!signature) {
        return -1;
    }

    // Hash transaction data before signing (Cellframe standard: hash_type=0x01)
    uint8_t tx_hash[32];  // SHA3-256 produces 32 bytes

    // DEBUG: Save transaction bytes to file for analysis
    FILE *debug_fp = fopen("/tmp/tx_signing_bytes.bin", "wb");
    if (debug_fp) {
        fwrite(tx_data, 1, tx_size, debug_fp);
        fclose(debug_fp);
        fprintf(stderr, "[TX_DEBUG] Saved transaction bytes to /tmp/tx_signing_bytes.bin\n");
    }

    SHA3_256(tx_hash, tx_data, tx_size);
    fprintf(stderr, "[TX] Transaction hash (SHA3-256): ");
    for (int i = 0; i < 32; i++) {
        fprintf(stderr, "%02x", tx_hash[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "[TX] Transaction size being hashed: %zu bytes\n", tx_size);

    // Sign the hash with Cellframe MODE_1 Dilithium
    size_t actual_sig_len = sig_len + 100;
    fprintf(stderr, "[TX] Signing hash with Cellframe MODE_1\n");
    int ret = pqcrystals_cellframe_dilithium_signature(
        signature, &actual_sig_len,
        tx_hash, 32,  // Sign the 32-byte hash
        NULL, 0,  // No context
        actual_priv_key
    );

    if (ret != 0) {
        fprintf(stderr, "[TX] Signature failed: %d\n", ret);
        free(signature);
        return -1;
    }

    fprintf(stderr, "[TX] Raw signature generated: %zu bytes\n", actual_sig_len);
    fprintf(stderr, "[TX] Signature (first 32 bytes): ");
    for (int i = 0; i < 32 && i < (int)actual_sig_len; i++) {
        fprintf(stderr, "%02x", signature[i]);
    }
    fprintf(stderr, "\n");

    // CRITICAL: Cellframe expects SERIALIZED signature with 20-byte wrapper!
    // Structure: [8-byte length][4-byte type][8-byte sig_len][ATTACHED signature]
    // ATTACHED signature: 2076 bytes (2044-byte sig + 32-byte message)
    // Total: 20 + 2076 = 2096 bytes

    if (actual_sig_len != (sig_len + 32)) {
        fprintf(stderr, "[TX] ERROR: Expected ATTACHED signature of %zu bytes, got %zu\n",
                sig_len + 32, actual_sig_len);
        free(signature);
        return -1;
    }

    fprintf(stderr, "[TX] Signature is ATTACHED format: %zu bytes (2044 + 32)\n", actual_sig_len);

    // Build serialized signature with 20-byte wrapper
    size_t serialized_size = 20 + actual_sig_len;  // 20 + 2076 = 2096
    uint8_t *serialized_sig = malloc(serialized_size);
    if (!serialized_sig) {
        free(signature);
        return -1;
    }

    // Build 20-byte header
    // CRITICAL: Signature serialization uses type=1, NOT SIG_TYPE_DILITHIUM (0x0102)!
    uint64_t total_len = serialized_size;         // 2096
    uint32_t sig_type = 1;                        // Serialization type (NOT dap_sign_t type!)
    uint64_t attached_sig_len = actual_sig_len;   // 2076

    size_t offset = 0;
    memcpy(serialized_sig + offset, &total_len, 8); offset += 8;
    memcpy(serialized_sig + offset, &sig_type, 4); offset += 4;
    memcpy(serialized_sig + offset, &attached_sig_len, 8); offset += 8;

    // Append ATTACHED signature (2076 bytes)
    memcpy(serialized_sig + offset, signature, actual_sig_len);
    free(signature);

    fprintf(stderr, "[TX] Serialized signature: %zu bytes (20-byte header + %zu-byte ATTACHED sig)\n",
            serialized_size, actual_sig_len);

    *sig_out = serialized_sig;
    *sig_size_out = serialized_size;  // 2096
    if (mode_out) *mode_out = 1;  // Always MODE_1

    return 0;
}

/**
 * Build dap_sign_t structure from public key and signature
 *
 * This builds the structure that Cellframe expects:
 * - header (14 bytes): type, hash_type, padding, sign_size, sign_pkey_size
 * - public key (1184 bytes for MODE_1)
 * - signature (2044 bytes for MODE_1)
 *
 * Total: 3242 bytes for MODE_1
 * This ENTIRE structure must be BASE64-encoded for JSON transactions.
 */
int cellframe_build_dap_sign_t(const uint8_t *pub_key, size_t pub_key_size,
                                 const uint8_t *signature, size_t sig_size,
                                 uint8_t **dap_sign_out, size_t *dap_sign_size_out) {
    if (!pub_key || !signature || !dap_sign_out || !dap_sign_size_out) {
        return -1;
    }

    fprintf(stderr, "[DAP_SIGN] Building dap_sign_t from:\n");
    fprintf(stderr, "[DAP_SIGN]   pub_key_size=%zu, sig_size=%zu\n", pub_key_size, sig_size);

    // CRITICAL: Keep the serialized public key WITH its 12-byte header!
    // Cellframe expects the FULL serialized key (1196 bytes for MODE_1)
    const uint8_t *actual_pub_key = pub_key;
    size_t actual_pub_key_size = pub_key_size;

    fprintf(stderr, "[DAP_SIGN] Using full serialized public key: %zu bytes (WITH header)\n", actual_pub_key_size);

    // Calculate total dap_sign_t size
    // 14 bytes header + pub_key_size + sig_size
    size_t total_size = 14 + actual_pub_key_size + sig_size;

    uint8_t *dap_sign = malloc(total_size);
    if (!dap_sign) {
        return -1;
    }

    // Build header (14 bytes)
    uint32_t sig_type = SIG_TYPE_DILITHIUM;  // 0x0102
    uint8_t hash_type = 0x01;                 // SHA3-256
    uint8_t padding = 0x00;
    uint32_t sign_size_field = (uint32_t)sig_size;
    uint32_t sign_pkey_size_field = (uint32_t)actual_pub_key_size;

    size_t offset = 0;
    memcpy(dap_sign + offset, &sig_type, 4); offset += 4;
    memcpy(dap_sign + offset, &hash_type, 1); offset += 1;
    memcpy(dap_sign + offset, &padding, 1); offset += 1;
    memcpy(dap_sign + offset, &sign_size_field, 4); offset += 4;
    memcpy(dap_sign + offset, &sign_pkey_size_field, 4); offset += 4;

    // Append public key (WITHOUT 12-byte header)
    memcpy(dap_sign + offset, actual_pub_key, actual_pub_key_size); offset += actual_pub_key_size;

    // Append signature
    memcpy(dap_sign + offset, signature, sig_size); offset += sig_size;

    fprintf(stderr, "[DAP_SIGN] Built dap_sign_t: %zu bytes total\n", total_size);
    fprintf(stderr, "[DAP_SIGN]   header: 14 bytes\n");
    fprintf(stderr, "[DAP_SIGN]   pubkey: %zu bytes\n", actual_pub_key_size);
    fprintf(stderr, "[DAP_SIGN]   signature: %zu bytes\n", sig_size);

    *dap_sign_out = dap_sign;
    *dap_sign_size_out = total_size;

    return 0;
}

/**
 * Sign transaction and return dap_sign_t structure
 *
 * This is the main signing function that combines:
 * 1. SHA3-256 hashing of transaction
 * 2. Dilithium signing of the hash
 * 3. Building proper dap_sign_t structure
 */
int cellframe_tx_sign(const uint8_t *tx_data, size_t tx_size,
                      const uint8_t *priv_key, size_t priv_key_size,
                      uint8_t **sig_out, size_t *sig_size_out) {
    fprintf(stderr, "[TX_SIGN] cellframe_tx_sign called with tx_size=%zu, priv_key_size=%zu\n",
            tx_size, priv_key_size);

    // Sign transaction to get raw signature
    uint8_t *raw_sig = NULL;
    size_t raw_sig_size = 0;
    int mode = -1;

    if (cellframe_tx_sign_raw(tx_data, tx_size, priv_key, priv_key_size,
                                &raw_sig, &raw_sig_size, &mode) != 0) {
        fprintf(stderr, "[TX_SIGN] cellframe_tx_sign_raw FAILED\n");
        return -1;
    }

    fprintf(stderr, "[TX_SIGN] cellframe_tx_sign_raw returned %zu bytes\n", raw_sig_size);

    // Note: We can't build dap_sign_t here because we don't have the public key
    // The caller (cellframe_tx_add_signature) will need to call cellframe_build_dap_sign_t

    *sig_out = raw_sig;
    *sig_size_out = raw_sig_size;

    return 0;
}

// cellframe_addr_from_str is now implemented in cellframe_addr.c

int cellframe_uint256_from_str(const char *value_str, uint256_t *value_out) {
    if (!value_str || !value_out) {
        return -1;
    }

    memset(value_out, 0, sizeof(uint256_t));

    // Parse decimal string to uint256_t
    // Cellframe uses datoshi units (token * 10^18)
    // For simple implementation, parse as double and convert

    double val = 0.0;
    if (sscanf(value_str, "%lf", &val) != 1) {
        return -1;
    }

    // Convert to datoshi (multiply by 10^18)
    // For simplicity, use uint64_t for now (sufficient for test amounts)
    uint64_t datoshi = (uint64_t)(val * 1000000000000000000.0);

    fprintf(stderr, "[DEBUG] Value conversion: '%s' -> %.18f -> %lu datoshi\n",
            value_str, val, datoshi);

    // Store in little-endian uint256_t
    value_out->lo[0] = datoshi;
    value_out->lo[1] = 0;
    value_out->lo[2] = 0;
    value_out->lo[3] = 0;

    return 0;
}

// ============================================================================
// UTXO QUERY FROM PUBLIC RPC
// ============================================================================

int cellframe_query_utxos(const char *rpc_url, const char *network,
                           const char *addr_str, const char *token,
                           cellframe_utxo_list_t **list_out) {
    if (!rpc_url || !network || !addr_str || !token || !list_out) {
        return -1;
    }

    // Build RPC request JSON
    // Format from SDK: {"method": "wallet", "params": ["wallet;outputs;-addr;..."], "id": "1", "version": "2"}
    char request[2048];
    snprintf(request, sizeof(request),
             "{\"method\":\"wallet\",\"params\":[\"wallet;outputs;-addr;%s;-token;%s;-net;%s\"],\"id\":\"1\",\"version\":\"2\"}",
             addr_str, token, network);

    fprintf(stderr, "[UTXO] Query: %s\n", request);

    // Execute curl request
    char curl_cmd[4096];
    snprintf(curl_cmd, sizeof(curl_cmd),
             "curl -s -X POST -H \"Content-Type: application/json\" -d '%s' '%s'",
             request, rpc_url);

    FILE *fp = popen(curl_cmd, "r");
    if (!fp) {
        fprintf(stderr, "[UTXO] Failed to execute curl\n");
        return -1;
    }

    // Read response
    char response[65536];
    size_t response_len = fread(response, 1, sizeof(response) - 1, fp);
    response[response_len] = '\0';
    pclose(fp);

    fprintf(stderr, "[UTXO] Response: %.500s%s\n", response,
            response_len > 500 ? "..." : "");

    // Parse JSON response
    json_object *json_root = json_tokener_parse(response);
    if (!json_root) {
        fprintf(stderr, "[UTXO] Failed to parse JSON response\n");
        return -1;
    }

    // Response format: {"type": 2, "result": [[{...}]]}
    // Extract "result" field
    json_object *result_obj = NULL;
    if (!json_object_object_get_ex(json_root, "result", &result_obj) ||
        !json_object_is_type(result_obj, json_type_array)) {
        fprintf(stderr, "[UTXO] No 'result' array in response\n");
        json_object_put(json_root);
        return -1;
    }

    if (json_object_array_length(result_obj) == 0) {
        fprintf(stderr, "[UTXO] Empty response\n");
        json_object_put(json_root);
        return -1;
    }

    // Get first array element from result
    json_object *first_array = json_object_array_get_idx(result_obj, 0);
    if (!first_array || !json_object_is_type(first_array, json_type_array)) {
        fprintf(stderr, "[UTXO] Invalid response structure\n");
        json_object_put(json_root);
        return -1;
    }

    if (json_object_array_length(first_array) == 0) {
        fprintf(stderr, "[UTXO] No items in first array\n");
        json_object_put(json_root);
        return -1;
    }

    // Get first item to access "outs" field
    json_object *first_item = json_object_array_get_idx(first_array, 0);
    if (!first_item) {
        fprintf(stderr, "[UTXO] No first item\n");
        json_object_put(json_root);
        return -1;
    }

    json_object *outs_obj = NULL;
    if (!json_object_object_get_ex(first_item, "outs", &outs_obj) ||
        !json_object_is_type(outs_obj, json_type_array)) {
        fprintf(stderr, "[UTXO] No 'outs' array in response\n");
        json_object_put(json_root);
        return -1;
    }

    size_t outs_count = json_object_array_length(outs_obj);
    fprintf(stderr, "[UTXO] Found %zu UTXOs\n", outs_count);

    if (outs_count == 0) {
        fprintf(stderr, "[UTXO] No UTXOs available\n");
        json_object_put(json_root);
        return -1;
    }

    // Allocate UTXO list
    cellframe_utxo_list_t *list = calloc(1, sizeof(cellframe_utxo_list_t));
    if (!list) {
        json_object_put(json_root);
        return -1;
    }

    list->utxos = calloc(outs_count, sizeof(cellframe_utxo_t));
    if (!list->utxos) {
        free(list);
        json_object_put(json_root);
        return -1;
    }

    // Parse each UTXO
    memset(&list->total_value, 0, sizeof(uint256_t));

    for (size_t i = 0; i < outs_count; i++) {
        json_object *out = json_object_array_get_idx(outs_obj, i);
        if (!out) continue;

        // Get prev_hash
        json_object *prev_hash_obj = NULL;
        if (!json_object_object_get_ex(out, "prev_hash", &prev_hash_obj)) {
            continue;
        }
        const char *prev_hash_str = json_object_get_string(prev_hash_obj);

        // Get out_prev_idx
        json_object *out_idx_obj = NULL;
        if (!json_object_object_get_ex(out, "out_prev_idx", &out_idx_obj)) {
            continue;
        }
        uint32_t out_idx = json_object_get_int(out_idx_obj);

        // Get value_datoshi
        json_object *value_obj = NULL;
        if (!json_object_object_get_ex(out, "value_datoshi", &value_obj)) {
            continue;
        }
        const char *value_str = json_object_get_string(value_obj);

        // Convert hex hash to binary (skip "0x" prefix if present)
        const char *hash_hex = prev_hash_str;
        if (strncmp(prev_hash_str, "0x", 2) == 0 || strncmp(prev_hash_str, "0X", 2) == 0) {
            hash_hex += 2;  // Skip "0x" prefix
        }

        if (strlen(hash_hex) != 64) {
            fprintf(stderr, "[UTXO] Invalid hash length: %s\n", prev_hash_str);
            continue;
        }

        for (int j = 0; j < 32; j++) {
            unsigned int byte;
            if (sscanf(hash_hex + j * 2, "%02x", &byte) != 1) {
                fprintf(stderr, "[UTXO] Failed to parse hash byte\n");
                break;
            }
            list->utxos[list->count].prev_hash.raw[j] = (uint8_t)byte;
        }

        list->utxos[list->count].out_prev_idx = out_idx;

        // Parse value (uint256_t from decimal string)
        // For now, use simple uint64_t parsing
        uint64_t value_datoshi = strtoull(value_str, NULL, 10);
        list->utxos[list->count].value.lo[0] = value_datoshi;
        list->utxos[list->count].value.lo[1] = 0;
        list->utxos[list->count].value.lo[2] = 0;
        list->utxos[list->count].value.lo[3] = 0;

        // Add to total
        list->total_value.lo[0] += value_datoshi;

        fprintf(stderr, "[UTXO] #%zu: hash=%.16s... idx=%u value=%lu datoshi\n",
                list->count, prev_hash_str, out_idx, value_datoshi);

        list->count++;
    }

    json_object_put(json_root);

    if (list->count == 0) {
        free(list->utxos);
        free(list);
        return -1;
    }

    *list_out = list;
    fprintf(stderr, "[UTXO] Successfully parsed %zu UTXOs, total: %lu datoshi\n",
            list->count, list->total_value.lo[0]);
    return 0;
}

void cellframe_utxo_list_free(cellframe_utxo_list_t *list) {
    if (!list) {
        return;
    }
    if (list->utxos) {
        free(list->utxos);
    }
    free(list);
}

// ============================================================================
// TRANSACTION SIGNING
// ============================================================================

int cellframe_tx_add_signature(cellframe_tx_builder_t *builder,
                                 const uint8_t *pub_key, size_t pub_key_size,
                                 const uint8_t *priv_key, size_t priv_key_size) {
    if (!builder || !pub_key || !priv_key) {
        return -1;
    }

    fprintf(stderr, "[TX] Adding signature to transaction\n");
    fprintf(stderr, "[TX] Current tx size: %zu bytes\n", builder->size);
    fprintf(stderr, "[TX] Public key size (original): %zu bytes\n", pub_key_size);
    fprintf(stderr, "[TX] Private key size (original): %zu bytes\n", priv_key_size);

    // Strip Cellframe SDK 12-byte serialization header from public key
    // MODE_1: 1196 bytes total = 12-byte header + 1184 bytes actual public key
    const uint8_t *actual_pub_key = pub_key;
    size_t actual_pub_key_size = pub_key_size;

    if (pub_key_size == 1196) {
        // MODE_1 public key with header
        actual_pub_key = pub_key + 12;
        actual_pub_key_size = 1184;
        fprintf(stderr, "[TX] Stripping 12-byte header from public key\n");
    }

    fprintf(stderr, "[TX] Using public key: %zu bytes\n", actual_pub_key_size);

    // CRITICAL: Sign transaction with tx_items_size = 0
    // Create a copy of transaction for signing
    uint8_t *tx_copy = malloc(builder->size);
    if (!tx_copy) {
        return -1;
    }
    memcpy(tx_copy, builder->data, builder->size);

    // Set tx_items_size to 0 in the copy (offset 8 in header)
    cellframe_tx_header_t *hdr_copy = (cellframe_tx_header_t *)tx_copy;
    uint32_t original_items_size = hdr_copy->tx_items_size;
    hdr_copy->tx_items_size = 0;

    fprintf(stderr, "[TX] Signing with tx_items_size=0 (original was %u)\n", original_items_size);

    // Sign with Dilithium
    uint8_t *signature = NULL;
    size_t sig_len = 0;
    int ret = cellframe_tx_sign(tx_copy, builder->size, priv_key, priv_key_size,
                                  &signature, &sig_len);
    free(tx_copy);

    if (ret != 0) {
        fprintf(stderr, "[TX] Signing failed\n");
        return -1;
    }

    fprintf(stderr, "[TX] Signature created: %zu bytes\n", sig_len);

    // Build dap_sign_t structure using helper function
    uint8_t *dap_sign = NULL;
    size_t dap_sign_size = 0;
    ret = cellframe_build_dap_sign_t(pub_key, pub_key_size, signature, sig_len,
                                       &dap_sign, &dap_sign_size);
    free(signature);

    if (ret != 0) {
        fprintf(stderr, "[TX] Failed to build dap_sign_t structure\n");
        return -1;
    }

    fprintf(stderr, "[TX] dap_sign_t built: %zu bytes total\n", dap_sign_size);

    // Build SIG item: header + dap_sign_t
    size_t sig_item_size = sizeof(cellframe_tx_sig_header_t) + dap_sign_size;
    uint8_t *sig_item = malloc(sig_item_size);
    if (!sig_item) {
        free(dap_sign);
        return -1;
    }

    cellframe_tx_sig_header_t *sig_hdr = (cellframe_tx_sig_header_t *)sig_item;
    sig_hdr->type = TX_ITEM_TYPE_SIG;  // 0x30
    sig_hdr->version = 1;
    sig_hdr->sig_size = (uint32_t)dap_sign_size;

    memcpy(sig_item + sizeof(cellframe_tx_sig_header_t), dap_sign, dap_sign_size);
    free(dap_sign);

    fprintf(stderr, "[TX] SIG item built: %zu bytes total\n", sig_item_size);

    // Append SIG item to transaction
    // Note: DO NOT update tx_items_size when adding signature
    // (signature items are not counted in tx_items_size)
    ret = ensure_capacity(builder, sig_item_size);
    if (ret != 0) {
        free(sig_item);
        return -1;
    }

    memcpy(builder->data + builder->size, sig_item, sig_item_size);
    builder->size += sig_item_size;
    free(sig_item);

    fprintf(stderr, "[TX] Signature added successfully. Final tx size: %zu bytes\n", builder->size);

    return 0;
}

// ============================================================================
// BINARY TO JSON CONVERSION
// ============================================================================

// Helper: Convert binary data to hex string
static char* bin_to_hex(const uint8_t *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

// Helper: Convert binary data to base64
static char* bin_to_base64(const uint8_t *data, size_t len) {
    // Simple base64 encoding
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    uint32_t val = 0;
    int valb = -6;

    for (i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out[j++] = base64_chars[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }

    if (valb > -6) {
        out[j++] = base64_chars[((val << 8) >> (valb + 8)) & 0x3F];
    }

    while (j % 4) {
        out[j++] = '=';
    }

    out[j] = '\0';
    return out;
}

int cellframe_tx_to_json(const uint8_t *tx_data, size_t tx_size,
                          const char *network, const char *chain,
                          char **json_out) {
    if (!tx_data || !network || !chain || !json_out) {
        return -1;
    }

    fprintf(stderr, "[TX] Converting transaction to JSON\n");
    fprintf(stderr, "[TX] Transaction size: %zu bytes\n", tx_size);

    // Convert entire transaction to base64
    char *tx_b64 = bin_to_base64(tx_data, tx_size);
    if (!tx_b64) {
        return -1;
    }

    // Build JSON for RPC
    // Note: For tx_create_json, we might need to send the binary as base64
    // or parse it into JSON structure. Based on SDK, let's try base64 first.
    size_t json_len = strlen(network) + strlen(chain) + strlen(tx_b64) + 1024;
    char *json = malloc(json_len);
    if (!json) {
        free(tx_b64);
        return -1;
    }

    // Use RPC format matching SDK: {"method":"X","params":["X;args"],"id":"1","version":"2"}
    // tx_create_json requires -tx_obj parameter with the base64 transaction
    snprintf(json, json_len,
             "{\"method\":\"tx_create_json\",\"params\":[\"tx_create_json;-net;%s;-chain;%s;-tx_obj;%s\"],\"id\":\"1\",\"version\":\"2\"}",
             network, chain, tx_b64);

    free(tx_b64);
    *json_out = json;

    fprintf(stderr, "[TX] JSON created (length: %zu)\n", strlen(json));
    return 0;
}

// ============================================================================
// NETWORK FEE QUERY FROM PUBLIC RPC
// ============================================================================

int cellframe_query_network_fee(const char *rpc_url, const char *network,
                                 uint256_t *fee_out, char *fee_addr_out) {
    if (!rpc_url || !network || !fee_out || !fee_addr_out) {
        return -1;
    }

    // Build RPC request JSON
    // Format: {"method": "net", "params": ["net;get;fee;-net;<network>"], "id": "1", "version": "2"}
    char request[2048];
    snprintf(request, sizeof(request),
             "{\"method\":\"net\",\"params\":[\"net;get;fee;-net;%s\"],\"id\":\"1\",\"version\":\"2\"}",
             network);

    fprintf(stderr, "[NET_FEE] Query: %s\n", request);

    // Execute curl request
    char curl_cmd[4096];
    snprintf(curl_cmd, sizeof(curl_cmd),
             "curl -s -X POST -H \"Content-Type: application/json\" -d '%s' '%s'",
             request, rpc_url);

    FILE *fp = popen(curl_cmd, "r");
    if (!fp) {
        fprintf(stderr, "[NET_FEE] Failed to execute curl\n");
        return -1;
    }

    // Read response
    char response[65536];
    size_t response_len = fread(response, 1, sizeof(response) - 1, fp);
    response[response_len] = '\0';
    pclose(fp);

    fprintf(stderr, "[NET_FEE] Response: %.500s%s\n", response,
            response_len > 500 ? "..." : "");

    // Parse JSON response
    json_object *json_root = json_tokener_parse(response);
    if (!json_root) {
        fprintf(stderr, "[NET_FEE] Failed to parse JSON response\n");
        return -1;
    }

    // Response format: {"type": 2, "result": [{...}]}
    // Extract "result" field
    json_object *result_obj = NULL;
    if (!json_object_object_get_ex(json_root, "result", &result_obj) ||
        !json_object_is_type(result_obj, json_type_array)) {
        fprintf(stderr, "[NET_FEE] No 'result' array in response\n");
        json_object_put(json_root);
        return -1;
    }

    if (json_object_array_length(result_obj) == 0) {
        fprintf(stderr, "[NET_FEE] Empty response\n");
        json_object_put(json_root);
        return -1;
    }

    // Get first result object
    json_object *first_result = json_object_array_get_idx(result_obj, 0);
    if (!first_result || !json_object_is_type(first_result, json_type_object)) {
        fprintf(stderr, "[NET_FEE] Invalid first result\n");
        json_object_put(json_root);
        return -1;
    }

    // Get fees object
    json_object *fees_obj = NULL;
    if (!json_object_object_get_ex(first_result, "fees", &fees_obj) ||
        !json_object_is_type(fees_obj, json_type_object)) {
        fprintf(stderr, "[NET_FEE] No 'fees' object\n");
        json_object_put(json_root);
        return -1;
    }

    // Get network fee object
    json_object *network_obj = NULL;
    if (!json_object_object_get_ex(fees_obj, "network", &network_obj) ||
        !json_object_is_type(network_obj, json_type_object)) {
        fprintf(stderr, "[NET_FEE] No 'network' object\n");
        json_object_put(json_root);
        return -1;
    }

    // Get balance (datoshi string)
    json_object *balance_obj = NULL;
    if (!json_object_object_get_ex(network_obj, "balance", &balance_obj)) {
        fprintf(stderr, "[NET_FEE] No 'balance' field\n");
        json_object_put(json_root);
        return -1;
    }
    const char *balance_str = json_object_get_string(balance_obj);

    // Get address
    json_object *addr_obj = NULL;
    if (!json_object_object_get_ex(network_obj, "addr", &addr_obj)) {
        fprintf(stderr, "[NET_FEE] No 'addr' field\n");
        json_object_put(json_root);
        return -1;
    }
    const char *addr_str = json_object_get_string(addr_obj);

    // Parse balance to uint256_t
    memset(fee_out, 0, sizeof(uint256_t));
    uint64_t balance_datoshi = strtoull(balance_str, NULL, 10);
    fee_out->lo[0] = balance_datoshi;

    // Copy address
    strncpy(fee_addr_out, addr_str, 119);
    fee_addr_out[119] = '\0';

    fprintf(stderr, "[NET_FEE] Fee: %lu datoshi (%.9f CELL)\n",
            balance_datoshi, balance_datoshi / 1e18);
    fprintf(stderr, "[NET_FEE] Address: %s\n", fee_addr_out);

    json_object_put(json_root);
    return 0;
}
