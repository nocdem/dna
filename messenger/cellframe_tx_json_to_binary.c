/*
 * cellframe_tx_json_to_binary.c - Parse JSON transaction and build binary
 *
 * This module reads unsigned transaction JSON (like cellframe-tool-sign does)
 * and constructs binary transaction data using Cellframe's exact format.
 *
 * Strategy: Match cellframe-tool-sign's JSON→Binary conversion exactly.
 */

#include "cellframe_tx.h"
#include "cellframe_addr.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Parse IN item from JSON
 */
static int parse_in_item(json_object *item_obj, cellframe_tx_builder_t *builder) {
    // Get prev_hash
    json_object *hash_obj = json_object_object_get(item_obj, "prev_hash");
    if (!hash_obj) {
        fprintf(stderr, "[JSON] IN item missing prev_hash\n");
        return -1;
    }
    const char *hash_str = json_object_get_string(hash_obj);

    // Get out_prev_idx
    json_object *idx_obj = json_object_object_get(item_obj, "out_prev_idx");
    if (!idx_obj) {
        fprintf(stderr, "[JSON] IN item missing out_prev_idx\n");
        return -1;
    }
    uint32_t out_idx = json_object_get_int(idx_obj);

    // Parse hash string (0xHEX format)
    cellframe_hash_t prev_hash;
    if (cellframe_hash_from_str(hash_str, &prev_hash) != 0) {
        fprintf(stderr, "[JSON] Failed to parse prev_hash: %s\n", hash_str);
        return -1;
    }

    return cellframe_tx_add_in(builder, &prev_hash, out_idx);
}

/**
 * Parse OUT item from JSON
 */
static int parse_out_item(json_object *item_obj, cellframe_tx_builder_t *builder) {
    // Get address
    json_object *addr_obj = json_object_object_get(item_obj, "addr");
    if (!addr_obj) {
        fprintf(stderr, "[JSON] OUT item missing addr\n");
        return -1;
    }
    const char *addr_str = json_object_get_string(addr_obj);

    // Get value
    json_object *value_obj = json_object_object_get(item_obj, "value");
    if (!value_obj) {
        fprintf(stderr, "[JSON] OUT item missing value\n");
        return -1;
    }
    const char *value_str = json_object_get_string(value_obj);

    // Get token
    json_object *token_obj = json_object_object_get(item_obj, "token");
    if (!token_obj) {
        fprintf(stderr, "[JSON] OUT item missing token\n");
        return -1;
    }
    const char *token = json_object_get_string(token_obj);

    // Parse address
    cellframe_addr_t addr;
    if (cellframe_addr_from_str(addr_str, &addr) != 0) {
        fprintf(stderr, "[JSON] Failed to parse address: %s\n", addr_str);
        return -1;
    }

    // Parse value
    uint256_t value;
    if (cellframe_uint256_from_str(value_str, &value) != 0) {
        fprintf(stderr, "[JSON] Failed to parse value: %s\n", value_str);
        return -1;
    }

    return cellframe_tx_add_out(builder, &addr, &value, token);
}

/**
 * Parse OUT_COND fee item from JSON
 */
static int parse_out_cond_item(json_object *item_obj, cellframe_tx_builder_t *builder) {
    // Get subtype
    json_object *subtype_obj = json_object_object_get(item_obj, "subtype");
    if (!subtype_obj) {
        fprintf(stderr, "[JSON] OUT_COND item missing subtype\n");
        return -1;
    }
    const char *subtype = json_object_get_string(subtype_obj);

    if (strcmp(subtype, "fee") != 0) {
        fprintf(stderr, "[JSON] Unsupported OUT_COND subtype: %s\n", subtype);
        return -1;
    }

    // Get value
    json_object *value_obj = json_object_object_get(item_obj, "value");
    if (!value_obj) {
        fprintf(stderr, "[JSON] OUT_COND item missing value\n");
        return -1;
    }
    const char *value_str = json_object_get_string(value_obj);

    // Parse value
    uint256_t value;
    if (cellframe_uint256_from_str(value_str, &value) != 0) {
        fprintf(stderr, "[JSON] Failed to parse value: %s\n", value_str);
        return -1;
    }

    return cellframe_tx_add_out_cond_fee(builder, &value);
}

/**
 * Build binary transaction from JSON
 *
 * @param json_file - Path to unsigned transaction JSON file
 * @param tx_out - Output binary transaction data
 * @param tx_size_out - Output transaction size
 * @param timestamp_out - Output timestamp (from JSON or generated)
 * @return 0 on success, -1 on error
 */
int cellframe_tx_from_json(const char *json_file,
                           uint8_t **tx_out, size_t *tx_size_out,
                           uint64_t *timestamp_out) {
    if (!json_file || !tx_out || !tx_size_out) {
        return -1;
    }

    // Read JSON file
    json_object *root = json_object_from_file(json_file);
    if (!root) {
        fprintf(stderr, "[JSON] Failed to parse JSON file: %s\n", json_file);
        return -1;
    }

    // Get timestamp (or use current time if not specified)
    uint64_t timestamp = time(NULL);
    json_object *ts_obj = json_object_object_get(root, "timestamp");
    if (ts_obj) {
        timestamp = json_object_get_int64(ts_obj);
        fprintf(stderr, "[JSON] Using timestamp from JSON: %lu\n", timestamp);
    } else {
        fprintf(stderr, "[JSON] No timestamp in JSON, using current time: %lu\n", timestamp);
    }

    if (timestamp_out) {
        *timestamp_out = timestamp;
    }

    // Create transaction builder
    cellframe_tx_builder_t *builder = cellframe_tx_builder_new();
    if (!builder) {
        json_object_put(root);
        return -1;
    }

    // Set timestamp
    cellframe_tx_set_timestamp(builder, timestamp);

    // Get items array
    json_object *items_obj = json_object_object_get(root, "items");
    if (!items_obj || !json_object_is_type(items_obj, json_type_array)) {
        fprintf(stderr, "[JSON] Missing or invalid 'items' array\n");
        cellframe_tx_builder_free(builder);
        json_object_put(root);
        return -1;
    }

    // Parse each item
    size_t n_items = json_object_array_length(items_obj);
    fprintf(stderr, "[JSON] Parsing %zu transaction items\n", n_items);

    for (size_t i = 0; i < n_items; i++) {
        json_object *item = json_object_array_get_idx(items_obj, i);
        if (!item) continue;

        // Get item type
        json_object *type_obj = json_object_object_get(item, "type");
        if (!type_obj) {
            fprintf(stderr, "[JSON] Item %zu missing 'type'\n", i);
            continue;
        }
        const char *type = json_object_get_string(type_obj);

        fprintf(stderr, "[JSON] Item %zu: type=%s\n", i, type);

        int ret = -1;
        if (strcmp(type, "in") == 0) {
            ret = parse_in_item(item, builder);
        } else if (strcmp(type, "out") == 0) {
            ret = parse_out_item(item, builder);
        } else if (strcmp(type, "out_cond") == 0) {
            ret = parse_out_cond_item(item, builder);
        } else if (strcmp(type, "sign") == 0) {
            // Skip signature items (we'll add our own)
            fprintf(stderr, "[JSON] Skipping signature item\n");
            continue;
        } else {
            fprintf(stderr, "[JSON] Unknown item type: %s\n", type);
            continue;
        }

        if (ret != 0) {
            fprintf(stderr, "[JSON] Failed to parse item %zu (type=%s)\n", i, type);
            cellframe_tx_builder_free(builder);
            json_object_put(root);
            return -1;
        }
    }

    // Finalize transaction
    if (cellframe_tx_finalize(builder) != 0) {
        fprintf(stderr, "[JSON] Failed to finalize transaction\n");
        cellframe_tx_builder_free(builder);
        json_object_put(root);
        return -1;
    }

    // Copy transaction data
    *tx_out = malloc(builder->size);
    if (!*tx_out) {
        cellframe_tx_builder_free(builder);
        json_object_put(root);
        return -1;
    }

    memcpy(*tx_out, builder->data, builder->size);
    *tx_size_out = builder->size;

    fprintf(stderr, "[JSON] Built binary transaction: %zu bytes\n", builder->size);

    // Cleanup
    cellframe_tx_builder_free(builder);
    json_object_put(root);

    return 0;
}
