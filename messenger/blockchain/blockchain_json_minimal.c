/*
 * cellframe_json_minimal.c - Minimal JSON Conversion Implementation
 *
 * Converts signed binary transactions to JSON format for RPC submission.
 */

#include "blockchain_json_minimal.h"
#include "blockchain_sign_minimal.h"
#include "../crypto/utils/base58.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// ============================================================================
// BASE64 ENCODING (Using OpenSSL)
// ============================================================================

int cellframe_base64_encode(const uint8_t *data, size_t data_len, char **base64_out) {
    if (!data || !base64_out) {
        return -1;
    }

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO *bio_b64 = BIO_new(BIO_f_base64());
    if (!bio_mem || !bio_b64) {
        if (bio_mem) BIO_free(bio_mem);
        if (bio_b64) BIO_free(bio_b64);
        return -1;
    }

    // No newlines in Base64 output
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    BIO *bio = BIO_push(bio_b64, bio_mem);
    BIO_write(bio, data, data_len);
    BIO_flush(bio);

    BUF_MEM *buf_mem;
    BIO_get_mem_ptr(bio, &buf_mem);

    size_t b64_len = buf_mem->length;
    char *base64 = malloc(b64_len + 1);
    if (!base64) {
        BIO_free_all(bio);
        return -1;
    }

    memcpy(base64, buf_mem->data, b64_len);
    base64[b64_len] = '\0';

    BIO_free_all(bio);

    // Convert to URL-safe Base64 (Cellframe requirement)
    // Replace '+' with '-' and '/' with '_'
    for (size_t i = 0; i < b64_len; i++) {
        if (base64[i] == '+') {
            base64[i] = '-';
        } else if (base64[i] == '/') {
            base64[i] = '_';
        }
    }

    *base64_out = base64;
    return (int)b64_len;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

void cellframe_hash_to_hex(const cellframe_hash_t *hash, char *hex_out) {
    if (!hash || !hex_out) {
        return;
    }

    hex_out[0] = '0';
    hex_out[1] = 'x';

    for (int i = 0; i < 32; i++) {
        sprintf(hex_out + 2 + (i * 2), "%02X", hash->raw[i]);
    }

    hex_out[66] = '\0';
}

void cellframe_uint256_to_str(const uint256_t *value, char *str_out) {
    if (!value || !str_out) {
        return;
    }

    // For amounts < 2^64, value is in lo.lo (bytes 16-23)
    // SDK: uint256_t.lo.lo contains the datoshi amount
    sprintf(str_out, "%llu", (unsigned long long)value->lo.lo);
}

// ============================================================================
// JSON CONVERSION
// ============================================================================

/**
 * Parse transaction and build JSON items array
 */
static int build_json_items(const uint8_t *tx_items, size_t tx_items_size,
                            uint64_t timestamp, char **items_json_out) {
    if (!tx_items || !items_json_out) {
        return -1;
    }

    // Build items array with bounds checking
    #define MAX_JSON_SIZE (1024 * 1024)  // 1MB max transaction size
    char *json = malloc(MAX_JSON_SIZE);
    if (!json) {
        return -1;
    }

    size_t json_len = 0;
    size_t remaining = MAX_JSON_SIZE;

    int ret = snprintf(json + json_len, remaining, "  \"items\": [\n");
    if (ret < 0 || (size_t)ret >= remaining) {
        free(json);
        return -1;
    }
    json_len += ret;
    remaining -= ret;

    size_t offset = 0;
    int item_count = 0;

    while (offset < tx_items_size) {
        const uint8_t *item = tx_items + offset;
        uint8_t type = item[0];

        if (item_count > 0) {
            ret = snprintf(json + json_len, remaining, ",\n");
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;
        }

        if (type == TX_ITEM_TYPE_IN) {
            // IN item: type (1) + hash (32) + idx (4) = 37 bytes
            cellframe_tx_in_t *in_item = (cellframe_tx_in_t*)item;

            char prev_hash_hex[67];
            cellframe_hash_to_hex(&in_item->tx_prev_hash, prev_hash_hex);

            ret = snprintf(json + json_len, remaining,
                "    {\"type\":\"in\", \"prev_hash\":\"%s\", \"out_prev_idx\":%u}",
                prev_hash_hex, in_item->tx_out_prev_idx);
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            offset += sizeof(cellframe_tx_in_t);

        } else if (type == TX_ITEM_TYPE_OUT) {
            // OUT item: type (1) + value (32) + addr (77) = 110 bytes
            cellframe_tx_out_t *out_item = (cellframe_tx_out_t*)item;

            char value_str[80];
            cellframe_uint256_to_str(&out_item->header.value, value_str);

            // Convert address to Base58
            char addr_base58[BASE58_ENCODE_SIZE(sizeof(cellframe_addr_t)) + 1];
            size_t addr_len = base58_encode(&out_item->addr, sizeof(cellframe_addr_t), addr_base58);
            if (addr_len == 0) {
                fprintf(stderr, "[JSON] Failed to encode address to Base58\n");
                free(json);
                return -1;
            }
            addr_base58[addr_len] = '\0';

            ret = snprintf(json + json_len, remaining,
                "    {\"type\":\"out\", \"addr\":\"%s\", \"value\":\"%s\"}",
                addr_base58, value_str);
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            offset += sizeof(cellframe_tx_out_t);

        } else if (type == TX_ITEM_TYPE_OUT_EXT) {
            // OUT_EXT item: type (1) + value (32) + addr (77) + token (10) = 120 bytes
            cellframe_tx_out_ext_t *out_ext_item = (cellframe_tx_out_ext_t*)item;

            char value_str[80];
            cellframe_uint256_to_str(&out_ext_item->header.value, value_str);

            // Convert address to Base58
            char addr_base58[BASE58_ENCODE_SIZE(sizeof(cellframe_addr_t)) + 1];
            size_t addr_len = base58_encode(&out_ext_item->addr, sizeof(cellframe_addr_t), addr_base58);
            if (addr_len == 0) {
                fprintf(stderr, "[JSON] Failed to encode address to Base58\n");
                free(json);
                return -1;
            }
            addr_base58[addr_len] = '\0';

            // Get token ticker (null-terminated)
            char token[CELLFRAME_TICKER_SIZE_MAX + 1];
            memcpy(token, out_ext_item->token, CELLFRAME_TICKER_SIZE_MAX);
            token[CELLFRAME_TICKER_SIZE_MAX] = '\0';

            ret = snprintf(json + json_len, remaining,
                "    {\"type\":\"out_ext\", \"addr\":\"%s\", \"value\":\"%s\", \"token\":\"%s\"}",
                addr_base58, value_str, token);
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            offset += sizeof(cellframe_tx_out_ext_t);

        } else if (type == TX_ITEM_TYPE_OUT_COND) {
            // OUT_COND item: 340 bytes
            cellframe_tx_out_cond_t *cond_item = (cellframe_tx_out_cond_t*)item;

            char value_str[80];
            cellframe_uint256_to_str(&cond_item->value, value_str);

            const char *subtype_str = "unknown";
            if (cond_item->subtype == TX_OUT_COND_SUBTYPE_FEE) {
                subtype_str = "fee";
            }

            ret = snprintf(json + json_len, remaining,
                "    {\"type\":\"out_cond\", \"subtype\":\"%s\", "
                "\"value\":\"%s\", \"ts_expires\":\"%s\", \"service_id\":\"0x%016lX\"}",
                subtype_str, value_str,
                cond_item->ts_expires == 0 ? "never" : "timestamp",
                cond_item->srv_uid);
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            offset += sizeof(cellframe_tx_out_cond_t);

        } else if (type == TX_ITEM_TYPE_TSD) {
            // TSD item: parse header + inner TSD
            cellframe_tx_tsd_t *tsd_item = (cellframe_tx_tsd_t*)item;
            cellframe_tsd_t *tsd = (cellframe_tsd_t*)tsd_item->tsd;

            // Write raw string (cellframe-tool-sign expects plain text, not base64)
            // Source: dap_chain_net_tx.c:1281 uses dap_strlen() directly on data string
            ret = snprintf(json + json_len, remaining,
                "    {\"type\":\"data\", \"type_tsd\":%u, \"data\":\"", tsd->type);
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            // Copy data with JSON escaping and bounds checking
            for (uint32_t i = 0; i < tsd->size; i++) {
                char c = tsd->data[i];

                // Check we have at least 2 bytes remaining for worst case (escape + char)
                if (remaining < 3) {
                    fprintf(stderr, "[JSON] TSD data too large, buffer full\n");
                    free(json);
                    return -1;
                }

                if (c == '"' || c == '\\') {
                    json[json_len++] = '\\';  // Escape quotes and backslashes
                    json[json_len++] = c;
                    remaining -= 2;
                } else if (c == '\n') {
                    json[json_len++] = '\\';
                    json[json_len++] = 'n';
                    remaining -= 2;
                } else if (c == '\r') {
                    json[json_len++] = '\\';
                    json[json_len++] = 'r';
                    remaining -= 2;
                } else if (c == '\t') {
                    json[json_len++] = '\\';
                    json[json_len++] = 't';
                    remaining -= 2;
                } else if (c == '\0') {
                    break;  // Stop at null terminator for strings
                } else {
                    json[json_len++] = c;
                    remaining--;
                }
            }

            ret = snprintf(json + json_len, remaining, "\", \"size\":%u}", tsd->size);
            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            offset += sizeof(cellframe_tx_tsd_t) + tsd_item->size;

        } else if (type == TX_ITEM_TYPE_SIG) {
            // SIG item: header (6) + dap_sign_t
            cellframe_tx_sig_header_t *sig_header = (cellframe_tx_sig_header_t*)item;
            const uint8_t *dap_sign_data = item + sizeof(cellframe_tx_sig_header_t);

            // Base64-encode dap_sign_t
            char *sig_b64 = NULL;
            if (cellframe_base64_encode(dap_sign_data, sig_header->sig_size, &sig_b64) < 0) {
                free(json);
                return -1;
            }

            ret = snprintf(json + json_len, remaining,
                "    {\"type\":\"sign\", \"sig_size\":%u, \"sig_b64\":\"%s\"}",
                sig_header->sig_size, sig_b64);

            free(sig_b64);

            if (ret < 0 || (size_t)ret >= remaining) {
                free(json);
                return -1;
            }
            json_len += ret;
            remaining -= ret;

            offset += sizeof(cellframe_tx_sig_header_t) + sig_header->sig_size;

        } else {
            fprintf(stderr, "[JSON] Unknown item type: 0x%02X at offset %zu\n", type, offset);
            free(json);
            return -1;
        }

        item_count++;
    }

    ret = snprintf(json + json_len, remaining, "\n  ]");
    if (ret < 0 || (size_t)ret >= remaining) {
        free(json);
        return -1;
    }
    json_len += ret;

    *items_json_out = json;
    return 0;
    #undef MAX_JSON_SIZE
}

int cellframe_tx_to_json(const uint8_t *tx_data, size_t tx_size, char **json_out) {
    if (!tx_data || tx_size < sizeof(cellframe_tx_header_t) || !json_out) {
        return -1;
    }

    // Parse header
    cellframe_tx_header_t *header = (cellframe_tx_header_t*)tx_data;
    uint64_t timestamp = header->ts_created;
    uint32_t items_size = header->tx_items_size;

    // Calculate datum_hash (SHA3-256 of entire transaction)
    uint8_t datum_hash_raw[32];
    cellframe_sha3_256(tx_data, tx_size, datum_hash_raw);

    char datum_hash_hex[67];
    cellframe_hash_t datum_hash;
    memcpy(datum_hash.raw, datum_hash_raw, 32);
    cellframe_hash_to_hex(&datum_hash, datum_hash_hex);

    // Parse items
    const uint8_t *tx_items = tx_data + sizeof(cellframe_tx_header_t);
    size_t tx_items_size = tx_size - sizeof(cellframe_tx_header_t);

    char *items_json = NULL;
    if (build_json_items(tx_items, tx_items_size, timestamp, &items_json) != 0) {
        return -1;
    }

    // Build complete JSON
    char *json = malloc(strlen(items_json) + 1024);
    if (!json) {
        free(items_json);
        return -1;
    }

    sprintf(json,
        "{\n"
        "  \"datum_hash\": \"%s\",\n"
        "  \"ts_created\": %lu,\n"
        "  \"datum_type\": \"tx\",\n"
        "%s\n"
        "}",
        datum_hash_hex, timestamp, items_json);

    free(items_json);

    *json_out = json;
    return 0;
}
