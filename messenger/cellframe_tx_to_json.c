/*
 * cellframe_tx_to_json.c - Convert binary Cellframe transaction to JSON
 *
 * Reads binary transaction and converts all items to JSON format
 */

#include "cellframe_tx.h"
#include "cellframe_addr.h"
#include "base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Base64 encode (URL-safe variant)
static char* base64_encode_urlsafe(const uint8_t *data, size_t len) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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

/**
 * Convert binary transaction to JSON
 *
 * This reads a signed binary transaction and converts all items to JSON format
 */
int cellframe_tx_binary_to_json(const uint8_t *tx_data, size_t tx_size, char **json_out) {
    if (!tx_data || tx_size < sizeof(cellframe_tx_header_t) || !json_out) {
        return -1;
    }

    const cellframe_tx_header_t *header = (const cellframe_tx_header_t *)tx_data;
    const uint8_t *items_data = tx_data + sizeof(cellframe_tx_header_t);
    // Parse ALL items including signature (which is AFTER tx_items_size)
    size_t items_size = tx_size - sizeof(cellframe_tx_header_t);

    // Build JSON string manually
    char *json = malloc(65536);  // Start with 64KB
    if (!json) return -1;
    size_t json_cap = 65536;
    size_t json_len = 0;

    // Start JSON
    json_len += snprintf(json + json_len, json_cap - json_len,
                         "{\"items\":[");

    // Parse items
    size_t offset = 0;
    bool first_item = true;
    while (offset < items_size) {
        const uint8_t *item = items_data + offset;
        uint8_t item_type = *item;

        if (!first_item) {
            json_len += snprintf(json + json_len, json_cap - json_len, ",");
        }
        first_item = false;

        switch (item_type) {
            case TX_ITEM_TYPE_IN: {
                const cellframe_tx_in_t *in = (const cellframe_tx_in_t *)item;

                // Convert hash to hex (UPPERCASE to match Cellframe)
                char hash_hex[65];
                for (int i = 0; i < 32; i++) {
                    sprintf(hash_hex + i*2, "%02X", in->tx_prev_hash.raw[i]);
                }
                hash_hex[64] = '\0';

                json_len += snprintf(json + json_len, json_cap - json_len,
                                     "{\"type\":\"in\",\"prev_hash\":\"0x%s\",\"out_prev_idx\":%u}",
                                     hash_hex, in->tx_out_prev_idx);

                offset += sizeof(cellframe_tx_in_t);
                break;
            }

            case TX_ITEM_TYPE_OUT: {
                const cellframe_tx_out_t *out = (const cellframe_tx_out_t *)item;

                // Convert address to Base58
                char addr_str[120];
                if (cellframe_addr_to_str(&out->addr, addr_str, sizeof(addr_str)) != 0) {
                    free(json);
                    return -1;
                }

                // Convert value to string (datoshi)
                char value_str[64];
                snprintf(value_str, sizeof(value_str), "%lu", out->header.value.lo[0]);

                json_len += snprintf(json + json_len, json_cap - json_len,
                                     "{\"type\":\"out\",\"addr\":\"%s\",\"value\":\"%s\"}",
                                     addr_str, value_str);

                offset += sizeof(cellframe_tx_out_t);
                break;
            }

            case TX_ITEM_TYPE_OUT_STD: {
                const cellframe_tx_out_std_t *out = (const cellframe_tx_out_std_t *)item;

                // Convert address to Base58
                char addr_str[120];
                if (cellframe_addr_to_str(&out->addr, addr_str, sizeof(addr_str)) != 0) {
                    free(json);
                    return -1;
                }

                // Convert value to string (datoshi)
                char value_str[64];
                snprintf(value_str, sizeof(value_str), "%lu", out->value.lo[0]);

                json_len += snprintf(json + json_len, json_cap - json_len,
                                     "{\"type\":\"out\",\"addr\":\"%s\",\"value\":\"%s\"}",
                                     addr_str, value_str);

                offset += sizeof(cellframe_tx_out_std_t);
                break;
            }

            case TX_ITEM_TYPE_OUT_EXT: {
                const cellframe_tx_out_ext_t *out = (const cellframe_tx_out_ext_t *)item;

                // Convert address to Base58
                char addr_str[120];
                if (cellframe_addr_to_str(&out->addr, addr_str, sizeof(addr_str)) != 0) {
                    free(json);
                    return -1;
                }

                // Convert value to string (datoshi)
                char value_str[64];
                snprintf(value_str, sizeof(value_str), "%lu", out->value.lo[0]);

                json_len += snprintf(json + json_len, json_cap - json_len,
                                     "{\"type\":\"out\",\"addr\":\"%s\",\"value\":\"%s\"}",
                                     addr_str, value_str);

                offset += sizeof(cellframe_tx_out_ext_t);
                break;
            }

            case TX_ITEM_TYPE_OUT_COND: {
                const cellframe_tx_out_cond_t *cond = (const cellframe_tx_out_cond_t *)item;

                // Convert value to string
                char value_str[64];
                snprintf(value_str, sizeof(value_str), "%lu", cond->value.lo[0]);

                json_len += snprintf(json + json_len, json_cap - json_len,
                                     "{\"type\":\"out_cond\",\"ts_expires\":\"never\","
                                     "\"value\":\"%s\",\"service_id\":\"0x%016lx\",\"subtype\":\"fee\"}",
                                     value_str, cond->srv_uid);

                offset += sizeof(cellframe_tx_out_cond_t) + cond->tsd_size;
                break;
            }

            case TX_ITEM_TYPE_SIG: {
                const cellframe_tx_sig_header_t *sig_hdr = (const cellframe_tx_sig_header_t *)item;
                const dap_sign_t *sig = (const dap_sign_t *)(item + sizeof(cellframe_tx_sig_header_t));

                // Encode entire dap_sign_t structure as base64 (Cellframe format)
                size_t dap_sign_size = sig_hdr->sig_size;
                char *sig_b64 = base64_encode_urlsafe((const uint8_t *)sig, dap_sign_size);

                if (!sig_b64) {
                    free(json);
                    return -1;
                }

                // Extract serialized public key from dap_sign_t (ALREADY has 12-byte header)
                // dap_sign_t layout: [14-byte header][serialized pubkey WITH header][serialized signature WITH wrapper]
                // The public key is already in Cellframe serialized format: [8-byte size][4-byte type][key data]
                size_t pub_key_size_raw = sig->header.sign_pkey_size;  // 1196 bytes (WITH 12-byte header)
                const uint8_t *pub_key_raw = sig->pkey_n_sign;

                // CRITICAL: Public key is ALREADY serialized with its 12-byte header!
                // Do NOT add another header or we get 1208 bytes instead of 1196.
                char *pub_key_b64 = base64_encode_urlsafe(pub_key_raw, pub_key_size_raw);

                if (!pub_key_b64) {
                    free(sig_b64);
                    free(json);
                    return -1;
                }

                // Ensure we have enough space
                size_t needed = strlen(sig_b64) + strlen(pub_key_b64) + 1024;
                if (json_len + needed >= json_cap) {
                    json_cap = json_len + needed + 65536;
                    char *new_json = realloc(json, json_cap);
                    if (!new_json) {
                        free(pub_key_b64);
                        free(sig_b64);
                        free(json);
                        return -1;
                    }
                    json = new_json;
                }

                // Output signature item matching Cellframe-tool-sign format (minimal fields)
                // Cellframe-tool-sign only outputs: type, sig_size, sig_b64
                // The dap_sign_t structure (sig_b64) already contains all the data (header, pubkey, signature)
                json_len += snprintf(json + json_len, json_cap - json_len,
                                     "{\"type\":\"sign\",\"sig_size\":%zu,\"sig_b64\":\"%s\"}",
                                     dap_sign_size, sig_b64);

                free(pub_key_b64);
                free(sig_b64);

                offset += sizeof(cellframe_tx_sig_header_t) + sig_hdr->sig_size;
                break;
            }

            default:
                // Unknown item type - skip
                fprintf(stderr, "[WARN] Unknown item type: 0x%02x\n", item_type);
                free(json);
                return -1;
        }
    }

    // Close items array, add timestamp and datum_type
    json_len += snprintf(json + json_len, json_cap - json_len,
                         "],\"ts_created\":%lu,\"datum_type\":\"tx\"}",
                         header->ts_created);

    *json_out = json;
    return 0;
}
