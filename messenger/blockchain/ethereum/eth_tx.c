/**
 * @file eth_tx.c
 * @brief Ethereum Transaction Implementation
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "eth_tx.h"
#include "eth_rlp.h"
#include "eth_wallet.h"
#include "../../crypto/utils/keccak256.h"
#include "../../crypto/utils/qgp_log.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "ETH_TX"

/* External RPC endpoint from eth_rpc.c */
extern const char* eth_rpc_get_endpoint(void);

/* Curl response buffer */
struct response_buffer {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

/**
 * Make JSON-RPC call
 */
static int eth_rpc_call(const char *method, json_object *params, json_object **result_out) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build request */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "method", json_object_new_string(method));
    json_object_object_add(req, "params", params);
    json_object_object_add(req, "id", json_object_new_int(1));

    const char *json_str = json_object_to_json_string(req);

    QGP_LOG_DEBUG(LOG_TAG, "RPC request: %s", json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, eth_rpc_get_endpoint());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(req);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "RPC response: %s", resp_buf.data);

    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse response");
        return -1;
    }

    /* Check for error */
    json_object *jerr = NULL;
    if (json_object_object_get_ex(resp, "error", &jerr) && jerr) {
        json_object *jmsg = NULL;
        const char *msg = "Unknown error";
        if (json_object_object_get_ex(jerr, "message", &jmsg)) {
            msg = json_object_get_string(jmsg);
        }
        QGP_LOG_ERROR(LOG_TAG, "RPC error: %s", msg);
        json_object_put(resp);
        return -1;
    }

    /* Get result */
    json_object *jresult = NULL;
    if (!json_object_object_get_ex(resp, "result", &jresult)) {
        QGP_LOG_ERROR(LOG_TAG, "No result in response");
        json_object_put(resp);
        return -1;
    }

    /* Return result (caller must free resp) */
    *result_out = json_object_get(jresult);
    json_object_put(resp);

    return 0;
}

/**
 * Parse hex string to uint64
 */
static int hex_to_u64(const char *hex, uint64_t *out) {
    if (!hex || !out) return -1;

    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    uint64_t val = 0;
    while (*p) {
        char c = *p++;
        uint8_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        val = (val << 4) | d;
    }

    *out = val;
    return 0;
}

/* ============================================================================
 * RPC QUERIES
 * ============================================================================ */

int eth_tx_get_nonce(const char *address, uint64_t *nonce_out) {
    if (!address || !nonce_out) return -1;

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));
    json_object_array_add(params, json_object_new_string("pending"));

    json_object *result = NULL;
    if (eth_rpc_call("eth_getTransactionCount", params, &result) != 0) {
        return -1;
    }

    const char *hex = json_object_get_string(result);
    int ret = hex_to_u64(hex, nonce_out);
    json_object_put(result);

    QGP_LOG_DEBUG(LOG_TAG, "Nonce for %s: %llu", address, (unsigned long long)*nonce_out);
    return ret;
}

int eth_tx_get_gas_price(uint64_t *gas_price_out) {
    if (!gas_price_out) return -1;

    json_object *params = json_object_new_array();

    json_object *result = NULL;
    if (eth_rpc_call("eth_gasPrice", params, &result) != 0) {
        return -1;
    }

    const char *hex = json_object_get_string(result);
    int ret = hex_to_u64(hex, gas_price_out);
    json_object_put(result);

    QGP_LOG_DEBUG(LOG_TAG, "Gas price: %llu wei", (unsigned long long)*gas_price_out);
    return ret;
}

int eth_tx_estimate_gas(
    const char *from,
    const char *to,
    const char *value,
    uint64_t *gas_out
) {
    if (!from || !to || !gas_out) return -1;

    json_object *tx_obj = json_object_new_object();
    json_object_object_add(tx_obj, "from", json_object_new_string(from));
    json_object_object_add(tx_obj, "to", json_object_new_string(to));
    if (value) {
        json_object_object_add(tx_obj, "value", json_object_new_string(value));
    }

    json_object *params = json_object_new_array();
    json_object_array_add(params, tx_obj);

    json_object *result = NULL;
    if (eth_rpc_call("eth_estimateGas", params, &result) != 0) {
        /* Fall back to default for simple transfers */
        *gas_out = ETH_GAS_LIMIT_TRANSFER;
        return 0;
    }

    const char *hex = json_object_get_string(result);
    int ret = hex_to_u64(hex, gas_out);
    json_object_put(result);

    return ret;
}

/* ============================================================================
 * TRANSACTION BUILDING
 * ============================================================================ */

void eth_tx_init_transfer(
    eth_tx_t *tx,
    uint64_t nonce,
    uint64_t gas_price,
    const uint8_t to[20],
    const uint8_t value_wei[32],
    uint64_t chain_id
) {
    if (!tx) return;

    memset(tx, 0, sizeof(*tx));
    tx->nonce = nonce;
    tx->gas_price = gas_price;
    tx->gas_limit = ETH_GAS_LIMIT_TRANSFER;
    memcpy(tx->to, to, 20);
    memcpy(tx->value, value_wei, 32);
    tx->data = NULL;
    tx->data_len = 0;
    tx->chain_id = chain_id;
}

/**
 * RLP encode transaction for signing (EIP-155)
 *
 * For signing: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
 */
static int eth_tx_encode_for_signing(const eth_tx_t *tx, eth_rlp_buffer_t *out) {
    eth_rlp_reset(out);

    int list_pos = eth_rlp_begin_list(out);
    if (list_pos < 0) return -1;

    /* nonce */
    if (eth_rlp_encode_uint64(out, tx->nonce) != 0) return -1;

    /* gasPrice */
    if (eth_rlp_encode_uint64(out, tx->gas_price) != 0) return -1;

    /* gasLimit */
    if (eth_rlp_encode_uint64(out, tx->gas_limit) != 0) return -1;

    /* to (20 bytes) */
    if (eth_rlp_encode_bytes(out, tx->to, 20) != 0) return -1;

    /* value (256-bit big-endian) */
    if (eth_rlp_encode_uint256(out, tx->value) != 0) return -1;

    /* data */
    if (eth_rlp_encode_bytes(out, tx->data, tx->data_len) != 0) return -1;

    /* EIP-155: chainId, 0, 0 */
    if (eth_rlp_encode_uint64(out, tx->chain_id) != 0) return -1;
    if (eth_rlp_encode_uint64(out, 0) != 0) return -1;
    if (eth_rlp_encode_uint64(out, 0) != 0) return -1;

    return eth_rlp_end_list(out, list_pos);
}

/**
 * RLP encode signed transaction
 *
 * [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
 */
static int eth_tx_encode_signed(
    const eth_tx_t *tx,
    uint64_t v,
    const uint8_t r[32],
    const uint8_t s[32],
    eth_rlp_buffer_t *out
) {
    eth_rlp_reset(out);

    int list_pos = eth_rlp_begin_list(out);
    if (list_pos < 0) return -1;

    /* nonce */
    if (eth_rlp_encode_uint64(out, tx->nonce) != 0) return -1;

    /* gasPrice */
    if (eth_rlp_encode_uint64(out, tx->gas_price) != 0) return -1;

    /* gasLimit */
    if (eth_rlp_encode_uint64(out, tx->gas_limit) != 0) return -1;

    /* to (20 bytes) */
    if (eth_rlp_encode_bytes(out, tx->to, 20) != 0) return -1;

    /* value (256-bit big-endian) */
    if (eth_rlp_encode_uint256(out, tx->value) != 0) return -1;

    /* data */
    if (eth_rlp_encode_bytes(out, tx->data, tx->data_len) != 0) return -1;

    /* v */
    if (eth_rlp_encode_uint64(out, v) != 0) return -1;

    /* r (32 bytes, strip leading zeros) */
    if (eth_rlp_encode_uint256(out, r) != 0) return -1;

    /* s (32 bytes, strip leading zeros) */
    if (eth_rlp_encode_uint256(out, s) != 0) return -1;

    return eth_rlp_end_list(out, list_pos);
}

int eth_tx_sign(
    const eth_tx_t *tx,
    const uint8_t private_key[32],
    eth_signed_tx_t *signed_out
) {
    if (!tx || !private_key || !signed_out) {
        return -1;
    }

    memset(signed_out, 0, sizeof(*signed_out));

    /* Create secp256k1 context */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create secp256k1 context");
        return -1;
    }

    int ret = -1;
    eth_rlp_buffer_t rlp_buf = {0};

    /* Initialize RLP buffer */
    if (eth_rlp_init(&rlp_buf, ETH_TX_MAX_SIZE) != 0) {
        goto cleanup;
    }

    /* Encode transaction for signing (EIP-155) */
    if (eth_tx_encode_for_signing(tx, &rlp_buf) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to RLP encode transaction");
        goto cleanup;
    }

    /* Hash with Keccak-256 */
    uint8_t tx_hash[32];
    if (keccak256(rlp_buf.data, rlp_buf.len, tx_hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to hash transaction");
        goto cleanup;
    }

    /* Sign with secp256k1 recoverable signature */
    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &sig, tx_hash, private_key, NULL, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        goto cleanup;
    }

    /* Extract r, s, recovery_id */
    uint8_t sig_data[64];
    int recovery_id;
    if (secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_data, &recovery_id, &sig) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize signature");
        goto cleanup;
    }

    uint8_t r[32], s[32];
    memcpy(r, sig_data, 32);
    memcpy(s, sig_data + 32, 32);

    /* Calculate v = recovery_id + chainId * 2 + 35 (EIP-155) */
    uint64_t v = (uint64_t)recovery_id + tx->chain_id * 2 + 35;

    /* Encode signed transaction */
    if (eth_tx_encode_signed(tx, v, r, s, &rlp_buf) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode signed transaction");
        goto cleanup;
    }

    /* Copy to output */
    if (rlp_buf.len > ETH_TX_MAX_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Signed transaction too large");
        goto cleanup;
    }

    memcpy(signed_out->raw_tx, rlp_buf.data, rlp_buf.len);
    signed_out->raw_tx_len = rlp_buf.len;

    /* Compute transaction hash (Keccak-256 of signed RLP) */
    uint8_t final_hash[32];
    if (keccak256(rlp_buf.data, rlp_buf.len, final_hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute tx hash");
        goto cleanup;
    }

    /* Format as hex */
    signed_out->tx_hash[0] = '0';
    signed_out->tx_hash[1] = 'x';
    for (int i = 0; i < 32; i++) {
        snprintf(signed_out->tx_hash + 2 + i * 2, 3, "%02x", final_hash[i]);
    }

    QGP_LOG_INFO(LOG_TAG, "Transaction signed: %s", signed_out->tx_hash);
    ret = 0;

cleanup:
    eth_rlp_free(&rlp_buf);
    secp256k1_context_destroy(ctx);
    return ret;
}

int eth_tx_send(const eth_signed_tx_t *signed_tx, char *tx_hash_out) {
    if (!signed_tx || !tx_hash_out) {
        return -1;
    }

    /* Convert raw tx to hex */
    char *hex_tx = malloc(signed_tx->raw_tx_len * 2 + 3);
    if (!hex_tx) {
        return -1;
    }

    hex_tx[0] = '0';
    hex_tx[1] = 'x';
    for (size_t i = 0; i < signed_tx->raw_tx_len; i++) {
        snprintf(hex_tx + 2 + i * 2, 3, "%02x", signed_tx->raw_tx[i]);
    }

    /* Make RPC call */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(hex_tx));

    json_object *result = NULL;
    int ret = eth_rpc_call("eth_sendRawTransaction", params, &result);

    free(hex_tx);

    if (ret != 0) {
        return -1;
    }

    /* Copy returned tx hash */
    const char *hash = json_object_get_string(result);
    if (hash) {
        strncpy(tx_hash_out, hash, 66);
        tx_hash_out[66] = '\0';
    } else {
        /* Use our computed hash */
        strcpy(tx_hash_out, signed_tx->tx_hash);
    }

    json_object_put(result);

    QGP_LOG_INFO(LOG_TAG, "Transaction sent: %s", tx_hash_out);
    return 0;
}

/* ============================================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================================ */

int eth_parse_amount(const char *amount_str, uint8_t wei_out[32]) {
    if (!amount_str || !wei_out) {
        return -1;
    }

    memset(wei_out, 0, 32);

    /* Parse decimal number */
    double eth_amount = strtod(amount_str, NULL);
    if (eth_amount <= 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid amount: %s", amount_str);
        return -1;
    }

    /* Convert to wei (multiply by 10^18) */
    /* For simplicity, handle amounts up to ~18 ETH with uint64_t precision */
    /* For larger amounts, we'd need arbitrary precision math */

    /* Split into whole and fractional parts */
    double whole = floor(eth_amount);
    double frac = eth_amount - whole;

    /* Convert whole ETH to wei (whole * 10^18) */
    uint64_t whole_wei = (uint64_t)whole * 1000000000000000000ULL;

    /* Convert fractional part */
    uint64_t frac_wei = (uint64_t)(frac * 1000000000000000000.0);

    /* Total wei (may overflow for very large amounts) */
    uint64_t total_wei = whole_wei + frac_wei;

    /* Store as big-endian 256-bit */
    for (int i = 0; i < 8; i++) {
        wei_out[31 - i] = (uint8_t)((total_wei >> (i * 8)) & 0xFF);
    }

    QGP_LOG_DEBUG(LOG_TAG, "Parsed %s ETH = %llu wei", amount_str, (unsigned long long)total_wei);
    return 0;
}

int eth_parse_address(const char *hex_address, uint8_t address_out[20]) {
    if (!hex_address || !address_out) {
        return -1;
    }

    const char *p = hex_address;

    /* Skip 0x prefix */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    /* Must be 40 hex chars */
    if (strlen(p) != 40) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid address length");
        return -1;
    }

    /* Parse hex */
    for (int i = 0; i < 20; i++) {
        unsigned int byte;
        if (sscanf(p + i * 2, "%2x", &byte) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid hex in address");
            return -1;
        }
        address_out[i] = (uint8_t)byte;
    }

    return 0;
}

int eth_send_eth(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount_eth,
    char *tx_hash_out
) {
    if (!private_key || !from_address || !to_address || !amount_eth || !tx_hash_out) {
        return -1;
    }

    /* Get nonce */
    uint64_t nonce;
    if (eth_tx_get_nonce(from_address, &nonce) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get nonce");
        return -1;
    }

    /* Get gas price */
    uint64_t gas_price;
    if (eth_tx_get_gas_price(&gas_price) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get gas price");
        return -1;
    }

    /* Add 10% to gas price for faster confirmation */
    gas_price = gas_price + gas_price / 10;

    /* Parse recipient address */
    uint8_t to[20];
    if (eth_parse_address(to_address, to) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid recipient address");
        return -1;
    }

    /* Parse amount */
    uint8_t value[32];
    if (eth_parse_amount(amount_eth, value) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid amount");
        return -1;
    }

    /* Build transaction */
    eth_tx_t tx;
    eth_tx_init_transfer(&tx, nonce, gas_price, to, value, ETH_CHAIN_MAINNET);

    /* Sign */
    eth_signed_tx_t signed_tx;
    if (eth_tx_sign(&tx, private_key, &signed_tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        return -1;
    }

    /* Send */
    if (eth_tx_send(&signed_tx, tx_hash_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send transaction");
        return -1;
    }

    return 0;
}
