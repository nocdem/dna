/**
 * @file trx_tx.c
 * @brief TRON Transaction Implementation
 *
 * Uses TronGrid API for transaction creation and broadcasting.
 * Signs transactions locally with secp256k1.
 *
 * @author DNA Messenger Team
 * @date 2025-12-14
 */

#include "trx_tx.h"
#include "trx_wallet.h"
#include "trx_base58.h"
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

#define LOG_TAG "TRX_TX"

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

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
 * Make TronGrid API POST request
 */
static int trongrid_post(const char *endpoint, json_object *body, json_object **response_out) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build URL */
    char url[512];
    snprintf(url, sizeof(url), "%s%s", trx_rpc_get_endpoint(), endpoint);

    const char *json_str = json_object_to_json_string(body);

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid POST %s: %s", endpoint, json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    if (!resp_buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "TronGrid response: %.500s", resp_buf.data);

    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse response");
        return -1;
    }

    /* Check for error */
    json_object *jerr = NULL;
    if (json_object_object_get_ex(resp, "Error", &jerr) ||
        json_object_object_get_ex(resp, "error", &jerr)) {
        const char *err_msg = json_object_get_string(jerr);
        QGP_LOG_ERROR(LOG_TAG, "TronGrid error: %s", err_msg ? err_msg : "Unknown");
        json_object_put(resp);
        return -1;
    }

    *response_out = resp;
    return 0;
}

/**
 * Parse hex string to bytes
 */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_size) {
    if (!hex || !out) return -1;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    if (hex_len / 2 > out_size) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }

    return (int)(hex_len / 2);
}

/**
 * Convert bytes to hex string
 */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_out + i * 2, 3, "%02x", bytes[i]);
    }
}

/* ============================================================================
 * TRANSACTION CREATION
 * ============================================================================ */

int trx_tx_create_transfer(
    const char *from_address,
    const char *to_address,
    uint64_t amount_sun,
    trx_tx_t *tx_out
) {
    if (!from_address || !to_address || !tx_out) {
        return -1;
    }

    memset(tx_out, 0, sizeof(*tx_out));

    QGP_LOG_INFO(LOG_TAG, "Creating TRX transfer: %s -> %s, %llu SUN",
                 from_address, to_address, (unsigned long long)amount_sun);

    /* Build request body */
    json_object *body = json_object_new_object();
    json_object_object_add(body, "owner_address", json_object_new_string(from_address));
    json_object_object_add(body, "to_address", json_object_new_string(to_address));
    json_object_object_add(body, "amount", json_object_new_int64((int64_t)amount_sun));
    json_object_object_add(body, "visible", json_object_new_boolean(1));

    /* Call createtransaction endpoint */
    json_object *resp = NULL;
    int ret = trongrid_post("/wallet/createtransaction", body, &resp);
    json_object_put(body);

    if (ret != 0 || !resp) {
        return -1;
    }

    /* Extract txID */
    json_object *jtxid = NULL;
    if (!json_object_object_get_ex(resp, "txID", &jtxid)) {
        QGP_LOG_ERROR(LOG_TAG, "No txID in response");
        json_object_put(resp);
        return -1;
    }

    strncpy(tx_out->tx_id, json_object_get_string(jtxid), sizeof(tx_out->tx_id) - 1);

    /* Extract raw_data_hex */
    json_object *jraw_data_hex = NULL;
    if (json_object_object_get_ex(resp, "raw_data_hex", &jraw_data_hex)) {
        const char *raw_hex = json_object_get_string(jraw_data_hex);
        if (raw_hex) {
            int len = hex_to_bytes(raw_hex, tx_out->raw_data, sizeof(tx_out->raw_data));
            if (len > 0) {
                tx_out->raw_data_len = (size_t)len;
            }
        }
    }

    /* Extract raw_data JSON object for broadcast */
    json_object *jraw_data = NULL;
    if (json_object_object_get_ex(resp, "raw_data", &jraw_data)) {
        const char *raw_json = json_object_to_json_string(jraw_data);
        if (raw_json) {
            strncpy(tx_out->raw_data_json, raw_json, sizeof(tx_out->raw_data_json) - 1);
            tx_out->raw_data_json[sizeof(tx_out->raw_data_json) - 1] = '\0';
        }
    }

    json_object_put(resp);

    QGP_LOG_INFO(LOG_TAG, "Transaction created: %s", tx_out->tx_id);
    return 0;
}

int trx_tx_create_trc20_transfer(
    const char *from_address,
    const char *to_address,
    const char *contract,
    const char *amount,
    trx_tx_t *tx_out
) {
    if (!from_address || !to_address || !contract || !amount || !tx_out) {
        return -1;
    }

    memset(tx_out, 0, sizeof(*tx_out));

    QGP_LOG_INFO(LOG_TAG, "Creating TRC-20 transfer: %s -> %s, amount=%s, contract=%s",
                 from_address, to_address, amount, contract);

    /* Convert to_address to hex for parameter encoding */
    uint8_t to_raw[21];
    if (trx_address_from_base58(to_address, to_raw) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid to_address");
        return -1;
    }

    /* Build transfer(address,uint256) function call
     * Function selector: a9059cbb
     * Parameter 1: address (32 bytes, left-padded)
     * Parameter 2: uint256 amount (32 bytes)
     */
    char parameter[129];  /* 64 bytes = 128 hex chars + null */
    memset(parameter, '0', 128);
    parameter[128] = '\0';

    /* Address in last 40 chars of first 64 chars (skip 0x41 prefix) */
    for (int i = 0; i < 20; i++) {
        snprintf(parameter + 24 + i * 2, 3, "%02x", to_raw[1 + i]);
    }

    /* Amount (parse as decimal, convert to uint256) */
    /* Note: amount should already have decimals applied */
    uint64_t amount_raw = strtoull(amount, NULL, 10);
    char amount_hex[17];
    snprintf(amount_hex, sizeof(amount_hex), "%016llx", (unsigned long long)amount_raw);
    memcpy(parameter + 64 + 48, amount_hex, 16);  /* Last 16 hex chars of second 64 */

    /* Build request body */
    json_object *body = json_object_new_object();
    json_object_object_add(body, "owner_address", json_object_new_string(from_address));
    json_object_object_add(body, "contract_address", json_object_new_string(contract));
    json_object_object_add(body, "function_selector", json_object_new_string("transfer(address,uint256)"));
    json_object_object_add(body, "parameter", json_object_new_string(parameter));
    json_object_object_add(body, "fee_limit", json_object_new_int64(100000000));  /* 100 TRX max fee */
    json_object_object_add(body, "visible", json_object_new_boolean(1));

    /* Call triggersmartcontract endpoint */
    json_object *resp = NULL;
    int ret = trongrid_post("/wallet/triggersmartcontract", body, &resp);
    json_object_put(body);

    if (ret != 0 || !resp) {
        return -1;
    }

    /* Extract transaction from response */
    json_object *jtx = NULL;
    if (!json_object_object_get_ex(resp, "transaction", &jtx)) {
        QGP_LOG_ERROR(LOG_TAG, "No transaction in response");
        json_object_put(resp);
        return -1;
    }

    /* Extract txID */
    json_object *jtxid = NULL;
    if (!json_object_object_get_ex(jtx, "txID", &jtxid)) {
        QGP_LOG_ERROR(LOG_TAG, "No txID in transaction");
        json_object_put(resp);
        return -1;
    }

    strncpy(tx_out->tx_id, json_object_get_string(jtxid), sizeof(tx_out->tx_id) - 1);

    /* Extract raw_data_hex */
    json_object *jraw_data_hex = NULL;
    if (json_object_object_get_ex(jtx, "raw_data_hex", &jraw_data_hex)) {
        const char *raw_hex = json_object_get_string(jraw_data_hex);
        if (raw_hex) {
            int len = hex_to_bytes(raw_hex, tx_out->raw_data, sizeof(tx_out->raw_data));
            if (len > 0) {
                tx_out->raw_data_len = (size_t)len;
            }
        }
    }

    /* Extract raw_data JSON object for broadcast */
    json_object *jraw_data = NULL;
    if (json_object_object_get_ex(jtx, "raw_data", &jraw_data)) {
        const char *raw_json = json_object_to_json_string(jraw_data);
        if (raw_json) {
            strncpy(tx_out->raw_data_json, raw_json, sizeof(tx_out->raw_data_json) - 1);
            tx_out->raw_data_json[sizeof(tx_out->raw_data_json) - 1] = '\0';
        }
    }

    json_object_put(resp);

    QGP_LOG_INFO(LOG_TAG, "TRC-20 transaction created: %s", tx_out->tx_id);
    return 0;
}

/* ============================================================================
 * TRANSACTION SIGNING
 * ============================================================================ */

int trx_tx_sign(
    const trx_tx_t *tx,
    const uint8_t private_key[32],
    trx_signed_tx_t *signed_out
) {
    if (!tx || !private_key || !signed_out) {
        return -1;
    }

    memset(signed_out, 0, sizeof(*signed_out));

    /* Copy transaction data */
    strncpy(signed_out->tx_id, tx->tx_id, sizeof(signed_out->tx_id) - 1);
    memcpy(signed_out->raw_data, tx->raw_data, tx->raw_data_len);
    signed_out->raw_data_len = tx->raw_data_len;
    strncpy(signed_out->raw_data_json, tx->raw_data_json, sizeof(signed_out->raw_data_json) - 1);
    signed_out->raw_data_json[sizeof(signed_out->raw_data_json) - 1] = '\0';

    /* Parse txID (32 bytes hex) to bytes */
    uint8_t tx_hash[32];
    if (hex_to_bytes(tx->tx_id, tx_hash, 32) != 32) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid txID format");
        return -1;
    }

    /* Create secp256k1 context */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create secp256k1 context");
        return -1;
    }

    /* Sign with recoverable signature */
    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &sig, tx_hash, private_key, NULL, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    /* Serialize signature */
    uint8_t sig_data[64];
    int recovery_id;
    if (secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_data, &recovery_id, &sig) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize signature");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_context_destroy(ctx);

    /* TRON signature format: r (32 bytes) + s (32 bytes) + v (1 byte) */
    memcpy(signed_out->signature, sig_data, 64);
    signed_out->signature[64] = (uint8_t)(recovery_id + 27);

    QGP_LOG_INFO(LOG_TAG, "Transaction signed: %s", signed_out->tx_id);
    return 0;
}

/* ============================================================================
 * TRANSACTION BROADCAST
 * ============================================================================ */

int trx_tx_broadcast(
    const trx_signed_tx_t *signed_tx,
    char *tx_id_out
) {
    if (!signed_tx || !tx_id_out) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Broadcasting transaction: %s", signed_tx->tx_id);

    /* Convert signature to hex */
    char sig_hex[131];
    bytes_to_hex(signed_tx->signature, 65, sig_hex);

    /* Convert raw_data to hex */
    char *raw_data_hex = malloc(signed_tx->raw_data_len * 2 + 1);
    if (!raw_data_hex) {
        return -1;
    }
    bytes_to_hex(signed_tx->raw_data, signed_tx->raw_data_len, raw_data_hex);

    /* Build request body */
    json_object *body = json_object_new_object();
    json_object_object_add(body, "txID", json_object_new_string(signed_tx->tx_id));
    json_object_object_add(body, "raw_data_hex", json_object_new_string(raw_data_hex));

    /* Include raw_data JSON object (required by TronGrid) */
    if (signed_tx->raw_data_json[0] != '\0') {
        json_object *raw_data_obj = json_tokener_parse(signed_tx->raw_data_json);
        if (raw_data_obj) {
            json_object_object_add(body, "raw_data", raw_data_obj);
        }
    }

    json_object *sig_array = json_object_new_array();
    json_object_array_add(sig_array, json_object_new_string(sig_hex));
    json_object_object_add(body, "signature", sig_array);

    /* Must match visible flag from createtransaction (true = Base58 addresses) */
    json_object_object_add(body, "visible", json_object_new_boolean(1));

    free(raw_data_hex);

    /* Call broadcasttransaction endpoint */
    json_object *resp = NULL;
    int ret = trongrid_post("/wallet/broadcasttransaction", body, &resp);
    json_object_put(body);

    if (ret != 0 || !resp) {
        return -1;
    }

    /* Check result */
    json_object *jresult = NULL;
    if (json_object_object_get_ex(resp, "result", &jresult)) {
        if (!json_object_get_boolean(jresult)) {
            json_object *jcode = NULL;
            json_object *jmsg = NULL;
            json_object_object_get_ex(resp, "code", &jcode);
            json_object_object_get_ex(resp, "message", &jmsg);
            QGP_LOG_ERROR(LOG_TAG, "Broadcast failed: %s - %s",
                         jcode ? json_object_get_string(jcode) : "Unknown",
                         jmsg ? json_object_get_string(jmsg) : "No message");
            json_object_put(resp);
            return -1;
        }
    }

    json_object_put(resp);

    /* Return transaction ID */
    strncpy(tx_id_out, signed_tx->tx_id, 64);
    tx_id_out[64] = '\0';

    QGP_LOG_INFO(LOG_TAG, "Transaction broadcast success: %s", tx_id_out);
    return 0;
}

/* ============================================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================================ */

int trx_parse_amount(const char *amount_str, uint64_t *sun_out) {
    if (!amount_str || !sun_out) {
        return -1;
    }

    double trx = strtod(amount_str, NULL);
    if (trx < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Negative amount: %s", amount_str);
        return -1;
    }

    *sun_out = (uint64_t)(trx * TRX_SUN_PER_TRX + 0.5);  /* Round */

    QGP_LOG_DEBUG(LOG_TAG, "Parsed %s TRX = %llu SUN", amount_str, (unsigned long long)*sun_out);
    return 0;
}

int trx_send_trx(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount_trx,
    char *tx_id_out
) {
    if (!private_key || !from_address || !to_address || !amount_trx || !tx_id_out) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Sending TRX: %s -> %s, amount=%s",
                 from_address, to_address, amount_trx);

    /* Parse amount */
    uint64_t amount_sun;
    if (trx_parse_amount(amount_trx, &amount_sun) != 0) {
        return -1;
    }

    /* Create transaction */
    trx_tx_t tx;
    if (trx_tx_create_transfer(from_address, to_address, amount_sun, &tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create transaction");
        return -1;
    }

    /* Sign transaction */
    trx_signed_tx_t signed_tx;
    if (trx_tx_sign(&tx, private_key, &signed_tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        return -1;
    }

    /* Broadcast transaction */
    if (trx_tx_broadcast(&signed_tx, tx_id_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to broadcast transaction");
        return -1;
    }

    return 0;
}

int trx_hex_to_base58(const char *hex_address, char *base58_out, size_t base58_size) {
    if (!hex_address || !base58_out || base58_size < 35) {
        return -1;
    }

    /* Parse hex (should be 42 chars = 21 bytes) */
    uint8_t raw[21];
    if (hex_to_bytes(hex_address, raw, 21) != 21) {
        return -1;
    }

    return trx_address_to_base58(raw, base58_out, base58_size);
}

int trx_base58_to_hex(const char *base58, char *hex_out, size_t hex_size) {
    if (!base58 || !hex_out || hex_size < 43) {
        return -1;
    }

    uint8_t raw[21];
    if (trx_address_from_base58(base58, raw) != 0) {
        return -1;
    }

    bytes_to_hex(raw, 21, hex_out);
    hex_out[42] = '\0';

    return 0;
}
