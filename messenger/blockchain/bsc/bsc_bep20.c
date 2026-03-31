/**
 * @file bsc_bep20.c
 * @brief BEP-20 Token Implementation for BNB Smart Chain
 *
 * Forked from eth_erc20.c. Uses BSC RPC endpoints for eth_call.
 * Key difference: BSC USDT/USDC use 18 decimals (not 6).
 */

#include "bsc_bep20.h"
#include "bsc_tx.h"
#include "bsc_rpc.h"
#include "bsc_wallet.h"
#include "../ethereum/eth_erc20.h"  /* eth_erc20_encode_transfer, eth_erc20_encode_balance_of */
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "BSC_BEP20"

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

static const bsc_bep20_token_t g_bsc_tokens[] = {
    { BSC_USDT_CONTRACT, "USDT", BSC_USDT_DECIMALS },
    { BSC_USDC_CONTRACT, "USDC", BSC_USDC_DECIMALS },
    { "", "", 0 }  /* Sentinel */
};

int bsc_bep20_get_token(const char *symbol, bsc_bep20_token_t *token_out) {
    if (!symbol || !token_out) return -1;

    for (int i = 0; g_bsc_tokens[i].symbol[0] != '\0'; i++) {
        if (strcasecmp(symbol, g_bsc_tokens[i].symbol) == 0) {
            *token_out = g_bsc_tokens[i];
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Unknown BSC token: %s", symbol);
    return -1;
}

bool bsc_bep20_is_supported(const char *symbol) {
    if (!symbol) return false;
    for (int i = 0; g_bsc_tokens[i].symbol[0] != '\0'; i++) {
        if (strcasecmp(symbol, g_bsc_tokens[i].symbol) == 0) return true;
    }
    return false;
}

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

struct bsc_bep20_resp {
    char *data;
    size_t size;
};

static size_t bsc_bep20_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct bsc_bep20_resp *buf = (struct bsc_bep20_resp *)userp;
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&buf->data[buf->size], contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

/**
 * Make eth_call via BSC RPC
 */
static int bsc_eth_call(const char *to, const char *data, char *result_out, size_t result_size) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "method", json_object_new_string("eth_call"));

    json_object *tx_obj = json_object_new_object();
    json_object_object_add(tx_obj, "to", json_object_new_string(to));
    json_object_object_add(tx_obj, "data", json_object_new_string(data));

    json_object *params = json_object_new_array();
    json_object_array_add(params, tx_obj);
    json_object_array_add(params, json_object_new_string("latest"));
    json_object_object_add(req, "params", params);
    json_object_object_add(req, "id", json_object_new_int(1));

    const char *json_str = json_object_to_json_string(req);

    struct bsc_bep20_resp resp = {0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, bsc_rpc_get_endpoint());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bsc_bep20_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(req);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "BSC eth_call CURL failed: %s", curl_easy_strerror(res));
        if (resp.data) free(resp.data);
        return -1;
    }

    if (!resp.data) return -1;

    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);
    if (!jresp) return -1;

    json_object *jerr = NULL;
    if (json_object_object_get_ex(jresp, "error", &jerr) && jerr) {
        QGP_LOG_ERROR(LOG_TAG, "BSC eth_call RPC error");
        json_object_put(jresp);
        return -1;
    }

    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult)) {
        json_object_put(jresp);
        return -1;
    }

    const char *result = json_object_get_string(jresult);
    if (result) {
        strncpy(result_out, result, result_size - 1);
        result_out[result_size - 1] = '\0';
    }

    json_object_put(jresp);
    return 0;
}

/**
 * Parse hex to uint256 (32 bytes big-endian)
 */
static int hex_to_uint256(const char *hex, uint8_t out[32]) {
    if (!hex || !out) return -1;
    memset(out, 0, 32);

    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    size_t len = strlen(p);
    if (len > 64) return -1;

    size_t start = 32 - (len + 1) / 2;
    for (size_t i = 0; i < len; i++) {
        char c = p[i];
        uint8_t nibble;
        if (c >= '0' && c <= '9') nibble = c - '0';
        else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
        else return -1;

        size_t byte_idx = start + i / 2;
        if (i % 2 == 0 && len % 2 == 0) out[byte_idx] = nibble << 4;
        else if (i % 2 == 0) out[byte_idx] = nibble;
        else out[byte_idx] |= nibble;
    }
    return 0;
}

/**
 * Format uint256 with decimals as decimal string
 */
static int uint256_to_decimal(const uint8_t value[32], uint8_t decimals,
                               char *out, size_t out_size) {
    if (!value || !out || out_size < 32) return -1;
    if (decimals > 19) return -1;

    uint64_t val = 0;
    for (int i = 24; i < 32; i++) val = (val << 8) | value[i];

    bool overflow = false;
    for (int i = 0; i < 24; i++) {
        if (value[i] != 0) { overflow = true; break; }
    }
    if (overflow) {
        snprintf(out, out_size, "999999999.0");
        return 0;
    }
    if (val == 0) {
        snprintf(out, out_size, "0.0");
        return 0;
    }

    uint64_t divisor = 1;
    for (int i = 0; i < decimals; i++) divisor *= 10;

    uint64_t whole = val / divisor;
    uint64_t frac = val % divisor;

    if (frac == 0) {
        snprintf(out, out_size, "%llu.0", (unsigned long long)whole);
    } else {
        char frac_fmt[16];
        snprintf(frac_fmt, sizeof(frac_fmt), "%%0%ullu", (unsigned)decimals);
        char frac_str[32];
        snprintf(frac_str, sizeof(frac_str), frac_fmt, (unsigned long long)frac);
        int last = (int)strlen(frac_str) - 1;
        while (last > 0 && frac_str[last] == '0') frac_str[last--] = '\0';
        snprintf(out, out_size, "%llu.%s", (unsigned long long)whole, frac_str);
    }
    return 0;
}

/**
 * Parse decimal amount to uint256 with variable decimals (string-based, no float)
 */
static int decimal_to_uint256(const char *amount, uint8_t decimals, uint8_t out[32]) {
    if (!amount || !out) return -1;
    if (decimals > 19) return -1;

    memset(out, 0, 32);

    const char *p = amount;
    while (*p == ' ') p++;
    if (*p == '\0') return -1;

    const char *dot = strchr(p, '.');

    uint64_t whole = 0;
    const char *end = dot ? dot : p + strlen(p);
    for (const char *c = p; c < end; c++) {
        if (*c < '0' || *c > '9') return -1;
        uint64_t prev = whole;
        whole = whole * 10 + (*c - '0');
        if (whole < prev) return -1;
    }

    uint64_t frac = 0;
    if (dot) {
        const char *frac_start = dot + 1;
        int frac_digits = 0;
        for (const char *c = frac_start; *c && frac_digits < decimals; c++) {
            if (*c < '0' || *c > '9') return -1;
            frac = frac * 10 + (*c - '0');
            frac_digits++;
        }
        for (int i = frac_digits; i < decimals; i++) frac *= 10;
    }

    uint64_t multiplier = 1;
    for (int i = 0; i < decimals; i++) multiplier *= 10;

    if (whole > UINT64_MAX / multiplier) return -1;
    uint64_t total = whole * multiplier;
    if (total > UINT64_MAX - frac) return -1;
    total += frac;

    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)((total >> (i * 8)) & 0xFF);
    return 0;
}

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

int bsc_bep20_get_balance(
    const char *address,
    const char *contract,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !contract || !balance_out || balance_size < 32) return -1;

    /* Encode balanceOf call (same ABI as ERC-20) */
    uint8_t call_data[36];
    int data_len = eth_erc20_encode_balance_of(address, call_data, sizeof(call_data));
    if (data_len < 0) return -1;

    char data_hex[128];
    data_hex[0] = '0'; data_hex[1] = 'x';
    for (int i = 0; i < data_len; i++) snprintf(data_hex + 2 + i * 2, 3, "%02x", call_data[i]);

    char result[128];
    if (bsc_eth_call(contract, data_hex, result, sizeof(result)) != 0) return -1;

    uint8_t balance_raw[32];
    if (hex_to_uint256(result, balance_raw) != 0) return -1;

    if (uint256_to_decimal(balance_raw, decimals, balance_out, balance_size) != 0) return -1;

    QGP_LOG_DEBUG(LOG_TAG, "BEP-20 balance for %s: %s", address, balance_out);
    return 0;
}

int bsc_bep20_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
) {
    bsc_bep20_token_t token;
    if (bsc_bep20_get_token(symbol, &token) != 0) return -1;
    return bsc_bep20_get_balance(address, token.contract, token.decimals,
                                  balance_out, balance_size);
}

/* ============================================================================
 * TOKEN TRANSFERS
 * ============================================================================ */

int bsc_bep20_send(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *contract,
    uint8_t decimals,
    int gas_speed,
    char *tx_hash_out
) {
    if (!private_key || !from_address || !to_address || !amount ||
        !contract || !tx_hash_out) return -1;

    QGP_LOG_INFO(LOG_TAG, "BEP-20 send: %s to %s, amount=%s, contract=%s",
                 from_address, to_address, amount, contract);

    if (gas_speed < 0 || gas_speed > 2) gas_speed = BSC_GAS_NORMAL;

    /* Get nonce */
    uint64_t nonce;
    if (bsc_tx_get_nonce(from_address, &nonce) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get BSC nonce");
        return -1;
    }

    /* Get gas price */
    uint64_t gas_price;
    if (bsc_tx_get_gas_price(&gas_price) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get BSC gas price");
        return -1;
    }

    static const int GAS_MULT[] = { 100, 110, 150 };
    gas_price = (gas_price * GAS_MULT[gas_speed]) / 100;

    /* Parse contract address */
    uint8_t contract_bytes[20];
    if (eth_parse_address(contract, contract_bytes) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid contract address");
        return -1;
    }

    /* Encode transfer(address,uint256) — same ABI as ERC-20 */
    uint8_t call_data[68];

    /* Function selector: transfer = 0xa9059cbb */
    call_data[0] = 0xa9; call_data[1] = 0x05;
    call_data[2] = 0x9c; call_data[3] = 0xbb;

    /* First param: to address (32 bytes, left-padded) */
    memset(call_data + 4, 0, 32);
    const char *p = to_address;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (strlen(p) != 40) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid to_address length");
        return -1;
    }
    for (int i = 0; i < 20; i++) {
        unsigned int byte;
        if (sscanf(p + i * 2, "%2x", &byte) != 1) return -1;
        call_data[4 + 12 + i] = (uint8_t)byte;
    }

    /* Second param: uint256 amount */
    if (decimal_to_uint256(amount, decimals, call_data + 36) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse amount: %s", amount);
        return -1;
    }

    /* Build TX with chain_id=56 */
    eth_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.nonce = nonce;
    tx.gas_price = gas_price;
    tx.gas_limit = BSC_GAS_LIMIT_BEP20_TX;
    memcpy(tx.to, contract_bytes, 20);
    memset(tx.value, 0, 32);
    tx.data = call_data;
    tx.data_len = 68;
    tx.chain_id = BSC_CHAIN_MAINNET;

    /* Sign */
    eth_signed_tx_t signed_tx;
    if (eth_tx_sign(&tx, private_key, &signed_tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign BEP-20 TX");
        return -1;
    }

    /* Send via BSC RPC */
    if (bsc_tx_send(&signed_tx, tx_hash_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send BEP-20 TX");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "BEP-20 transfer sent: %s", tx_hash_out);
    return 0;
}

int bsc_bep20_send_by_symbol(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *symbol,
    int gas_speed,
    char *tx_hash_out
) {
    bsc_bep20_token_t token;
    if (bsc_bep20_get_token(symbol, &token) != 0) return -1;

    return bsc_bep20_send(private_key, from_address, to_address, amount,
                           token.contract, token.decimals, gas_speed, tx_hash_out);
}
