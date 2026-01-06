/**
 * @file eth_erc20.c
 * @brief ERC-20 Token Implementation for Ethereum
 *
 * @author DNA Messenger Team
 * @date 2025-12-14
 */

#include "eth_erc20.h"
#include "eth_tx.h"
#include "eth_wallet.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "ETH_ERC20"

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

/* Known tokens on Ethereum mainnet */
static const eth_erc20_token_t g_known_tokens[] = {
    { ETH_USDT_CONTRACT, "USDT", ETH_USDT_DECIMALS },
    { ETH_USDC_CONTRACT, "USDC", ETH_USDC_DECIMALS },
    { "", "", 0 }  /* Sentinel */
};

int eth_erc20_get_token(const char *symbol, eth_erc20_token_t *token_out) {
    if (!symbol || !token_out) {
        return -1;
    }

    for (int i = 0; g_known_tokens[i].symbol[0] != '\0'; i++) {
        if (strcasecmp(symbol, g_known_tokens[i].symbol) == 0) {
            *token_out = g_known_tokens[i];
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Unknown token symbol: %s", symbol);
    return -1;
}

bool eth_erc20_is_supported(const char *symbol) {
    if (!symbol) return false;

    for (int i = 0; g_known_tokens[i].symbol[0] != '\0'; i++) {
        if (strcasecmp(symbol, g_known_tokens[i].symbol) == 0) {
            return true;
        }
    }
    return false;
}

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
 * Make eth_call RPC request
 */
static int eth_call(const char *to, const char *data, char *result_out, size_t result_size) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build JSON-RPC request */
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

    QGP_LOG_DEBUG(LOG_TAG, "eth_call request: %s", json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, eth_rpc_get_endpoint());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* Configure SSL CA bundle (required for Android) */
    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

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

    QGP_LOG_DEBUG(LOG_TAG, "eth_call response: %s", resp_buf.data);

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

    const char *result = json_object_get_string(jresult);
    if (result) {
        strncpy(result_out, result, result_size - 1);
        result_out[result_size - 1] = '\0';
    }

    json_object_put(resp);
    return 0;
}

/**
 * Parse hex string to uint256 (big-endian 32 bytes)
 */
static int hex_to_uint256(const char *hex, uint8_t out[32]) {
    if (!hex || !out) return -1;

    memset(out, 0, 32);

    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    size_t len = strlen(p);
    if (len > 64) return -1;  /* Too long */

    /* Right-align in 32 bytes */
    size_t start = 32 - (len + 1) / 2;

    for (size_t i = 0; i < len; i++) {
        char c = p[i];
        uint8_t nibble;

        if (c >= '0' && c <= '9') nibble = c - '0';
        else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
        else return -1;

        size_t byte_idx = start + i / 2;
        if (i % 2 == 0 && len % 2 == 0) {
            out[byte_idx] = nibble << 4;
        } else if (i % 2 == 0) {
            out[byte_idx] = nibble;
        } else {
            out[byte_idx] |= nibble;
        }
    }

    return 0;
}

/**
 * Format uint256 with decimals as decimal string
 */
static int uint256_to_decimal_string(const uint8_t value[32], uint8_t decimals,
                                      char *out, size_t out_size) {
    if (!value || !out || out_size < 32) return -1;

    /* For simplicity, handle up to uint64 range */
    /* This covers most practical token balances */
    uint64_t val = 0;
    for (int i = 24; i < 32; i++) {  /* Only last 8 bytes */
        val = (val << 8) | value[i];
    }

    /* Check if there are significant bits in upper bytes */
    bool overflow = false;
    for (int i = 0; i < 24; i++) {
        if (value[i] != 0) {
            overflow = true;
            break;
        }
    }

    if (overflow) {
        /* Very large balance - show in scientific notation or truncate */
        snprintf(out, out_size, "999999999.0");
        return 0;
    }

    if (val == 0) {
        snprintf(out, out_size, "0.0");
        return 0;
    }

    /* Calculate divisor for decimals */
    uint64_t divisor = 1;
    for (int i = 0; i < decimals; i++) {
        divisor *= 10;
    }

    uint64_t whole = val / divisor;
    uint64_t frac = val % divisor;

    if (frac == 0) {
        snprintf(out, out_size, "%llu.0", (unsigned long long)whole);
    } else {
        /* Format fractional part with leading zeros */
        char frac_fmt[16];
        snprintf(frac_fmt, sizeof(frac_fmt), "%%0%ullu", (unsigned)decimals);

        char frac_str[32];
        snprintf(frac_str, sizeof(frac_str), frac_fmt, (unsigned long long)frac);

        /* Trim trailing zeros */
        int last = (int)strlen(frac_str) - 1;
        while (last > 0 && frac_str[last] == '0') {
            frac_str[last--] = '\0';
        }

        snprintf(out, out_size, "%llu.%s", (unsigned long long)whole, frac_str);
    }

    return 0;
}

/**
 * Parse decimal amount string to uint256 with decimals
 */
static int decimal_to_uint256(const char *amount, uint8_t decimals, uint8_t out[32]) {
    if (!amount || !out) return -1;

    memset(out, 0, 32);

    /* Parse decimal number */
    double value = strtod(amount, NULL);
    if (value < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Negative amount: %s", amount);
        return -1;
    }

    /* Multiply by 10^decimals */
    double multiplier = 1.0;
    for (int i = 0; i < decimals; i++) {
        multiplier *= 10.0;
    }

    uint64_t raw_value = (uint64_t)(value * multiplier + 0.5);  /* Round */

    /* Store as big-endian in last 8 bytes */
    for (int i = 0; i < 8; i++) {
        out[31 - i] = (uint8_t)((raw_value >> (i * 8)) & 0xFF);
    }

    return 0;
}

/* ============================================================================
 * ENCODING FUNCTIONS
 * ============================================================================ */

int eth_erc20_encode_balance_of(
    const char *address,
    uint8_t *data_out,
    size_t data_size
) {
    if (!address || !data_out || data_size < 36) {
        return -1;
    }

    /* Function selector: balanceOf(address) = 0x70a08231 */
    data_out[0] = 0x70;
    data_out[1] = 0xa0;
    data_out[2] = 0x82;
    data_out[3] = 0x31;

    /* Pad address to 32 bytes (left-padded with zeros) */
    memset(data_out + 4, 0, 32);

    /* Parse address */
    const char *p = address;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    if (strlen(p) != 40) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid address length");
        return -1;
    }

    /* Address goes in last 20 bytes of 32-byte slot */
    for (int i = 0; i < 20; i++) {
        unsigned int byte;
        if (sscanf(p + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        data_out[4 + 12 + i] = (uint8_t)byte;
    }

    return 36;  /* 4 bytes selector + 32 bytes parameter */
}

int eth_erc20_encode_transfer(
    const char *to_address,
    const char *amount,
    uint8_t decimals,
    uint8_t *data_out,
    size_t data_size
) {
    if (!to_address || !amount || !data_out || data_size < 68) {
        return -1;
    }

    /* Function selector: transfer(address,uint256) = 0xa9059cbb */
    data_out[0] = 0xa9;
    data_out[1] = 0x05;
    data_out[2] = 0x9c;
    data_out[3] = 0xbb;

    /* First parameter: address (32 bytes, left-padded) */
    memset(data_out + 4, 0, 32);

    const char *p = to_address;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    if (strlen(p) != 40) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid to_address length");
        return -1;
    }

    for (int i = 0; i < 20; i++) {
        unsigned int byte;
        if (sscanf(p + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        data_out[4 + 12 + i] = (uint8_t)byte;
    }

    /* Second parameter: uint256 amount */
    if (decimal_to_uint256(amount, decimals, data_out + 36) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse amount: %s", amount);
        return -1;
    }

    return 68;  /* 4 bytes selector + 32 bytes address + 32 bytes amount */
}

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

int eth_erc20_get_balance(
    const char *address,
    const char *contract,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !contract || !balance_out || balance_size < 32) {
        return -1;
    }

    /* Encode balanceOf call */
    uint8_t call_data[36];
    int data_len = eth_erc20_encode_balance_of(address, call_data, sizeof(call_data));
    if (data_len < 0) {
        return -1;
    }

    /* Convert to hex string */
    char data_hex[128];
    data_hex[0] = '0';
    data_hex[1] = 'x';
    for (int i = 0; i < data_len; i++) {
        snprintf(data_hex + 2 + i * 2, 3, "%02x", call_data[i]);
    }

    /* Make eth_call */
    char result[128];
    if (eth_call(contract, data_hex, result, sizeof(result)) != 0) {
        return -1;
    }

    /* Parse result (uint256 balance) */
    uint8_t balance_raw[32];
    if (hex_to_uint256(result, balance_raw) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse balance result: %s", result);
        return -1;
    }

    /* Format as decimal string */
    if (uint256_to_decimal_string(balance_raw, decimals, balance_out, balance_size) != 0) {
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "ERC-20 balance for %s: %s", address, balance_out);
    return 0;
}

int eth_erc20_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
) {
    eth_erc20_token_t token;
    if (eth_erc20_get_token(symbol, &token) != 0) {
        return -1;
    }

    return eth_erc20_get_balance(address, token.contract, token.decimals,
                                  balance_out, balance_size);
}

/* ============================================================================
 * TOKEN TRANSFERS
 * ============================================================================ */

int eth_erc20_send(
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
        !contract || !tx_hash_out) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "ERC-20 send: %s to %s, amount=%s, contract=%s",
                 from_address, to_address, amount, contract);

    /* Validate gas speed */
    if (gas_speed < 0 || gas_speed > 2) {
        gas_speed = ETH_GAS_NORMAL;
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

    /* Apply gas speed multiplier */
    static const int GAS_MULTIPLIERS[] = { 80, 100, 150 };
    gas_price = (gas_price * GAS_MULTIPLIERS[gas_speed]) / 100;

    /* Parse contract address */
    uint8_t contract_bytes[20];
    if (eth_parse_address(contract, contract_bytes) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid contract address");
        return -1;
    }

    /* Encode transfer call data */
    uint8_t call_data[68];
    int data_len = eth_erc20_encode_transfer(to_address, amount, decimals,
                                              call_data, sizeof(call_data));
    if (data_len < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode transfer");
        return -1;
    }

    /* Build transaction */
    eth_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.nonce = nonce;
    tx.gas_price = gas_price;
    tx.gas_limit = ETH_GAS_LIMIT_ERC20;
    memcpy(tx.to, contract_bytes, 20);
    memset(tx.value, 0, 32);  /* No ETH value for token transfer */
    tx.data = call_data;
    tx.data_len = (size_t)data_len;
    tx.chain_id = ETH_CHAIN_MAINNET;

    /* Sign transaction */
    eth_signed_tx_t signed_tx;
    if (eth_tx_sign(&tx, private_key, &signed_tx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        return -1;
    }

    /* Send transaction */
    if (eth_tx_send(&signed_tx, tx_hash_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "ERC-20 transfer sent: %s", tx_hash_out);
    return 0;
}

int eth_erc20_send_by_symbol(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *symbol,
    int gas_speed,
    char *tx_hash_out
) {
    eth_erc20_token_t token;
    if (eth_erc20_get_token(symbol, &token) != 0) {
        return -1;
    }

    return eth_erc20_send(private_key, from_address, to_address, amount,
                          token.contract, token.decimals, gas_speed, tx_hash_out);
}
