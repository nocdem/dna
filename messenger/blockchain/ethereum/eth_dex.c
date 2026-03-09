/**
 * @file eth_dex.c
 * @brief Ethereum DEX Quote Implementation (Uniswap v2)
 *
 * Fetches on-chain reserves from Uniswap v2 pair contracts via eth_call,
 * then calculates swap output using constant product formula.
 *
 * Uniswap v2 fee: 0.3% (997/1000)
 * Formula: amount_out = (reserve_out * amount_in * 997) / (reserve_in * 1000 + amount_in * 997)
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#include "eth_dex.h"
#include "eth_wallet.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "ETH_DEX"

/* ============================================================================
 * KNOWN UNISWAP V2 PAIRS
 * ============================================================================
 * token0/token1 are sorted by address (Uniswap v2 convention).
 * getReserves() returns (reserve0, reserve1, blockTimestampLast).
 * ============================================================================ */

typedef struct {
    const char *token_a;        /* First token symbol (user-facing) */
    const char *token_b;        /* Second token symbol (user-facing) */
    const char *pair_address;   /* Uniswap v2 pair contract */
    uint8_t decimals_a;         /* token_a decimals */
    uint8_t decimals_b;         /* token_b decimals */
    bool a_is_token0;           /* true if token_a is the lower address (token0) */
} uniswap_pair_t;

/*
 * WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
 * USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48  (6 decimals)
 * USDT: 0xdAC17F958D2ee523a2206206994597C13D831ec7  (6 decimals)
 *
 * Address ordering (determines token0/token1):
 *   USDC (0xA0b8) < WETH (0xC02a) < USDT (0xdAC1)
 *
 * ETH/USDC pair: token0=USDC, token1=WETH  → a_is_token0=false (ETH is token1)
 * ETH/USDT pair: token0=WETH, token1=USDT  → a_is_token0=true  (ETH is token0)
 */
static const uniswap_pair_t known_pairs[] = {
    {
        .token_a = "ETH",
        .token_b = "USDC",
        .pair_address = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",
        .decimals_a = 18,
        .decimals_b = 6,
        .a_is_token0 = false,   /* USDC < WETH, so WETH(ETH) is token1 */
    },
    {
        .token_a = "ETH",
        .token_b = "USDT",
        .pair_address = "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852",
        .decimals_a = 18,
        .decimals_b = 6,
        .a_is_token0 = true,    /* WETH < USDT, so WETH(ETH) is token0 */
    },
};

#define NUM_KNOWN_PAIRS (sizeof(known_pairs) / sizeof(known_pairs[0]))

/* ============================================================================
 * RPC HELPERS (with fallback)
 * ============================================================================ */

/* Endpoint array matching eth_wallet.h defines */
static const char *g_eth_dex_endpoints[] = {
    ETH_RPC_ENDPOINT_DEFAULT,
    ETH_RPC_ENDPOINT_FALLBACK1,
    ETH_RPC_ENDPOINT_FALLBACK2,
    ETH_RPC_ENDPOINT_FALLBACK3
};
static int g_eth_dex_current_idx = 0;

struct dex_response_buffer {
    char *data;
    size_t size;
};

static size_t dex_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct dex_response_buffer *buf = (struct dex_response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

/**
 * Make eth_call to a contract on a single endpoint
 * Returns: 0=success, -1=network error (retry), -2=RPC error (don't retry)
 */
static int eth_dex_call_single(const char *endpoint, const char *to,
                               const char *data, char *result_hex, size_t result_size) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* Build JSON-RPC request for eth_call */
    char body[512];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\","
        "\"params\":[{\"to\":\"%s\",\"data\":\"%s\"},\"latest\"],\"id\":1}",
        to, data);

    struct dex_response_buffer resp = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dex_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "CURL failed (%s): %s", endpoint, curl_easy_strerror(res));
        if (resp.data) free(resp.data);
        return -1;
    }

    if (!resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "Empty response from %s", endpoint);
        return -1;
    }

    /* Parse JSON response */
    json_object *jresp = json_tokener_parse(resp.data);
    free(resp.data);

    if (!jresp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON from %s", endpoint);
        return -1;
    }

    json_object *jerr = NULL;
    if (json_object_object_get_ex(jresp, "error", &jerr) && jerr) {
        json_object *jmsg = NULL;
        const char *msg = "unknown";
        if (json_object_object_get_ex(jerr, "message", &jmsg))
            msg = json_object_get_string(jmsg);
        QGP_LOG_ERROR(LOG_TAG, "RPC error from %s: %s", endpoint, msg);
        json_object_put(jresp);
        return -2;
    }

    json_object *jresult = NULL;
    if (!json_object_object_get_ex(jresp, "result", &jresult)) {
        QGP_LOG_ERROR(LOG_TAG, "No result from %s", endpoint);
        json_object_put(jresp);
        return -1;
    }

    const char *hex = json_object_get_string(jresult);
    if (!hex) {
        json_object_put(jresp);
        return -1;
    }

    snprintf(result_hex, result_size, "%s", hex);
    json_object_put(jresp);
    return 0;
}

/**
 * eth_call with fallback across all endpoints
 */
static int eth_dex_call(const char *to, const char *data,
                        char *result_hex, size_t result_size) {
    int start_idx = g_eth_dex_current_idx;

    for (int attempt = 0; attempt < ETH_RPC_ENDPOINT_COUNT; attempt++) {
        int idx = (start_idx + attempt) % ETH_RPC_ENDPOINT_COUNT;
        const char *endpoint = g_eth_dex_endpoints[idx];

        int rc = eth_dex_call_single(endpoint, to, data, result_hex, result_size);
        if (rc == 0) {
            if (idx != g_eth_dex_current_idx) {
                g_eth_dex_current_idx = idx;
                QGP_LOG_INFO(LOG_TAG, "Switched to endpoint: %s", endpoint);
            }
            return 0;
        }
        if (rc == -2) return -1;  /* RPC error — don't retry */

        QGP_LOG_WARN(LOG_TAG, "Endpoint failed: %s, trying next...", endpoint);
    }

    QGP_LOG_ERROR(LOG_TAG, "All ETH RPC endpoints failed for eth_call");
    return -1;
}

/* ============================================================================
 * RESERVES PARSING + CPMM MATH
 * ============================================================================ */

/**
 * Parse a uint256 from a 64-char hex slice into __uint128_t
 * Only parses the lower 128 bits (sufficient for reserves)
 */
static __uint128_t parse_uint256_lower128(const char *hex64) {
    /* Skip leading zeros, parse from the right (lower 32 hex chars = 128 bits) */
    __uint128_t val = 0;
    for (int i = 0; i < 64; i++) {
        char c = hex64[i];
        uint8_t nibble;
        if (c >= '0' && c <= '9')      nibble = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') nibble = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') nibble = (uint8_t)(c - 'A' + 10);
        else return 0;
        val = (val << 4) | nibble;
    }
    return val;
}

/**
 * Parse decimal string to __uint128_t with given decimals
 * "1.5" with 18 decimals → 1500000000000000000
 */
static __uint128_t parse_decimal_to_raw(const char *amount, uint8_t decimals) {
    __uint128_t whole = 0;
    __uint128_t frac = 0;
    int frac_digits = 0;
    bool in_frac = false;

    for (const char *p = amount; *p; p++) {
        if (*p == '.') {
            in_frac = true;
            continue;
        }
        if (*p < '0' || *p > '9') break;
        if (!in_frac) {
            whole = whole * 10 + (uint8_t)(*p - '0');
        } else if (frac_digits < decimals) {
            frac = frac * 10 + (uint8_t)(*p - '0');
            frac_digits++;
        }
    }

    /* Scale whole part */
    __uint128_t scale = 1;
    for (int i = 0; i < decimals; i++) scale *= 10;

    /* Scale fractional part to fill remaining decimal places */
    __uint128_t frac_scale = 1;
    for (int i = 0; i < (decimals - frac_digits); i++) frac_scale *= 10;

    return whole * scale + frac * frac_scale;
}

/**
 * Format raw amount to decimal string
 */
static void format_raw_to_decimal(char *buf, size_t buf_size, __uint128_t raw, uint8_t decimals) {
    __uint128_t scale = 1;
    for (int i = 0; i < decimals; i++) scale *= 10;

    __uint128_t whole = raw / scale;
    __uint128_t frac  = raw % scale;

    /* Convert whole to string */
    char whole_str[42] = "0";
    if (whole > 0) {
        char tmp[42];
        int pos = 0;
        __uint128_t v = whole;
        while (v > 0) {
            tmp[pos++] = '0' + (char)(v % 10);
            v /= 10;
        }
        for (int i = 0; i < pos; i++) whole_str[i] = tmp[pos - 1 - i];
        whole_str[pos] = '\0';
    }

    /* Convert frac to zero-padded string */
    char frac_str[42];
    {
        char tmp[42];
        int pos = 0;
        __uint128_t v = frac;
        if (v == 0) {
            tmp[pos++] = '0';
        } else {
            while (v > 0) {
                tmp[pos++] = '0' + (char)(v % 10);
                v /= 10;
            }
        }
        /* Zero-pad to 'decimals' digits */
        int pad = decimals - pos;
        int j = 0;
        for (int i = 0; i < pad; i++) frac_str[j++] = '0';
        for (int i = pos - 1; i >= 0; i--) frac_str[j++] = tmp[i];
        frac_str[j] = '\0';
    }

    /* Trim trailing zeros from frac (keep at least 2) */
    int frac_len = (int)strlen(frac_str);
    while (frac_len > 2 && frac_str[frac_len - 1] == '0') {
        frac_str[--frac_len] = '\0';
    }

    snprintf(buf, buf_size, "%s.%s", whole_str, frac_str);
}

/* ============================================================================
 * PAIR LOOKUP
 * ============================================================================ */

static int find_pair(const char *from_token, const char *to_token, bool *reversed) {
    for (size_t i = 0; i < NUM_KNOWN_PAIRS; i++) {
        if (strcasecmp(known_pairs[i].token_a, from_token) == 0 &&
            strcasecmp(known_pairs[i].token_b, to_token) == 0) {
            *reversed = false;
            return (int)i;
        }
        if (strcasecmp(known_pairs[i].token_b, from_token) == 0 &&
            strcasecmp(known_pairs[i].token_a, to_token) == 0) {
            *reversed = true;
            return (int)i;
        }
    }
    return -1;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int eth_dex_get_quote(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    eth_dex_quote_t *quote_out
) {
    if (!from_token || !to_token || !amount_in || !quote_out) return -1;

    bool reversed = false;
    int pair_idx = find_pair(from_token, to_token, &reversed);
    if (pair_idx < 0) {
        QGP_LOG_WARN(LOG_TAG, "No Uniswap v2 pair for %s/%s", from_token, to_token);
        return -2;
    }

    const uniswap_pair_t *pair = &known_pairs[pair_idx];

    /* Determine decimals for from/to */
    uint8_t from_dec = reversed ? pair->decimals_b : pair->decimals_a;
    uint8_t to_dec   = reversed ? pair->decimals_a : pair->decimals_b;

    /* Step 1: Call getReserves() on pair contract
     * Selector: 0x0902f1ac (no arguments) */
    char result_hex[256] = {0};
    int rc = eth_dex_call(pair->pair_address, "0x0902f1ac", result_hex, sizeof(result_hex));
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch reserves for %s", pair->pair_address);
        return -1;
    }

    /* Response: 0x + 64 hex (reserve0) + 64 hex (reserve1) + 64 hex (blockTimestampLast)
     * Total: 2 + 192 = 194 chars minimum */
    const char *hex = result_hex;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;

    if (strlen(hex) < 128) {  /* Need at least reserve0 + reserve1 */
        QGP_LOG_ERROR(LOG_TAG, "Response too short: %zu chars", strlen(hex));
        return -1;
    }

    __uint128_t reserve0 = parse_uint256_lower128(hex);
    __uint128_t reserve1 = parse_uint256_lower128(hex + 64);

    QGP_LOG_DEBUG(LOG_TAG, "Reserves fetched for %s/%s", pair->token_a, pair->token_b);

    if (reserve0 == 0 || reserve1 == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Zero reserves in pool %s", pair->pair_address);
        return -1;
    }

    /* Step 2: Determine which reserve is input/output
     * If !reversed: from=token_a, to=token_b
     *   if a_is_token0: reserve_in=reserve0, reserve_out=reserve1
     *   else:           reserve_in=reserve1, reserve_out=reserve0
     * If reversed: from=token_b, to=token_a — swap input/output */
    __uint128_t reserve_in, reserve_out;
    if (!reversed) {
        if (pair->a_is_token0) {
            reserve_in  = reserve0;
            reserve_out = reserve1;
        } else {
            reserve_in  = reserve1;
            reserve_out = reserve0;
        }
    } else {
        if (pair->a_is_token0) {
            reserve_in  = reserve1;
            reserve_out = reserve0;
        } else {
            reserve_in  = reserve0;
            reserve_out = reserve1;
        }
    }

    /* Step 3: Parse input amount */
    __uint128_t raw_in = parse_decimal_to_raw(amount_in, from_dec);
    if (raw_in == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid input amount: %s", amount_in);
        return -1;
    }

    /* Step 4: CPMM formula — Uniswap v2 fee is 0.3% (997/1000)
     * amount_out = (reserve_out * amount_in_with_fee) / (reserve_in * 1000 + amount_in_with_fee)
     * where amount_in_with_fee = amount_in * 997 */
    __uint128_t in_with_fee = raw_in * 997;
    __uint128_t numerator   = reserve_out * in_with_fee;
    __uint128_t denominator = reserve_in * 1000 + in_with_fee;

    if (denominator == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Denominator overflow/zero");
        return -1;
    }

    __uint128_t raw_out = numerator / denominator;

    /* Step 5: Calculate price impact
     * Spot price = reserve_out / reserve_in (adjusted for decimals)
     * Execution price = raw_out / raw_in (adjusted for decimals)
     * Impact = (spot - execution) / spot * 100 */
    double spot_price = ((double)reserve_out / (double)reserve_in);
    double exec_price = ((double)raw_out / (double)raw_in);
    /* Adjust for decimal difference */
    /* spot and exec use raw amounts, so decimal difference is already encoded */
    double impact_pct = 0.0;
    if (spot_price > 0.0) {
        impact_pct = (1.0 - exec_price / spot_price) * 100.0;
        if (impact_pct < 0.0) impact_pct = 0.0;
    }

    /* Step 6: Calculate fee in input token terms */
    __uint128_t fee_raw = raw_in * 3 / 1000;  /* 0.3% */

    /* Step 7: Calculate unit price (1 from_token = X to_token) */
    __uint128_t one_unit_in = 1;
    for (int i = 0; i < from_dec; i++) one_unit_in *= 10;
    __uint128_t one_in_fee = one_unit_in * 997;
    __uint128_t one_num = reserve_out * one_in_fee;
    __uint128_t one_den = reserve_in * 1000 + one_in_fee;
    __uint128_t one_out = (one_den > 0) ? one_num / one_den : 0;

    /* Step 8: Fill output struct */
    memset(quote_out, 0, sizeof(*quote_out));
    strncpy(quote_out->from_token, from_token, sizeof(quote_out->from_token) - 1);
    strncpy(quote_out->to_token, to_token, sizeof(quote_out->to_token) - 1);
    strncpy(quote_out->amount_in, amount_in, sizeof(quote_out->amount_in) - 1);

    format_raw_to_decimal(quote_out->amount_out, sizeof(quote_out->amount_out), raw_out, to_dec);
    format_raw_to_decimal(quote_out->price, sizeof(quote_out->price), one_out, to_dec);
    format_raw_to_decimal(quote_out->fee, sizeof(quote_out->fee), fee_raw, from_dec);

    snprintf(quote_out->price_impact, sizeof(quote_out->price_impact), "%.4f", impact_pct);
    snprintf(quote_out->pool_address, sizeof(quote_out->pool_address), "%s", pair->pair_address);

    quote_out->from_decimals = from_dec;
    quote_out->to_decimals = to_dec;

    QGP_LOG_INFO(LOG_TAG, "Quote: %s %s → %s %s (impact: %s%%, pool: %s)",
                 quote_out->amount_in, quote_out->from_token,
                 quote_out->amount_out, quote_out->to_token,
                 quote_out->price_impact, quote_out->pool_address);

    return 0;
}

int eth_dex_list_pairs(char ***pairs_out, int *count_out) {
    if (!pairs_out || !count_out) return -1;

    int total = (int)(NUM_KNOWN_PAIRS * 2);  /* Each pair generates A/B and B/A */
    char **pairs = calloc((size_t)total, sizeof(char *));
    if (!pairs) return -1;

    int idx = 0;
    for (size_t i = 0; i < NUM_KNOWN_PAIRS; i++) {
        pairs[idx] = malloc(32);
        if (pairs[idx]) {
            snprintf(pairs[idx], 32, "%s/%s", known_pairs[i].token_a, known_pairs[i].token_b);
        }
        idx++;

        pairs[idx] = malloc(32);
        if (pairs[idx]) {
            snprintf(pairs[idx], 32, "%s/%s", known_pairs[i].token_b, known_pairs[i].token_a);
        }
        idx++;
    }

    *pairs_out = pairs;
    *count_out = total;
    return 0;
}

void eth_dex_free_pairs(char **pairs, int count) {
    if (!pairs) return;
    for (int i = 0; i < count; i++) {
        free(pairs[i]);
    }
    free(pairs);
}
