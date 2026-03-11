/**
 * @file eth_dex.c
 * @brief Ethereum DEX Quote Implementation (Uniswap v2/v3 + PancakeSwap v2/v3)
 *
 * Fetches on-chain quotes from Uniswap v2 and v3:
 *
 * V2: getReserves() + constant product formula
 *     Fee: 0.3% (997/1000)
 *     Formula: out = (R_out * in * 997) / (R_in * 1000 + in * 997)
 *
 * V3: QuoterV2.quoteExactInputSingle() — on-chain swap simulation
 *     Fee: per-pool (0.05%, 0.3%, 1%)
 *     The contract simulates tick traversal and returns exact amountOut.
 *
 * When both V2 and V3 pools exist for a pair, V3 is tried first
 * (better prices due to concentrated liquidity), V2 as fallback.
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#include "eth_dex.h"
#include "eth_wallet.h"
#include "eth_erc20.h"
#include "eth_tx.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/keccak256.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif

/* Portable case-insensitive substring search (strcasestr is a GNU extension) */
static const char *dex_strcasestr(const char *haystack, const char *needle) {
    if (!needle[0]) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) { h++; n++; }
        if (!*n) return haystack;
    }
    return NULL;
}
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "ETH_DEX"

/* ============================================================================
 * TOKEN ADDRESSES (Ethereum mainnet, without 0x prefix)
 * ============================================================================ */

#define WETH_ADDRESS "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
#define USDC_ADDRESS "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
#define USDT_ADDRESS "dAC17F958D2ee523a2206206994597C13D831ec7"

/* Uniswap v3 QuoterV2 contract */
#define UNI_QUOTER_V2_ADDRESS "0x61fFE014bA17989E743c5F6cB21bF9697530B21e"

/* PancakeSwap v3 QuoterV2 contract (on Ethereum mainnet) */
#define CAKE_QUOTER_V2_ADDRESS "0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997"

/* Router contracts for on-chain swaps */
#define UNI_V2_ROUTER    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
#define UNI_V3_ROUTER    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
#define CAKE_V2_ROUTER   "0xEfF92A263d31888d860bD50809A8D171709b7b1c"
#define CAKE_V3_ROUTER   "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4"

/* quoteExactInputSingle((address,address,uint256,uint24,uint160)) — same ABI for both */
#define QUOTER_V2_SELECTOR "c6a5026a"

/* ============================================================================
 * KNOWN DEX PAIRS
 * ============================================================================
 * V3 pairs listed FIRST — they are tried before V2 (better prices).
 *
 * Token ordering (Uniswap convention, sorted by address):
 *   USDC (0xA0b8) < WETH (0xC02a) < USDT (0xdAC1)
 *
 * a_is_token0: true if token_a's contract address < token_b's contract address
 *              (only matters for V2 getReserves interpretation)
 * ============================================================================ */

typedef enum {
    DEX_UNISWAP_V2,
    DEX_UNISWAP_V3,
    DEX_PANCAKE_V2,
    DEX_PANCAKE_V3
} eth_dex_type_t;

typedef struct {
    const char *token_a;        /* First token symbol (user-facing) */
    const char *token_b;        /* Second token symbol (user-facing) */
    const char *pool_address;   /* V2: pair contract, V3: pool contract */
    const char *addr_a;         /* token_a contract address (no 0x prefix) */
    const char *addr_b;         /* token_b contract address (no 0x prefix) */
    uint8_t decimals_a;
    uint8_t decimals_b;
    bool a_is_token0;           /* V2: needed for reserve ordering */
    eth_dex_type_t dex_type;
    uint32_t fee_tier;          /* V3: 500=0.05%, 3000=0.3%, 10000=1%. V2: fee in bps */
    uint32_t fee_numerator;     /* V2 CPMM: multiply by this (e.g. 997 for 0.3%, 9975 for 0.25%) */
    uint32_t fee_denominator;   /* V2 CPMM: divide by this (e.g. 1000 or 10000) */
    const char *quoter_address; /* V3: QuoterV2 contract address (NULL for V2) */
    const char *router_address; /* Router contract for on-chain swaps */
    const char *dex_name;
} eth_dex_pair_t;

static const eth_dex_pair_t known_pairs[] = {
    /* ── Uniswap v3 ──────────────────────────────────────────────── */
    {
        .token_a = "ETH",  .token_b = "USDC",
        .pool_address = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640",
        .addr_a = WETH_ADDRESS,  .addr_b = USDC_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = false,       /* USDC(0xA0b8) < WETH(0xC02a) */
        .dex_type = DEX_UNISWAP_V3, .fee_tier = 500,
        .fee_numerator = 0, .fee_denominator = 0,
        .quoter_address = UNI_QUOTER_V2_ADDRESS,
        .router_address = UNI_V3_ROUTER,
        .dex_name = "Uniswap v3",
    },
    {
        .token_a = "ETH",  .token_b = "USDT",
        .pool_address = "0x4e68Ccd3E89f51C3074ca5072bbAC773960dFa36",
        .addr_a = WETH_ADDRESS,  .addr_b = USDT_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = true,        /* WETH(0xC02a) < USDT(0xdAC1) */
        .dex_type = DEX_UNISWAP_V3, .fee_tier = 3000,
        .fee_numerator = 0, .fee_denominator = 0,
        .quoter_address = UNI_QUOTER_V2_ADDRESS,
        .router_address = UNI_V3_ROUTER,
        .dex_name = "Uniswap v3",
    },
    /* ── PancakeSwap v3 ──────────────────────────────────────────── */
    {
        .token_a = "ETH",  .token_b = "USDC",
        .pool_address = "0x1ac1A8FEaAEa1900C4166dEeed0C11cC10669D36",
        .addr_a = WETH_ADDRESS,  .addr_b = USDC_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = false,
        .dex_type = DEX_PANCAKE_V3, .fee_tier = 500,
        .fee_numerator = 0, .fee_denominator = 0,
        .quoter_address = CAKE_QUOTER_V2_ADDRESS,
        .router_address = CAKE_V3_ROUTER,
        .dex_name = "PancakeSwap v3",
    },
    {
        .token_a = "ETH",  .token_b = "USDT",
        .pool_address = "0x6CA298D2983aB03Aa1da7679389D955A4eFEE15C",
        .addr_a = WETH_ADDRESS,  .addr_b = USDT_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = true,
        .dex_type = DEX_PANCAKE_V3, .fee_tier = 500,
        .fee_numerator = 0, .fee_denominator = 0,
        .quoter_address = CAKE_QUOTER_V2_ADDRESS,
        .router_address = CAKE_V3_ROUTER,
        .dex_name = "PancakeSwap v3",
    },
    /* ── Uniswap v2 ──────────────────────────────────────────────── */
    {
        .token_a = "ETH",  .token_b = "USDC",
        .pool_address = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",
        .addr_a = WETH_ADDRESS,  .addr_b = USDC_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = false,
        .dex_type = DEX_UNISWAP_V2, .fee_tier = 3000,
        .fee_numerator = 997, .fee_denominator = 1000,
        .quoter_address = NULL,
        .router_address = UNI_V2_ROUTER,
        .dex_name = "Uniswap v2",
    },
    {
        .token_a = "ETH",  .token_b = "USDT",
        .pool_address = "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852",
        .addr_a = WETH_ADDRESS,  .addr_b = USDT_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = true,
        .dex_type = DEX_UNISWAP_V2, .fee_tier = 3000,
        .fee_numerator = 997, .fee_denominator = 1000,
        .quoter_address = NULL,
        .router_address = UNI_V2_ROUTER,
        .dex_name = "Uniswap v2",
    },
    /* ── PancakeSwap v2 ──────────────────────────────────────────── */
    {
        .token_a = "ETH",  .token_b = "USDC",
        .pool_address = "0x2E8135bE71230c6B1B4045696d41C09Db0414226",
        .addr_a = WETH_ADDRESS,  .addr_b = USDC_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = false,
        .dex_type = DEX_PANCAKE_V2, .fee_tier = 2500,
        .fee_numerator = 9975, .fee_denominator = 10000,
        .quoter_address = NULL,
        .router_address = CAKE_V2_ROUTER,
        .dex_name = "PancakeSwap v2",
    },
    {
        .token_a = "ETH",  .token_b = "USDT",
        .pool_address = "0x17c1Ae82D99379240059940093762c5e4539aba5",
        .addr_a = WETH_ADDRESS,  .addr_b = USDT_ADDRESS,
        .decimals_a = 18,  .decimals_b = 6,
        .a_is_token0 = true,
        .dex_type = DEX_PANCAKE_V2, .fee_tier = 2500,
        .fee_numerator = 9975, .fee_denominator = 10000,
        .quoter_address = NULL,
        .router_address = CAKE_V2_ROUTER,
        .dex_name = "PancakeSwap v2",
    },
};

#define NUM_KNOWN_PAIRS (sizeof(known_pairs) / sizeof(known_pairs[0]))

/* ============================================================================
 * RPC HELPERS (with fallback)
 * ============================================================================ */

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
 * Make eth_call to a contract on a single endpoint.
 * data can be up to ~400 chars for QuoterV2 calls.
 * Returns: 0=success, -1=network error (retry), -2=RPC error (don't retry)
 */
static int eth_dex_call_single(const char *endpoint, const char *to,
                               const char *data, char *result_hex, size_t result_size) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* Build JSON-RPC request for eth_call */
    char body[1024];
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

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

/** eth_call with fallback across all endpoints */
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
        if (rc == -2) return -1;

        QGP_LOG_WARN(LOG_TAG, "Endpoint failed: %s, trying next...", endpoint);
    }

    QGP_LOG_ERROR(LOG_TAG, "All ETH RPC endpoints failed for eth_call");
    return -1;
}

/* ============================================================================
 * MATH HELPERS
 * ============================================================================ */

/** Parse a uint256 from a 64-char hex slice into __uint128_t */
static __uint128_t parse_uint256_lower128(const char *hex64) {
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

/** Parse decimal string to raw amount with given decimals */
static __uint128_t parse_decimal_to_raw(const char *amount, uint8_t decimals) {
    __uint128_t whole = 0;
    __uint128_t frac = 0;
    int frac_digits = 0;
    bool in_frac = false;

    for (const char *p = amount; *p; p++) {
        if (*p == '.') { in_frac = true; continue; }
        if (*p < '0' || *p > '9') break;
        if (!in_frac) {
            whole = whole * 10 + (uint8_t)(*p - '0');
        } else if (frac_digits < decimals) {
            frac = frac * 10 + (uint8_t)(*p - '0');
            frac_digits++;
        }
    }

    __uint128_t scale = 1;
    for (int i = 0; i < decimals; i++) scale *= 10;
    __uint128_t frac_scale = 1;
    for (int i = 0; i < (decimals - frac_digits); i++) frac_scale *= 10;

    return whole * scale + frac * frac_scale;
}

/** Format raw amount to decimal string */
static void format_raw_to_decimal(char *buf, size_t buf_size, __uint128_t raw, uint8_t decimals) {
    __uint128_t scale = 1;
    for (int i = 0; i < decimals; i++) scale *= 10;

    __uint128_t whole = raw / scale;
    __uint128_t frac  = raw % scale;

    char whole_str[42] = "0";
    if (whole > 0) {
        char tmp[42];
        int pos = 0;
        __uint128_t v = whole;
        while (v > 0) { tmp[pos++] = '0' + (char)(v % 10); v /= 10; }
        for (int i = 0; i < pos; i++) whole_str[i] = tmp[pos - 1 - i];
        whole_str[pos] = '\0';
    }

    char frac_str[42];
    {
        char tmp[42];
        int pos = 0;
        __uint128_t v = frac;
        if (v == 0) { tmp[pos++] = '0'; }
        else { while (v > 0) { tmp[pos++] = '0' + (char)(v % 10); v /= 10; } }
        int pad = decimals - pos;
        int j = 0;
        for (int i = 0; i < pad; i++) frac_str[j++] = '0';
        for (int i = pos - 1; i >= 0; i--) frac_str[j++] = tmp[i];
        frac_str[j] = '\0';
    }

    int frac_len = (int)strlen(frac_str);
    while (frac_len > 2 && frac_str[frac_len - 1] == '0') {
        frac_str[--frac_len] = '\0';
    }

    snprintf(buf, buf_size, "%s.%s", whole_str, frac_str);
}

/** Format __uint128_t as 64-char zero-padded hex (for ABI encoding) */
static void uint128_to_hex64(char *out, __uint128_t val) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 63; i >= 0; i--) {
        out[i] = hex_chars[val & 0xF];
        val >>= 4;
    }
    out[64] = '\0';
}

/* ============================================================================
 * UNISWAP V2 QUOTE (getReserves + CPMM)
 * ============================================================================ */

static int eth_dex_quote_v2(const eth_dex_pair_t *pair, bool reversed,
                            const char *amount_in, eth_dex_quote_t *quote_out) {
    uint8_t from_dec = reversed ? pair->decimals_b : pair->decimals_a;
    uint8_t to_dec   = reversed ? pair->decimals_a : pair->decimals_b;

    /* getReserves() — selector 0x0902f1ac */
    char result_hex[256] = {0};
    int rc = eth_dex_call(pair->pool_address, "0x0902f1ac", result_hex, sizeof(result_hex));
    if (rc != 0) return -1;

    const char *hex = result_hex;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    if (strlen(hex) < 128) return -1;

    __uint128_t reserve0 = parse_uint256_lower128(hex);
    __uint128_t reserve1 = parse_uint256_lower128(hex + 64);
    if (reserve0 == 0 || reserve1 == 0) return -1;

    /* Map reserves to input/output based on token ordering */
    __uint128_t reserve_in, reserve_out;
    if (!reversed) {
        reserve_in  = pair->a_is_token0 ? reserve0 : reserve1;
        reserve_out = pair->a_is_token0 ? reserve1 : reserve0;
    } else {
        reserve_in  = pair->a_is_token0 ? reserve1 : reserve0;
        reserve_out = pair->a_is_token0 ? reserve0 : reserve1;
    }

    __uint128_t raw_in = parse_decimal_to_raw(amount_in, from_dec);
    if (raw_in == 0) return -1;

    /* CPMM: out = (R_out * in * fee_num) / (R_in * fee_den + in * fee_num)
     * Uniswap v2:    fee_num=997,  fee_den=1000  (0.3% fee)
     * PancakeSwap v2: fee_num=9975, fee_den=10000 (0.25% fee)
     */
    uint32_t fee_num = pair->fee_numerator;
    uint32_t fee_den = pair->fee_denominator;
    __uint128_t in_with_fee = raw_in * fee_num;
    __uint128_t numerator   = reserve_out * in_with_fee;
    __uint128_t denominator = reserve_in * fee_den + in_with_fee;
    if (denominator == 0) return -1;

    __uint128_t raw_out = numerator / denominator;

    /* Price impact */
    double spot_price = (double)reserve_out / (double)reserve_in;
    double exec_price = (double)raw_out / (double)raw_in;
    double impact_pct = 0.0;
    if (spot_price > 0.0) {
        impact_pct = (1.0 - exec_price / spot_price) * 100.0;
        if (impact_pct < 0.0) impact_pct = 0.0;
    }

    /* Fee = amount_in * (1 - fee_num/fee_den) */
    __uint128_t fee_raw = raw_in * (fee_den - fee_num) / fee_den;

    /* Unit price */
    __uint128_t one_unit = 1;
    for (int i = 0; i < from_dec; i++) one_unit *= 10;
    __uint128_t one_fee = one_unit * fee_num;
    __uint128_t one_num = reserve_out * one_fee;
    __uint128_t one_den = reserve_in * fee_den + one_fee;
    __uint128_t one_out = (one_den > 0) ? one_num / one_den : 0;

    /* Fill output */
    memset(quote_out, 0, sizeof(*quote_out));
    strncpy(quote_out->from_token, reversed ? pair->token_b : pair->token_a, sizeof(quote_out->from_token) - 1);
    strncpy(quote_out->to_token, reversed ? pair->token_a : pair->token_b, sizeof(quote_out->to_token) - 1);
    strncpy(quote_out->amount_in, amount_in, sizeof(quote_out->amount_in) - 1);
    format_raw_to_decimal(quote_out->amount_out, sizeof(quote_out->amount_out), raw_out, to_dec);
    format_raw_to_decimal(quote_out->price, sizeof(quote_out->price), one_out, to_dec);
    format_raw_to_decimal(quote_out->fee, sizeof(quote_out->fee), fee_raw, from_dec);
    snprintf(quote_out->price_impact, sizeof(quote_out->price_impact), "%.4f", impact_pct);
    snprintf(quote_out->pool_address, sizeof(quote_out->pool_address), "%s", pair->pool_address);
    strncpy(quote_out->dex_name, pair->dex_name, sizeof(quote_out->dex_name) - 1);
    quote_out->from_decimals = from_dec;
    quote_out->to_decimals = to_dec;

    return 0;
}

/* ============================================================================
 * UNISWAP V3 QUOTE (QuoterV2)
 * ============================================================================
 * Calls QuoterV2.quoteExactInputSingle() to simulate the swap on-chain.
 *
 * ABI encoding (tuple of static types, no offset pointer):
 *   selector:           c6a5026a                        (4 bytes)
 *   tokenIn:            000...{20-byte addr}            (32 bytes)
 *   tokenOut:           000...{20-byte addr}            (32 bytes)
 *   amountIn:           {uint256}                       (32 bytes)
 *   fee:                000...{uint24}                  (32 bytes)
 *   sqrtPriceLimitX96:  000...0                         (32 bytes, 0=no limit)
 *
 * Response:
 *   amountOut:                  (uint256, first 32 bytes)
 *   sqrtPriceX96After:         (uint160, next 32 bytes)
 *   initializedTicksCrossed:   (uint32,  next 32 bytes)
 *   gasEstimate:               (uint256, next 32 bytes)
 * ============================================================================ */

static int eth_dex_quote_v3(const eth_dex_pair_t *pair, bool reversed,
                            const char *amount_in, eth_dex_quote_t *quote_out) {
    uint8_t from_dec = reversed ? pair->decimals_b : pair->decimals_a;
    uint8_t to_dec   = reversed ? pair->decimals_a : pair->decimals_b;
    const char *addr_in  = reversed ? pair->addr_b : pair->addr_a;
    const char *addr_out = reversed ? pair->addr_a : pair->addr_b;

    /* Parse input amount to raw */
    __uint128_t raw_in = parse_decimal_to_raw(amount_in, from_dec);
    if (raw_in == 0) return -1;

    /* Build ABI-encoded call data for quoteExactInputSingle */
    char amount_hex[65];
    uint128_to_hex64(amount_hex, raw_in);

    char fee_hex[65];
    uint128_to_hex64(fee_hex, (__uint128_t)pair->fee_tier);

    /* selector(4) + 5 params(32 each) = 164 bytes = 328 hex + "0x" = 330 chars */
    char call_data[340];
    snprintf(call_data, sizeof(call_data),
        "0x" QUOTER_V2_SELECTOR
        "000000000000000000000000%s"    /* tokenIn  (addr_in, 40 hex) */
        "000000000000000000000000%s"    /* tokenOut (addr_out, 40 hex) */
        "%s"                            /* amountIn (64 hex) */
        "%s"                            /* fee      (64 hex) */
        "0000000000000000000000000000000000000000000000000000000000000000",  /* sqrtPriceLimitX96 = 0 */
        addr_in, addr_out, amount_hex, fee_hex);

    /* Call QuoterV2 (Uniswap or PancakeSwap, same ABI) */
    char result_hex[600] = {0};
    int rc = eth_dex_call(pair->quoter_address, call_data, result_hex, sizeof(result_hex));
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "V3 QuoterV2 call failed for %s/%s",
                     pair->token_a, pair->token_b);
        return -1;
    }

    /* Parse amountOut from first 32 bytes of response */
    const char *hex = result_hex;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    if (strlen(hex) < 64) {
        QGP_LOG_ERROR(LOG_TAG, "V3 response too short: %zu", strlen(hex));
        return -1;
    }

    __uint128_t raw_out = parse_uint256_lower128(hex);
    if (raw_out == 0) {
        QGP_LOG_ERROR(LOG_TAG, "V3 returned zero amountOut");
        return -1;
    }

    /* Fee in input token */
    __uint128_t fee_raw = raw_in * pair->fee_tier / 1000000;
    double fee_pct = (double)pair->fee_tier / 10000.0;  /* e.g. 500 → 0.05% */

    /* Execution price = amountOut / amountIn (in raw, adjusted by caller) */
    /* For unit price, compute what 1 unit of input gives */
    __uint128_t one_unit = 1;
    for (int i = 0; i < from_dec; i++) one_unit *= 10;

    /* Estimate unit price from the quote ratio (avoids second RPC call) */
    /* unit_out ≈ raw_out * one_unit / raw_in */
    __uint128_t unit_out = 0;
    if (raw_in > 0) {
        /* Use double to avoid overflow in multiplication */
        double ratio = (double)raw_out / (double)raw_in;
        unit_out = (__uint128_t)(ratio * (double)one_unit);
    }

    /* Price impact: for V3, the fee IS the dominant cost for normal trades.
     * True price impact from tick crossing is (fee_pct + slippage).
     * We estimate slippage from the QuoterV2 sqrtPriceX96After if available. */
    double impact_pct = fee_pct;  /* Minimum impact = fee */
    if (strlen(hex) >= 128) {
        /* sqrtPriceX96After is in bytes 32-63 of response */
        __uint128_t sqrtAfter = parse_uint256_lower128(hex + 64);

        /* Get current sqrtPriceX96 from pool slot0 */
        char slot0_hex[512] = {0};
        int slot0_rc = eth_dex_call(pair->pool_address, "0x3850c7bd", slot0_hex, sizeof(slot0_hex));
        if (slot0_rc == 0) {
            const char *s0 = slot0_hex;
            if (s0[0] == '0' && (s0[1] == 'x' || s0[1] == 'X')) s0 += 2;
            if (strlen(s0) >= 64) {
                __uint128_t sqrtBefore = parse_uint256_lower128(s0);
                if (sqrtBefore > 0 && sqrtAfter > 0) {
                    double priceBefore = (double)sqrtBefore * (double)sqrtBefore;
                    double priceAfter  = (double)sqrtAfter  * (double)sqrtAfter;
                    double price_move = 0.0;
                    if (priceBefore > 0.0) {
                        if (priceAfter > priceBefore)
                            price_move = (priceAfter / priceBefore - 1.0) * 100.0;
                        else
                            price_move = (1.0 - priceAfter / priceBefore) * 100.0;
                    }
                    impact_pct = fee_pct + price_move;
                }
            }
        }
    }

    /* Fill output */
    memset(quote_out, 0, sizeof(*quote_out));
    strncpy(quote_out->from_token, reversed ? pair->token_b : pair->token_a, sizeof(quote_out->from_token) - 1);
    strncpy(quote_out->to_token, reversed ? pair->token_a : pair->token_b, sizeof(quote_out->to_token) - 1);
    strncpy(quote_out->amount_in, amount_in, sizeof(quote_out->amount_in) - 1);
    format_raw_to_decimal(quote_out->amount_out, sizeof(quote_out->amount_out), raw_out, to_dec);
    format_raw_to_decimal(quote_out->price, sizeof(quote_out->price), unit_out, to_dec);
    format_raw_to_decimal(quote_out->fee, sizeof(quote_out->fee), fee_raw, from_dec);
    snprintf(quote_out->price_impact, sizeof(quote_out->price_impact), "%.4f", impact_pct);
    snprintf(quote_out->pool_address, sizeof(quote_out->pool_address), "%s", pair->pool_address);
    strncpy(quote_out->dex_name, pair->dex_name, sizeof(quote_out->dex_name) - 1);
    quote_out->from_decimals = from_dec;
    quote_out->to_decimals = to_dec;

    QGP_LOG_INFO(LOG_TAG, "V3 Quote: %s %s -> %s %s (fee: %.2f%%, pool: %s)",
                 quote_out->amount_in, quote_out->from_token,
                 quote_out->amount_out, quote_out->to_token,
                 fee_pct, quote_out->pool_address);

    return 0;
}

/* ============================================================================
 * COW PROTOCOL QUOTE (api.cow.fi)
 * ============================================================================
 * CoW Protocol is an intent-based DEX aggregator with built-in MEV protection.
 * Orders are signed off-chain and executed by bonded solvers via batch auctions.
 * No API key required — public REST endpoint.
 *
 * Quote flow: POST /api/v1/quote → returns buyAmount + feeAmount
 * Token addresses must be 0x-prefixed, checksummed or lowercase.
 * ============================================================================ */

#define COW_QUOTE_URL "https://api.cow.fi/mainnet/api/v1/quote"

/* CoW-supported token pairs (symbol → 0x-prefixed address) */
typedef struct {
    const char *symbol;
    const char *address;     /* 0x-prefixed, checksummed */
    uint8_t decimals;
} cow_token_t;

static const cow_token_t cow_tokens[] = {
    { "ETH",  "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18 },  /* CoW uses WETH for ETH */
    { "WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18 },
    { "USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  6 },
    { "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7",  6 },
};

#define NUM_COW_TOKENS (sizeof(cow_tokens) / sizeof(cow_tokens[0]))

static const cow_token_t *cow_find_token(const char *symbol) {
    for (size_t i = 0; i < NUM_COW_TOKENS; i++) {
        if (strcasecmp(cow_tokens[i].symbol, symbol) == 0)
            return &cow_tokens[i];
    }
    return NULL;
}

/**
 * Parse decimal string to raw amount string (for CoW API).
 * E.g. "1.5" with 18 decimals → "1500000000000000000"
 * Returns allocated string, caller must free.
 */
static char *cow_decimal_to_raw(const char *amount_str, uint8_t decimals) {
    __uint128_t raw = parse_decimal_to_raw(amount_str, decimals);
    if (raw == 0) return NULL;

    /* Convert __uint128_t to decimal string */
    char tmp[64];
    int pos = 0;
    __uint128_t v = raw;
    if (v == 0) { tmp[pos++] = '0'; }
    else { while (v > 0) { tmp[pos++] = '0' + (char)(v % 10); v /= 10; } }

    char *result = malloc((size_t)pos + 1);
    if (!result) return NULL;
    for (int i = 0; i < pos; i++) result[i] = tmp[pos - 1 - i];
    result[pos] = '\0';
    return result;
}

/**
 * Get a swap quote from CoW Protocol.
 *
 * POST https://api.cow.fi/mainnet/api/v1/quote
 * Body: { sellToken, buyToken, sellAmountBeforeFee, kind: "sell",
 *         from: "0x0000...", validFor: 600 }
 * Response: { quote: { sellAmount, buyAmount, feeAmount, ... } }
 */
static int cow_get_quote(const char *from_symbol, const char *to_symbol,
                         const char *amount_in, eth_dex_quote_t *quote_out) {

    const cow_token_t *from_tok = cow_find_token(from_symbol);
    const cow_token_t *to_tok   = cow_find_token(to_symbol);
    if (!from_tok || !to_tok) return -2;

    /* Convert amount to raw */
    char *raw_amount = cow_decimal_to_raw(amount_in, from_tok->decimals);
    if (!raw_amount) {
        QGP_LOG_ERROR(LOG_TAG, "CoW: failed to convert amount: %s", amount_in);
        return -1;
    }

    /* Build JSON body */
    char body[1024];
    snprintf(body, sizeof(body),
        "{\"sellToken\":\"%s\","
        "\"buyToken\":\"%s\","
        "\"sellAmountBeforeFee\":\"%s\","
        "\"from\":\"0x0000000000000000000000000000000000000000\","
        "\"kind\":\"sell\","
        "\"validFor\":600}",
        from_tok->address, to_tok->address, raw_amount);
    free(raw_amount);

    QGP_LOG_DEBUG(LOG_TAG, "CoW quote request: %.200s", body);

    /* POST request */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "CoW: curl_easy_init failed");
        return -1;
    }

    struct dex_response_buffer resp = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, COW_QUOTE_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dex_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK || !resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "CoW: request failed: %s", curl_easy_strerror(res));
        free(resp.data);
        return -1;
    }

    if (http_code != 200) {
        QGP_LOG_WARN(LOG_TAG, "CoW: HTTP %ld: %.200s", http_code, resp.data);
        free(resp.data);
        return (http_code == 400 || http_code == 404) ? -2 : -1;
    }

    /* Parse JSON response */
    json_object *root = json_tokener_parse(resp.data);
    free(resp.data);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "CoW: JSON parse failed");
        return -1;
    }

    /* Response: { "quote": { "sellAmount": "...", "buyAmount": "...", "feeAmount": "..." } } */
    json_object *quote_obj;
    if (!json_object_object_get_ex(root, "quote", &quote_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "CoW: response missing 'quote' field");
        json_object_put(root);
        return -1;
    }

    json_object *sell_obj, *buy_obj, *fee_obj;
    if (!json_object_object_get_ex(quote_obj, "sellAmount", &sell_obj) ||
        !json_object_object_get_ex(quote_obj, "buyAmount", &buy_obj) ||
        !json_object_object_get_ex(quote_obj, "feeAmount", &fee_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "CoW: quote missing sellAmount/buyAmount/feeAmount");
        json_object_put(root);
        return -1;
    }

    const char *sell_raw = json_object_get_string(sell_obj);
    const char *buy_raw  = json_object_get_string(buy_obj);
    const char *fee_raw  = json_object_get_string(fee_obj);

    /* Parse raw amounts to __uint128_t for formatting */
    __uint128_t sell_val = 0, buy_val = 0, fee_val = 0;
    for (const char *p = sell_raw; *p; p++) { if (*p >= '0' && *p <= '9') sell_val = sell_val * 10 + (uint8_t)(*p - '0'); }
    for (const char *p = buy_raw;  *p; p++) { if (*p >= '0' && *p <= '9') buy_val  = buy_val  * 10 + (uint8_t)(*p - '0'); }
    for (const char *p = fee_raw;  *p; p++) { if (*p >= '0' && *p <= '9') fee_val  = fee_val  * 10 + (uint8_t)(*p - '0'); }

    /* Unit price: 1 from = X to */
    __uint128_t one_unit = 1;
    for (int i = 0; i < from_tok->decimals; i++) one_unit *= 10;
    __uint128_t unit_out = 0;
    if (sell_val > 0) {
        double ratio = (double)buy_val / (double)sell_val;
        unit_out = (__uint128_t)(ratio * (double)one_unit);
    }

    /* Price impact: CoW uses batch auctions so real price impact is near-zero.
     * The fee is NOT price impact — it's the solver/protocol fee.
     * Report 0 since CoW doesn't expose actual market impact. */
    double impact_pct = 0.0;
    (void)fee_val; /* fee is shown separately in the fee field */

    /* Fill output */
    memset(quote_out, 0, sizeof(*quote_out));
    strncpy(quote_out->from_token, from_symbol, sizeof(quote_out->from_token) - 1);
    strncpy(quote_out->to_token, to_symbol, sizeof(quote_out->to_token) - 1);

    /* amount_in = sellAmount (after fee deduction) */
    format_raw_to_decimal(quote_out->amount_in, sizeof(quote_out->amount_in),
                          sell_val, from_tok->decimals);
    format_raw_to_decimal(quote_out->amount_out, sizeof(quote_out->amount_out),
                          buy_val, to_tok->decimals);
    format_raw_to_decimal(quote_out->price, sizeof(quote_out->price),
                          unit_out, to_tok->decimals);
    format_raw_to_decimal(quote_out->fee, sizeof(quote_out->fee),
                          fee_val, from_tok->decimals);

    snprintf(quote_out->price_impact, sizeof(quote_out->price_impact), "%.4f", impact_pct);
    strncpy(quote_out->pool_address, "CoW Settlement", sizeof(quote_out->pool_address) - 1);
    strncpy(quote_out->dex_name, "CoW Protocol", sizeof(quote_out->dex_name) - 1);
    quote_out->from_decimals = from_tok->decimals;
    quote_out->to_decimals = to_tok->decimals;

    QGP_LOG_INFO(LOG_TAG, "CoW quote: %s %s -> %s %s (fee: %s %s)",
                 quote_out->amount_in, from_symbol,
                 quote_out->amount_out, to_symbol,
                 quote_out->fee, from_symbol);

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

/**
 * Check if a pair's DEX name matches the filter.
 * Filter is case-insensitive partial match: "v3" matches "Uniswap v3".
 */
static bool dex_filter_matches(const char *dex_name, const char *filter) {
    if (!filter || filter[0] == '\0') return true;  /* No filter = match all */
    return dex_strcasestr(dex_name, filter) != NULL;
}

int eth_dex_get_quotes(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    eth_dex_quote_t *quotes_out,
    int max_quotes,
    int *count_out
) {
    if (!from_token || !to_token || !amount_in || !quotes_out || !count_out) return -1;

    *count_out = 0;
    bool found_any = false;

    for (size_t i = 0; i < NUM_KNOWN_PAIRS && *count_out < max_quotes; i++) {
        bool reversed = false;
        if (strcasecmp(known_pairs[i].token_a, from_token) == 0 &&
            strcasecmp(known_pairs[i].token_b, to_token) == 0) {
            reversed = false;
        } else if (strcasecmp(known_pairs[i].token_b, from_token) == 0 &&
                   strcasecmp(known_pairs[i].token_a, to_token) == 0) {
            reversed = true;
        } else {
            continue;
        }

        const eth_dex_pair_t *pair = &known_pairs[i];

        /* Apply DEX filter */
        if (!dex_filter_matches(pair->dex_name, dex_filter)) continue;

        found_any = true;
        int rc;

        if (pair->dex_type == DEX_UNISWAP_V3 || pair->dex_type == DEX_PANCAKE_V3) {
            rc = eth_dex_quote_v3(pair, reversed, amount_in, &quotes_out[*count_out]);
        } else {
            rc = eth_dex_quote_v2(pair, reversed, amount_in, &quotes_out[*count_out]);
        }

        if (rc == 0) {
            QGP_LOG_INFO(LOG_TAG, "Quote via %s: %s %s -> %s %s",
                         pair->dex_name, amount_in, from_token,
                         quotes_out[*count_out].amount_out, to_token);
            (*count_out)++;
        } else {
            QGP_LOG_WARN(LOG_TAG, "%s failed for %s/%s",
                         pair->dex_name, from_token, to_token);
        }
    }

    /* CoW Protocol quote (MEV-protected aggregator) */
    if (*count_out < max_quotes && dex_filter_matches("CoW Protocol", dex_filter)) {
        /* CoW supports ETH/WETH, USDC, USDT pairs */
        if (cow_find_token(from_token) && cow_find_token(to_token)) {
            found_any = true;
            int rc = cow_get_quote(from_token, to_token, amount_in,
                                   &quotes_out[*count_out]);
            if (rc == 0) {
                QGP_LOG_INFO(LOG_TAG, "Quote via CoW Protocol: %s %s -> %s %s",
                             amount_in, from_token,
                             quotes_out[*count_out].amount_out, to_token);
                (*count_out)++;
            } else {
                QGP_LOG_WARN(LOG_TAG, "CoW Protocol failed for %s/%s (rc=%d)",
                             from_token, to_token, rc);
            }
        }
    }

    if (!found_any) {
        QGP_LOG_WARN(LOG_TAG, "No ETH DEX pair for %s/%s", from_token, to_token);
        return -2;
    }

    return (*count_out > 0) ? 0 : -1;
}

/* CoW Protocol supported pairs for list_pairs */
static const char *cow_pair_list[][2] = {
    { "ETH",  "USDC" },
    { "ETH",  "USDT" },
    { "USDC", "USDT" },
};

#define NUM_COW_PAIRS (sizeof(cow_pair_list) / sizeof(cow_pair_list[0]))

int eth_dex_list_pairs(char ***pairs_out, int *count_out) {
    if (!pairs_out || !count_out) return -1;

    /* On-chain pairs (both directions) + CoW pairs (both directions) */
    int total = (int)(NUM_KNOWN_PAIRS * 2 + NUM_COW_PAIRS * 2);
    char **pairs = calloc((size_t)total, sizeof(char *));
    if (!pairs) return -1;

    int idx = 0;

    /* On-chain pairs (Uniswap/PancakeSwap) */
    for (size_t i = 0; i < NUM_KNOWN_PAIRS; i++) {
        /* Format: "TOKEN_A/TOKEN_B (DEX_NAME)" */
        pairs[idx] = malloc(48);
        if (pairs[idx]) {
            snprintf(pairs[idx], 48, "%s/%s (%s)",
                     known_pairs[i].token_a, known_pairs[i].token_b,
                     known_pairs[i].dex_name);
        }
        idx++;

        pairs[idx] = malloc(48);
        if (pairs[idx]) {
            snprintf(pairs[idx], 48, "%s/%s (%s)",
                     known_pairs[i].token_b, known_pairs[i].token_a,
                     known_pairs[i].dex_name);
        }
        idx++;
    }

    /* CoW Protocol pairs */
    for (size_t i = 0; i < NUM_COW_PAIRS; i++) {
        pairs[idx] = malloc(48);
        if (pairs[idx]) {
            snprintf(pairs[idx], 48, "%s/%s (CoW Protocol)",
                     cow_pair_list[i][0], cow_pair_list[i][1]);
        }
        idx++;

        pairs[idx] = malloc(48);
        if (pairs[idx]) {
            snprintf(pairs[idx], 48, "%s/%s (CoW Protocol)",
                     cow_pair_list[i][1], cow_pair_list[i][0]);
        }
        idx++;
    }

    *pairs_out = pairs;
    *count_out = idx;
    return 0;
}

void eth_dex_free_pairs(char **pairs, int count) {
    if (!pairs) return;
    for (int i = 0; i < count; i++) {
        free(pairs[i]);
    }
    free(pairs);
}

/* ============================================================================
 * COW PROTOCOL SWAP EXECUTION
 * ============================================================================ */

/* Forward declaration */
static size_t cow_write_cb(void *contents, size_t size, size_t nmemb, void *userp);

/* CoW Protocol settlement contract (GPv2Settlement) */
#define COW_SETTLEMENT_CONTRACT "0x9008D19f58AAbD9eD0D60971565AA8510560ab41"

/* CoW VaultRelayer — needs ERC-20 approve */
#define COW_VAULT_RELAYER "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110"

/* WETH contract */
#define COW_WETH_CONTRACT "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

/* Helper: parse hex string to bytes */
static int cow_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    size_t hex_len = strlen(p);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(p + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* EIP-712 domain separator for CoW Protocol (mainnet) */
static void cow_compute_domain_separator(uint8_t domain_hash[32]) {
    /*
     * EIP-712 domain:
     *   name = "Gnosis Protocol"
     *   version = "v2"
     *   chainId = 1
     *   verifyingContract = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41
     *
     * domainSeparator = keccak256(
     *   keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
     *   || keccak256("Gnosis Protocol")
     *   || keccak256("v2")
     *   || uint256(1)
     *   || uint256(0x9008D19f58AAbD9eD0D60971565AA8510560ab41)
     * )
     */
    uint8_t buf[5 * 32];  /* 5 fields × 32 bytes */

    /* Type hash */
    const char *type_str = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    keccak256((const uint8_t *)type_str, strlen(type_str), buf);

    /* keccak256("Gnosis Protocol") */
    const char *name = "Gnosis Protocol";
    keccak256((const uint8_t *)name, strlen(name), buf + 32);

    /* keccak256("v2") */
    const char *version = "v2";
    keccak256((const uint8_t *)version, strlen(version), buf + 64);

    /* chainId = 1 */
    memset(buf + 96, 0, 32);
    buf[127] = 1;

    /* verifyingContract */
    memset(buf + 128, 0, 32);
    cow_hex_to_bytes(COW_SETTLEMENT_CONTRACT, buf + 128 + 12, 20);

    keccak256(buf, sizeof(buf), domain_hash);
}

/* CoW order type hash */
static void cow_order_type_hash(uint8_t hash[32]) {
    const char *type_str =
        "Order("
        "address sellToken,"
        "address buyToken,"
        "address receiver,"
        "uint256 sellAmount,"
        "uint256 buyAmount,"
        "uint32 validTo,"
        "bytes32 appData,"
        "uint256 feeAmount,"
        "string kind,"
        "bool partiallyFillable,"
        "string sellTokenBalance,"
        "string buyTokenBalance"
        ")";
    keccak256((const uint8_t *)type_str, strlen(type_str), hash);
}

/* Helper: write a raw decimal string as uint256 big-endian */
static void cow_decimal_str_to_uint256(const char *str, uint8_t out[32]) {
    memset(out, 0, 32);
    __uint128_t val = 0;
    for (const char *p = str; *p; p++) {
        if (*p >= '0' && *p <= '9') val = val * 10 + (uint8_t)(*p - '0');
    }
    /* Store in last 16 bytes (128-bit max) */
    for (int i = 0; i < 16; i++) {
        out[31 - i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/* Sign a CoW order with EIP-712 */
static int cow_sign_order(
    const uint8_t private_key[32],
    const char *sell_token,     /* contract address with 0x */
    const char *buy_token,      /* contract address with 0x */
    const char *receiver,       /* receiver address with 0x */
    const char *sell_amount,    /* raw decimal string */
    const char *buy_amount,     /* raw decimal string */
    uint32_t valid_to,          /* unix timestamp */
    const char *fee_amount,     /* raw decimal string */
    uint8_t sig_out[65]         /* r(32) + s(32) + v(1) */
) {
    /* Compute domain separator */
    uint8_t domain_sep[32];
    cow_compute_domain_separator(domain_sep);

    /* Compute struct hash */
    /* 13 fields × 32 bytes = 416 bytes */
    uint8_t struct_data[13 * 32];
    memset(struct_data, 0, sizeof(struct_data));

    /* [0] Order type hash */
    cow_order_type_hash(struct_data);

    /* [1] sellToken (address, left-padded) */
    cow_hex_to_bytes(sell_token, struct_data + 32 + 12, 20);

    /* [2] buyToken */
    cow_hex_to_bytes(buy_token, struct_data + 64 + 12, 20);

    /* [3] receiver */
    cow_hex_to_bytes(receiver, struct_data + 96 + 12, 20);

    /* [4] sellAmount */
    cow_decimal_str_to_uint256(sell_amount, struct_data + 128);

    /* [5] buyAmount */
    cow_decimal_str_to_uint256(buy_amount, struct_data + 160);

    /* [6] validTo (uint32, right-aligned in 32 bytes) */
    struct_data[192 + 28] = (uint8_t)((valid_to >> 24) & 0xFF);
    struct_data[192 + 29] = (uint8_t)((valid_to >> 16) & 0xFF);
    struct_data[192 + 30] = (uint8_t)((valid_to >> 8) & 0xFF);
    struct_data[192 + 31] = (uint8_t)(valid_to & 0xFF);

    /* [7] appData (bytes32 — zero for now, can add referral later) */
    /* Already zero */

    /* [8] feeAmount — offset 8*32=256 */
    cow_decimal_str_to_uint256(fee_amount, struct_data + 256);

    /* [9] kind: keccak256("sell") — offset 9*32=288 */
    keccak256((const uint8_t *)"sell", 4, struct_data + 288);

    /* [10] partiallyFillable: false = 0 — offset 10*32=320, already zero */

    /* [11] sellTokenBalance: keccak256("erc20") — offset 11*32=352 */
    keccak256((const uint8_t *)"erc20", 5, struct_data + 352);

    /* [12] buyTokenBalance: keccak256("erc20") — offset 12*32=384 */
    keccak256((const uint8_t *)"erc20", 5, struct_data + 384);

    uint8_t struct_hash[32];
    keccak256(struct_data, sizeof(struct_data), struct_hash);

    /* EIP-712 message: "\x19\x01" || domainSeparator || structHash */
    uint8_t msg[66];
    msg[0] = 0x19;
    msg[1] = 0x01;
    memcpy(msg + 2, domain_sep, 32);
    memcpy(msg + 34, struct_hash, 32);

    uint8_t msg_hash[32];
    keccak256(msg, 66, msg_hash);

    /* Sign with secp256k1 */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create secp256k1 context");
        return -1;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg_hash, private_key, NULL, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign CoW order");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    uint8_t sig_data[64];
    int recovery_id;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_data, &recovery_id, &sig);
    secp256k1_context_destroy(ctx);

    /* r + s + v (v = 27 + recovery_id for EIP-712) */
    memcpy(sig_out, sig_data, 64);
    sig_out[64] = (uint8_t)(27 + recovery_id);

    return 0;
}

/* Helper: bytes to hex string */
static void cow_bytes_to_hex(const uint8_t *data, size_t len, char *hex_out) {
    hex_out[0] = '0'; hex_out[1] = 'x';
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_out + 2 + i * 2, 3, "%02x", data[i]);
    }
}

/* Wait for TX confirmation by polling eth_getTransactionReceipt */
static int cow_wait_for_tx(const char *tx_hash, int max_seconds) {
    QGP_LOG_INFO(LOG_TAG, "Waiting for TX confirmation: %s", tx_hash);

    for (int elapsed = 0; elapsed < max_seconds; elapsed += 5) {
        sleep(5);

        /* Check via eth_getTransactionReceipt */
        CURL *curl = curl_easy_init();
        if (!curl) continue;

        char body[256];
        snprintf(body, sizeof(body),
            "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\","
            "\"params\":[\"%s\"],\"id\":1}", tx_hash);

        struct { char *data; size_t size; } resp = {0};
        struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, eth_rpc_get_endpoint());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cow_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        const char *ca_bundle = qgp_platform_ca_bundle_path();
        if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK || !resp.data) {
            free(resp.data);
            continue;
        }

        json_object *jresp = json_tokener_parse(resp.data);
        free(resp.data);
        if (!jresp) continue;

        json_object *jresult;
        if (json_object_object_get_ex(jresp, "result", &jresult) &&
            !json_object_is_type(jresult, json_type_null)) {
            /* Receipt exists — TX is mined */
            json_object *jstatus;
            if (json_object_object_get_ex(jresult, "status", &jstatus)) {
                const char *st = json_object_get_string(jstatus);
                if (st && strcmp(st, "0x1") == 0) {
                    json_object_put(jresp);
                    QGP_LOG_INFO(LOG_TAG, "TX confirmed: %s", tx_hash);
                    return 0;
                } else {
                    json_object_put(jresp);
                    QGP_LOG_ERROR(LOG_TAG, "TX failed: %s", tx_hash);
                    return -1;
                }
            }
            json_object_put(jresp);
            return 0;  /* Receipt exists, assume success */
        }
        json_object_put(jresp);

        QGP_LOG_DEBUG(LOG_TAG, "TX not yet mined, waiting... (%ds)", elapsed + 5);
    }

    QGP_LOG_ERROR(LOG_TAG, "TX confirmation timeout after %ds: %s", max_seconds, tx_hash);
    return -1;
}

/* Post order to CoW API */
static int cow_post_order(
    const char *sell_token,
    const char *buy_token,
    const char *receiver,
    const char *sell_amount,
    const char *buy_amount,
    uint32_t valid_to,
    const char *fee_amount,
    const char *sig_hex,       /* 0x + 130 hex chars */
    const char *from_address,
    char *order_uid_out,       /* Output: order UID */
    size_t uid_size
) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* Build JSON order body */
    json_object *order = json_object_new_object();
    json_object_object_add(order, "sellToken", json_object_new_string(sell_token));
    json_object_object_add(order, "buyToken", json_object_new_string(buy_token));
    json_object_object_add(order, "receiver", json_object_new_string(receiver));
    json_object_object_add(order, "sellAmount", json_object_new_string(sell_amount));
    json_object_object_add(order, "buyAmount", json_object_new_string(buy_amount));
    json_object_object_add(order, "validTo", json_object_new_int64((int64_t)valid_to));
    json_object_object_add(order, "feeAmount", json_object_new_string(fee_amount));
    json_object_object_add(order, "kind", json_object_new_string("sell"));
    json_object_object_add(order, "partiallyFillable", json_object_new_boolean(0));
    json_object_object_add(order, "sellTokenBalance", json_object_new_string("erc20"));
    json_object_object_add(order, "buyTokenBalance", json_object_new_string("erc20"));

    /* appData: zero hash for now */
    json_object_object_add(order, "appData",
        json_object_new_string("0x0000000000000000000000000000000000000000000000000000000000000000"));

    json_object_object_add(order, "signature", json_object_new_string(sig_hex));
    json_object_object_add(order, "signingScheme", json_object_new_string("eip712"));
    json_object_object_add(order, "from", json_object_new_string(from_address));

    const char *body = json_object_to_json_string(order);
    QGP_LOG_INFO(LOG_TAG, "CoW POST /orders body length: %zu", strlen(body));

    struct { char *data; size_t size; } resp = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char url[128];
    snprintf(url, sizeof(url), "https://api.cow.fi/mainnet/api/v1/orders");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cow_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    json_object_put(order);

    if (res != CURLE_OK || !resp.data) {
        QGP_LOG_ERROR(LOG_TAG, "CoW POST /orders failed: %s",
                      res != CURLE_OK ? curl_easy_strerror(res) : "no data");
        free(resp.data);
        return -1;
    }

    if (http_code != 201) {
        QGP_LOG_ERROR(LOG_TAG, "CoW POST /orders HTTP %ld: %.500s", http_code, resp.data);
        free(resp.data);
        return -1;
    }

    /* Response is a JSON string: the order UID in quotes */
    /* e.g., "\"0xabcdef...\"" — parse as JSON string */
    json_object *juid = json_tokener_parse(resp.data);
    if (juid && json_object_is_type(juid, json_type_string)) {
        strncpy(order_uid_out, json_object_get_string(juid), uid_size - 1);
        order_uid_out[uid_size - 1] = '\0';
        json_object_put(juid);
    } else {
        /* Try raw — might just be a plain string */
        strncpy(order_uid_out, resp.data, uid_size - 1);
        order_uid_out[uid_size - 1] = '\0';
        /* Strip surrounding quotes if present */
        size_t len = strlen(order_uid_out);
        if (len > 2 && order_uid_out[0] == '"' && order_uid_out[len-1] == '"') {
            memmove(order_uid_out, order_uid_out + 1, len - 2);
            order_uid_out[len - 2] = '\0';
        }
        if (juid) json_object_put(juid);
    }

    free(resp.data);
    QGP_LOG_INFO(LOG_TAG, "CoW order submitted: %s", order_uid_out);
    return 0;
}

/* Poll CoW order status until fulfilled or timeout */
static int cow_poll_order(const char *order_uid, int max_seconds) {
    QGP_LOG_INFO(LOG_TAG, "Polling CoW order status...");

    char url[256];
    snprintf(url, sizeof(url), "https://api.cow.fi/mainnet/api/v1/orders/%s", order_uid);

    for (int elapsed = 0; elapsed < max_seconds; elapsed += 5) {
        sleep(5);

        CURL *curl = curl_easy_init();
        if (!curl) continue;

        struct { char *data; size_t size; } resp = {0};

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cow_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

        const char *ca_bundle = qgp_platform_ca_bundle_path();
        if (ca_bundle) curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK || !resp.data) {
            free(resp.data);
            continue;
        }

        json_object *jresp = json_tokener_parse(resp.data);
        free(resp.data);
        if (!jresp) continue;

        json_object *jstatus;
        if (json_object_object_get_ex(jresp, "status", &jstatus)) {
            const char *status = json_object_get_string(jstatus);
            if (status) {
                if (strcmp(status, "fulfilled") == 0) {
                    QGP_LOG_INFO(LOG_TAG, "CoW order fulfilled!");
                    json_object_put(jresp);
                    return 0;
                } else if (strcmp(status, "cancelled") == 0 ||
                           strcmp(status, "expired") == 0) {
                    QGP_LOG_ERROR(LOG_TAG, "CoW order %s", status);
                    json_object_put(jresp);
                    return -1;
                }
                QGP_LOG_DEBUG(LOG_TAG, "CoW order status: %s (%ds)", status, elapsed + 5);
            }
        }
        json_object_put(jresp);
    }

    QGP_LOG_ERROR(LOG_TAG, "CoW order poll timeout after %ds", max_seconds);
    return -1;
}

/* CURL write callback for swap functions */
static size_t cow_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct { char *data; size_t size; } *buf = userp;
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(buf->data + buf->size, contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

/* ============================================================================
 * V2 ROUTER SWAP — swapExactETHForTokens
 * Selector: 0x7ff36ab5
 * Args: (uint256 amountOutMin, address[] path, address to, uint256 deadline)
 * ETH is sent as msg.value — no WETH wrap needed.
 * ============================================================================ */
static int eth_dex_swap_v2(
    const eth_wallet_t *wallet,
    const eth_dex_pair_t *pair,
    const char *amount_in,      /* decimal ETH string */
    __uint128_t amount_out_min, /* raw minimum output (with slippage) */
    bool selling_eth,           /* true: ETH→token, false: token→ETH */
    char *tx_hash_out
) {
    uint64_t nonce;
    if (eth_tx_get_nonce(wallet->address_hex, &nonce) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "V2 swap: failed to get nonce");
        return -1;
    }

    uint64_t gas_price;
    if (eth_tx_get_gas_price(&gas_price) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "V2 swap: failed to get gas price");
        return -1;
    }
    gas_price = (gas_price * 150) / 100;  /* FAST = 1.5x */

    uint8_t router_bytes[20];
    if (eth_parse_address(pair->router_address, router_bytes) != 0) return -1;

    if (selling_eth) {
        /* swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)
         * path = [WETH, tokenOut]
         * Calldata layout:
         *   [0..3]    selector 0x7ff36ab5
         *   [4..35]   amountOutMin (uint256)
         *   [36..67]  offset to path array = 128 (0x80)
         *   [68..99]  to address (recipient)
         *   [100..131] deadline (uint256)
         *   [132..163] path array length = 2
         *   [164..195] path[0] = WETH
         *   [196..227] path[1] = tokenOut
         * Total: 228 bytes
         */
        uint8_t calldata[228];
        memset(calldata, 0, sizeof(calldata));

        /* Selector */
        calldata[0] = 0x7f; calldata[1] = 0xf3; calldata[2] = 0x6a; calldata[3] = 0xb5;

        /* amountOutMin — encode __uint128_t as 32-byte big-endian */
        for (int i = 0; i < 16; i++)
            calldata[4 + 16 + i] = (uint8_t)(amount_out_min >> (8 * (15 - i)));

        /* offset to path array = 128 = 0x80 */
        calldata[67] = 0x80;

        /* to = recipient (wallet address) */
        uint8_t to_bytes[20];
        eth_parse_address(wallet->address_hex, to_bytes);
        memcpy(calldata + 68 + 12, to_bytes, 20);

        /* deadline = block.timestamp + 300 (5 minutes) */
        uint64_t deadline = (uint64_t)time(NULL) + 300;
        for (int i = 0; i < 8; i++)
            calldata[100 + 24 + i] = (uint8_t)(deadline >> (8 * (7 - i)));

        /* path length = 2 */
        calldata[163] = 2;

        /* path[0] = WETH */
        uint8_t weth_bytes[20];
        eth_parse_address("0x" WETH_ADDRESS, weth_bytes);
        memcpy(calldata + 164 + 12, weth_bytes, 20);

        /* path[1] = output token */
        const char *out_addr = pair->addr_b;  /* ETH is always token_a */
        char full_addr[44];
        snprintf(full_addr, sizeof(full_addr), "0x%s", out_addr);
        uint8_t out_bytes[20];
        eth_parse_address(full_addr, out_bytes);
        memcpy(calldata + 196 + 12, out_bytes, 20);

        /* Parse ETH value */
        uint8_t value_wei[32];
        if (eth_parse_amount(amount_in, value_wei) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "V2 swap: failed to parse amount: %s", amount_in);
            return -1;
        }

        eth_tx_t tx;
        memset(&tx, 0, sizeof(tx));
        tx.nonce = nonce;
        tx.gas_price = gas_price;
        tx.gas_limit = 200000;
        memcpy(tx.to, router_bytes, 20);
        memcpy(tx.value, value_wei, 32);
        tx.data = calldata;
        tx.data_len = sizeof(calldata);
        tx.chain_id = ETH_CHAIN_MAINNET;

        eth_signed_tx_t signed_tx;
        if (eth_tx_sign(&tx, wallet->private_key, &signed_tx) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "V2 swap: failed to sign TX");
            return -1;
        }

        if (eth_tx_send_private(&signed_tx, tx_hash_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "V2 swap: failed to send TX");
            return -1;
        }

        QGP_LOG_INFO(LOG_TAG, "V2 swap TX sent via Flashbots (%s): %s", pair->dex_name, tx_hash_out);
        return 0;
    }

    /* TODO: token→ETH swap (swapExactTokensForETH) — not yet needed */
    QGP_LOG_ERROR(LOG_TAG, "V2 swap: token→ETH not yet implemented");
    return -1;
}

/* ============================================================================
 * V3 ROUTER SWAP — exactInputSingle
 * Selector: 0x04e45aaf
 * Struct: (address tokenIn, address tokenOut, uint24 fee, address recipient,
 *          uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)
 * For ETH→token: tokenIn=WETH, send ETH as msg.value
 * ============================================================================ */
static int eth_dex_swap_v3(
    const eth_wallet_t *wallet,
    const eth_dex_pair_t *pair,
    const char *amount_in,
    __uint128_t raw_amount_in,
    __uint128_t amount_out_min,
    bool selling_eth,
    char *tx_hash_out
) {
    uint64_t nonce;
    if (eth_tx_get_nonce(wallet->address_hex, &nonce) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "V3 swap: failed to get nonce");
        return -1;
    }

    uint64_t gas_price;
    if (eth_tx_get_gas_price(&gas_price) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "V3 swap: failed to get gas price");
        return -1;
    }
    gas_price = (gas_price * 150) / 100;  /* FAST */

    uint8_t router_bytes[20];
    if (eth_parse_address(pair->router_address, router_bytes) != 0) return -1;

    if (selling_eth) {
        /* exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
         * Calldata layout:
         *   [0..3]    selector 0x04e45aaf
         *   [4..35]   tokenIn (WETH)
         *   [36..67]  tokenOut
         *   [68..99]  fee (uint24, right-aligned)
         *   [100..131] recipient
         *   [132..163] amountIn (uint256)
         *   [164..195] amountOutMinimum (uint256)
         *   [196..227] sqrtPriceLimitX96 = 0 (no limit)
         * Total: 228 bytes
         */
        uint8_t calldata[228];
        memset(calldata, 0, sizeof(calldata));

        /* Selector */
        calldata[0] = 0x04; calldata[1] = 0xe4; calldata[2] = 0x5a; calldata[3] = 0xaf;

        /* tokenIn = WETH */
        uint8_t weth_bytes[20];
        eth_parse_address("0x" WETH_ADDRESS, weth_bytes);
        memcpy(calldata + 4 + 12, weth_bytes, 20);

        /* tokenOut */
        const char *out_addr = pair->addr_b;
        char full_addr[44];
        snprintf(full_addr, sizeof(full_addr), "0x%s", out_addr);
        uint8_t out_bytes[20];
        eth_parse_address(full_addr, out_bytes);
        memcpy(calldata + 36 + 12, out_bytes, 20);

        /* fee tier (uint24) */
        uint32_t fee = pair->fee_tier;
        calldata[99]  = (uint8_t)(fee & 0xFF);
        calldata[98]  = (uint8_t)((fee >> 8) & 0xFF);
        calldata[97]  = (uint8_t)((fee >> 16) & 0xFF);

        /* recipient */
        uint8_t to_bytes[20];
        eth_parse_address(wallet->address_hex, to_bytes);
        memcpy(calldata + 100 + 12, to_bytes, 20);

        /* amountIn */
        for (int i = 0; i < 16; i++)
            calldata[132 + 16 + i] = (uint8_t)(raw_amount_in >> (8 * (15 - i)));

        /* amountOutMinimum */
        for (int i = 0; i < 16; i++)
            calldata[164 + 16 + i] = (uint8_t)(amount_out_min >> (8 * (15 - i)));

        /* sqrtPriceLimitX96 = 0 (no limit) — already zeroed */

        /* Parse ETH value */
        uint8_t value_wei[32];
        if (eth_parse_amount(amount_in, value_wei) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "V3 swap: failed to parse amount: %s", amount_in);
            return -1;
        }

        eth_tx_t tx;
        memset(&tx, 0, sizeof(tx));
        tx.nonce = nonce;
        tx.gas_price = gas_price;
        tx.gas_limit = 250000;
        memcpy(tx.to, router_bytes, 20);
        memcpy(tx.value, value_wei, 32);
        tx.data = calldata;
        tx.data_len = sizeof(calldata);
        tx.chain_id = ETH_CHAIN_MAINNET;

        eth_signed_tx_t signed_tx;
        if (eth_tx_sign(&tx, wallet->private_key, &signed_tx) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "V3 swap: failed to sign TX");
            return -1;
        }

        if (eth_tx_send_private(&signed_tx, tx_hash_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "V3 swap: failed to send TX");
            return -1;
        }

        QGP_LOG_INFO(LOG_TAG, "V3 swap TX sent via Flashbots (%s): %s", pair->dex_name, tx_hash_out);
        return 0;
    }

    QGP_LOG_ERROR(LOG_TAG, "V3 swap: token→ETH not yet implemented");
    return -1;
}

int eth_dex_execute_swap(
    const eth_wallet_t *wallet,
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    eth_dex_swap_result_t *result_out
) {
    if (!wallet || !from_token || !to_token || !amount_in || !result_out) return -1;
    memset(result_out, 0, sizeof(*result_out));

    bool selling_eth = (strcasecmp(from_token, "ETH") == 0);

    /* Step 1: Get quotes from all on-chain DEXes to find best price */
    QGP_LOG_INFO(LOG_TAG, "DEX swap: %s %s -> %s — getting quotes from all DEXes",
                 amount_in, from_token, to_token);

    eth_dex_quote_t quotes[NUM_KNOWN_PAIRS + 1];  /* +1 for CoW */
    int quote_count = 0;
    eth_dex_get_quotes(from_token, to_token, amount_in, NULL,
                       quotes, (int)(NUM_KNOWN_PAIRS + 1), &quote_count);

    if (quote_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No DEX quotes available for %s -> %s", from_token, to_token);
        return -2;
    }

    /* Find the best quote (highest amount_out) — exclude CoW (off-chain, unreliable for small amounts) */
    int best_idx = -1;
    double best_out = 0.0;
    for (int i = 0; i < quote_count; i++) {
        if (strcmp(quotes[i].dex_name, "CoW Protocol") == 0) continue;  /* Skip CoW */
        double out = atof(quotes[i].amount_out);
        if (out > best_out) {
            best_out = out;
            best_idx = i;
        }
    }

    if (best_idx < 0) {
        QGP_LOG_ERROR(LOG_TAG, "No on-chain DEX quotes for %s -> %s", from_token, to_token);
        return -2;
    }

    eth_dex_quote_t *best = &quotes[best_idx];
    QGP_LOG_INFO(LOG_TAG, "Best quote: %s %s -> %s %s via %s",
                 best->amount_in, from_token, best->amount_out, to_token, best->dex_name);

    /* Find the matching pair from known_pairs for router info */
    const eth_dex_pair_t *swap_pair = NULL;
    for (size_t i = 0; i < NUM_KNOWN_PAIRS; i++) {
        if (strcmp(known_pairs[i].pool_address, best->pool_address) == 0) {
            swap_pair = &known_pairs[i];
            break;
        }
    }

    if (!swap_pair) {
        QGP_LOG_ERROR(LOG_TAG, "Could not find pair info for pool %s", best->pool_address);
        return -1;
    }

    /* Calculate amountOutMin with 1% slippage tolerance */
    uint8_t from_dec = selling_eth ? swap_pair->decimals_a : swap_pair->decimals_b;
    uint8_t to_dec = selling_eth ? swap_pair->decimals_b : swap_pair->decimals_a;
    __uint128_t raw_out = parse_decimal_to_raw(best->amount_out, to_dec);
    __uint128_t amount_out_min = raw_out * 99 / 100;  /* 1% slippage */
    __uint128_t raw_in = parse_decimal_to_raw(amount_in, from_dec);

    QGP_LOG_INFO(LOG_TAG, "Swap via %s (router %s), slippage 1%%",
                 swap_pair->dex_name, swap_pair->router_address);

    /* Step 2: Execute on-chain swap via router */
    char tx_hash[68] = {0};
    int rc;

    if (swap_pair->dex_type == DEX_UNISWAP_V2 || swap_pair->dex_type == DEX_PANCAKE_V2) {
        rc = eth_dex_swap_v2(wallet, swap_pair, amount_in, amount_out_min,
                             selling_eth, tx_hash);
    } else {
        rc = eth_dex_swap_v3(wallet, swap_pair, amount_in, raw_in, amount_out_min,
                             selling_eth, tx_hash);
    }

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Router swap failed");
        return -1;
    }

    /* Step 3: Wait for TX confirmation */
    if (cow_wait_for_tx(tx_hash, 120) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Swap TX not confirmed after 120s: %s", tx_hash);
        return -1;
    }

    /* Fill result */
    strncpy(result_out->tx_signature, tx_hash, sizeof(result_out->tx_signature) - 1);
    strncpy(result_out->amount_in, amount_in, sizeof(result_out->amount_in) - 1);
    strncpy(result_out->amount_out, best->amount_out, sizeof(result_out->amount_out) - 1);
    strncpy(result_out->from_token, from_token, sizeof(result_out->from_token) - 1);
    strncpy(result_out->to_token, to_token, sizeof(result_out->to_token) - 1);
    strncpy(result_out->dex_name, swap_pair->dex_name, sizeof(result_out->dex_name) - 1);
    strncpy(result_out->price_impact, best->price_impact, sizeof(result_out->price_impact) - 1);

    QGP_LOG_INFO(LOG_TAG, "Swap complete: %s %s -> %s %s via %s, tx=%s",
                 amount_in, from_token, best->amount_out, to_token,
                 swap_pair->dex_name, tx_hash);

    return 0;
}
