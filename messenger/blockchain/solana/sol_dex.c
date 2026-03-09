/**
 * @file sol_dex.c
 * @brief Solana DEX Quote Implementation (Jupiter Aggregator)
 *
 * Fetches quotes from Jupiter public API (api.jup.ag/swap/v1/quote).
 * Jupiter aggregates all major Solana DEXes and returns the best route.
 * No API key required — public endpoint with rate limiting.
 *
 * Supports platformFeeBps for referral revenue on swap execution.
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#include "sol_dex.h"
#include "crypto/utils/qgp_log.h"
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

#define LOG_TAG "SOL_DEX"

/* Jupiter public quote endpoint — no API key needed */
#define JUPITER_QUOTE_URL "https://lite-api.jup.ag/swap/v1/quote"

/* ============================================================================
 * TOKEN REGISTRY
 *
 * Solana token mint addresses (mainnet).
 * ============================================================================ */

typedef struct {
    const char *symbol;
    const char *mint;
    uint8_t decimals;
} sol_token_t;

static const sol_token_t known_tokens[] = {
    { "SOL",  "So11111111111111111111111111111111111111112",          9  },
    { "USDC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",      6  },
    { "USDT", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",       6  },
};

#define NUM_KNOWN_TOKENS (sizeof(known_tokens) / sizeof(known_tokens[0]))

/* Known trading pairs for sol_dex_list_pairs */
static const char *known_pairs[][2] = {
    { "SOL", "USDC" },
    { "SOL", "USDT" },
    { "USDC", "USDT" },
};

#define NUM_KNOWN_PAIRS (sizeof(known_pairs) / sizeof(known_pairs[0]))

static const sol_token_t *find_token(const char *symbol) {
    for (size_t i = 0; i < NUM_KNOWN_TOKENS; i++) {
        if (strcasecmp(known_tokens[i].symbol, symbol) == 0) {
            return &known_tokens[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * CURL RESPONSE BUFFER
 * ============================================================================ */

typedef struct {
    char *data;
    size_t size;
} curl_buf_t;

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    curl_buf_t *buf = (curl_buf_t *)userp;

    char *tmp = realloc(buf->data, buf->size + total + 1);
    if (!tmp) return 0;

    buf->data = tmp;
    memcpy(buf->data + buf->size, contents, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

/* ============================================================================
 * AMOUNT HELPERS
 * ============================================================================ */

/**
 * Convert decimal string (e.g. "1.5") to raw lamports/base units string.
 * Returns allocated string, caller must free.
 */
static char *decimal_to_raw(const char *amount_str, uint8_t decimals) {
    if (!amount_str) return NULL;

    const char *dot = strchr(amount_str, '.');
    char whole_str[64] = {0};
    char frac_str[32] = {0};

    if (dot) {
        size_t whole_len = (size_t)(dot - amount_str);
        if (whole_len >= sizeof(whole_str)) return NULL;
        memcpy(whole_str, amount_str, whole_len);
        strncpy(frac_str, dot + 1, sizeof(frac_str) - 1);
    } else {
        strncpy(whole_str, amount_str, sizeof(whole_str) - 1);
    }

    /* Pad or truncate fraction to match decimals */
    int frac_len = (int)strlen(frac_str);
    if (frac_len < decimals) {
        for (int i = frac_len; i < decimals; i++) {
            frac_str[i] = '0';
        }
        frac_str[decimals] = '\0';
    } else if (frac_len > decimals) {
        frac_str[decimals] = '\0';
    }

    /* Concatenate whole + fraction (no dot) */
    char raw[128];
    snprintf(raw, sizeof(raw), "%s%s", whole_str, frac_str);

    /* Strip leading zeros (but keep at least "0") */
    char *p = raw;
    while (*p == '0' && *(p + 1) != '\0') p++;

    return strdup(p);
}

/**
 * Convert raw lamports string to decimal string.
 */
static void raw_to_decimal(const char *raw_str, uint8_t decimals, char *out, size_t out_size) {
    if (!raw_str || !out) return;

    size_t len = strlen(raw_str);

    if (len <= (size_t)decimals) {
        /* Less digits than decimals — result is 0.000...X */
        char padded[128] = {0};
        int pad = decimals - (int)len;
        for (int i = 0; i < pad; i++) padded[i] = '0';
        memcpy(padded + pad, raw_str, len);
        padded[decimals] = '\0';

        /* Trim trailing zeros */
        int tlen = (int)strlen(padded);
        while (tlen > 1 && padded[tlen - 1] == '0') {
            padded[--tlen] = '\0';
        }

        snprintf(out, out_size, "0.%s", padded);
    } else {
        /* Split into whole and fraction */
        size_t whole_len = len - (size_t)decimals;
        char whole[64] = {0};
        char frac[32] = {0};
        memcpy(whole, raw_str, whole_len);
        memcpy(frac, raw_str + whole_len, (size_t)decimals);
        frac[decimals] = '\0';

        /* Trim trailing zeros from fraction */
        int tlen = (int)strlen(frac);
        while (tlen > 1 && frac[tlen - 1] == '0') {
            frac[--tlen] = '\0';
        }

        if (tlen == 0 || (tlen == 1 && frac[0] == '0')) {
            snprintf(out, out_size, "%s.0", whole);
        } else {
            snprintf(out, out_size, "%s.%s", whole, frac);
        }
    }
}

/* ============================================================================
 * JUPITER QUOTE API
 * ============================================================================ */

static int jupiter_get_quote(
    const sol_token_t *from_tok,
    const sol_token_t *to_tok,
    const char *amount_raw,
    sol_dex_quote_t *quote_out
) {
    /* Build URL */
    char url[512];
    snprintf(url, sizeof(url),
             "%s?inputMint=%s&outputMint=%s&amount=%s&slippageBps=50",
             JUPITER_QUOTE_URL, from_tok->mint, to_tok->mint, amount_raw);

    QGP_LOG_DEBUG(LOG_TAG, "Jupiter quote: %s", url);

    /* HTTP GET */
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "curl_easy_init failed");
        return -1;
    }

    curl_buf_t buf = { .data = NULL, .size = 0 };
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "Jupiter request failed: %s", curl_easy_strerror(res));
        free(buf.data);
        return -1;
    }

    if (http_code != 200) {
        QGP_LOG_ERROR(LOG_TAG, "Jupiter HTTP %ld: %.200s", http_code, buf.data);
        free(buf.data);
        return (http_code == 400) ? -2 : -1;
    }

    /* Parse JSON response */
    json_object *root = json_tokener_parse(buf.data);
    free(buf.data);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Jupiter JSON parse failed");
        return -1;
    }

    /* Extract fields */
    json_object *in_amount_obj, *out_amount_obj, *impact_obj, *route_plan_obj;
    if (!json_object_object_get_ex(root, "inAmount", &in_amount_obj) ||
        !json_object_object_get_ex(root, "outAmount", &out_amount_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "Jupiter response missing inAmount/outAmount");
        json_object_put(root);
        return -1;
    }

    const char *in_amount_raw = json_object_get_string(in_amount_obj);
    const char *out_amount_raw = json_object_get_string(out_amount_obj);

    /* Price impact */
    const char *impact_str = "0";
    if (json_object_object_get_ex(root, "priceImpactPct", &impact_obj)) {
        impact_str = json_object_get_string(impact_obj);
    }

    /* DEX name from routePlan[0].swapInfo.label */
    const char *dex_label = "Jupiter";
    const char *amm_key = "";
    if (json_object_object_get_ex(root, "routePlan", &route_plan_obj) &&
        json_object_is_type(route_plan_obj, json_type_array) &&
        json_object_array_length(route_plan_obj) > 0) {
        json_object *step0 = json_object_array_get_idx(route_plan_obj, 0);
        json_object *swap_info;
        if (json_object_object_get_ex(step0, "swapInfo", &swap_info)) {
            json_object *label_obj, *amm_obj;
            if (json_object_object_get_ex(swap_info, "label", &label_obj)) {
                dex_label = json_object_get_string(label_obj);
            }
            if (json_object_object_get_ex(swap_info, "ammKey", &amm_obj)) {
                amm_key = json_object_get_string(amm_obj);
            }
        }
    }

    /* Fill quote result */
    memset(quote_out, 0, sizeof(*quote_out));
    strncpy(quote_out->from_token, from_tok->symbol, sizeof(quote_out->from_token) - 1);
    strncpy(quote_out->to_token, to_tok->symbol, sizeof(quote_out->to_token) - 1);
    strncpy(quote_out->dex_name, dex_label, sizeof(quote_out->dex_name) - 1);
    strncpy(quote_out->pool_address, amm_key, sizeof(quote_out->pool_address) - 1);
    quote_out->from_decimals = from_tok->decimals;
    quote_out->to_decimals = to_tok->decimals;

    /* Convert raw amounts to decimal strings */
    raw_to_decimal(in_amount_raw, from_tok->decimals,
                   quote_out->amount_in, sizeof(quote_out->amount_in));
    raw_to_decimal(out_amount_raw, to_tok->decimals,
                   quote_out->amount_out, sizeof(quote_out->amount_out));

    /* Price impact — Jupiter returns as decimal string (e.g. "0.0012" = 0.12%) */
    double impact_val = atof(impact_str) * 100.0;
    snprintf(quote_out->price_impact, sizeof(quote_out->price_impact), "%.2f", impact_val);

    /* Price: 1 from = X to */
    double in_val = atof(quote_out->amount_in);
    double out_val = atof(quote_out->amount_out);
    if (in_val > 0.0) {
        snprintf(quote_out->price, sizeof(quote_out->price), "%.6f", out_val / in_val);
    } else {
        strncpy(quote_out->price, "0", sizeof(quote_out->price) - 1);
    }

    /* Fee — Jupiter doesn't return explicit fee in quote, show as N/A */
    strncpy(quote_out->fee, "included", sizeof(quote_out->fee) - 1);

    QGP_LOG_INFO(LOG_TAG, "Jupiter quote: %s %s -> %s %s via %s (impact: %s%%)",
                 quote_out->amount_in, from_tok->symbol,
                 quote_out->amount_out, to_tok->symbol,
                 dex_label, quote_out->price_impact);

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int sol_dex_get_quotes(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    sol_dex_quote_t *quotes_out,
    int max_quotes,
    int *count_out
) {
    if (!from_token || !to_token || !amount_in || !quotes_out || !count_out) return -1;
    *count_out = 0;

    /* Resolve token symbols to mint addresses */
    const sol_token_t *from_tok = find_token(from_token);
    const sol_token_t *to_tok = find_token(to_token);
    if (!from_tok || !to_tok) {
        QGP_LOG_WARN(LOG_TAG, "Unknown token: %s or %s", from_token, to_token);
        return -2;
    }

    if (max_quotes < 1) return -1;

    /* Convert decimal amount to raw lamports */
    char *amount_raw = decimal_to_raw(amount_in, from_tok->decimals);
    if (!amount_raw) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to convert amount: %s", amount_in);
        return -1;
    }

    /* Jupiter returns the best route — one quote per call */
    int rc = jupiter_get_quote(from_tok, to_tok, amount_raw, &quotes_out[0]);
    free(amount_raw);

    if (rc != 0) return rc;

    /* Apply dex_filter if specified */
    if (dex_filter && dex_filter[0] != '\0') {
        if (!dex_strcasestr(quotes_out[0].dex_name, dex_filter)) {
            QGP_LOG_DEBUG(LOG_TAG, "Quote filtered: %s doesn't match %s",
                          quotes_out[0].dex_name, dex_filter);
            return -2;
        }
    }

    *count_out = 1;
    return 0;
}

int sol_dex_list_pairs(char ***pairs_out, int *count_out) {
    if (!pairs_out || !count_out) return -1;

    int total = NUM_KNOWN_PAIRS * 2;  /* Both directions */
    char **pairs = calloc((size_t)total, sizeof(char *));
    if (!pairs) return -1;

    int idx = 0;
    for (size_t i = 0; i < NUM_KNOWN_PAIRS; i++) {
        pairs[idx] = malloc(32);
        if (pairs[idx]) {
            snprintf(pairs[idx], 32, "%s/%s", known_pairs[i][0], known_pairs[i][1]);
        }
        idx++;

        pairs[idx] = malloc(32);
        if (pairs[idx]) {
            snprintf(pairs[idx], 32, "%s/%s", known_pairs[i][1], known_pairs[i][0]);
        }
        idx++;
    }

    *pairs_out = pairs;
    *count_out = total;
    return 0;
}

void sol_dex_free_pairs(char **pairs, int count) {
    if (!pairs) return;
    for (int i = 0; i < count; i++) {
        free(pairs[i]);
    }
    free(pairs);
}
