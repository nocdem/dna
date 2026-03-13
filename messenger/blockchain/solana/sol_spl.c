/**
 * @file sol_spl.c
 * @brief SPL Token Implementation for Solana
 *
 * @author DNA Connect Team
 * @date 2025-12-16
 */

#include "sol_spl.h"
#include "sol_rpc.h"
#include "sol_wallet.h"
#include "sol_tx.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "SOL_SPL"

/* Known SPL tokens */
static const sol_spl_token_t known_tokens[] = {
    { SOL_USDT_MINT, "USDT", SOL_USDT_DECIMALS },
    { SOL_USDC_MINT, "USDC", SOL_USDC_DECIMALS },
};

#define NUM_KNOWN_TOKENS (sizeof(known_tokens) / sizeof(known_tokens[0]))

/* Response buffer */
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

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

int sol_spl_get_token(const char *symbol, sol_spl_token_t *token_out) {
    if (!symbol || !token_out) {
        return -1;
    }

    for (size_t i = 0; i < NUM_KNOWN_TOKENS; i++) {
        if (strcasecmp(known_tokens[i].symbol, symbol) == 0) {
            *token_out = known_tokens[i];
            return 0;
        }
    }

    return -1;
}

bool sol_spl_is_supported(const char *symbol) {
    if (!symbol) return false;

    for (size_t i = 0; i < NUM_KNOWN_TOKENS; i++) {
        if (strcasecmp(known_tokens[i].symbol, symbol) == 0) {
            return true;
        }
    }

    return false;
}

/* ============================================================================
 * BALANCE QUERIES
 * ============================================================================ */

int sol_spl_get_balance(
    const char *address,
    const char *mint,
    uint8_t decimals,
    char *balance_out,
    size_t balance_size
) {
    if (!address || !mint || !balance_out || balance_size == 0) {
        return -1;
    }

    /* Initialize with 0 balance */
    strncpy(balance_out, "0", balance_size);

    /* Check endpoint is available */
    const char *endpoint = sol_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "Solana RPC endpoint not configured");
        return -1;
    }

    /* Rate limit to avoid 429 errors */
    sol_rpc_rate_limit_delay();

    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build JSON-RPC request for getTokenAccountsByOwner */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "id", json_object_new_int(1));
    json_object_object_add(req, "method", json_object_new_string("getTokenAccountsByOwner"));

    /* Params: [address, {mint: mint_address}, {encoding: "jsonParsed"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));

    json_object *filter = json_object_new_object();
    json_object_object_add(filter, "mint", json_object_new_string(mint));
    json_object_array_add(params, filter);

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("jsonParsed"));
    json_object_array_add(params, opts);

    json_object_object_add(req, "params", params);

    const char *json_str = json_object_to_json_string(req);

    QGP_LOG_DEBUG(LOG_TAG, "SPL balance request: %s", json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
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

    QGP_LOG_DEBUG(LOG_TAG, "SPL balance response: %.500s", resp_buf.data);

    /* Parse response */
    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON response");
        return -1;
    }

    /* Check for error */
    json_object *error_obj;
    if (json_object_object_get_ex(resp, "error", &error_obj) && error_obj) {
        json_object *msg_obj;
        const char *err_msg = "Unknown error";
        if (json_object_object_get_ex(error_obj, "message", &msg_obj)) {
            err_msg = json_object_get_string(msg_obj);
        }
        QGP_LOG_ERROR(LOG_TAG, "RPC error: %s", err_msg);
        json_object_put(resp);
        return -1;
    }

    /* Extract result */
    json_object *result;
    if (!json_object_object_get_ex(resp, "result", &result)) {
        QGP_LOG_ERROR(LOG_TAG, "No result in response");
        json_object_put(resp);
        return -1;
    }

    /* Get value array */
    json_object *value_arr;
    if (!json_object_object_get_ex(result, "value", &value_arr)) {
        QGP_LOG_ERROR(LOG_TAG, "No value in result");
        json_object_put(resp);
        return -1;
    }

    /* Sum up all token account balances (usually just one) */
    uint64_t total_amount = 0;
    int arr_len = json_object_array_length(value_arr);

    for (int i = 0; i < arr_len; i++) {
        json_object *account = json_object_array_get_idx(value_arr, i);
        json_object *account_data, *parsed, *info, *token_amount, *amount_obj;

        if (json_object_object_get_ex(account, "account", &account_data) &&
            json_object_object_get_ex(account_data, "data", &parsed) &&
            json_object_object_get_ex(parsed, "parsed", &info) &&
            json_object_object_get_ex(info, "info", &token_amount) &&
            json_object_object_get_ex(token_amount, "tokenAmount", &amount_obj)) {

            json_object *amt_str;
            if (json_object_object_get_ex(amount_obj, "amount", &amt_str)) {
                const char *amount_str = json_object_get_string(amt_str);
                if (amount_str) {
                    total_amount += strtoull(amount_str, NULL, 10);
                }
            }
        }
    }

    /* Format balance with decimals */
    if (total_amount == 0) {
        snprintf(balance_out, balance_size, "0.0");
    } else {
        /* Calculate divisor based on decimals */
        uint64_t divisor = 1;
        for (int i = 0; i < decimals; i++) {
            divisor *= 10;
        }

        uint64_t whole = total_amount / divisor;
        uint64_t frac = total_amount % divisor;

        if (frac == 0) {
            snprintf(balance_out, balance_size, "%llu.0", (unsigned long long)whole);
        } else {
            /* Format with appropriate decimal places */
            char frac_str[32];
            snprintf(frac_str, sizeof(frac_str), "%0*llu", decimals, (unsigned long long)frac);

            /* Trim trailing zeros */
            int len = strlen(frac_str);
            while (len > 0 && frac_str[len - 1] == '0') {
                frac_str[--len] = '\0';
            }

            snprintf(balance_out, balance_size, "%llu.%s", (unsigned long long)whole, frac_str);
        }
    }

    json_object_put(resp);
    QGP_LOG_DEBUG(LOG_TAG, "SPL balance for %s: %s", mint, balance_out);

    return 0;
}

int sol_spl_get_balance_by_symbol(
    const char *address,
    const char *symbol,
    char *balance_out,
    size_t balance_size
) {
    sol_spl_token_t token;
    if (sol_spl_get_token(symbol, &token) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Unknown token: %s", symbol);
        return -1;
    }

    return sol_spl_get_balance(address, token.mint, token.decimals, balance_out, balance_size);
}

/* ============================================================================
 * ATA (ASSOCIATED TOKEN ACCOUNT) FUNCTIONS
 * ============================================================================ */

/**
 * Check if a 32-byte value is on the Ed25519 curve.
 *
 * Ed25519 curve equation: -x² + y² = 1 + d·x²·y²  (mod p)
 * where p = 2^255 - 19, d = -121665/121666 mod p
 *
 * The 32-byte compressed encoding stores y (255 bits) + sign of x (1 bit).
 * A point is on the curve iff y < p AND (y²-1)/(d·y²+1) is a quadratic residue mod p.
 *
 * Returns true if on curve, false if off curve (valid PDA).
 */
static bool is_on_ed25519_curve(const uint8_t point[32]) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return true; /* fail safe: assume on curve */

    BIGNUM *p = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *y2 = BN_new();
    BIGNUM *u = BN_new();
    BIGNUM *v = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *check = BN_new();
    BIGNUM *one = BN_new();
    bool on_curve = false;

    /* p = 2^255 - 19 */
    BN_set_word(p, 1);
    BN_lshift(p, p, 255);
    BIGNUM *nineteen = BN_new();
    BN_set_word(nineteen, 19);
    BN_sub(p, p, nineteen);
    BN_free(nineteen);

    /* d = -121665/121666 mod p = 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
    BN_dec2bn(&d, "37095705934669439343138083508754565189542113879843219016388785533085940283555");

    /* Extract y from point (little-endian, clear top bit which is sign of x) */
    uint8_t y_bytes[32];
    memcpy(y_bytes, point, 32);
    y_bytes[31] &= 0x7F;  /* clear sign bit */

    /* Convert from little-endian to BIGNUM */
    uint8_t y_be[32];
    for (int i = 0; i < 32; i++) {
        y_be[i] = y_bytes[31 - i];
    }
    BN_bin2bn(y_be, 32, y);

    /* Check y < p */
    if (BN_cmp(y, p) >= 0) {
        goto cleanup;  /* y >= p means not on curve */
    }

    BN_set_word(one, 1);

    /* u = y² - 1 mod p */
    BN_mod_sqr(y2, y, p, ctx);
    BN_mod_sub(u, y2, one, p, ctx);

    /* v = d·y² + 1 mod p */
    BN_mod_mul(v, d, y2, p, ctx);
    BN_mod_add(v, v, one, p, ctx);

    /* x² = u · v^(-1) mod p */
    BN_mod_inverse(v, v, p, ctx);
    if (!v) {
        /* v has no inverse — not on curve */
        goto cleanup;
    }
    BN_mod_mul(x2, u, v, p, ctx);

    /* Check if x² is a quadratic residue: x²^((p-1)/2) ∈ {0, 1} mod p */
    /* exp = (p-1)/2 */
    BN_copy(exp, p);
    BN_sub_word(exp, 1);
    BN_rshift1(exp, exp);

    BN_mod_exp(check, x2, exp, p, ctx);

    /* QR check: result must be 0 or 1 */
    if (BN_is_zero(check) || BN_is_one(check)) {
        on_curve = true;
    }

cleanup:
    BN_free(p);
    BN_free(d);
    BN_free(y);
    BN_free(y2);
    BN_free(u);
    BN_free(v);
    BN_free(x2);
    BN_free(exp);
    BN_free(check);
    BN_free(one);
    BN_CTX_free(ctx);

    return on_curve;
}

int sol_spl_derive_ata(
    const uint8_t owner_pubkey[32],
    const uint8_t mint_pubkey[32],
    uint8_t ata_pubkey_out[32]
) {
    if (!owner_pubkey || !mint_pubkey || !ata_pubkey_out) {
        QGP_LOG_ERROR(LOG_TAG, "derive_ata: NULL parameter");
        return -1;
    }

    /* Decode program IDs from base58 */
    uint8_t token_program[32];
    uint8_t assoc_token_program[32];

    if (sol_address_to_pubkey(SOL_TOKEN_PROGRAM_ID, token_program) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decode Token Program ID");
        return -1;
    }
    if (sol_address_to_pubkey(SOL_ASSOCIATED_TOKEN_PROGRAM_ID, assoc_token_program) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decode Associated Token Program ID");
        return -1;
    }

    static const char pda_marker[] = "ProgramDerivedAddress";

    /*
     * PDA derivation: for bump = 255 down to 0
     *   hash = SHA256(owner(32) + token_program(32) + mint(32) + bump(1) + assoc_token_program(32) + "ProgramDerivedAddress")
     *   If hash is NOT on Ed25519 curve → valid PDA
     */
    for (int bump = 255; bump >= 0; bump--) {
        uint8_t bump_byte = (uint8_t)bump;

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create EVP_MD_CTX");
            return -1;
        }

        uint8_t hash[32];
        unsigned int hash_len = 0;

        if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(md_ctx, owner_pubkey, 32) != 1 ||
            EVP_DigestUpdate(md_ctx, token_program, 32) != 1 ||
            EVP_DigestUpdate(md_ctx, mint_pubkey, 32) != 1 ||
            EVP_DigestUpdate(md_ctx, &bump_byte, 1) != 1 ||
            EVP_DigestUpdate(md_ctx, assoc_token_program, 32) != 1 ||
            EVP_DigestUpdate(md_ctx, pda_marker, sizeof(pda_marker) - 1) != 1 ||
            EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            QGP_LOG_ERROR(LOG_TAG, "SHA256 computation failed");
            return -1;
        }
        EVP_MD_CTX_free(md_ctx);

        if (!is_on_ed25519_curve(hash)) {
            memcpy(ata_pubkey_out, hash, 32);
            QGP_LOG_DEBUG(LOG_TAG, "ATA derived with bump=%d", bump);
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Failed to derive ATA: no valid PDA found in 256 bumps");
    return -1;
}

int sol_spl_check_ata(
    const char *ata_address,
    bool *exists_out
) {
    if (!ata_address || !exists_out) {
        return -1;
    }

    *exists_out = false;

    /* Check endpoint */
    const char *endpoint = sol_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "Solana RPC endpoint not configured");
        return -1;
    }

    /* Rate limit */
    sol_rpc_rate_limit_delay();

    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build JSON-RPC request for getAccountInfo */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "id", json_object_new_int(1));
    json_object_object_add(req, "method", json_object_new_string("getAccountInfo"));

    /* Params: [ata_address, {"encoding": "jsonParsed"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(ata_address));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("jsonParsed"));
    json_object_array_add(params, opts);

    json_object_object_add(req, "params", params);

    const char *json_str = json_object_to_json_string(req);

    QGP_LOG_DEBUG(LOG_TAG, "ATA check request: %s", json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* Configure SSL CA bundle */
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

    QGP_LOG_DEBUG(LOG_TAG, "ATA check response: %.500s", resp_buf.data);

    /* Parse response */
    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!resp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse JSON response");
        return -1;
    }

    /* Check for RPC error */
    json_object *error_obj;
    if (json_object_object_get_ex(resp, "error", &error_obj) && error_obj) {
        json_object *msg_obj;
        const char *err_msg = "Unknown error";
        if (json_object_object_get_ex(error_obj, "message", &msg_obj)) {
            err_msg = json_object_get_string(msg_obj);
        }
        QGP_LOG_ERROR(LOG_TAG, "RPC error: %s", err_msg);
        json_object_put(resp);
        return -1;
    }

    /* Extract result */
    json_object *result;
    if (!json_object_object_get_ex(resp, "result", &result)) {
        QGP_LOG_ERROR(LOG_TAG, "No result in response");
        json_object_put(resp);
        return -1;
    }

    /* Check result.value — null means account doesn't exist */
    json_object *value;
    if (json_object_object_get_ex(result, "value", &value) && value &&
        !json_object_is_type(value, json_type_null)) {
        *exists_out = true;
        QGP_LOG_DEBUG(LOG_TAG, "ATA %s exists", ata_address);
    } else {
        *exists_out = false;
        QGP_LOG_DEBUG(LOG_TAG, "ATA %s does not exist", ata_address);
    }

    json_object_put(resp);
    return 0;
}

/* ============================================================================
 * AMOUNT PARSING HELPER
 * ============================================================================ */

/**
 * Parse a decimal amount string to raw token units.
 * E.g., "10.5" with 6 decimals → 10500000
 */
static int parse_amount_to_raw(const char *amount_str, uint8_t decimals, uint64_t *raw_out) {
    if (!amount_str || !raw_out) return -1;

    const char *p = amount_str;
    while (*p == ' ') p++;
    if (*p == '\0') return -1;

    const char *dot = strchr(p, '.');

    /* Parse whole part */
    uint64_t whole = 0;
    const char *end = dot ? dot : p + strlen(p);
    for (const char *c = p; c < end; c++) {
        if (*c < '0' || *c > '9') return -1;
        uint64_t prev = whole;
        whole = whole * 10 + (*c - '0');
        if (whole < prev) return -1;  /* overflow */
    }

    /* Parse fractional part — pad or truncate to `decimals` digits */
    uint64_t frac = 0;
    if (dot) {
        const char *frac_start = dot + 1;
        int frac_digits = 0;
        for (const char *c = frac_start; *c && frac_digits < decimals; c++) {
            if (*c < '0' || *c > '9') return -1;
            frac = frac * 10 + (*c - '0');
            frac_digits++;
        }
        for (int i = frac_digits; i < decimals; i++) {
            frac *= 10;
        }
    }

    /* Compute divisor for overflow check */
    uint64_t divisor = 1;
    for (int i = 0; i < decimals; i++) {
        divisor *= 10;
    }

    if (whole > UINT64_MAX / divisor) return -1;
    *raw_out = whole * divisor + frac;
    return 0;
}

/* ============================================================================
 * COMPACT-U16 ENCODING (duplicated from sol_tx.c — both are static)
 * ============================================================================ */

static size_t encode_compact_u16(uint16_t value, uint8_t *out) {
    if (value < 0x80) {
        out[0] = (uint8_t)value;
        return 1;
    } else if (value < 0x4000) {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(value >> 7);
        return 2;
    } else {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7f) | 0x80);
        out[2] = (uint8_t)(value >> 14);
        return 3;
    }
}

/* ============================================================================
 * SPL TOKEN TRANSFER
 * ============================================================================ */

int sol_spl_send(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *mint_address,
    const char *amount,
    uint8_t decimals,
    char *signature_out,
    size_t sig_out_size
) {
    if (!wallet || !to_address || !mint_address || !amount ||
        !signature_out || sig_out_size == 0) {
        return -1;
    }

    /* 1. Parse amount to raw token units */
    uint64_t raw_amount = 0;
    if (parse_amount_to_raw(amount, decimals, &raw_amount) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid token amount: %s", amount);
        return -1;
    }
    if (raw_amount == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Amount must be > 0");
        return -1;
    }
    QGP_LOG_DEBUG(LOG_TAG, "SPL send: %s raw units = %llu",
                  amount, (unsigned long long)raw_amount);

    /* 2. Decode addresses to pubkeys */
    uint8_t to_pubkey[32];
    if (sol_address_to_pubkey(to_address, to_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid recipient address: %s", to_address);
        return -1;
    }

    uint8_t mint_pubkey[32];
    if (sol_address_to_pubkey(mint_address, mint_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid mint address: %s", mint_address);
        return -4;
    }

    /* 3. Derive sender and recipient ATAs */
    uint8_t sender_ata[32];
    if (sol_spl_derive_ata(wallet->public_key, mint_pubkey, sender_ata) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive sender ATA");
        return -1;
    }

    uint8_t recipient_ata[32];
    if (sol_spl_derive_ata(to_pubkey, mint_pubkey, recipient_ata) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive recipient ATA");
        return -1;
    }

    /* 4. Check if recipient ATA exists */
    char recipient_ata_addr[SOL_ADDRESS_SIZE + 1];
    if (sol_pubkey_to_address(recipient_ata, recipient_ata_addr) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode recipient ATA address");
        return -1;
    }

    bool ata_exists = false;
    if (sol_spl_check_ata(recipient_ata_addr, &ata_exists) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to check recipient ATA existence");
        return -1;
    }
    QGP_LOG_DEBUG(LOG_TAG, "Recipient ATA %s exists: %s",
                  recipient_ata_addr, ata_exists ? "yes" : "no");

    /* 5. Get recent blockhash */
    uint8_t blockhash[32];
    if (sol_rpc_get_recent_blockhash(blockhash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get recent blockhash");
        return -1;
    }

    /* 6. Decode program IDs */
    uint8_t token_program[32];
    if (sol_address_to_pubkey(SOL_TOKEN_PROGRAM_ID, token_program) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decode Token Program ID");
        return -1;
    }

    /* 7. Build message */
    uint8_t message[1024];
    size_t msg_offset = 0;

    if (ata_exists) {
        /*
         * Simple transfer: 4 accounts, 1 instruction
         * Header: [1, 0, 1]
         * Accounts: sender, sender_ata, recipient_ata, token_program
         */
        message[msg_offset++] = 1;  /* num_required_signatures */
        message[msg_offset++] = 0;  /* num_readonly_signed */
        message[msg_offset++] = 1;  /* num_readonly_unsigned (token_program) */

        /* Account keys (4) */
        msg_offset += encode_compact_u16(4, message + msg_offset);
        memcpy(message + msg_offset, wallet->public_key, 32); msg_offset += 32;
        memcpy(message + msg_offset, sender_ata, 32);         msg_offset += 32;
        memcpy(message + msg_offset, recipient_ata, 32);      msg_offset += 32;
        memcpy(message + msg_offset, token_program, 32);      msg_offset += 32;

        /* Recent blockhash */
        memcpy(message + msg_offset, blockhash, 32);
        msg_offset += 32;

        /* Instructions (1): Token Transfer */
        msg_offset += encode_compact_u16(1, message + msg_offset);

        /* Token Transfer instruction */
        message[msg_offset++] = 3;  /* program_id_index = token_program */

        /* Account indices: [sender_ata=1, recipient_ata=2, owner=0] */
        msg_offset += encode_compact_u16(3, message + msg_offset);
        message[msg_offset++] = 1;  /* source (sender_ata) */
        message[msg_offset++] = 2;  /* destination (recipient_ata) */
        message[msg_offset++] = 0;  /* owner (sender) */

        /* Instruction data: 1-byte instruction type (3=Transfer) + 8-byte LE amount */
        msg_offset += encode_compact_u16(9, message + msg_offset);
        message[msg_offset++] = 3;  /* Transfer instruction */
        for (int i = 0; i < 8; i++) {
            message[msg_offset++] = (raw_amount >> (i * 8)) & 0xFF;
        }
    } else {
        /*
         * Create ATA + Transfer: 8 accounts, 2 instructions
         * Header: [1, 0, 4]
         * Accounts: sender, sender_ata, recipient_ata, recipient,
         *           mint, system_program, token_program, assoc_token_program
         */
        uint8_t system_program[32];
        uint8_t assoc_token_program[32];

        if (sol_address_to_pubkey("11111111111111111111111111111111", system_program) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decode System Program ID");
            return -1;
        }
        if (sol_address_to_pubkey(SOL_ASSOCIATED_TOKEN_PROGRAM_ID, assoc_token_program) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decode Associated Token Program ID");
            return -1;
        }

        message[msg_offset++] = 1;  /* num_required_signatures */
        message[msg_offset++] = 0;  /* num_readonly_signed */
        message[msg_offset++] = 4;  /* num_readonly_unsigned (recipient, mint, system, token, assoc) */
                                     /* Actually 4: mint, system_program, token_program, assoc_token_program */
                                     /* Wait: recipient is writable (receives ATA), sender_ata writable, recipient_ata writable */
                                     /* readonly unsigned: mint(4), system_program(5), token_program(6), assoc_token_program(7) */

        /* Account keys (8) */
        msg_offset += encode_compact_u16(8, message + msg_offset);
        memcpy(message + msg_offset, wallet->public_key, 32);  msg_offset += 32;  /* 0: sender (signer, writable) */
        memcpy(message + msg_offset, sender_ata, 32);           msg_offset += 32;  /* 1: sender_ata (writable) */
        memcpy(message + msg_offset, recipient_ata, 32);        msg_offset += 32;  /* 2: recipient_ata (writable) */
        memcpy(message + msg_offset, to_pubkey, 32);            msg_offset += 32;  /* 3: recipient (writable - wallet owner of new ATA) */
        memcpy(message + msg_offset, mint_pubkey, 32);          msg_offset += 32;  /* 4: mint (readonly) */
        memcpy(message + msg_offset, system_program, 32);       msg_offset += 32;  /* 5: system_program (readonly) */
        memcpy(message + msg_offset, token_program, 32);        msg_offset += 32;  /* 6: token_program (readonly) */
        memcpy(message + msg_offset, assoc_token_program, 32);  msg_offset += 32;  /* 7: assoc_token_program (readonly) */

        /* Recent blockhash */
        memcpy(message + msg_offset, blockhash, 32);
        msg_offset += 32;

        /* Instructions (2) */
        msg_offset += encode_compact_u16(2, message + msg_offset);

        /* Instruction 1: CreateAssociatedTokenAccount */
        message[msg_offset++] = 7;  /* program_id_index = assoc_token_program */

        /* Account indices: [payer=0, ata=2, wallet_owner=3, mint=4, system=5, token=6] */
        msg_offset += encode_compact_u16(6, message + msg_offset);
        message[msg_offset++] = 0;  /* payer (sender) */
        message[msg_offset++] = 2;  /* associated_token_account (recipient_ata) */
        message[msg_offset++] = 3;  /* wallet_address (recipient) */
        message[msg_offset++] = 4;  /* token_mint */
        message[msg_offset++] = 5;  /* system_program */
        message[msg_offset++] = 6;  /* token_program */

        /* Instruction data: empty for CreateAssociatedTokenAccount */
        msg_offset += encode_compact_u16(0, message + msg_offset);

        /* Instruction 2: Token Transfer */
        message[msg_offset++] = 6;  /* program_id_index = token_program */

        /* Account indices: [source=1, destination=2, owner=0] */
        msg_offset += encode_compact_u16(3, message + msg_offset);
        message[msg_offset++] = 1;  /* source (sender_ata) */
        message[msg_offset++] = 2;  /* destination (recipient_ata) */
        message[msg_offset++] = 0;  /* owner (sender) */

        /* Instruction data: 1-byte instruction type (3=Transfer) + 8-byte LE amount */
        msg_offset += encode_compact_u16(9, message + msg_offset);
        message[msg_offset++] = 3;  /* Transfer instruction */
        for (int i = 0; i < 8; i++) {
            message[msg_offset++] = (raw_amount >> (i * 8)) & 0xFF;
        }
    }

    /* 8. Sign the message */
    uint8_t signature[64];
    if (sol_sign_message(message, msg_offset,
                         wallet->private_key, wallet->public_key,
                         signature) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign SPL transaction");
        return -1;
    }

    /* 9. Build final TX: compact-u16(1) + signature(64) + message */
    uint8_t tx_data[2048];
    size_t tx_offset = 0;

    tx_offset += encode_compact_u16(1, tx_data + tx_offset);
    memcpy(tx_data + tx_offset, signature, 64);
    tx_offset += 64;
    memcpy(tx_data + tx_offset, message, msg_offset);
    tx_offset += msg_offset;

    /* 10. Base64 encode */
    char tx_base64[4096];
    sol_base64_encode(tx_data, tx_offset, tx_base64);

    /* 11. Send transaction */
    if (sol_rpc_send_transaction(tx_base64, signature_out, sig_out_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send SPL transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "SPL transfer sent: %s (amount=%llu, ata_created=%s)",
                 signature_out, (unsigned long long)raw_amount,
                 ata_exists ? "no" : "yes");
    return 0;
}

int sol_spl_send_by_symbol(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *symbol,
    const char *amount,
    char *signature_out,
    size_t sig_out_size
) {
    if (!wallet || !to_address || !symbol || !amount ||
        !signature_out || sig_out_size == 0) {
        return -1;
    }

    /* Try known token registry first */
    sol_spl_token_t token;
    if (sol_spl_get_token(symbol, &token) == 0) {
        return sol_spl_send(wallet, to_address, token.mint, amount,
                            token.decimals, signature_out, sig_out_size);
    }

    /* If symbol looks like a mint address (>= 32 chars), treat as raw mint */
    if (strlen(symbol) >= 32) {
        QGP_LOG_DEBUG(LOG_TAG, "Treating '%s' as mint address with 9 decimals", symbol);
        return sol_spl_send(wallet, to_address, symbol, amount,
                            9, signature_out, sig_out_size);
    }

    QGP_LOG_ERROR(LOG_TAG, "Unknown token symbol: %s", symbol);
    return -4;
}

/* ============================================================================
 * FEE ESTIMATION
 * ============================================================================ */

int sol_spl_estimate_fee(
    const char *owner_address,
    const char *to_address,
    const char *mint_address,
    uint64_t *fee_lamports_out,
    bool *ata_exists_out
) {
    if (!owner_address || !to_address || !mint_address || !fee_lamports_out) {
        return -1;
    }

    /* Decode addresses */
    uint8_t to_pubkey[32];
    if (sol_address_to_pubkey(to_address, to_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid recipient address: %s", to_address);
        return -1;
    }

    uint8_t mint_pubkey[32];
    if (sol_address_to_pubkey(mint_address, mint_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid mint address: %s", mint_address);
        return -1;
    }

    /* Derive recipient ATA */
    uint8_t recipient_ata[32];
    if (sol_spl_derive_ata(to_pubkey, mint_pubkey, recipient_ata) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive recipient ATA");
        return -1;
    }

    char recipient_ata_addr[SOL_ADDRESS_SIZE + 1];
    if (sol_pubkey_to_address(recipient_ata, recipient_ata_addr) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode recipient ATA address");
        return -1;
    }

    /* Check ATA existence */
    bool exists = false;
    if (sol_spl_check_ata(recipient_ata_addr, &exists) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to check ATA existence");
        return -1;
    }

    if (ata_exists_out) {
        *ata_exists_out = exists;
    }

    /* Base fee: 5000 lamports (signature fee) */
    uint64_t fee = 5000;

    if (!exists) {
        /* Add rent for creating the ATA (165 bytes token account) */
        uint64_t rent = 0;
        if (sol_rpc_get_minimum_balance_for_rent(SOL_TOKEN_ACCOUNT_DATA_SIZE, &rent) != 0) {
            rent = 2039280;  /* Fallback: well-known rent for 165-byte account */
            QGP_LOG_WARN(LOG_TAG, "Using fallback rent value: %llu",
                         (unsigned long long)rent);
        }
        fee += rent;
        QGP_LOG_DEBUG(LOG_TAG, "ATA creation needed, rent=%llu, total fee=%llu",
                      (unsigned long long)rent, (unsigned long long)fee);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "ATA exists, fee=%llu", (unsigned long long)fee);
    }

    *fee_lamports_out = fee;
    return 0;
}
