/**
 * @file sol_dex.c
 * @brief Solana DEX Quote Implementation (Raydium AMM v4)
 *
 * On-chain quote fetching from Raydium CPMM pools.
 * 1. Reads pool account data via getAccountInfo to extract vault pubkeys
 * 2. Reads vault balances via getTokenAccountBalance
 * 3. Applies constant product (x*y=k) formula for quote
 *
 * No external API — purely on-chain data via Solana JSON-RPC.
 *
 * Pool layout reference: raydium-io/raydium-amm (state.rs AmmInfo struct)
 * Total size: 752 bytes. coin_vault at offset 296, pc_vault at offset 328.
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#include "sol_dex.h"
#include "sol_rpc.h"
#include "sol_wallet.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <json-c/json.h>

/* Internal RPC function from sol_rpc.c (not in public header to avoid json-c dependency) */
extern int sol_rpc_call(const char *method, json_object *params, json_object **result_out);

#define LOG_TAG "SOL_DEX"

/* Raydium AMM v4 fee: 0.25% (25 bps) */
#define RAYDIUM_FEE_NUMERATOR   25
#define RAYDIUM_FEE_DENOMINATOR 10000

/* Raydium AMM v4 pool account layout offsets (from state.rs AmmInfo)
 *
 * Layout: 16 x u64 (128) + Fees (64) + StateData (144) + Pubkeys...
 *   0-127:   u64 fields (status, nonce, ..., sys_decimal_value)
 *   128-191: Fees struct (8 x u64 = 64 bytes)
 *   192-335: StateData struct (144 bytes: u64s + u128s)
 *   336:     coin_vault (Pubkey, 32 bytes)
 *   368:     pc_vault (Pubkey, 32 bytes)
 *   400:     coin_vault_mint (Pubkey, 32 bytes)
 *   432:     pc_vault_mint (Pubkey, 32 bytes)
 *   464:     lp_mint (Pubkey, 32 bytes)
 *   496+:    open_orders, market, market_program, target_orders, padding, amm_owner
 *
 * Verified against live mainnet pool 58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2:
 *   coin_mint(400) = So11...112 (wSOL), pc_mint(432) = EPjFW...Dt1v (USDC)
 */
#define AMM_COIN_DECIMALS_OFFSET  32   /* u64: coin token decimals */
#define AMM_PC_DECIMALS_OFFSET    40   /* u64: pc token decimals */
#define AMM_COIN_VAULT_OFFSET    336   /* Pubkey: coin vault SPL token account */
#define AMM_PC_VAULT_OFFSET      368   /* Pubkey: pc vault SPL token account */
#define AMM_COIN_MINT_OFFSET     400   /* Pubkey: coin mint */
#define AMM_PC_MINT_OFFSET       432   /* Pubkey: pc mint */
#define AMM_ACCOUNT_SIZE         752   /* Total AmmInfo size (on-chain) */

/* ============================================================================
 * KNOWN RAYDIUM v4 POOL ADDRESSES (Mainnet)
 *
 * Only the pool address is needed — vault addresses and decimals are
 * extracted at runtime from on-chain pool account data.
 *
 * Sources:
 *   SOL/USDC: raydium-sdk-v1 README, GeckoTerminal, Solscan
 *   SOL/USDT: GeckoTerminal, DEX Screener (confirmed $1.17M liquidity)
 *   USDC/USDT: Raydium liquidity pool list
 * ============================================================================ */

typedef struct {
    const char *token_a;        /* Coin token symbol (maps to coin_vault) */
    const char *token_b;        /* PC token symbol (maps to pc_vault) */
    const char *pool_address;   /* Raydium AMM v4 pool account address */
} raydium_pool_t;

static const raydium_pool_t known_pools[] = {
    /* SOL/USDC — primary Raydium v4 pool */
    {
        .token_a = "SOL",
        .token_b = "USDC",
        .pool_address = "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2",
    },
    /* SOL/USDT — Raydium v4 pool */
    {
        .token_a = "SOL",
        .token_b = "USDT",
        .pool_address = "7XawhbbxtsRcQA8KTkHT9f9nc6d69UwqCDh6U5EEbEmX",
    },
};

#define NUM_KNOWN_POOLS (sizeof(known_pools) / sizeof(known_pools[0]))

/* ============================================================================
 * INTERNAL: Read pool account data and extract vault pubkeys + decimals
 * ============================================================================ */

/**
 * Decode base64-encoded pool data and extract fields at known offsets.
 * Returns vault addresses as base58 strings and decimals.
 */
static int parse_pool_data(
    const char *base64_data,
    char *coin_vault_out,   /* base58, at least 45 bytes */
    char *pc_vault_out,     /* base58, at least 45 bytes */
    uint8_t *coin_decimals_out,
    uint8_t *pc_decimals_out
) {
    if (!base64_data) return -1;

    /* Decode base64 to raw bytes */
    /* Simple base64 decode — pool data is ~752 bytes = ~1004 base64 chars */
    size_t b64_len = strlen(base64_data);
    size_t max_decoded = (b64_len * 3) / 4 + 4;
    uint8_t *raw = malloc(max_decoded);
    if (!raw) return -1;

    /* Base64 decode table */
    static const int b64_table[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
    };

    size_t decoded_len = 0;
    uint32_t accum = 0;
    int bits = 0;
    for (size_t i = 0; i < b64_len; i++) {
        uint8_t c = (uint8_t)base64_data[i];
        if (c == '=' || c == '\n' || c == '\r') continue;
        accum = (accum << 6) | b64_table[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            raw[decoded_len++] = (uint8_t)(accum >> bits) & 0xFF;
        }
    }

    if (decoded_len < AMM_ACCOUNT_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Pool data too short: %zu < %d", decoded_len, AMM_ACCOUNT_SIZE);
        free(raw);
        return -1;
    }

    /* Extract decimals (u64 stored as little-endian, we only need low byte) */
    *coin_decimals_out = raw[AMM_COIN_DECIMALS_OFFSET];
    *pc_decimals_out = raw[AMM_PC_DECIMALS_OFFSET];

    /* Extract coin_vault pubkey (32 bytes at offset 296) → base58 */
    uint8_t coin_vault_pubkey[32];
    memcpy(coin_vault_pubkey, raw + AMM_COIN_VAULT_OFFSET, 32);
    if (sol_pubkey_to_address(coin_vault_pubkey, coin_vault_out) != 0) {
        free(raw);
        return -1;
    }

    /* Extract pc_vault pubkey (32 bytes at offset 328) → base58 */
    uint8_t pc_vault_pubkey[32];
    memcpy(pc_vault_pubkey, raw + AMM_PC_VAULT_OFFSET, 32);
    if (sol_pubkey_to_address(pc_vault_pubkey, pc_vault_out) != 0) {
        free(raw);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Pool parsed: coin_vault=%s pc_vault=%s coin_dec=%d pc_dec=%d",
                  coin_vault_out, pc_vault_out, *coin_decimals_out, *pc_decimals_out);

    free(raw);
    return 0;
}

/**
 * Fetch pool account data via getAccountInfo RPC
 */
static int fetch_pool_data(
    const char *pool_address,
    char *coin_vault_out,
    char *pc_vault_out,
    uint8_t *coin_decimals_out,
    uint8_t *pc_decimals_out
) {
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(pool_address));

    /* Request base64 encoding for raw data access */
    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("base64"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    int rc = sol_rpc_call("getAccountInfo", params, &result);
    json_object_put(params);

    if (rc != 0 || !result) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch pool account: %s", pool_address);
        return -1;
    }

    /* Extract: result.value.data[0] (base64 string) */
    json_object *value_obj, *data_arr;
    if (!json_object_object_get_ex(result, "value", &value_obj) || !value_obj ||
        json_object_is_type(value_obj, json_type_null)) {
        QGP_LOG_ERROR(LOG_TAG, "Pool account not found: %s", pool_address);
        json_object_put(result);
        return -1;
    }

    if (!json_object_object_get_ex(value_obj, "data", &data_arr) ||
        !json_object_is_type(data_arr, json_type_array) ||
        json_object_array_length(data_arr) < 1) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid pool data format");
        json_object_put(result);
        return -1;
    }

    const char *base64_data = json_object_get_string(json_object_array_get_idx(data_arr, 0));
    rc = parse_pool_data(base64_data, coin_vault_out, pc_vault_out,
                         coin_decimals_out, pc_decimals_out);

    json_object_put(result);
    return rc;
}

/* ============================================================================
 * INTERNAL: Read vault balance via getTokenAccountBalance
 * ============================================================================ */

static int read_vault_balance(const char *vault_address, uint64_t *balance_out) {
    if (!vault_address || !balance_out) return -1;

    *balance_out = 0;

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(vault_address));

    json_object *result = NULL;
    int rc = sol_rpc_call("getTokenAccountBalance", params, &result);
    json_object_put(params);

    if (rc != 0 || !result) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read vault balance: %s", vault_address);
        return -1;
    }

    /* Parse: result.value.amount (string of base units) */
    json_object *value_obj, *amount_obj;
    if (json_object_object_get_ex(result, "value", &value_obj) &&
        json_object_object_get_ex(value_obj, "amount", &amount_obj)) {
        const char *amount_str = json_object_get_string(amount_obj);
        if (amount_str) {
            *balance_out = strtoull(amount_str, NULL, 10);
        }
    }

    json_object_put(result);
    return 0;
}

/* ============================================================================
 * INTERNAL: Find pool for token pair
 * ============================================================================ */

static int find_pool(const char *from_token, const char *to_token, bool *reversed) {
    for (size_t i = 0; i < NUM_KNOWN_POOLS; i++) {
        if (strcasecmp(known_pools[i].token_a, from_token) == 0 &&
            strcasecmp(known_pools[i].token_b, to_token) == 0) {
            *reversed = false;
            return (int)i;
        }
        if (strcasecmp(known_pools[i].token_b, from_token) == 0 &&
            strcasecmp(known_pools[i].token_a, to_token) == 0) {
            *reversed = true;
            return (int)i;
        }
    }
    return -1;
}

/* ============================================================================
 * INTERNAL: Amount formatting
 * ============================================================================ */

static void format_amount(uint64_t raw, uint8_t decimals, char *out, size_t out_size) {
    if (raw == 0) {
        snprintf(out, out_size, "0.0");
        return;
    }

    uint64_t divisor = 1;
    for (int i = 0; i < decimals; i++) {
        divisor *= 10;
    }

    uint64_t whole = raw / divisor;
    uint64_t frac = raw % divisor;

    if (frac == 0) {
        snprintf(out, out_size, "%llu.0", (unsigned long long)whole);
    } else {
        char frac_str[32];
        snprintf(frac_str, sizeof(frac_str), "%0*llu", decimals, (unsigned long long)frac);

        /* Trim trailing zeros */
        int len = (int)strlen(frac_str);
        while (len > 0 && frac_str[len - 1] == '0') {
            frac_str[--len] = '\0';
        }

        snprintf(out, out_size, "%llu.%s", (unsigned long long)whole, frac_str);
    }
}

static uint64_t parse_amount(const char *amount_str, uint8_t decimals) {
    if (!amount_str) return 0;

    const char *dot = strchr(amount_str, '.');
    uint64_t whole = strtoull(amount_str, NULL, 10);

    uint64_t divisor = 1;
    for (int i = 0; i < decimals; i++) {
        divisor *= 10;
    }

    uint64_t result = whole * divisor;

    if (dot) {
        const char *frac_start = dot + 1;
        int frac_len = (int)strlen(frac_start);
        uint64_t frac_val = strtoull(frac_start, NULL, 10);

        if (frac_len < decimals) {
            for (int i = 0; i < decimals - frac_len; i++) {
                frac_val *= 10;
            }
        } else if (frac_len > decimals) {
            for (int i = 0; i < frac_len - decimals; i++) {
                frac_val /= 10;
            }
        }

        result += frac_val;
    }

    return result;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int sol_dex_get_quote(
    const char *from_token,
    const char *to_token,
    const char *amount_in_str,
    sol_dex_quote_t *quote_out
) {
    if (!from_token || !to_token || !amount_in_str || !quote_out) return -1;

    memset(quote_out, 0, sizeof(sol_dex_quote_t));

    /* Find pool */
    bool reversed = false;
    int pool_idx = find_pool(from_token, to_token, &reversed);
    if (pool_idx < 0) {
        QGP_LOG_WARN(LOG_TAG, "No pool found for %s/%s", from_token, to_token);
        return -2;
    }

    const raydium_pool_t *pool = &known_pools[pool_idx];

    /* Step 1: Fetch pool account data to get vault addresses + decimals */
    char coin_vault[48] = {0};
    char pc_vault[48] = {0};
    uint8_t coin_decimals = 0, pc_decimals = 0;

    if (fetch_pool_data(pool->pool_address, coin_vault, pc_vault,
                        &coin_decimals, &pc_decimals) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse pool data for %s", pool->pool_address);
        return -1;
    }

    /* Determine input/output based on direction */
    const char *in_vault  = reversed ? pc_vault : coin_vault;
    const char *out_vault = reversed ? coin_vault : pc_vault;
    uint8_t in_decimals   = reversed ? pc_decimals : coin_decimals;
    uint8_t out_decimals  = reversed ? coin_decimals : pc_decimals;

    /* Step 2: Read vault balances (reserves) */
    uint64_t reserve_in = 0, reserve_out = 0;
    if (read_vault_balance(in_vault, &reserve_in) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read input vault: %s", in_vault);
        return -1;
    }
    if (read_vault_balance(out_vault, &reserve_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read output vault: %s", out_vault);
        return -1;
    }

    if (reserve_in == 0 || reserve_out == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Pool has zero reserves (in=%llu out=%llu)",
                      (unsigned long long)reserve_in, (unsigned long long)reserve_out);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Pool %s/%s reserves: in=%llu out=%llu",
                  from_token, to_token,
                  (unsigned long long)reserve_in,
                  (unsigned long long)reserve_out);

    /* Step 3: Calculate quote using CPMM formula */
    uint64_t amount_in = parse_amount(amount_in_str, in_decimals);
    if (amount_in == 0) {
        QGP_LOG_WARN(LOG_TAG, "Input amount is zero");
        return -1;
    }

    /* Raydium CPMM with 0.25% fee:
     * amount_in_with_fee = amount_in * (10000 - 25)
     * amount_out = (reserve_out * amount_in_with_fee) / (reserve_in * 10000 + amount_in_with_fee)
     *
     * Using __uint128_t to prevent overflow with large reserves
     */
    __uint128_t in_with_fee = (__uint128_t)amount_in * (RAYDIUM_FEE_DENOMINATOR - RAYDIUM_FEE_NUMERATOR);
    __uint128_t numerator   = (__uint128_t)reserve_out * in_with_fee;
    __uint128_t denominator = (__uint128_t)reserve_in * RAYDIUM_FEE_DENOMINATOR + in_with_fee;

    if (denominator == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Division by zero in quote calculation");
        return -1;
    }

    uint64_t amount_out = (uint64_t)(numerator / denominator);
    uint64_t fee_amount = (amount_in * RAYDIUM_FEE_NUMERATOR) / RAYDIUM_FEE_DENOMINATOR;

    /* Price impact */
    double reserve_ratio = (double)reserve_out / (double)reserve_in;
    double ideal_out = (double)amount_in * reserve_ratio;
    double price_impact = 0.0;
    if (ideal_out > 0) {
        price_impact = ((ideal_out - (double)amount_out) / ideal_out) * 100.0;
    }

    /* Spot price (1 from_token = X to_token), adjusted for decimals */
    double in_divisor = 1.0, out_divisor = 1.0;
    for (int i = 0; i < in_decimals; i++) in_divisor *= 10.0;
    for (int i = 0; i < out_decimals; i++) out_divisor *= 10.0;
    double price = ((double)reserve_out / out_divisor) / ((double)reserve_in / in_divisor);

    /* Fill result */
    strncpy(quote_out->from_token, from_token, sizeof(quote_out->from_token) - 1);
    strncpy(quote_out->to_token, to_token, sizeof(quote_out->to_token) - 1);
    strncpy(quote_out->amount_in, amount_in_str, sizeof(quote_out->amount_in) - 1);
    strncpy(quote_out->pool_address, pool->pool_address, sizeof(quote_out->pool_address) - 1);
    quote_out->from_decimals = in_decimals;
    quote_out->to_decimals = out_decimals;

    format_amount(amount_out, out_decimals, quote_out->amount_out, sizeof(quote_out->amount_out));
    format_amount(fee_amount, in_decimals, quote_out->fee, sizeof(quote_out->fee));
    snprintf(quote_out->price, sizeof(quote_out->price), "%.6f", price);
    snprintf(quote_out->price_impact, sizeof(quote_out->price_impact), "%.2f", price_impact);

    QGP_LOG_INFO(LOG_TAG, "Quote: %s %s -> %s %s (impact: %s%%, fee: %s)",
                 amount_in_str, from_token,
                 quote_out->amount_out, to_token,
                 quote_out->price_impact, quote_out->fee);

    return 0;
}

int sol_dex_list_pairs(char ***pairs_out, int *count_out) {
    if (!pairs_out || !count_out) return -1;

    int total = NUM_KNOWN_POOLS * 2;
    char **pairs = calloc(total, sizeof(char *));
    if (!pairs) return -1;

    int idx = 0;
    for (size_t i = 0; i < NUM_KNOWN_POOLS; i++) {
        pairs[idx] = malloc(32);
        if (pairs[idx]) {
            snprintf(pairs[idx], 32, "%s/%s", known_pools[i].token_a, known_pools[i].token_b);
        }
        idx++;

        pairs[idx] = malloc(32);
        if (pairs[idx]) {
            snprintf(pairs[idx], 32, "%s/%s", known_pools[i].token_b, known_pools[i].token_a);
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
