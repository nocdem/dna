/**
 * @file cellframe_dex.c
 * @brief Cellframe DEX Quote Implementation (Order Book Simulation)
 *
 * Fetches open orders from Cellframe public RPC and simulates filling
 * them as a taker. The order book is sorted by best rate and walked
 * until the user's requested amount is filled.
 *
 * Rate semantics in Cellframe:
 *   Order sells token_sell, wants token_buy.
 *   rate = how many token_buy per 1 token_sell
 *   So if order sells CELL and buys CPUNK with rate=10000:
 *     1 CELL = 10000 CPUNK (seller wants 10000 CPUNK per CELL sold)
 *
 * As a TAKER buying CELL (paying CPUNK):
 *   We look for orders where sell_token=CELL, buy_token=CPUNK
 *   We pay rate * remain_coins of CPUNK to get remain_coins of CELL
 *
 * As a TAKER buying CPUNK (paying CELL):
 *   We look for orders where sell_token=CPUNK, buy_token=CELL
 *   We pay rate * remain_coins of CELL to get remain_coins of CPUNK
 *
 * @author DNA Messenger Team
 * @date 2026-03-09
 */

#include "cellframe_dex.h"
#include "cellframe_rpc.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "CELL_DEX"

/* All Cellframe tokens use 18 decimals (datoshi) */
#define CELL_DECIMALS 18

/* ============================================================================
 * TOKEN REGISTRY
 * ============================================================================ */

typedef struct {
    const char *symbol;
    uint8_t decimals;
} cell_token_t;

static const cell_token_t known_tokens[] = {
    { "CELL",  18 },
    { "CPUNK", 18 },
    { "KEL",   18 },
    { "QEVM",  18 },
    { "mCELL", 18 },
    { "mKEL",  18 },
};

#define NUM_KNOWN_TOKENS (sizeof(known_tokens) / sizeof(known_tokens[0]))

/* Known trading pairs for cell_dex_list_pairs */
static const char *known_pairs[][2] = {
    { "CELL",  "CPUNK" },
    { "CELL",  "KEL"   },
    { "CELL",  "QEVM"  },
    { "CPUNK", "CELL"  },
    { "KEL",   "CELL"  },
    { "QEVM",  "CELL"  },
};

#define NUM_KNOWN_PAIRS (sizeof(known_pairs) / sizeof(known_pairs[0]))

static const cell_token_t *find_token(const char *symbol) {
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
 * ORDER BOOK STRUCTURES
 * ============================================================================ */

typedef struct {
    double rate;            /* rate from order */
    double remain;          /* remaining coins (sell_token amount) */
    double effective_price; /* for taker: cost per unit of desired token */
} ob_entry_t;

/* Comparator: sort by effective_price ascending (best price for taker first) */
static int ob_cmp_asc(const void *a, const void *b) {
    double da = ((const ob_entry_t *)a)->effective_price;
    double db = ((const ob_entry_t *)b)->effective_price;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

/* ============================================================================
 * FETCH ORDERS FROM RPC
 * ============================================================================ */

/**
 * Fetch all open orders from Cellframe public RPC.
 * Returns parsed JSON root object (caller must json_object_put).
 */
static json_object *fetch_orders(void) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "curl_easy_init failed");
        return NULL;
    }

    /* Build request JSON */
    json_object *jreq = json_object_new_object();
    json_object_object_add(jreq, "method", json_object_new_string("srv_xchange"));

    json_object *subcmd = json_object_new_array();
    json_object_array_add(subcmd, json_object_new_string("orders"));
    json_object_object_add(jreq, "subcommand", subcmd);

    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string("Backbone"));
    json_object_object_add(args, "status", json_object_new_string("opened"));
    json_object_object_add(jreq, "arguments", args);

    json_object_object_add(jreq, "id", json_object_new_string("1"));

    const char *json_str = json_object_to_json_string(jreq);

    curl_buf_t buf = { .data = NULL, .size = 0 };
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, CELLFRAME_RPC_ENDPOINT);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DNA-Messenger/1.0");

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jreq);

    if (res != CURLE_OK || !buf.data) {
        QGP_LOG_ERROR(LOG_TAG, "RPC request failed: %s", curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    if (http_code != 200) {
        QGP_LOG_ERROR(LOG_TAG, "RPC HTTP %ld", http_code);
        free(buf.data);
        return NULL;
    }

    json_object *root = json_tokener_parse(buf.data);
    free(buf.data);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "JSON parse failed");
        return NULL;
    }

    return root;
}

/* ============================================================================
 * QUOTE SIMULATION
 * ============================================================================ */

/**
 * Simulate a taker quote by walking the order book.
 *
 * The user wants to SELL from_token and BUY to_token.
 * We look for orders where sell_token == to_token (someone is selling what we want).
 *
 * For each matching order:
 *   - The order sells `remain` of to_token
 *   - The order wants `rate` of from_token per 1 to_token sold
 *   - So to buy X of to_token, taker pays X * rate of from_token
 *
 * We walk orders sorted by lowest rate (cheapest for taker) first,
 * filling until we've spent all of amount_in.
 */
int cell_dex_get_quotes(
    const char *from_token,
    const char *to_token,
    const char *amount_in,
    const char *dex_filter,
    cell_dex_quote_t *quotes_out,
    int max_quotes,
    int *count_out
) {
    (void)dex_filter;  /* unused for Cellframe */

    if (!from_token || !to_token || !amount_in || !quotes_out || !count_out) return -1;
    *count_out = 0;

    const cell_token_t *from_tok = find_token(from_token);
    const cell_token_t *to_tok = find_token(to_token);
    if (!from_tok || !to_tok) {
        QGP_LOG_WARN(LOG_TAG, "Unknown token: %s or %s", from_token, to_token);
        return -2;
    }

    if (max_quotes < 1) return -1;

    double user_amount = atof(amount_in);
    if (user_amount <= 0.0) {
        QGP_LOG_WARN(LOG_TAG, "Invalid amount: %s", amount_in);
        return -1;
    }

    /* Fetch all orders */
    json_object *root = fetch_orders();
    if (!root) return -1;

    /* Navigate to orders array: result[0].orders */
    json_object *result_arr;
    if (!json_object_object_get_ex(root, "result", &result_arr) ||
        !json_object_is_type(result_arr, json_type_array) ||
        json_object_array_length(result_arr) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No result in RPC response");
        json_object_put(root);
        return -1;
    }

    json_object *first = json_object_array_get_idx(result_arr, 0);
    json_object *orders_arr;
    if (!json_object_object_get_ex(first, "orders", &orders_arr) ||
        !json_object_is_type(orders_arr, json_type_array)) {
        QGP_LOG_ERROR(LOG_TAG, "No orders array in response");
        json_object_put(root);
        return -1;
    }

    int n_orders = (int)json_object_array_length(orders_arr);

    /* Build order book: filter matching orders */
    ob_entry_t *ob = calloc((size_t)n_orders, sizeof(ob_entry_t));
    if (!ob) {
        json_object_put(root);
        return -1;
    }

    int ob_count = 0;
    bool has_live_orders = false;

    for (int i = 0; i < n_orders; i++) {
        json_object *order = json_object_array_get_idx(orders_arr, i);

        json_object *j_sell, *j_buy, *j_rate, *j_remain, *j_avail;
        if (!json_object_object_get_ex(order, "sell_token", &j_sell) ||
            !json_object_object_get_ex(order, "buy_token", &j_buy) ||
            !json_object_object_get_ex(order, "rate", &j_rate) ||
            !json_object_object_get_ex(order, "remain_coins", &j_remain)) {
            continue;
        }

        /* Skip cancel_only orders */
        const char *avail = NULL;
        if (json_object_object_get_ex(order, "availability", &j_avail)) {
            avail = json_object_get_string(j_avail);
            if (avail && strcmp(avail, "cancel_only") == 0) {
                continue;
            }
        }

        const char *sell_tok = json_object_get_string(j_sell);
        const char *buy_tok = json_object_get_string(j_buy);

        /*
         * We want to BUY to_token by SELLING from_token.
         * Matching orders: sell_token == to_token AND buy_token == from_token
         *
         * Order rate = how many buy_token (our from_token) per 1 sell_token (our to_token)
         * So to get X of to_token, we pay X * rate of from_token
         * effective_price for taker = rate (lower is better)
         */
        if (strcasecmp(sell_tok, to_token) == 0 &&
            strcasecmp(buy_tok, from_token) == 0) {
            double rate = atof(json_object_get_string(j_rate));
            double remain = atof(json_object_get_string(j_remain));

            if (rate <= 0.0 || remain < 0.001) continue;  /* skip dust orders */

            /* Track if any order is truly live (not migrate) */
            if (!avail || strcmp(avail, "migrate") != 0) {
                has_live_orders = true;
            }

            ob[ob_count].rate = rate;
            ob[ob_count].remain = remain;
            ob[ob_count].effective_price = rate; /* cost in from_token per to_token */
            ob_count++;
        }
    }

    json_object_put(root);

    if (ob_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No matching orders for %s -> %s", from_token, to_token);
        free(ob);
        return -2;
    }

    /* Sort by effective price ascending (cheapest first) */
    qsort(ob, (size_t)ob_count, sizeof(ob_entry_t), ob_cmp_asc);

    /* Walk order book: spend user_amount of from_token, accumulate to_token */
    double remaining_in = user_amount;
    double total_out = 0.0;
    int orders_used = 0;

    for (int i = 0; i < ob_count && remaining_in > 1e-18; i++) {
        double rate = ob[i].rate;
        double avail_to = ob[i].remain;        /* how much to_token this order has */
        double cost_for_all = avail_to * rate;  /* cost to buy all of it */

        if (cost_for_all <= remaining_in) {
            /* Fill entire order */
            total_out += avail_to;
            remaining_in -= cost_for_all;
        } else {
            /* Partial fill — buy what we can afford */
            double can_buy = remaining_in / rate;
            total_out += can_buy;
            remaining_in = 0.0;
        }
        orders_used++;
    }

    double actually_spent = user_amount - remaining_in;

    if (total_out <= 0.0) {
        QGP_LOG_WARN(LOG_TAG, "No liquidity for %s -> %s", from_token, to_token);
        free(ob);
        return -2;
    }

    /* Calculate effective price and slippage */
    double eff_price = total_out / actually_spent;  /* 1 from = X to */
    double best_price = 1.0 / ob[0].rate;           /* best single-order rate */
    double slippage = 0.0;
    if (best_price > 0.0) {
        slippage = fabs((eff_price - best_price) / best_price) * 100.0;
    }

    /* Fill quote result */
    cell_dex_quote_t *q = &quotes_out[0];
    memset(q, 0, sizeof(*q));
    strncpy(q->from_token, from_token, sizeof(q->from_token) - 1);
    strncpy(q->to_token, to_token, sizeof(q->to_token) - 1);
    strncpy(q->dex_name, "Cellframe DEX", sizeof(q->dex_name) - 1);
    strncpy(q->pool_address, "orderbook", sizeof(q->pool_address) - 1);
    q->from_decimals = from_tok->decimals;
    q->to_decimals = to_tok->decimals;
    q->orders_used = orders_used;
    q->stale_warning = !has_live_orders;

    snprintf(q->amount_in, sizeof(q->amount_in), "%.6f", actually_spent);
    snprintf(q->amount_out, sizeof(q->amount_out), "%.6f", total_out);
    snprintf(q->price, sizeof(q->price), "%.6f", eff_price);
    snprintf(q->price_impact, sizeof(q->price_impact), "%.2f", slippage);
    strncpy(q->fee, "included", sizeof(q->fee) - 1);

    /* Warn if not fully filled */
    if (remaining_in > 1e-18) {
        QGP_LOG_WARN(LOG_TAG, "Partial fill: wanted %s, filled %.6f %s (%.1f%%)",
                     amount_in, actually_spent, from_token,
                     (actually_spent / user_amount) * 100.0);
    }

    QGP_LOG_INFO(LOG_TAG, "Quote: %.6f %s -> %.6f %s (eff. price: %.6f, %d orders, impact: %s%%)",
                 actually_spent, from_token, total_out, to_token,
                 eff_price, orders_used, q->price_impact);

    free(ob);
    *count_out = 1;
    return 0;
}

/* ============================================================================
 * LIST PAIRS
 * ============================================================================ */

int cell_dex_list_pairs(char ***pairs_out, int *count_out) {
    if (!pairs_out || !count_out) return -1;

    int total = (int)NUM_KNOWN_PAIRS;
    char **pairs = calloc((size_t)total, sizeof(char *));
    if (!pairs) return -1;

    for (int i = 0; i < total; i++) {
        pairs[i] = malloc(32);
        if (pairs[i]) {
            snprintf(pairs[i], 32, "%s/%s", known_pairs[i][0], known_pairs[i][1]);
        }
    }

    *pairs_out = pairs;
    *count_out = total;
    return 0;
}

void cell_dex_free_pairs(char **pairs, int count) {
    if (!pairs) return;
    for (int i = 0; i < count; i++) {
        free(pairs[i]);
    }
    free(pairs);
}
