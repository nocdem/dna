/**
 * @file sol_rpc.c
 * @brief Solana JSON-RPC Client Implementation
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#include "sol_rpc.h"
#include "sol_wallet.h"
#include "../../crypto/utils/base58.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <json-c/json.h>

#define LOG_TAG "SOL_RPC"

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

/**
 * Make JSON-RPC call to Solana
 */
static int sol_rpc_call(
    const char *method,
    json_object *params,
    json_object **result_out
) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize CURL");
        return -1;
    }

    /* Build request */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "id", json_object_new_int(1));
    json_object_object_add(req, "method", json_object_new_string(method));

    if (params) {
        json_object_object_add(req, "params", params);
    } else {
        json_object_object_add(req, "params", json_object_new_array());
    }

    const char *json_str = json_object_to_json_string(req);

    QGP_LOG_DEBUG(LOG_TAG, "RPC request: %s", json_str);

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, sol_rpc_get_endpoint());
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

    QGP_LOG_DEBUG(LOG_TAG, "RPC response: %s", resp_buf.data);

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

    /* Return result (caller must handle reference counting) */
    *result_out = json_object_get(result);
    json_object_put(resp);

    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int sol_rpc_get_balance(
    const char *address,
    uint64_t *lamports_out
) {
    if (!address || !lamports_out) {
        return -1;
    }

    /* Build params: [address, {commitment: "confirmed"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getBalance", params, &result) != 0) {
        return -1;
    }

    /* Parse result: {"context": {...}, "value": <lamports>} */
    json_object *value_obj;
    if (!json_object_object_get_ex(result, "value", &value_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "No value in balance response");
        json_object_put(result);
        return -1;
    }

    *lamports_out = json_object_get_uint64(value_obj);
    json_object_put(result);

    return 0;
}

int sol_rpc_get_recent_blockhash(uint8_t blockhash_out[32]) {
    if (!blockhash_out) {
        return -1;
    }

    /* Build params with commitment */
    json_object *params = json_object_new_array();
    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getLatestBlockhash", params, &result) != 0) {
        return -1;
    }

    /* Parse result: {"context": {...}, "value": {"blockhash": "...", ...}} */
    json_object *value_obj, *blockhash_obj;
    if (!json_object_object_get_ex(result, "value", &value_obj) ||
        !json_object_object_get_ex(value_obj, "blockhash", &blockhash_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "No blockhash in response");
        json_object_put(result);
        return -1;
    }

    const char *blockhash_b58 = json_object_get_string(blockhash_obj);

    /* Decode base58 blockhash */
    size_t decoded_len = base58_decode(blockhash_b58, blockhash_out);
    json_object_put(result);

    if (decoded_len != 32) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid blockhash length: %zu", decoded_len);
        return -1;
    }

    return 0;
}

int sol_rpc_get_minimum_balance_for_rent(
    size_t data_len,
    uint64_t *lamports_out
) {
    if (!lamports_out) {
        return -1;
    }

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_uint64(data_len));

    json_object *result = NULL;
    if (sol_rpc_call("getMinimumBalanceForRentExemption", params, &result) != 0) {
        return -1;
    }

    *lamports_out = json_object_get_uint64(result);
    json_object_put(result);

    return 0;
}

int sol_rpc_send_transaction(
    const char *tx_base64,
    char *signature_out,
    size_t sig_out_size
) {
    if (!tx_base64 || !signature_out || sig_out_size == 0) {
        return -1;
    }

    /* Build params: [tx_base64, {encoding: "base64"}] */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(tx_base64));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("base64"));
    json_object_object_add(opts, "preflightCommitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("sendTransaction", params, &result) != 0) {
        return -1;
    }

    /* Result is the transaction signature */
    const char *sig = json_object_get_string(result);
    strncpy(signature_out, sig, sig_out_size - 1);
    signature_out[sig_out_size - 1] = '\0';

    json_object_put(result);
    return 0;
}

int sol_rpc_get_transaction_status(
    const char *signature,
    bool *success_out
) {
    if (!signature || !success_out) {
        return -1;
    }

    /* Build params */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(signature));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getSignatureStatuses", params, &result) != 0) {
        return -1;
    }

    /* Parse result: {"context": {...}, "value": [status or null]} */
    json_object *value_obj;
    if (!json_object_object_get_ex(result, "value", &value_obj)) {
        json_object_put(result);
        return -1;
    }

    json_object *status = json_object_array_get_idx(value_obj, 0);
    if (!status || json_object_is_type(status, json_type_null)) {
        /* Transaction not found - still pending */
        json_object_put(result);
        return 1;
    }

    /* Check if transaction succeeded */
    json_object *err_obj;
    if (json_object_object_get_ex(status, "err", &err_obj)) {
        *success_out = json_object_is_type(err_obj, json_type_null);
    } else {
        *success_out = true;
    }

    json_object_put(result);
    return 0;
}

/**
 * Helper to extract pubkey string from account key object
 */
static const char* get_account_key_str(json_object *key_obj) {
    if (!key_obj) return NULL;

    /* Handle string format (legacy transactions) */
    if (json_object_is_type(key_obj, json_type_string)) {
        return json_object_get_string(key_obj);
    }

    /* Handle object format with pubkey field (versioned transactions) */
    if (json_object_is_type(key_obj, json_type_object)) {
        json_object *pubkey_obj;
        if (json_object_object_get_ex(key_obj, "pubkey", &pubkey_obj)) {
            return json_object_get_string(pubkey_obj);
        }
    }

    return NULL;
}

/**
 * Helper to get transaction details for a single signature
 */
static int sol_rpc_get_tx_details(
    const char *signature,
    const char *our_address,
    sol_transaction_t *tx_out
) {
    /* Build params for getTransaction */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(signature));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("json"));
    json_object_object_add(opts, "maxSupportedTransactionVersion", json_object_new_int(0));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getTransaction", params, &result) != 0) {
        return -1;
    }

    if (!result || json_object_is_type(result, json_type_null)) {
        if (result) json_object_put(result);
        return -1;
    }

    /* Get block time */
    json_object *block_time_obj;
    if (json_object_object_get_ex(result, "blockTime", &block_time_obj) &&
        !json_object_is_type(block_time_obj, json_type_null)) {
        tx_out->block_time = json_object_get_int64(block_time_obj);
    }

    /* Get slot */
    json_object *slot_obj;
    if (json_object_object_get_ex(result, "slot", &slot_obj)) {
        tx_out->slot = json_object_get_uint64(slot_obj);
    }

    /* Parse meta for balance changes */
    json_object *meta_obj;
    if (json_object_object_get_ex(result, "meta", &meta_obj)) {
        /* Check transaction error */
        json_object *err_obj;
        if (json_object_object_get_ex(meta_obj, "err", &err_obj)) {
            tx_out->success = json_object_is_type(err_obj, json_type_null);
        }

        /* Get pre and post balances */
        json_object *pre_balances, *post_balances;
        json_object *transaction_obj, *message_obj;

        if (json_object_object_get_ex(meta_obj, "preBalances", &pre_balances) &&
            json_object_object_get_ex(meta_obj, "postBalances", &post_balances) &&
            json_object_object_get_ex(result, "transaction", &transaction_obj) &&
            json_object_object_get_ex(transaction_obj, "message", &message_obj)) {

            /* Try both accountKeys (legacy) and staticAccountKeys (versioned) */
            json_object *account_keys_obj = NULL;
            if (!json_object_object_get_ex(message_obj, "accountKeys", &account_keys_obj)) {
                json_object_object_get_ex(message_obj, "staticAccountKeys", &account_keys_obj);
            }

            if (account_keys_obj) {
                int num_accounts = json_object_array_length(account_keys_obj);
                int num_balances = json_object_array_length(pre_balances);
                int our_index = -1;

                /* Find our address in account keys */
                for (int i = 0; i < num_accounts; i++) {
                    const char *key_str = get_account_key_str(
                        json_object_array_get_idx(account_keys_obj, i));
                    if (key_str && strcmp(key_str, our_address) == 0) {
                        our_index = i;
                        break;
                    }
                }

                /* If we found our address and have balance data */
                if (our_index >= 0 && our_index < num_balances) {
                    int64_t pre = json_object_get_int64(
                        json_object_array_get_idx(pre_balances, our_index));
                    int64_t post = json_object_get_int64(
                        json_object_array_get_idx(post_balances, our_index));
                    int64_t diff = post - pre;

                    if (diff < 0) {
                        /* We sent (balance decreased) */
                        tx_out->lamports = (uint64_t)(-diff);
                        tx_out->is_outgoing = true;
                        strncpy(tx_out->from, our_address, sizeof(tx_out->from) - 1);

                        /* Find recipient with largest positive balance change */
                        int64_t max_received = 0;
                        int recipient_idx = -1;
                        for (int i = 0; i < num_balances && i < num_accounts; i++) {
                            if (i == our_index) continue;
                            int64_t o_pre = json_object_get_int64(
                                json_object_array_get_idx(pre_balances, i));
                            int64_t o_post = json_object_get_int64(
                                json_object_array_get_idx(post_balances, i));
                            int64_t o_diff = o_post - o_pre;
                            if (o_diff > max_received) {
                                max_received = o_diff;
                                recipient_idx = i;
                            }
                        }
                        if (recipient_idx >= 0) {
                            const char *key_str = get_account_key_str(
                                json_object_array_get_idx(account_keys_obj, recipient_idx));
                            if (key_str) {
                                strncpy(tx_out->to, key_str, sizeof(tx_out->to) - 1);
                            }
                        }
                    } else if (diff > 0) {
                        /* We received (balance increased) */
                        tx_out->lamports = (uint64_t)diff;
                        tx_out->is_outgoing = false;
                        strncpy(tx_out->to, our_address, sizeof(tx_out->to) - 1);

                        /* Find sender with largest negative balance change */
                        int64_t max_sent = 0;
                        int sender_idx = -1;
                        for (int i = 0; i < num_balances && i < num_accounts; i++) {
                            if (i == our_index) continue;
                            int64_t o_pre = json_object_get_int64(
                                json_object_array_get_idx(pre_balances, i));
                            int64_t o_post = json_object_get_int64(
                                json_object_array_get_idx(post_balances, i));
                            int64_t o_diff = o_pre - o_post; /* Positive if sent */
                            if (o_diff > max_sent) {
                                max_sent = o_diff;
                                sender_idx = i;
                            }
                        }
                        if (sender_idx >= 0) {
                            const char *key_str = get_account_key_str(
                                json_object_array_get_idx(account_keys_obj, sender_idx));
                            if (key_str) {
                                strncpy(tx_out->from, key_str, sizeof(tx_out->from) - 1);
                            }
                        }
                    }
                } else {
                    /* Address not found - scan all balance changes */
                    /* Find the largest positive and negative balance changes */
                    int64_t max_increase = 0, max_decrease = 0;
                    int increase_idx = -1, decrease_idx = -1;

                    for (int i = 0; i < num_balances && i < num_accounts; i++) {
                        int64_t pre = json_object_get_int64(
                            json_object_array_get_idx(pre_balances, i));
                        int64_t post = json_object_get_int64(
                            json_object_array_get_idx(post_balances, i));
                        int64_t diff = post - pre;

                        if (diff > max_increase) {
                            max_increase = diff;
                            increase_idx = i;
                        }
                        if (-diff > max_decrease) {
                            max_decrease = -diff;
                            decrease_idx = i;
                        }
                    }

                    /* Check if we're the recipient (largest increase) */
                    if (increase_idx >= 0) {
                        const char *key_str = get_account_key_str(
                            json_object_array_get_idx(account_keys_obj, increase_idx));
                        if (key_str && strcmp(key_str, our_address) == 0) {
                            tx_out->lamports = (uint64_t)max_increase;
                            tx_out->is_outgoing = false;
                            strncpy(tx_out->to, our_address, sizeof(tx_out->to) - 1);
                            if (decrease_idx >= 0) {
                                const char *sender = get_account_key_str(
                                    json_object_array_get_idx(account_keys_obj, decrease_idx));
                                if (sender) {
                                    strncpy(tx_out->from, sender, sizeof(tx_out->from) - 1);
                                }
                            }
                        }
                    }

                    /* Check if we're the sender (largest decrease) */
                    if (decrease_idx >= 0 && tx_out->lamports == 0) {
                        const char *key_str = get_account_key_str(
                            json_object_array_get_idx(account_keys_obj, decrease_idx));
                        if (key_str && strcmp(key_str, our_address) == 0) {
                            tx_out->lamports = (uint64_t)max_decrease;
                            tx_out->is_outgoing = true;
                            strncpy(tx_out->from, our_address, sizeof(tx_out->from) - 1);
                            if (increase_idx >= 0) {
                                const char *recipient = get_account_key_str(
                                    json_object_array_get_idx(account_keys_obj, increase_idx));
                                if (recipient) {
                                    strncpy(tx_out->to, recipient, sizeof(tx_out->to) - 1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    json_object_put(result);
    return 0;
}

int sol_rpc_get_transactions(
    const char *address,
    sol_transaction_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Get signatures for address */
    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(address));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "limit", json_object_new_int(20));
    json_object_object_add(opts, "commitment", json_object_new_string("confirmed"));
    json_object_array_add(params, opts);

    json_object *result = NULL;
    if (sol_rpc_call("getSignaturesForAddress", params, &result) != 0) {
        return -1;
    }

    int arr_len = json_object_array_length(result);
    if (arr_len == 0) {
        json_object_put(result);
        return 0;
    }

    /* Allocate transaction array */
    sol_transaction_t *txs = calloc(arr_len, sizeof(sol_transaction_t));
    if (!txs) {
        json_object_put(result);
        return -1;
    }

    int valid_count = 0;
    for (int i = 0; i < arr_len; i++) {
        json_object *sig_info = json_object_array_get_idx(result, i);

        json_object *sig_obj, *err_obj;

        if (!json_object_object_get_ex(sig_info, "signature", &sig_obj)) {
            continue;
        }

        const char *signature = json_object_get_string(sig_obj);
        strncpy(txs[valid_count].signature, signature,
                sizeof(txs[valid_count].signature) - 1);

        /* Check error status from signature list */
        if (json_object_object_get_ex(sig_info, "err", &err_obj)) {
            txs[valid_count].success = json_object_is_type(err_obj, json_type_null);
        } else {
            txs[valid_count].success = true;
        }

        /* Fetch full transaction details */
        if (sol_rpc_get_tx_details(signature, address, &txs[valid_count]) != 0) {
            /* If we can't get details, use basic info from signature list */
            json_object *slot_obj, *time_obj;
            if (json_object_object_get_ex(sig_info, "slot", &slot_obj)) {
                txs[valid_count].slot = json_object_get_uint64(slot_obj);
            }
            if (json_object_object_get_ex(sig_info, "blockTime", &time_obj) &&
                !json_object_is_type(time_obj, json_type_null)) {
                txs[valid_count].block_time = json_object_get_int64(time_obj);
            }
            strncpy(txs[valid_count].from, address, sizeof(txs[valid_count].from) - 1);
        }

        valid_count++;
    }

    json_object_put(result);

    *txs_out = txs;
    *count_out = valid_count;

    return 0;
}

void sol_rpc_free_transactions(sol_transaction_t *txs, int count) {
    (void)count;
    if (txs) {
        free(txs);
    }
}

int sol_rpc_get_slot(uint64_t *slot_out) {
    if (!slot_out) {
        return -1;
    }

    json_object *result = NULL;
    if (sol_rpc_call("getSlot", NULL, &result) != 0) {
        return -1;
    }

    *slot_out = json_object_get_uint64(result);
    json_object_put(result);

    return 0;
}
