/*
 * cellframe_rpc.c - Cellframe Public RPC Client
 */

#include "cellframe_rpc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Response buffer for curl
struct response_buffer {
    char *data;
    size_t size;
};

// Curl write callback
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

/**
 * Make RPC call to Cellframe public RPC
 */
int cellframe_rpc_call(const cellframe_rpc_request_t *request, cellframe_rpc_response_t **response_out) {
    if (!request || !response_out) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    // Build JSON request
    json_object *jreq = json_object_new_object();
    json_object_object_add(jreq, "method", json_object_new_string(request->method));

    if (request->subcommand) {
        json_object_object_add(jreq, "subcommand", json_object_new_string(request->subcommand));
    } else {
        json_object_object_add(jreq, "subcommand", json_object_new_string(""));
    }

    if (request->arguments) {
        json_object_object_add(jreq, "arguments", json_object_get(request->arguments));
    } else {
        json_object_object_add(jreq, "arguments", json_object_new_object());
    }

    json_object_object_add(jreq, "id", json_object_new_int(request->id));

    const char *json_str = json_object_to_json_string(jreq);

    // Setup response buffer
    struct response_buffer resp_buf = {0};

    // Setup curl
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, CELLFRAME_RPC_ENDPOINT);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);

    // Perform request
    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jreq);

    if (res != CURLE_OK) {
        if (resp_buf.data) {
            free(resp_buf.data);
        }
        return -1;
    }

    // Parse response
    json_object *jresp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!jresp) {
        return -1;
    }

    // Extract response fields
    cellframe_rpc_response_t *response = calloc(1, sizeof(cellframe_rpc_response_t));
    if (!response) {
        json_object_put(jresp);
        return -1;
    }

    json_object *jtype = NULL;
    json_object *jresult = NULL;
    json_object *jid = NULL;
    json_object *jversion = NULL;

    if (json_object_object_get_ex(jresp, "type", &jtype)) {
        response->type = json_object_get_int(jtype);
    }

    if (json_object_object_get_ex(jresp, "result", &jresult)) {
        response->result = json_object_get(jresult);
    }

    if (json_object_object_get_ex(jresp, "id", &jid)) {
        response->id = json_object_get_int(jid);
    }

    if (json_object_object_get_ex(jresp, "version", &jversion)) {
        response->version = json_object_get_int(jversion);
    }

    json_object_put(jresp);

    *response_out = response;
    return 0;
}

/**
 * Get transaction details
 */
int cellframe_rpc_get_tx(const char *net, const char *tx_hash, cellframe_rpc_response_t **response_out) {
    if (!net || !tx_hash || !response_out) {
        return -1;
    }

    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string(net));
    json_object_object_add(args, "tx", json_object_new_string(tx_hash));

    cellframe_rpc_request_t req = {
        .method = "tx_history",
        .subcommand = "",
        .arguments = args,
        .id = 1
    };

    int ret = cellframe_rpc_call(&req, response_out);
    json_object_put(args);

    return ret;
}

/**
 * Get block details
 */
int cellframe_rpc_get_block(const char *net, uint64_t block_num, cellframe_rpc_response_t **response_out) {
    if (!net || !response_out) {
        return -1;
    }

    char block_str[32];
    snprintf(block_str, sizeof(block_str), "%llu", (unsigned long long)block_num);

    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string(net));
    json_object_object_add(args, "num", json_object_new_string(block_str));

    cellframe_rpc_request_t req = {
        .method = "block",
        .subcommand = "dump",
        .arguments = args,
        .id = 1
    };

    int ret = cellframe_rpc_call(&req, response_out);
    json_object_put(args);

    return ret;
}

/**
 * Get wallet balance
 */
int cellframe_rpc_get_balance(const char *net, const char *address, const char *token, cellframe_rpc_response_t **response_out) {
    if (!net || !address || !token || !response_out) {
        return -1;
    }

    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string(net));
    json_object_object_add(args, "addr", json_object_new_string(address));
    json_object_object_add(args, "token", json_object_new_string(token));

    cellframe_rpc_request_t req = {
        .method = "wallet",
        .subcommand = "info",
        .arguments = args,
        .id = 1
    };

    int ret = cellframe_rpc_call(&req, response_out);
    json_object_put(args);

    return ret;
}

/**
 * Get UTXOs for address
 * Uses Cellframe RPC "wallet" method with "outputs" subcommand
 */
int cellframe_rpc_get_utxo(const char *net, const char *address, const char *token, cellframe_rpc_response_t **response_out) {
    if (!net || !address || !token || !response_out) {
        return -1;
    }

    // Build params string: "wallet;outputs;-addr;...;-token;...;-net;..."
    char params_str[1024];
    snprintf(params_str, sizeof(params_str),
             "wallet;outputs;-addr;%s;-token;%s;-net;%s",
             address, token, net);

    // Create params array with single string
    json_object *params_array = json_object_new_array();
    json_object_array_add(params_array, json_object_new_string(params_str));

    // Create request with params instead of arguments
    CURL *curl = curl_easy_init();
    if (!curl) {
        json_object_put(params_array);
        return -1;
    }

    // Build JSON request manually (different format from cellframe_rpc_call)
    json_object *jreq = json_object_new_object();
    json_object_object_add(jreq, "method", json_object_new_string("wallet"));
    json_object_object_add(jreq, "params", params_array);
    json_object_object_add(jreq, "id", json_object_new_string("1"));
    json_object_object_add(jreq, "version", json_object_new_string("2"));

    const char *json_str = json_object_to_json_string(jreq);

    // Setup response buffer
    struct response_buffer resp_buf = {0};

    // Setup curl
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, CELLFRAME_RPC_ENDPOINT);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);

    // Perform request
    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jreq);

    if (res != CURLE_OK) {
        if (resp_buf.data) {
            free(resp_buf.data);
        }
        return -1;
    }

    // Parse response
    json_object *jresp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);

    if (!jresp) {
        return -1;
    }

    // Extract response fields
    cellframe_rpc_response_t *response = calloc(1, sizeof(cellframe_rpc_response_t));
    if (!response) {
        json_object_put(jresp);
        return -1;
    }

    json_object *jtype = NULL;
    json_object *jresult = NULL;
    json_object *jid = NULL;
    json_object *jversion = NULL;

    if (json_object_object_get_ex(jresp, "type", &jtype)) {
        response->type = json_object_get_int(jtype);
    }

    if (json_object_object_get_ex(jresp, "result", &jresult)) {
        response->result = json_object_get(jresult);
    }

    if (json_object_object_get_ex(jresp, "id", &jid)) {
        response->id = json_object_get_int(jid);
    }

    if (json_object_object_get_ex(jresp, "version", &jversion)) {
        response->version = json_object_get_int(jversion);
    }

    json_object_put(jresp);

    *response_out = response;
    return 0;
}

/**
 * Submit signed transaction
 */
int cellframe_rpc_submit_tx(const char *net, const char *chain, const char *tx_json, cellframe_rpc_response_t **response_out) {
    if (!net || !chain || !tx_json || !response_out) {
        return -1;
    }

    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string(net));
    json_object_object_add(args, "chain", json_object_new_string(chain));
    json_object_object_add(args, "tx_obj", json_object_new_string(tx_json));

    cellframe_rpc_request_t req = {
        .method = "tx_create_json",
        .subcommand = "",
        .arguments = args,
        .id = 1
    };

    int ret = cellframe_rpc_call(&req, response_out);
    json_object_put(args);

    return ret;
}

/**
 * Free RPC response
 */
void cellframe_rpc_response_free(cellframe_rpc_response_t *response) {
    if (!response) {
        return;
    }

    if (response->result) {
        json_object_put(response->result);
    }

    if (response->error) {
        free(response->error);
    }

    free(response);
}

/**
 * Verify DNA name registration transaction
 */
int cellframe_verify_registration_tx(const char *tx_hash, const char *network, const char *expected_name) {
    if (!tx_hash || !network || !expected_name) {
        fprintf(stderr, "[TX_VERIFY] NULL parameters\n");
        return -1;
    }

    printf("[TX_VERIFY] Verifying transaction: %s\n", tx_hash);
    printf("[TX_VERIFY] Network: %s, Expected name: %s\n", network, expected_name);

    // 1. Query transaction from blockchain
    cellframe_rpc_response_t *response = NULL;
    int ret = cellframe_rpc_get_tx(network, tx_hash, &response);
    if (ret != 0 || !response) {
        fprintf(stderr, "[TX_VERIFY] Failed to query transaction\n");
        return -1;
    }

    if (!response->result) {
        fprintf(stderr, "[TX_VERIFY] No result in response\n");
        cellframe_rpc_response_free(response);
        return -1;
    }

    // 2. Parse transaction JSON from result
    // Result is an array, get first element
    json_object *tx_obj = NULL;
    if (json_object_is_type(response->result, json_type_array)) {
        if (json_object_array_length(response->result) == 0) {
            fprintf(stderr, "[TX_VERIFY] Transaction not found\n");
            cellframe_rpc_response_free(response);
            return -2;
        }
        tx_obj = json_object_array_get_idx(response->result, 0);
    } else {
        tx_obj = response->result;
    }

    if (!tx_obj) {
        fprintf(stderr, "[TX_VERIFY] No transaction object in response\n");
        cellframe_rpc_response_free(response);
        return -1;
    }

    // 3. Extract transaction fields
    json_object *j_status = NULL;
    json_object *j_value = NULL;
    json_object *j_to_addr = NULL;
    json_object *j_token = NULL;
    json_object *j_memo = NULL;

    json_object_object_get_ex(tx_obj, "status", &j_status);
    json_object_object_get_ex(tx_obj, "value", &j_value);
    json_object_object_get_ex(tx_obj, "recv_addr", &j_to_addr);
    json_object_object_get_ex(tx_obj, "token", &j_token);
    json_object_object_get_ex(tx_obj, "memo", &j_memo);

    // 4. Verify status = "ACCEPTED"
    if (!j_status) {
        fprintf(stderr, "[TX_VERIFY] No status field\n");
        cellframe_rpc_response_free(response);
        return -2;
    }

    const char *status = json_object_get_string(j_status);
    if (strcmp(status, "ACCEPTED") != 0) {
        fprintf(stderr, "[TX_VERIFY] Transaction not accepted (status: %s)\n", status);
        cellframe_rpc_response_free(response);
        return -2;
    }

    // 5. Verify amount = "0.01" (stored as string)
    if (!j_value) {
        fprintf(stderr, "[TX_VERIFY] No value field\n");
        cellframe_rpc_response_free(response);
        return -2;
    }

    const char *value_str = json_object_get_string(j_value);
    double value = atof(value_str);
    if (value < 0.009 || value > 0.011) {  // Allow small floating point error
        fprintf(stderr, "[TX_VERIFY] Invalid amount: %s (expected 0.01)\n", value_str);
        cellframe_rpc_response_free(response);
        return -2;
    }

    // 6. Verify recipient address
    if (!j_to_addr) {
        fprintf(stderr, "[TX_VERIFY] No recv_addr field\n");
        cellframe_rpc_response_free(response);
        return -2;
    }

    const char *to_addr = json_object_get_string(j_to_addr);
    if (strcmp(to_addr, DNA_REGISTRATION_ADDRESS) != 0) {
        fprintf(stderr, "[TX_VERIFY] Invalid recipient: %s\n", to_addr);
        fprintf(stderr, "[TX_VERIFY] Expected: %s\n", DNA_REGISTRATION_ADDRESS);
        cellframe_rpc_response_free(response);
        return -2;
    }

    // 7. Verify token = "CPUNK"
    if (!j_token) {
        fprintf(stderr, "[TX_VERIFY] No token field\n");
        cellframe_rpc_response_free(response);
        return -2;
    }

    const char *token = json_object_get_string(j_token);
    if (strcmp(token, "CPUNK") != 0) {
        fprintf(stderr, "[TX_VERIFY] Invalid token: %s (expected CPUNK)\n", token);
        cellframe_rpc_response_free(response);
        return -2;
    }

    // 8. Verify memo = expected_name
    if (!j_memo) {
        fprintf(stderr, "[TX_VERIFY] No memo field\n");
        cellframe_rpc_response_free(response);
        return -2;
    }

    const char *memo = json_object_get_string(j_memo);
    if (strcmp(memo, expected_name) != 0) {
        fprintf(stderr, "[TX_VERIFY] Invalid memo: %s (expected: %s)\n", memo, expected_name);
        cellframe_rpc_response_free(response);
        return -2;
    }

    printf("[TX_VERIFY] ✓ Transaction verified successfully\n");
    printf("[TX_VERIFY]   Amount: %s CPUNK\n", value_str);
    printf("[TX_VERIFY]   To: %s\n", to_addr);
    printf("[TX_VERIFY]   Memo: %s\n", memo);
    printf("[TX_VERIFY]   Status: %s\n", status);

    cellframe_rpc_response_free(response);
    return 0;  // Valid ✅
}
