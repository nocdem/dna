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
