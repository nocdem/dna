/*
 * cellframe_rpc.h - Cellframe Public RPC Client
 *
 * Client for Cellframe public RPC API: http://rpc.cellframe.net/connect
 */

#ifndef CELLFRAME_RPC_H
#define CELLFRAME_RPC_H

#include <stdint.h>
#include <stddef.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CELLFRAME_RPC_ENDPOINT "http://rpc.cellframe.net/connect"

/**
 * RPC request structure
 */
typedef struct {
    const char *method;
    const char *subcommand;  // Can be NULL
    json_object *arguments;  // JSON object with arguments
    int id;
} cellframe_rpc_request_t;

/**
 * RPC response structure
 */
typedef struct {
    int type;
    json_object *result;  // Array or object with results
    int id;
    int version;
    char *error;  // Error message if request failed
} cellframe_rpc_response_t;

/**
 * Make RPC call to Cellframe public RPC
 *
 * @param request - RPC request structure
 * @param response_out - Response structure (caller must free with cellframe_rpc_response_free)
 * @return 0 on success, -1 on error
 */
int cellframe_rpc_call(const cellframe_rpc_request_t *request, cellframe_rpc_response_t **response_out);

/**
 * Get transaction details
 *
 * @param net - Network name (e.g., "Backbone")
 * @param tx_hash - Transaction hash (e.g., "0x1DB0DAD...")
 * @param response_out - Response structure
 * @return 0 on success, -1 on error
 */
int cellframe_rpc_get_tx(const char *net, const char *tx_hash, cellframe_rpc_response_t **response_out);

/**
 * Get block details
 *
 * @param net - Network name (e.g., "Backbone")
 * @param block_num - Block number
 * @param response_out - Response structure
 * @return 0 on success, -1 on error
 */
int cellframe_rpc_get_block(const char *net, uint64_t block_num, cellframe_rpc_response_t **response_out);

/**
 * Get wallet balance
 *
 * @param net - Network name (e.g., "Backbone")
 * @param address - Wallet address
 * @param token - Token name (e.g., "CPUNK")
 * @param response_out - Response structure
 * @return 0 on success, -1 on error
 */
int cellframe_rpc_get_balance(const char *net, const char *address, const char *token, cellframe_rpc_response_t **response_out);

/**
 * Free RPC response
 */
void cellframe_rpc_response_free(cellframe_rpc_response_t *response);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_RPC_H */
