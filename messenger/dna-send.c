/*
 * dna-send.c - DNA Messenger CLI Tool for Sending Cellframe Tokens
 *
 * Usage: dna-send --wallet <file> --recipient <address> --amount <value> [OPTIONS]
 *
 * Builds, signs, and submits Cellframe transactions via Public RPC.
 */

#include "cellframe_minimal.h"
#include "cellframe_tx_builder_minimal.h"
#include "cellframe_sign_minimal.h"
#include "cellframe_json_minimal.h"
#include "cellframe_rpc.h"
#include "wallet.h"
#include "base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <json-c/json.h>

#define DEFAULT_RPC_URL "http://rpc.cellframe.net/connect"
#define DEFAULT_NETWORK "Backbone"
#define DEFAULT_CHAIN "main"
#define DEFAULT_TOKEN "CELL"

// Network fee constants
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"
#define NETWORK_FEE_DATOSHI 2000000000000000ULL  // 0.002 CELL

// ============================================================================
// UTXO STRUCTURE
// ============================================================================

typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} utxo_t;

// ============================================================================
// COMMAND-LINE ARGUMENTS
// ============================================================================

typedef struct {
    const char *wallet_file;
    const char *recipient;
    const char *amount;
    const char *fee;
    const char *network;
    const char *chain;
    const char *token;
    const char *rpc_url;
    const char *tsd_data;     // Optional TSD data
    uint64_t timestamp;  // Override timestamp (0 = use current time)
    int verbose;
} dna_send_args_t;

static struct option long_options[] = {
    {"wallet",    required_argument, 0, 'w'},
    {"recipient", required_argument, 0, 'r'},
    {"amount",    required_argument, 0, 'a'},
    {"fee",       required_argument, 0, 'f'},
    {"network",   required_argument, 0, 'n'},
    {"chain",     required_argument, 0, 'c'},
    {"token",     required_argument, 0, 't'},
    {"rpc",       required_argument, 0, 'u'},
    {"timestamp", required_argument, 0, 'T'},
    {"tsd",       required_argument, 0, 'd'},
    {"verbose",   no_argument,       0, 'v'},
    {"help",      no_argument,       0, 'h'},
    {0, 0, 0, 0}
};

static void print_usage(const char *prog_name) {
    printf("DNA Messenger - Cellframe Token Sender\n\n");
    printf("Usage: %s --wallet <file> --recipient <address> --amount <value> [OPTIONS]\n\n", prog_name);
    printf("Required Arguments:\n");
    printf("  -w, --wallet <file>       Wallet file (.dwallet)\n");
    printf("  -r, --recipient <address> Recipient address (Base58)\n");
    printf("  -a, --amount <value>      Amount to send (e.g., 0.01, 1000000000000000000)\n");
    printf("  -f, --fee <value>         Validator fee (e.g., 0.01)\n\n");
    printf("Optional Arguments:\n");
    printf("  -n, --network <name>      Network name (default: Backbone)\n");
    printf("  -c, --chain <name>        Chain name (default: main)\n");
    printf("  -t, --token <ticker>      Token ticker (default: CELL)\n");
    printf("  -u, --rpc <url>           RPC endpoint (default: %s)\n", DEFAULT_RPC_URL);
    printf("  -d, --tsd <text>          Optional: Custom TSD data to include\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  -h, --help                Show this help\n\n");
    printf("Examples:\n");
    printf("  # Send 0.01 CELL to recipient\n");
    printf("  %s -w test.dwallet -r Rj7J7MiX2bWy... -a 0.01 -f 0.01\n\n", prog_name);
    printf("  # Send 1000000000000000000 datoshi (1 CELL)\n");
    printf("  %s -w test.dwallet -r Rj7J7MiX2b... -a 1000000000000000000 -f 0.01\n\n", prog_name);
}

static int parse_args(int argc, char **argv, dna_send_args_t *args) {
    memset(args, 0, sizeof(dna_send_args_t));

    // Set defaults
    args->network = DEFAULT_NETWORK;
    args->chain = DEFAULT_CHAIN;
    args->token = DEFAULT_TOKEN;
    args->rpc_url = DEFAULT_RPC_URL;

    int opt;
    while ((opt = getopt_long(argc, argv, "w:r:a:f:n:c:t:u:T:d:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'w': args->wallet_file = optarg; break;
            case 'r': args->recipient = optarg; break;
            case 'a': args->amount = optarg; break;
            case 'f': args->fee = optarg; break;
            case 'n': args->network = optarg; break;
            case 'c': args->chain = optarg; break;
            case 't': args->token = optarg; break;
            case 'u': args->rpc_url = optarg; break;
            case 'T': args->timestamp = (uint64_t)strtoull(optarg, NULL, 10); break;
            case 'd': args->tsd_data = optarg; break;
            case 'v': args->verbose = 1; break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    // Validate required arguments
    if (!args->wallet_file || !args->recipient || !args->amount || !args->fee) {
        fprintf(stderr, "Error: Missing required arguments\n\n");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char **argv) {
    printf("=== DNA MESSENGER - CELLFRAME TOKEN SENDER ===\n\n");

    // Parse arguments
    dna_send_args_t args;
    if (parse_args(argc, argv, &args) != 0) {
        return 1;
    }

    if (args.verbose) {
        printf("[CONFIG]\n");
        printf("  Wallet:    %s\n", args.wallet_file);
        printf("  Recipient: %s\n", args.recipient);
        printf("  Amount:    %s %s\n", args.amount, args.token);
        printf("  Fee:       %s %s\n", args.fee, args.token);
        printf("  Network:   %s\n", args.network);
        printf("  Chain:     %s\n", args.chain);
        printf("  RPC URL:   %s\n\n", args.rpc_url);
    }

    // Step 1: Load wallet
    printf("[1/6] Loading wallet...\n");
    cellframe_wallet_t *wallet = NULL;
    if (wallet_read_cellframe_path(args.wallet_file, &wallet) != 0 || !wallet) {
        fprintf(stderr, "[ERROR] Failed to load wallet: %s\n", args.wallet_file);
        return 1;
    }

    printf("      Wallet: %s\n", wallet->name);
    printf("      Address: %s\n", wallet->address);
    printf("      Pubkey: %zu bytes\n", wallet->public_key_size);
    printf("      Privkey: %zu bytes\n\n", wallet->private_key_size);

    // Step 2: Parse transaction parameters
    printf("[2/7] Parsing transaction parameters...\n");

    // Parse amounts
    uint256_t amount, fee;
    if (cellframe_uint256_from_str(args.amount, &amount) != 0) {
        fprintf(stderr, "[ERROR] Failed to parse amount: %s\n", args.amount);
        wallet_free(wallet);
        return 1;
    }
    if (cellframe_uint256_from_str(args.fee, &fee) != 0) {
        fprintf(stderr, "[ERROR] Failed to parse fee: %s\n", args.fee);
        wallet_free(wallet);
        return 1;
    }

    if (args.verbose) {
        printf("      Amount: %lu datoshi\n", amount.lo.lo);
        printf("      Fee:    %lu datoshi\n", fee.lo.lo);
    }
    printf("\n");

    // Step 3: Query and select UTXOs
    printf("[3/7] Querying UTXOs...\n");

    utxo_t *selected_utxos = NULL;
    int num_selected_utxos = 0;
    uint64_t total_input_u64 = 0;

    // Calculate required (simplified for now - assuming amounts fit in uint64)
    uint64_t required_u64 = amount.lo.lo + NETWORK_FEE_DATOSHI + fee.lo.lo;

    // Query UTXOs from RPC
    cellframe_rpc_response_t *utxo_resp = NULL;
    if (cellframe_rpc_get_utxo(args.network, wallet->address, args.token, &utxo_resp) == 0 && utxo_resp) {
        if (utxo_resp->result) {
            if (args.verbose) {
                const char *result_str = json_object_to_json_string_ext(utxo_resp->result, JSON_C_TO_STRING_PRETTY);
                printf("      UTXO Response:\n%s\n", result_str);
            }

            // Parse UTXO response: result[0][0]["outs"][]
            if (json_object_is_type(utxo_resp->result, json_type_array) &&
                json_object_array_length(utxo_resp->result) > 0) {

                json_object *first_array = json_object_array_get_idx(utxo_resp->result, 0);
                if (first_array && json_object_is_type(first_array, json_type_array) &&
                    json_object_array_length(first_array) > 0) {

                    json_object *first_item = json_object_array_get_idx(first_array, 0);
                    json_object *outs_obj = NULL;

                    if (first_item && json_object_object_get_ex(first_item, "outs", &outs_obj) &&
                        json_object_is_type(outs_obj, json_type_array)) {

                        int num_utxos = json_object_array_length(outs_obj);
                        if (num_utxos == 0) {
                            fprintf(stderr, "[ERROR] No UTXOs available for this address\n");
                            cellframe_rpc_response_free(utxo_resp);
                            wallet_free(wallet);
                            return 1;
                        }

                        printf("      Found %d UTXO%s\n", num_utxos, num_utxos > 1 ? "s" : "");

                        // Parse all UTXOs
                        utxo_t *all_utxos = malloc(sizeof(utxo_t) * num_utxos);
                        int valid_utxos = 0;

                        for (int i = 0; i < num_utxos; i++) {
                            json_object *utxo_obj = json_object_array_get_idx(outs_obj, i);
                            json_object *jhash = NULL, *jidx = NULL, *jvalue = NULL;

                            if (utxo_obj &&
                                json_object_object_get_ex(utxo_obj, "prev_hash", &jhash) &&
                                json_object_object_get_ex(utxo_obj, "out_prev_idx", &jidx) &&
                                json_object_object_get_ex(utxo_obj, "value_datoshi", &jvalue)) {

                                const char *hash_str = json_object_get_string(jhash);
                                const char *value_str = json_object_get_string(jvalue);

                                // Parse hash
                                if (hash_str && strlen(hash_str) >= 66 && hash_str[0] == '0' && hash_str[1] == 'x') {
                                    for (int j = 0; j < 32; j++) {
                                        sscanf(hash_str + 2 + (j * 2), "%2hhx", &all_utxos[valid_utxos].hash.raw[j]);
                                    }
                                    all_utxos[valid_utxos].idx = json_object_get_int(jidx);
                                    cellframe_uint256_from_str(value_str, &all_utxos[valid_utxos].value);
                                    valid_utxos++;
                                }
                            }
                        }

                        if (valid_utxos == 0) {
                            fprintf(stderr, "[ERROR] No valid UTXOs found\n");
                            free(all_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            wallet_free(wallet);
                            return 1;
                        }

                        // Select UTXOs (greedy selection)
                        selected_utxos = malloc(sizeof(utxo_t) * valid_utxos);
                        for (int i = 0; i < valid_utxos; i++) {
                            selected_utxos[num_selected_utxos++] = all_utxos[i];
                            total_input_u64 += all_utxos[i].value.lo.lo;

                            if (total_input_u64 >= required_u64) {
                                break;  // Have enough
                            }
                        }

                        free(all_utxos);

                        // Check if we have enough
                        if (total_input_u64 < required_u64) {
                            fprintf(stderr, "[ERROR] Insufficient funds\n");
                            fprintf(stderr, "        Available: %lu datoshi (%d UTXO%s)\n",
                                    total_input_u64, num_selected_utxos, num_selected_utxos > 1 ? "s" : "");
                            fprintf(stderr, "        Required:  %lu datoshi\n", required_u64);
                            free(selected_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            wallet_free(wallet);
                            return 1;
                        }

                        printf("      Selected %d UTXO%s (total: %lu datoshi)\n", num_selected_utxos,
                               num_selected_utxos > 1 ? "s" : "", total_input_u64);
                        for (int i = 0; i < num_selected_utxos; i++) {
                            char hash_hex[67];
                            cellframe_hash_to_hex(&selected_utxos[i].hash, hash_hex);
                            printf("        UTXO %d: %.16s... idx=%u\n", i+1, hash_hex, selected_utxos[i].idx);
                        }

                    } else {
                        fprintf(stderr, "[ERROR] No UTXOs found in response\n");
                        cellframe_rpc_response_free(utxo_resp);
                        wallet_free(wallet);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "[ERROR] Invalid UTXO response structure\n");
                    cellframe_rpc_response_free(utxo_resp);
                    wallet_free(wallet);
                    return 1;
                }
            } else {
                fprintf(stderr, "[ERROR] Invalid UTXO response format\n");
                cellframe_rpc_response_free(utxo_resp);
                wallet_free(wallet);
                return 1;
            }
        }
        cellframe_rpc_response_free(utxo_resp);
    } else {
        fprintf(stderr, "[ERROR] Failed to query UTXOs from RPC\n");
        wallet_free(wallet);
        return 1;
    }
    printf("\n");

    // Step 4: Build transaction
    printf("[4/7] Building transaction...\n");
    cellframe_tx_builder_t *builder = cellframe_tx_builder_new();
    if (!builder) {
        fprintf(stderr, "[ERROR] Failed to create transaction builder\n");
        wallet_free(wallet);
        return 1;
    }

    // Set timestamp
    uint64_t ts = args.timestamp ? args.timestamp : (uint64_t)time(NULL);
    cellframe_tx_set_timestamp(builder, ts);
    if (args.verbose) {
        printf("      Timestamp: %lu%s\n", ts, args.timestamp ? " (override)" : "");
    }

    // Parse recipient address from Base58
    cellframe_addr_t recipient_addr;
    size_t decoded_size = base58_decode(args.recipient, &recipient_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "[ERROR] Failed to decode recipient address (got %zu bytes, expected %zu)\n",
                decoded_size, sizeof(cellframe_addr_t));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Parse network collector address from Base58
    cellframe_addr_t network_collector_addr;
    decoded_size = base58_decode(NETWORK_FEE_COLLECTOR, &network_collector_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "[ERROR] Failed to decode network collector address\n");
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Parse sender address (for change output)
    cellframe_addr_t sender_addr;
    decoded_size = base58_decode(wallet->address, &sender_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "[ERROR] Failed to decode sender address\n");
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Calculate network fee
    uint256_t network_fee = {0};
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    // Calculate change (simplified - using uint64)
    uint64_t change_u64 = total_input_u64 - amount.lo.lo - NETWORK_FEE_DATOSHI - fee.lo.lo;
    uint256_t change = {0};
    change.lo.lo = change_u64;

    if (args.verbose) {
        printf("      Transaction breakdown:\n");
        printf("        Total input:     %lu datoshi\n", total_input_u64);
        printf("        - Recipient:     %lu datoshi\n", amount.lo.lo);
        printf("        - Network fee:   %lu datoshi\n", NETWORK_FEE_DATOSHI);
        printf("        - Validator fee: %lu datoshi\n", fee.lo.lo);
        printf("        = Change:        %lu datoshi\n", change_u64);
    }

    // Add all IN items
    for (int i = 0; i < num_selected_utxos; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            fprintf(stderr, "[ERROR] Failed to add IN item %d\n", i);
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            wallet_free(wallet);
            return 1;
        }
    }

    // Add OUT item (recipient)
    if (cellframe_tx_add_out(builder, &recipient_addr, amount) != 0) {
        fprintf(stderr, "[ERROR] Failed to add recipient OUT item\n");
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Add OUT item (network fee collector)
    if (cellframe_tx_add_out(builder, &network_collector_addr, network_fee) != 0) {
        fprintf(stderr, "[ERROR] Failed to add network fee OUT item\n");
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Add OUT item (change) - only if change > 0
    int has_change = 0;
    if (change.hi.hi != 0 || change.hi.lo != 0 || change.lo.hi != 0 || change.lo.lo != 0) {
        if (cellframe_tx_add_out(builder, &sender_addr, change) != 0) {
            fprintf(stderr, "[ERROR] Failed to add change OUT item\n");
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            wallet_free(wallet);
            return 1;
        }
        has_change = 1;
    }

    // Add TSD item (optional) - BEFORE the fee
    int has_tsd = 0;
    if (args.tsd_data && strlen(args.tsd_data) > 0) {
        size_t tsd_len = strlen(args.tsd_data) + 1;  // Include null terminator
        if (cellframe_tx_add_tsd(builder, TSD_TYPE_CUSTOM_STRING,
                                 (const uint8_t*)args.tsd_data, tsd_len) != 0) {
            fprintf(stderr, "[ERROR] Failed to add TSD item\n");
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            wallet_free(wallet);
            return 1;
        }
        has_tsd = 1;
    }

    // Add OUT_COND item (validator fee)
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        fprintf(stderr, "[ERROR] Failed to add validator FEE item\n");
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    printf("      Transaction items: %d IN + %d OUT + 1 FEE%s\n",
           num_selected_utxos, 2 + has_change, has_tsd ? " + 1 TSD" : "");
    printf("        - %d input%s\n", num_selected_utxos, num_selected_utxos > 1 ? "s" : "");
    printf("        - 1 recipient output\n");
    printf("        - 1 network fee output\n");
    if (has_change) {
        printf("        - 1 change output\n");
    }
    printf("        - 1 validator fee\n");
    if (has_tsd) {
        printf("        - 1 TSD item (%zu bytes)\n", strlen(args.tsd_data) + 1);
    }
    printf("\n");

    // Free selected UTXOs (no longer needed)
    free(selected_utxos);

    // Step 4.5: Export unsigned transaction JSON (for testing with cellframe-tool-sign)
    printf("[4.5/7] Exporting unsigned transaction...\n");

    // Get unsigned transaction data (use get_data, NOT get_signing_data!)
    // We need the REAL tx_items_size for JSON export
    size_t unsigned_tx_size;
    const uint8_t *unsigned_tx_data = cellframe_tx_get_data(builder, &unsigned_tx_size);
    if (!unsigned_tx_data) {
        fprintf(stderr, "[ERROR] Failed to get unsigned transaction data\n");
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Convert to JSON
    char *unsigned_json = NULL;
    if (cellframe_tx_to_json(unsigned_tx_data, unsigned_tx_size, &unsigned_json) != 0) {
        fprintf(stderr, "[ERROR] Failed to convert unsigned transaction to JSON\n");
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Save to file
    FILE *f = fopen("/tmp/unsigned_tx.json", "w");
    if (f) {
        fprintf(f, "%s\n", unsigned_json);
        fclose(f);
        printf("      Unsigned JSON saved: /tmp/unsigned_tx.json\n");
    } else {
        fprintf(stderr, "[WARN] Could not save unsigned transaction to file\n");
    }

    if (args.verbose) {
        printf("\n=== UNSIGNED TRANSACTION JSON ===\n");
        printf("%s\n", unsigned_json);
        printf("=================================\n\n");
    }

    free(unsigned_json);
    printf("\n");

    // Step 5: Sign transaction
    printf("[5/7] Signing transaction...\n");

    // DEBUG: Save ORIGINAL unsigned binary (with actual tx_items_size)
    size_t orig_size;
    const uint8_t *orig_data = cellframe_tx_get_data(builder, &orig_size);
    if (orig_data) {
        FILE *f_bin = fopen("/tmp/unsigned_tx_our.bin", "wb");
        if (f_bin) {
            fwrite(orig_data, 1, orig_size, f_bin);
            fclose(f_bin);
//             fprintf(stderr, "[DEBUG] Unsigned binary saved: /tmp/unsigned_tx_our.bin (%zu bytes)\n", orig_size);
        }

        // DEBUG: Print hex dump of first 100 bytes
//         fprintf(stderr, "[DEBUG] First 100 bytes of unsigned transaction:\n");
        for (size_t i = 0; i < (orig_size < 100 ? orig_size : 100); i++) {
            fprintf(stderr, "%02x", orig_data[i]);
            if ((i + 1) % 32 == 0) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
    }

    // Get signing data (TEMPORARY COPY with tx_items_size = 0)
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        fprintf(stderr, "[ERROR] Failed to get transaction data for signing\n");
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    if (args.verbose) {
        printf("      Transaction size: %zu bytes\n", tx_size);
    }

    // Sign transaction
    uint8_t *dap_sign = NULL;
    size_t dap_sign_size = 0;
    if (cellframe_sign_transaction(tx_data, tx_size,
                                    wallet->private_key, wallet->private_key_size,
                                    wallet->public_key, wallet->public_key_size,
                                    &dap_sign, &dap_sign_size) != 0) {
        fprintf(stderr, "[ERROR] Failed to sign transaction\n");
        free((void*)tx_data);  // Free temporary copy
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Free temporary signing data (it was a copy with tx_items_size=0)
    free((void*)tx_data);

    printf("      Signature size: %zu bytes\n", dap_sign_size);

    // Add signature to transaction
    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        fprintf(stderr, "[ERROR] Failed to add signature\n");
        free(dap_sign);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }
    free(dap_sign);
    printf("      Signature added\n\n");

    // Step 6: Convert to JSON
    printf("[6/7] Converting to JSON...\n");

    // Get complete signed transaction
    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        fprintf(stderr, "[ERROR] Failed to get signed transaction data\n");
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    // Convert to JSON
    char *json = NULL;
    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        fprintf(stderr, "[ERROR] Failed to convert transaction to JSON\n");
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    printf("      JSON size: %zu bytes\n", strlen(json));

    // Save signed JSON to file
    FILE *f_signed = fopen("/tmp/signed_tx.json", "w");
    if (f_signed) {
        fprintf(f_signed, "%s\n", json);
        fclose(f_signed);
        printf("      Signed JSON saved: /tmp/signed_tx.json\n\n");
    }

    // Print JSON
    printf("=== SIGNED TRANSACTION JSON ===\n");
    printf("%s\n", json);
    printf("================================\n\n");

    // Step 7: Submit to RPC
    printf("[7/7] Submitting to RPC...\n");

    cellframe_rpc_response_t *submit_resp = NULL;
    if (cellframe_rpc_submit_tx(args.network, args.chain, json, &submit_resp) == 0 && submit_resp) {
        printf("      Transaction submitted successfully!\n\n");

        if (submit_resp->result) {
            const char *result_str = json_object_to_json_string_ext(submit_resp->result, JSON_C_TO_STRING_PRETTY);
            printf("=== RPC RESPONSE ===\n");
            printf("%s\n", result_str);
            printf("====================\n\n");

            // Try to extract transaction hash from response
            json_object *jhash = NULL;
            if (json_object_object_get_ex(submit_resp->result, "hash", &jhash)) {
                const char *tx_hash = json_object_get_string(jhash);
                printf("Transaction Hash: %s\n", tx_hash);
                printf("View on explorer: https://explorer.cellframe.net/tx/%s\n", tx_hash);
            }
        }

        cellframe_rpc_response_free(submit_resp);
    } else {
        fprintf(stderr, "[ERROR] Failed to submit transaction to RPC\n");
        free(json);
        cellframe_tx_builder_free(builder);
        wallet_free(wallet);
        return 1;
    }

    free(json);

    // Cleanup
    cellframe_tx_builder_free(builder);
    wallet_free(wallet);

    printf("=== TRANSACTION SUBMITTED SUCCESSFULLY ===\n");
    printf("\n");
    printf("Your transaction has been broadcast to the Cellframe network!\n");
    printf("Check the blockchain explorer to confirm.\n");

    return 0;
}
