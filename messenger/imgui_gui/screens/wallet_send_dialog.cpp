#include "wallet_send_dialog.h"
#include "wallet_screen.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "imgui.h"

extern "C" {
#include "../../blockchain/wallet.h"
#include "../../blockchain/blockchain_rpc.h"
#include "../../blockchain/blockchain_tx_builder_minimal.h"
#include "../../blockchain/blockchain_sign_minimal.h"
#include "../../blockchain/blockchain_json_minimal.h"
#include "../../crypto/utils/base58.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
}

// Network fee constants
#define NETWORK_FEE_DATOSHI 2000000000000000ULL  // 0.002 CELL
#define NETWORK_FEE_COLLECTOR "mHLjDKBUWvbwW8UZo8X4U76aPT8j7EsdZ1b7e8rKEtL8xoE"

// UTXO structure for transaction building
typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} utxo_t;

namespace WalletSendDialog {

void buildAndSendTransaction(AppState& state) {
    state.send_status = "Checking wallet...";

    // Get wallet
    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets || state.current_wallet_index < 0) {
        state.send_status = "ERROR: No wallet loaded";
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[state.current_wallet_index];

    // Check if address is available
    if (wallet->address[0] == '\0') {
        if (wallet->status == WALLET_STATUS_PROTECTED) {
            state.send_status = "ERROR: Wallet is password-protected. Cannot send from protected wallet.";
        } else {
            state.send_status = "ERROR: Could not generate wallet address. Wallet may be corrupted.";
        }
        return;
    }

    char address[WALLET_ADDRESS_MAX];
    strncpy(address, wallet->address, WALLET_ADDRESS_MAX - 1);
    address[WALLET_ADDRESS_MAX - 1] = '\0';

    state.send_status = "Querying UTXOs...";

    // Get parameters
    const char *amount_str = state.send_amount;
    const char *fee_str = state.send_fee;
    const char *recipient = state.send_recipient;

    // Parse amounts
    uint256_t amount, fee;
    if (cellframe_uint256_from_str(amount_str, &amount) != 0) {
        state.send_status = "ERROR: Failed to parse amount";
        return;
    }

    if (cellframe_uint256_from_str(fee_str, &fee) != 0) {
        state.send_status = "ERROR: Failed to parse fee";
        return;
    }

    // STEP 1: Query UTXOs
    utxo_t *selected_utxos = NULL;
    int num_selected_utxos = 0;
    uint64_t total_input_u64 = 0;

    uint64_t required_u64 = amount.lo.lo + NETWORK_FEE_DATOSHI + fee.lo.lo;

    cellframe_rpc_response_t *utxo_resp = NULL;
    if (cellframe_rpc_get_utxo("Backbone", address, "CELL", &utxo_resp) == 0 && utxo_resp) {
        if (utxo_resp->result) {
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
                            state.send_status = "ERROR: No UTXOs available";
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        // Parse all UTXOs
                        utxo_t *all_utxos = (utxo_t*)malloc(sizeof(utxo_t) * num_utxos);
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
                            state.send_status = "ERROR: No valid UTXOs";
                            free(all_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        // Select UTXOs (greedy selection)
                        selected_utxos = (utxo_t*)malloc(sizeof(utxo_t) * valid_utxos);
                        for (int i = 0; i < valid_utxos; i++) {
                            selected_utxos[num_selected_utxos++] = all_utxos[i];
                            total_input_u64 += all_utxos[i].value.lo.lo;

                            if (total_input_u64 >= required_u64) {
                                break;
                            }
                        }

                        free(all_utxos);

                        // Check if we have enough
                        if (total_input_u64 < required_u64) {
                            char error_msg[256];
                            snprintf(error_msg, sizeof(error_msg),
                                    "ERROR: Insufficient funds. Need: %.6f CELL, Have: %.6f CELL",
                                    (double)required_u64 / 1e18, (double)total_input_u64 / 1e18);
                            state.send_status = std::string(error_msg);
                            free(selected_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                    } else {
                        state.send_status = "ERROR: Invalid UTXO response";
                        cellframe_rpc_response_free(utxo_resp);
                        return;
                    }
                } else {
                    state.send_status = "ERROR: Invalid UTXO response";
                    cellframe_rpc_response_free(utxo_resp);
                    return;
                }
            } else {
                state.send_status = "ERROR: Invalid UTXO response";
                cellframe_rpc_response_free(utxo_resp);
                return;
            }
        }
        cellframe_rpc_response_free(utxo_resp);
    } else {
        state.send_status = "ERROR: Failed to query UTXOs from RPC";
        return;
    }

    // STEP 2: Build transaction
    state.send_status = "Building transaction...";

    cellframe_tx_builder_t *builder = cellframe_tx_builder_new();
    if (!builder) {
        state.send_status = "ERROR: Failed to create builder";
        free(selected_utxos);
        return;
    }

    // Set timestamp
    uint64_t ts = (uint64_t)time(NULL);
    cellframe_tx_set_timestamp(builder, ts);

    // Parse recipient address from Base58
    cellframe_addr_t recipient_addr;
    size_t decoded_size = base58_decode(recipient, &recipient_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        state.send_status = "ERROR: Invalid recipient address";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Parse network collector address
    cellframe_addr_t network_collector_addr;
    decoded_size = base58_decode(NETWORK_FEE_COLLECTOR, &network_collector_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        state.send_status = "ERROR: Invalid network collector address";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Parse sender address (for change)
    cellframe_addr_t sender_addr;
    decoded_size = base58_decode(address, &sender_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        state.send_status = "ERROR: Invalid sender address";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Calculate network fee
    uint256_t network_fee = {0};
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    // Calculate change
    uint64_t change_u64 = total_input_u64 - amount.lo.lo - NETWORK_FEE_DATOSHI - fee.lo.lo;
    uint256_t change = {0};
    change.lo.lo = change_u64;

    // Add all IN items
    for (int i = 0; i < num_selected_utxos; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            state.send_status = "ERROR: Failed to add IN item";
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add OUT item (recipient)
    if (cellframe_tx_add_out(builder, &recipient_addr, amount) != 0) {
        state.send_status = "ERROR: Failed to add recipient OUT";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add OUT item (network fee collector)
    if (cellframe_tx_add_out(builder, &network_collector_addr, network_fee) != 0) {
        state.send_status = "ERROR: Failed to add network fee OUT";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add OUT item (change) - only if change > 0
    if (change.hi.hi != 0 || change.hi.lo != 0 || change.lo.hi != 0 || change.lo.lo != 0) {
        if (cellframe_tx_add_out(builder, &sender_addr, change) != 0) {
            state.send_status = "ERROR: Failed to add change OUT";
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add OUT_COND item (validator fee)
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        state.send_status = "ERROR: Failed to add validator fee";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Free selected UTXOs
    free(selected_utxos);

    // STEP 3: Sign transaction
    state.send_status = "Signing transaction...";


    // Get signing data
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        state.send_status = "ERROR: Failed to get transaction data";
        cellframe_tx_builder_free(builder);
        return;
    }


    // Sign transaction
    uint8_t *dap_sign = NULL;
    size_t dap_sign_size = 0;
    if (cellframe_sign_transaction(tx_data, tx_size,
                                    wallet->private_key, wallet->private_key_size,
                                    wallet->public_key, wallet->public_key_size,
                                    &dap_sign, &dap_sign_size) != 0) {
        state.send_status = "ERROR: Failed to sign transaction";
        free((void*)tx_data);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Free temporary signing data
    free((void*)tx_data);


    // Add signature to transaction
    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        state.send_status = "ERROR: Failed to add signature";
        free(dap_sign);
        cellframe_tx_builder_free(builder);
        return;
    }
    free(dap_sign);

    // STEP 4: Convert to JSON
    state.send_status = "Converting to JSON...";


    // Get complete signed transaction
    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        state.send_status = "ERROR: Failed to get signed transaction";
        cellframe_tx_builder_free(builder);
        return;
    }

    // Convert to JSON
    char *json = NULL;
    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        state.send_status = "ERROR: Failed to convert to JSON";
        cellframe_tx_builder_free(builder);
        return;
    }


    // STEP 5: Submit to RPC
    state.send_status = "Submitting to RPC...";


    cellframe_rpc_response_t *submit_resp = NULL;
    if (cellframe_rpc_submit_tx("Backbone", "main", json, &submit_resp) == 0 && submit_resp) {
        printf("      Transaction submitted successfully!\n\n");

        std::string txHash = "N/A";
        bool txCreated = false;

        if (submit_resp->result) {
            const char *result_str = json_object_to_json_string_ext(submit_resp->result, JSON_C_TO_STRING_PRETTY);
            printf("=== RPC RESPONSE ===\n%s\n====================\n\n", result_str);

            // Response format: [ { "tx_create": true, "hash": "0x...", "total_items": 7 } ]
            if (json_object_is_type(submit_resp->result, json_type_array) &&
                json_object_array_length(submit_resp->result) > 0) {

                json_object *first_elem = json_object_array_get_idx(submit_resp->result, 0);
                if (first_elem) {
                    // Check tx_create status
                    json_object *jtx_create = NULL;
                    if (json_object_object_get_ex(first_elem, "tx_create", &jtx_create)) {
                        txCreated = json_object_get_boolean(jtx_create);
                    }

                    // Extract hash
                    json_object *jhash = NULL;
                    if (json_object_object_get_ex(first_elem, "hash", &jhash)) {
                        const char *tx_hash = json_object_get_string(jhash);
                        if (tx_hash) {
                            txHash = std::string(tx_hash);
                        }
                    }
                }
            }
        }

        cellframe_rpc_response_free(submit_resp);

        // Check if transaction was actually created
        if (!txCreated) {
            state.send_status = "ERROR: Transaction failed to create. May indicate insufficient balance or network issues.";
            free(json);
            cellframe_tx_builder_free(builder);
            return;
        }

        // Success!
        char success_msg[512];
        snprintf(success_msg, sizeof(success_msg),
                "SUCCESS! Transaction submitted!\nHash: %s\nAmount: %s CELL\nExplorer: https://scan.cellframe.net/datum-details/%s?net=Backbone",
                txHash.c_str(), amount_str, txHash.c_str());
        state.send_status = std::string(success_msg);

    } else {
        state.send_status = "ERROR: Failed to submit transaction to RPC";
        free(json);
        cellframe_tx_builder_free(builder);
        return;
    }

    free(json);
    cellframe_tx_builder_free(builder);

}

void render(AppState& state) {
    if (!state.show_send_dialog) return;

    // Center the modal
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(550, 500), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Send Tokens", &state.show_send_dialog, ImGuiWindowFlags_NoResize)) {
        // Wallet name
        ImGui::Text(ICON_FA_WALLET " From: %s", state.wallet_name.c_str());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Show balance
        auto it = state.token_balances.find("CELL");
        if (it != state.token_balances.end()) {
            std::string formatted = WalletScreen::formatBalance(it->second);
            ImGui::TextDisabled("Available: %s CELL", formatted.c_str());
        } else {
            ImGui::TextDisabled("Available: 0.00 CELL");
        }
        ImGui::Spacing();

        // Recipient address
        ImGui::Text("To Address:");
        ImGui::PushItemWidth(-1);
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        ImGui::InputText("##recipient", state.send_recipient, sizeof(state.send_recipient));
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::Spacing();

        // Amount
        ImGui::Text("Amount:");
        ImGui::PushItemWidth(-120);
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        ImGui::InputText("##amount", state.send_amount, sizeof(state.send_amount));
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::TextDisabled("CELL");
        ImGui::SameLine();
        if (ImGui::Button("MAX", ImVec2(60, 0))) {
            // Calculate max amount (balance - fees)
            auto balance_it = state.token_balances.find("CELL");
            if (balance_it != state.token_balances.end()) {
                try {
                    double balance = std::stod(balance_it->second);
                    double fee = std::stod(state.send_fee);
                    double network_fee = 0.002;
                    double max_amount = balance - fee - network_fee;
                    if (max_amount > 0) {
                        snprintf(state.send_amount, sizeof(state.send_amount), "%.6f", max_amount);
                    }
                } catch (...) {}
            }
        }
        ImGui::Spacing();

        // Validator fee
        ImGui::Text("Validator Fee:");
        ImGui::PushItemWidth(-80);
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        ImGui::InputText("##fee", state.send_fee, sizeof(state.send_fee));
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::TextDisabled("CELL");
        ImGui::Spacing();

        // Network fee (fixed, read-only)
        ImGui::TextDisabled("Network Fee: 0.002 CELL (fixed)");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Total
        try {
            double amount = std::stod(state.send_amount);
            double fee = std::stod(state.send_fee);
            double network_fee = 0.002;
            double total = amount + fee + network_fee;
            ImGui::Text("Total: %.6f CELL", total);
        } catch (...) {
            ImGui::TextDisabled("Total: (invalid amount)");
        }
        ImGui::Spacing();
        ImGui::Spacing();

        // Status message
        if (!state.send_status.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::TextInfo() : ClubTheme::TextInfo());
            ImGui::TextWrapped("%s", state.send_status.c_str());
            ImGui::PopStyleColor();
            ImGui::Spacing();
        }

        // Buttons
        float btn_width = 120.0f;
        float btn_spacing = (ImGui::GetContentRegionAvail().x - (btn_width * 2)) / 3.0f;

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + btn_spacing);
        if (ButtonDark(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, 40))) {
            buildAndSendTransaction(state);
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(btn_width, 40))) {
            state.show_send_dialog = false;
            state.send_status.clear();
        }

        ImGui::EndPopup();
    }

    // Open the modal if flag is set
    if (state.show_send_dialog && !ImGui::IsPopupOpen("Send Tokens")) {
        ImGui::OpenPopup("Send Tokens");
    }
}

} // namespace WalletSendDialog
