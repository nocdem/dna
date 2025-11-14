#include "wallet_transaction_history_dialog.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../../blockchain/wallet.h"
#include "../../blockchain/blockchain_rpc.h"

#include <ctime>
#include <cstring>
#include <string>

namespace WalletTransactionHistoryDialog {

void load(AppState& state) {
    state.transaction_list.clear();
    state.transaction_history_loading = true;
    state.transaction_history_error.clear();

    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets || state.current_wallet_index < 0) {
        state.transaction_history_error = "No wallet loaded";
        state.transaction_history_loading = false;
        return;
    }

    // Get wallet address
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(&wallets->wallets[state.current_wallet_index], "Backbone", address) != 0) {
        state.transaction_history_error = "Failed to get wallet address";
        state.transaction_history_loading = false;
        return;
    }

    // Query transaction history via RPC
    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string("Backbone"));
    json_object_object_add(args, "addr", json_object_new_string(address));
    json_object_object_add(args, "chain", json_object_new_string("main"));

    cellframe_rpc_request_t req = {
        .method = "tx_history",
        .subcommand = "",
        .arguments = args,
        .id = 1
    };

    cellframe_rpc_response_t *response = nullptr;
    int ret = cellframe_rpc_call(&req, &response);
    json_object_put(args);

    if (ret == 0 && response && response->result) {
        json_object *jresult = response->result;

        // DEBUG: Print full RPC response
        const char *json_str = json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY);

        if (json_object_is_type(jresult, json_type_array)) {
            int result_len = json_object_array_length(jresult);

            if (result_len > 0) {
                json_object *tx_array = json_object_array_get_idx(jresult, 0);

                if (json_object_is_type(tx_array, json_type_array)) {
                    int array_len = json_object_array_length(tx_array);

                    // Skip first 2 items (query parameters), show ALL transactions
                    for (int i = 2; i < array_len; i++) {
                        json_object *tx_obj = json_object_array_get_idx(tx_array, i);

                        // DEBUG: Print each transaction object
                        const char *tx_json = json_object_to_json_string_ext(tx_obj, JSON_C_TO_STRING_PRETTY);

                        json_object *status_obj = nullptr;
                        if (!json_object_object_get_ex(tx_obj, "status", &status_obj)) {
                            continue;
                        }

                        json_object *hash_obj = nullptr, *timestamp_obj = nullptr, *data_obj = nullptr;
                        json_object_object_get_ex(tx_obj, "hash", &hash_obj);
                        json_object_object_get_ex(tx_obj, "tx_created", &timestamp_obj);
                        json_object_object_get_ex(tx_obj, "data", &data_obj);

                        std::string hash = hash_obj ? json_object_get_string(hash_obj) : "N/A";
                        std::string shortHash = hash.substr(0, 12) + "...";
                        std::string status = json_object_get_string(status_obj);

                        // Parse timestamp (smart formatting from Qt lines 143-154)
                        std::string timeStr = "Unknown";
                        if (timestamp_obj) {
                            const char *ts_str = json_object_get_string(timestamp_obj);
                            // Parse RFC2822 format timestamp (e.g., "Mon, 15 Oct 2024 14:30:00 GMT")
                            // Manual parsing for cross-platform compatibility (strptime is POSIX-only)
                            struct tm tm_time = {};
                            char month_str[4];
                            int parsed = sscanf(ts_str, "%*[^,], %d %3s %d %d:%d:%d",
                                              &tm_time.tm_mday, month_str, &tm_time.tm_year,
                                              &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);

                            if (parsed == 6) {
                                // Convert month string to number
                                const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
                                for (int i = 0; i < 12; i++) {
                                    if (strcmp(month_str, months[i]) == 0) {
                                        tm_time.tm_mon = i;
                                        break;
                                    }
                                }
                                tm_time.tm_year -= 1900;  // tm_year is years since 1900

                                time_t tx_time = mktime(&tm_time);
                                time_t now = time(nullptr);
                                int64_t diff = now - tx_time;

                                if (diff < 60) {
                                    timeStr = "Just now";
                                } else if (diff < 3600) {
                                    timeStr = std::to_string(diff / 60) + "m ago";
                                } else if (diff < 86400) {
                                    timeStr = std::to_string(diff / 3600) + "h ago";
                                } else if (diff < 86400 * 30) {
                                    timeStr = std::to_string(diff / 86400) + "d ago";
                                } else {
                                    char date_buf[64];
                                    strftime(date_buf, sizeof(date_buf), "%b %d, %Y", &tm_time);
                                    timeStr = date_buf;
                                }
                            }
                        }

                        // Parse transaction data (from Qt lines 158-217)
                        std::string direction = "received";
                        std::string amount = "0.00";
                        std::string token = "UNKNOWN";
                        std::string otherAddress = shortHash;

                        if (data_obj && json_object_is_type(data_obj, json_type_array)) {
                            int data_count = json_object_array_length(data_obj);
                            if (data_count > 0) {
                                json_object *first_data = json_object_array_get_idx(data_obj, 0);

                                json_object *tx_type_obj = nullptr, *token_obj = nullptr;
                                json_object *coins_obj = nullptr, *addr_obj = nullptr;

                                if (json_object_object_get_ex(first_data, "tx_type", &tx_type_obj)) {
                                    const char *tx_type_str = json_object_get_string(tx_type_obj);

                                    if (strcmp(tx_type_str, "recv") == 0) {
                                        direction = "received";
                                        if (json_object_object_get_ex(first_data, "recv_coins", &coins_obj)) {
                                            amount = json_object_get_string(coins_obj);
                                            // Smart decimal formatting (Qt lines 177-188)
                                            double amt = std::stod(amount);
                                            char formatted[64];
                                            if (amt < 0.01) {
                                                snprintf(formatted, sizeof(formatted), "%.8f", amt);
                                            } else if (amt < 1.0) {
                                                snprintf(formatted, sizeof(formatted), "%.4f", amt);
                                            } else {
                                                snprintf(formatted, sizeof(formatted), "%.2f", amt);
                                            }
                                            amount = formatted;
                                            // Remove trailing zeros
                                            while (amount.back() == '0') amount.pop_back();
                                            if (amount.back() == '.') amount.pop_back();
                                        }
                                        if (json_object_object_get_ex(first_data, "source_address", &addr_obj)) {
                                            std::string full_addr = json_object_get_string(addr_obj);
                                            otherAddress = full_addr.substr(0, 12) + "...";
                                        }
                                    } else if (strcmp(tx_type_str, "send") == 0) {
                                        direction = "sent";
                                        if (json_object_object_get_ex(first_data, "send_coins", &coins_obj)) {
                                            amount = json_object_get_string(coins_obj);
                                            // Smart decimal formatting (Qt lines 194-206)
                                            double amt = std::stod(amount);
                                            char formatted[64];
                                            if (amt < 0.01) {
                                                snprintf(formatted, sizeof(formatted), "%.8f", amt);
                                            } else if (amt < 1.0) {
                                                snprintf(formatted, sizeof(formatted), "%.4f", amt);
                                            } else {
                                                snprintf(formatted, sizeof(formatted), "%.2f", amt);
                                            }
                                            amount = formatted;
                                            // Remove trailing zeros
                                            while (amount.back() == '0') amount.pop_back();
                                            if (amount.back() == '.') amount.pop_back();
                                        }
                                        if (json_object_object_get_ex(first_data, "destination_address", &addr_obj)) {
                                            std::string full_addr = json_object_get_string(addr_obj);
                                            otherAddress = full_addr.substr(0, 12) + "...";
                                        }
                                    }

                                    if (json_object_object_get_ex(first_data, "token", &token_obj)) {
                                        token = json_object_get_string(token_obj);
                                    } else {
                                    }
                                } else {
                                }
                            }
                        } else {
                        }

                        // Add transaction to list
                        AppState::Transaction tx;
                        tx.direction = direction;
                        tx.amount = amount;
                        tx.token = token;
                        tx.address = otherAddress;
                        tx.time = timeStr;
                        tx.status = status;
                        tx.is_declined = (status.find("DECLINED") != std::string::npos);

                        state.transaction_list.push_back(tx);
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    } else {
        state.transaction_history_error = "Failed to load transaction history";
    }

    state.transaction_history_loading = false;
}

void render(AppState& state) {
    if (!state.show_transaction_history) return;

    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Transaction History")) {
        ImGui::OpenPopup("Transaction History");
        load(state);
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = (io.DisplaySize.x < 600);

    ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x : 700, is_mobile ? io.DisplaySize.y : 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Transaction History", &state.show_transaction_history, ImGuiWindowFlags_NoResize)) {
        ImGui::PushFont(io.Fonts->Fonts[2]); // Title font
        ImGui::Text("Transaction History - %s", state.wallet_name.c_str());
        ImGui::PopFont();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Scrollable transaction list
        ImGui::BeginChild("TransactionList", ImVec2(0, -50), true);

        if (state.transaction_history_loading) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "Loading transactions...");
        } else if (!state.transaction_history_error.empty()) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), "%s", state.transaction_history_error.c_str());
        } else if (state.transaction_list.empty()) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "No transactions found");
        } else {
            // Display all transactions
            for (size_t i = 0; i < state.transaction_list.size(); i++) {
                const auto& tx = state.transaction_list[i];

                ImGui::PushID(i);
                ImGui::BeginGroup();

                // Transaction item (similar to Qt createTransactionItem)
                float item_height = 60.0f;
                ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                ImDrawList* draw_list = ImGui::GetWindowDrawList();

                // Background
                ImU32 bg_color = IM_COL32(30, 30, 35, 255);
                draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + ImGui::GetContentRegionAvail().x, cursor_pos.y + item_height), bg_color, 4.0f);

                ImGui::Dummy(ImVec2(0, 5));
                ImGui::Indent(10);

                // Direction icon (Qt lines 252-259)
                ImGui::PushFont(io.Fonts->Fonts[2]); // Large font for icon
                if (tx.direction == "sent") {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), ICON_FA_ARROW_UP); // Red arrow up
                } else {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), ICON_FA_ARROW_DOWN); // Green arrow down
                }
                ImGui::PopFont();
                ImGui::SameLine();

                // Transaction info
                ImGui::BeginGroup();
                ImGui::PushFont(io.Fonts->Fonts[1]); // Bold font
                ImGui::Text("%s %s", tx.amount.c_str(), tx.token.c_str());
                ImGui::PopFont();
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", tx.address.c_str());
                ImGui::EndGroup();

                // Time and status (right-aligned)
                ImGui::SameLine(ImGui::GetContentRegionAvail().x - 120);
                ImGui::BeginGroup();
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", tx.time.c_str());
                if (tx.is_declined) {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), "%s", tx.status.c_str()); // Red for DECLINED
                } else {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), "%s", tx.status.c_str()); // Green for ACCEPTED
                }
                ImGui::EndGroup();

                ImGui::Unindent(10);
                ImGui::Dummy(ImVec2(0, 5));

                ImGui::EndGroup();
                ImGui::PopID();

                if (i < state.transaction_list.size() - 1) {
                    ImGui::Spacing();
                }
            }
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Close button
        if (ThemedButton("Close", ImVec2(-1, 40))) {
            state.show_transaction_history = false;
        }

        ImGui::EndPopup();
    }
}

} // namespace WalletTransactionHistoryDialog
