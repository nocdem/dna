#include "wallet_screen.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "wallet_transaction_history_dialog.h"
#include "../../blockchain/wallet.h"
#include "../../blockchain/blockchain_rpc.h"

#include <cstdio>

namespace WalletScreen {

void loadWallet(AppState& state) {
    if (state.wallet_loading) return;  // Already loading

    state.wallet_loading = true;
    state.wallet_error.clear();

    wallet_list_t *wallets = nullptr;
    int ret = wallet_list_cellframe(&wallets);

    if (ret != 0 || !wallets || wallets->count == 0) {
        state.wallet_error = "No wallets found. Create one with cellframe-node-cli.";
        state.wallet_loaded = false;
        state.wallet_loading = false;
        return;
    }

    // Store wallet list and use first wallet
    state.wallet_list = wallets;
    state.current_wallet_index = 0;
    state.wallet_name = std::string(wallets->wallets[0].name);
    state.wallet_loaded = true;
    state.wallet_loading = false;

    printf("[Wallet] Loaded wallet: %s\n", state.wallet_name.c_str());

    // Automatically refresh balances
    refreshBalances(state);
}

void refreshBalances(AppState& state) {
    if (!state.wallet_loaded || state.current_wallet_index < 0) {
        return;
    }

    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets) return;

    cellframe_wallet_t *wallet = &wallets->wallets[state.current_wallet_index];

    // Get wallet address for Backbone network
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        state.wallet_error = "Failed to get wallet address";
        return;
    }

    printf("[Wallet] Querying balances for address: %s\n", address);

    // Query balance for CPUNK token
    cellframe_rpc_response_t *response = nullptr;
    if (cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response) == 0 && response->result) {
        json_object *jresult = response->result;

        if (json_object_is_type(jresult, json_type_array) && json_object_array_length(jresult) > 0) {
            json_object *first = json_object_array_get_idx(jresult, 0);
            if (json_object_is_type(first, json_type_array) && json_object_array_length(first) > 0) {
                json_object *wallet_obj = json_object_array_get_idx(first, 0);
                json_object *tokens_obj = nullptr;

                if (json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                    int token_count = json_object_array_length(tokens_obj);

                    for (int i = 0; i < token_count; i++) {
                        json_object *token_entry = json_object_array_get_idx(tokens_obj, i);
                        json_object *token_info_obj = nullptr;
                        json_object *coins_obj = nullptr;

                        // Get coins from top level
                        if (!json_object_object_get_ex(token_entry, "coins", &coins_obj)) {
                            printf("[Wallet] Token %d: No 'coins' field, skipping\n", i);
                            continue;
                        }

                        // Get ticker from nested "token" object
                        if (!json_object_object_get_ex(token_entry, "token", &token_info_obj)) {
                            printf("[Wallet] Token %d: No 'token' object, skipping\n", i);
                            continue;
                        }

                        json_object *ticker_obj = nullptr;
                        if (json_object_object_get_ex(token_info_obj, "ticker", &ticker_obj)) {
                            const char *ticker = json_object_get_string(ticker_obj);
                            const char *coins = json_object_get_string(coins_obj);

                            state.token_balances[ticker] = coins;
                            printf("[Wallet] %s: %s\n", ticker, coins);
                        } else {
                            printf("[Wallet] Token %d: No 'ticker' field in token object\n", i);
                        }
                    }
                }
            }
        }

        if (response) {
            cellframe_rpc_response_free(response);
        }
    }

    // Also query CELL and KEL (on different networks if needed)
    // For now, assume they're all on Backbone network
}

std::string formatBalance(const std::string& coins) {
    if (coins.empty() || coins == "0") {
        return "0.00";
    }

    // Try to parse as double
    try {
        double value = std::stod(coins);

        // Format with 2 decimals for large amounts, 8 for small amounts
        if (value >= 0.01) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%.2f", value);
            return std::string(buf);
        } else if (value > 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%.8f", value);
            return std::string(buf);
        }
        return "0.00";
    } catch (...) {
        return coins;  // Return as-is if parsing fails
    }
}

void render(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    float padding = is_mobile ? 15.0f : 20.0f;

    ImGui::SetCursorPos(ImVec2(padding, padding));
    ImGui::BeginChild("WalletContent", ImVec2(-padding, -padding), false);

    // Load wallet on first render
    if (!state.wallet_loaded && !state.wallet_loading) {
        loadWallet(state);
    }

    // Show error if wallet failed to load
    if (!state.wallet_error.empty()) {
        ImVec2 available_size = ImGui::GetContentRegionAvail();
        ImVec2 center = ImVec2(available_size.x * 0.5f, available_size.y * 0.5f);

        const char* error_icon = ICON_FA_TRIANGLE_EXCLAMATION " Wallet Error";
        ImVec2 text_size = ImGui::CalcTextSize(error_icon);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y - 60));
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), "%s", error_icon);

        ImVec2 desc_size = ImGui::CalcTextSize(state.wallet_error.c_str());
        ImGui::SetCursorPos(ImVec2(center.x - desc_size.x * 0.5f, center.y - 20));
        ImGui::TextDisabled("%s", state.wallet_error.c_str());

        ImGui::EndChild();
        return;
    }

    // Show loading spinner while wallet is loading
    if (state.wallet_loading) {
        ImVec2 available_size = ImGui::GetContentRegionAvail();
        ImVec2 center = ImVec2(available_size.x * 0.5f, available_size.y * 0.5f);
        ImGui::SetCursorPos(ImVec2(center.x - 50, center.y - 50));
        ThemedSpinner("##wallet_loading", 20.0f, 4.0f);
        ImGui::SetCursorPos(ImVec2(center.x - 50, center.y));
        ImGui::TextDisabled("Loading wallet...");
        ImGui::EndChild();
        return;
    }

    // Header with wallet selector
    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (wallets && wallets->count > 1) {
        // Show dropdown if multiple wallets
        ImGui::Text(ICON_FA_WALLET " Wallet:");
        ImGui::SameLine();
        
        if (ImGui::BeginCombo("##wallet_selector", state.wallet_name.c_str())) {
            for (int i = 0; i < wallets->count; i++) {
                bool is_selected = (state.current_wallet_index == i);
                if (ImGui::Selectable(wallets->wallets[i].name, is_selected)) {
                    state.current_wallet_index = i;
                    state.wallet_name = std::string(wallets->wallets[i].name);
                    refreshBalances(state);  // Reload balances for new wallet
                }
                if (is_selected) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
    } else {
        // Single wallet, just show name
        ImGui::Text(ICON_FA_WALLET " %s", state.wallet_name.c_str());
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Refresh button
    if (ImGui::Button(ICON_FA_ARROWS_ROTATE " Refresh")) {
        refreshBalances(state);
    }
    ImGui::Spacing();

    // Token balance cards
    const char* tokens[] = {"CPUNK", "CELL", "KEL"};
    const char* token_names[] = {"ChipPunk", "Cellframe", "KelVPN"};
    const char* token_icons[] = {ICON_FA_COINS, ICON_FA_BOLT, ICON_FA_GEM};

    for (int i = 0; i < 3; i++) {
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
        ImVec4 card_bg = g_app_settings.theme == 0 ? DNATheme::InputBackground() : ClubTheme::InputBackground();
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(card_bg.x, card_bg.y, card_bg.z, 0.9f));

        float card_height = is_mobile ? 100.0f : 120.0f;
        char card_id[32];
        snprintf(card_id, sizeof(card_id), "##card_%s", tokens[i]);
        ImGui::BeginChild(card_id, ImVec2(-1, card_height), true);

        // Token icon and name
        ImGui::SetCursorPos(ImVec2(20, 15));
        ImGui::Text("%s %s", token_icons[i], tokens[i]);

        ImGui::SetCursorPos(ImVec2(20, 35));
        ImGui::TextDisabled("%s", token_names[i]);

        // Balance
        ImGui::SetCursorPos(ImVec2(20, is_mobile ? 60 : 65));
        auto it = state.token_balances.find(tokens[i]);
        if (it != state.token_balances.end()) {
            std::string formatted = formatBalance(it->second);
            ImGui::Text("%s", formatted.c_str());
        } else {
            ImGui::TextDisabled("0.00");
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();

        ImGui::Spacing();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Action buttons
    float btn_height = is_mobile ? 50.0f : 45.0f;

    if (is_mobile) {
        // Mobile: Stacked full-width buttons
        if (ThemedButton(ICON_FA_PAPER_PLANE " Send Tokens", ImVec2(-1, btn_height))) {
            state.show_send_dialog = true;
            state.send_status.clear();
        }
        ImGui::Spacing();

        if (ThemedButton(ICON_FA_DOWNLOAD " Receive", ImVec2(-1, btn_height))) {
            state.show_receive_dialog = true;
            // Get wallet address for Backbone network
            wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
            if (wallets && state.current_wallet_index >= 0) {
                wallet_get_address(&wallets->wallets[state.current_wallet_index],
                                  "Backbone", state.wallet_address);
            }
        }
        ImGui::Spacing();

        if (ThemedButton(ICON_FA_RECEIPT " Transaction History", ImVec2(-1, btn_height))) {
            state.show_transaction_history = true;
            WalletTransactionHistoryDialog::load(state);
        }
    } else {
        // Desktop: Side-by-side buttons
        ImGuiStyle& style = ImGui::GetStyle();
        float available_width = ImGui::GetContentRegionAvail().x;
        float spacing = style.ItemSpacing.x;
        float btn_width = (available_width - spacing * 2) / 3.0f;

        if (ThemedButton(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, btn_height))) {
            state.show_send_dialog = true;
            state.send_status.clear();
        }
        ImGui::SameLine();

        if (ThemedButton(ICON_FA_DOWNLOAD " Receive", ImVec2(btn_width, btn_height))) {
            state.show_receive_dialog = true;
            // Get wallet address for Backbone network
            wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
            if (wallets && state.current_wallet_index >= 0) {
                wallet_get_address(&wallets->wallets[state.current_wallet_index],
                                  "Backbone", state.wallet_address);
            }
        }
        ImGui::SameLine();

        if (ThemedButton(ICON_FA_RECEIPT " History", ImVec2(btn_width, btn_height))) {
            state.show_transaction_history = true;
            WalletTransactionHistoryDialog::load(state);
        }
    }

    ImGui::EndChild();
}

} // namespace WalletScreen
