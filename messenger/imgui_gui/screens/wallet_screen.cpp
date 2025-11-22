#include "wallet_screen.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../helpers/file_browser.h"
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

    // Don't automatically refresh - will be done by preloadAllBalances
}

void preloadAllBalances(AppState& state) {
    if (!state.wallet_loaded) {
        return;
    }

    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets) return;

    printf("[Wallet] Preloading balances for %d wallet(s)...\n", wallets->count);

    // Query balances for each wallet
    for (int wallet_idx = 0; wallet_idx < wallets->count; wallet_idx++) {
        cellframe_wallet_t *wallet = &wallets->wallets[wallet_idx];

        // Initialize empty balance map for this wallet
        state.all_wallet_balances[wallet_idx] = std::map<std::string, std::string>();

        // Get wallet address for Backbone network
        char address[WALLET_ADDRESS_MAX];
        if (wallet_get_address(wallet, "Backbone", address) != 0) {
            printf("[Wallet] Failed to get address for wallet %d (%s)\n", wallet_idx, wallet->name);
            continue;
        }

        printf("[Wallet] Querying balances for wallet %d (%s): %s\n", 
               wallet_idx, wallet->name, address);

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

                            if (!json_object_object_get_ex(token_entry, "coins", &coins_obj)) {
                                continue;
                            }

                            if (!json_object_object_get_ex(token_entry, "token", &token_info_obj)) {
                                continue;
                            }

                            json_object *ticker_obj = nullptr;
                            if (json_object_object_get_ex(token_info_obj, "ticker", &ticker_obj)) {
                                const char *ticker = json_object_get_string(ticker_obj);
                                const char *coins = json_object_get_string(coins_obj);

                                state.all_wallet_balances[wallet_idx][ticker] = coins;
                                printf("[Wallet] Wallet %d - %s: %s\n", wallet_idx, ticker, coins);
                            }
                        }
                    }
                }
            }

            if (response) {
                cellframe_rpc_response_free(response);
            }
        }
    }

    // Set token_balances for the current wallet
    if (state.current_wallet_index >= 0 && state.all_wallet_balances.count(state.current_wallet_index)) {
        state.token_balances = state.all_wallet_balances[state.current_wallet_index];
    }

    printf("[Wallet] Preload complete - cached balances for %zu wallet(s)\n", 
           state.all_wallet_balances.size());
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

    // Load wallet on first render (or if preload task is still running, wait for it)
    if (!state.wallet_loaded && !state.wallet_loading) {
        // Check if preload is still running
        if (state.wallet_preload_task.isRunning()) {
            // Show loading spinner while preload is happening
            ImVec2 available_size = ImGui::GetContentRegionAvail();
            ImVec2 center = ImVec2(available_size.x * 0.5f, available_size.y * 0.5f);
            ImGui::SetCursorPos(ImVec2(center.x - 50, center.y - 50));
            ThemedSpinner("##wallet_preloading", 20.0f, 4.0f);
            ImGui::SetCursorPos(ImVec2(center.x - 50, center.y));
            ImGui::TextDisabled("Loading wallet...");
            ImGui::EndChild();
            return;
        }
        
        // If preload didn't run or failed, try loading now
        if (!state.wallet_preload_task.isCompleted()) {
            loadWallet(state);
        }
    }
    
    // Auto-refresh balances every 30 seconds (for all wallets)
    static double last_refresh_time = 0.0;
    double current_time = ImGui::GetTime();
    if (state.wallet_loaded && (current_time - last_refresh_time) >= 30.0) {
        preloadAllBalances(state);  // Refresh all wallets to keep cache up-to-date
        last_refresh_time = current_time;
    }

    // Show error if wallet failed to load
    if (!state.wallet_error.empty()) {
        ImVec2 available_size = ImGui::GetContentRegionAvail();
        ImVec2 center = ImVec2(available_size.x * 0.5f, available_size.y * 0.5f);

        // Large wallet icon
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        ImGui::SetWindowFontScale(4.0f);  // Make icon 4x larger
        
        // Calculate icon size and center it properly
        ImVec2 icon_size = ImGui::CalcTextSize(ICON_FA_WALLET);
        ImGui::SetCursorPos(ImVec2(center.x - icon_size.x * 0.5f, center.y - 150));
        ImGui::Text(ICON_FA_WALLET);
        
        ImGui::SetWindowFontScale(1.0f);
        ImGui::PopStyleColor();

        // Error message
        const char* error_text = "No wallets found";
        ImVec2 text_size = ImGui::CalcTextSize(error_text);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y - 70));
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(), "%s", error_text);

        // Description
        const char* desc_text = "Create one with cellframe-node-cli or browse for existing wallet files";
        ImVec2 desc_size = ImGui::CalcTextSize(desc_text);
        ImGui::SetCursorPos(ImVec2(center.x - desc_size.x * 0.5f, center.y - 10));
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", desc_text);

        // Browse button
        ImGui::SetCursorPos(ImVec2(center.x - 100, center.y + 30));
        
        // Show different button text based on file browser task state
        const char* button_text = ICON_FA_FOLDER_OPEN " Browse Wallet Files";
        if (state.file_browser_task.isRunning()) {
            button_text = ICON_FA_SPINNER " Opening File Browser...";
        }
        
        bool button_disabled = state.file_browser_task.isRunning();
        if (button_disabled) {
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.6f);
        }
        
        if (ThemedButton(button_text, ImVec2(200, 40)) && !button_disabled) {
            // Start async file browser
            state.file_browser_task.start([](AsyncTask* task) {
                FileBrowser::openFileDialogAsync(task, "Select Wallet File", FileBrowser::FILE_TYPE_WALLETS);
            });
        }
        
        if (button_disabled) {
            ImGui::PopStyleVar();
        }
        
        // Check if file browser task completed
        if (state.file_browser_task.isCompleted() && !state.file_browser_task.isRunning()) {
            std::string walletPath = FileBrowser::getAsyncResult();
            
            if (!walletPath.empty()) {
                // TODO: Load the selected wallet file
                // For now, just show the path in the error message
                state.wallet_error = "Selected wallet: " + walletPath + " (Loading not yet implemented)";
                printf("[Wallet] Selected wallet file: %s\n", walletPath.c_str());
            } else {
                // Check for file browser error
                const std::string& error = FileBrowser::getLastError();
                if (!error.empty()) {
                    state.wallet_error = "File browser error: " + error;
                } else {
                    // User cancelled, don't show error
                    printf("[Wallet] File selection cancelled\n");
                }
            }
            
            // Task will auto-reset on next start() call
        }

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
        // Show collapsing header with tree nodes for multiple wallets
        if (ImGui::CollapsingHeader("Wallets", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Spacing();  // Top padding
            
            // Add padding to selectable items
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 8.0f));
            
            for (int i = 0; i < wallets->count; i++) {
                bool is_selected = (state.current_wallet_index == i);
                
                // Add indentation (increased from 10.0f to 20.0f)
                ImGui::Indent(20.0f);
                
                // Use Selectable instead of TreeNode for better clickability
                if (ImGui::Selectable(wallets->wallets[i].name, is_selected, 0, ImVec2(0, 0))) {
                    state.current_wallet_index = i;
                    state.wallet_name = std::string(wallets->wallets[i].name);
                    
                    // Use cached balances (should always be available from preload)
                    if (state.all_wallet_balances.count(i)) {
                        state.token_balances = state.all_wallet_balances[i];
                        printf("[Wallet] Switched to wallet %d (using cached balances)\n", i);
                    }
                    
                    static double last_refresh_time = 0.0;
                    last_refresh_time = ImGui::GetTime();  // Reset timer on manual wallet change
                }
                
                ImGui::Unindent(20.0f);
                
                // Add small spacing between wallets
                ImGui::Spacing();
            }
            
            ImGui::PopStyleVar();  // Pop FramePadding
            ImGui::Spacing();  // Bottom padding
        }
    } else {
        // Single wallet, just show name
        ImGui::Text(ICON_FA_WALLET " %s", state.wallet_name.c_str());
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Token balance display (borderless table)
    const char* tokens[] = {"CPUNK", "CELL", "KEL"};

    if (ImGui::BeginTable("##tokens_table", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoPadOuterX)) {
        // Setup columns: token (left), amount (left), button (right)
        ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Amount", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Button", ImGuiTableColumnFlags_WidthFixed, 100.0f);

        for (int i = 0; i < 3; i++) {
            ImGui::TableNextRow();
            
            // Token column (left-aligned, 2x text)
            ImGui::TableNextColumn();
            ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
            ImGui::SetWindowFontScale(2.0f);
            ImGui::Text("%s", tokens[i]);
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopFont();
            
            // Amount column (left-aligned, 2x text)
            ImGui::TableNextColumn();
            auto it = state.token_balances.find(tokens[i]);
            std::string formatted = (it != state.token_balances.end()) ? formatBalance(it->second) : "0.00";
            
            ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
            ImGui::SetWindowFontScale(2.0f);
            if (it != state.token_balances.end()) {
                ImGui::Text("%s", formatted.c_str());
            } else {
                ImGui::TextDisabled("%s", formatted.c_str());
            }
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopFont();
            
            // Button column (right-aligned, normal size)
            ImGui::TableNextColumn();
            
            // Vertically align button with scaled text
            float line_height = ImGui::GetTextLineHeight();
            float scaled_line_height = line_height * 2.0f;
            float btn_height = scaled_line_height * 0.8f;  // Button height matches scaled text better
            float btn_offset = (scaled_line_height - btn_height) * 0.5f;
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + btn_offset);
            
            char btn_id[32];
            snprintf(btn_id, sizeof(btn_id), ICON_FA_PAPER_PLANE " Send##%s", tokens[i]);
            if (ThemedButton(btn_id, ImVec2(-1, btn_height))) {
                state.show_send_dialog = true;
                state.send_status.clear();
            }
        }
        
        ImGui::EndTable();
    }

    ImGui::Spacing();

    // Action buttons (Receive and History only)
    float btn_height = is_mobile ? 50.0f : 45.0f;

    if (is_mobile) {
        // Mobile: Stacked full-width buttons
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
        float btn_width = (available_width - spacing) / 2.0f;

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
