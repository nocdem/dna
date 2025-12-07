#include "wallet_screen.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../helpers/file_browser.h"
#include "wallet_transaction_history_dialog.h"
#include "../../blockchain/cellframe/cellframe_wallet.h"
#include "../../blockchain/cellframe/cellframe_rpc.h"

#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#include <pwd.h>
#endif

// Global settings instance
extern AppSettings g_app_settings;

namespace WalletScreen {

static const char* get_home_dir() {
#ifdef _WIN32
    return getenv("USERPROFILE");
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    return home;
#endif
}

static void ensure_dna_wallets_dir() {
    const char *home = get_home_dir();
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);
    mkdir(dna_dir, 0755);
    
    char wallets_dir[512];
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/.dna/wallets", home);
    mkdir(wallets_dir, 0755);
}

static int copy_wallet_file(const char *src, const char *dst) {
    FILE *src_file = fopen(src, "rb");
    if (!src_file) {
        return -1;
    }
    
    FILE *dst_file = fopen(dst, "wb");
    if (!dst_file) {
        fclose(src_file);
        return -1;
    }
    
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        if (fwrite(buffer, 1, bytes, dst_file) != bytes) {
            fclose(src_file);
            fclose(dst_file);
            return -1;
        }
    }
    
    fclose(src_file);
    fclose(dst_file);
    return 0;
}

void loadWallet(AppState& state) {
    if (state.wallet_loading) return;  // Already loading

    state.wallet_loading = true;
    state.wallet_error.clear();

    // Load wallet for current identity only
    if (state.current_identity.empty()) {
        state.wallet_error = "No identity selected.";
        state.wallet_loaded = false;
        state.wallet_loading = false;
        return;
    }

    wallet_list_t *identity_wallets = nullptr;
    int ret = wallet_list_for_identity(state.current_identity.c_str(), &identity_wallets);

    if (ret != 0 || !identity_wallets || identity_wallets->count == 0) {
        state.wallet_error = "No wallet found for this identity.";
        state.wallet_loaded = false;
        state.wallet_loading = false;
        if (identity_wallets) wallet_list_free(identity_wallets);
        return;
    }

    // Store wallet list (should be single wallet per identity)
    state.wallet_list = identity_wallets;
    state.current_wallet_index = 0;
    state.wallet_name = std::string(identity_wallets->wallets[0].name);
    state.wallet_loaded = true;
    state.wallet_loading = false;

    printf("[Wallet] Loaded wallet for identity: %s\n", state.current_identity.substr(0, 16).c_str());
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
            // Start async file browser for multiple selection
            state.file_browser_task.start([](AsyncTask* task) {
                FileBrowser::openMultipleFileDialogAsync(task, "Select Wallet Files (multiple selection supported)", FileBrowser::FILE_TYPE_WALLETS);
            });
        }
        
        if (button_disabled) {
            ImGui::PopStyleVar();
        }
        
        // Check if file browser task completed
        if (state.file_browser_task.isCompleted() && !state.file_browser_task.isRunning()) {
            std::vector<std::string> walletPaths = FileBrowser::getAsyncMultipleResults();
            
            if (!walletPaths.empty()) {
                ensure_dna_wallets_dir();
                
                int successful_wallets = 0;
                int failed_wallets = 0;
                std::string last_error;
                
                const char *home = get_home_dir();
                char wallets_dir[512];
                snprintf(wallets_dir, sizeof(wallets_dir), "%s/.dna/wallets", home);
                
                // Process each selected wallet file
                for (const std::string& walletPath : walletPaths) {
                    // Test if the wallet can be loaded
                    cellframe_wallet_t *test_wallet = nullptr;
                    if (wallet_read_cellframe_path(walletPath.c_str(), &test_wallet) == 0 && test_wallet) {
                        // Extract filename
                        const char *filename = strrchr(walletPath.c_str(), '/');
                        if (!filename) {
                            filename = strrchr(walletPath.c_str(), '\\');
                        }
                        filename = filename ? filename + 1 : walletPath.c_str();
                        
                        // Build destination path
                        char dest_path[1024];
                        snprintf(dest_path, sizeof(dest_path), "%s/%s", wallets_dir, filename);
                        
                        // Copy the wallet file
                        if (copy_wallet_file(walletPath.c_str(), dest_path) == 0) {
                            successful_wallets++;
                            printf("[Wallet] Copied wallet to DNA directory: %s\n", filename);
                        } else {
                            failed_wallets++;
                            last_error = "Failed to copy: " + std::string(filename);
                            printf("[Wallet] Failed to copy wallet file: %s\n", walletPath.c_str());
                        }
                        
                        wallet_free(test_wallet);
                    } else {
                        failed_wallets++;
                        last_error = "Failed to load: " + walletPath;
                        printf("[Wallet] Failed to load wallet file: %s\n", walletPath.c_str());
                    }
                }
                
                // Update UI based on results
                if (successful_wallets > 0) {
                    state.wallet_error.clear();
                    
                    // Reload wallets to include the new ones
                    state.wallet_loading = false;
                    loadWallet(state);
                    
                    // Immediately cache balances for all wallets
                    preloadAllBalances(state);
                    
                    // Show success message
                    if (failed_wallets > 0) {
                        state.wallet_error = "Added " + std::to_string(successful_wallets) + " wallet(s), " + 
                                           std::to_string(failed_wallets) + " failed. " + last_error;
                    }
                } else {
                    // All wallets failed
                    state.wallet_error = "Failed to process any of the selected wallet files. " + last_error;
                }
            } else {
                // Check for file browser error
                const std::string& error = FileBrowser::getLastError();
                if (!error.empty()) {
                    state.wallet_error = "File browser error: " + error;
                } else {
                    printf("[Wallet] File selection cancelled\n");
                }
            }
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

    // Single wallet per identity - no selector needed
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
