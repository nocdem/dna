#include "app.h"
#include "imgui.h"
#include "modal_helper.h"
#include "ui_helpers.h"
#include "font_awesome.h"
#include "theme_colors.h"
#include "settings_manager.h"
#include "helpers/identity_helpers.h"
#include "screens/register_name_screen.h"
#include "screens/message_wall_screen.h"
#include "screens/profile_editor_screen.h"
#include "screens/settings_screen.h"
#include "screens/wallet_receive_dialog.h"
#include "screens/wallet_send_dialog.h"
#include "screens/wallet_transaction_history_dialog.h"
#include "screens/wallet_screen.h"
#include "screens/add_contact_dialog.h"
#include "screens/contacts_sidebar.h"
#include "screens/chat_screen.h"
#include "screens/layout_manager.h"
#include "screens/identity_selection_screen.h"
#include "helpers/data_loader.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>  // For _mkdir
#include "../win32/dirent.h"
// Undefine Windows status macros that conflict with our enum
#undef STATUS_PENDING
#else
#include <dirent.h>
#endif

// Backend includes
extern "C" {
    #include "../messenger.h"
    #include "../messenger_p2p.h"  // For messenger_p2p_check_offline_messages
    #include "../crypto/bip39/bip39.h"
    #include "../dht/dht_keyserver.h"
    #include "../dht/dht_singleton.h"
    #include "../dht/dna_message_wall.h"  // For message wall functions
    #include "../p2p/p2p_transport.h"  // For P2P transport DHT access
    #include "../crypto/utils/qgp_types.h"  // For qgp_key_load, qgp_key_free
    #include "../crypto/utils/qgp_platform.h"  // For qgp_platform_home_dir
    #include "../database/contacts_db.h"  // For contacts_db_add, contacts_db_exists
    #include "../database/profile_manager.h"  // For profile caching and fetching
    #include "../blockchain/wallet.h"  // For wallet functions
    #include "../blockchain/blockchain_rpc.h"  // For RPC calls
    #include "../blockchain/blockchain_tx_builder_minimal.h"  // Transaction builder
    #include "../blockchain/blockchain_sign_minimal.h"  // Transaction signing
    #include "../blockchain/blockchain_addr.h"  // Address utilities
    #include "../blockchain/blockchain_json_minimal.h"  // JSON conversion
    #include "../blockchain/blockchain_minimal.h"  // TSD types
    #include "../crypto/utils/base58.h"  // Base58 encoding
    #include <time.h>
}

#include <json-c/json.h>  // For JSON parsing

#ifdef _WIN32
// Simple strptime implementation for Windows
static char* strptime(const char* s, const char* format, struct tm* tm) {
    // Simple RFC2822 parser: "Mon, 15 Oct 2024 14:30:00"
    const char* month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char day_name[4], month_name[4];
    int day, year, hour, min, sec;

    int parsed = sscanf(s, "%3s, %d %3s %d %d:%d:%d",
                        day_name, &day, month_name, &year, &hour, &min, &sec);

    if (parsed == 7) {
        tm->tm_mday = day;
        tm->tm_year = year - 1900;
        tm->tm_hour = hour;
        tm->tm_min = min;
        tm->tm_sec = sec;

        // Find month
        for (int i = 0; i < 12; i++) {
            if (strcmp(month_name, month_names[i]) == 0) {
                tm->tm_mon = i;
                break;
            }
        }
        return (char*)s + strlen(s);
    }
    return nullptr;
}
#endif

// Network fee constants
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"
#define NETWORK_FEE_DATOSHI 2000000000000000ULL  // 0.002 CELL

// UTXO structure for transaction building
typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} utxo_t;

// Forward declaration for ApplyTheme (defined in main.cpp)
extern void ApplyTheme(int theme);
extern AppSettings g_app_settings;

// Method implementations will be moved here from app.h
// This file will contain all the inline method bodies

void DNAMessengerApp::render() {
    ImGuiIO& io = ImGui::GetIO();

    // First frame initialization
    if (state.is_first_frame) {
        state.is_first_frame = false;
    }

    // Handle post-login events (new messages, contact sync)
    handlePostLoginEvents();

    // Process pending DHT registration (identity created before DHT was ready)
    processPendingRegistration();

    // Show identity selection on first run (but not during spinner operations)
    if (state.show_identity_selection && !state.show_operation_spinner) {
        IdentitySelectionScreen::render(state);
    } else if (!state.show_operation_spinner) {
        // Main window only shows when identity is selected
        // Detect screen size for responsive layout
        bool is_mobile = io.DisplaySize.x < 600.0f;

        // Main window (fullscreen)
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);

        // Add global padding
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));

        ImGui::Begin("DNA Messenger", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoScrollbar);

        // Mobile: Full-screen views with bottom navigation
        // Desktop: Side-by-side layout
        if (is_mobile) {
            LayoutManager::renderMobileLayout(state);
        } else {
            LayoutManager::renderDesktopLayout(state,
                [this](int contact_idx) { DataLoader::loadMessagesForContact(state, contact_idx); });
        }

        ImGui::End();
        ImGui::PopStyleVar(); // Pop WindowPadding
    }

    // Render operation spinner overlay (must be after all windows/modals)
    renderOperationSpinner();

    // Render all dialogs
    renderDialogs();
}


void DNAMessengerApp::handlePostLoginEvents() {
    // Model E: No continuous polling - offline messages checked once on login
    if (state.identity_loaded) {
        // Reload current conversation if new messages arrived
        if (state.new_messages_received && state.selected_contact >= 0) {
            DataLoader::loadMessagesForContact(state, state.selected_contact);
            state.new_messages_received = false;
        }

        // Reload contacts if DHT sync completed
        if (state.contacts_synced_from_dht) {
            printf("[Contacts] DHT sync completed, reloading contact list...\n");
            DataLoader::reloadContactsFromDatabase(state);
            state.contacts_synced_from_dht = false;
        }
    }
}


void DNAMessengerApp::processPendingRegistration() {
    // Process pending DHT registration (identity created before DHT was ready)
    if (!state.pending_registration_fingerprint.empty()) {
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            printf("[Identity] DHT now ready - processing pending registration for: %s\n",
                   state.pending_registration_name.c_str());

            // Get home directory
            const char* home = qgp_platform_home_dir();
            if (home) {
#ifdef _WIN32
                std::string dna_dir = std::string(home) + "\\.dna";
#else
                std::string dna_dir = std::string(home) + "/.dna";
#endif

                // Load keys from disk
                std::string dsa_path = dna_dir + "/" + state.pending_registration_fingerprint + ".dsa";
                std::string kem_path = dna_dir + "/" + state.pending_registration_fingerprint + ".kem";

                qgp_key_t *sign_key = nullptr;
                qgp_key_t *enc_key = nullptr;

                if (qgp_key_load(dsa_path.c_str(), &sign_key) == 0 && sign_key &&
                    qgp_key_load(kem_path.c_str(), &enc_key) == 0 && enc_key) {

                    // Publish to DHT
                    int ret = dht_keyserver_publish(
                        dht_ctx,
                        state.pending_registration_fingerprint.c_str(),
                        state.pending_registration_name.c_str(),
                        sign_key->public_key,
                        enc_key->public_key,
                        sign_key->private_key
                    );

                    qgp_key_free(sign_key);
                    qgp_key_free(enc_key);

                    if (ret == 0) {
                        printf("[Identity] ✓ Pending registration completed successfully!\n");
                        state.identity_name_cache[state.pending_registration_fingerprint] = state.pending_registration_name;
                    } else {
                        printf("[Identity] ERROR: Pending registration failed\n");
                    }
                } else {
                    printf("[Identity] ERROR: Failed to load keys for pending registration\n");
                    if (sign_key) qgp_key_free(sign_key);
                    if (enc_key) qgp_key_free(enc_key);
                }
            }

            // Clear pending registration (whether success or failure)
            state.pending_registration_fingerprint.clear();
            state.pending_registration_name.clear();
        }
    }
}


void DNAMessengerApp::renderOperationSpinner() {
    // Render operation spinner overlay (for async DHT operations)
    // This must be AFTER all other windows/modals so it's on top
    if (state.show_operation_spinner) {
        ImGuiIO& io = ImGui::GetIO();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);

        // Use themed background
        ImVec4 bg_color = ImGui::GetStyleColorVec4(ImGuiCol_WindowBg);
        bg_color.w = 0.95f; // Slightly transparent
        ImGui::PushStyleColor(ImGuiCol_WindowBg, bg_color);

        ImGui::Begin("##operation_spinner", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoInputs);

        // Center spinner
        float spinner_size = 40.0f;
        ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
        ImGui::SetCursorPos(ImVec2(center.x - spinner_size, center.y - spinner_size * 2));
        ThemedSpinner("##op_spinner", spinner_size, 6.0f);

        // Show latest message from async task
        auto messages = state.dht_publish_task.getMessages();
        if (!messages.empty()) {
            const char* msg = messages.back().c_str();
            ImVec2 text_size = ImGui::CalcTextSize(msg);
            ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_size));
            ImGui::Text("%s", msg);
        } else {
            // Fallback to static message
            ImVec2 text_size = ImGui::CalcTextSize(state.operation_spinner_message);
            ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_size));
            ImGui::Text("%s", state.operation_spinner_message);
        }

        ImGui::End();
        ImGui::PopStyleColor();

        // Check if async task completed
        if (state.dht_publish_task.isCompleted() && !state.dht_publish_task.isRunning()) {
            state.show_operation_spinner = false;
            // Identity selection is already hidden when Create button was clicked
        }
    }
}


void DNAMessengerApp::renderDialogs() {
    // Add Contact dialog
    if (state.show_add_contact_dialog) {
        ImGui::OpenPopup("Add Contact");
        AddContactDialog::render(state, [this]() { DataLoader::reloadContactsFromDatabase(state); });
    }

    // Receive dialog
    WalletReceiveDialog::render(state);

    // Send dialog
    WalletSendDialog::render(state);

    // Transaction History dialog
    WalletTransactionHistoryDialog::render(state);

    // Message Wall dialog
    MessageWallScreen::render(state);

    // Profile Editor dialog
    ProfileEditorScreen::render(state);

    // Register DNA Name dialog
    RegisterNameScreen::render(state);
}



// Static method: Input filter callback for identity name
int DNAMessengerApp::IdentityNameInputFilter(ImGuiInputTextCallbackData* data) {
    if (data->EventChar < 256) {
        char c = (char)data->EventChar;
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_') {
            return 0; // Accept
        }
    }
    return 1; // Reject
}
