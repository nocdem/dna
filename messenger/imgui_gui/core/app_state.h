#ifndef APP_STATE_H
#define APP_STATE_H

#include "data_types.h"
#include "imgui.h"
#include "../helpers/async_helpers.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>

// View enumeration
enum View {
    VIEW_CONTACTS,
    VIEW_CHAT,
    VIEW_WALLET,
    VIEW_SETTINGS
};

// Identity creation wizard steps
enum CreateIdentityStep {
    STEP_NAME,
    STEP_SEED_PHRASE,
    STEP_CREATING
};

// Identity restore wizard steps
enum RestoreIdentityStep {
    RESTORE_STEP_SEED  // Single step: just seed phrase input (username not required)
};

// Centralized application state
class AppState {
public:
    AppState();

    // View state
    View current_view;
    int selected_contact;
    int prev_selected_contact;
    bool should_focus_input;
    int input_cursor_pos;
    bool show_wallet;

    // Identity management state
    bool show_identity_selection;
    bool identity_loaded;
    bool identities_scanned;  // Track if we've scanned at least once
    int selected_identity_idx;
    CreateIdentityStep create_identity_step;
    RestoreIdentityStep restore_identity_step;
    char generated_mnemonic[512];
    bool seed_confirmed;
    bool seed_copied;
    float seed_copied_timer;
    char new_identity_name[128];
    std::vector<std::string> identities;
    std::string current_identity;
    
    // DHT name cache (fingerprint -> display name)
    std::map<std::string, std::string> identity_name_cache;

    // Pending DHT registration (when identity created before DHT ready)
    std::string pending_registration_fingerprint;
    std::string pending_registration_name;

    // Loading screen state
    bool is_first_frame;
    float loading_start_time;
    
    // Background operation spinner
    bool show_operation_spinner;
    char operation_spinner_message[256];

    // Emoji picker state
    bool show_emoji_picker;
    ImVec2 emoji_picker_pos;

    // Add Contact dialog state
    bool show_add_contact_dialog;
    char add_contact_input[256];  // Input buffer for fingerprint/name
    bool add_contact_lookup_in_progress;
    std::string add_contact_found_name;
    std::string add_contact_found_fingerprint;
    std::string add_contact_error_message;
    float add_contact_last_input_time;  // Track when user last typed
    std::string add_contact_last_searched_input;  // Track what we last searched

    // Message and sync state (Model E: no continuous polling, check once on login)
    bool new_messages_received;  // Flag to reload current conversation
    bool contacts_synced_from_dht;  // Flag to indicate DHT sync completed
    bool should_scroll_to_bottom;  // Flag to force scroll after sending message
    int scroll_to_bottom_frames;  // Frames to wait before scrolling (0 = don't scroll)

    // Data
    std::vector<Contact> contacts;
    std::map<int, std::vector<Message>> contact_messages;
    mutable std::mutex messages_mutex;  // Protect contact_messages from concurrent access
    char message_input[16384]; // 16KB for long messages

    // Wallet state
    bool wallet_loaded;
    bool wallet_loading;
    std::string wallet_name;
    std::map<std::string, std::string> token_balances;  // ticker -> balance (CPUNK, CELL, KEL)
    std::string wallet_error;
    void *wallet_list;  // wallet_list_t* (opaque pointer)
    int current_wallet_index;

    // Receive dialog state
    bool show_receive_dialog;
    char wallet_address[256];  // Current wallet address for selected network
    bool address_copied;
    float address_copied_timer;

    // Send dialog state
    bool show_send_dialog;
    char send_recipient[256];
    char send_amount[32];
    char send_fee[32];
    std::string send_status;

    // Transaction History dialog state
    bool show_transaction_history;
    struct Transaction {
        std::string direction;  // "sent" or "received"
        std::string amount;     // Formatted amount
        std::string token;      // CPUNK, CELL, KEL, etc.
        std::string address;    // Other party's address (shortened)
        std::string time;       // Formatted timestamp
        std::string status;     // ACCEPTED, DECLINED, etc.
        bool is_declined;       // For red coloring
    };
    std::vector<Transaction> transaction_list;
    bool transaction_history_loading;
    std::string transaction_history_error;

    // Message Wall dialog state
    bool show_message_wall;
    std::string wall_fingerprint;
    std::string wall_display_name;
    bool wall_is_own;
    char wall_message_input[1025];  // 1024 + null terminator
    struct WallMessage {
        uint64_t timestamp;
        std::string text;
        bool verified;
    };
    std::vector<WallMessage> wall_messages;
    bool wall_loading;
    std::string wall_status;

    // Profile Editor dialog state
    bool show_profile_editor;

    // Contact Profile Viewer dialog state
    bool show_contact_profile;
    std::string viewed_profile_fingerprint;
    std::string viewed_profile_name;
    char profile_backbone[256];
    char profile_kelvpn[256];
    char profile_subzero[256];
    char profile_millixt[256];
    char profile_testnet[256];
    char profile_btc[256];
    char profile_eth[256];
    char profile_sol[256];
    char profile_ltc[256];
    char profile_doge[256];
    char profile_telegram[256];
    char profile_twitter[256];
    char profile_github[256];
    char profile_discord[256];
    char profile_website[256];
    char profile_pic_cid[256];
    char profile_bio[513];  // 512 + null terminator
    std::string profile_status;
    std::string profile_registered_name;
    bool profile_loading;
    bool profile_cached;  // Track if profile has been loaded once

    // Register DNA Name dialog state
    bool show_register_name;
    char register_name_input[21];  // 20 + null terminator
    std::string register_name_availability;
    bool register_name_available;
    bool register_name_checking;
    std::string register_name_status;
    float register_name_last_input_time;  // Track when user last typed
    std::string register_name_last_checked_input;  // Track last checked input
    AsyncTask register_name_task;  // Async task for name registration

    // Async tasks for DHT operations
    AsyncTask dht_publish_task;
    AsyncTask contact_lookup_task;
    AsyncTask contact_sync_task;
    AsyncTask message_poll_task;
    AsyncTaskQueue message_send_queue;  // Queue for sending multiple messages rapidly
    AsyncTask message_load_task;
    AsyncTask identity_scan_task;

    // Messenger backend context (opaque pointer, defined in messenger.h)
    void *messenger_ctx;

    // Mock data loading functions
    void scanIdentities();
    void loadIdentity(const std::string& identity);
};

#endif // APP_STATE_H
