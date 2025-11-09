#ifndef APP_STATE_H
#define APP_STATE_H

#include "data_types.h"
#include "imgui.h"
#include <string>
#include <vector>
#include <map>

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
    RESTORE_STEP_NAME,
    RESTORE_STEP_SEED
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

    // Loading screen state
    bool is_first_frame;
    float loading_start_time;

    // Emoji picker state
    bool show_emoji_picker;
    ImVec2 emoji_picker_pos;

    // Data
    std::vector<Contact> contacts;
    std::map<int, std::vector<Message>> contact_messages;
    char message_input[16384]; // 16KB for long messages

    // Mock data loading functions
    void scanIdentities();
    void loadIdentity(const std::string& identity);
};

#endif // APP_STATE_H
