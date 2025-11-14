#include "identity_selection_screen.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../settings_manager.h"
#include "../modal_helper.h"
#include "../helpers/data_loader.h"
#include "imgui.h"

extern "C" {
#include "../../messenger.h"
#include "../../crypto/bip39/bip39.h"
#include "../../dht/dht_singleton.h"
#include "../../dht/dht_keyserver.h"
#include "../../crypto/utils/qgp_platform.h"
}

#include <cstring>
#include <algorithm>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#endif

// Forward declaration for input filter callback
static int IdentityNameInputFilter(ImGuiInputTextCallbackData* data);

namespace IdentitySelectionScreen {

void render(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    // Open the modal on first render
    static bool first_render = true;
    if (first_render) {
        ImGui::OpenPopup("DNA Messenger - Select Identity");
        first_render = false;
    }

    // Set size before modal
    ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x * 0.9f : 500, is_mobile ? io.DisplaySize.y * 0.9f : 500));

    if (CenteredModal::Begin("DNA Messenger - Select Identity", nullptr, ImGuiWindowFlags_NoResize)) {
        // Add padding at top
        ImGui::Spacing();
        ImGui::Spacing();

    // Title (centered)
    const char* title_text = "Welcome to DNA Messenger";
    float title_width = ImGui::CalcTextSize(title_text).x;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - title_width) * 0.5f);
    ImGui::Text("%s", title_text);
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();

    // Info text (centered)
    const char* info_text = "Select an existing identity or create a new one:";
    float info_width = ImGui::CalcTextSize(info_text).x;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - info_width) * 0.5f);
    ImGui::Text("%s", info_text);
    ImGui::Spacing();

    // Load identities on first render (async)
    if (!state.identities_scanned && !state.identity_scan_task.isRunning()) {
        state.identity_scan_task.start([&state](AsyncTask* task) {
            // Scan for identity files
            DataLoader::scanIdentities(state);

            // Do async DHT reverse lookups for names (all in parallel!)
            dht_context_t *dht_ctx = dht_singleton_get();
            if (dht_ctx) {
                // Track how many lookups we started
                size_t pending_lookups = 0;

                for (const auto& fp : state.identities) {
                    if (fp.length() == 128 && state.identity_name_cache.find(fp) == state.identity_name_cache.end()) {
                        // Initialize with shortened fingerprint (fallback)
                        state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);

                        // Start async DHT reverse lookup
                        pending_lookups++;

                        // Create userdata structure with app pointer and fingerprint
                        struct lookup_ctx {
                            AppState *state_ptr;
                            char fingerprint[129];
                        };

                        lookup_ctx *ctx = new lookup_ctx;
                        ctx->state_ptr = &state;
                        strncpy(ctx->fingerprint, fp.c_str(), 128);
                        ctx->fingerprint[128] = '\0';

                        dht_keyserver_reverse_lookup_async(dht_ctx, fp.c_str(),
                            [](char *registered_name, void *userdata) {
                                lookup_ctx *ctx = (lookup_ctx*)userdata;

                                if (registered_name) {
                                    // Found registered name, update cache
                                    std::string fp_str(ctx->fingerprint);
                                    printf("[Identity] DHT lookup: %s → %s\n", fp_str.substr(0, 16).c_str(), registered_name);
                                    ctx->state_ptr->identity_name_cache[fp_str] = std::string(registered_name);
                                    free(registered_name);
                                }
                                // If NULL, fallback already set above

                                delete ctx;
                            },
                            ctx);
                    }
                }

                printf("[Identity] Started %zu async DHT lookups\n", pending_lookups);
            } else {
                // No DHT available, use shortened fingerprints
                for (const auto& fp : state.identities) {
                    if (fp.length() == 128 && state.identity_name_cache.find(fp) == state.identity_name_cache.end()) {
                        state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                    }
                }
            }

            // Mark as complete immediately (lookups continue in background)
            state.identities_scanned = true;
        });
    }


    // Identity list (reduce reserved space for buttons to prevent scrollbar)
    ImGui::BeginChild("IdentityList", ImVec2(0, is_mobile ? -180 : -140), true);

    // Show spinner while scanning
    if (state.identity_scan_task.isRunning()) {
        float spinner_radius = 30.0f;
        float window_width = ImGui::GetWindowWidth();
        float window_height = ImGui::GetWindowHeight();
        ImVec2 center = ImVec2(window_width * 0.5f, window_height * 0.4f);
        ImGui::SetCursorPos(ImVec2(center.x - spinner_radius, center.y - spinner_radius));
        ThemedSpinner("##identity_scan", spinner_radius, 6.0f);

        const char* loading_text = "Loading identities...";
        ImVec2 text_size = ImGui::CalcTextSize(loading_text);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_radius + 20));
        ImGui::Text("%s", loading_text);
    } else if (state.identities.empty()) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "No identities found.");
        ImGui::TextWrapped("Create a new identity to get started.");
    } else {
        for (size_t i = 0; i < state.identities.size(); i++) {
            ImGui::PushID(i);
            bool selected = (state.selected_identity_idx == (int)i);

            float item_height = is_mobile ? 50 : 35;
            ImVec2 text_size = ImGui::CalcTextSize(state.identities[i].c_str());
            float text_offset_y = (item_height - text_size.y) * 0.5f;

            // Custom color handling for hover and selection
            ImVec4 text_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            ImVec4 bg_color = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();

            ImVec2 pos = ImGui::GetCursorScreenPos();
            ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, item_height);

            // Check hover
            bool hovered = ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x + size.x, pos.y + size.y));

            if (hovered) {
                bg_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                text_color = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();
            }

            if (selected) {
                bg_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                text_color = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();
            }

            // Draw background
            if (selected || hovered) {
                ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(bg_color));
            }

            // Draw text centered vertically with left padding
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + text_offset_y);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, text_color);

            // Get display name (use cache to avoid blocking DHT lookups)
            std::string fingerprint = state.identities[i];
            std::string display_name;

            // Check cache first
            auto cached = state.identity_name_cache.find(fingerprint);
            if (cached != state.identity_name_cache.end()) {
                // Use cached name
                display_name = cached->second;
            } else if (fingerprint.length() == 128) {
                // Not in cache and looks like a fingerprint - show shortened version for now
                // DHT lookup will happen async later
                display_name = fingerprint.substr(0, 10) + "..." + fingerprint.substr(fingerprint.length() - 10);
            } else {
                // Short name (legacy), use as-is
                display_name = fingerprint;
            }

            ImGui::Text("%s", display_name.c_str());
            ImGui::PopStyleColor();

            // Move cursor back and render invisible button for click detection
            ImGui::SetCursorScreenPos(pos);
            if (ImGui::InvisibleButton(state.identities[i].c_str(), size)) {
                if (state.selected_identity_idx == (int)i) {
                    state.selected_identity_idx = -1;
                } else {
                    state.selected_identity_idx = i;
                }
            }

            ImGui::PopID();
        }
    }

    ImGui::EndChild();

    ImGui::Spacing();

    // Buttons
    float btn_height = is_mobile ? 50.0f : 40.0f;

    // Select button (only if identity selected)
    ImGui::BeginDisabled(state.selected_identity_idx < 0);
    if (ButtonDark(ICON_FA_USER " Select Identity", ImVec2(-1, btn_height))) {
        if (state.selected_identity_idx >= 0 && state.selected_identity_idx < (int)state.identities.size()) {
            // Close identity selection modal immediately
            ImGui::CloseCurrentPopup();
            state.show_identity_selection = false;

            // Show spinner overlay with "Connecting..." message
            state.show_operation_spinner = true;
            snprintf(state.operation_spinner_message, sizeof(state.operation_spinner_message),
                     "Connecting...");

            state.current_identity = state.identities[state.selected_identity_idx];

            // Load identity asynchronously
            state.dht_publish_task.start([&state](AsyncTask* task) {
                task->addMessage("Loading identity...");
                std::this_thread::sleep_for(std::chrono::milliseconds(300));

                task->addMessage("Connecting...");
                DataLoader::loadIdentity(state, state.current_identity, [&state](int i) { DataLoader::loadMessagesForContact(state, i); });

                task->addMessage("✓ Connected successfully!");
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            });
        }
    }
    ImGui::EndDisabled();

    // Create new button
    if (ButtonDark(ICON_FA_CIRCLE_PLUS " Create New Identity", ImVec2(-1, btn_height))) {
        // Generate mnemonic immediately (skip name step)
        if (bip39_generate_mnemonic(24, state.generated_mnemonic, sizeof(state.generated_mnemonic)) == 0) {
            state.create_identity_step = STEP_SEED_PHRASE;
            state.seed_confirmed = false;
            state.seed_copied = false;
            ImGui::OpenPopup("Create New Identity");
        } else {
            printf("[Identity] ERROR: Failed to generate mnemonic\n");
        }
    }

    // Restore from seed button
    if (ButtonDark(ICON_FA_DOWNLOAD " Restore from Seed", ImVec2(-1, btn_height))) {
        state.restore_identity_step = RESTORE_STEP_SEED;
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::OpenPopup("Restore from Seed");
    }

    // Restore from seed popup - single step (just seed phrase, username not required)
    if (CenteredModal::Begin("Restore from Seed")) {
        renderRestoreStep2_Seed(state);
        CenteredModal::End();
    }

        // Create identity popup - show seed phrase (name step removed)
        if (CenteredModal::Begin("Create New Identity")) {
            if (state.create_identity_step == STEP_SEED_PHRASE) {
                renderCreateIdentityStep2(state);
            }
            // STEP_CREATING is handled by spinner overlay, no modal content needed

            CenteredModal::End();
        }

        CenteredModal::End(); // End identity selection modal
    }
}




void renderCreateIdentityStep1(AppState& state) {
    // Step 1: Enter identity name
    ImGui::Text("Step 1: Choose Your Identity Name");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextWrapped("Your identity name is your username in DNA Messenger.");
    ImGui::TextWrapped("Requirements: 3-20 characters, letters/numbers/underscore only");
    ImGui::Spacing();

    // Auto-focus input when step 1 is active
    if (state.create_identity_step == STEP_NAME && strlen(state.new_identity_name) == 0) {
        ImGui::SetKeyboardFocusHere();
    }

    // Style input like chat message input (recipient bubble color)
    ImVec4 input_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)  // DNA: slightly lighter than bg
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f); // Club: slightly lighter
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));

    bool enter_pressed = ImGui::InputText("##IdentityName", state.new_identity_name, sizeof(state.new_identity_name),
                    ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_EnterReturnsTrue, IdentityNameInputFilter);

    ImGui::PopStyleColor(2);

    // Validate identity name
    size_t name_len = strlen(state.new_identity_name);
    bool name_valid = true;
    std::string error_msg;

    if (name_len > 0) {
        // First check for invalid characters (highest priority)
        char invalid_char = '\0';
        for (size_t i = 0; i < name_len; i++) {
            char c = state.new_identity_name[i];
            if (!((c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '_')) {
                name_valid = false;
                invalid_char = c;
                char buf[64];
                snprintf(buf, sizeof(buf), "Invalid character \"%c\"", c);
                error_msg = buf;
                break;
            }
        }

        // Then check length only if characters are valid
        if (name_valid) {
            if (name_len < 3) {
                name_valid = false;
                error_msg = "Too short (minimum 3 characters)";
            } else if (name_len > 20) {
                name_valid = false;
                error_msg = "Too long (maximum 20 characters)";
            }
        }
    } else {
        name_valid = false;
    }

    // Show validation feedback
    if (name_len > 0 && !name_valid) {
        ImVec4 error_color = g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning();
        ImGui::PushStyleColor(ImGuiCol_Text, error_color);
        ImGui::TextWrapped("✗ %s", error_msg.c_str());
        ImGui::PopStyleColor();
    } else if (name_len > 0 && name_valid) {
        ImVec4 success_color = g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess();
        ImGui::PushStyleColor(ImGuiCol_Text, success_color);
        ImGui::Text("✓ Valid identity name");
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Spacing();

    // Center buttons
    float button_width = 120.0f;
    float spacing = 10.0f;
    float total_width = button_width * 2 + spacing;
    float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;

    if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);

    ImGui::BeginDisabled(!name_valid || name_len == 0);
    if (ButtonDark("Next", ImVec2(button_width, 40)) || (enter_pressed && name_valid && name_len > 0)) {
        // Generate real BIP39 24-word seed phrase
        char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
        if (bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic)) != 0) {
            printf("[Identity] ERROR: Failed to generate BIP39 mnemonic\n");
            snprintf(state.generated_mnemonic, sizeof(state.generated_mnemonic), "ERROR: Failed to generate seed");
        } else {
            snprintf(state.generated_mnemonic, sizeof(state.generated_mnemonic), "%s", mnemonic);
            printf("[Identity] Generated 24-word BIP39 seed phrase\n");
            printf("[Identity] SEED PHRASE (copy from here if clipboard fails):\n%s\n", mnemonic);
        }
        state.create_identity_step = STEP_SEED_PHRASE;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
        // Reset wizard state and go back to identity selection
        state.create_identity_step = STEP_NAME;
        state.seed_confirmed = false;
        state.seed_copied = false;
        memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::CloseCurrentPopup();
    }
}


void renderCreateIdentityStep2(AppState& state) {
    // Display and confirm seed phrase
    ImGui::Text("Your Recovery Seed Phrase");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImVec4 warning_color = g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning();
    ImGui::PushStyleColor(ImGuiCol_Text, warning_color);
    ImGui::TextWrapped("IMPORTANT: Write down these 24 words in order!");
    ImGui::TextWrapped("This is the ONLY way to recover your identity.");
    ImGui::PopStyleColor();
    ImGui::Spacing();



    // Copy button - full width
    if (ButtonDark(ICON_FA_COPY " Copy All Words", ImVec2(-1, 40))) {
        ImGui::SetClipboardText(state.generated_mnemonic);
        state.seed_copied = true;
        state.seed_copied_timer = 3.0f; // Show message for 3 seconds

        // Fallback: Also print to console for manual copying (Wayland/clipboard issues)
        printf("\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  SEED PHRASE (24 words) - SELECT AND COPY FROM TERMINAL:\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("%s\n", state.generated_mnemonic);
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("\n");
    }

    ImGui::Spacing();

    // Display seed phrase in a bordered box with proper alignment
    ImGui::BeginChild("SeedPhraseDisplay", ImVec2(0, 250), true, ImGuiWindowFlags_NoScrollbar);

    // Split mnemonic into words
    char* mnemonic_copy = strdup(state.generated_mnemonic);
    char* words[24];
    int word_count = 0;
    char* token = strtok(mnemonic_copy, " ");
    while (token != nullptr && word_count < 24) {
        words[word_count++] = token;
        token = strtok(nullptr, " ");
    }

    // Display in 2 columns of 12 words each for better readability
    ImGui::Columns(2, nullptr, false);

    for (int i = 0; i < word_count; i++) {
        // Format: " 1. word      "
        char label[32];
        snprintf(label, sizeof(label), "%2d. %-14s", i + 1, words[i]);
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "%s", label);

        // Switch to second column after 12 words
        if (i == 11) {
            ImGui::NextColumn();
        }
    }

    ImGui::Columns(1);

    free(mnemonic_copy);

    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::Checkbox("I have written down my 24-word seed phrase securely", &state.seed_confirmed);
    ImGui::Spacing();

    // Show success message if recently copied (centered above buttons)
    if (state.seed_copied && state.seed_copied_timer > 0.0f) {
        const char* msg = "✓ Words copied to clipboard!";
        ImVec2 text_size = ImGui::CalcTextSize(msg);
        float center_offset = (ImGui::GetContentRegionAvail().x - text_size.x) * 0.5f;
        if (center_offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + center_offset);

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f)); // Green
        ImGui::Text("%s", msg);
        ImGui::PopStyleColor();
        state.seed_copied_timer -= ImGui::GetIO().DeltaTime;
        if (state.seed_copied_timer <= 0.0f) {
            state.seed_copied = false;
        }
    }

    ImGui::Spacing();

    // Center buttons
    float button_width = 120.0f;
    float spacing = 10.0f;
    float total_width = button_width * 2 + spacing;
    float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;

    if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);

    if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
        // Reset wizard state and go back to identity selection
        state.seed_confirmed = false;
        state.seed_copied = false;
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();

    ImGui::BeginDisabled(!state.seed_confirmed);
    if (ButtonDark("Create", ImVec2(button_width, 40))) {
        // Close all modals immediately
        ImGui::CloseCurrentPopup();
        state.show_identity_selection = false; // Hide identity list modal immediately

        // Show spinner overlay
        state.show_operation_spinner = true;
        snprintf(state.operation_spinner_message, sizeof(state.operation_spinner_message),
                 "Creating identity...");

        // Copy mnemonic to heap for async task (no name needed)
        std::string mnemonic_copy = std::string(state.generated_mnemonic);

        // Start async identity creation task
        state.dht_publish_task.start([&state, mnemonic_copy](AsyncTask* task) {
            task->addMessage("Generating cryptographic keys...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Saving keys...");
            createIdentityWithSeed(state, mnemonic_copy.c_str());

            task->addMessage("Initializing messenger context...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Connecting...");
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            task->addMessage("✓ Identity created successfully!");
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        });
    }
    ImGui::EndDisabled();
}


void renderCreateIdentityStep3(AppState& state) {
    // Step 3: This step is now handled by the spinner overlay
    // The modal will close and spinner will show until creation completes
    // This function should never actually render since we trigger async task immediately
}


void createIdentityWithSeed(AppState& state, const char* mnemonic) {
    printf("[Identity] Creating identity (fingerprint-only, no name registration)\n");

    // Derive cryptographic seeds from BIP39 mnemonic
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(mnemonic, "", signing_seed, encryption_seed) != 0) {
        printf("[Identity] ERROR: Failed to derive seeds from mnemonic\n");
        return;
    }

    printf("[Identity] Derived seeds from mnemonic\n");

    // Ensure ~/.dna directory exists
    const char* home = qgp_platform_home_dir();
    if (!home) {
        printf("[Identity] ERROR: Failed to get home directory\n");
        return;
    }

#ifdef _WIN32
    std::string dna_dir = std::string(home) + "\\.dna";
#else
    std::string dna_dir = std::string(home) + "/.dna";
#endif

#ifdef _WIN32
    mkdir(dna_dir.c_str());
#else
    mkdir(dna_dir.c_str(), 0700);
#endif

    // Create temporary messenger context for key generation
    messenger_context_t *ctx = messenger_init("temp");
    if (!ctx) {
        printf("[Identity] ERROR: Failed to initialize messenger context\n");
        return;
    }

    // Generate keys from seeds (returns fingerprint)
    char fingerprint[129];
    int result = messenger_generate_keys_from_seeds(ctx, signing_seed, encryption_seed, fingerprint);

    // Securely wipe seeds from memory
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));

    if (result != 0) {
        printf("[Identity] ERROR: Failed to generate keys\n");
        messenger_free(ctx);
        return;
    }

    printf("[Identity] Generated keys with fingerprint: %.20s...\n", fingerprint);
    printf("[Identity] ✓ Identity created successfully (no name registered)\n");
    printf("[Identity] TIP: You can register a human-readable name later in Settings\n");

    // Identity created successfully
    state.identities.push_back(fingerprint);
    state.current_identity = fingerprint;
    state.identity_loaded = true;
    // DON'T set show_identity_selection here - it's set in render() when task completes

    // Load contacts for the new identity
    DataLoader::loadIdentity(state, fingerprint, [&state](int i) { DataLoader::loadMessagesForContact(state, i); });

    // Reset wizard state
    memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
    memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
    state.seed_confirmed = false;
    // Modal will be closed when async task completes (in render())

    messenger_free(ctx);
    printf("[Identity] Identity created successfully\n");
}


void renderRestoreStep2_Seed(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    ImGui::Text("Restore Your Identity");
    ImGui::Spacing();
    ImGui::Spacing();

    ImGui::TextWrapped("Enter your 24-word seed phrase to restore your identity.");
    ImGui::Spacing();
    ImGui::TextWrapped("Your cryptographic keys will be regenerated from the seed phrase.");
    ImGui::Spacing();
    ImGui::Spacing();

    // Style input
    ImVec4 input_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);

    ImGui::SetNextItemWidth(-1);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    ImGui::InputTextMultiline("##RestoreSeedPhrase", state.generated_mnemonic, sizeof(state.generated_mnemonic),
                             ImVec2(-1, 200), ImGuiInputTextFlags_WordWrap);
    ImGui::PopStyleColor();

    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::TextWrapped("Paste or type your 24-word seed phrase (separated by spaces).");
    ImGui::Spacing();

    // Validate word count
    int word_count = 0;
    if (strlen(state.generated_mnemonic) > 0) {
        char* mnemonic_copy = strdup(state.generated_mnemonic);
        char* token = strtok(mnemonic_copy, " \n\r\t");
        while (token != nullptr) {
            word_count++;
            token = strtok(nullptr, " \n\r\t");
        }
        free(mnemonic_copy);

        if (word_count != 24) {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
                              "Invalid: Found %d words, need exactly 24 words", word_count);
            ImGui::PopTextWrapPos();
        } else {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "✓ Valid: 24 words");
        }
    }

    ImGui::Spacing();

    float button_width = is_mobile ? -1 : 150.0f;

    if (ButtonDark("Cancel", ImVec2(button_width, 40)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        // Reset wizard state and go back to identity selection
        state.restore_identity_step = RESTORE_STEP_SEED;
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::CloseCurrentPopup();
    }

    if (!is_mobile) ImGui::SameLine();

    ImGui::BeginDisabled(word_count != 24);
    if (ButtonDark("Restore", ImVec2(button_width, 40))) {
        // Close all modals immediately
        ImGui::CloseCurrentPopup();
        state.show_identity_selection = false; // Hide identity list modal immediately
        state.restore_identity_step = RESTORE_STEP_SEED; // Reset wizard

        // Show spinner overlay
        state.show_operation_spinner = true;
        snprintf(state.operation_spinner_message, sizeof(state.operation_spinner_message),
                 "Restoring identity...");

        // Copy mnemonic to heap for async task
        std::string mnemonic_copy = std::string(state.generated_mnemonic);

        state.dht_publish_task.start([&state, mnemonic_copy](AsyncTask* task) {
            task->addMessage("Validating seed phrase...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Deriving cryptographic keys...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Regenerating identity from seed...");
            restoreIdentityWithSeed(state, mnemonic_copy.c_str());

            task->addMessage("Initializing messenger context...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Connecting...");
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            task->addMessage("✓ Identity restored successfully!");
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        });
    }
    ImGui::EndDisabled();
}


void restoreIdentityWithSeed(AppState& state, const char* mnemonic) {
    printf("[Identity] Restoring identity from seed phrase\n");

    // Clean up mnemonic: trim, lowercase, normalize spaces
    std::string cleaned_mnemonic = mnemonic;

    // Trim leading/trailing whitespace
    size_t start = cleaned_mnemonic.find_first_not_of(" \n\r\t");
    size_t end = cleaned_mnemonic.find_last_not_of(" \n\r\t");
    if (start == std::string::npos) {
        printf("[Identity] ERROR: Empty mnemonic\n");
        return;
    }
    cleaned_mnemonic = cleaned_mnemonic.substr(start, end - start + 1);

    // Convert to lowercase
    std::transform(cleaned_mnemonic.begin(), cleaned_mnemonic.end(),
                   cleaned_mnemonic.begin(), ::tolower);

    // Normalize multiple spaces/newlines to single spaces
    std::string normalized;
    bool prev_space = false;
    for (char c : cleaned_mnemonic) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            if (!prev_space) {
                normalized += ' ';
                prev_space = true;
            }
        } else {
            normalized += c;
            prev_space = false;
        }
    }

    // Trim trailing space if added
    if (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }

    printf("[Identity] Cleaned mnemonic: '%s'\n", normalized.c_str());
    printf("[Identity] Mnemonic length: %zu bytes\n", normalized.length());

    // Count words for debug
    int word_count = 0;
    std::string temp = normalized;
    size_t pos = 0;
    while ((pos = temp.find(' ')) != std::string::npos) {
        word_count++;
        temp = temp.substr(pos + 1);
    }
    if (!temp.empty()) word_count++; // Last word
    printf("[Identity] Word count: %d\n", word_count);

    // Validate mnemonic using BIP39
    if (!bip39_validate_mnemonic(normalized.c_str())) {
        printf("[Identity] ERROR: Invalid BIP39 mnemonic\n");
        printf("[Identity] Please check that you have exactly 24 valid words\n");
        // TODO: Show error modal to user
        return;
    }

    printf("[Identity] Seed phrase validated\n");

    // Derive seeds from mnemonic (no passphrase)
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(normalized.c_str(), "", signing_seed, encryption_seed) != 0) {
        printf("[Identity] ERROR: Failed to derive seeds from mnemonic\n");
        return;
    }

    printf("[Identity] Derived seeds from mnemonic\n");

    // Create temporary messenger context
    messenger_context_t *ctx = messenger_init("temp");
    if (!ctx) {
        printf("[Identity] ERROR: Failed to initialize messenger context\n");
        // Securely wipe seeds
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return;
    }

    printf("[Identity] Generating keys from seeds...\n");

    // Generate keys from seeds (fingerprint-first, no name required)
    char fingerprint[129];
    int result = messenger_generate_keys_from_seeds(ctx, signing_seed, encryption_seed, fingerprint);

    // Securely wipe seeds from memory
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));

    if (result != 0) {
        printf("[Identity] ERROR: Failed to generate keys from seeds\n");
        messenger_free(ctx);
        return;
    }

    printf("✓ Identity restored successfully!\n");
    printf("✓ Fingerprint: %s\n", fingerprint);
    printf("✓ Keys saved to: ~/.dna/%s.dsa and ~/.dna/%s.kem\n", fingerprint, fingerprint);

    // Try to fetch registered name via DHT reverse lookup
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        printf("[Identity] Looking up registered name from DHT...\n");
        char *registered_name = nullptr;
        int lookup_result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &registered_name);

        if (lookup_result == 0 && registered_name && registered_name[0] != '\0') {
            printf("✓ Found registered name: %s\n", registered_name);
            state.identity_name_cache[fingerprint] = registered_name;
            free(registered_name);
        } else {
            printf("  No registered name found for this identity\n");
            printf("\n");
            printf("TIP: You can register a human-readable name for this identity\n");
            printf("     in Settings → Register Name\n");
            printf("\n");
        }
    }

    // Keys are saved to ~/.dna/<fingerprint>.{dsa,kem}
    // Add to identity list
    state.identities.push_back(fingerprint);
    state.current_identity = fingerprint;
    state.identity_loaded = true;

    // Load identity state (contacts, etc)
    DataLoader::loadIdentity(state, fingerprint, [&state](int i) { DataLoader::loadMessagesForContact(state, i); });

    // Cleanup
    messenger_free(ctx);

    // Reset UI state
    memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));

    printf("[Identity] Identity restore complete\n");
}

} // namespace IdentitySelectionScreen

// Static input filter callback
static int IdentityNameInputFilter(ImGuiInputTextCallbackData* data) {
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
