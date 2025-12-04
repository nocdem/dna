#include "layout_manager.h"
#include "profile_sidebar.h"
#include "contacts_sidebar.h"
#include "chat_screen.h"
#include "wallet_screen.h"
#include "settings_screen.h"
#include "feed_screen.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "imgui.h"

namespace LayoutManager {

void renderMobileLayout(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    float screen_height = io.DisplaySize.y;
    float bottom_nav_height = 60.0f;

    // Track view changes to close emoji picker
    static View prev_view = VIEW_CONTACTS;
    static int prev_contact = -1;

    if (prev_view != state.current_view || prev_contact != state.selected_contact) {
        state.show_emoji_picker = false;
    }
    prev_view = state.current_view;
    prev_contact = state.selected_contact;

    // Content area (full screen minus bottom nav) - use full width
    ImGui::BeginChild("MobileContent", ImVec2(-1, -bottom_nav_height), false, ImGuiWindowFlags_NoScrollbar);

    switch(state.current_view) {
        case VIEW_CONTACTS:
            ContactsSidebar::renderContactsList(state);
            break;
        case VIEW_CHAT:
            ChatScreen::render(state);
            break;
        case VIEW_WALLET:
            WalletScreen::render(state);
            break;
        case VIEW_SETTINGS:
            SettingsScreen::render(state);
            break;
        case VIEW_FEED:
        case VIEW_FEED_CHANNEL:
            FeedScreen::render(state);
            break;
    }

    ImGui::EndChild();

    // Bottom navigation bar
    renderBottomNavBar(state);
}


void renderDesktopLayout(AppState& state,
                         std::function<void(int)> load_messages_callback) {
    // Left column with profile sidebar on top and contacts/groups below
    ImGui::BeginChild("LeftColumn", ImVec2(250, 0), false, ImGuiWindowFlags_NoScrollbar);
    
    // Profile sidebar (top part)
    ProfileSidebar::renderSidebar(state);
    
    // Contacts and groups sidebar (bottom part)
    ContactsSidebar::renderSidebar(state, load_messages_callback);
    
    ImGui::EndChild();

    ImGui::SameLine();

    // Main content area (right)
    ImGui::BeginChild("MainContent", ImVec2(0, 0), true);

    switch(state.current_view) {
        case VIEW_CONTACTS:
        case VIEW_CHAT:
            ChatScreen::render(state);
            break;
        case VIEW_WALLET:
            WalletScreen::render(state);
            break;
        case VIEW_SETTINGS:
            SettingsScreen::render(state);
            break;
        case VIEW_FEED:
        case VIEW_FEED_CHANNEL:
            FeedScreen::render(state);
            break;
    }

    ImGui::EndChild();
}


void renderBottomNavBar(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    float btn_width = io.DisplaySize.x / 5.0f;  // 5 buttons now

    // Show current identity name centered above nav bar
    if (!state.current_identity.empty()) {
        ImGui::Spacing();

        // Get display name from cache, or use shortened fingerprint
        std::string display_name = state.current_identity.substr(0, 10) + "...";
        auto it = state.identity_name_cache.find(state.current_identity);
        if (it != state.identity_name_cache.end()) {
            display_name = it->second;
        }

        // Center the identity name
        float text_width = ImGui::CalcTextSize(display_name.c_str()).x;
        float center_x = (io.DisplaySize.x - text_width) * 0.5f;
        ImGui::SetCursorPosX(center_x);
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", display_name.c_str());

        ImGui::Spacing();
    }

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

    // Contacts/Chats button
    if (ThemedButton(ICON_FA_COMMENTS "\nChats", ImVec2(btn_width, 60), state.current_view == VIEW_CONTACTS || state.current_view == VIEW_CHAT)) {
        state.current_view = VIEW_CONTACTS;
    }

    ImGui::SameLine();

    // Feed button (new!)
    if (ThemedButton(ICON_FA_NEWSPAPER "\nFeed", ImVec2(btn_width, 60), state.current_view == VIEW_FEED || state.current_view == VIEW_FEED_CHANNEL)) {
        state.current_view = VIEW_FEED;
        state.selected_contact = -1;
    }

    ImGui::SameLine();

    // Wallet button
    if (ThemedButton(ICON_FA_WALLET "\nWallet", ImVec2(btn_width, 60), state.current_view == VIEW_WALLET)) {
        state.current_view = VIEW_WALLET;
        state.selected_contact = -1;
    }

    ImGui::SameLine();

    // Settings button
    if (ThemedButton(ICON_FA_GEAR "\nSettings", ImVec2(btn_width, 60), state.current_view == VIEW_SETTINGS)) {
        state.current_view = VIEW_SETTINGS;
        state.selected_contact = -1;
    }

    ImGui::SameLine();

    // Profile button - Phase 1.2: Wire to ProfileEditorScreen
    if (ThemedButton(ICON_FA_USER "\nProfile", ImVec2(btn_width, 60), false)) {
        state.show_profile_editor = true;
    }

    ImGui::PopStyleVar(2);
}

} // namespace LayoutManager
