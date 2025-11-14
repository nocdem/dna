#include "contacts_sidebar.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../../database/contacts_db.h"
#include "../../messenger.h"

#include <cstring>
#include <cstdio>

// External settings variable
extern AppSettings g_app_settings;

namespace ContactsSidebar {

void renderContactsList(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();

    // Get full available width before any child windows
    float full_width = ImGui::GetContentRegionAvail().x;

    // Top bar with title and add button
    ImGui::BeginChild("ContactsHeader", ImVec2(full_width, 60), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);

    ImGui::Text("  DNA Messenger");

    ImGui::SameLine(io.DisplaySize.x - 60);
    if (ThemedButton(ICON_FA_CIRCLE_PLUS, ImVec2(50, 40))) {
        // TODO: Add contact dialog
    }

    ImGui::EndChild();

    // Contact list (large touch targets)
    ImGui::BeginChild("ContactsScrollArea", ImVec2(full_width, 0), false);

    for (size_t i = 0; i < state.contacts.size(); i++) {
        ImGui::PushID(i);

        // Get button width
        float button_width = ImGui::GetContentRegionAvail().x;
        if (i == 0) {
        }

        // Large touch-friendly buttons (80px height)
        bool selected = (int)i == state.selected_contact;
        if (selected) {
            ImVec4 highlight = g_app_settings.theme == 0 ? DNATheme::Border() : ClubTheme::Border();
            ImGui::PushStyleColor(ImGuiCol_Button, highlight);
        }

        if (ThemedButton("##contact", ImVec2(button_width, 80))) {
            state.selected_contact = i;
            state.current_view = VIEW_CHAT;
        }

        // Right-click context menu
        if (ImGui::BeginPopupContextItem("mobile_contact_context_menu")) {
            ImGui::Text("%s", state.contacts[i].name.c_str());
            ImGui::Separator();

            if (ImGui::MenuItem(ICON_FA_BROOM " Clear messages")) {
                {
                    std::lock_guard<std::mutex> lock(state.messages_mutex);
                    state.contact_messages[i].clear();
                }
                printf("[Context Menu] Cleared messages for contact: %s\n",
                       state.contacts[i].name.c_str());
            }

            if (ImGui::MenuItem(ICON_FA_TRASH " Delete contact")) {
                if (contacts_db_remove(state.contacts[i].address.c_str()) == 0) {
                    printf("[Context Menu] Deleted contact: %s\n",
                           state.contacts[i].name.c_str());
                    {
                        std::lock_guard<std::mutex> lock(state.messages_mutex);
                        state.contact_messages.erase(i);
                    }
                    state.contacts.erase(state.contacts.begin() + i);
                    if (state.selected_contact == (int)i) {
                        state.selected_contact = -1;
                        state.current_view = VIEW_CONTACTS;
                    }
                    // Sync deletion to DHT for multi-device support
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        messenger_sync_contacts_to_dht(ctx);
                        printf("[Context Menu] Synced contact deletion to DHT\n");
                    }
                } else {
                    printf("[Context Menu] Failed to delete contact: %s\n",
                           state.contacts[i].name.c_str());
                }
            }

            ImGui::Separator();

            if (ImGui::MenuItem(ICON_FA_CIRCLE_INFO " View details")) {
                printf("[Context Menu] View details for: %s\n",
                       state.contacts[i].name.c_str());
            }

            ImGui::EndPopup();
        }

        if (selected) {
            ImGui::PopStyleColor();
        }

        // Draw contact info on top of button
        ImVec2 button_min = ImGui::GetItemRectMin();
        ImVec2 button_max = ImGui::GetItemRectMax();
        ImDrawList* draw_list = ImGui::GetWindowDrawList();

        // Online indicator (circle)
        ImVec2 circle_center = ImVec2(button_min.x + 30, button_min.y + 40);
        ImU32 status_color = state.contacts[i].is_online ?
            IM_COL32(0, 255, 0, 255) : IM_COL32(128, 128, 128, 255);
        draw_list->AddCircleFilled(circle_center, 8.0f, status_color);

        // Contact name
        ImVec2 text_pos = ImVec2(button_min.x + 50, button_min.y + 20);
        draw_list->AddText(ImGui::GetFont(), 20.0f, text_pos,
            IM_COL32(255, 255, 255, 255), state.contacts[i].name.c_str());

        // Status text
        const char* status = state.contacts[i].is_online ? "Online" : "Offline";
        ImVec2 status_pos = ImVec2(button_min.x + 50, button_min.y + 45);
        draw_list->AddText(ImGui::GetFont(), 14.0f, status_pos,
            IM_COL32(180, 180, 180, 255), status);

        ImGui::PopID();
    }

    ImGui::EndChild();
}


void renderSidebar(AppState& state, std::function<void(int)> load_messages_callback) {
    // Push border color before creating child
    ImVec4 border_col = (g_app_settings.theme == 0) ? DNATheme::Separator() : ClubTheme::Separator();
    ImGui::PushStyleColor(ImGuiCol_Border, border_col);

    ImGui::BeginChild("Sidebar", ImVec2(250, 0), true, ImGuiWindowFlags_NoScrollbar);

    // Navigation buttons (40px each)
    if (ThemedButton(ICON_FA_COMMENTS " Chat", ImVec2(-1, 40), state.current_view == VIEW_CONTACTS || state.current_view == VIEW_CHAT)) {
        state.current_view = VIEW_CONTACTS;
    }
    if (ThemedButton(ICON_FA_WALLET " Wallet", ImVec2(-1, 40), state.current_view == VIEW_WALLET)) {
        state.current_view = VIEW_WALLET;
    }
    if (ThemedButton(ICON_FA_GEAR " Settings", ImVec2(-1, 40), state.current_view == VIEW_SETTINGS)) {
        state.current_view = VIEW_SETTINGS;
    }

    ImGui::Spacing();
    ImGui::Text("Contacts");
    ImGui::Spacing();

    // Contact list - use remaining space minus 3 action buttons
    float add_button_height = 40.0f;
    float num_buttons = 3.0f;
    float spacing = ImGui::GetStyle().ItemSpacing.y;
    float available_height = ImGui::GetContentRegionAvail().y - (add_button_height * num_buttons) - (spacing * num_buttons);

    ImGui::BeginChild("ContactList", ImVec2(0, available_height), false);

    float list_width = ImGui::GetContentRegionAvail().x;
    for (size_t i = 0; i < state.contacts.size(); i++) {
        ImGui::PushID(i);

        float item_height = 30;
        bool selected = (state.selected_contact == (int)i);

        // Use invisible button for interaction
        ImVec2 cursor_screen_pos = ImGui::GetCursorScreenPos();
        bool clicked = ImGui::InvisibleButton("##contact", ImVec2(list_width, item_height));
        bool hovered = ImGui::IsItemHovered();

        if (clicked) {
            state.selected_contact = i;
            state.current_view = VIEW_CHAT;
            // Load messages for this contact from database
            load_messages_callback(i);
        }

        // Right-click context menu
        if (ImGui::BeginPopupContextItem("contact_context_menu")) {
            ImGui::Text("%s", state.contacts[i].name.c_str());
            ImGui::Separator();

            if (ImGui::MenuItem(ICON_FA_BROOM " Clear messages")) {
                // Clear messages for this contact from memory
                {
                    std::lock_guard<std::mutex> lock(state.messages_mutex);
                    state.contact_messages[i].clear();
                }
                printf("[Context Menu] Cleared messages for contact: %s\n",
                       state.contacts[i].name.c_str());
            }

            if (ImGui::MenuItem(ICON_FA_TRASH " Delete contact")) {
                if (contacts_db_remove(state.contacts[i].address.c_str()) == 0) {
                    printf("[Context Menu] Deleted contact: %s\n",
                           state.contacts[i].name.c_str());
                    // Clear messages from memory
                    {
                        std::lock_guard<std::mutex> lock(state.messages_mutex);
                        state.contact_messages.erase(i);
                    }
                    // Remove from contacts list
                    state.contacts.erase(state.contacts.begin() + i);
                    // Deselect if this was selected
                    if (state.selected_contact == (int)i) {
                        state.selected_contact = -1;
                        state.current_view = VIEW_CONTACTS;
                    }
                    // Sync deletion to DHT for multi-device support
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        messenger_sync_contacts_to_dht(ctx);
                        printf("[Context Menu] Synced contact deletion to DHT\n");
                    }
                } else {
                    printf("[Context Menu] Failed to delete contact: %s\n",
                           state.contacts[i].name.c_str());
                }
            }

            ImGui::Separator();

            if (ImGui::MenuItem(ICON_FA_CIRCLE_INFO " View details")) {
                // TODO: Show contact details dialog
                printf("[Context Menu] View details for: %s\n",
                       state.contacts[i].name.c_str());
            }

            ImGui::EndPopup();
        }

        // Draw background
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 rect_min = cursor_screen_pos;
        ImVec2 rect_max = ImVec2(cursor_screen_pos.x + list_width, cursor_screen_pos.y + item_height);

        if (selected) {
            ImVec4 col = (g_app_settings.theme == 0) ? DNATheme::ButtonActive() : ClubTheme::ButtonActive();
            ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
            draw_list->AddRectFilled(rect_min, rect_max, bg_color);
        } else if (hovered) {
            ImVec4 col = (g_app_settings.theme == 0) ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
            ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
            draw_list->AddRectFilled(rect_min, rect_max, bg_color);
        }

        // Format: "ICON Name" with mail icon (theme-colored)
        const char* icon = ICON_FA_ENVELOPE;

        char display_text[256];
        snprintf(display_text, sizeof(display_text), "%s   %s", icon, state.contacts[i].name.c_str());

        // Center text vertically
        ImVec2 text_size = ImGui::CalcTextSize(display_text);
        float text_offset_y = (item_height - text_size.y) * 0.5f;
        ImVec2 text_pos = ImVec2(cursor_screen_pos.x + 8, cursor_screen_pos.y + text_offset_y);
        ImU32 text_color;
        if (selected || hovered) {
            // Use theme background color when selected or hovered
            ImVec4 bg_col = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();
            text_color = IM_COL32((int)(bg_col.x * 255), (int)(bg_col.y * 255), (int)(bg_col.z * 255), 255);
        } else {
            // Normal theme text color
            ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            text_color = IM_COL32((int)(text_col.x * 255), (int)(text_col.y * 255), (int)(text_col.z * 255), 255);
        }
        draw_list->AddText(text_pos, text_color, display_text);

        ImGui::PopID();
    }

    ImGui::EndChild(); // ContactList

    // Action buttons at bottom (40px each to match main buttons)
    float button_width = ImGui::GetContentRegionAvail().x;
    if (ThemedButton(ICON_FA_CIRCLE_PLUS " Add Contact", ImVec2(button_width, add_button_height), false)) {
        state.show_add_contact_dialog = true;
        state.add_contact_lookup_in_progress = false;
        state.add_contact_error_message.clear();
        state.add_contact_found_name.clear();
        state.add_contact_found_fingerprint.clear();
        state.add_contact_last_searched_input.clear();
        memset(state.add_contact_input, 0, sizeof(state.add_contact_input));
        ImGui::OpenPopup("Add Contact");
    }

    if (ThemedButton(ICON_FA_USERS " Create Group", ImVec2(button_width, add_button_height), false)) {
        // TODO: Open create group dialog
    }

    if (ThemedButton(ICON_FA_ARROWS_ROTATE " Refresh", ImVec2(button_width, add_button_height), false)) {
        // TODO: Refresh contact list / sync from DHT
    }

    ImGui::EndChild(); // Sidebar

    ImGui::PopStyleColor(); // Border
}

} // namespace ContactsSidebar
