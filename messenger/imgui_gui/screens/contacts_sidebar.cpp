#include "contacts_sidebar.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../../database/contacts_db.h"
#include "../../messenger.h"
#include "../helpers/data_loader.h"  // Phase 1.4: For contact refresh

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
                // Phase 1.1: Wire to ContactProfileViewer
                state.viewed_profile_fingerprint = state.contacts[i].address;
                state.viewed_profile_name = state.contacts[i].name;
                state.show_contact_profile = true;
                printf("[Context Menu] Opening profile viewer for: %s\n",
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
    
    // Set sidebar background to button color (InputBackground)
    ImVec4 sidebar_bg = (g_app_settings.theme == 0) ? DNATheme::InputBackground() : ClubTheme::InputBackground();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, sidebar_bg);

    ImGui::BeginChild("Sidebar", ImVec2(250, 0), true, ImGuiWindowFlags_NoScrollbar);

    // Show current identity name centered at top
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
        float center_x = (250 - text_width) * 0.5f;
        ImGui::SetCursorPosX(center_x);
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(), "%s", display_name.c_str());
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

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
    ImGui::Separator();
    ImGui::Spacing();
    
    // Edit Profile button - only show if user has registered name
    bool has_registered_name = !state.profile_registered_name.empty() &&
                               state.profile_registered_name != "Loading..." &&
                               state.profile_registered_name != "N/A (DHT not connected)" &&
                               state.profile_registered_name != "Error loading";
    
    if (has_registered_name) {
        if (ThemedButton(ICON_FA_USER " Edit Profile", ImVec2(-1, 40))) {
            state.show_profile_editor = true;
        }
    }

    ImGui::Spacing();

    // Groups and Contacts in a single scrollable child
    // Calculate available height: total sidebar height minus fixed elements at top and bottom
    float add_button_height = 40.0f;
    float num_buttons = 3.0f;
    float spacing = ImGui::GetStyle().ItemSpacing.y;
    float available_height = ImGui::GetContentRegionAvail().y - (add_button_height * num_buttons) - (spacing * num_buttons);

    // Set scrollbar background to match sidebar background
    ImGui::PushStyleColor(ImGuiCol_ScrollbarBg, sidebar_bg);
    ImGui::BeginChild("GroupsAndContactsScroll", ImVec2(0, available_height), false);
    
    // Groups section header with pending invitations badge
    char groups_header[64];
    if (state.pending_invitations.size() > 0) {
        snprintf(groups_header, sizeof(groups_header), "Groups (%zu pending)", state.pending_invitations.size());
    } else {
        snprintf(groups_header, sizeof(groups_header), "Groups");
    }
    ImGui::Text("%s", groups_header);
    ImGui::Spacing();

    // Groups list (if any)
    if (state.groups.size() > 0 || state.pending_invitations.size() > 0) {
        float list_width = ImGui::GetContentRegionAvail().x;

        // Render pending invitations first (with special styling)
        for (size_t i = 0; i < state.pending_invitations.size(); i++) {
            ImGui::PushID(1000 + i); // Offset ID to avoid conflicts

            float item_height = 30;
            ImVec2 cursor_screen_pos = ImGui::GetCursorScreenPos();
            bool clicked = ImGui::InvisibleButton("##invitation", ImVec2(list_width, item_height));

            if (clicked) {
                // Open invitation dialog when clicked
                state.selected_invitation_index = i;
                state.show_group_invitation_dialog = true;
                state.invitation_action_status.clear();
                state.invitation_action_in_progress = false;
                printf("[Groups] Clicked pending invitation: %s\n", state.pending_invitations[i].group_name.c_str());
            }

            // Draw background (highlight pending invitations)
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            ImVec2 rect_min = cursor_screen_pos;
            ImVec2 rect_max = ImVec2(cursor_screen_pos.x + list_width, cursor_screen_pos.y + item_height);

            // Orange/yellow background for pending invitations
            ImU32 bg_color = IM_COL32(255, 165, 0, 100); // Orange with alpha
            draw_list->AddRectFilled(rect_min, rect_max, bg_color);

            // Display: "ICON Group Name (Pending)"
            char display_text[256];
            snprintf(display_text, sizeof(display_text), "%s   %s (Pending)", ICON_FA_ENVELOPE, state.pending_invitations[i].group_name.c_str());

            ImVec2 text_size = ImGui::CalcTextSize(display_text);
            float text_offset_y = (item_height - text_size.y) * 0.5f;
            ImVec2 text_pos = ImVec2(cursor_screen_pos.x + 8, cursor_screen_pos.y + text_offset_y);
            ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            ImU32 text_color = IM_COL32((int)(text_col.x * 255), (int)(text_col.y * 255), (int)(text_col.z * 255), 255);
            draw_list->AddText(text_pos, text_color, display_text);

            ImGui::PopID();
        }

        // Render groups
        for (size_t i = 0; i < state.groups.size(); i++) {
            ImGui::PushID(2000 + i); // Offset ID to avoid conflicts

            float item_height = 30;
            ImVec2 cursor_screen_pos = ImGui::GetCursorScreenPos();
            bool clicked = ImGui::InvisibleButton("##group", ImVec2(list_width, item_height));
            bool hovered = ImGui::IsItemHovered();

            if (clicked) {
                // Select group and show group chat
                state.selected_group = i;
                state.is_viewing_group = true;
                state.selected_contact = -1;  // Deselect contact
                state.current_view = VIEW_CHAT;
                printf("[Groups] Selected group: %s\n", state.groups[i].name.c_str());

                // Load group messages (Phase 6.2)
                messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                if (ctx) {
                    backup_message_t *messages = NULL;
                    int count = 0;

                    if (messenger_load_group_messages(ctx, state.groups[i].group_uuid.c_str(),
                                                     &messages, &count) == 0) {
                        printf("[Groups] Loaded %d messages for group\n", count);

                        // Convert to Message format and store in group_messages
                        std::vector<Message> msg_list;
                        for (int j = 0; j < count; j++) {
                            Message msg;
                            msg.sender = std::string(messages[j].sender);
                            // Check if outgoing by comparing sender with current identity
                            msg.is_outgoing = (strcmp(messages[j].sender, ctx->identity) == 0);
                            msg.status = (MessageStatus)messages[j].status;

                            // Decrypt message content
                            char *plaintext = NULL;
                            size_t plaintext_len = 0;
                            if (messenger_decrypt_message(ctx, messages[j].id, &plaintext, &plaintext_len) == 0) {
                                msg.content = std::string(plaintext, plaintext_len);
                                free(plaintext);
                            } else {
                                msg.content = "[Failed to decrypt]";
                            }

                            // Format timestamp
                            char time_str[64];
                            struct tm *tm_info = localtime(&messages[j].timestamp);
                            strftime(time_str, sizeof(time_str), "%H:%M", tm_info);
                            msg.timestamp = std::string(time_str);

                            msg_list.push_back(msg);
                        }

                        // Store in group_messages map
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            state.group_messages[i] = msg_list;
                        }

                        message_backup_free_messages(messages, count);
                    } else {
                        printf("[Groups] Failed to load messages or no messages found\n");
                        // Initialize empty message list
                        std::lock_guard<std::mutex> lock(state.messages_mutex);
                        state.group_messages[i] = std::vector<Message>();
                    }
                }
            }

            // Draw background
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            ImVec2 rect_min = cursor_screen_pos;
            ImVec2 rect_max = ImVec2(cursor_screen_pos.x + list_width, cursor_screen_pos.y + item_height);

            if (hovered) {
                ImVec4 col = (g_app_settings.theme == 0) ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
                ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
                draw_list->AddRectFilled(rect_min, rect_max, bg_color);
            }

            // Display: "ICON Group Name"
            char display_text[256];
            snprintf(display_text, sizeof(display_text), "%s   %s", ICON_FA_USERS, state.groups[i].name.c_str());

            ImVec2 text_size = ImGui::CalcTextSize(display_text);
            float text_offset_y = (item_height - text_size.y) * 0.5f;
            ImVec2 text_pos = ImVec2(cursor_screen_pos.x + 8, cursor_screen_pos.y + text_offset_y);
            ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            ImU32 text_color = IM_COL32((int)(text_col.x * 255), (int)(text_col.y * 255), (int)(text_col.z * 255), 255);
            draw_list->AddText(text_pos, text_color, display_text);

            ImGui::PopID();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    ImGui::Text("Contacts");
    ImGui::Spacing();

    // Contact list
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
            state.selected_group = -1;  // Deselect group
            state.is_viewing_group = false;
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
                // Phase 1.1: Wire to ContactProfileViewer
                state.viewed_profile_fingerprint = state.contacts[i].address;
                state.viewed_profile_name = state.contacts[i].name;
                state.show_contact_profile = true;
                printf("[Context Menu] Opening profile viewer for: %s\n",
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

    ImGui::EndChild(); // GroupsAndContactsScroll
    ImGui::PopStyleColor(); // ScrollbarBg

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
        // Phase 1.3: Open create group dialog
        state.show_create_group_dialog = true;
        state.create_group_in_progress = false;
        state.create_group_status.clear();
        state.create_group_selected_members.clear();
        memset(state.create_group_name_input, 0, sizeof(state.create_group_name_input));
        ImGui::OpenPopup("Create Group");
    }

    if (ThemedButton(ICON_FA_ARROWS_ROTATE " Refresh", ImVec2(button_width, add_button_height), false)) {
        // Phase 1.4: Trigger DHT contact sync
        messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
        if (ctx) {
            printf("[Contacts] Refreshing contacts from DHT...\n");
            int result = messenger_sync_contacts_from_dht(ctx);
            if (result == 0) {
                printf("[Contacts] ✓ Successfully synced from DHT\n");
                // Reload contacts from database to update UI
                DataLoader::reloadContactsFromDatabase(state);
            } else {
                fprintf(stderr, "[Contacts] ✗ Failed to sync from DHT\n");
            }
        }
    }

    ImGui::EndChild(); // Sidebar

    ImGui::PopStyleColor(2); // Border + ChildBg
}

} // namespace ContactsSidebar
