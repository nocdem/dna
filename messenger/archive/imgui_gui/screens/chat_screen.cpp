#include "chat_screen.h"
#include "../modal_helper.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../texture_manager.h"
#include "imgui.h"
#include <cstring>

// Undefine Windows macros that conflict with MessageStatus enum
#ifdef _WIN32
#undef STATUS_PENDING
#endif

extern "C" {
#include "../../messenger.h"
#include "../../message_backup.h"
#include <json-c/json.h>
}

namespace ChatScreen {

void renderGroupChat(AppState& state, bool is_mobile) {
    const Group& group = state.groups[state.selected_group];

    // Top bar (mobile: with back button)
    float header_height = is_mobile ? 60.0f : 40.0f;
    ImGui::BeginChild("GroupChatHeader", ImVec2(0, header_height), true, ImGuiWindowFlags_NoScrollbar);

    if (is_mobile) {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        if (ThemedButton(ICON_FA_ARROW_LEFT " Back", ImVec2(100, 40))) {
            state.current_view = VIEW_CONTACTS;
            state.selected_group = -1;
            state.is_viewing_group = false;
        }
        ImGui::SameLine();
    }

    // Group icon and name
    const char* group_icon = ICON_FA_USERS;
    ImVec4 icon_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

    // Center text vertically in header
    float text_size_y = ImGui::CalcTextSize(group.name.c_str()).y;
    float text_offset_y = (header_height - text_size_y) * 0.5f;
    ImGui::SetCursorPosY(text_offset_y);

    ImGui::TextColored(icon_color, "%s", group_icon);
    ImGui::SameLine();

    ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
    ImGui::TextColored(text_col, "%s (%d members)", group.name.c_str(), group.member_count);

    ImGui::EndChild();

    // Message area
    float input_height = is_mobile ? 100.0f : 80.0f;
    ImGui::BeginChild("GroupMessageArea", ImVec2(0, -input_height), true);

    // Copy messages with mutex protection (minimal lock time)
    std::vector<Message> messages_copy;
    {
        std::lock_guard<std::mutex> lock(state.messages_mutex);
        messages_copy = state.group_messages[state.selected_group];
    }

    // Render all group messages (matching contact chat styling)
    for (size_t i = 0; i < messages_copy.size(); i++) {
        const auto& msg = messages_copy[i];

        // Calculate bubble width based on current window size
        float available_width = ImGui::GetContentRegionAvail().x;
        float bubble_width = available_width;  // 100% of available width (padding inside bubble prevents overflow)

        // All bubbles aligned left (Telegram-style)

        // Draw bubble background with proper padding (theme-aware)
        ImVec4 base_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

        // Recipient bubble: much lighter (0.12 opacity)
        // Own bubble: normal opacity (0.25)
        ImVec4 bg_color;
        if (msg.is_outgoing) {
            bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
        } else {
            bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
        }

        ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0)); // No border
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f); // Square corners

        char bubble_id[32];
        snprintf(bubble_id, sizeof(bubble_id), "group_bubble%zu", i);

        // Calculate padding and dimensions
        float padding_horizontal = 15.0f;
        float padding_vertical = 12.0f;
        float content_width = bubble_width - (padding_horizontal * 2);

        ImVec2 text_size = ImGui::CalcTextSize(msg.content.c_str(), NULL, false, content_width);

        float bubble_height = text_size.y + (padding_vertical * 2);

        ImGui::BeginChild(bubble_id, ImVec2(bubble_width, bubble_height), false,
            ImGuiWindowFlags_NoScrollbar);

        // Right-click context menu - set compact style BEFORE opening
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.0f, 0.0f)); // No vertical padding
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.0f, 0.0f)); // No vertical spacing

        if (ImGui::BeginPopupContextWindow()) {
            if (ImGui::MenuItem(ICON_FA_COPY " Copy")) {
                ImGui::SetClipboardText(msg.content.c_str());
            }
            ImGui::EndPopup();
        }

        ImGui::PopStyleVar(2);

        // Apply padding
        ImGui::SetCursorPos(ImVec2(padding_horizontal, padding_vertical));

        // Use TextWrapped for better text rendering
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + content_width);
        ImGui::TextWrapped("%s", msg.content.c_str());
        ImGui::PopTextWrapPos();

        // Status indicator (bottom-right corner) for outgoing messages
        if (msg.is_outgoing) {
            const char* status_icon;
            ImVec4 status_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

            switch (msg.status) {
                case STATUS_PENDING:
                    status_icon = ICON_FA_CLOCK;
                    break;
                case STATUS_SENT:
                    status_icon = ICON_FA_CHECK;
                    break;
                case STATUS_FAILED:
                    status_icon = ICON_FA_CIRCLE_EXCLAMATION;
                    break;
            }

            status_color.w = 0.6f; // Subtle opacity for all states
            float icon_size = 12.0f;
            ImVec2 status_pos = ImVec2(content_width - icon_size, bubble_height - padding_vertical - icon_size);

            ImGui::SetCursorPos(status_pos);
            ImGui::PushStyleColor(ImGuiCol_Text, status_color);
            ImGui::Text("%s", status_icon);
            ImGui::PopStyleColor();

            // Add retry hover tooltip and click handler for failed messages
            if (msg.status == STATUS_FAILED) {
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Send failed - click to retry");
                }
                if (ImGui::IsItemClicked()) {
                    // TODO: Add group message retry functionality
                    // retryGroupMessage(state, state.selected_group, i);
                }
            }
        }

        ImGui::EndChild();

        // Get bubble position for arrow (AFTER EndChild)
        ImVec2 bubble_min = ImGui::GetItemRectMin();
        ImVec2 bubble_max = ImGui::GetItemRectMax();

        ImGui::PopStyleVar(1); // ChildRounding
        ImGui::PopStyleColor(2); // ChildBg, Border

        // Draw triangle arrow pointing DOWN from bubble to username
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec4 arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, msg.is_outgoing ? 0.25f : 0.12f);
        ImU32 arrow_col_u32 = IM_COL32(
            (int)(arrow_color.x * 255), (int)(arrow_color.y * 255), 
            (int)(arrow_color.z * 255), (int)(arrow_color.w * 255)
        );

        // Arrow pointing down from left side of bubble
        float arrow_x = bubble_min.x + 20.0f;  // Small offset from left edge
        float arrow_y = bubble_max.y;          // Bottom of bubble
        float arrow_size = 8.0f;

        ImVec2 p1 = ImVec2(arrow_x - arrow_size * 0.5f, arrow_y);
        ImVec2 p2 = ImVec2(arrow_x + arrow_size * 0.5f, arrow_y);
        ImVec2 p3 = ImVec2(arrow_x, arrow_y + arrow_size);

        draw_list->AddTriangleFilled(p1, p2, p3, arrow_col_u32);

        // Username and timestamp (below arrow)
        ImGui::Spacing();
        ImVec4 meta_color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, meta_color);
        const char* sender_label = msg.is_outgoing ? "You" : msg.sender.c_str();
        ImGui::Text("%s • %s", sender_label, msg.timestamp.c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Spacing();
    }

    // Handle scroll logic
    float current_scroll = ImGui::GetScrollY();
    float max_scroll = ImGui::GetScrollMaxY();
    bool is_at_bottom = (current_scroll >= max_scroll - 1.0f);

    bool user_scrolled_up = !is_at_bottom && ImGui::IsWindowFocused();
    if (user_scrolled_up && state.scroll_to_bottom_frames > 0) {
        state.scroll_to_bottom_frames = 0;
    }

    if (state.scroll_to_bottom_frames > 0) {
        state.scroll_to_bottom_frames--;
        if (state.scroll_to_bottom_frames == 0) {
            ImGui::SetScrollY(ImGui::GetScrollMaxY());
        }
    } else if (state.should_scroll_to_bottom) {
        state.scroll_to_bottom_frames = 2;
        state.should_scroll_to_bottom = false;
    }

    ImGui::EndChild();

    // Input area
    ImGui::Spacing();
    ImGui::Spacing();

    ImVec4 recipient_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f);

    ImGui::PushStyleColor(ImGuiCol_FrameBg, recipient_bg);

    if (is_mobile) {
        // Mobile layout
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        bool enter_pressed = ImGui::InputTextMultiline("##GroupMessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(-1, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine);
        ImGui::PopStyleColor();

        // Send button
        if (ThemedButton(ICON_FA_PAPER_PLANE, ImVec2(-1, 40)) || enter_pressed) {
            if (strlen(state.message_input) > 0 && state.selected_group >= 0) {
                messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                if (ctx) {
                    std::string message_copy = std::string(state.message_input);
                    std::string group_uuid = state.groups[state.selected_group].group_uuid;
                    int group_idx = state.selected_group;

                    // Get message index
                    int msg_idx;
                    {
                        std::lock_guard<std::mutex> lock(state.messages_mutex);
                        msg_idx = state.group_messages[group_idx].size();

                        // Optimistic UI update
                        Message pending_msg;
                        pending_msg.sender = "You";
                        pending_msg.content = message_copy;
                        pending_msg.timestamp = "now";
                        pending_msg.is_outgoing = true;
                        pending_msg.status = STATUS_PENDING;
                        state.group_messages[group_idx].push_back(pending_msg);
                    }

                    // Clear input
                    state.message_input[0] = '\0';
                    state.should_focus_input = true;
                    state.should_scroll_to_bottom = true;

                    // Enqueue send task
                    state.message_send_queue.enqueue([&state, ctx, message_copy, group_uuid, group_idx, msg_idx]() {
                        int result = messenger_send_group_message(ctx, group_uuid.c_str(), message_copy.c_str());

                        // Update status
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            if (msg_idx < (int)state.group_messages[group_idx].size()) {
                                state.group_messages[group_idx][msg_idx].status =
                                    (result == 0) ? STATUS_SENT : STATUS_FAILED;
                            }
                        }

                        if (result == 0) {
                            printf("[Group Send] [OK] Message sent to group %s\n", group_uuid.c_str());
                        } else {
                            printf("[Group Send] ERROR: Failed to send to group %s\n", group_uuid.c_str());
                        }
                    }, msg_idx);
                }
            }
        }
    } else {
        // Desktop layout
        float input_width = ImGui::GetContentRegionAvail().x - 70;

        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        bool enter_pressed = ImGui::InputTextMultiline("##GroupMessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(input_width, 40),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine);
        ImGui::PopStyleColor();

        ImGui::SameLine();

        // Send button
        if (ThemedButton(ICON_FA_PAPER_PLANE, ImVec2(60, 40)) || enter_pressed) {
            if (strlen(state.message_input) > 0 && state.selected_group >= 0) {
                messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                if (ctx) {
                    std::string message_copy = std::string(state.message_input);
                    std::string group_uuid = state.groups[state.selected_group].group_uuid;
                    int group_idx = state.selected_group;

                    // Get message index
                    int msg_idx;
                    {
                        std::lock_guard<std::mutex> lock(state.messages_mutex);
                        msg_idx = state.group_messages[group_idx].size();

                        // Optimistic UI update
                        Message pending_msg;
                        pending_msg.sender = "You";
                        pending_msg.content = message_copy;
                        pending_msg.timestamp = "now";
                        pending_msg.is_outgoing = true;
                        pending_msg.status = STATUS_PENDING;
                        state.group_messages[group_idx].push_back(pending_msg);
                    }

                    // Clear input
                    state.message_input[0] = '\0';
                    state.should_focus_input = true;
                    state.should_scroll_to_bottom = true;

                    // Enqueue send task
                    state.message_send_queue.enqueue([&state, ctx, message_copy, group_uuid, group_idx, msg_idx]() {
                        int result = messenger_send_group_message(ctx, group_uuid.c_str(), message_copy.c_str());

                        // Update status
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            if (msg_idx < (int)state.group_messages[group_idx].size()) {
                                state.group_messages[group_idx][msg_idx].status =
                                    (result == 0) ? STATUS_SENT : STATUS_FAILED;
                            }
                        }

                        if (result == 0) {
                            printf("[Group Send] [OK] Message sent to group %s\n", group_uuid.c_str());
                        } else {
                            printf("[Group Send] ERROR: Failed to send to group %s\n", group_uuid.c_str());
                        }
                    }, msg_idx);
                }
            }
        }
    }

    ImGui::PopStyleColor();
}

void retryMessage(AppState& state, int contact_idx, int msg_idx) {
    if (contact_idx < 0 || contact_idx >= (int)state.contacts.size()) {
        printf("[Retry] ERROR: Invalid contact index\n");
        return;
    }

    // Check queue limit before retrying
    if (state.message_send_queue.size() >= 20) {
        printf("[Retry] ERROR: Queue full, cannot retry\n");
        return;
    }

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx) {
        printf("[Retry] ERROR: No messenger context\n");
        return;
    }

    // Validate and copy message data (with mutex protection)
    std::string message_copy;
    std::string recipient;
    {
        std::lock_guard<std::mutex> lock(state.messages_mutex);
        recipient = state.contacts[contact_idx].address;
        std::vector<Message>& messages = state.contact_messages[recipient];

        if (msg_idx < 0 || msg_idx >= (int)messages.size()) {
            printf("[Retry] ERROR: Invalid message index\n");
            return;
        }

        Message& msg = messages[msg_idx];
        if (msg.status != STATUS_FAILED) {
            printf("[Retry] ERROR: Can only retry failed messages\n");
            return;
        }

        // Update status to pending
        msg.status = STATUS_PENDING;

        // Copy data for async task
        message_copy = msg.content;
    }

    printf("[Retry] Retrying message to %s...\n", recipient.c_str());

    // Enqueue retry task (capture fingerprint, not index)
    state.message_send_queue.enqueue([&state, ctx, message_copy, recipient, msg_idx]() {
        const char* recipients[] = { recipient.c_str() };
        int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str(), 0, MESSAGE_TYPE_CHAT);

        // Update status with mutex protection
        {
            std::lock_guard<std::mutex> lock(state.messages_mutex);
            auto& msgs = state.contact_messages[recipient];
            if (msg_idx >= 0 && msg_idx < (int)msgs.size()) {
                msgs[msg_idx].status = (result == 0) ? STATUS_SENT : STATUS_FAILED;
            }
        }

        if (result == 0) {
            printf("[Retry] [OK] Message retry successful to %s\n", recipient.c_str());
        } else {
            printf("[Retry] ERROR: Message retry failed to %s\n", recipient.c_str());
        }
    }, msg_idx);
}

void render(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    // Handle group mode
    if (state.is_viewing_group) {
        if (state.selected_group < 0 || state.selected_group >= (int)state.groups.size()) {
            if (is_mobile) {
                state.current_view = VIEW_CONTACTS;
                return;
            } else {
                ImGui::Text("Select a group to start chatting");
                return;
            }
        }

        // Render group chat UI
        renderGroupChat(state, is_mobile);
        return;
    }

    // Handle contact mode
    if (state.selected_contact < 0 || state.selected_contact >= (int)state.contacts.size()) {
        if (is_mobile) {
            // On mobile, show state.contacts list
            state.current_view = VIEW_CONTACTS;
            return;
        } else {
            ImGui::Text("Select a contact to start chatting");
            return;
        }
    }

    Contact& contact = state.contacts[state.selected_contact];

    // Top bar (mobile: with back button)
    float header_height = is_mobile ? 60.0f : 40.0f;
    ImGui::BeginChild("ChatHeader", ImVec2(0, header_height), true, ImGuiWindowFlags_NoScrollbar);

    if (is_mobile) {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        if (ThemedButton(ICON_FA_ARROW_LEFT " Back", ImVec2(100, 40))) {
            state.current_view = VIEW_CONTACTS;
            state.selected_contact = -1;
        }
        ImGui::SameLine();
    }

    // Style contact name same as in contact list
    // Use mail icon with theme colors
    const char* status_icon = ICON_FA_ENVELOPE;
    ImVec4 icon_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

    // Center text vertically in header
    float text_size_y = ImGui::CalcTextSize(contact.name.c_str()).y;
    float text_offset_y = (header_height - text_size_y) * 0.5f;
    ImGui::SetCursorPosY(text_offset_y);

    ImGui::TextColored(icon_color, "%s", status_icon);
    ImGui::SameLine();

    ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
    ImGui::TextColored(text_col, "%s", contact.name.c_str());

    // Profile and Wall buttons (right side of header)
    ImGui::SameLine();
    float btn_width = is_mobile ? 110.0f : 120.0f;
    float btn_height = is_mobile ? 40.0f : 30.0f;
    float btn_spacing = 5.0f;
    float total_width = (btn_width * 2) + btn_spacing;
    float btn_y_pos = (header_height - btn_height) * 0.5f;

    // Position both buttons at the same Y coordinate
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - total_width - 10);
    ImGui::SetCursorPosY(btn_y_pos);

    // Profile button
    if (ThemedButton(ICON_FA_USER " Profile", ImVec2(btn_width, btn_height))) {
        // Open profile viewer for this contact
        state.viewed_profile_fingerprint = contact.address;  // Use address as fingerprint
        state.viewed_profile_name = contact.name;
        state.show_contact_profile = true;
    }

    // Wall button (ensure same Y position)
    ImGui::SameLine();
    ImGui::SetCursorPosY(btn_y_pos);
    if (ThemedButton(ICON_FA_NEWSPAPER " Wall", ImVec2(btn_width, btn_height))) {
        // Open message wall for this contact
        state.wall_fingerprint = contact.address;  // Use address as fingerprint
        state.wall_display_name = contact.name;
        state.wall_is_own = false;  // Viewing someone else's wall
        state.show_message_wall = true;
    }

    ImGui::EndChild();

    // Message area
    float input_height = is_mobile ? 100.0f : 80.0f;
    ImGui::BeginChild("MessageArea", ImVec2(0, -input_height), true);

    // Show spinner while loading messages for the first time
    if (state.message_load_task.isRunning()) {
        float spinner_radius = 30.0f;
        float window_width = ImGui::GetWindowWidth();
        float window_height = ImGui::GetWindowHeight();
        ImVec2 center = ImVec2(window_width * 0.5f, window_height * 0.4f);
        ImGui::SetCursorPos(ImVec2(center.x - spinner_radius, center.y - spinner_radius));
        ThemedSpinner("##message_load", spinner_radius, 6.0f);

        const char* loading_text = "Loading message history...";
        ImVec2 text_size = ImGui::CalcTextSize(loading_text);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_radius + 20));
        ImGui::Text("%s", loading_text);

        ImGui::EndChild();

        // Input area (disabled while loading)
        ImGui::BeginChild("InputArea", ImVec2(0, 0), true);
        ImGui::EndChild();
        return;
    }

    // Copy messages with mutex protection (minimal lock time)
    std::vector<Message> messages_copy;
    {
        std::lock_guard<std::mutex> lock(state.messages_mutex);
        messages_copy = state.contact_messages[contact.address];
    }

    // Render all messages (no clipper for variable-height items)
    for (size_t i = 0; i < messages_copy.size(); i++) {
        const auto& msg = messages_copy[i];

        // Phase 6.2: Render group invitations with special UI
        if (msg.message_type == MESSAGE_TYPE_GROUP_INVITATION) {
            // Parse JSON to extract invitation details
            json_object *j_msg = json_tokener_parse(msg.content.c_str());
            if (j_msg) {
                json_object *j_uuid = NULL, *j_name = NULL, *j_inviter = NULL, *j_count = NULL;
                json_object_object_get_ex(j_msg, "group_uuid", &j_uuid);
                json_object_object_get_ex(j_msg, "group_name", &j_name);
                json_object_object_get_ex(j_msg, "inviter", &j_inviter);
                json_object_object_get_ex(j_msg, "member_count", &j_count);

                const char *group_uuid = j_uuid ? json_object_get_string(j_uuid) : "unknown";
                const char *group_name = j_name ? json_object_get_string(j_name) : "Unknown Group";
                const char *inviter = j_inviter ? json_object_get_string(j_inviter) : "Unknown";
                int member_count = j_count ? json_object_get_int(j_count) : 0;

                // Blue invitation box
                float available_width = ImGui::GetContentRegionAvail().x;
                ImVec4 invitation_bg = ImVec4(0.2f, 0.4f, 0.8f, 0.3f);  // Blue background
                ImGui::PushStyleColor(ImGuiCol_ChildBg, invitation_bg);
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.2f, 0.4f, 0.8f, 0.6f));
                ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 2.0f);

                char invitation_id[64];
                snprintf(invitation_id, sizeof(invitation_id), "invitation_%zu", i);

                float invitation_height = 120.0f;
                ImGui::BeginChild(invitation_id, ImVec2(available_width, invitation_height), true);

                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);

                // Icon and title
                ImGui::Text(ICON_FA_USERS " Group Invitation");
                ImGui::Spacing();

                // Group details
                ImGui::Text("You've been invited to:");
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                ImGui::Text("  %s", group_name);
                ImGui::PopStyleColor();
                ImGui::Text("From: %s • %d members", msg.sender.c_str(), member_count);

                ImGui::Spacing();

                // Accept/Decline buttons
                ImGui::SetCursorPosX(15.0f);
                if (ImGui::Button(ICON_FA_CHECK " Accept", ImVec2(120, 30))) {
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        messenger_accept_group_invitation(ctx, group_uuid);
                        // Group will appear in groups list on next app restart or manual refresh
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button(ICON_FA_XMARK " Decline", ImVec2(120, 30))) {
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        messenger_reject_group_invitation(ctx, group_uuid);
                    }
                }

                ImGui::EndChild();
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(2);

                json_object_put(j_msg);

                // Timestamp below invitation
                ImGui::Spacing();
                ImVec4 meta_color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Text, meta_color);
                ImGui::Text("%s • %s", msg.sender.c_str(), msg.timestamp.c_str());
                ImGui::PopStyleColor();
                ImGui::Spacing();
                ImGui::Spacing();

                continue;  // Skip regular message rendering
            }
        }

            // Calculate bubble width based on current window size
            float available_width = ImGui::GetContentRegionAvail().x;
            float bubble_width = available_width;  // 100% of available width (padding inside bubble prevents overflow)

            // All bubbles aligned left (Telegram-style)

            // Draw bubble background with proper padding (theme-aware)
            ImVec4 base_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

            // Recipient bubble: much lighter (0.12 opacity)
            // Own bubble: normal opacity (0.25)
            ImVec4 bg_color;
            if (msg.is_outgoing) {
                bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
            } else {
                bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
            }

            ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0)); // No border
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f); // Square corners

        char bubble_id[32];
        snprintf(bubble_id, sizeof(bubble_id), "bubble%zu", i);

        // Calculate padding and dimensions
        float padding_horizontal = 15.0f;
        float padding_vertical = 12.0f;
        float content_width = bubble_width - (padding_horizontal * 2);

        ImVec2 text_size = ImGui::CalcTextSize(msg.content.c_str(), NULL, false, content_width);

        float bubble_height = text_size.y + (padding_vertical * 2);

        ImGui::BeginChild(bubble_id, ImVec2(bubble_width, bubble_height), false,
            ImGuiWindowFlags_NoScrollbar);

        // Right-click context menu - set compact style BEFORE opening
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.0f, 0.0f)); // No vertical padding
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.0f, 0.0f)); // No vertical spacing

        if (ImGui::BeginPopupContextWindow()) {
            if (ImGui::MenuItem(ICON_FA_COPY " Copy")) {
                ImGui::SetClipboardText(msg.content.c_str());
            }
            CenteredModal::End();
        }

        ImGui::PopStyleVar(2);

        // Apply padding
        ImGui::SetCursorPos(ImVec2(padding_horizontal, padding_vertical));

        // Use TextWrapped for better text rendering
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + content_width);
        ImGui::TextWrapped("%s", msg.content.c_str());
        ImGui::PopTextWrapPos();

        // Status indicator (bottom-right corner) for outgoing messages
        if (msg.is_outgoing) {
            const char* status_icon;
            ImVec4 status_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

            switch (msg.status) {
                case STATUS_PENDING:
                    status_icon = ICON_FA_CLOCK;
                    break;
                case STATUS_SENT:
                    status_icon = ICON_FA_CHECK;
                    break;
                case STATUS_FAILED:
                    status_icon = ICON_FA_CIRCLE_EXCLAMATION;
                    break;
            }

            status_color.w = 0.6f; // Subtle opacity for all states
            float icon_size = 12.0f;
            ImVec2 status_pos = ImVec2(content_width - icon_size, bubble_height - padding_vertical - icon_size);

            ImGui::SetCursorPos(status_pos);
            ImGui::PushStyleColor(ImGuiCol_Text, status_color);
            ImGui::Text("%s", status_icon);
            ImGui::PopStyleColor();

            // Add retry hover tooltip and click handler for failed messages
            if (msg.status == STATUS_FAILED) {
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Send failed - click to retry");
                }
                if (ImGui::IsItemClicked()) {
                    retryMessage(state, state.selected_contact, i);
                }
            }
        }

        ImGui::EndChild();

        // Get bubble position for arrow (AFTER EndChild)
        ImVec2 bubble_min = ImGui::GetItemRectMin();
        ImVec2 bubble_max = ImGui::GetItemRectMax();

        ImGui::PopStyleVar(1); // ChildRounding
        ImGui::PopStyleColor(2); // ChildBg, Border

        // Draw triangle arrow pointing DOWN from bubble to username
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec4 arrow_color;
        if (msg.is_outgoing) {
            arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
        } else {
            arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
        }
        ImU32 arrow_col = ImGui::ColorConvertFloat4ToU32(arrow_color);

        // Triangle points: pointing DOWN from bubble to username
        float arrow_x = bubble_min.x + 20.0f; // 20px from left edge
        float arrow_top = bubble_max.y; // Bottom of bubble
        float arrow_bottom = bubble_max.y + 10.0f; // Point of arrow extends down

        ImVec2 p1(arrow_x, arrow_bottom);           // Bottom point (pointing down)
        ImVec2 p2(arrow_x - 8.0f, arrow_top);       // Top left (at bubble bottom)
        ImVec2 p3(arrow_x + 8.0f, arrow_top);       // Top right (at bubble bottom)

        draw_list->AddTriangleFilled(p1, p2, p3, arrow_col);

        // Sender name and timestamp BELOW the arrow (theme-aware)
        ImVec4 meta_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
        meta_color.w = 0.7f; // Slightly transparent

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8.0f); // Space for arrow

        // Show avatar for incoming messages if available
        if (!msg.is_outgoing && state.profile_avatar_loaded && !state.profile_avatar_base64.empty()) {
            int avatar_width = 0, avatar_height = 0;
            std::string avatar_key = "chat_" + msg.sender;  // Unique key for this sender
            GLuint texture_id = TextureManager::getInstance().loadAvatar(
                avatar_key,
                state.profile_avatar_base64,
                &avatar_width,
                &avatar_height
            );

            if (texture_id != 0) {
                float avatar_size = 20.0f;  // Small avatar for chat messages
                ImVec2 avatar_pos = ImGui::GetCursorScreenPos();

                // Draw circular clipped avatar
                ImDrawList* draw_list_avatar = ImGui::GetWindowDrawList();
                draw_list_avatar->AddImageRounded(
                    (void*)(intptr_t)texture_id,
                    avatar_pos,
                    ImVec2(avatar_pos.x + avatar_size, avatar_pos.y + avatar_size),
                    ImVec2(0, 0),
                    ImVec2(1, 1),
                    IM_COL32(255, 255, 255, 255),
                    avatar_size * 0.5f  // Circular
                );

                ImGui::Dummy(ImVec2(avatar_size, avatar_size));
                ImGui::SameLine();
            }
        }

        ImGui::PushStyleColor(ImGuiCol_Text, meta_color);
        const char* sender_label = msg.is_outgoing ? "You" : msg.sender.c_str();
        ImGui::Text("%s • %s", sender_label, msg.timestamp.c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Spacing();
    }  // End message loop

    // Handle scroll logic BEFORE EndChild() (operates on MessageArea window)
    float current_scroll = ImGui::GetScrollY();
    float max_scroll = ImGui::GetScrollMaxY();
    bool is_at_bottom = (current_scroll >= max_scroll - 1.0f);

    // Check if user actively scrolled UP (not just hovering)
    bool user_scrolled_up = !is_at_bottom && ImGui::IsWindowFocused();

    if (user_scrolled_up && state.scroll_to_bottom_frames > 0) {
        state.scroll_to_bottom_frames = 0; // Cancel auto-scroll if user scrolled up
    }

    // Delayed scroll (wait 2 frames for message to fully render)
    if (state.scroll_to_bottom_frames > 0) {
        state.scroll_to_bottom_frames--;
        if (state.scroll_to_bottom_frames == 0) {
            ImGui::SetScrollY(ImGui::GetScrollMaxY());
        }
    } else if (state.should_scroll_to_bottom) {
        // Start delayed scroll
        state.scroll_to_bottom_frames = 2;
        state.should_scroll_to_bottom = false;
    }

    ImGui::EndChild();

    // Message input area - Multiline with recipient bubble color
    ImGui::Spacing();
    ImGui::Spacing();

    // Recipient bubble background color
    ImVec4 recipient_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)  // DNA: slightly lighter than bg
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f); // Club: slightly lighter

    ImGui::PushStyleColor(ImGuiCol_FrameBg, recipient_bg);

    // Check if we need to autofocus (contact changed or message sent)
    bool should_autofocus = (state.prev_selected_contact != state.selected_contact) || state.should_focus_input;
    if (state.prev_selected_contact != state.selected_contact) {
        state.prev_selected_contact = state.selected_contact;
        state.should_scroll_to_bottom = true;  // Scroll to bottom when switching contacts
    }
    state.should_focus_input = false; // Reset flag

    if (is_mobile) {
        // Mobile: stacked layout
        if (should_autofocus) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        bool enter_pressed = ImGui::InputTextMultiline("##MessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(-1, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine);
        ImGui::PopStyleColor();

        // Send button with paper plane icon
        if (ThemedButton(ICON_FA_PAPER_PLANE, ImVec2(-1, 40)) || enter_pressed) {
            if (strlen(state.message_input) > 0 && state.selected_contact >= 0) {
                // Check queue limit
                if (state.message_send_queue.size() >= 20) {
                    ImGui::OpenPopup("Queue Full");
                } else {
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        // Copy data for async task
                        std::string message_copy = std::string(state.message_input);
                        std::string recipient = state.contacts[state.selected_contact].address;

                        // Get message index BEFORE appending (important for queue)
                        int msg_idx;
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            msg_idx = state.contact_messages[recipient].size();

                            // Optimistic UI update: append pending message immediately
                            Message pending_msg;
                            pending_msg.sender = "You";
                            pending_msg.content = message_copy;
                            pending_msg.timestamp = "now";
                            pending_msg.is_outgoing = true;
                            pending_msg.status = STATUS_PENDING;
                            state.contact_messages[recipient].push_back(pending_msg);
                        }

                        // Clear input immediately for better UX
                        state.message_input[0] = '\0';
                        state.should_focus_input = true;
                        state.should_scroll_to_bottom = true;  // Force scroll to bottom after sending

                        // Enqueue message send task (capture fingerprint, not index)
                        state.message_send_queue.enqueue([&state, ctx, message_copy, recipient, msg_idx]() {
                            const char* recipients[] = { recipient.c_str() };
                            int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str(), 0, MESSAGE_TYPE_CHAT);

                            // Update status with mutex protection
                            {
                                std::lock_guard<std::mutex> lock(state.messages_mutex);
                                auto& msgs = state.contact_messages[recipient];
                                if (msg_idx < (int)msgs.size()) {
                                    msgs[msg_idx].status = (result == 0) ? STATUS_SENT : STATUS_FAILED;
                                }
                            }

                            if (result == 0) {
                                printf("[Send] [OK] Message sent to %s (queue processed)\n", recipient.c_str());
                            } else {
                                printf("[Send] ERROR: Failed to send to %s (status=FAILED)\n", recipient.c_str());
                            }
                        }, msg_idx);
                    } else {
                        printf("[Send] ERROR: No messenger context\n");
                    }
                }
            }
        }
    } else {
        // Desktop: side-by-side
        float input_width = ImGui::GetContentRegionAvail().x - 70; // Reserve 70px for button

        ImVec2 input_pos = ImGui::GetCursorScreenPos();

        if (should_autofocus) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::SetNextItemWidth(input_width);

        // Callback to set cursor position if needed
        auto input_callback = [](ImGuiInputTextCallbackData* data) -> int {
            AppState* state_ptr = (AppState*)data->UserData;
            if (state_ptr->input_cursor_pos >= 0) {
                data->CursorPos = state_ptr->input_cursor_pos;
                data->SelectionStart = data->SelectionEnd = data->CursorPos;
                state_ptr->input_cursor_pos = -1; // Reset
            }
            return 0;
        };

        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        bool enter_pressed = ImGui::InputTextMultiline("##MessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(input_width, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_CallbackAlways,
            input_callback, &state);
        ImGui::PopStyleColor();

        // Get input box position right after rendering it
        ImVec2 input_rect_min = ImGui::GetItemRectMin();

        // Check if ':' was just typed to trigger emoji picker
        static char prev_message[16384] = "";
        static bool already_triggered_for_current = false;
        static ImVec2 prev_window_size = ImVec2(0, 0);
        ImVec2 current_window_size = ImGui::GetIO().DisplaySize;
        size_t len = strlen(state.message_input);
        bool message_changed = (strcmp(state.message_input, prev_message) != 0);

        // Close emoji picker if window was resized
        if (state.show_emoji_picker && (prev_window_size.x != current_window_size.x || prev_window_size.y != current_window_size.y)) {
            state.show_emoji_picker = false;
        }
        prev_window_size = current_window_size;

        // Reset trigger flag if message changed
        if (message_changed) {
            already_triggered_for_current = false;
            strcpy(prev_message, state.message_input);
        }

        // Detect if ':' was just typed - calculate text cursor position
        if (!already_triggered_for_current && len > 0 && state.message_input[len-1] == ':' && ImGui::IsItemActive()) {
            state.show_emoji_picker = true;

            // Calculate approximate cursor position based on text
            ImFont* font = ImGui::GetFont();
            float font_size = ImGui::GetFontSize();

            // Count newlines to determine which line we're on
            int line_num = 0;
            int last_newline_pos = -1;
            for (size_t i = 0; i < len; i++) {
                if (state.message_input[i] == '\n') {
                    line_num++;
                    last_newline_pos = i;
                }
            }

            // Calculate text width from last newline (or start) to cursor
            const char* line_start = (last_newline_pos >= 0) ? &state.message_input[last_newline_pos + 1] : state.message_input;
            size_t chars_in_line = len - (last_newline_pos + 1);
            ImVec2 text_size = font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, line_start, line_start + chars_in_line);

            // Position picker at text cursor location
            float cursor_x = input_rect_min.x + text_size.x + 5.0f; // 5px padding
            float cursor_y = input_rect_min.y + (line_num * font_size * 1.2f); // 1.2 line height multiplier

            // Emoji picker size
            float picker_width = 400.0f;
            float picker_height = 200.0f;

            // Check if picker would go outside window bounds (right side)
            float window_right = ImGui::GetIO().DisplaySize.x;
            if (cursor_x + picker_width > window_right) {
                // Place on left side of cursor instead
                cursor_x = cursor_x - picker_width - 10.0f;
                // Make sure it doesn't go off left side
                if (cursor_x < 0) cursor_x = 10.0f;
            }

            state.emoji_picker_pos = ImVec2(cursor_x, cursor_y - 210);
            already_triggered_for_current = true;
        }

        // Emoji picker popup
        if (state.show_emoji_picker) {
            ImGui::SetNextWindowPos(state.emoji_picker_pos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(ImVec2(300, 280), ImGuiCond_Always);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10));

            if (ImGui::Begin("##EmojiPicker", &state.show_emoji_picker, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize)) {
                // ESC to close
                if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                    state.show_emoji_picker = false;
                    state.should_focus_input = true; // Refocus message input
                }

                // Close if clicked outside
                if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows)) {
                    state.show_emoji_picker = false;
                }

                // Font Awesome emoji icons in a single flat array
                static const char* emojis[] = {
                    // Smileys
                    ICON_FA_FACE_SMILE, ICON_FA_FACE_GRIN, ICON_FA_FACE_LAUGH, ICON_FA_FACE_GRIN_BEAM,
                    ICON_FA_FACE_GRIN_HEARTS, ICON_FA_FACE_KISS_WINK_HEART, ICON_FA_FACE_GRIN_WINK, ICON_FA_FACE_SMILE_WINK,
                    ICON_FA_FACE_GRIN_TONGUE, ICON_FA_FACE_SURPRISE, ICON_FA_FACE_FROWN, ICON_FA_FACE_SAD_TEAR,
                    ICON_FA_FACE_ANGRY, ICON_FA_FACE_TIRED, ICON_FA_FACE_MEH, ICON_FA_FACE_ROLLING_EYES,
                    // Hearts & Symbols
                    ICON_FA_HEART, ICON_FA_HEART_PULSE, ICON_FA_HEART_CRACK, ICON_FA_STAR,
                    ICON_FA_THUMBS_UP, ICON_FA_THUMBS_DOWN, ICON_FA_FIRE, ICON_FA_ROCKET,
                    ICON_FA_BOLT, ICON_FA_CROWN, ICON_FA_GEM, ICON_FA_TROPHY,
                    ICON_FA_GIFT, ICON_FA_CAKE_CANDLES, ICON_FA_BELL, ICON_FA_MUSIC,
                    // Objects
                    ICON_FA_CHECK, ICON_FA_XMARK, ICON_FA_CIRCLE_EXCLAMATION, ICON_FA_CIRCLE_QUESTION,
                    ICON_FA_LIGHTBULB, ICON_FA_COMMENT, ICON_FA_ENVELOPE, ICON_FA_PHONE,
                    ICON_FA_LOCATION_DOT, ICON_FA_CALENDAR, ICON_FA_CLOCK, ICON_FA_FLAG,
                    ICON_FA_SHIELD, ICON_FA_KEY, ICON_FA_LOCK, ICON_FA_EYE
                };
                static const int emoji_count = sizeof(emojis) / sizeof(emojis[0]);
                static const int emojis_per_row = 7;

                ImGui::BeginChild("EmojiGrid", ImVec2(0, 0), false);

                // Display emojis as text with click detection
                ImVec4 text_color = g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text();
                ImVec4 hover_bg_color = g_app_settings.theme == 0 ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
                ImVec4 hover_text_color = g_app_settings.theme == 0 ? DNATheme::Background() : ClubTheme::Background();
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 8));

                // Display emojis in a grid (7 per row)
                for (int i = 0; i < emoji_count; i++) {
                    ImGui::PushID(i);
                    
                    ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                    bool clicked = ImGui::InvisibleButton("##emoji", ImVec2(35, 35));
                    bool hovered = ImGui::IsItemHovered();
                    
                    // Draw hover background
                    if (hovered) {
                        ImDrawList* draw_list = ImGui::GetWindowDrawList();
                        ImU32 bg_color = ImGui::GetColorU32(hover_bg_color);
                        draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + 35, cursor_pos.y + 35), bg_color, 4.0f);
                    }
                    
                    // Draw emoji icon centered - use dark color when hovered
                    ImVec4 icon_color = hovered ? hover_text_color : text_color;
                    ImVec2 text_size = ImGui::CalcTextSize(emojis[i]);
                    ImVec2 text_pos = ImVec2(
                        cursor_pos.x + (35 - text_size.x) * 0.5f,
                        cursor_pos.y + (35 - text_size.y) * 0.5f
                    );
                    ImGui::GetWindowDrawList()->AddText(text_pos, ImGui::GetColorU32(icon_color), emojis[i]);
                    
                    if (clicked) {
                        if (len > 0) state.message_input[len-1] = '\0'; // Remove the ':'
                        // Bounds-checked emoji append
                        size_t current_len = strlen(state.message_input);
                        size_t emoji_len = strlen(emojis[i]);
                        size_t remaining = sizeof(state.message_input) - current_len - 1;
                        if (emoji_len <= remaining) {
                            strncat(state.message_input, emojis[i], remaining);
                        }
                        state.input_cursor_pos = strlen(state.message_input); // Set cursor to end
                        state.show_emoji_picker = false;
                        state.should_focus_input = true;
                    }
                    
                    ImGui::PopID();
                    if ((i + 1) % emojis_per_row != 0 && i < emoji_count - 1) ImGui::SameLine();
                }

                ImGui::PopStyleVar();
                ImGui::EndChild();
                ImGui::End();
            }
            ImGui::PopStyleVar();
        }

        ImGui::SameLine();

        // Send button - round button with paper plane icon
        ImVec4 btn_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(btn_color.x * 0.9f, btn_color.y * 0.9f, btn_color.z * 0.9f, btn_color.w));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(btn_color.x * 0.8f, btn_color.y * 0.8f, btn_color.z * 0.8f, btn_color.w));
        ImVec4 dark_text = g_app_settings.theme == 0 ? DNATheme::Background() : ClubTheme::Background();
        ImGui::PushStyleColor(ImGuiCol_Text, dark_text); // Dark text on button
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 25.0f); // Round button

        // Center icon in button
        const char* icon = ICON_FA_PAPER_PLANE;
        ImVec2 icon_size = ImGui::CalcTextSize(icon);
        float button_size = 50.0f;
        ImVec2 padding((button_size - icon_size.x) * 0.5f, (button_size - icon_size.y) * 0.5f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, padding);

        bool icon_clicked = ThemedButton(icon, ImVec2(button_size, button_size));

        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(4);

        if (icon_clicked || enter_pressed) {
            if (strlen(state.message_input) > 0 && state.selected_contact >= 0) {
                // Check queue limit
                if (state.message_send_queue.size() >= 20) {
                    ImGui::OpenPopup("Queue Full");
                } else {
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        // Copy data for async task
                        std::string message_copy = std::string(state.message_input);
                        std::string recipient = state.contacts[state.selected_contact].address;

                        // Get message index BEFORE appending (important for queue)
                        int msg_idx;
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            msg_idx = state.contact_messages[recipient].size();

                            // Optimistic UI update: append pending message immediately
                            Message pending_msg;
                            pending_msg.sender = "You";
                            pending_msg.content = message_copy;
                            pending_msg.timestamp = "now";
                            pending_msg.is_outgoing = true;
                            pending_msg.status = STATUS_PENDING;
                            state.contact_messages[recipient].push_back(pending_msg);
                        }

                        // Clear input immediately for better UX
                        state.message_input[0] = '\0';
                        state.should_focus_input = true;
                        state.should_scroll_to_bottom = true;  // Force scroll to bottom after sending

                        // Enqueue message send task (capture fingerprint, not index)
                        state.message_send_queue.enqueue([&state, ctx, message_copy, recipient, msg_idx]() {
                            const char* recipients[] = { recipient.c_str() };
                            int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str(), 0, MESSAGE_TYPE_CHAT);

                            // Update status with mutex protection
                            {
                                std::lock_guard<std::mutex> lock(state.messages_mutex);
                                auto& msgs = state.contact_messages[recipient];
                                if (msg_idx < (int)msgs.size()) {
                                    msgs[msg_idx].status = (result == 0) ? STATUS_SENT : STATUS_FAILED;
                                }
                            }

                            if (result == 0) {
                                printf("[Send] [OK] Message sent to %s (queue processed)\n", recipient.c_str());
                            } else {
                                printf("[Send] ERROR: Failed to send to %s (status=FAILED)\n", recipient.c_str());
                            }
                        }, msg_idx);
                    } else {
                        printf("[Send] ERROR: No messenger context\n");
                    }
                }
            }
        }
    }

    ImGui::PopStyleColor(); // FrameBg

    // Queue Full modal
    if (CenteredModal::Begin("Queue Full", NULL, ImGuiWindowFlags_NoResize, true, true, 400, 590)) {
        ImGui::Text("Message queue is full (20 pending messages).");
        ImGui::Text("Please wait for messages to send before adding more.");
        ImGui::Spacing();
        if (ThemedButton("OK", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        CenteredModal::End();
    }
}

} // namespace ChatScreen
