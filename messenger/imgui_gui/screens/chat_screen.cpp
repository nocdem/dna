#include "chat_screen.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "imgui.h"
#include <cstring>

extern "C" {
#include "../../messenger.h"
}

namespace ChatScreen {

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
        std::vector<Message>& messages = state.contact_messages[contact_idx];

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
        recipient = state.contacts[contact_idx].address;
    }

    printf("[Retry] Retrying message to %s...\n", recipient.c_str());

    // Enqueue retry task
    state.message_send_queue.enqueue([&state, ctx, message_copy, recipient, contact_idx, msg_idx]() {
        const char* recipients[] = { recipient.c_str() };
        int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str());

        // Update status with mutex protection
        {
            std::lock_guard<std::mutex> lock(state.messages_mutex);
            if (msg_idx >= 0 && msg_idx < (int)state.contact_messages[contact_idx].size()) {
                state.contact_messages[contact_idx][msg_idx].status =
                    (result == 0) ? STATUS_SENT : STATUS_FAILED;
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
        messages_copy = state.contact_messages[state.selected_contact];
    }

    // Render all messages (no clipper for variable-height items)
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
                        int contact_idx = state.selected_contact;

                        // Get message index BEFORE appending (important for queue)
                        int msg_idx;
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            msg_idx = state.contact_messages[contact_idx].size();

                            // Optimistic UI update: append pending message immediately
                            Message pending_msg;
                            pending_msg.sender = "You";
                            pending_msg.content = message_copy;
                            pending_msg.timestamp = "now";
                            pending_msg.is_outgoing = true;
                            pending_msg.status = STATUS_PENDING;
                            state.contact_messages[contact_idx].push_back(pending_msg);
                        }

                        // Clear input immediately for better UX
                        state.message_input[0] = '\0';
                        state.should_focus_input = true;
                        state.should_scroll_to_bottom = true;  // Force scroll to bottom after sending

                        // Enqueue message send task
                        state.message_send_queue.enqueue([&state, ctx, message_copy, recipient, contact_idx, msg_idx]() {
                            const char* recipients[] = { recipient.c_str() };
                            int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str());

                            // Update status with mutex protection
                            {
                                std::lock_guard<std::mutex> lock(state.messages_mutex);
                                if (msg_idx < (int)state.contact_messages[contact_idx].size()) {
                                    state.contact_messages[contact_idx][msg_idx].status =
                                        (result == 0) ? STATUS_SENT : STATUS_FAILED;
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
            ImGui::SetNextWindowSize(ImVec2(400, 200), ImGuiCond_Always);
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
                static const int emojis_per_row = 9;

                ImGui::BeginChild("EmojiGrid", ImVec2(0, 0), false);

                // Transparent button style
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.3f, 0.3f, 0.3f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.4f, 0.4f, 0.4f, 0.4f));
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 2));
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));

                // Display emojis in a grid (9 per row)
                for (int i = 0; i < emoji_count; i++) {
                    if (ImGui::Button(emojis[i], ImVec2(35, 35))) {
                        if (len > 0) state.message_input[len-1] = '\0'; // Remove the ':'
                        strcat(state.message_input, emojis[i]);
                        state.input_cursor_pos = strlen(state.message_input); // Set cursor to end
                        state.show_emoji_picker = false;
                        state.should_focus_input = true;
                    }
                    if ((i + 1) % emojis_per_row != 0 && i < emoji_count - 1) ImGui::SameLine();
                }

                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(3);
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

        bool icon_clicked = ImGui::Button(icon, ImVec2(button_size, button_size));

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
                        int contact_idx = state.selected_contact;

                        // Get message index BEFORE appending (important for queue)
                        int msg_idx;
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            msg_idx = state.contact_messages[contact_idx].size();

                            // Optimistic UI update: append pending message immediately
                            Message pending_msg;
                            pending_msg.sender = "You";
                            pending_msg.content = message_copy;
                            pending_msg.timestamp = "now";
                            pending_msg.is_outgoing = true;
                            pending_msg.status = STATUS_PENDING;
                            state.contact_messages[contact_idx].push_back(pending_msg);
                        }

                        // Clear input immediately for better UX
                        state.message_input[0] = '\0';
                        state.should_focus_input = true;
                        state.should_scroll_to_bottom = true;  // Force scroll to bottom after sending

                        // Enqueue message send task
                        state.message_send_queue.enqueue([&state, ctx, message_copy, recipient, contact_idx, msg_idx]() {
                            const char* recipients[] = { recipient.c_str() };
                            int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str());

                            // Update status with mutex protection
                            {
                                std::lock_guard<std::mutex> lock(state.messages_mutex);
                                if (msg_idx < (int)state.contact_messages[contact_idx].size()) {
                                    state.contact_messages[contact_idx][msg_idx].status =
                                        (result == 0) ? STATUS_SENT : STATUS_FAILED;
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
    if (ImGui::BeginPopupModal("Queue Full", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Message queue is full (20 pending messages).");
        ImGui::Text("Please wait for messages to send before adding more.");
        ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

} // namespace ChatScreen
