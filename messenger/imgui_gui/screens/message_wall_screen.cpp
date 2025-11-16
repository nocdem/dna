#include "message_wall_screen.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/client/dna_message_wall.h"
    #include "../../p2p/p2p_transport.h"
    #include "../../crypto/utils/qgp_types.h"
    #include "../../crypto/utils/qgp_platform.h"
    #include <time.h>
}

#include <cstring>
#include <cctype>

namespace MessageWallScreen {

// Format wall timestamp (from Qt MessageWallDialog.cpp lines 418-438)
std::string formatWallTimestamp(uint64_t timestamp) {
    time_t now = time(nullptr);
    int64_t secondsAgo = now - (time_t)timestamp;

    if (secondsAgo < 60) {
        return "Just now";
    } else if (secondsAgo < 3600) {
        int minutes = secondsAgo / 60;
        return std::to_string(minutes) + " min" + (minutes > 1 ? "s" : "") + " ago";
    } else if (secondsAgo < 86400) {
        int hours = secondsAgo / 3600;
        return std::to_string(hours) + " hour" + (hours > 1 ? "s" : "") + " ago";
    } else if (secondsAgo < 604800) {
        int days = secondsAgo / 86400;
        return std::to_string(days) + " day" + (days > 1 ? "s" : "") + " ago";
    } else {
        char buf[64];
        struct tm *tm_info = localtime((time_t*)&timestamp);
        strftime(buf, sizeof(buf), "%b %d, %Y", tm_info);
        return std::string(buf);
    }
}

// Load message wall from DHT (from Qt MessageWallDialog.cpp lines 129-174)
void loadMessageWall(AppState& state) {
    state.wall_status = "Loading wall from DHT...";
    state.wall_loading = true;
    state.wall_messages.clear();

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.wall_status = "Error: DHT not available";
        state.wall_loading = false;
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.wall_status = "Error: DHT not available";
        state.wall_loading = false;
        return;
    }

    // Load wall from DHT
    dna_message_wall_t *wall = nullptr;
    int ret = dna_load_wall(dht_ctx, state.wall_fingerprint.c_str(), &wall);

    if (ret == -2) {
        state.wall_status = "No messages yet. Be the first to post!";
        state.wall_loading = false;
        return;
    } else if (ret != 0) {
        state.wall_status = "Error loading wall from DHT";
        state.wall_loading = false;
        return;
    }

    // Display messages
    if (wall && wall->message_count > 0) {
        for (size_t i = 0; i < wall->message_count; i++) {
            const dna_wall_message_t *msg = &wall->messages[i];
            AppState::WallMessage wall_msg;
            wall_msg.timestamp = msg->timestamp;
            wall_msg.text = msg->text;
            wall_msg.verified = true;  // TODO: Implement signature verification
            state.wall_messages.push_back(wall_msg);
        }
        state.wall_status = "Loaded " + std::to_string(wall->message_count) + " messages";
    } else {
        state.wall_status = "No messages yet. Be the first to post!";
    }

    if (wall) {
        dna_message_wall_free(wall);
    }

    state.wall_loading = false;
}

// Post to message wall (from Qt MessageWallDialog.cpp lines 242-315)
void postToMessageWall(AppState& state) {
    std::string messageText = std::string(state.wall_message_input);

    // Trim whitespace
    while (!messageText.empty() && isspace(messageText.front())) messageText.erase(0, 1);
    while (!messageText.empty() && isspace(messageText.back())) messageText.pop_back();

    if (messageText.empty()) {
        state.wall_status = "Error: Message is empty";
        return;
    }

    if (messageText.length() > 1024) {
        state.wall_status = "Error: Message exceeds 1024 characters";
        return;
    }

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.wall_status = "Error: DHT not available";
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.wall_status = "Error: DHT not available";
        return;
    }

    // Load private key for signing
    const char *home_dir = qgp_platform_home_dir();
    if (!home_dir) {
        state.wall_status = "Error: Failed to get home directory";
        return;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home_dir, ctx->identity);

    qgp_key_t *key = nullptr;
    int ret = qgp_key_load(key_path, &key);
    if (ret != 0 || !key) {
        state.wall_status = "Error: Failed to load private key for signing";
        return;
    }

    // Post message to DHT
    state.wall_status = "Posting message...";

    ret = dna_post_to_wall(dht_ctx, state.wall_fingerprint.c_str(),
                           messageText.c_str(), key->private_key);

    qgp_key_free(key);

    if (ret != 0) {
        state.wall_status = "Error: Failed to post message to DHT";
        return;
    }

    // Success
    state.wall_status = "Message posted successfully!";
    memset(state.wall_message_input, 0, sizeof(state.wall_message_input));

    // Reload wall after 500ms
    // (In real implementation, would use async task)
    loadMessageWall(state);
}

// Render message wall dialog
void render(AppState& state) {
    if (!state.show_message_wall) return;


    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Message Wall")) {
        ImGui::OpenPopup("Message Wall");
        loadMessageWall(state);
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();


    if (CenteredModal::Begin("Message Wall", &state.show_message_wall, ImGuiWindowFlags_NoResize, true, false, 600)) {
        // Title

        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 100);
        if (ThemedButton(ICON_FA_ROTATE " Refresh", ImVec2(100, 30))) {
            loadMessageWall(state);
        }

        ImGui::Spacing();

        // Status label
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", state.wall_status.c_str());

        ImGui::Separator();
        ImGui::Spacing();

        // Message list
        ImGui::BeginChild("WallMessages", ImVec2(0, state.wall_is_own ? -200 : -50), true);

        if (state.wall_loading) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "Loading messages...");
        } else if (state.wall_messages.empty()) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "No messages yet. Be the first to post!");
        } else {
            for (size_t i = 0; i < state.wall_messages.size(); i++) {
                const auto& msg = state.wall_messages[i];

                ImGui::PushID(i);
                ImGui::BeginGroup();

                // Background
                ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                ImDrawList* draw_list = ImGui::GetWindowDrawList();
                float item_height = 80.0f;
                ImU32 bg_color = IM_COL32(30, 30, 35, 255);
                draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + ImGui::GetContentRegionAvail().x, cursor_pos.y + item_height), bg_color, 4.0f);

                ImGui::Dummy(ImVec2(0, 5));
                ImGui::Indent(10);

                // Header: timestamp + verification
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", formatWallTimestamp(msg.timestamp).c_str());
                ImGui::SameLine();
                if (msg.verified) {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), ICON_FA_CIRCLE_CHECK " Signed");
                }

                ImGui::Spacing();

                // Message text
                ImGui::TextWrapped("%s", msg.text.c_str());

                ImGui::Unindent(10);
                ImGui::Dummy(ImVec2(0, 5));

                ImGui::EndGroup();
                ImGui::PopID();

                if (i < state.wall_messages.size() - 1) {
                    ImGui::Spacing();
                }
            }
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Post section (only if own wall)
        if (state.wall_is_own) {
            ImGui::Text(ICON_FA_PEN " Post New Message");
            ImGui::Spacing();

            // Message input (white text for visibility)
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputTextMultiline("##WallInput", state.wall_message_input, sizeof(state.wall_message_input),
                                     ImVec2(-1, 80), ImGuiInputTextFlags_None);
            ImGui::PopStyleColor();

            // Character counter
            int len = strlen(state.wall_message_input);
            ImGui::Text("%d / 1024", len);
            ImGui::SameLine();

            // Post button
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - 150);
            if (ThemedButton(ICON_FA_PAPER_PLANE " Post Message", ImVec2(150, 35))) {
                postToMessageWall(state);
            }
        } else {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), ICON_FA_CIRCLE_INFO " This is %s's public message wall (read-only)", state.wall_display_name.c_str());
        }

        ImGui::Spacing();

        // Close button
        if (ThemedButton("Close", ImVec2(-1, 40))) {
            state.show_message_wall = false;
        }

        CenteredModal::End();
    }
}

} // namespace MessageWallScreen
