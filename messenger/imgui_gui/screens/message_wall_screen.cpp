#include "message_wall_screen.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../texture_manager.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/client/dna_message_wall.h"
    #include "../../dht/client/dna_wall_votes.h"
    #include "../../dht/client/dna_profile.h"
    #include "../../p2p/p2p_transport.h"
    #include "../../crypto/utils/qgp_types.h"
    #include "../../crypto/utils/qgp_platform.h"
    #include "../../database/keyserver_cache.h"  // Phase 7.1: For signature verification
    #include <time.h>
}

#include <cstring>
#include <cctype>
#include <algorithm>

namespace MessageWallScreen {

// Thread helper: Find root parent of a message
std::string findRootParent(const std::vector<AppState::WallMessage>& messages, const std::string& post_id) {
    // Find the message
    for (const auto& msg : messages) {
        if (msg.post_id == post_id) {
            // If it's a top-level post, it IS the root
            if (msg.reply_to.empty() || msg.reply_depth == 0) {
                return post_id;
            }
            // Otherwise, recursively find parent's root
            return findRootParent(messages, msg.reply_to);
        }
    }
    return post_id;  // Fallback
}

// Thread helper: Get latest timestamp in thread (for sorting by activity)
uint64_t getThreadLatestTimestamp(const std::vector<AppState::WallMessage>& messages, const std::string& root_id) {
    uint64_t latest = 0;
    for (const auto& msg : messages) {
        std::string msg_root = findRootParent(messages, msg.post_id);
        if (msg_root == root_id && msg.timestamp > latest) {
            latest = msg.timestamp;
        }
    }
    return latest;
}

// Cast a vote on a wall post
void castVote(AppState& state, const std::string& post_id, int8_t vote_value) {
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

    // Cast vote
    state.wall_status = vote_value > 0 ? "Casting upvote..." : "Casting downvote...";
    ret = dna_cast_vote(dht_ctx, post_id.c_str(), state.current_identity.c_str(),
                        vote_value, key->private_key);

    qgp_key_free(key);

    if (ret == -2) {
        state.wall_status = "Error: You already voted on this post (votes are permanent)";
        return;
    } else if (ret != 0) {
        state.wall_status = "Error: Failed to cast vote";
        return;
    }

    // Success - update UI
    for (auto& msg : state.wall_messages) {
        if (msg.post_id == post_id) {
            msg.user_vote = vote_value;
            if (vote_value == 1) {
                msg.upvotes++;
            } else {
                msg.downvotes++;
            }
            break;
        }
    }

    state.wall_status = vote_value > 0 ? "Upvote cast successfully!" : "Downvote cast successfully!";
}

// Load votes for all messages
void loadVotesForMessages(AppState& state) {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        return;
    }

    for (auto& msg : state.wall_messages) {
        // Load votes from DHT
        dna_wall_votes_t *votes = nullptr;
        int ret = dna_load_votes(dht_ctx, msg.post_id.c_str(), &votes);

        if (ret == 0 && votes) {
            msg.upvotes = votes->upvote_count;
            msg.downvotes = votes->downvote_count;
            msg.user_vote = dna_get_user_vote(votes, state.current_identity.c_str());
            dna_wall_votes_free(votes);
        } else {
            // No votes yet
            msg.upvotes = 0;
            msg.downvotes = 0;
            msg.user_vote = 0;
        }
    }
}

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
            wall_msg.post_id = msg->post_id;
            wall_msg.timestamp = msg->timestamp;
            wall_msg.text = msg->text;

            // Phase 7.1: Signature verification
            // All messages are signed with Dilithium5 when posted (dna_post_to_wall)
            // Signatures are verified during dna_load_wall() when fetching from DHT
            // UI displays pre-validated messages (no need to re-verify on every render)
            wall_msg.verified = (msg->signature_len > 0);  // Signature present = already verified

            wall_msg.reply_to = msg->reply_to;
            wall_msg.reply_depth = msg->reply_depth;
            wall_msg.reply_count = msg->reply_count;

            // Initialize vote fields (will be loaded separately if needed)
            wall_msg.upvotes = 0;
            wall_msg.downvotes = 0;
            wall_msg.user_vote = 0;

            // Extract sender fingerprint from post_id (first 128 chars before underscore)
            std::string post_id_str(msg->post_id);
            size_t underscore_pos = post_id_str.find('_');
            if (underscore_pos != std::string::npos && underscore_pos == 128) {
                wall_msg.sender_fingerprint = post_id_str.substr(0, 128);

                // Try to load sender's avatar from profile cache/DHT
                dna_unified_identity_t *sender_profile = nullptr;
                int ret = dna_load_identity(dht_ctx, wall_msg.sender_fingerprint.c_str(), &sender_profile);
                if (ret == 0 && sender_profile && sender_profile->avatar_base64[0] != '\0') {
                    wall_msg.sender_avatar = std::string(sender_profile->avatar_base64);
                }
                if (sender_profile) {
                    dna_identity_free(sender_profile);
                }
            }

            state.wall_messages.push_back(wall_msg);
        }
        state.wall_status = "Loaded " + std::to_string(wall->message_count) + " messages";

        // Load votes for all messages
        loadVotesForMessages(state);
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

    // Post message to DHT (with optional reply_to)
    state.wall_status = "Posting message...";

    const char *reply_to = state.wall_reply_to.empty() ? NULL : state.wall_reply_to.c_str();
    // Pass both: wall owner's fingerprint (where wall is stored) and poster's fingerprint (current user)
    ret = dna_post_to_wall(dht_ctx,
                           state.wall_fingerprint.c_str(),  // Wall owner
                           state.current_identity.c_str(),  // Poster (current user)
                           messageText.c_str(), key->private_key, reply_to);

    qgp_key_free(key);

    if (ret == -2) {
        state.wall_status = "Error: Maximum thread depth exceeded (3 levels max)";
        return;
    } else if (ret != 0) {
        state.wall_status = "Error: Failed to post message to DHT";
        return;
    }

    // Success
    state.wall_status = state.wall_reply_to.empty() ?
                        "Message posted successfully!" :
                        "Reply posted successfully!";
    memset(state.wall_message_input, 0, sizeof(state.wall_message_input));
    state.wall_reply_to.clear();  // Clear reply mode

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
            // Group messages by thread (root parent) and sort by latest activity
            std::vector<std::string> root_posts;  // List of root post IDs
            std::map<std::string, uint64_t> thread_activity;  // root_id -> latest timestamp

            // Find all root posts (top-level posts)
            for (const auto& msg : state.wall_messages) {
                if (msg.reply_to.empty() || msg.reply_depth == 0) {
                    if (std::find(root_posts.begin(), root_posts.end(), msg.post_id) == root_posts.end()) {
                        root_posts.push_back(msg.post_id);
                        thread_activity[msg.post_id] = getThreadLatestTimestamp(state.wall_messages, msg.post_id);
                    }
                }
            }

            // Sort threads by latest activity (most recent first)
            std::sort(root_posts.begin(), root_posts.end(), [&thread_activity](const std::string& a, const std::string& b) {
                return thread_activity[a] > thread_activity[b];
            });

            // Display each thread
            for (size_t thread_idx = 0; thread_idx < root_posts.size(); thread_idx++) {
                const std::string& root_id = root_posts[thread_idx];
                bool is_expanded = state.wall_expanded_threads.count(root_id) > 0;

                // Collect all messages in this thread
                std::vector<const AppState::WallMessage*> thread_msgs;
                for (const auto& msg : state.wall_messages) {
                    if (findRootParent(state.wall_messages, msg.post_id) == root_id) {
                        thread_msgs.push_back(&msg);
                    }
                }

                // Sort thread messages by timestamp (oldest first for natural reading)
                std::sort(thread_msgs.begin(), thread_msgs.end(), [](const AppState::WallMessage* a, const AppState::WallMessage* b) {
                    return a->timestamp < b->timestamp;
                });

                // Display messages (root only if collapsed, all if expanded)
                size_t display_count = is_expanded ? thread_msgs.size() : 1;
                for (size_t i = 0; i < display_count; i++) {
                    const auto& msg = *thread_msgs[i];

                ImGui::PushID(msg.post_id.c_str());

                // Threading: indent based on reply_depth (20px per level)
                float thread_indent = msg.reply_depth * 20.0f;
                if (thread_indent > 0) {
                    ImGui::Indent(thread_indent);
                }

                ImGui::BeginGroup();

                // Background
                ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                ImDrawList* draw_list = ImGui::GetWindowDrawList();
                float item_height = 100.0f;  // Increased for Reply button
                ImU32 bg_color = IM_COL32(30, 30, 35, 255);
                draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + ImGui::GetContentRegionAvail().x, cursor_pos.y + item_height), bg_color, 4.0f);

                // Thread depth indicator (colored bar on left)
                if (msg.reply_depth > 0) {
                    ImU32 depth_colors[] = {
                        IM_COL32(100, 180, 255, 255),  // Level 1: Blue
                        IM_COL32(100, 255, 180, 255),  // Level 2: Green
                        IM_COL32(255, 180, 100, 255)   // Level 3: Orange
                    };
                    ImU32 depth_color = depth_colors[(msg.reply_depth - 1) % 3];
                    draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + 3, cursor_pos.y + item_height), depth_color);
                }

                ImGui::Dummy(ImVec2(0, 5));
                ImGui::Indent(10);

                // Header: avatar + timestamp + verification
                // Display avatar if available
                if (!msg.sender_avatar.empty()) {
                    int avatar_width = 0, avatar_height = 0;
                    GLuint texture_id = TextureManager::getInstance().loadAvatar(
                        msg.sender_fingerprint,
                        msg.sender_avatar,
                        &avatar_width,
                        &avatar_height
                    );

                    if (texture_id != 0) {
                        float avatar_size = 24.0f;  // Small avatar for wall posts
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

                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", formatWallTimestamp(msg.timestamp).c_str());
                ImGui::SameLine();
                if (msg.verified) {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), ICON_FA_CIRCLE_CHECK " Signed");
                }

                ImGui::Spacing();

                // Show "Reply to" line if this is a reply
                if (msg.reply_depth > 0 && !msg.reply_to.empty()) {
                    // Find parent message
                    std::string parent_text = "";
                    for (const auto& m : state.wall_messages) {
                        if (m.post_id == msg.reply_to) {
                            parent_text = m.text;
                            break;
                        }
                    }

                    // Show reply context
                    if (!parent_text.empty()) {
                        // Truncate parent text to first 50 chars
                        std::string truncated = parent_text;
                        if (truncated.length() > 50) {
                            truncated = truncated.substr(0, 50) + "...";
                        }

                        const char* reply_icon = ICON_FA_TURN_UP " ";
                        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(),
                                         "%sReplying to: \"%s\"", reply_icon, truncated.c_str());
                        ImGui::Spacing();
                    }
                }

                // Message text
                ImGui::TextWrapped("%s", msg.text.c_str());

                ImGui::Spacing();

                // Community voting UI
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 4));
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 4));

                // Upvote button (highlight if user upvoted)
                bool user_upvoted = (msg.user_vote == 1);
                if (user_upvoted) {
                    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(50, 150, 255, 255));  // Blue highlight
                }
                bool upvote_clicked = ThemedButton((std::string("\xf0\x9f\x91\x8d ") + std::to_string(msg.upvotes)).c_str(), ImVec2(60, 25), false);
                if (user_upvoted) {
                    ImGui::PopStyleColor();
                }

                ImGui::SameLine();

                // Downvote button (highlight if user downvoted)
                bool user_downvoted = (msg.user_vote == -1);
                if (user_downvoted) {
                    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(255, 100, 100, 255));  // Red highlight
                }
                bool downvote_clicked = ThemedButton((std::string("\xf0\x9f\x91\x8e ") + std::to_string(msg.downvotes)).c_str(), ImVec2(60, 25), false);
                if (user_downvoted) {
                    ImGui::PopStyleColor();
                }

                ImGui::SameLine();

                // Net score
                int net_score = msg.upvotes - msg.downvotes;
                ImVec4 score_color = net_score > 0 ? ImVec4(0.3f, 0.8f, 0.3f, 1.0f) :   // Green
                                    net_score < 0 ? ImVec4(0.8f, 0.3f, 0.3f, 1.0f) :   // Red
                                                   ImVec4(0.7f, 0.7f, 0.7f, 1.0f);    // Gray
                ImGui::TextColored(score_color, "Score: %+d", net_score);

                ImGui::PopStyleVar(2);

                // Handle vote clicks
                if (upvote_clicked && msg.user_vote != 1) {
                    castVote(state, msg.post_id, 1);  // Cast upvote
                }
                if (downvote_clicked && msg.user_vote != -1) {
                    castVote(state, msg.post_id, -1);  // Cast downvote
                }

                ImGui::Spacing();

                // Footer: Reply button + expand/collapse + reply count
                if (msg.reply_depth < 2) {  // Only allow replies up to depth 2
                    if (ThemedButton(ICON_FA_REPLY " Reply", ImVec2(80, 25), false)) {
                        state.wall_reply_to = msg.post_id;
                        state.wall_status = "Replying to message...";
                    }

                    // For root post (depth 0), show expand/collapse button
                    if (msg.reply_depth == 0 && thread_msgs.size() > 1) {
                        ImGui::SameLine();
                        const char* expand_icon = is_expanded ? ICON_FA_ANGLE_UP : ICON_FA_ANGLE_DOWN;
                        const char* expand_text = is_expanded ? "Collapse" : "Expand";
                        if (ThemedButton((std::string(expand_icon) + " " + expand_text).c_str(), ImVec2(100, 25), false)) {
                            if (is_expanded) {
                                state.wall_expanded_threads.erase(root_id);
                            } else {
                                state.wall_expanded_threads.insert(root_id);
                            }
                        }
                    }

                    // Show reply count
                    int total_replies = thread_msgs.size() - 1;  // Subtract root post
                    if (msg.reply_depth == 0 && total_replies > 0) {
                        ImGui::SameLine();
                        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(),
                                         ICON_FA_COMMENT " %d %s", total_replies, total_replies == 1 ? "reply" : "replies");
                    }
                }

                ImGui::Unindent(10);
                ImGui::Dummy(ImVec2(0, 5));

                ImGui::EndGroup();

                if (thread_indent > 0) {
                    ImGui::Unindent(thread_indent);
                }

                ImGui::PopID();

                if (i < display_count - 1) {
                    ImGui::Spacing();
                }
                }  // End message loop

                // Thread separator
                if (thread_idx < root_posts.size() - 1) {
                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();
                }
            }  // End thread loop
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Post section (allow posting to any wall)
        // Show reply mode indicator
        if (!state.wall_reply_to.empty()) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(),
                             ICON_FA_REPLY " Replying to message");
            ImGui::SameLine();
            if (ThemedButton(ICON_FA_XMARK " Cancel", ImVec2(80, 25), false)) {
                state.wall_reply_to.clear();
                state.wall_status = "Reply cancelled";
            }
            ImGui::Spacing();
        } else {
            if (state.wall_is_own) {
                ImGui::Text(ICON_FA_PEN " Post New Message");
            } else {
                ImGui::Text(ICON_FA_PEN " Post on %s's Wall", state.wall_display_name.c_str());
            }
            ImGui::Spacing();
        }

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

        ImGui::Spacing();

        // Close button
        if (ThemedButton("Close", ImVec2(-1, 40))) {
            state.show_message_wall = false;
        }

        CenteredModal::End();
    }
}

} // namespace MessageWallScreen
