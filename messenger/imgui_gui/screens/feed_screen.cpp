/*
 * DNA Feed Screen - Public Feed UI Implementation
 *
 * Uses real DHT calls for all operations - no mock data.
 */

#include "feed_screen.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "imgui.h"
#include <algorithm>
#include <ctime>
#include <cstring>
#include <map>
#include <functional>

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/client/dna_feed.h"
    #include "../../p2p/p2p_transport.h"
    #include "../../crypto/utils/qgp_types.h"
    #include "../../crypto/utils/qgp_platform.h"
}

namespace FeedScreen {

// Get DHT context from app state
static dht_context_t* getDhtContext(AppState& state) {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        return nullptr;
    }
    return p2p_transport_get_dht_context(ctx->p2p_transport);
}

// Get private key for signing operations
static qgp_key_t* loadPrivateKey(AppState& state) {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->identity[0]) {
        return nullptr;
    }

    const char *home_dir = qgp_platform_home_dir();
    if (!home_dir) {
        return nullptr;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home_dir, ctx->identity);

    qgp_key_t *key = nullptr;
    int ret = qgp_key_load(key_path, &key);
    if (ret != 0 || !key) {
        return nullptr;
    }

    return key;
}

std::string formatTimestamp(uint64_t timestamp_ms) {
    uint64_t now_ms = (uint64_t)time(NULL) * 1000;
    uint64_t diff_ms = now_ms - timestamp_ms;
    uint64_t diff_sec = diff_ms / 1000;

    if (diff_sec < 60) {
        return "just now";
    } else if (diff_sec < 3600) {
        int mins = diff_sec / 60;
        return std::to_string(mins) + (mins == 1 ? " min ago" : " mins ago");
    } else if (diff_sec < 86400) {
        int hours = diff_sec / 3600;
        return std::to_string(hours) + (hours == 1 ? " hour ago" : " hours ago");
    } else {
        int days = diff_sec / 86400;
        return std::to_string(days) + (days == 1 ? " day ago" : " days ago");
    }
}

// Load author names from cache
static std::string getAuthorName(AppState& state, const std::string& fingerprint) {
    // Check identity name cache first
    auto it = state.identity_name_cache.find(fingerprint);
    if (it != state.identity_name_cache.end()) {
        return it->second;
    }

    // Check contact list for names (address is the fingerprint)
    for (const auto& contact : state.contacts) {
        if (contact.address == fingerprint && !contact.name.empty()) {
            state.identity_name_cache[fingerprint] = contact.name;
            return contact.name;
        }
    }

    // Return shortened fingerprint
    if (fingerprint.length() > 16) {
        std::string shortened = fingerprint.substr(0, 8) + "..." + fingerprint.substr(fingerprint.length() - 8);
        state.identity_name_cache[fingerprint] = shortened;
        return shortened;
    }
    return fingerprint;
}

void render(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();

    // Auto-load channels on first render if empty
    static bool first_render = true;
    if (first_render && state.feed_channels.empty()) {
        first_render = false;
        loadChannels(state);
    }

    if (is_mobile) {
        // Mobile: Full-screen views
        if (state.current_view == VIEW_FEED) {
            renderChannelList(state);
        } else if (state.current_view == VIEW_FEED_CHANNEL) {
            renderChannelContent(state);
        }
    } else {
        // Desktop: Side-by-side layout
        // Channel sidebar (250px)
        ImGui::BeginChild("FeedSidebar", ImVec2(250, 0), false, ImGuiWindowFlags_NoScrollbar);
        renderChannelList(state);
        ImGui::EndChild();

        ImGui::SameLine();

        // Content area
        ImGui::BeginChild("FeedContent", ImVec2(0, 0), true);
        if (state.selected_feed_channel >= 0) {
            renderChannelContent(state);
        } else {
            // No channel selected
            ImGui::Spacing();
            ImGui::Spacing();
            float text_width = ImGui::CalcTextSize("Select a channel to view posts").x;
            ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - text_width) / 2);
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(),
                              "Select a channel to view posts");
        }
        ImGui::EndChild();
    }

    // Create Channel Dialog
    if (state.show_create_channel_dialog) {
        ImGui::OpenPopup("Create Channel");
        state.show_create_channel_dialog = false;
    }

    if (ImGui::BeginPopupModal("Create Channel", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Create a new public channel");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Channel Name:");
        ImGui::InputText("##channel_name", state.create_channel_name, sizeof(state.create_channel_name));

        ImGui::Text("Description:");
        ImGui::InputTextMultiline("##channel_desc", state.create_channel_desc, sizeof(state.create_channel_desc),
                                  ImVec2(300, 60));

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Create", ImVec2(120, 0))) {
            if (strlen(state.create_channel_name) > 0) {
                // Create channel via DHT
                dht_context_t *dht_ctx = getDhtContext(state);
                qgp_key_t *key = loadPrivateKey(state);

                if (dht_ctx && key) {
                    dna_feed_channel_t *new_channel = nullptr;
                    int ret = dna_feed_channel_create(dht_ctx,
                                                       state.create_channel_name,
                                                       state.create_channel_desc,
                                                       state.current_identity.c_str(),
                                                       key->private_key,
                                                       &new_channel);
                    if (ret == 0 && new_channel) {
                        // Add to local list
                        FeedChannel ch;
                        ch.channel_id = new_channel->channel_id;
                        ch.name = new_channel->name;
                        ch.description = new_channel->description;
                        ch.creator_fp = new_channel->creator_fingerprint;
                        ch.created_at = new_channel->created_at;
                        ch.subscriber_count = 1;
                        ch.last_activity = new_channel->created_at;
                        state.feed_channels.push_back(ch);
                        dna_feed_channel_free(new_channel);

                        state.feed_status = "Channel created!";
                    } else if (ret == -2) {
                        state.feed_status = "Channel already exists";
                    } else {
                        state.feed_status = "Failed to create channel";
                    }
                    qgp_key_free(key);
                } else {
                    state.feed_status = "DHT not available";
                }

                // Clear inputs
                memset(state.create_channel_name, 0, sizeof(state.create_channel_name));
                memset(state.create_channel_desc, 0, sizeof(state.create_channel_desc));
                ImGui::CloseCurrentPopup();
            }
        }

        ImGui::SameLine();

        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            memset(state.create_channel_name, 0, sizeof(state.create_channel_name));
            memset(state.create_channel_desc, 0, sizeof(state.create_channel_desc));
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void renderChannelList(AppState& state) {
    ImVec4 theme_color = g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text();
    ImVec4 hint_color = g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint();

    // Header
    ImGui::Spacing();
    ImGui::TextColored(theme_color, ICON_FA_NEWSPAPER " Channels");
    ImGui::Separator();
    ImGui::Spacing();

    // Action buttons
    float btn_width = (ImGui::GetContentRegionAvail().x - 8) / 2;
    if (ThemedButton(ICON_FA_PLUS " Create", ImVec2(btn_width, 30), false)) {
        state.show_create_channel_dialog = true;
    }
    ImGui::SameLine();
    if (ThemedButton(ICON_FA_ARROWS_ROTATE " Refresh", ImVec2(btn_width, 30), false)) {
        loadChannels(state);
    }
    ImGui::Spacing();

    // Status message
    if (!state.feed_status.empty()) {
        ImGui::TextColored(hint_color, "%s", state.feed_status.c_str());
        ImGui::Spacing();
    }

    ImGui::Separator();
    ImGui::Spacing();

    // Channel list
    ImGui::BeginChild("ChannelListScroll", ImVec2(0, 0), false);

    if (state.feed_loading) {
        ImGui::Spacing();
        float spinner_x = (ImGui::GetContentRegionAvail().x - 30) / 2;
        ImGui::SetCursorPosX(spinner_x);
        ThemedSpinner("##loading_channels", 15.0f, 2.5f);
        ImGui::Spacing();
        float text_width = ImGui::CalcTextSize("Loading...").x;
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - text_width) / 2);
        ImGui::TextColored(hint_color, "Loading...");
    } else if (state.feed_channels.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(hint_color, "No channels yet.");
        ImGui::TextColored(hint_color, "Click 'Create' to start one!");
    } else {
        for (size_t i = 0; i < state.feed_channels.size(); i++) {
            const FeedChannel& channel = state.feed_channels[i];

            bool is_selected = (state.selected_feed_channel == (int)i);
            ImGui::PushID((int)i);

            // Channel item - use Selectable for proper hit testing
            float item_height = 50.0f;
            ImVec2 item_min = ImGui::GetCursorScreenPos();

            // Draw selection background
            if (is_selected) {
                ImVec4 bg_color = theme_color;
                bg_color.w = 0.2f;
                ImVec2 item_max = ImVec2(item_min.x + ImGui::GetContentRegionAvail().x, item_min.y + item_height);
                ImGui::GetWindowDrawList()->AddRectFilled(item_min, item_max, ImGui::ColorConvertFloat4ToU32(bg_color), 4.0f);
            }

            // Channel content in a group
            ImGui::BeginGroup();

            // Padding
            ImGui::Dummy(ImVec2(10, 8));
            ImGui::SameLine();

            // Channel icon and name
            ImGui::TextColored(theme_color, ICON_FA_HASHTAG);
            ImGui::SameLine();
            ImGui::Text("%s", channel.name.c_str());

            // Description (truncated)
            ImGui::Dummy(ImVec2(28, 0));
            ImGui::SameLine();
            std::string desc = channel.description;
            if (desc.length() > 35) {
                desc = desc.substr(0, 32) + "...";
            }
            ImGui::TextColored(hint_color, "%s", desc.c_str());

            ImGui::EndGroup();

            // Make the whole area clickable
            ImVec2 group_min = item_min;
            ImVec2 group_max = ImVec2(item_min.x + ImGui::GetContentRegionAvail().x, item_min.y + item_height);
            if (ImGui::IsMouseHoveringRect(group_min, group_max) && ImGui::IsMouseClicked(0)) {
                state.selected_feed_channel = (int)i;
                state.current_channel_id = channel.channel_id;
                state.current_view = VIEW_FEED_CHANNEL;
                loadChannelPosts(state);
            }

            // Ensure proper spacing
            ImGui::Dummy(ImVec2(0, 4));

            ImGui::PopID();
        }
    }

    ImGui::EndChild();
}

void renderChannelContent(AppState& state) {
    if (state.selected_feed_channel < 0 || state.selected_feed_channel >= (int)state.feed_channels.size()) {
        return;
    }

    const FeedChannel& channel = state.feed_channels[state.selected_feed_channel];
    ImVec4 theme_color = g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text();
    ImVec4 hint_color = g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint();
    bool is_mobile = IsMobileLayout();

    // Header
    ImGui::Spacing();

    // Back button (mobile)
    if (is_mobile) {
        if (ThemedButton(ICON_FA_ARROW_LEFT " Back", ImVec2(80, 30), false)) {
            state.current_view = VIEW_FEED;
        }
        ImGui::SameLine();
    }

    // Channel name
    ImGui::TextColored(theme_color, ICON_FA_HASHTAG " %s", channel.name.c_str());

    // Refresh button
    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_FA_ARROWS_ROTATE)) {
        loadChannelPosts(state);
    }

    ImGui::Separator();

    // Posts area
    float input_height = 80;
    ImGui::BeginChild("PostsScroll", ImVec2(0, -input_height), false);

    if (state.feed_loading) {
        // Loading spinner
        ImGui::Spacing();
        ImGui::Spacing();
        float spinner_x = (ImGui::GetContentRegionAvail().x - 40) / 2;
        ImGui::SetCursorPosX(spinner_x);
        ThemedSpinner("##loading", 20.0f, 3.0f);
        ImGui::Spacing();
        float text_width = ImGui::CalcTextSize("Loading posts...").x;
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - text_width) / 2);
        ImGui::TextColored(hint_color, "Loading posts...");
    } else if (state.feed_posts.empty()) {
        // Empty state
        ImGui::Spacing();
        ImGui::Spacing();
        float text_width = ImGui::CalcTextSize("No posts yet. Be the first to post!").x;
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - text_width) / 2);
        ImGui::TextColored(hint_color, "No posts yet. Be the first to post!");
    } else {
        // Render posts
        ImGui::Spacing();
        for (const FeedPost& post : state.feed_posts) {
            renderPostCard(state, post, false);
            ImGui::Spacing();
        }
    }

    ImGui::EndChild();

    // Post composition area
    ImGui::Separator();
    ImGui::Spacing();

    // Input field
    float send_btn_width = 60;
    ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x - send_btn_width - 8);
    ImGui::InputTextMultiline("##post_input", state.feed_post_input, sizeof(state.feed_post_input),
                              ImVec2(0, 50), ImGuiInputTextFlags_None);
    ImGui::PopItemWidth();

    ImGui::SameLine();

    // Send button
    bool can_send = strlen(state.feed_post_input) > 0 && !state.current_identity.empty();
    if (ThemedButton(ICON_FA_PAPER_PLANE, ImVec2(send_btn_width, 50), false)) {
        if (can_send) {
            // Create post via DHT
            dht_context_t *dht_ctx = getDhtContext(state);
            qgp_key_t *key = loadPrivateKey(state);

            if (dht_ctx && key) {
                dna_feed_post_t *new_post = nullptr;
                int ret = dna_feed_post_create(dht_ctx,
                                                state.current_channel_id.c_str(),
                                                state.current_identity.c_str(),
                                                state.feed_post_input,
                                                key->private_key,
                                                &new_post);
                if (ret == 0 && new_post) {
                    // Add to local posts list
                    FeedPost fp;
                    fp.post_id = new_post->post_id;
                    fp.channel_id = new_post->channel_id;
                    fp.author_fp = new_post->author_fingerprint;
                    fp.author_name = getAuthorName(state, fp.author_fp);
                    fp.text = new_post->text;
                    fp.timestamp = new_post->timestamp;
                    fp.updated = new_post->updated;
                    fp.comment_count = 0;
                    fp.upvotes = 0;
                    fp.downvotes = 0;
                    fp.user_vote = 0;
                    fp.verified = true;

                    // Add post and sort by activity
                    state.feed_posts.push_back(fp);
                    std::sort(state.feed_posts.begin(), state.feed_posts.end(),
                              [](const FeedPost &a, const FeedPost &b) {
                                  return a.updated > b.updated;
                              });

                    dna_feed_post_free(new_post);
                    state.feed_status = "Post created!";
                } else {
                    state.feed_status = "Failed to create post";
                }
                qgp_key_free(key);
            } else {
                state.feed_status = "Not signed in or DHT unavailable";
            }

            memset(state.feed_post_input, 0, sizeof(state.feed_post_input));
        }
    }

    // Character count
    int char_count = strlen(state.feed_post_input);
    int max_chars = DNA_FEED_MAX_POST_TEXT - 1;
    ImVec4 count_color = (char_count > max_chars) ? ImVec4(1, 0.3f, 0.3f, 1) : hint_color;
    ImGui::TextColored(count_color, "%d/%d", char_count, max_chars);
}

void renderPostCard(AppState& state, const FeedPost& post, bool is_reply) {
    (void)is_reply;  // No longer used
    ImVec4 theme_color = g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text();
    ImVec4 hint_color = g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint();
    ImVec4 bg_color = g_app_settings.theme == 0 ? DNATheme::Background() : ClubTheme::Background();

    // Post card background
    ImVec2 content_region = ImGui::GetContentRegionAvail();
    float card_width = content_region.x;

    ImGui::PushID(post.post_id.c_str());

    ImVec2 card_min = ImGui::GetCursorScreenPos();
    ImGui::BeginGroup();

    // Card content with background
    bg_color.w = 0.12f;
    ImVec2 padding = ImVec2(10, 8);

    // Header: Avatar placeholder + Name + Time
    ImGui::TextColored(theme_color, ICON_FA_USER);
    ImGui::SameLine();
    ImGui::Text("%s", post.author_name.empty() ? getAuthorName(const_cast<AppState&>(state), post.author_fp).c_str() : post.author_name.c_str());
    ImGui::SameLine();
    ImGui::TextColored(hint_color, "- %s", formatTimestamp(post.timestamp).c_str());

    // Verified badge
    if (post.verified) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), ICON_FA_CIRCLE_CHECK);
    }

    // Post text
    ImGui::TextWrapped("%s", post.text.c_str());

    // Action bar
    ImGui::Spacing();

    // Comments button
    char comment_label[64];
    snprintf(comment_label, sizeof(comment_label), ICON_FA_COMMENT " %d", post.comment_count);
    if (ThemedButton(comment_label, ImVec2(80, 25), false)) {
        // TODO: Expand to show comments (Phase 9)
    }
    ImGui::SameLine();

    // Voting UI
    int vote_action = renderVotingUI(const_cast<AppState&>(state), post);
    if (vote_action != 0) {
        // Cast vote via DHT
        dht_context_t *dht_ctx = getDhtContext(state);
        qgp_key_t *key = loadPrivateKey(const_cast<AppState&>(state));

        if (dht_ctx && key) {
            int ret = dna_feed_vote_cast(dht_ctx, post.post_id.c_str(),
                                          state.current_identity.c_str(),
                                          (int8_t)vote_action, key->private_key);
            if (ret == 0) {
                // Update local state
                for (auto& p : state.feed_posts) {
                    if (p.post_id == post.post_id) {
                        p.user_vote = vote_action;
                        if (vote_action == 1) p.upvotes++;
                        else p.downvotes++;
                        break;
                    }
                }
                state.feed_status = vote_action == 1 ? "Upvoted!" : "Downvoted!";
            } else if (ret == -2) {
                state.feed_status = "Already voted (votes are permanent)";
            } else {
                state.feed_status = "Failed to cast vote";
            }
            qgp_key_free(key);
        }
    }

    ImGui::EndGroup();

    // Draw card background
    ImVec2 card_max = ImGui::GetItemRectMax();
    card_max.x = card_min.x + card_width - 10;
    ImGui::GetWindowDrawList()->AddRectFilled(
        ImVec2(card_min.x - 5, card_min.y - 5),
        ImVec2(card_max.x + 5, card_max.y + 5),
        ImGui::ColorConvertFloat4ToU32(bg_color), 8.0f);

    ImGui::PopID();
}

int renderVotingUI(AppState& state, const FeedPost& post) {
    int action = 0;

    // Only allow voting if not already voted
    bool can_vote = (post.user_vote == 0) && !state.current_identity.empty();

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 4));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 4));

    // Upvote button (highlight if user upvoted)
    bool user_upvoted = (post.user_vote == 1);
    if (user_upvoted) {
        ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(50, 150, 255, 255));  // Blue highlight
    }
    std::string up_label = std::string("\xf0\x9f\x91\x8d ") + std::to_string(post.upvotes);
    if (ThemedButton(up_label.c_str(), ImVec2(60, 25), false)) {
        if (can_vote) action = 1;
    }
    if (user_upvoted) {
        ImGui::PopStyleColor();
    }

    ImGui::SameLine();

    // Downvote button (highlight if user downvoted)
    bool user_downvoted = (post.user_vote == -1);
    if (user_downvoted) {
        ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(255, 100, 100, 255));  // Red highlight
    }
    std::string down_label = std::string("\xf0\x9f\x91\x8e ") + std::to_string(post.downvotes);
    if (ThemedButton(down_label.c_str(), ImVec2(60, 25), false)) {
        if (can_vote) action = -1;
    }
    if (user_downvoted) {
        ImGui::PopStyleColor();
    }

    ImGui::SameLine();

    // Net score
    int net_score = post.upvotes - post.downvotes;
    ImVec4 score_color = net_score > 0 ? ImVec4(0.3f, 0.8f, 0.3f, 1.0f) :   // Green
                        net_score < 0 ? ImVec4(0.8f, 0.3f, 0.3f, 1.0f) :   // Red
                                       ImVec4(0.7f, 0.7f, 0.7f, 1.0f);    // Gray
    ImGui::TextColored(score_color, "Score: %+d", net_score);

    ImGui::PopStyleVar(2);

    return action;
}

void loadChannels(AppState& state) {
    dht_context_t *dht_ctx = getDhtContext(state);
    if (!dht_ctx) {
        state.feed_status = "DHT not available";
        return;
    }

    state.feed_loading = true;
    state.feed_status = "Loading channels...";
    state.feed_channels.clear();

    // Try to get registry from DHT
    dna_feed_registry_t *registry = nullptr;
    int ret = dna_feed_registry_get(dht_ctx, &registry);

    if (ret == 0 && registry && registry->channel_count > 0) {
        // Convert to GUI format
        for (size_t i = 0; i < registry->channel_count; i++) {
            FeedChannel ch;
            ch.channel_id = registry->channels[i].channel_id;
            ch.name = registry->channels[i].name;
            ch.description = registry->channels[i].description;
            ch.creator_fp = registry->channels[i].creator_fingerprint;
            ch.created_at = registry->channels[i].created_at;
            ch.subscriber_count = registry->channels[i].subscriber_count;
            ch.last_activity = registry->channels[i].last_activity;
            state.feed_channels.push_back(ch);
        }
        dna_feed_registry_free(registry);
        registry = nullptr;  // Prevent double-free
        state.feed_status = "";
    } else if (ret == -2) {
        // No registry exists - try to create default channels
        state.feed_status = "Initializing default channels...";

        qgp_key_t *key = loadPrivateKey(state);
        if (key && !state.current_identity.empty()) {
            int created = dna_feed_init_default_channels(dht_ctx,
                                                          state.current_identity.c_str(),
                                                          key->private_key);
            qgp_key_free(key);

            if (created > 0) {
                // Reload after creating defaults
                state.feed_loading = false;
                loadChannels(state);
                return;
            }
        }
        state.feed_status = "No channels available yet";
    } else {
        state.feed_status = "Failed to load channels";
    }

    if (registry) dna_feed_registry_free(registry);
    state.feed_loading = false;
}

void loadChannelPosts(AppState& state) {
    if (state.current_channel_id.empty()) return;

    dht_context_t *dht_ctx = getDhtContext(state);
    if (!dht_ctx) {
        state.feed_status = "DHT not available";
        return;
    }

    state.feed_loading = true;
    state.feed_status = "Loading posts...";
    state.feed_posts.clear();

    // Get today's posts
    dna_feed_post_t *posts = nullptr;
    size_t count = 0;
    int ret = dna_feed_posts_get_by_channel(dht_ctx, state.current_channel_id.c_str(),
                                            nullptr, &posts, &count);

    if (ret == 0 && posts && count > 0) {
        // Convert to GUI format
        for (size_t i = 0; i < count; i++) {
            FeedPost fp;
            fp.post_id = posts[i].post_id;
            fp.channel_id = posts[i].channel_id;
            fp.author_fp = posts[i].author_fingerprint;
            fp.author_name = getAuthorName(state, fp.author_fp);
            fp.text = posts[i].text;
            fp.timestamp = posts[i].timestamp;
            fp.updated = posts[i].updated;
            fp.comment_count = posts[i].comment_count;
            fp.upvotes = posts[i].upvotes;
            fp.downvotes = posts[i].downvotes;
            fp.user_vote = posts[i].user_vote;
            fp.verified = (posts[i].signature_len > 0);  // Has signature = verified
            state.feed_posts.push_back(fp);
        }
        free(posts);

        // Load votes for each post
        for (auto& post : state.feed_posts) {
            dna_feed_votes_t *votes = nullptr;
            if (dna_feed_votes_get(dht_ctx, post.post_id.c_str(), &votes) == 0 && votes) {
                post.upvotes = votes->upvote_count;
                post.downvotes = votes->downvote_count;
                post.user_vote = dna_feed_get_user_vote(votes, state.current_identity.c_str());
                dna_feed_votes_free(votes);
            }
        }

        // Sort by last activity (most recent first)
        std::sort(state.feed_posts.begin(), state.feed_posts.end(),
                  [](const FeedPost &a, const FeedPost &b) {
                      return a.updated > b.updated;
                  });

        state.feed_status = "";
    } else if (ret == -2) {
        state.feed_status = "";  // No posts is not an error
    } else {
        state.feed_status = "Failed to load posts";
    }

    state.feed_loading = false;
}

} // namespace FeedScreen
