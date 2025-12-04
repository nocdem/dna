/*
 * DNA Feed Screen - Public Feed UI
 *
 * Main orchestrator for the public feed feature.
 * Handles channel list, post display, and composition.
 */

#ifndef FEED_SCREEN_H
#define FEED_SCREEN_H

#include "../core/app_state.h"

namespace FeedScreen {

/**
 * @brief Render the feed screen
 *
 * Handles both mobile and desktop layouts:
 * - VIEW_FEED: Shows channel list
 * - VIEW_FEED_CHANNEL: Shows selected channel's posts
 */
void render(AppState& state);

/**
 * @brief Render the channel list (sidebar or full-screen on mobile)
 */
void renderChannelList(AppState& state);

/**
 * @brief Render the channel content (posts + composition)
 */
void renderChannelContent(AppState& state);

/**
 * @brief Render a single post card
 */
void renderPostCard(AppState& state, const FeedPost& post, bool is_reply = false);

/**
 * @brief Render voting UI for a post
 *
 * @return -1 for downvote clicked, +1 for upvote clicked, 0 for no action
 */
int renderVotingUI(AppState& state, const FeedPost& post);

/**
 * @brief Load channels from DHT
 */
void loadChannels(AppState& state);

/**
 * @brief Load posts for the selected channel
 */
void loadChannelPosts(AppState& state);

/**
 * @brief Format timestamp for display
 */
std::string formatTimestamp(uint64_t timestamp_ms);

} // namespace FeedScreen

#endif // FEED_SCREEN_H
