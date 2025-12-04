#ifndef MESSAGE_WALL_SCREEN_H
#define MESSAGE_WALL_SCREEN_H

#include "../core/app_state.h"
#include <string>
#include <cstdint>

namespace MessageWallScreen {
    // Format wall timestamp for display
    std::string formatWallTimestamp(uint64_t timestamp);

    // Load message wall from DHT
    void loadMessageWall(AppState& state);

    // Post message to wall
    void postToMessageWall(AppState& state);

    // Render the message wall dialog
    void render(AppState& state);
}

#endif // MESSAGE_WALL_SCREEN_H
