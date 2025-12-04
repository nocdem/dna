#ifndef CHAT_SCREEN_H
#define CHAT_SCREEN_H

#include "../core/app_state.h"

namespace ChatScreen {
    // Render the main chat view with messages and input
    void render(AppState& state);

    // Retry a failed message (called from message context menu)
    void retryMessage(AppState& state, int contact_idx, int msg_idx);
}

#endif // CHAT_SCREEN_H
