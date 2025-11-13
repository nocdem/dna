#ifndef LAYOUT_MANAGER_H
#define LAYOUT_MANAGER_H

#include "../core/app_state.h"
#include <functional>

namespace LayoutManager {
    // Render mobile layout (fullscreen view switcher + bottom nav)
    void renderMobileLayout(AppState& state, std::function<void()> render_chat_view);

    // Render desktop layout (sidebar + main content)
    void renderDesktopLayout(AppState& state,
                             std::function<void(int)> load_messages_callback,
                             std::function<void()> render_chat_view);

    // Render bottom navigation bar (mobile only)
    void renderBottomNavBar(AppState& state);
}

#endif // LAYOUT_MANAGER_H
