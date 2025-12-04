#ifndef CONTACTS_SIDEBAR_H
#define CONTACTS_SIDEBAR_H

#include "../core/app_state.h"
#include <functional>

namespace ContactsSidebar {
    // Render contacts list (mobile view)
    void renderContactsList(AppState& state);

    // Render sidebar with navigation and contacts (desktop view)
    // load_messages_callback: Called when contact is clicked to load their messages
    void renderSidebar(AppState& state, std::function<void(int)> load_messages_callback);
}

#endif // CONTACTS_SIDEBAR_H
