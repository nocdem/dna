#ifndef PROFILE_EDITOR_SCREEN_H
#define PROFILE_EDITOR_SCREEN_H

#include "../core/app_state.h"

namespace ProfileEditorScreen {
    // Load profile from DHT
    void loadProfile(AppState& state);

    // Save profile to DHT
    void saveProfile(AppState& state);

    // Render the profile editor dialog
    void render(AppState& state);
}

#endif // PROFILE_EDITOR_SCREEN_H
