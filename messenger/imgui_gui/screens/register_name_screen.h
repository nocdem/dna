#ifndef REGISTER_NAME_SCREEN_H
#define REGISTER_NAME_SCREEN_H

#include "../core/app_state.h"

// Forward declare DNAMessengerApp class
class DNAMessengerApp;

namespace RegisterNameScreen {
    // Check if name is available in DHT
    void checkNameAvailability(AppState& state);

    // Register the name in DHT
    void registerName(AppState& state);

    // Render the register name dialog
    void render(AppState& state);
}

#endif // REGISTER_NAME_SCREEN_H
