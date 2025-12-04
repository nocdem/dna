#ifndef IDENTITY_SELECTION_SCREEN_H
#define IDENTITY_SELECTION_SCREEN_H

#include "../core/app_state.h"

namespace IdentitySelectionScreen {
    // Main identity selection screen
    void render(AppState& state);

    // Create identity wizard steps
    void renderCreateIdentityStep1(AppState& state);
    void renderCreateIdentityStep2(AppState& state);

    // Identity creation
    void createIdentityWithSeed(AppState& state, const char* mnemonic);

    // Restore identity wizard
    void renderRestoreStep2_Seed(AppState& state);

    // Identity restoration
    void restoreIdentityWithSeed(AppState& state, const char* mnemonic);
}

#endif // IDENTITY_SELECTION_SCREEN_H
