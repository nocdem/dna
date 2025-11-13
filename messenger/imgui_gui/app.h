#ifndef APP_H
#define APP_H

#include "imgui.h"
#include "settings_manager.h"
#include "ui_helpers.h"
#include "font_awesome.h"
#include "modal_helper.h"
#include "core/app_state.h"
#include <algorithm>
#include <cmath>
#include <cstring>

// Forward declaration for ApplyTheme
void ApplyTheme(int theme);

class DNAMessengerApp {
public:
    DNAMessengerApp() {
        // AppState constructor handles all initialization
    }

    // Main render method
    void render();

    // Check if identities are ready (scanned and DHT lookups done)
    bool areIdentitiesReady() const { return state.identities_scanned; }

private:
    // Centralized application state
    AppState state;

    // Identity helper (was static, now regular method)
    static int IdentityNameInputFilter(ImGuiInputTextCallbackData* data);

    // Render loop helpers
    void handlePostLoginEvents();
    void processPendingRegistration();
    void renderOperationSpinner();
    void renderDialogs();
};

#endif // APP_H
