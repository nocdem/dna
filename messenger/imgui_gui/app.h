#ifndef APP_H
#define APP_H

#include "imgui.h"
#include "settings_manager.h"
#include "ui_helpers.h"
#include "font_awesome.h"
#include "modal_helper.h"
#include "async_task.h"
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

    // Async tasks for DHT operations
    AsyncTask dht_publish_task;
    AsyncTask contact_lookup_task;
    AsyncTask message_poll_task;
    AsyncTask message_send_task;
    AsyncTask message_load_task;
    AsyncTask identity_scan_task;

    // Identity selection and management
    void renderIdentitySelection();
    void scanIdentities();

    // Create identity wizard
    void renderCreateIdentityStep1();
    void renderCreateIdentityStep2();
    void renderCreateIdentityStep3();
    void createIdentityWithSeed(const char* name, const char* mnemonic);

    // Restore identity wizard
    void renderRestoreStep2_Seed();
    void restoreIdentityWithSeed(const char* mnemonic);

    // Identity helper (was static, now regular method)
    static int IdentityNameInputFilter(ImGuiInputTextCallbackData* data);

    // Data loading
    void loadIdentity(const std::string& identity);
    void loadMessagesForContact(int contact_index);

    // Message polling
    void checkForNewMessages();

    // Contact management
    void renderAddContactDialog();

    // Layout managers
    void renderMobileLayout();
    void renderDesktopLayout();

    // UI Components
    void renderBottomNavBar();
    void renderContactsList();
    void renderSidebar();

    // Main views
    void renderChatView();
    void renderWalletView();
    void renderSettingsView();
};

#endif // APP_H
