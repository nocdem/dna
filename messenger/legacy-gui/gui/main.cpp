/*
 * DNA Messenger - Qt GUI
 * Main entry point
 */

#include <QApplication>
#include <QMessageBox>
#include "MainWindow.h"
#include "IdentitySelectionDialog.h"

// C linkage for global DHT singleton
extern "C" {
    #include "../dht/dht_singleton.h"
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Set application metadata
    app.setApplicationName("DNA Messenger");
    app.setApplicationVersion("0.1");
    app.setOrganizationName("DNA Messenger Project");

    // Initialize global DHT singleton at app startup
    // This bootstraps DHT once for the entire application lifecycle
    // Benefits:
    // - Key publishing during identity creation works immediately
    // - Messaging starts faster (DHT already bootstrapped)
    // - Single DHT context shared by all operations
    printf("[MAIN] Initializing global DHT singleton...\n");
    if (dht_singleton_init() != 0) {
        QMessageBox::critical(
            nullptr,
            "DHT Initialization Failed",
            "Failed to initialize DHT network.\n\n"
            "Please check your internet connection and try again."
        );
        return 1;
    }
    printf("[MAIN] Global DHT ready!\n");

    // Show identity selection dialog
    IdentitySelectionDialog identityDialog;
    if (identityDialog.exec() != QDialog::Accepted) {
        // User cancelled identity selection, cleanup and exit
        dht_singleton_cleanup();
        return 0;
    }

    // Get selected identity
    QString selectedIdentity = identityDialog.getSelectedIdentity();
    if (selectedIdentity.isEmpty()) {
        // No identity selected, cleanup and exit
        dht_singleton_cleanup();
        return 0;
    }

    // Create and show main window with selected identity
    MainWindow window(selectedIdentity);
    window.show();

    int result = app.exec();

    // Cleanup global DHT singleton on app shutdown
    dht_singleton_cleanup();

    return result;
}
