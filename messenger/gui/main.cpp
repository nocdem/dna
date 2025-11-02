/*
 * DNA Messenger - Qt GUI
 * Main entry point
 */

#include <QApplication>
#include "MainWindow.h"
#include "IdentitySelectionDialog.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Set application metadata
    app.setApplicationName("DNA Messenger");
    app.setApplicationVersion("0.1");
    app.setOrganizationName("DNA Messenger Project");

    // Show identity selection dialog first
    IdentitySelectionDialog identityDialog;
    if (identityDialog.exec() != QDialog::Accepted) {
        // User cancelled identity selection, exit application
        return 0;
    }

    // Get selected identity
    QString selectedIdentity = identityDialog.getSelectedIdentity();
    if (selectedIdentity.isEmpty()) {
        // No identity selected, exit
        return 0;
    }

    // Create and show main window with selected identity
    MainWindow window(selectedIdentity);
    window.show();

    return app.exec();
}
