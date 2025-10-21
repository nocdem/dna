/*
 * cpunk-wallet-gui - Main Entry Point
 *
 * Standalone CF20 wallet application for Cellframe blockchain
 */

#include <QApplication>
#include "WalletMainWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Set application metadata
    app.setApplicationName("cpunk Wallet");
    app.setApplicationVersion("0.1.0");
    app.setOrganizationName("cpunk");
    app.setOrganizationDomain("cpunk.io");

    WalletMainWindow window;
    window.show();

    return app.exec();
}
