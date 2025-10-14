/*
 * DNA Messenger - Qt GUI
 * Main entry point
 */

#include <QApplication>
#include "MainWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Set application metadata
    app.setApplicationName("DNA Messenger");
    app.setApplicationVersion("0.1");
    app.setOrganizationName("DNA Messenger Project");

    MainWindow window;
    window.show();

    return app.exec();
}
