/*
 * DNA Messenger - Qt GUI
 * Main Window
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QLabel>
#include <QStatusBar>

// Forward declarations for C API
extern "C" {
    #include "../messenger.h"
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onContactSelected(QListWidgetItem *item);
    void onSendMessage();
    void onRefreshMessages();
    void onCheckForUpdates();
    void onThemeIO();
    void onThemeClub();
    void onFontScaleSmall();
    void onFontScaleMedium();
    void onFontScaleLarge();
    void onFontScaleExtraLarge();

private:
    void setupUI();
    void loadContacts();
    void loadConversation(const QString &contact);
    QString getLocalIdentity();
    void applyTheme(const QString &themeName);
    void applyFontScale(double scale);

    // Messenger context
    messenger_context_t *ctx;
    QString currentIdentity;
    QString currentContact;

    // UI Components
    QListWidget *contactList;
    QTextEdit *messageDisplay;
    QLineEdit *messageInput;
    QPushButton *sendButton;
    QPushButton *refreshButton;
    QLabel *statusLabel;

    // Theme management
    QString currentTheme;

    // Font scale management
    double fontScale;
};

#endif // MAINWINDOW_H
