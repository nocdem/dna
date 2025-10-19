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
#include <QTimer>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QSoundEffect>

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
    void onAttachImage();  // Attach image to message
    void onToggleFullscreen();  // NEW: Toggle fullscreen mode
    void onThemeIO();
    void onThemeClub();
    void onFontScaleSmall();
    void onFontScaleMedium();
    void onFontScaleLarge();
    void onFontScaleExtraLarge();
    void onMinimizeWindow();
    void onCloseWindow();
    void checkForNewMessages();
    void checkForStatusUpdates();
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onAddRecipients();
    void onCreateGroup();
    void onGroupSettings();
    void onManageGroupMembers();
    void onUserMenuClicked();
    void onLogout();
    void onManageIdentities();
    void onWallet();
    void onWalletSelected(const QString &walletName);  // NEW: Open specific wallet
    void refreshWalletMenu();  // NEW: Populate wallet submenu

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;  // For fullscreen ESC key
    void keyPressEvent(QKeyEvent *event) override;  // For F11 fullscreen toggle

private:
    void setupUI();
    void loadContacts();
    void loadConversation(const QString &contact);
    void loadGroupConversation(int groupId);
    QString getLocalIdentity();
    void applyTheme(const QString &themeName);
    void applyFontScale(double scale);
    int scaledIconSize(int baseSize) const;  // Helper for icon scaling
    QString processMessageForDisplay(const QString &messageText);  // NEW: Process images in message
    QString imageToBase64(const QString &imagePath);  // NEW: Convert image to base64

    // Contact/Group item type
    enum ContactType {
        TYPE_CONTACT,
        TYPE_GROUP
    };

    struct ContactItem {
        ContactType type;
        QString name;
        int groupId;  // Only used for groups
    };

    // Messenger context
    messenger_context_t *ctx;
    QString currentIdentity;
    QString currentContact;
    int currentGroupId;
    ContactType currentContactType;

    // UI Components
    QListWidget *contactList;
    QTextEdit *messageDisplay;
    QLineEdit *messageInput;
    QPushButton *sendButton;
    QPushButton *refreshButton;
    QPushButton *addRecipientsButton;
    QPushButton *createGroupButton;
    QPushButton *groupSettingsButton;
    QPushButton *userMenuButton;
    QPushButton *attachImageButton;  // Attach image button
    QLabel *statusLabel;
    QLabel *recipientsLabel;

    // System tray
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;

    // Wallet menu
    QMenu *walletMenu;

    // Fullscreen state
    bool isFullscreen;
    QRect normalGeometry;  // Store window geometry before fullscreen

    // Theme management
    QString currentTheme;

    // Font scale management
    double fontScale;

    // Notification system
    QTimer *pollTimer;
    QTimer *statusPollTimer;
    int lastCheckedMessageId;
    QSoundEffect *notificationSound;

    // Multi-recipient support
    QStringList additionalRecipients;

    // Contact/Group mapping
    QMap<QString, ContactItem> contactItems;
};

#endif // MAINWINDOW_H
