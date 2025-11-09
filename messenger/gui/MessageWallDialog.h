/*
 * DNA Messenger - Qt GUI
 * Message Wall Dialog
 *
 * Public message board view for any user's DNA identity.
 * Messages are stored in DHT and signed with Dilithium5.
 */

#ifndef MESSAGEWALLDIALOG_H
#define MESSAGEWALLDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QScrollArea>

// Forward declarations for C API
extern "C" {
    #include "../messenger.h"
    #include "../dht/dna_message_wall.h"
}

class MessageWallDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Open message wall for a specific user
     * @param ctx Messenger context
     * @param fingerprint User's SHA3-512 fingerprint (128 hex chars)
     * @param displayName User's display name (registered name or shortened fingerprint)
     * @param isOwnWall True if viewing own wall (enables posting)
     * @param parent Parent widget
     */
    explicit MessageWallDialog(messenger_context_t *ctx,
                               const QString &fingerprint,
                               const QString &displayName,
                               bool isOwnWall,
                               QWidget *parent = nullptr);
    ~MessageWallDialog();

private slots:
    void onRefreshWall();
    void onPostMessage();
    void onMessageTextChanged();

private:
    void setupUI();
    void loadWall();
    void displayMessages(const dna_message_wall_t *wall);
    void applyTheme();
    QString formatTimestamp(uint64_t timestamp);
    QString shortenFingerprint(const QString &fp);

    // Messenger context
    messenger_context_t *m_ctx;

    // Wall info
    QString m_fingerprint;
    QString m_displayName;
    bool m_isOwnWall;

    // UI Components
    QLabel *titleLabel;
    QLabel *statusLabel;
    QListWidget *messageList;
    QTextEdit *messageInput;
    QLabel *charCountLabel;
    QPushButton *postButton;
    QPushButton *refreshButton;
    QPushButton *closeButton;

    // Current theme
    QString currentTheme;
};

#endif // MESSAGEWALLDIALOG_H
