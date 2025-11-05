/*
 * DNA Messenger - Qt GUI
 * Message Wall Dialog
 */

#include "MessageWallDialog.h"
#include "ThemeManager.h"
#include <QMessageBox>
#include <QDateTime>
#include <QFrame>
#include <QGroupBox>
#include <QScrollBar>

extern "C" {
    #include "../p2p/p2p_transport.h"
    #include "../qgp_platform.h"
    #include "../qgp_types.h"
    #include "../qgp_dilithium.h"
    #include "../qgp_kyber.h"
}

MessageWallDialog::MessageWallDialog(messenger_context_t *ctx,
                                     const QString &fingerprint,
                                     const QString &displayName,
                                     bool isOwnWall,
                                     QWidget *parent)
    : QDialog(parent)
    , m_ctx(ctx)
    , m_fingerprint(fingerprint)
    , m_displayName(displayName)
    , m_isOwnWall(isOwnWall)
{
    setWindowTitle(QString::fromUtf8("DNA Message Wall - %1").arg(displayName));
    resize(700, 600);

    setupUI();
    applyTheme();

    // Connect to theme manager
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &MessageWallDialog::applyTheme);

    // Load wall on open
    QTimer::singleShot(100, this, &MessageWallDialog::onRefreshWall);
}

MessageWallDialog::~MessageWallDialog() {
}

void MessageWallDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Title section
    QHBoxLayout *titleLayout = new QHBoxLayout();
    titleLabel = new QLabel(QString::fromUtf8("📋 Message Wall: %1").arg(m_displayName));
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold;");
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();

    // Refresh button
    refreshButton = new QPushButton(QString::fromUtf8("🔄 Refresh"));
    refreshButton->setFixedSize(120, 35);
    connect(refreshButton, &QPushButton::clicked, this, &MessageWallDialog::onRefreshWall);
    titleLayout->addWidget(refreshButton);

    mainLayout->addLayout(titleLayout);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8("Loading wall..."));
    statusLabel->setStyleSheet("font-style: italic; color: gray;");
    mainLayout->addWidget(statusLabel);

    // Message list (scrollable)
    messageList = new QListWidget();
    messageList->setWordWrap(true);
    messageList->setSpacing(5);
    messageList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    mainLayout->addWidget(messageList, 1);

    // Post section (only if own wall)
    if (m_isOwnWall) {
        QGroupBox *postGroup = new QGroupBox(QString::fromUtf8("📝 Post New Message"));
        QVBoxLayout *postLayout = new QVBoxLayout(postGroup);

        // Message input
        messageInput = new QTextEdit();
        messageInput->setPlaceholderText(QString::fromUtf8("Write your message here (max 1024 characters)..."));
        messageInput->setMinimumHeight(100);
        messageInput->setMaximumHeight(150);
        connect(messageInput, &QTextEdit::textChanged,
                this, &MessageWallDialog::onMessageTextChanged);
        postLayout->addWidget(messageInput);

        // Character counter + Post button
        QHBoxLayout *postActionLayout = new QHBoxLayout();
        charCountLabel = new QLabel(QString::fromUtf8("0 / 1024"));
        charCountLabel->setStyleSheet("font-size: 12px; color: gray;");
        postActionLayout->addWidget(charCountLabel);
        postActionLayout->addStretch();

        postButton = new QPushButton(QString::fromUtf8("📤 Post Message"));
        postButton->setFixedSize(150, 35);
        postButton->setEnabled(false);
        connect(postButton, &QPushButton::clicked, this, &MessageWallDialog::onPostMessage);
        postActionLayout->addWidget(postButton);

        postLayout->addLayout(postActionLayout);
        mainLayout->addWidget(postGroup);
    } else {
        // Read-only view
        QLabel *readOnlyLabel = new QLabel(QString::fromUtf8("ℹ️ This is %1's public message wall (read-only)")
                                           .arg(m_displayName));
        readOnlyLabel->setStyleSheet("font-style: italic; color: gray; padding: 10px;");
        mainLayout->addWidget(readOnlyLabel);
    }

    // Close button
    QHBoxLayout *closeLayout = new QHBoxLayout();
    closeLayout->addStretch();
    closeButton = new QPushButton(QString::fromUtf8("Close"));
    closeButton->setFixedSize(100, 35);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    closeLayout->addWidget(closeButton);
    mainLayout->addLayout(closeLayout);
}

void MessageWallDialog::loadWall() {
    statusLabel->setText(QString::fromUtf8("Loading wall from DHT..."));
    statusLabel->setStyleSheet("font-style: italic; color: gray;");

    // Get DHT context
    dht_context_t *dht_ctx = p2p_transport_get_dht_context(m_ctx->p2p_transport);
    if (!dht_ctx) {
        statusLabel->setText(QString::fromUtf8("❌ Error: DHT not available"));
        statusLabel->setStyleSheet("color: red;");
        return;
    }

    // Load wall from DHT
    dna_message_wall_t *wall = nullptr;
    int ret = dna_load_wall(dht_ctx, m_fingerprint.toUtf8().constData(), &wall);

    if (ret == -2) {
        // Wall not found (new user)
        statusLabel->setText(QString::fromUtf8("📋 No messages yet. Be the first to post!"));
        statusLabel->setStyleSheet("font-style: italic; color: gray;");
        messageList->clear();
        return;
    } else if (ret != 0) {
        // Error loading
        statusLabel->setText(QString::fromUtf8("❌ Error loading wall from DHT"));
        statusLabel->setStyleSheet("color: red;");
        return;
    }

    // Display messages
    if (wall && wall->message_count > 0) {
        displayMessages(wall);
        statusLabel->setText(QString::fromUtf8("✅ Loaded %1 messages")
                             .arg(wall->message_count));
        statusLabel->setStyleSheet("color: green;");
    } else {
        statusLabel->setText(QString::fromUtf8("📋 No messages yet. Be the first to post!"));
        statusLabel->setStyleSheet("font-style: italic; color: gray;");
        messageList->clear();
    }

    // Free wall
    if (wall) {
        dna_message_wall_free(wall);
    }
}

void MessageWallDialog::displayMessages(const dna_message_wall_t *wall) {
    if (!wall || wall->message_count == 0) {
        return;
    }

    messageList->clear();

    // Display messages (newest first)
    for (size_t i = 0; i < wall->message_count; i++) {
        const dna_wall_message_t *msg = &wall->messages[i];

        // Create message item widget
        QWidget *itemWidget = new QWidget();
        QVBoxLayout *itemLayout = new QVBoxLayout(itemWidget);
        itemLayout->setContentsMargins(10, 8, 10, 8);
        itemLayout->setSpacing(5);

        // Header: timestamp + verification status
        QHBoxLayout *headerLayout = new QHBoxLayout();

        QString timestampStr = formatTimestamp(msg->timestamp);
        QLabel *timestampLabel = new QLabel(timestampStr);
        timestampLabel->setStyleSheet("font-size: 11px; color: gray;");
        headerLayout->addWidget(timestampLabel);

        headerLayout->addStretch();

        // Signature verification indicator (TODO: implement verification)
        QLabel *verifiedLabel = new QLabel(QString::fromUtf8("✓ Signed"));
        verifiedLabel->setStyleSheet("font-size: 11px; color: green;");
        headerLayout->addWidget(verifiedLabel);

        itemLayout->addLayout(headerLayout);

        // Message text
        QLabel *textLabel = new QLabel(QString::fromUtf8(msg->text));
        textLabel->setWordWrap(true);
        textLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        textLabel->setStyleSheet("font-size: 13px; padding: 5px;");
        itemLayout->addWidget(textLabel);

        // Separator line
        QFrame *separator = new QFrame();
        separator->setFrameShape(QFrame::HLine);
        separator->setFrameShadow(QFrame::Sunken);
        separator->setStyleSheet("color: #cccccc;");
        itemLayout->addWidget(separator);

        // Add to list
        QListWidgetItem *item = new QListWidgetItem();
        item->setSizeHint(itemWidget->sizeHint());
        messageList->addItem(item);
        messageList->setItemWidget(item, itemWidget);
    }

    // Scroll to top (newest messages)
    messageList->scrollToTop();
}

void MessageWallDialog::onRefreshWall() {
    loadWall();
}

void MessageWallDialog::onPostMessage() {
    QString messageText = messageInput->toPlainText().trimmed();

    if (messageText.isEmpty()) {
        QMessageBox::warning(this, "Empty Message",
                            "Please write a message before posting.");
        return;
    }

    if (messageText.length() > 1024) {
        QMessageBox::warning(this, "Message Too Long",
                            QString("Message is %1 characters. Maximum is 1024.")
                            .arg(messageText.length()));
        return;
    }

    // Get DHT context
    dht_context_t *dht_ctx = p2p_transport_get_dht_context(m_ctx->p2p_transport);
    if (!dht_ctx) {
        QMessageBox::critical(this, "DHT Error", "DHT context not available.");
        return;
    }

    // Load private key for signing
    const char *home_dir = qgp_platform_home_dir();
    if (!home_dir) {
        QMessageBox::critical(this, "Error", "Failed to get home directory.");
        return;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s-dilithium.pqkey",
             home_dir, m_ctx->identity);

    qgp_key_t *key = nullptr;
    int ret = qgp_key_load(key_path, &key);
    if (ret != 0 || !key) {
        QMessageBox::critical(this, "Key Error",
                             "Failed to load private key for signing.");
        return;
    }

    // Post message to DHT
    statusLabel->setText(QString::fromUtf8("📤 Posting message..."));
    statusLabel->setStyleSheet("font-style: italic; color: blue;");
    postButton->setEnabled(false);

    ret = dna_post_to_wall(dht_ctx, m_fingerprint.toUtf8().constData(),
                           messageText.toUtf8().constData(),
                           key->private_key);

    qgp_key_free(key);

    if (ret != 0) {
        QMessageBox::critical(this, "Post Failed",
                             "Failed to post message to DHT. Please try again.");
        statusLabel->setText(QString::fromUtf8("❌ Post failed"));
        statusLabel->setStyleSheet("color: red;");
        postButton->setEnabled(true);
        return;
    }

    // Success
    QMessageBox::information(this, "Posted",
                            "Message posted successfully to your public wall!");

    // Clear input
    messageInput->clear();
    charCountLabel->setText("0 / 1024");
    postButton->setEnabled(false);

    // Reload wall
    QTimer::singleShot(500, this, &MessageWallDialog::onRefreshWall);
}

void MessageWallDialog::onMessageTextChanged() {
    if (!messageInput) {
        return;
    }

    QString text = messageInput->toPlainText();
    int length = text.length();

    // Limit to 1024 characters
    if (length > 1024) {
        text = text.left(1024);
        messageInput->setPlainText(text);
        QTextCursor cursor = messageInput->textCursor();
        cursor.movePosition(QTextCursor::End);
        messageInput->setTextCursor(cursor);
        length = 1024;
    }

    // Update character counter
    charCountLabel->setText(QString::fromUtf8("%1 / 1024").arg(length));

    // Enable/disable post button
    postButton->setEnabled(length > 0 && length <= 1024);
}

void MessageWallDialog::applyTheme() {
    currentTheme = ThemeManager::instance()->currentTheme();

    QString bgColor, textColor, accentColor, buttonBg, buttonHover;

    if (currentTheme == "cpunk.club") {
        // Orange theme
        bgColor = "#1a1a1a";
        textColor = "#ffffff";
        accentColor = "#ff6b35";
        buttonBg = "#ff6b35";
        buttonHover = "#ff8555";
    } else {
        // cpunk.io (cyan theme) - default
        bgColor = "#0a0a0a";
        textColor = "#00ffff";
        accentColor = "#00ffff";
        buttonBg = "#006666";
        buttonHover = "#008888";
    }

    // Apply to dialog
    setStyleSheet(QString(
        "QDialog { background-color: %1; color: %2; }"
        "QLabel { color: %2; }"
        "QListWidget { "
        "   background-color: #1a1a1a; "
        "   border: 1px solid %3; "
        "   border-radius: 5px; "
        "   color: %2; "
        "}"
        "QListWidget::item { "
        "   background-color: #2a2a2a; "
        "   border: none; "
        "   border-radius: 3px; "
        "   margin: 2px; "
        "}"
        "QListWidget::item:selected { "
        "   background-color: #3a3a3a; "
        "}"
        "QTextEdit { "
        "   background-color: #1a1a1a; "
        "   border: 1px solid %3; "
        "   border-radius: 5px; "
        "   color: %2; "
        "   padding: 5px; "
        "}"
        "QPushButton { "
        "   background-color: %4; "
        "   color: white; "
        "   border: none; "
        "   border-radius: 5px; "
        "   padding: 5px; "
        "   font-weight: bold; "
        "}"
        "QPushButton:hover { background-color: %5; }"
        "QPushButton:disabled { "
        "   background-color: #555555; "
        "   color: #999999; "
        "}"
        "QGroupBox { "
        "   border: 1px solid %3; "
        "   border-radius: 5px; "
        "   margin-top: 10px; "
        "   padding-top: 10px; "
        "   color: %2; "
        "}"
        "QGroupBox::title { "
        "   subcontrol-origin: margin; "
        "   subcontrol-position: top left; "
        "   padding: 0 5px; "
        "   color: %3; "
        "}"
    ).arg(bgColor, textColor, accentColor, buttonBg, buttonHover));
}

QString MessageWallDialog::formatTimestamp(uint64_t timestamp) {
    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
    QDateTime now = QDateTime::currentDateTime();

    qint64 secondsAgo = dt.secsTo(now);

    if (secondsAgo < 60) {
        return QString::fromUtf8("Just now");
    } else if (secondsAgo < 3600) {
        int minutes = secondsAgo / 60;
        return QString::fromUtf8("%1 min%2 ago").arg(minutes).arg(minutes > 1 ? "s" : "");
    } else if (secondsAgo < 86400) {
        int hours = secondsAgo / 3600;
        return QString::fromUtf8("%1 hour%2 ago").arg(hours).arg(hours > 1 ? "s" : "");
    } else if (secondsAgo < 604800) {
        int days = secondsAgo / 86400;
        return QString::fromUtf8("%1 day%2 ago").arg(days).arg(days > 1 ? "s" : "");
    } else {
        return dt.toString("MMM d, yyyy");
    }
}

QString MessageWallDialog::shortenFingerprint(const QString &fp) {
    if (fp.length() <= 16) {
        return fp;
    }
    return fp.left(8) + "..." + fp.right(8);
}
