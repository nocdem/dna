/*
 * DNA Messenger - Qt GUI
 * Main Window Implementation
 */

#include "MainWindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QInputDialog>
#include <QStringList>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>

// Platform-specific includes for identity detection
#ifdef _WIN32
#include <windows.h>
#else
#include <glob.h>
#endif

QString MainWindow::getLocalIdentity() {
    QDir homeDir = QDir::home();
    QDir dnaDir = QDir(homeDir.filePath(".dna"));

    if (!dnaDir.exists()) {
        return QString();  // No .dna directory
    }

#ifdef _WIN32
    // Windows: use FindFirstFile
    QString searchPath = dnaDir.filePath("*-dilithium.pqkey");
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.toUtf8().constData(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return QString();  // No identity files found
    }

    // Extract identity from filename (remove -dilithium.pqkey suffix)
    QString filename = QString::fromUtf8(findData.cFileName);
    FindClose(hFind);

    if (filename.endsWith("-dilithium.pqkey")) {
        return filename.left(filename.length() - 17);  // Remove suffix
    }
    return QString();
#else
    // Unix: use glob
    QString pattern = dnaDir.filePath("*-dilithium.pqkey");
    glob_t globResult;

    if (glob(pattern.toUtf8().constData(), GLOB_NOSORT, NULL, &globResult) == 0 && globResult.gl_pathc > 0) {
        // Extract filename from path
        QString path = QString::fromUtf8(globResult.gl_pathv[0]);
        QString filename = QFileInfo(path).fileName();

        globfree(&globResult);

        if (filename.endsWith("-dilithium.pqkey")) {
            return filename.left(filename.length() - 17);  // Remove suffix
        }
    }

    globfree(&globResult);
    return QString();
#endif
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ctx(nullptr) {

    // Auto-detect local identity
    currentIdentity = getLocalIdentity();

    if (currentIdentity.isEmpty()) {
        // No local identity found, prompt for manual entry
        bool ok;
        currentIdentity = QInputDialog::getText(this, "DNA Messenger Login",
                                                 "No local identity found.\nEnter your identity:",
                                                 QLineEdit::Normal,
                                                 "", &ok);

        if (!ok || currentIdentity.isEmpty()) {
            QMessageBox::critical(this, "Error", "Identity required to start messenger");
            QApplication::quit();
            return;
        }
    }

    // Initialize messenger context
    ctx = messenger_init(currentIdentity.toUtf8().constData());
    if (!ctx) {
        QMessageBox::critical(this, "Error",
                              QString("Failed to initialize messenger for '%1'").arg(currentIdentity));
        QApplication::quit();
        return;
    }

    setupUI();
    loadContacts();

    setWindowTitle(QString("DNA Messenger - %1").arg(currentIdentity));
    resize(800, 600);
}

MainWindow::~MainWindow() {
    if (ctx) {
        messenger_free(ctx);
    }
}

void MainWindow::setupUI() {
    // Central widget with splitter
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);

    // Left side: Contact list
    QWidget *leftPanel = new QWidget;
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);

    QLabel *contactsLabel = new QLabel("Contacts");
    contactsLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    leftLayout->addWidget(contactsLabel);

    contactList = new QListWidget;
    connect(contactList, &QListWidget::itemClicked, this, &MainWindow::onContactSelected);
    leftLayout->addWidget(contactList);

    refreshButton = new QPushButton("Refresh");
    connect(refreshButton, &QPushButton::clicked, this, &MainWindow::onRefreshMessages);
    leftLayout->addWidget(refreshButton);

    leftPanel->setLayout(leftLayout);

    // Right side: Chat area
    QWidget *rightPanel = new QWidget;
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);

    QLabel *chatLabel = new QLabel("Conversation");
    chatLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    rightLayout->addWidget(chatLabel);

    messageDisplay = new QTextEdit;
    messageDisplay->setReadOnly(true);
    rightLayout->addWidget(messageDisplay);

    // Message input area
    QHBoxLayout *inputLayout = new QHBoxLayout;
    messageInput = new QLineEdit;
    messageInput->setPlaceholderText("Type a message...");
    connect(messageInput, &QLineEdit::returnPressed, this, &MainWindow::onSendMessage);
    inputLayout->addWidget(messageInput);

    sendButton = new QPushButton("Send");
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::onSendMessage);
    inputLayout->addWidget(sendButton);

    rightLayout->addLayout(inputLayout);
    rightPanel->setLayout(rightLayout);

    // Add panels to splitter
    QSplitter *splitter = new QSplitter(Qt::Horizontal);
    splitter->addWidget(leftPanel);
    splitter->addWidget(rightPanel);
    splitter->setStretchFactor(0, 1);  // Left panel: 25%
    splitter->setStretchFactor(1, 3);  // Right panel: 75%

    mainLayout->addWidget(splitter);

    // Status bar
    statusLabel = new QLabel("Ready");
    statusBar()->addWidget(statusLabel);
}

void MainWindow::loadContacts() {
    contactList->clear();

    // Load contacts from keyserver
    char **identities = NULL;
    int count = 0;

    if (messenger_get_contact_list(ctx, &identities, &count) == 0) {
        for (int i = 0; i < count; i++) {
            contactList->addItem(QString::fromUtf8(identities[i]));
            free(identities[i]);
        }
        free(identities);

        statusLabel->setText(QString("%1 contacts loaded").arg(count));
    } else {
        statusLabel->setText("Failed to load contacts");
    }
}

void MainWindow::onContactSelected(QListWidgetItem *item) {
    if (!item) return;

    currentContact = item->text();
    loadConversation(currentContact);
}

void MainWindow::loadConversation(const QString &contact) {
    messageDisplay->clear();

    if (contact.isEmpty()) {
        return;
    }

    messageDisplay->append(QString("=== Conversation with %1 ===\n").arg(contact));

    // Load messages from database
    message_info_t *messages = NULL;
    int count = 0;

    if (messenger_get_conversation(ctx, contact.toUtf8().constData(), &messages, &count) == 0) {
        if (count == 0) {
            messageDisplay->append("(no messages exchanged)");
        } else {
            for (int i = 0; i < count; i++) {
                QString sender = QString::fromUtf8(messages[i].sender);
                QString timestamp = QString::fromUtf8(messages[i].timestamp);

                // Format timestamp (extract time from "YYYY-MM-DD HH:MM:SS")
                QString timeOnly = timestamp.mid(11, 5);  // Extract "HH:MM"

                if (sender == currentIdentity) {
                    messageDisplay->append(QString("[%1] You: [message #%2]")
                                           .arg(timeOnly)
                                           .arg(messages[i].id));
                } else {
                    messageDisplay->append(QString("[%1] %2: [message #%3]")
                                           .arg(timeOnly)
                                           .arg(sender)
                                           .arg(messages[i].id));
                }
            }
        }

        messenger_free_messages(messages, count);
        statusLabel->setText(QString("Loaded %1 messages with %2").arg(count).arg(contact));
    } else {
        messageDisplay->append("Failed to load conversation");
        statusLabel->setText("Error loading conversation");
    }
}

void MainWindow::onSendMessage() {
    if (currentContact.isEmpty()) {
        QMessageBox::warning(this, "No Contact Selected",
                             "Please select a contact from the list first");
        return;
    }

    QString message = messageInput->text().trimmed();
    if (message.isEmpty()) {
        return;
    }

    // Send message using messenger API
    int result = messenger_send_message(ctx,
                                         currentContact.toUtf8().constData(),
                                         message.toUtf8().constData());

    if (result == 0) {
        // Success - add to display
        QString timestamp = QDateTime::currentDateTime().toString("HH:mm");
        messageDisplay->append(QString("[%1] You: %2").arg(timestamp, message));
        messageInput->clear();
        statusLabel->setText("Message sent");
    } else {
        QMessageBox::critical(this, "Send Failed",
                              "Failed to send message. Check console for details.");
        statusLabel->setText("Message send failed");
    }
}

void MainWindow::onRefreshMessages() {
    if (!currentContact.isEmpty()) {
        loadConversation(currentContact);
    }
    statusLabel->setText("Messages refreshed");
}
