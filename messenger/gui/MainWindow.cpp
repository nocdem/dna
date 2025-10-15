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
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QProcess>

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
        return filename.left(filename.length() - 16);  // Remove suffix (16 chars: "-dilithium.pqkey")
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
            return filename.left(filename.length() - 16);  // Remove suffix (16 chars: "-dilithium.pqkey")
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

    setWindowTitle(QString("DNA Messenger v%1 - %2").arg(PQSIGNUM_VERSION).arg(currentIdentity));
    resize(800, 600);

    // Print debug info on startup
    printf("DNA Messenger GUI v%s (commit %s)\n", PQSIGNUM_VERSION, BUILD_HASH);
    printf("Build date: %s\n", BUILD_TS);
    printf("Identity: %s\n", currentIdentity.toUtf8().constData());
}

MainWindow::~MainWindow() {
    if (ctx) {
        messenger_free(ctx);
    }
}

void MainWindow::setupUI() {
    // Create menu bar
    QMenuBar *menuBar = new QMenuBar(this);
    setMenuBar(menuBar);

    QMenu *helpMenu = menuBar->addMenu("Help");
    QAction *updateAction = helpMenu->addAction("Check for Updates");
    connect(updateAction, &QAction::triggered, this, &MainWindow::onCheckForUpdates);

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
                QString recipient = QString::fromUtf8(messages[i].recipient);
                QString timestamp = QString::fromUtf8(messages[i].timestamp);

                // Format timestamp (extract time from "YYYY-MM-DD HH:MM:SS")
                QString timeOnly = timestamp.mid(11, 5);  // Extract "HH:MM"

                // Decrypt message if current user can decrypt it
                // This includes: received messages (recipient == currentIdentity)
                // AND sent messages (sender == currentIdentity, thanks to sender-as-first-recipient)
                QString messageText = "[encrypted]";
                if (recipient == currentIdentity || sender == currentIdentity) {
                    char *plaintext = NULL;
                    size_t plaintext_len = 0;

                    if (messenger_decrypt_message(ctx, messages[i].id, &plaintext, &plaintext_len) == 0) {
                        messageText = QString::fromUtf8(plaintext, plaintext_len);
                        free(plaintext);
                    } else {
                        messageText = "[decryption failed]";
                    }
                }

                if (sender == currentIdentity) {
                    messageDisplay->append(QString("[%1] You: %2")
                                           .arg(timeOnly)
                                           .arg(messageText));
                } else {
                    messageDisplay->append(QString("[%1] %2: %3")
                                           .arg(timeOnly)
                                           .arg(sender)
                                           .arg(messageText));
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

    // Send message using messenger API (single recipient for now)
    // IMPORTANT: Store QByteArray to keep the data alive during the call
    QByteArray recipientBytes = currentContact.toUtf8();
    QByteArray messageBytes = message.toUtf8();
    const char *recipient = recipientBytes.constData();

    int result = messenger_send_message(ctx,
                                         &recipient,
                                         1,  // Single recipient
                                         messageBytes.constData());

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

void MainWindow::onCheckForUpdates() {
    QString currentVersion = QString(PQSIGNUM_VERSION);

    printf("\n========== DEBUG: Update Check ==========\n");
    printf("Current version: %s (commit %s, built %s)\n",
           PQSIGNUM_VERSION, BUILD_HASH, BUILD_TS);

    QMessageBox::information(this, "Check for Updates",
                             QString("Current version: %1\n\nChecking latest version on GitHub...").arg(currentVersion));

    // Get latest commit count from GitHub
    QProcess process;
    QString latestVersion = "unknown";

#ifdef _WIN32
    // Windows: use PowerShell with GitHub API
    // Fetch 100 commits and count them (this gives approximate version number)
    QString command = "try { "
                      "$commits = Invoke-RestMethod -Uri 'https://api.github.com/repos/nocdem/dna-messenger/commits?per_page=100' "
                      "-Headers @{'User-Agent'='DNA-Messenger'} -ErrorAction Stop; "
                      "Write-Output $commits.Count "
                      "} catch { Write-Output 'unknown' }";
    printf("Command: powershell (GitHub API - fetch 100 commits)\n");
    process.start("powershell", QStringList() << "-Command" << command);
#else
    // Linux: Use curl with GitHub API
    // Fetch 100 commits and count them
    QString command = "curl -s -H 'User-Agent: DNA-Messenger' "
                      "'https://api.github.com/repos/nocdem/dna-messenger/commits?per_page=100' 2>/dev/null | "
                      "grep -c '\"sha\"' || echo 'unknown'";

    printf("Command: curl (GitHub API - fetch 100 commits)\n");
    process.start("sh", QStringList() << "-c" << command);
#endif

    printf("Waiting for command to finish (10 second timeout)...\n");

    if (process.waitForFinished(10000)) {  // 10 second timeout
        latestVersion = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        QString errorOutput = QString::fromUtf8(process.readAllStandardError()).trimmed();
        int exitCode = process.exitCode();

        printf("Command finished:\n");
        printf("  Exit code: %d\n", exitCode);
        printf("  stdout: '%s'\n", latestVersion.toUtf8().constData());
        printf("  stderr: '%s'\n", errorOutput.toUtf8().constData());
    } else {
        printf("Command timed out!\n");
        QString errorOutput = QString::fromUtf8(process.readAllStandardError()).trimmed();
        printf("  stderr: '%s'\n", errorOutput.toUtf8().constData());
    }

    if (latestVersion == "unknown" || latestVersion.isEmpty()) {
        printf("ERROR: Failed to fetch version (result: '%s')\n", latestVersion.toUtf8().constData());
        printf("=========================================\n\n");
        QMessageBox::warning(this, "Update Check Failed",
                             "Could not fetch latest version from GitHub.\n"
                             "Make sure you have git installed and internet connection.");
        return;
    }

    printf("Successfully fetched latest version: %s\n", latestVersion.toUtf8().constData());

    // Compare versions
    bool ok;
    int currentV = currentVersion.toInt(&ok);
    if (!ok) currentV = 0;

    int latestV = latestVersion.toInt(&ok);
    if (!ok) latestV = 0;

    printf("Version comparison:\n");
    printf("  Current: %d\n", currentV);
    printf("  Latest:  %d\n", latestV);

    if (latestV > currentV) {
        printf("Result: UPDATE AVAILABLE\n");
        printf("=========================================\n\n");
        // Update available
        QMessageBox::StandardButton reply = QMessageBox::question(this, "Update Available",
                                            QString("New version available!\n\n"
                                                    "Current version: %1\n"
                                                    "Latest version:  %2\n\n"
                                                    "Do you want to update now?").arg(currentVersion, latestVersion),
                                            QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
#ifdef _WIN32
            // Windows: Launch updater script in new window and close GUI
            // The updater waits for GUI to close, then rebuilds
            QProcess::startDetached("cmd", QStringList()
                                    << "/c"
                                    << "start \"DNA Messenger Updater\" cmd /c \"C:\\dna-messenger\\update_windows.bat\"");
            QMessageBox::information(this, "Updating",
                                     "Update process started.\n\n"
                                     "DNA Messenger will now close.\n"
                                     "A command window will appear to show update progress.\n\n"
                                     "Please restart DNA Messenger when the update completes.");
            QApplication::quit();
#else
            // Linux: Update in place
            QProcess updateProcess;
            updateProcess.start("sh", QStringList()
                              << "-c"
                              << "REPO=$(git rev-parse --show-toplevel 2>/dev/null); "
                                 "if [ -n \"$REPO\" ]; then "
                                 "cd \"$REPO\" && git pull origin main && "
                                 "cd build && cmake .. && make -j$(nproc); "
                                 "else echo 'Not a git repository'; fi");

            if (updateProcess.waitForFinished(60000)) {  // 60 second timeout
                QMessageBox::information(this, "Update Complete",
                                         "Update complete!\n\n"
                                         "Please restart DNA Messenger to use the new version.");
                QApplication::quit();
            } else {
                QMessageBox::critical(this, "Update Failed",
                                      "Update failed!\n"
                                      "Make sure you're running from the git repository.");
            }
#endif
        }
    } else {
        printf("Result: UP TO DATE\n");
        printf("=========================================\n\n");
        QMessageBox::information(this, "Up to Date",
                                 QString("You are running the latest version: %1").arg(currentVersion));
    }
}
