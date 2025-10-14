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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ctx(nullptr) {

    // Get local identity or prompt for login
    // For now, use a simple dialog
    bool ok;
    currentIdentity = QInputDialog::getText(this, "DNA Messenger Login",
                                             "Enter your identity:",
                                             QLineEdit::Normal,
                                             "", &ok);

    if (!ok || currentIdentity.isEmpty()) {
        QMessageBox::critical(this, "Error", "Identity required to start messenger");
        QApplication::quit();
        return;
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
    // For now, just show a placeholder
    // TODO: Implement messenger_list_pubkeys() integration

    contactList->addItem("alice");
    contactList->addItem("bob");
    contactList->addItem("charlie");

    statusLabel->setText("Contacts loaded");
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

    // TODO: Load messages from database using messenger_show_conversation()
    // For now, show placeholder
    messageDisplay->append("[12:00] You: Hey there!");
    messageDisplay->append("[12:01] " + contact + ": Hi! How are you?");
    messageDisplay->append("[12:02] You: Doing great, thanks!");

    statusLabel->setText(QString("Viewing conversation with %1").arg(contact));
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
