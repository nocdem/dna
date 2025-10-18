/*
 * DNA Messenger - Qt GUI
 * Main Window Implementation
 */

#include "MainWindow.h"
#include <QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QMessageBox>
#include <QInputDialog>
#include <QDialog>
#include <QStringList>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QProcess>
#include <QSettings>
#include <QFontDatabase>
#include <QMouseEvent>

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
    : QMainWindow(parent), ctx(nullptr), lastCheckedMessageId(0), currentGroupId(-1), currentContactType(TYPE_CONTACT), fontScale(1.5) {  // Changed default from 3.0 to 1.5

    // Remove native window frame for custom title bar
    setWindowFlags(Qt::FramelessWindowHint);

    // Check if user has saved identity preference in QSettings
    QSettings settings("DNA Messenger", "GUI");
    QString savedIdentity = settings.value("currentIdentity").toString();

    if (!savedIdentity.isEmpty()) {
        // Use saved identity preference
        currentIdentity = savedIdentity;
    } else {
        // Auto-detect local identity from filesystem
        currentIdentity = getLocalIdentity();
    }

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

        // Save manually entered identity to settings
        settings.setValue("currentIdentity", currentIdentity);
    }

    // Initialize messenger context
    ctx = messenger_init(currentIdentity.toUtf8().constData());
    if (!ctx) {
        QMessageBox::critical(this, "Error",
                              QString("Failed to initialize messenger for '%1'").arg(currentIdentity));
        QApplication::quit();
        return;
    }

    // Load futuristic font from resources
    int fontId = QFontDatabase::addApplicationFont(":/fonts/Orbitron.ttf");
    if (fontId != -1) {
        QStringList fontFamilies = QFontDatabase::applicationFontFamilies(fontId);
        if (!fontFamilies.isEmpty()) {
            QFont orbitronFont(fontFamilies.at(0));
            QApplication::setFont(orbitronFont);
            printf("Loaded Orbitron font\n");
        }
    } else {
        printf("Failed to load Orbitron font\n");
    }

    setupUI();
    loadContacts();

    // Initialize system tray icon
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(QIcon(":/icons/dna_icon.png"));
    trayIcon->setToolTip("DNA Messenger");

    trayMenu = new QMenu(this);
    trayMenu->addAction("Show", this, &MainWindow::show);
    trayMenu->addAction("Exit", qApp, &QApplication::quit);
    trayIcon->setContextMenu(trayMenu);

    connect(trayIcon, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayIconActivated);

    trayIcon->show();

    // Initialize notification sound
    notificationSound = new QSoundEffect(this);
    notificationSound->setSource(QUrl("qrc:/sounds/message.wav"));
    notificationSound->setVolume(0.5);

    // Initialize polling timer (5 seconds)
    pollTimer = new QTimer(this);
    connect(pollTimer, &QTimer::timeout, this, &MainWindow::checkForNewMessages);
    pollTimer->start(5000);

    // Initialize status polling timer (10 seconds)
    statusPollTimer = new QTimer(this);
    connect(statusPollTimer, &QTimer::timeout, this, &MainWindow::checkForStatusUpdates);
    statusPollTimer->start(10000);

    // Save current identity (reuse settings from earlier)
    settings.setValue("currentIdentity", currentIdentity);  // Save logged-in user
    QString savedTheme = settings.value("theme", "io").toString();  // Default to "io" theme
    double savedFontScale = settings.value("fontScale", 1.5).toDouble();  // Default to 1.5x (Medium)

    applyTheme(savedTheme);
    applyFontScale(savedFontScale);

    // Scale window to 60% of screen size (reduced from 80%)
    QScreen *screen = QGuiApplication::primaryScreen();
    QRect screenGeometry = screen->availableGeometry();
    int width = screenGeometry.width() * 0.6;
    int height = screenGeometry.height() * 0.6;
    resize(width, height);

    // Center window on screen
    move(screenGeometry.center() - rect().center());

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
    // Create custom title bar
    titleBar = new QWidget(this);
    titleBar->setFixedHeight(60);
    titleBar->setStyleSheet(
        "QWidget {"
        "   background: #0D3438;"
        "   border-bottom: 2px solid #00D9FF;"
        "}"
    );

    QHBoxLayout *titleLayout = new QHBoxLayout(titleBar);
    titleLayout->setContentsMargins(20, 0, 0, 0);
    titleLayout->setSpacing(10);

    // Title label (version + username)
    titleLabel = new QLabel(QString("DNA Messenger v%1 - %2").arg(PQSIGNUM_VERSION).arg(currentIdentity), titleBar);
    titleLabel->setStyleSheet(
        "font-family: 'Orbitron';"
        "font-size: 48px;"
        "font-weight: bold;"
        "color: #00D9FF;"
        "background: transparent;"
        "border: none;"
    );
    titleLayout->addWidget(titleLabel);

    titleLayout->addStretch();

    // Minimize button
    minimizeButton = new QPushButton(titleBar);
    minimizeButton->setIcon(QIcon(":/icons/minimize.svg"));
    minimizeButton->setIconSize(QSize(scaledIconSize(24), scaledIconSize(24)));
    minimizeButton->setToolTip("Minimize");
    int buttonSize = static_cast<int>(50 * fontScale);
    minimizeButton->setFixedSize(buttonSize, buttonSize);
    minimizeButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 10px;"
        "   font-family: 'Orbitron';"
        "   font-size: 24px;"
        "   font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.3);"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.4);"
        "}"
    );
    connect(minimizeButton, &QPushButton::clicked, this, &MainWindow::onMinimizeWindow);
    titleLayout->addWidget(minimizeButton);

    // Close button
    closeButton = new QPushButton(titleBar);
    closeButton->setIcon(QIcon(":/icons/close.svg"));
    closeButton->setIconSize(QSize(scaledIconSize(24), scaledIconSize(24)));
    closeButton->setToolTip("Close");
    closeButton->setFixedSize(buttonSize, buttonSize);
    closeButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(255, 107, 53, 0.3);"
        "   color: #FF6B35;"
        "   border: 2px solid #FF6B35;"
        "   border-radius: 10px;"
        "   font-family: 'Orbitron';"
        "   font-size: 24px;"
        "   font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(255, 107, 53, 0.5);"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(255, 107, 53, 0.7);"
        "}"
    );
    connect(closeButton, &QPushButton::clicked, this, &MainWindow::onCloseWindow);
    titleLayout->addWidget(closeButton);

    titleBar->setLayout(titleLayout);

    // Set cpunk.io theme - dark teal with cyan accents
    setStyleSheet(
        "QMainWindow {"
        "   background: qlineargradient(x1:0, y1:0, x2:1, y2:1, "
        "       stop:0 #0A2A2E, stop:1 #0D3438);"
        "}"
        "QMenuBar {"
        "   background: #0D3438;"
        "   color: #00D9FF;"
        "   padding: 8px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "   border-bottom: 2px solid #00D9FF;"
        "}"
        "QMenuBar::item {"
        "   padding: 8px 15px;"
        "   color: #00D9FF;"
        "}"
        "QMenuBar::item:selected {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   border-radius: 5px;"
        "}"
        "QMenu {"
        "   background: #0D3438;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 10px;"
        "   padding: 8px;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "   color: #00D9FF;"
        "}"
        "QMenu::item {"
        "   padding: 10px 20px;"
        "   color: #00D9FF;"
        "}"
        "QMenu::item:selected {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   border-radius: 5px;"
        "}"
        "QStatusBar {"
        "   background: #0D3438;"
        "   color: #00D9FF;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "   padding: 8px;"
        "   border-top: 2px solid #00D9FF;"
        "}"
    );

    // Create menu bar (not using setMenuBar to keep it below title bar)
    QMenuBar *menuBar = new QMenuBar();

    // Settings menu
    QMenu *settingsMenu = menuBar->addMenu(QString::fromUtf8("Settings"));

    // Theme submenu
    QMenu *themeMenu = settingsMenu->addMenu(QString::fromUtf8("Theme"));
    QAction *themeIOAction = themeMenu->addAction(QString::fromUtf8("cpunk.io (Cyan)"));
    QAction *themeClubAction = themeMenu->addAction(QString::fromUtf8("cpunk.club (Orange)"));
    connect(themeIOAction, &QAction::triggered, this, &MainWindow::onThemeIO);
    connect(themeClubAction, &QAction::triggered, this, &MainWindow::onThemeClub);

    // Font Scale submenu
    QMenu *fontScaleMenu = settingsMenu->addMenu(QString::fromUtf8("Font Scale"));
    QAction *fontSmallAction = fontScaleMenu->addAction(QString::fromUtf8("Small (1x)"));
    QAction *fontMediumAction = fontScaleMenu->addAction(QString::fromUtf8("Medium (2x)"));
    QAction *fontLargeAction = fontScaleMenu->addAction(QString::fromUtf8("Large (3x)"));
    QAction *fontExtraLargeAction = fontScaleMenu->addAction(QString::fromUtf8("Extra Large (4x)"));
    connect(fontSmallAction, &QAction::triggered, this, &MainWindow::onFontScaleSmall);
    connect(fontMediumAction, &QAction::triggered, this, &MainWindow::onFontScaleMedium);
    connect(fontLargeAction, &QAction::triggered, this, &MainWindow::onFontScaleLarge);
    connect(fontExtraLargeAction, &QAction::triggered, this, &MainWindow::onFontScaleExtraLarge);

    // Wallet menu
    QMenu *walletMenu = menuBar->addMenu(QString::fromUtf8("Wallet"));
    QAction *walletAction = walletMenu->addAction(QString::fromUtf8("Open Wallet"));
    connect(walletAction, &QAction::triggered, this, &MainWindow::onWallet);

    // Help menu
    QMenu *helpMenu = menuBar->addMenu(QString::fromUtf8("Help"));
    QAction *updateAction = helpMenu->addAction(QString::fromUtf8("Check for Updates"));
    connect(updateAction, &QAction::triggered, this, &MainWindow::onCheckForUpdates);

    // Central widget with vertical layout for title bar + content
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *mainVerticalLayout = new QVBoxLayout(centralWidget);
    mainVerticalLayout->setContentsMargins(0, 0, 0, 0);
    mainVerticalLayout->setSpacing(0);

    // Add title bar at the top
    mainVerticalLayout->addWidget(titleBar);

    // Add menu bar below title bar
    mainVerticalLayout->addWidget(menuBar);

    // Content widget for the splitter
    QWidget *contentWidget = new QWidget;
    QHBoxLayout *mainLayout = new QHBoxLayout(contentWidget);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // Left side: Contact list
    QWidget *leftPanel = new QWidget;
    leftPanel->setStyleSheet(
        "QWidget {"
        "   background: #0A2A2E;"
        "   border-radius: 15px;"
        "   padding: 10px;"
        "}"
    );
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);

    QLabel *contactsLabel = new QLabel(QString::fromUtf8("Contacts"));
    contactsLabel->setStyleSheet(
        "font-weight: bold; "
        "font-family: 'Orbitron'; font-size: 72px; "
        "color: #00D9FF; "
        "background: transparent; "
        "padding: 10px;"
    );

    // User menu button at very top
    userMenuButton = new QPushButton(currentIdentity);
    userMenuButton->setIcon(QIcon(":/icons/user.svg"));
    userMenuButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    userMenuButton->setToolTip("User Menu");
    userMenuButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.15);"
        "   color: #00D9FF;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 15px;"
        "   padding: 15px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "   text-align: left;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.25);"
        "   border: 2px solid #33E6FF;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.35);"
        "   border: 2px solid #00D9FF;"
        "}"
    );
    connect(userMenuButton, &QPushButton::clicked, this, &MainWindow::onUserMenuClicked);
    leftLayout->addWidget(userMenuButton);

    leftLayout->addWidget(contactsLabel);

    contactList = new QListWidget;
    contactList->setStyleSheet(
        "QListWidget {"
        "   background: #0D3438;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 10px;"
        "   padding: 8px;"
        "   font-family: 'Orbitron'; font-size: 54px;"
        "   color: #00D9FF;"
        "}"
        "QListWidget::item {"
        "   background: rgba(0, 217, 255, 0.1);"
        "   border: 1px solid rgba(0, 217, 255, 0.3);"
        "   border-radius: 10px;"
        "   padding: 15px;"
        "   margin: 5px;"
        "   color: #00D9FF;"
        "}"
        "QListWidget::item:hover {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   border: 2px solid #00D9FF;"
        "}"
        "QListWidget::item:selected {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   color: #FFFFFF;"
        "   font-weight: bold;"
        "   border: 2px solid #00D9FF;"
        "}"
    );
    connect(contactList, &QListWidget::itemClicked, this, &MainWindow::onContactSelected);
    leftLayout->addWidget(contactList);

    refreshButton = new QPushButton("Refresh");
    refreshButton->setIcon(QIcon(":/icons/refresh.svg"));
    refreshButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    refreshButton->setToolTip("Refresh messages");
    refreshButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 15px;"
        "   padding: 15px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 54px;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   border: 2px solid #33E6FF;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.4);"
        "   border: 2px solid #00D9FF;"
        "}"
    );
    connect(refreshButton, &QPushButton::clicked, this, &MainWindow::onRefreshMessages);
    leftLayout->addWidget(refreshButton);

    // Create Group button
    createGroupButton = new QPushButton("Create Group");
    createGroupButton->setIcon(QIcon(":/icons/group.svg"));
    createGroupButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    createGroupButton->setToolTip("Create a new group");
    createGroupButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 15px;"
        "   padding: 15px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   border: 2px solid #33E6FF;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.4);"
        "   border: 2px solid #00D9FF;"
        "}"
    );
    connect(createGroupButton, &QPushButton::clicked, this, &MainWindow::onCreateGroup);
    leftLayout->addWidget(createGroupButton);

    // Group Settings button (initially hidden, shown when group selected)
    groupSettingsButton = new QPushButton("Group Settings");
    groupSettingsButton->setIcon(QIcon(":/icons/settings.svg"));
    groupSettingsButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    groupSettingsButton->setToolTip("Manage group settings");
    groupSettingsButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(255, 140, 66, 0.2);"
        "   color: #FF8C42;"
        "   border: 2px solid #FF8C42;"
        "   border-radius: 15px;"
        "   padding: 15px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(255, 140, 66, 0.3);"
        "   border: 2px solid #FFB380;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(255, 140, 66, 0.4);"
        "   border: 2px solid #FF8C42;"
        "}"
    );
    connect(groupSettingsButton, &QPushButton::clicked, this, &MainWindow::onGroupSettings);
    groupSettingsButton->setVisible(false);  // Hidden by default
    leftLayout->addWidget(groupSettingsButton);

    leftPanel->setLayout(leftLayout);

    // Right side: Chat area
    QWidget *rightPanel = new QWidget;
    rightPanel->setStyleSheet(
        "QWidget {"
        "   background: #0A2A2E;"
        "   border-radius: 15px;"
        "   padding: 10px;"
        "}"
    );
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);

    QLabel *chatLabel = new QLabel(QString::fromUtf8("Conversation"));
    chatLabel->setStyleSheet(
        "font-weight: bold; "
        "font-family: 'Orbitron'; font-size: 72px; "
        "color: #00D9FF; "
        "background: transparent; "
        "padding: 10px;"
    );
    rightLayout->addWidget(chatLabel);

    messageDisplay = new QTextEdit;
    messageDisplay->setReadOnly(true);
    messageDisplay->setStyleSheet(
        "QTextEdit {"
        "   background: #0D3438;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 10px;"
        "   padding: 15px;"
        "   font-family: 'Orbitron'; font-size: 48px;"
        "   color: #00D9FF;"
        "}"
    );
    rightLayout->addWidget(messageDisplay);

    // Recipients label
    recipientsLabel = new QLabel(QString::fromUtf8("To: ..."));
    recipientsLabel->setStyleSheet(
        "QLabel {"
        "   background: rgba(0, 217, 255, 0.1);"
        "   color: #00D9FF;"
        "   border: 2px solid rgba(0, 217, 255, 0.3);"
        "   border-radius: 10px;"
        "   padding: 10px 15px;"
        "   font-family: 'Orbitron'; font-size: 42px;"
        "}"
    );
    rightLayout->addWidget(recipientsLabel);

    // Recipients button row
    QHBoxLayout *recipientsButtonLayout = new QHBoxLayout;
    recipientsButtonLayout->addStretch();

    addRecipientsButton = new QPushButton("Add Recipients");
    addRecipientsButton->setIcon(QIcon(":/icons/add.svg"));
    addRecipientsButton->setIconSize(QSize(scaledIconSize(18), scaledIconSize(18)));
    addRecipientsButton->setToolTip("Add recipients to your message");
    addRecipientsButton->setStyleSheet(
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 12px;"
        "   padding: 10px 20px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 42px;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   border: 2px solid #33E6FF;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.4);"
        "   border: 2px solid #00D9FF;"
        "}"
    );
    connect(addRecipientsButton, &QPushButton::clicked, this, &MainWindow::onAddRecipients);
    recipientsButtonLayout->addWidget(addRecipientsButton);

    rightLayout->addLayout(recipientsButtonLayout);

    // Message input area
    QHBoxLayout *inputLayout = new QHBoxLayout;
    messageInput = new QLineEdit;
    messageInput->setPlaceholderText(QString::fromUtf8("Type a message..."));
    messageInput->setStyleSheet(
        "QLineEdit {"
        "   background: #0D3438;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 15px;"
        "   padding: 15px 20px;"
        "   font-family: 'Orbitron'; font-size: 54px;"
        "   color: #00D9FF;"
        "}"
        "QLineEdit:focus {"
        "   border: 2px solid #33E6FF;"
        "   background: rgba(0, 217, 255, 0.1);"
        "}"
    );
    connect(messageInput, &QLineEdit::returnPressed, this, &MainWindow::onSendMessage);
    inputLayout->addWidget(messageInput);

    sendButton = new QPushButton("Send");
    sendButton->setIcon(QIcon(":/icons/send.svg"));
    sendButton->setIconSize(QSize(scaledIconSize(18), scaledIconSize(18)));
    sendButton->setToolTip("Send message");
    sendButton->setStyleSheet(
        "QPushButton {"
        "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "       stop:0 #FF6B35, stop:1 #FF8C42);"
        "   color: white;"
        "   border: 2px solid #FF6B35;"
        "   border-radius: 15px;"
        "   padding: 15px 30px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 54px;"
        "}"
        "QPushButton:hover {"
        "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "       stop:0 #FF8C42, stop:1 #FFA55C);"
        "   border: 2px solid #FF8C42;"
        "}"
        "QPushButton:pressed {"
        "   background: #FF5722;"
        "   border: 2px solid #E64A19;"
        "}"
    );
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::onSendMessage);
    inputLayout->addWidget(sendButton);

    rightLayout->addLayout(inputLayout);
    rightPanel->setLayout(rightLayout);

    // Add panels to splitter
    QSplitter *splitter = new QSplitter(Qt::Horizontal);
    splitter->setStyleSheet(
        "QSplitter::handle {"
        "   background: #00D9FF;"
        "   width: 3px;"
        "}"
    );
    splitter->addWidget(leftPanel);
    splitter->addWidget(rightPanel);
    splitter->setStretchFactor(0, 1);  // Left panel: 25%
    splitter->setStretchFactor(1, 3);  // Right panel: 75%

    mainLayout->addWidget(splitter);
    contentWidget->setLayout(mainLayout);

    // Add content to main vertical layout with stretch factor to fill remaining space
    mainVerticalLayout->addWidget(contentWidget, 1);

    // Status bar
    statusLabel = new QLabel(QString::fromUtf8("Ready"));
    statusBar()->addWidget(statusLabel);
}

void MainWindow::loadContacts() {
    contactList->clear();
    contactItems.clear();

    int totalItems = 0;

    // Load contacts from keyserver
    char **identities = NULL;
    int contactCount = 0;

    if (messenger_get_contact_list(ctx, &identities, &contactCount) == 0) {
        for (int i = 0; i < contactCount; i++) {
            QString identity = QString::fromUtf8(identities[i]);
            QString displayText = QString::fromUtf8("") + identity;
            contactList->addItem(displayText);

            // Store contact metadata
            ContactItem item;
            item.type = TYPE_CONTACT;
            item.name = identity;
            item.groupId = -1;
            contactItems[displayText] = item;

            free(identities[i]);
            totalItems++;
        }
        free(identities);
    }

    // Load groups
    group_info_t *groups = NULL;
    int groupCount = 0;

    if (messenger_get_groups(ctx, &groups, &groupCount) == 0) {
        for (int i = 0; i < groupCount; i++) {
            QString groupName = QString::fromUtf8(groups[i].name);
            QString displayText = QString::fromUtf8("") + groupName;
            contactList->addItem(displayText);

            // Store group metadata
            ContactItem item;
            item.type = TYPE_GROUP;
            item.name = groupName;
            item.groupId = groups[i].id;
            contactItems[displayText] = item;

            totalItems++;
        }
        messenger_free_groups(groups, groupCount);
    }

    if (totalItems > 0) {
        statusLabel->setText(QString::fromUtf8("%1 contact(s) and %2 group(s) loaded")
                             .arg(contactCount).arg(groupCount));
    } else {
        statusLabel->setText(QString::fromUtf8("No contacts or groups found"));
    }
}

void MainWindow::onContactSelected(QListWidgetItem *item) {
    if (!item) return;

    QString itemText = item->text();

    // Look up item metadata
    if (!contactItems.contains(itemText)) {
        return;
    }

    ContactItem contactItem = contactItems[itemText];
    currentContactType = contactItem.type;

    // Clear additional recipients when selecting a new item
    additionalRecipients.clear();

    if (contactItem.type == TYPE_CONTACT) {
        // Handle contact selection
        currentContact = contactItem.name;
        currentGroupId = -1;

        // Hide Group Settings button for contacts
        groupSettingsButton->setVisible(false);

        // Update recipients label
        recipientsLabel->setText(QString::fromUtf8("To: ") + currentContact);

        // Mark all messages from this contact as read
        messenger_mark_conversation_read(ctx, currentContact.toUtf8().constData());

        loadConversation(currentContact);
    } else if (contactItem.type == TYPE_GROUP) {
        // Handle group selection
        currentContact.clear();
        currentGroupId = contactItem.groupId;

        // Show Group Settings button for groups
        groupSettingsButton->setVisible(true);

        // Update recipients label
        recipientsLabel->setText(QString::fromUtf8("To: Group - ") + contactItem.name);

        loadGroupConversation(currentGroupId);
    }
}

void MainWindow::loadConversation(const QString &contact) {
    messageDisplay->clear();

    if (contact.isEmpty()) {
        return;
    }

    // Calculate font sizes for message bubbles
    int headerFontSize = static_cast<int>(24 * fontScale);
    int metaFontSize = static_cast<int>(13 * fontScale);
    int messageFontSize = static_cast<int>(18 * fontScale);

    // Cute header with emoji - cpunk.io theme
    messageDisplay->setHtml(QString(
        "<div style='text-align: center; background: rgba(0, 217, 255, 0.2); "
        "padding: 15px; border-radius: 15px; margin-bottom: 15px; border: 2px solid #00D9FF;'>"
        "<span style='font-family: 'Orbitron'; font-size: %1px; font-weight: bold; color: #00D9FF;'>%2 Conversation with %3 %4</span>"
        "</div>"
    ).arg(headerFontSize + 18).arg(QString::fromUtf8(""), contact));

    // Load messages from database
    message_info_t *messages = NULL;
    int count = 0;

    if (messenger_get_conversation(ctx, contact.toUtf8().constData(), &messages, &count) == 0) {
        if (count == 0) {
            messageDisplay->append(QString(
                "<div style='text-align: center; color: rgba(0, 217, 255, 0.6); padding: 30px; font-style: italic; font-family: 'Orbitron'; font-size: %1px;'>"
                "%2"
                "</div>"
            ).arg(messageFontSize).arg(QString::fromUtf8("💭 No messages yet. Start the conversation!")));
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
                        messageText = QString::fromUtf8("🔒 [decryption failed]");
                    }
                }

                if (sender == currentIdentity) {
                    // Generate status checkmark
                    QString statusCheckmark;
                    QString status = messages[i].status ? QString::fromUtf8(messages[i].status) : "sent";

                    if (status == "read") {
                        // Double checkmark colored (theme-aware)
                        if (currentTheme == "club") {
                            statusCheckmark = QString::fromUtf8("<span style='color: #FF8C42;'>✓✓</span>");
                        } else {
                            statusCheckmark = QString::fromUtf8("<span style='color: #00D9FF;'>✓✓</span>");
                        }
                    } else if (status == "delivered") {
                        // Double checkmark gray
                        statusCheckmark = QString::fromUtf8("<span style='color: #888888;'>✓✓</span>");
                    } else {
                        // Single checkmark gray (sent)
                        statusCheckmark = QString::fromUtf8("<span style='color: #888888;'>✓</span>");
                    }

                    // Sent messages - theme-aware bubble aligned right
                    QString sentBubble;
                    if (currentTheme == "club") {
                        // cpunk.club: orange gradient
                        sentBubble = QString(
                            "<div style='text-align: right; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF8C42, stop:1 #FFB380); "
                            "color: white; padding: 15px 20px; border-radius: 20px 20px 5px 20px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid #FF8C42;'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 You %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    } else {
                        // cpunk.io: cyan gradient (default)
                        sentBubble = QString(
                            "<div style='text-align: right; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00D9FF, stop:1 #0D8B9C); "
                            "color: white; padding: 15px 20px; border-radius: 20px 20px 5px 20px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid #00D9FF;'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 You %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    }
                    messageDisplay->append(sentBubble);
                } else {
                    // Received messages - theme-aware bubble aligned left
                    QString receivedBubble;
                    if (currentTheme == "club") {
                        // cpunk.club: darker brown/orange
                        receivedBubble = QString(
                            "<div style='text-align: left; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2B1F16, stop:1 #3D2B1F); "
                            "color: #FFB380; padding: 15px 20px; border-radius: 20px 20px 20px 5px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid rgba(255, 140, 66, 0.5);'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    } else {
                        // cpunk.io: darker teal (default)
                        receivedBubble = QString(
                            "<div style='text-align: left; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0D3438, stop:1 #0A5A62); "
                            "color: #00D9FF; padding: 15px 20px; border-radius: 20px 20px 20px 5px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid rgba(0, 217, 255, 0.5);'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    }
                    messageDisplay->append(receivedBubble);
                }
            }
        }

        messenger_free_messages(messages, count);
        statusLabel->setText(QString::fromUtf8("Loaded %1 messages with %2").arg(count).arg(contact));
    } else {
        messageDisplay->append(QString(
            "<div style='text-align: center; color: #FF6B35; padding: 20px; font-family: 'Orbitron'; font-size: %1px; font-weight: bold;'>"
            "%2"
            "</div>"
        ).arg(messageFontSize).arg(QString::fromUtf8("Failed to load conversation")));
        statusLabel->setText(QString::fromUtf8("Error loading conversation"));
    }
}

void MainWindow::loadGroupConversation(int groupId) {
    messageDisplay->clear();

    if (groupId < 0) {
        return;
    }

    // Calculate font sizes for message bubbles
    int headerFontSize = static_cast<int>(24 * fontScale);
    int metaFontSize = static_cast<int>(13 * fontScale);
    int messageFontSize = static_cast<int>(18 * fontScale);

    // Get group info for header
    group_info_t groupInfo;
    if (messenger_get_group_info(ctx, groupId, &groupInfo) == 0) {
        // Display group header
        messageDisplay->setHtml(QString(
            "<div style='text-align: center; background: rgba(0, 217, 255, 0.2); "
            "padding: 15px; border-radius: 15px; margin-bottom: 15px; border: 2px solid #00D9FF;'>"
            "<span style='font-family: 'Orbitron'; font-size: %1px; font-weight: bold; color: #00D9FF;'>%2 Group: %3 %4</span>"
            "</div>"
        ).arg(headerFontSize + 18).arg(QString::fromUtf8(""), QString::fromUtf8(groupInfo.name)));

        // Free group info strings
        free(groupInfo.name);
        if (groupInfo.description) free(groupInfo.description);
        if (groupInfo.creator) free(groupInfo.creator);
        if (groupInfo.created_at) free(groupInfo.created_at);
    } else {
        messageDisplay->setHtml(QString(
            "<div style='text-align: center; background: rgba(0, 217, 255, 0.2); "
            "padding: 15px; border-radius: 15px; margin-bottom: 15px; border: 2px solid #00D9FF;'>"
            "<span style='font-family: 'Orbitron'; font-size: %1px; font-weight: bold; color: #00D9FF;'>%2 Group Conversation %3</span>"
            "</div>"
        ).arg(headerFontSize + 18).arg(QString::fromUtf8("")));
    }

    // Load messages from database
    message_info_t *messages = NULL;
    int count = 0;

    if (messenger_get_group_conversation(ctx, groupId, &messages, &count) == 0) {
        if (count == 0) {
            messageDisplay->append(QString(
                "<div style='text-align: center; color: rgba(0, 217, 255, 0.6); padding: 30px; font-style: italic; font-family: 'Orbitron'; font-size: %1px;'>"
                "%2"
                "</div>"
            ).arg(messageFontSize).arg(QString::fromUtf8("💭 No messages yet. Start the conversation!")));
        } else {
            for (int i = 0; i < count; i++) {
                QString sender = QString::fromUtf8(messages[i].sender);
                QString timestamp = QString::fromUtf8(messages[i].timestamp);

                // Format timestamp (extract time from "YYYY-MM-DD HH:MM:SS")
                QString timeOnly = timestamp.mid(11, 5);  // Extract "HH:MM"

                // Decrypt message
                QString messageText = "[encrypted]";
                char *plaintext = NULL;
                size_t plaintext_len = 0;

                if (messenger_decrypt_message(ctx, messages[i].id, &plaintext, &plaintext_len) == 0) {
                    messageText = QString::fromUtf8(plaintext, plaintext_len);
                    free(plaintext);
                } else {
                    messageText = QString::fromUtf8("🔒 [decryption failed]");
                }

                if (sender == currentIdentity) {
                    // Sent messages by current user
                    QString statusCheckmark = QString::fromUtf8("<span style='color: #888888;'>✓</span>");

                    QString sentBubble;
                    if (currentTheme == "club") {
                        sentBubble = QString(
                            "<div style='text-align: right; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF8C42, stop:1 #FFB380); "
                            "color: white; padding: 15px 20px; border-radius: 20px 20px 5px 20px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid #FF8C42;'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 You %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    } else {
                        sentBubble = QString(
                            "<div style='text-align: right; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00D9FF, stop:1 #0D8B9C); "
                            "color: white; padding: 15px 20px; border-radius: 20px 20px 5px 20px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid #00D9FF;'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 You %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    }
                    messageDisplay->append(sentBubble);
                } else {
                    // Messages from other group members
                    QString receivedBubble;
                    if (currentTheme == "club") {
                        receivedBubble = QString(
                            "<div style='text-align: left; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2B1F16, stop:1 #3D2B1F); "
                            "color: #FFB380; padding: 15px 20px; border-radius: 20px 20px 20px 5px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid rgba(255, 140, 66, 0.5);'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    } else {
                        receivedBubble = QString(
                            "<div style='text-align: left; margin: 8px 0;'>"
                            "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0D3438, stop:1 #0A5A62); "
                            "color: #00D9FF; padding: 15px 20px; border-radius: 20px 20px 20px 5px; "
                            "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid rgba(0, 217, 255, 0.5);'>"
                            "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 %3 %4 %5</div>"
                            "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                            "</div>"
                            "</div>"
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(messageText.toHtmlEscaped());
                    }
                    messageDisplay->append(receivedBubble);
                }
            }
        }

        messenger_free_messages(messages, count);
        statusLabel->setText(QString::fromUtf8("Loaded %1 group messages").arg(count));
    } else {
        messageDisplay->append(QString(
            "<div style='text-align: center; color: #FF6B35; padding: 20px; font-family: 'Orbitron'; font-size: %1px; font-weight: bold;'>"
            "%2"
            "</div>"
        ).arg(messageFontSize).arg(QString::fromUtf8("Failed to load group conversation")));
        statusLabel->setText(QString::fromUtf8("Error loading group conversation"));
    }
}

void MainWindow::onSendMessage() {
    QString message = messageInput->text().trimmed();
    if (message.isEmpty()) {
        return;
    }

    int result = -1;

    // Check if we're sending to a group or contact
    if (currentContactType == TYPE_GROUP && currentGroupId >= 0) {
        // Send to group
        QByteArray messageBytes = message.toUtf8();
        result = messenger_send_group_message(ctx, currentGroupId, messageBytes.constData());
    } else if (currentContactType == TYPE_CONTACT && !currentContact.isEmpty()) {
        // Send to contact(s)
        // Build recipient list: currentContact + additionalRecipients
        QVector<QByteArray> recipientBytes;  // Store QByteArray to keep data alive
        QVector<const char*> recipients;

        // Add primary recipient
        recipientBytes.append(currentContact.toUtf8());
        recipients.append(recipientBytes.last().constData());

        // Add additional recipients
        for (const QString &recipient : additionalRecipients) {
            recipientBytes.append(recipient.toUtf8());
            recipients.append(recipientBytes.last().constData());
        }

        QByteArray messageBytes = message.toUtf8();
        result = messenger_send_message(ctx,
                                         recipients.data(),
                                         recipients.size(),
                                         messageBytes.constData());
    } else {
        QMessageBox::warning(this, "No Selection",
                             "Please select a contact or group from the list first");
        return;
    }

    if (result == 0) {
        // Success - add message bubble to display with theme-aware colors
        QString timestamp = QDateTime::currentDateTime().toString("HH:mm");

        // Calculate font sizes for message bubbles
        int metaFontSize = static_cast<int>(13 * fontScale);
        int messageFontSize = static_cast<int>(18 * fontScale);

        // New message starts with "sent" status (single gray checkmark)
        QString statusCheckmark = QString::fromUtf8("<span style='color: #888888;'>✓</span>");

        QString sentBubble;
        if (currentTheme == "club") {
            // cpunk.club: orange gradient
            sentBubble = QString(
                "<div style='text-align: right; margin: 8px 0;'>"
                "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF8C42, stop:1 #FFB380); "
                "color: white; padding: 15px 20px; border-radius: 20px 20px 5px 20px; "
                "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid #FF8C42;'>"
                "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 You %3 %4 %5</div>"
                "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                "</div>"
                "</div>"
            ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timestamp, statusCheckmark).arg(messageFontSize).arg(message.toHtmlEscaped());
        } else {
            // cpunk.io: cyan gradient (default)
            sentBubble = QString(
                "<div style='text-align: right; margin: 8px 0;'>"
                "<div style='display: inline-block; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00D9FF, stop:1 #0D8B9C); "
                "color: white; padding: 15px 20px; border-radius: 20px 20px 5px 20px; "
                "max-width: 70%; text-align: left; box-shadow: 2px 2px 8px rgba(0,0,0,0.3); border: 2px solid #00D9FF;'>"
                "<div style='font-family: 'Orbitron'; font-size: %1px; opacity: 0.9; margin-bottom: 5px;'>%2 You %3 %4 %5</div>"
                "<div style='font-family: 'Orbitron'; font-size: %6px; line-height: 1.4;'>%7</div>"
                "</div>"
                "</div>"
            ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timestamp, statusCheckmark).arg(messageFontSize).arg(message.toHtmlEscaped());
        }
        messageDisplay->append(sentBubble);
        messageInput->clear();
        statusLabel->setText(QString::fromUtf8("Message sent"));
    } else {
        QMessageBox::critical(this, QString::fromUtf8("Send Failed"),
                              QString::fromUtf8("Failed to send message. Check console for details."));
        statusLabel->setText(QString::fromUtf8("Message send failed"));
    }
}

void MainWindow::onRefreshMessages() {
    if (currentContactType == TYPE_CONTACT && !currentContact.isEmpty()) {
        loadConversation(currentContact);
    } else if (currentContactType == TYPE_GROUP && currentGroupId >= 0) {
        loadGroupConversation(currentGroupId);
    }
    statusLabel->setText(QString::fromUtf8("Messages refreshed"));
}

void MainWindow::checkForNewMessages() {
    if (!ctx || currentIdentity.isEmpty()) {
        return;
    }

    // Query for new UNREAD messages since lastCheckedMessageId
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", lastCheckedMessageId);

    const char *query =
        "SELECT id, sender, created_at, status "
        "FROM messages "
        "WHERE recipient = $1 AND id > $2 AND status != 'read' "
        "ORDER BY id ASC";

    const char *params[2] = {
        currentIdentity.toUtf8().constData(),
        id_str
    };

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return;
    }

    int count = PQntuples(res);

    for (int i = 0; i < count; i++) {
        int msgId = atoi(PQgetvalue(res, i, 0));
        QString sender = QString::fromUtf8(PQgetvalue(res, i, 1));
        QString timestamp = QString::fromUtf8(PQgetvalue(res, i, 2));
        QString status = QString::fromUtf8(PQgetvalue(res, i, 3));

        if (msgId > lastCheckedMessageId) {
            lastCheckedMessageId = msgId;
        }

        // Mark message as delivered (recipient has fetched it)
        int markResult = messenger_mark_delivered(ctx, msgId);
        printf("[DELIVERY] Message ID %d marked as delivered (result: %d)\n", msgId, markResult);

        // Only notify if message is not already read
        if (status != "read") {
            // Play notification sound
            notificationSound->play();

            // Show desktop notification
            QString notificationTitle = QString::fromUtf8("New Message");
            QString notificationBody = QString("From: %1\n%2")
                .arg(sender)
                .arg(timestamp);

            trayIcon->showMessage(notificationTitle, notificationBody,
                                  QSystemTrayIcon::Information, 5000);

            printf("[NOTIFICATION] New message from %s (ID: %d, status: %s)\n",
                   sender.toUtf8().constData(), msgId, status.toUtf8().constData());
        }

        // If viewing this contact, refresh conversation and mark as read
        if (currentContact == sender) {
            loadConversation(currentContact);
            messenger_mark_conversation_read(ctx, sender.toUtf8().constData());
            printf("[READ] Conversation with %s marked as read\n", sender.toUtf8().constData());
        }
    }

    PQclear(res);
}

void MainWindow::checkForStatusUpdates() {
    // Only check if we have an active conversation open
    if (!ctx || currentContact.isEmpty()) {
        return;
    }

    // Query for detailed status updates on sent messages in current conversation
    const char *query =
        "SELECT id, status, delivered_at, read_at "
        "FROM messages "
        "WHERE sender = $1 AND recipient = $2 "
        "AND status IN ('delivered', 'read') "
        "ORDER BY id DESC LIMIT 5";

    const char *params[2] = {
        currentIdentity.toUtf8().constData(),
        currentContact.toUtf8().constData()
    };

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return;
    }

    // Silently refresh conversation to update checkmarks if there were any updates
    int count = PQntuples(res);
    if (count > 0) {
        loadConversation(currentContact);
    }

    PQclear(res);
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onCheckForUpdates() {
    QString currentVersion = QString(PQSIGNUM_VERSION);

    printf("\n========== DEBUG: Update Check ==========\n");
    printf("Current version: %s (commit %s, built %s)\n",
           PQSIGNUM_VERSION, BUILD_HASH, BUILD_TS);

    QMessageBox::information(this, "Check for Updates",
                             QString("Current version: %1\n\nChecking latest version on GitHub...").arg(currentVersion));

    // Step 1: Fetch MAJOR.MINOR from README
    QProcess readmeProcess;
    QString majorMinor = "unknown";

#ifdef _WIN32
    QString readmeCommand = "try { "
                           "$readme = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/nocdem/dna-messenger/main/README.md' "
                           "-Headers @{'User-Agent'='DNA-Messenger'} -ErrorAction Stop; "
                           "if ($readme -match '- \\*\\*Major:\\*\\*\\s+(\\d+)') { $major = $matches[1] }; "
                           "if ($readme -match '- \\*\\*Minor:\\*\\*\\s+(\\d+)') { $minor = $matches[1] }; "
                           "Write-Output \"$major.$minor\" "
                           "} catch { Write-Output 'unknown' }";
    printf("Step 1: Fetching MAJOR.MINOR from README...\n");
    readmeProcess.start("powershell", QStringList() << "-Command" << readmeCommand);
#else
    QString readmeCommand = "curl -s -H 'User-Agent: DNA-Messenger' "
                           "'https://raw.githubusercontent.com/nocdem/dna-messenger/main/README.md' 2>/dev/null | "
                           "awk '/- \\*\\*Major:\\*\\*/ {major=$3} /- \\*\\*Minor:\\*\\*/ {minor=$3} END {print major\".\"minor}' || echo 'unknown'";
    printf("Step 1: Fetching MAJOR.MINOR from README...\n");
    readmeProcess.start("sh", QStringList() << "-c" << readmeCommand);
#endif

    if (readmeProcess.waitForFinished(10000)) {
        majorMinor = QString::fromUtf8(readmeProcess.readAllStandardOutput()).trimmed();
        printf("  Result: %s\n", majorMinor.toUtf8().constData());
    } else {
        printf("  Timed out!\n");
    }

    if (majorMinor == "unknown" || majorMinor.isEmpty() || !majorMinor.contains('.')) {
        printf("ERROR: Failed to fetch MAJOR.MINOR from README\n");
        printf("=========================================\n\n");
        QMessageBox::warning(this, "Update Check Failed",
                             "Could not fetch version info from GitHub README.");
        return;
    }

    // Step 2: Fetch PATCH (commit count) from GitHub
    QProcess commitProcess;
    QString patch = "unknown";

#ifdef _WIN32
    QString commitCommand = "try { "
                           "$commits = Invoke-RestMethod -Uri 'https://api.github.com/repos/nocdem/dna-messenger/commits?per_page=100' "
                           "-Headers @{'User-Agent'='DNA-Messenger'} -ErrorAction Stop; "
                           "Write-Output $commits.Count "
                           "} catch { Write-Output 'unknown' }";
    printf("Step 2: Fetching PATCH (commit count) from GitHub API...\n");
    commitProcess.start("powershell", QStringList() << "-Command" << commitCommand);
#else
    QString commitCommand = "curl -s -H 'User-Agent: DNA-Messenger' "
                           "'https://api.github.com/repos/nocdem/dna-messenger/commits?per_page=100' 2>/dev/null | "
                           "grep -c '\"sha\"' || echo 'unknown'";
    printf("Step 2: Fetching PATCH (commit count) from GitHub API...\n");
    commitProcess.start("sh", QStringList() << "-c" << commitCommand);
#endif

    if (commitProcess.waitForFinished(10000)) {
        patch = QString::fromUtf8(commitProcess.readAllStandardOutput()).trimmed();
        printf("  Result: %s\n", patch.toUtf8().constData());
    } else {
        printf("  Timed out!\n");
    }

    if (patch == "unknown" || patch.isEmpty()) {
        printf("ERROR: Failed to fetch commit count\n");
        printf("=========================================\n\n");
        QMessageBox::warning(this, "Update Check Failed",
                             "Could not fetch commit count from GitHub.");
        return;
    }

    // Step 3: Combine into full version
    QString latestVersion = majorMinor + "." + patch;
    printf("Step 3: Combined latest version: %s\n", latestVersion.toUtf8().constData());

    // Compare versions (semantic versioning: major.minor.patch)
    QStringList currentParts = currentVersion.split('.');
    QStringList latestParts = latestVersion.split('.');

    int currentMajor = 0, currentMinor = 0, currentPatch = 0;
    int latestMajor = 0, latestMinor = 0, latestPatch = 0;

    if (currentParts.size() >= 3) {
        currentMajor = currentParts[0].toInt();
        currentMinor = currentParts[1].toInt();
        currentPatch = currentParts[2].toInt();
    }

    if (latestParts.size() >= 3) {
        latestMajor = latestParts[0].toInt();
        latestMinor = latestParts[1].toInt();
        latestPatch = latestParts[2].toInt();
    }

    printf("Version comparison:\n");
    printf("  Current: %d.%d.%d (%s)\n", currentMajor, currentMinor, currentPatch,
           currentVersion.toUtf8().constData());
    printf("  Latest:  %d.%d.%d (%s)\n", latestMajor, latestMinor, latestPatch,
           latestVersion.toUtf8().constData());

    // Compare: major first, then minor, then patch
    bool updateAvailable = false;
    if (latestMajor > currentMajor) {
        updateAvailable = true;
    } else if (latestMajor == currentMajor && latestMinor > currentMinor) {
        updateAvailable = true;
    } else if (latestMajor == currentMajor && latestMinor == currentMinor && latestPatch > currentPatch) {
        updateAvailable = true;
    }

    if (updateAvailable) {
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
            // Windows: Launch updater script from the repository root
            // Find the repository root by looking for .git directory
            QString exePath = QCoreApplication::applicationDirPath();
            QDir dir(exePath);

            printf("\n========== DEBUG: Windows Update ==========\n");
            printf("Executable path: %s\n", exePath.toUtf8().constData());
            printf("Looking for .git directory...\n");

            // Navigate up to find repository root (where .git exists)
            QString repoRoot;
            while (dir.cdUp()) {
                QString currentPath = dir.absolutePath();
                printf("  Checking: %s\n", currentPath.toUtf8().constData());
                if (dir.exists(".git")) {
                    repoRoot = currentPath;
                    printf("  Found .git at: %s\n", repoRoot.toUtf8().constData());
                    break;
                }
            }

            if (repoRoot.isEmpty()) {
                printf("ERROR: Could not find repository root\n");
                printf("==========================================\n\n");
                QMessageBox::critical(this, QString::fromUtf8("Update Failed"),
                                     QString::fromUtf8("Could not find repository root.\n\n"
                                     "Searched from: %1\n\n"
                                     "Make sure you are running from a git repository.").arg(exePath));
                return;
            }

            QString updateScript = repoRoot + "\\update_windows.bat";
            printf("Update script path: %s\n", updateScript.toUtf8().constData());

            if (!QFileInfo::exists(updateScript)) {
                printf("ERROR: Update script not found at: %s\n", updateScript.toUtf8().constData());
                printf("==========================================\n\n");
                QMessageBox::critical(this, QString::fromUtf8("Update Failed"),
                                     QString::fromUtf8("Update script not found:\n%1\n\n"
                                     "Please update manually using:\n"
                                     "git pull && cmake --build build --config Release").arg(updateScript));
                return;
            }

            printf("Launching update script...\n");

            // Build command
            QString nativeUpdateScript = QDir::toNativeSeparators(updateScript);
            QString nativeRepoRoot = QDir::toNativeSeparators(repoRoot);

            printf("Native script path: %s\n", nativeUpdateScript.toUtf8().constData());
            printf("Native repo root: %s\n", nativeRepoRoot.toUtf8().constData());
            printf("==========================================\n\n");

            // Launch updater script in new window - use cmd /k to keep window open
            // The script will change to the correct directory itself
            QProcess::startDetached("cmd", QStringList() << "/k" << nativeUpdateScript);

            // Quit immediately so updater can replace the executable
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

void MainWindow::onThemeIO() {
    applyTheme("io");
}

void MainWindow::onThemeClub() {
    applyTheme("club");
}

void MainWindow::applyTheme(const QString &themeName) {
    currentTheme = themeName;

    // Save theme preference
    QSettings settings("DNA Messenger", "GUI");
    settings.setValue("theme", themeName);

    // Calculate font sizes based on scale (base sizes: 16px menu, 18px list, 24px headers, 13px meta, 18px message)
    int menuFontSize = static_cast<int>(16 * fontScale);
    int listFontSize = static_cast<int>(18 * fontScale);
    int headerFontSize = static_cast<int>(24 * fontScale);
    int metaFontSize = static_cast<int>(13 * fontScale);
    int messageFontSize = static_cast<int>(18 * fontScale);

    // Apply theme colors based on selection
    if (themeName == "io") {
        // cpunk.io theme - dark teal with cyan accents
        setStyleSheet(QString(
            "QMainWindow {"
            "   background: qlineargradient(x1:0, y1:0, x2:1, y2:1, "
            "       stop:0 #0A2A2E, stop:1 #0D3438);"
            "}"
            "QMenuBar {"
            "   background: #0D3438;"
            "   color: #00D9FF;"
            "   padding: 8px;"
            "   font-family: 'Orbitron';"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   border-bottom: 2px solid #00D9FF;"
            "}"
            "QMenuBar::item {"
            "   padding: 8px 15px;"
            "   color: #00D9FF;"
            "}"
            "QMenuBar::item:selected {"
            "   background: rgba(0, 217, 255, 0.2);"
            "   border-radius: 5px;"
            "}"
            "QMenu {"
            "   background: #0D3438;"
            "   border: 2px solid #00D9FF;"
            "   border-radius: 10px;"
            "   padding: 8px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #00D9FF;"
            "}"
            "QMenu::item {"
            "   padding: 10px 20px;"
            "   color: #00D9FF;"
            "}"
            "QMenu::item:selected {"
            "   background: rgba(0, 217, 255, 0.3);"
            "   border-radius: 5px;"
            "}"
            "QStatusBar {"
            "   background: #0D3438;"
            "   color: #00D9FF;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   padding: 8px;"
            "   border-top: 2px solid #00D9FF;"
            "}"
        ).arg(menuFontSize));

        contactList->parentWidget()->setStyleSheet(
            "QWidget {"
            "   background: #0A2A2E;"
            "   border-radius: 15px;"
            "   padding: 10px;"
            "}"
        );

        contactList->parentWidget()->findChild<QLabel*>()->setStyleSheet(QString(
            "font-weight: bold; "
            "font-family: 'Orbitron'; font-size: %1px; "
            "color: #00D9FF; "
            "background: transparent; "
            "padding: 10px;"
        ).arg(headerFontSize));

        contactList->setStyleSheet(QString(
            "QListWidget {"
            "   background: #0D3438;"
            "   border: 2px solid #00D9FF;"
            "   border-radius: 10px;"
            "   padding: 8px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #00D9FF;"
            "}"
            "QListWidget::item {"
            "   background: rgba(0, 217, 255, 0.1);"
            "   border: 1px solid rgba(0, 217, 255, 0.3);"
            "   border-radius: 10px;"
            "   padding: 15px;"
            "   margin: 5px;"
            "   color: #00D9FF;"
            "}"
            "QListWidget::item:hover {"
            "   background: rgba(0, 217, 255, 0.2);"
            "   border: 2px solid #00D9FF;"
            "}"
            "QListWidget::item:selected {"
            "   background: rgba(0, 217, 255, 0.3);"
            "   color: #FFFFFF;"
            "   font-weight: bold;"
            "   border: 2px solid #00D9FF;"
            "}"
        ).arg(listFontSize));

        refreshButton->setStyleSheet(QString(
            "QPushButton {"
            "   background: rgba(0, 217, 255, 0.2);"
            "   color: #00D9FF;"
            "   border: 2px solid #00D9FF;"
            "   border-radius: 15px;"
            "   padding: 15px;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "}"
            "QPushButton:hover {"
            "   background: rgba(0, 217, 255, 0.3);"
            "   border: 2px solid #33E6FF;"
            "}"
            "QPushButton:pressed {"
            "   background: rgba(0, 217, 255, 0.4);"
            "   border: 2px solid #00D9FF;"
            "}"
        ).arg(listFontSize));

        messageDisplay->parentWidget()->setStyleSheet(
            "QWidget {"
            "   background: #0A2A2E;"
            "   border-radius: 15px;"
            "   padding: 10px;"
            "}"
        );

        messageDisplay->parentWidget()->findChildren<QLabel*>()[0]->setStyleSheet(QString(
            "font-weight: bold; "
            "font-family: 'Orbitron'; font-size: %1px; "
            "color: #00D9FF; "
            "background: transparent; "
            "padding: 10px;"
        ).arg(headerFontSize));

        messageDisplay->setStyleSheet(QString(
            "QTextEdit {"
            "   background: #0D3438;"
            "   border: 2px solid #00D9FF;"
            "   border-radius: 10px;"
            "   padding: 15px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #00D9FF;"
            "}"
        ).arg(menuFontSize));

        messageInput->setStyleSheet(QString(
            "QLineEdit {"
            "   background: #0D3438;"
            "   border: 2px solid #00D9FF;"
            "   border-radius: 15px;"
            "   padding: 15px 20px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #00D9FF;"
            "}"
            "QLineEdit:focus {"
            "   border: 2px solid #33E6FF;"
            "   background: rgba(0, 217, 255, 0.1);"
            "}"
        ).arg(listFontSize));

        sendButton->setStyleSheet(QString(
            "QPushButton {"
            "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "       stop:0 #FF6B35, stop:1 #FF8C42);"
            "   color: white;"
            "   border: 2px solid #FF6B35;"
            "   border-radius: 15px;"
            "   padding: 15px 30px;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "}"
            "QPushButton:hover {"
            "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "       stop:0 #FF8C42, stop:1 #FFA55C);"
            "   border: 2px solid #FF8C42;"
            "}"
            "QPushButton:pressed {"
            "   background: #FF5722;"
            "   border: 2px solid #E64A19;"
            "}"
        ).arg(listFontSize));

        statusLabel->setText(QString::fromUtf8("Theme: cpunk.io (Cyan)"));

    } else if (themeName == "club") {
        // cpunk.club theme - dark brown with orange accents
        setStyleSheet(QString(
            "QMainWindow {"
            "   background: qlineargradient(x1:0, y1:0, x2:1, y2:1, "
            "       stop:0 #1A1410, stop:1 #2B1F16);"
            "}"
            "QMenuBar {"
            "   background: #2B1F16;"
            "   color: #FF8C42;"
            "   padding: 8px;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   border-bottom: 2px solid #FF8C42;"
            "}"
            "QMenuBar::item {"
            "   padding: 8px 15px;"
            "   color: #FF8C42;"
            "}"
            "QMenuBar::item:selected {"
            "   background: rgba(255, 140, 66, 0.2);"
            "   border-radius: 5px;"
            "}"
            "QMenu {"
            "   background: #2B1F16;"
            "   border: 2px solid #FF8C42;"
            "   border-radius: 10px;"
            "   padding: 8px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #FF8C42;"
            "}"
            "QMenu::item {"
            "   padding: 10px 20px;"
            "   color: #FF8C42;"
            "}"
            "QMenu::item:selected {"
            "   background: rgba(255, 140, 66, 0.3);"
            "   border-radius: 5px;"
            "}"
            "QStatusBar {"
            "   background: #2B1F16;"
            "   color: #FF8C42;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   padding: 8px;"
            "   border-top: 2px solid #FF8C42;"
            "}"
        ).arg(menuFontSize));

        contactList->parentWidget()->setStyleSheet(
            "QWidget {"
            "   background: #1A1410;"
            "   border-radius: 15px;"
            "   padding: 10px;"
            "}"
        );

        contactList->parentWidget()->findChild<QLabel*>()->setStyleSheet(QString(
            "font-weight: bold; "
            "font-family: 'Orbitron'; font-size: %1px; "
            "color: #FF8C42; "
            "background: transparent; "
            "padding: 10px;"
        ).arg(headerFontSize));

        contactList->setStyleSheet(QString(
            "QListWidget {"
            "   background: #2B1F16;"
            "   border: 2px solid #FF8C42;"
            "   border-radius: 10px;"
            "   padding: 8px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #FFB380;"
            "}"
            "QListWidget::item {"
            "   background: rgba(255, 140, 66, 0.1);"
            "   border: 1px solid rgba(255, 140, 66, 0.3);"
            "   border-radius: 10px;"
            "   padding: 15px;"
            "   margin: 5px;"
            "   color: #FFB380;"
            "}"
            "QListWidget::item:hover {"
            "   background: rgba(255, 140, 66, 0.2);"
            "   border: 2px solid #FF8C42;"
            "}"
            "QListWidget::item:selected {"
            "   background: rgba(255, 140, 66, 0.3);"
            "   color: #FFFFFF;"
            "   font-weight: bold;"
            "   border: 2px solid #FF8C42;"
            "}"
        ).arg(listFontSize));

        refreshButton->setStyleSheet(QString(
            "QPushButton {"
            "   background: rgba(255, 140, 66, 0.2);"
            "   color: #FF8C42;"
            "   border: 2px solid #FF8C42;"
            "   border-radius: 15px;"
            "   padding: 15px;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "}"
            "QPushButton:hover {"
            "   background: rgba(255, 140, 66, 0.3);"
            "   border: 2px solid #FFB380;"
            "}"
            "QPushButton:pressed {"
            "   background: rgba(255, 140, 66, 0.4);"
            "   border: 2px solid #FF8C42;"
            "}"
        ).arg(listFontSize));

        messageDisplay->parentWidget()->setStyleSheet(
            "QWidget {"
            "   background: #1A1410;"
            "   border-radius: 15px;"
            "   padding: 10px;"
            "}"
        );

        messageDisplay->parentWidget()->findChildren<QLabel*>()[0]->setStyleSheet(QString(
            "font-weight: bold; "
            "font-family: 'Orbitron'; font-size: %1px; "
            "   color: #FF8C42; "
            "background: transparent; "
            "padding: 10px;"
        ).arg(headerFontSize));

        messageDisplay->setStyleSheet(QString(
            "QTextEdit {"
            "   background: #2B1F16;"
            "   border: 2px solid #FF8C42;"
            "   border-radius: 10px;"
            "   padding: 15px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #FFB380;"
            "}"
        ).arg(menuFontSize));

        messageInput->setStyleSheet(QString(
            "QLineEdit {"
            "   background: #2B1F16;"
            "   border: 2px solid #FF8C42;"
            "   border-radius: 15px;"
            "   padding: 15px 20px;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "   color: #FFB380;"
            "}"
            "QLineEdit:focus {"
            "   border: 2px solid #FFB380;"
            "   background: rgba(255, 140, 66, 0.1);"
            "}"
        ).arg(listFontSize));

        sendButton->setStyleSheet(QString(
            "QPushButton {"
            "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "       stop:0 #00D9FF, stop:1 #00B8CC);"
            "   color: white;"
            "   border: 2px solid #00D9FF;"
            "   border-radius: 15px;"
            "   padding: 15px 30px;"
            "   font-weight: bold;"
            "   font-family: 'Orbitron'; font-size: %1px;"
            "}"
            "QPushButton:hover {"
            "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "       stop:0 #00E6FF, stop:1 #00D9FF);"
            "   border: 2px solid #00E6FF;"
            "}"
            "QPushButton:pressed {"
            "   background: #00B8CC;"
            "   border: 2px solid #009AA8;"
            "}"
        ).arg(listFontSize));

        statusLabel->setText(QString::fromUtf8("Theme: cpunk.club (Orange)"));
    }
    
    // Reload conversation to apply new message bubble colors
    if (!currentContact.isEmpty()) {
        loadConversation(currentContact);
    }
}

void MainWindow::onFontScaleSmall() {
    applyFontScale(1.0);
}

void MainWindow::onFontScaleMedium() {
    applyFontScale(2.0);
}

void MainWindow::onFontScaleLarge() {
    applyFontScale(3.0);
}

void MainWindow::onFontScaleExtraLarge() {
    applyFontScale(4.0);
}

void MainWindow::applyFontScale(double scale) {
    fontScale = scale;
    
    // Save font scale preference
    QSettings settings("DNA Messenger", "GUI");
    settings.setValue("fontScale", scale);
    
    // Update all icon sizes
    if (minimizeButton) minimizeButton->setIconSize(QSize(scaledIconSize(24), scaledIconSize(24)));
    if (closeButton) closeButton->setIconSize(QSize(scaledIconSize(24), scaledIconSize(24)));
    if (userMenuButton) userMenuButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    if (refreshButton) refreshButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    if (createGroupButton) createGroupButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    if (groupSettingsButton) groupSettingsButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    if (addRecipientsButton) addRecipientsButton->setIconSize(QSize(scaledIconSize(18), scaledIconSize(18)));
    if (sendButton) sendButton->setIconSize(QSize(scaledIconSize(18), scaledIconSize(18)));
    
    // Re-apply the current theme with new font sizes
    applyTheme(currentTheme);
    
    // Update status bar
    QString scaleText;
    if (scale == 1.0) scaleText = "Small (1x)";
    else if (scale == 2.0) scaleText = "Medium (2x)";
    else if (scale == 3.0) scaleText = "Large (3x)";
    else if (scale == 4.0) scaleText = "Extra Large (4x)";
    else scaleText = QString::number(scale) + "x";
    
    statusLabel->setText(QString::fromUtf8("Font Scale: %1").arg(scaleText));
}

int MainWindow::scaledIconSize(int baseSize) const {
    return static_cast<int>(baseSize * fontScale);
}

void MainWindow::onAddRecipients() {
    if (currentContact.isEmpty()) {
        QMessageBox::warning(this, "No Contact Selected",
                             "Please select a primary contact first");
        return;
    }

    // Create dialog for multi-selection
    QDialog dialog(this);
    dialog.setWindowTitle(QString::fromUtf8("Add Recipients"));
    dialog.setModal(true);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);

    QLabel *label = new QLabel(QString::fromUtf8("Select additional recipients:"));
    layout->addWidget(label);

    // List widget with multi-selection
    QListWidget *listWidget = new QListWidget(&dialog);
    listWidget->setSelectionMode(QAbstractItemView::MultiSelection);

    // Load all contacts except current contact
    char **identities = NULL;
    int count = 0;

    if (messenger_get_contact_list(ctx, &identities, &count) == 0) {
        for (int i = 0; i < count; i++) {
            QString contact = QString::fromUtf8(identities[i]);
            // Don't include current contact or sender
            if (contact != currentContact && contact != currentIdentity) {
                QListWidgetItem *item = new QListWidgetItem(QString::fromUtf8("") + contact);
                listWidget->addItem(item);

                // Pre-select if already in additionalRecipients
                if (additionalRecipients.contains(contact)) {
                    item->setSelected(true);
                }
            }
            free(identities[i]);
        }
        free(identities);
    }

    layout->addWidget(listWidget);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout;
    QPushButton *okButton = new QPushButton("OK"); okButton->setIcon(QIcon(":/icons/check.svg")); okButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); okButton;
    QPushButton *cancelButton = new QPushButton("Cancel"); cancelButton->setIcon(QIcon(":/icons/close.svg")); cancelButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); cancelButton;

    connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    if (dialog.exec() == QDialog::Accepted) {
        // Update additionalRecipients list
        additionalRecipients.clear();

        for (int i = 0; i < listWidget->count(); i++) {
            QListWidgetItem *item = listWidget->item(i);
            if (item->isSelected()) {
                // Strip emoji prefix "👤 "
                QString contact = item->text();
                if (contact.startsWith(QString::fromUtf8(""))) {
                    contact = contact.mid(3);
                }
                additionalRecipients.append(contact);
            }
        }

        // Update recipients label
        QString recipientsText = QString::fromUtf8("To: ") + currentContact;
        if (!additionalRecipients.isEmpty()) {
            recipientsText += ", " + additionalRecipients.join(", ");
        }
        recipientsLabel->setText(recipientsText);

        statusLabel->setText(QString::fromUtf8("%1 additional recipient(s) added").arg(additionalRecipients.count()));
    }
}

// Window dragging
void MainWindow::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton) {
        // Map click position to titleBar's coordinate system
        QPoint titleBarPos = titleBar->mapFromGlobal(event->globalPos());
        if (titleBar->rect().contains(titleBarPos)) {
            dragPosition = event->globalPos() - frameGeometry().topLeft();
            event->accept();
        }
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent *event) {
    if (event->buttons() & Qt::LeftButton && !dragPosition.isNull()) {
        move(event->globalPos() - dragPosition);
        event->accept();
    }
}

// Window control buttons
void MainWindow::onMinimizeWindow() {
    showMinimized();
}

void MainWindow::onCloseWindow() {
    QApplication::quit();
}

// Group management functions
void MainWindow::onCreateGroup() {
    // Create dialog
    QDialog dialog(this);
    dialog.setWindowTitle(QString::fromUtf8("Create New Group"));
    dialog.setMinimumSize(600, 500);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);

    // Group name input
    QLabel *nameLabel = new QLabel(QString::fromUtf8("📝 Group Name:"));
    QLineEdit *nameEdit = new QLineEdit();
    nameEdit->setPlaceholderText("Enter group name (required)");
    layout->addWidget(nameLabel);
    layout->addWidget(nameEdit);

    // Description input
    QLabel *descLabel = new QLabel(QString::fromUtf8("📄 Description (optional):"));
    QLineEdit *descEdit = new QLineEdit();
    descEdit->setPlaceholderText("Enter group description");
    layout->addWidget(descLabel);
    layout->addWidget(descEdit);

    // Member selection
    QLabel *memberLabel = new QLabel(QString::fromUtf8("Select Members:"));
    layout->addWidget(memberLabel);

    QListWidget *memberList = new QListWidget();
    memberList->setSelectionMode(QAbstractItemView::MultiSelection);

    // Load contacts (excluding current user)
    char **identities = NULL;
    int contactCount = 0;
    if (messenger_get_contact_list(ctx, &identities, &contactCount) == 0) {
        for (int i = 0; i < contactCount; i++) {
            QString identity = QString::fromUtf8(identities[i]);
            if (identity != currentIdentity) {  // Exclude self
                QListWidgetItem *item = new QListWidgetItem(QString::fromUtf8("") + identity);
                memberList->addItem(item);
            }
            free(identities[i]);
        }
        free(identities);
    }

    layout->addWidget(memberList);

    // Info label
    QLabel *infoLabel = new QLabel(QString::fromUtf8("💡 Hold Ctrl/Cmd to select multiple members"));
    infoLabel->setStyleSheet("color: gray; font-size: 10px;");
    layout->addWidget(infoLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *okButton = new QPushButton("Create"); okButton->setIcon(QIcon(":/icons/check.svg")); okButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); okButton;
    QPushButton *cancelButton = new QPushButton("Cancel"); cancelButton->setIcon(QIcon(":/icons/close.svg")); cancelButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); cancelButton;

    connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    // Show dialog
    if (dialog.exec() == QDialog::Accepted) {
        QString groupName = nameEdit->text().trimmed();
        QString description = descEdit->text().trimmed();

        // Validate group name
        if (groupName.isEmpty()) {
            QMessageBox::warning(this, "Invalid Input", "Group name cannot be empty");
            return;
        }

        // Collect selected members
        QStringList selectedMembers;
        for (int i = 0; i < memberList->count(); i++) {
            QListWidgetItem *item = memberList->item(i);
            if (item->isSelected()) {
                // Strip emoji prefix
                QString member = item->text();
                if (member.startsWith(QString::fromUtf8(""))) {
                    member = member.mid(3);
                }
                selectedMembers.append(member);
            }
        }

        // Validate at least one member selected
        if (selectedMembers.isEmpty()) {
            QMessageBox::warning(this, "Invalid Input", "Please select at least one member");
            return;
        }

        // Convert to C array
        QList<QByteArray> memberBytes;
        QVector<const char*> memberPtrs;
        for (const QString &member : selectedMembers) {
            memberBytes.append(member.toUtf8());
        }
        for (const QByteArray &bytes : memberBytes) {
            memberPtrs.append(bytes.constData());
        }

        // Create group
        int groupId = -1;
        QByteArray nameBytes = groupName.toUtf8();
        QByteArray descBytes = description.isEmpty() ? QByteArray() : description.toUtf8();

        int result = messenger_create_group(
            ctx,
            nameBytes.constData(),
            description.isEmpty() ? NULL : descBytes.constData(),
            memberPtrs.data(),
            memberPtrs.size(),
            &groupId
        );

        if (result == 0) {
            QMessageBox::information(this, "Success",
                QString("Group \"%1\" created successfully!").arg(groupName));
            loadContacts();  // Refresh contact list
        } else {
            QMessageBox::critical(this, "Error", "Failed to create group");
        }
    }
}

void MainWindow::onGroupSettings() {
    if (currentContactType != TYPE_GROUP || currentGroupId < 0) {
        QMessageBox::warning(this, "No Group Selected", "Please select a group first");
        return;
    }

    // Get current group info
    group_info_t groupInfo;
    if (messenger_get_group_info(ctx, currentGroupId, &groupInfo) != 0) {
        QMessageBox::critical(this, "Error", "Failed to load group information");
        return;
    }

    // Create dialog
    QDialog dialog(this);
    dialog.setWindowTitle(QString::fromUtf8("Group Settings"));
    dialog.setMinimumSize(500, 400);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);

    // Display read-only info
    QLabel *infoLabel = new QLabel(
        QString::fromUtf8("Group ID: %1\n"
                         "👤 Creator: %2\n"
                         "📅 Created: %3\n"
                         "👥 Members: %4")
        .arg(groupInfo.id)
        .arg(QString::fromUtf8(groupInfo.creator))
        .arg(QString::fromUtf8(groupInfo.created_at))
        .arg(groupInfo.member_count)
    );
    infoLabel->setStyleSheet("background: rgba(0, 217, 255, 0.1); padding: 10px; border-radius: 5px;");
    layout->addWidget(infoLabel);

    // Group name input
    QLabel *nameLabel = new QLabel(QString::fromUtf8("📝 Group Name:"));
    QLineEdit *nameEdit = new QLineEdit();
    nameEdit->setText(QString::fromUtf8(groupInfo.name));
    layout->addWidget(nameLabel);
    layout->addWidget(nameEdit);

    // Description input
    QLabel *descLabel = new QLabel(QString::fromUtf8("📄 Description:"));
    QLineEdit *descEdit = new QLineEdit();
    if (groupInfo.description) {
        descEdit->setText(QString::fromUtf8(groupInfo.description));
    }
    layout->addWidget(descLabel);
    layout->addWidget(descEdit);

    // Action buttons
    QHBoxLayout *actionLayout = new QHBoxLayout();

    QPushButton *manageMembersButton = new QPushButton("Manage Members"); manageMembersButton->setIcon(QIcon(":/icons/group.svg")); manageMembersButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); manageMembersButton;
    connect(manageMembersButton, &QPushButton::clicked, [this, &dialog]() {
        dialog.accept();  // Close settings dialog
        onManageGroupMembers();  // Open members dialog
    });
    actionLayout->addWidget(manageMembersButton);

    // Delete button (only for creator)
    bool isCreator = (QString::fromUtf8(groupInfo.creator) == currentIdentity);
    if (isCreator) {
        QPushButton *deleteButton = new QPushButton("Delete Group"); deleteButton->setIcon(QIcon(":/icons/delete.svg")); deleteButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); deleteButton;
        deleteButton->setStyleSheet("background: rgba(255, 0, 0, 0.2); color: red;");
        connect(deleteButton, &QPushButton::clicked, [this, &dialog, &groupInfo]() {
            QMessageBox::StandardButton reply = QMessageBox::question(
                this,
                "Confirm Delete",
                QString::fromUtf8("Are you sure you want to delete the group '%1'?\n"
                                 "This action cannot be undone!")
                    .arg(QString::fromUtf8(groupInfo.name)),
                QMessageBox::Yes | QMessageBox::No
            );

            if (reply == QMessageBox::Yes) {
                if (messenger_delete_group(ctx, currentGroupId) == 0) {
                    QMessageBox::information(this, "Success", "Group deleted successfully");
                    loadContacts();  // Refresh contact list
                    currentGroupId = -1;
                    currentContactType = TYPE_CONTACT;
                    messageDisplay->clear();
                    dialog.reject();
                } else {
                    QMessageBox::critical(this, "Error", "Failed to delete group");
                }
            }
        });
        actionLayout->addWidget(deleteButton);
    } else {
        // Leave group button (for non-creators)
        QPushButton *leaveButton = new QPushButton("Leave Group"); leaveButton->setIcon(QIcon(":/icons/exit.svg")); leaveButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); leaveButton;
        leaveButton->setStyleSheet("background: rgba(255, 140, 0, 0.2); color: orange;");
        connect(leaveButton, &QPushButton::clicked, [this, &dialog, &groupInfo]() {
            QMessageBox::StandardButton reply = QMessageBox::question(
                this,
                "Confirm Leave",
                QString::fromUtf8("Are you sure you want to leave the group '%1'?")
                    .arg(QString::fromUtf8(groupInfo.name)),
                QMessageBox::Yes | QMessageBox::No
            );

            if (reply == QMessageBox::Yes) {
                if (messenger_leave_group(ctx, currentGroupId) == 0) {
                    QMessageBox::information(this, "Success", "Left group successfully");
                    loadContacts();  // Refresh contact list
                    currentGroupId = -1;
                    currentContactType = TYPE_CONTACT;
                    messageDisplay->clear();
                    dialog.reject();
                } else {
                    QMessageBox::critical(this, "Error", "Failed to leave group");
                }
            }
        });
        actionLayout->addWidget(leaveButton);
    }

    layout->addLayout(actionLayout);

    // Save/Cancel buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *saveButton = new QPushButton("Save"); saveButton->setIcon(QIcon(":/icons/save.svg")); saveButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); saveButton;
    QPushButton *cancelButton = new QPushButton("Cancel"); cancelButton->setIcon(QIcon(":/icons/close.svg")); cancelButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); cancelButton;

    connect(saveButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    // Show dialog
    if (dialog.exec() == QDialog::Accepted) {
        QString newName = nameEdit->text().trimmed();
        QString newDesc = descEdit->text().trimmed();

        // Validate name
        if (newName.isEmpty()) {
            QMessageBox::warning(this, "Invalid Input", "Group name cannot be empty");
            // Free group info before returning
            free(groupInfo.name);
            if (groupInfo.description) free(groupInfo.description);
            free(groupInfo.creator);
            free(groupInfo.created_at);
            return;
        }

        // Check if anything changed
        bool nameChanged = (newName != QString::fromUtf8(groupInfo.name));
        bool descChanged = (newDesc != QString::fromUtf8(groupInfo.description ? groupInfo.description : ""));

        if (nameChanged || descChanged) {
            QByteArray nameBytes = newName.toUtf8();
            QByteArray descBytes = newDesc.toUtf8();

            int result = messenger_update_group_info(
                ctx,
                currentGroupId,
                nameChanged ? nameBytes.constData() : NULL,
                descChanged ? descBytes.constData() : NULL
            );

            if (result == 0) {
                QMessageBox::information(this, "Success", "Group settings updated successfully");
                loadContacts();  // Refresh contact list
            } else {
                QMessageBox::critical(this, "Error", "Failed to update group settings");
            }
        }
    }

    // Free group info
    free(groupInfo.name);
    if (groupInfo.description) free(groupInfo.description);
    free(groupInfo.creator);
    free(groupInfo.created_at);
}

void MainWindow::onManageGroupMembers() {
    if (currentContactType != TYPE_GROUP || currentGroupId < 0) {
        QMessageBox::warning(this, "No Group Selected", "Please select a group first");
        return;
    }

    // Get current group info
    group_info_t groupInfo;
    if (messenger_get_group_info(ctx, currentGroupId, &groupInfo) != 0) {
        QMessageBox::critical(this, "Error", "Failed to load group information");
        return;
    }

    // Get current members
    char **members = NULL;
    int memberCount = 0;
    if (messenger_get_group_members(ctx, currentGroupId, &members, &memberCount) != 0) {
        QMessageBox::critical(this, "Error", "Failed to load group members");
        free(groupInfo.name);
        if (groupInfo.description) free(groupInfo.description);
        free(groupInfo.creator);
        free(groupInfo.created_at);
        return;
    }

    // Create dialog
    QDialog dialog(this);
    dialog.setWindowTitle(QString::fromUtf8("Manage Group Members"));
    dialog.setMinimumSize(600, 500);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);

    // Group info header
    QLabel *headerLabel = new QLabel(
        QString::fromUtf8("Group: %1\n"
                         "Members: %2")
        .arg(QString::fromUtf8(groupInfo.name))
        .arg(memberCount)
    );
    headerLabel->setStyleSheet("background: rgba(0, 217, 255, 0.1); padding: 10px; border-radius: 5px; font-weight: bold;");
    layout->addWidget(headerLabel);

    // Current members list
    QLabel *currentLabel = new QLabel(QString::fromUtf8("📋 Current Members:"));
    layout->addWidget(currentLabel);

    QListWidget *currentMembersList = new QListWidget();
    currentMembersList->setSelectionMode(QAbstractItemView::MultiSelection);

    // Populate current members
    for (int i = 0; i < memberCount; i++) {
        QString member = QString::fromUtf8(members[i]);
        QString displayText = QString::fromUtf8("") + member;

        // Mark creator with special icon
        if (member == QString::fromUtf8(groupInfo.creator)) {
            displayText += QString::fromUtf8(" 👑 (Creator)");
        }

        QListWidgetItem *item = new QListWidgetItem(displayText);

        // Don't allow removing creator or self
        if (member == QString::fromUtf8(groupInfo.creator) || member == currentIdentity) {
            item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
            item->setForeground(Qt::gray);
        }

        currentMembersList->addItem(item);
    }

    layout->addWidget(currentMembersList);

    // Remove members button
    QPushButton *removeButton = new QPushButton("Remove Selected Members"); removeButton->setIcon(QIcon(":/icons/delete.svg")); removeButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); removeButton;
    removeButton->setStyleSheet("background: rgba(255, 0, 0, 0.2); color: red;");
    connect(removeButton, &QPushButton::clicked, [this, currentMembersList, &groupInfo]() {
        QStringList toRemove;
        for (int i = 0; i < currentMembersList->count(); i++) {
            QListWidgetItem *item = currentMembersList->item(i);
            if (item->isSelected()) {
                QString memberText = item->text();
                // Strip emoji and extract member name
                if (memberText.startsWith(QString::fromUtf8(""))) {
                    memberText = memberText.mid(3);
                    // Remove " 👑 (Creator)" suffix if present
                    int crownPos = memberText.indexOf(QString::fromUtf8(" 👑"));
                    if (crownPos >= 0) {
                        memberText = memberText.left(crownPos);
                    }
                    toRemove.append(memberText);
                }
            }
        }

        if (toRemove.isEmpty()) {
            QMessageBox::information(this, "No Selection", "Please select members to remove");
            return;
        }

        QMessageBox::StandardButton reply = QMessageBox::question(
            this,
            "Confirm Remove",
            QString::fromUtf8("Remove %1 member(s) from the group?").arg(toRemove.count()),
            QMessageBox::Yes | QMessageBox::No
        );

        if (reply == QMessageBox::Yes) {
            int removed = 0;
            for (const QString &member : toRemove) {
                QByteArray memberBytes = member.toUtf8();
                if (messenger_remove_group_member(ctx, currentGroupId, memberBytes.constData()) == 0) {
                    removed++;
                }
            }

            if (removed > 0) {
                QMessageBox::information(this, "Success",
                    QString::fromUtf8("Removed %1 member(s)").arg(removed));

                // Refresh the members list
                currentMembersList->clear();
                char **updatedMembers = NULL;
                int updatedCount = 0;
                if (messenger_get_group_members(ctx, currentGroupId, &updatedMembers, &updatedCount) == 0) {
                    for (int i = 0; i < updatedCount; i++) {
                        QString member = QString::fromUtf8(updatedMembers[i]);
                        QString displayText = QString::fromUtf8("") + member;

                        if (member == QString::fromUtf8(groupInfo.creator)) {
                            displayText += QString::fromUtf8(" 👑 (Creator)");
                        }

                        QListWidgetItem *item = new QListWidgetItem(displayText);
                        if (member == QString::fromUtf8(groupInfo.creator) || member == currentIdentity) {
                            item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
                            item->setForeground(Qt::gray);
                        }
                        currentMembersList->addItem(item);

                        free(updatedMembers[i]);
                    }
                    free(updatedMembers);
                }
            } else {
                QMessageBox::warning(this, "Error", "Failed to remove members");
            }
        }
    });
    layout->addWidget(removeButton);

    // Separator
    QFrame *separator = new QFrame();
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    layout->addWidget(separator);

    // Add new members section
    QLabel *addLabel = new QLabel(QString::fromUtf8("Add New Members:"));
    layout->addWidget(addLabel);

    QListWidget *availableContactsList = new QListWidget();
    availableContactsList->setSelectionMode(QAbstractItemView::MultiSelection);

    // Load all contacts
    char **allContacts = NULL;
    int contactCount = 0;
    if (messenger_get_contact_list(ctx, &allContacts, &contactCount) == 0) {
        // Create set of current members for quick lookup
        QSet<QString> currentMembers;
        for (int i = 0; i < memberCount; i++) {
            currentMembers.insert(QString::fromUtf8(members[i]));
        }

        // Add contacts that are not already members
        for (int i = 0; i < contactCount; i++) {
            QString contact = QString::fromUtf8(allContacts[i]);
            if (!currentMembers.contains(contact)) {
                QListWidgetItem *item = new QListWidgetItem(QString::fromUtf8("") + contact);
                availableContactsList->addItem(item);
            }
            free(allContacts[i]);
        }
        free(allContacts);
    }

    layout->addWidget(availableContactsList);

    // Add members button
    QPushButton *addButton = new QPushButton("Add Selected Members"); addButton->setIcon(QIcon(":/icons/add.svg")); addButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); addButton;
    addButton->setStyleSheet("background: rgba(0, 217, 255, 0.2); color: #00D9FF;");
    connect(addButton, &QPushButton::clicked, [this, availableContactsList, currentMembersList, &groupInfo]() {
        QStringList toAdd;
        for (int i = 0; i < availableContactsList->count(); i++) {
            QListWidgetItem *item = availableContactsList->item(i);
            if (item->isSelected()) {
                QString contactText = item->text();
                // Strip emoji prefix
                if (contactText.startsWith(QString::fromUtf8(""))) {
                    contactText = contactText.mid(3);
                    toAdd.append(contactText);
                }
            }
        }

        if (toAdd.isEmpty()) {
            QMessageBox::information(this, "No Selection", "Please select members to add");
            return;
        }

        int added = 0;
        for (const QString &member : toAdd) {
            QByteArray memberBytes = member.toUtf8();
            if (messenger_add_group_member(ctx, currentGroupId, memberBytes.constData()) == 0) {
                added++;
            }
        }

        if (added > 0) {
            QMessageBox::information(this, "Success",
                QString::fromUtf8("Added %1 member(s)").arg(added));

            // Refresh both lists
            currentMembersList->clear();
            availableContactsList->clear();

            // Reload members
            char **updatedMembers = NULL;
            int updatedCount = 0;
            if (messenger_get_group_members(ctx, currentGroupId, &updatedMembers, &updatedCount) == 0) {
                QSet<QString> updatedMemberSet;
                for (int i = 0; i < updatedCount; i++) {
                    QString member = QString::fromUtf8(updatedMembers[i]);
                    updatedMemberSet.insert(member);

                    QString displayText = QString::fromUtf8("") + member;
                    if (member == QString::fromUtf8(groupInfo.creator)) {
                        displayText += QString::fromUtf8(" 👑 (Creator)");
                    }

                    QListWidgetItem *item = new QListWidgetItem(displayText);
                    if (member == QString::fromUtf8(groupInfo.creator) || member == currentIdentity) {
                        item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
                        item->setForeground(Qt::gray);
                    }
                    currentMembersList->addItem(item);

                    free(updatedMembers[i]);
                }
                free(updatedMembers);

                // Reload available contacts
                char **allContacts = NULL;
                int contactCount = 0;
                if (messenger_get_contact_list(ctx, &allContacts, &contactCount) == 0) {
                    for (int i = 0; i < contactCount; i++) {
                        QString contact = QString::fromUtf8(allContacts[i]);
                        if (!updatedMemberSet.contains(contact)) {
                            availableContactsList->addItem(QString::fromUtf8("") + contact);
                        }
                        free(allContacts[i]);
                    }
                    free(allContacts);
                }
            }
        } else {
            QMessageBox::warning(this, "Error", "Failed to add members");
        }
    });
    layout->addWidget(addButton);

    // Close button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *closeButton = new QPushButton("Done"); closeButton->setIcon(QIcon(":/icons/check.svg")); closeButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); closeButton;
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    layout->addLayout(buttonLayout);

    // Show dialog
    dialog.exec();

    // Refresh contact list after dialog closes (in case members changed)
    loadContacts();

    // Free allocated memory
    for (int i = 0; i < memberCount; i++) {
        free(members[i]);
    }
    free(members);
    free(groupInfo.name);
    if (groupInfo.description) free(groupInfo.description);
    free(groupInfo.creator);
    free(groupInfo.created_at);
}

// User menu functions
void MainWindow::onUserMenuClicked() {
    // Create popup menu
    QMenu menu(this);
    menu.setStyleSheet(
        "QMenu {"
        "   background: #0D3438;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 10px;"
        "   padding: 10px;"
        "   font-family: 'Orbitron';"
        "   font-size: 36px;"
        "   color: #00D9FF;"
        "}"
        "QMenu::item {"
        "   background: transparent;"
        "   padding: 10px 20px;"
        "   border-radius: 5px;"
        "}"
        "QMenu::item:selected {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   color: #FFFFFF;"
        "}"
    );

    QAction *logoutAction = menu.addAction(QString::fromUtf8("Logout"));
    QAction *manageIdentitiesAction = menu.addAction(QString::fromUtf8("🔑 Manage Identities"));

    connect(logoutAction, &QAction::triggered, this, &MainWindow::onLogout);
    connect(manageIdentitiesAction, &QAction::triggered, this, &MainWindow::onManageIdentities);

    // Show menu below the button
    QPoint globalPos = userMenuButton->mapToGlobal(QPoint(0, userMenuButton->height()));
    menu.exec(globalPos);
}

void MainWindow::onLogout() {
    QMessageBox::StandardButton reply = QMessageBox::question(
        this,
        "Logout",
        QString::fromUtf8("Are you sure you want to logout?"),
        QMessageBox::Yes | QMessageBox::No
    );

    if (reply == QMessageBox::Yes) {
        // Clear saved identity from config
        QSettings settings("DNA Messenger", "GUI");
        settings.remove("currentIdentity");

        QMessageBox::information(this, "Logout",
            QString::fromUtf8("Logged out successfully.\n\nThe application will now close.\n"
                             "You can login with a different identity on next launch."));

        // Close the application
        QApplication::quit();
    }
}

void MainWindow::onManageIdentities() {
    // Create dialog
    QDialog dialog(this);
    dialog.setWindowTitle(QString::fromUtf8("🔑 Manage Identities"));
    dialog.setMinimumSize(700, 500);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);

    // Info label
    QLabel *infoLabel = new QLabel(
        QString::fromUtf8("Current Identity: %1\n\n"
                         "Identity keys are stored in: ~/.dna/\n"
                         "Each identity has its own encryption and signing keys.")
        .arg(currentIdentity)
    );
    infoLabel->setStyleSheet("background: rgba(0, 217, 255, 0.1); padding: 15px; border-radius: 5px;");
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    // List available identities from ~/.dna/ directory
    QLabel *listLabel = new QLabel(QString::fromUtf8("📂 Available Identities:"));
    layout->addWidget(listLabel);

    QListWidget *identityList = new QListWidget();

    QDir homeDir = QDir::home();
    QDir dnaDir = homeDir.filePath(".dna");

    if (dnaDir.exists()) {
        QStringList keyFiles = dnaDir.entryList(QStringList() << "*-dilithium.pqkey", QDir::Files);
        for (const QString &keyFile : keyFiles) {
            QString identity = keyFile;
            identity.remove("-dilithium.pqkey");

            QString displayText = QString::fromUtf8("🔑 ") + identity;
            if (identity == currentIdentity) {
                displayText += QString::fromUtf8(" (current)");
            }
            identityList->addItem(displayText);
        }
    }

    layout->addWidget(identityList);

    // Action buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    QPushButton *switchButton = new QPushButton("Switch Identity"); switchButton->setIcon(QIcon(":/icons/switch.svg")); switchButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); switchButton;
    connect(switchButton, &QPushButton::clicked, [this, identityList, &dialog]() {
        QListWidgetItem *selectedItem = identityList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(this, "No Selection", "Please select an identity to switch to");
            return;
        }

        QString selectedText = selectedItem->text();
        // Remove emoji and "(current)" marker
        selectedText = selectedText.remove(QString::fromUtf8("🔑 ")).remove(QString::fromUtf8(" (current)")).trimmed();

        if (selectedText == currentIdentity) {
            QMessageBox::information(this, "Already Current",
                QString::fromUtf8("You are already logged in as '%1'").arg(selectedText));
            return;
        }

        QMessageBox::StandardButton reply = QMessageBox::question(
            this,
            "Switch Identity",
            QString::fromUtf8("Switch to identity '%1'?\n\n"
                             "The application will restart.").arg(selectedText),
            QMessageBox::Yes | QMessageBox::No
        );

        if (reply == QMessageBox::Yes) {
            // Save new identity to config
            QSettings settings("DNA Messenger", "GUI");
            settings.setValue("currentIdentity", selectedText);

            QMessageBox::information(this, "Identity Switched",
                QString::fromUtf8("Identity switched to '%1'.\n\n"
                                 "The application will now restart.").arg(selectedText));

            // Restart the application
            dialog.accept();
            QApplication::quit();
            QProcess::startDetached(QApplication::applicationFilePath(), QStringList());
        }
    });
    buttonLayout->addWidget(switchButton);

    QPushButton *closeButton = new QPushButton("Close"); closeButton->setIcon(QIcon(":/icons/close.svg")); closeButton->setIconSize(QSize(static_cast<int>(18 * fontScale), static_cast<int>(18 * fontScale))); closeButton;
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    layout->addLayout(buttonLayout);

    // Additional info
    QLabel *noteLabel = new QLabel(
        QString::fromUtf8("💡 Note: To create a new identity, use the CLI tool:\n"
                         "   ./dna_messenger")
    );
    noteLabel->setStyleSheet("color: gray; font-size: 10px;");
    noteLabel->setWordWrap(true);
    layout->addWidget(noteLabel);

    dialog.exec();
}

void MainWindow::onWallet() {
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(QString::fromUtf8("CF20 Wallet"));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setText(QString::fromUtf8("🚧 CF20 Wallet - Coming Soon!\n\n"
                                     "Integrated Cellframe CF20 token wallet for cpunk network.\n\n"
                                     "Planned Features:\n"
                                     "• 💳 Read local Cellframe wallet files\n"
                                     "• 🌐 Connect via public RPC to cpunk network\n"
                                     "• 💰 View CF20 token balances\n"
                                     "• 💸 Send/receive CF20 tokens directly in messenger\n"
                                     "• 📊 Transaction history\n"
                                     "• 🔐 Secure wallet integration\n\n"
                                     "Network: Cellframe cpunk\n"
                                     "Status: To be implemented in Phase 8+"));
    msgBox.setStandardButtons(QMessageBox::Ok);

    // Style the message box
    msgBox.setStyleSheet(
        "QMessageBox {"
        "   background: #0D3438;"
        "   color: #00D9FF;"
        "   font-family: 'Orbitron';"
        "}"
        "QLabel {"
        "   color: #00D9FF;"
        "   font-size: 12px;"
        "}"
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   border: 2px solid #00D9FF;"
        "   border-radius: 5px;"
        "   padding: 8px 20px;"
        "   font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.3);"
        "}"
    );

    msgBox.exec();
}
