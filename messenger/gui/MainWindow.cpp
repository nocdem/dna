/*
 * DNA Messenger - Qt GUI
 * Main Window Implementation
 */

#include "MainWindow.h"
#include "WalletDialog.h"
#include "SendTokensDialog.h"
#include "ThemeManager.h"

extern "C" {
    #include "../wallet.h"
}

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
#include <QFileDialog>
#include <QBuffer>
#include <QImageReader>
#include <QImageWriter>
#include <QRegularExpression>

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

MainWindow::MainWindow(const QString &identity, QWidget *parent)
    : QMainWindow(parent), ctx(nullptr), lastCheckedMessageId(0), currentGroupId(-1), currentContactType(TYPE_CONTACT), fontScale(1.5) {  // Changed default from 3.0 to 1.5

    // Remove native window frame for custom title bar
    // Use native window frame instead of custom frameless window
    // setWindowFlags(Qt::FramelessWindowHint);  // REMOVED: Using native title bar now

    // Use identity provided by IdentitySelectionDialog
    currentIdentity = identity;

    setWindowTitle(QString("DNA Messenger v%1 - %2").arg(PQSIGNUM_VERSION).arg(currentIdentity));

    // Initialize fullscreen state
    isFullscreen = false;

    // Save selected identity to settings for future reference
    QSettings settings("DNA Messenger", "GUI");
    settings.setValue("currentIdentity", currentIdentity);

    // Initialize messenger context
    ctx = messenger_init(currentIdentity.toUtf8().constData());
    if (!ctx) {
        QMessageBox::critical(this, "Error",
                              QString("Failed to initialize messenger for '%1'").arg(currentIdentity));
        QApplication::quit();
        return;
    }

    // Phase 9.1b: Initialize P2P transport
    printf("[P2P] Initializing P2P transport for %s...\n", currentIdentity.toUtf8().constData());
    if (messenger_p2p_init(ctx) == 0) {
        printf("[P2P] ✓ P2P transport initialized successfully\n");
    } else {
        printf("[P2P] ✗ P2P transport initialization failed (will use PostgreSQL only)\n");
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

    // Phase 9.1b: Initialize P2P presence refresh timer (5 minutes)
    p2pPresenceTimer = new QTimer(this);
    connect(p2pPresenceTimer, &QTimer::timeout, this, &MainWindow::onRefreshP2PPresence);
    p2pPresenceTimer->start(300000);  // 5 minutes = 300,000ms

    // Phase 9.2: Initialize DHT offline message check timer (2 minutes)
    offlineMessageTimer = new QTimer(this);
    connect(offlineMessageTimer, &QTimer::timeout, this, &MainWindow::onCheckOfflineMessages);
    offlineMessageTimer->start(120000);  // 2 minutes = 120,000ms

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
        // Phase 9.1b: Shutdown P2P transport before freeing messenger
        if (ctx->p2p_enabled) {
            printf("[P2P] Shutting down P2P transport...\n");
            messenger_p2p_shutdown(ctx);
        }
        messenger_free(ctx);
    }
}

void MainWindow::setupUI() {

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
        "   font-family: 'Orbitron'; font-size: 12px;"
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
        "   font-family: 'Orbitron'; font-size: 12px;"
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
        "   font-family: 'Orbitron'; font-size: 12px;"
        "   padding: 8px;"
        "   border-top: 2px solid #00D9FF;"
        "}"
    );

    // Create menu bar and set it as the main window menu bar
    QMenuBar *menuBar = new QMenuBar(this);
    setMenuBar(menuBar);  // This makes it a native menu bar

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

    // Wallet menu (dynamically populated with wallet names)
    walletMenu = menuBar->addMenu(QString::fromUtf8("💰 Wallet"));
    refreshWalletMenu();  // Populate with wallet names

    // View menu (NEW)
    QMenu *viewMenu = menuBar->addMenu(QString::fromUtf8("View"));
    QAction *fullscreenAction = viewMenu->addAction(QString::fromUtf8("Fullscreen (F11)"));
    fullscreenAction->setCheckable(true);
    fullscreenAction->setShortcut(QKeySequence(Qt::Key_F11));
    connect(fullscreenAction, &QAction::triggered, this, &MainWindow::onToggleFullscreen);

    // Help menu (removed Check for Updates - will be implemented as binary updater in future)
    // QMenu *helpMenu = menuBar->addMenu(QString::fromUtf8("Help"));

    // Central widget with vertical layout
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *mainVerticalLayout = new QVBoxLayout(centralWidget);
    mainVerticalLayout->setContentsMargins(0, 0, 0, 0);
    mainVerticalLayout->setSpacing(0);

    // Note: titleBar removed - using native OS title bar
    // Note: menuBar managed by QMainWindow (setMenuBar in constructor)

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
        "font-family: 'Orbitron'; font-size: 16px; "
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
        "   font-family: 'Orbitron'; font-size: 12px;"
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
        "   font-family: 'Orbitron'; font-size: 13px;"
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
        "   font-family: 'Orbitron'; font-size: 13px;"
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
        "   font-family: 'Orbitron'; font-size: 12px;"
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
        "   font-family: 'Orbitron'; font-size: 12px;"
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
        "font-family: 'Orbitron'; font-size: 16px; "
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
        "   font-family: 'Orbitron'; font-size: 12px;"
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
        "   font-family: 'Orbitron'; font-size: 11px;"
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
        "   font-family: 'Orbitron'; font-size: 11px;"
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
        "   font-family: 'Orbitron'; font-size: 13px;"
        "   color: #00D9FF;"
        "}"
        "QLineEdit:focus {"
        "   border: 2px solid #33E6FF;"
        "   background: rgba(0, 217, 255, 0.1);"
        "}"
    );
    connect(messageInput, &QLineEdit::returnPressed, this, &MainWindow::onSendMessage);
    inputLayout->addWidget(messageInput);

    // Attach Image button
    attachImageButton = new QPushButton("Image");
    attachImageButton->setIcon(QIcon(":/icons/add.svg"));  // Using add icon as paperclip
    attachImageButton->setIconSize(QSize(scaledIconSize(18), scaledIconSize(18)));
    attachImageButton->setToolTip("Attach image");
    attachImageButton->setStyleSheet(
        "QPushButton {"
        "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "       stop:0 #00A8CC, stop:1 #00D9FF);"
        "   color: white;"
        "   border: 2px solid #00A8CC;"
        "   border-radius: 15px;"
        "   padding: 15px 25px;"
        "   font-weight: bold;"
        "   font-family: 'Orbitron'; font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "   background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "       stop:0 #00D9FF, stop:1 #33E6FF);"
        "   border: 2px solid #00D9FF;"
        "}"
        "QPushButton:pressed {"
        "   background: #008CA8;"
        "   border: 2px solid #006B82;"
        "}"
    );
    connect(attachImageButton, &QPushButton::clicked, this, &MainWindow::onAttachImage);
    inputLayout->addWidget(attachImageButton);

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
        "   font-family: 'Orbitron'; font-size: 13px;"
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

    // Phase 9.1b: P2P status indicator
    p2pStatusLabel = new QLabel(ctx->p2p_enabled ?
        QString::fromUtf8("🔵 P2P: Online") :
        QString::fromUtf8("🔴 P2P: Disabled"));
    statusBar()->addPermanentWidget(p2pStatusLabel);
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
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8("Me"), QString::fromUtf8("•"), timeOnly, statusCheckmark).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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
                        ).arg(metaFontSize).arg(QString::fromUtf8(""), sender, QString::fromUtf8("•"), timeOnly).arg(messageFontSize).arg(processMessageForDisplay(messageText));
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

    // Get all messages from SQLite for current user
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx,
                                                     currentIdentity.toUtf8().constData(),
                                                     &all_messages,
                                                     &all_count);
    if (result != 0) {
        fprintf(stderr, "[GUI] Failed to fetch messages from SQLite\n");
        return;
    }

    // Filter for new UNREAD incoming messages since lastCheckedMessageId
    for (int i = 0; i < all_count; i++) {
        // Only process incoming messages (where we are recipient)
        if (strcmp(all_messages[i].recipient, currentIdentity.toUtf8().constData()) != 0) {
            continue;
        }

        // Only process messages newer than lastCheckedMessageId
        if (all_messages[i].id <= lastCheckedMessageId) {
            continue;
        }

        // Only process unread messages
        if (all_messages[i].read) {
            continue;
        }

        int msgId = all_messages[i].id;
        QString sender = QString::fromUtf8(all_messages[i].sender);

        // Format timestamp
        struct tm *tm_info = localtime(&all_messages[i].timestamp);
        char timestamp_str[32];
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
        QString timestamp = QString::fromUtf8(timestamp_str);

        QString status = all_messages[i].read ? "read" : (all_messages[i].delivered ? "delivered" : "sent");

        if (msgId > lastCheckedMessageId) {
            lastCheckedMessageId = msgId;
        }

        // Mark message as delivered (recipient has fetched it)
        int markResult = messenger_mark_delivered(ctx, msgId);
        printf("[DELIVERY] Message ID %d marked as delivered (result: %d)\n", msgId, markResult);

        // Only notify if message is not already read
        if (!all_messages[i].read) {
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

    message_backup_free_messages(all_messages, all_count);
}

void MainWindow::checkForStatusUpdates() {
    // Only check if we have an active conversation open
    if (!ctx || currentContact.isEmpty()) {
        return;
    }

    // Get conversation from SQLite
    backup_message_t *messages = NULL;
    int count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx,
                                                   currentContact.toUtf8().constData(),
                                                   &messages,
                                                   &count);
    if (result != 0) {
        fprintf(stderr, "[GUI] Failed to fetch conversation from SQLite\n");
        return;
    }

    // Check for delivered or read status on our sent messages (where we are sender)
    int status_update_count = 0;
    for (int i = count - 1; i >= 0 && status_update_count < 5; i--) {
        // Only check messages we sent (sender = current identity)
        if (strcmp(messages[i].sender, currentIdentity.toUtf8().constData()) != 0) {
            continue;
        }

        // Only count messages that have been delivered or read
        if (messages[i].delivered || messages[i].read) {
            status_update_count++;
        }
    }

    // Silently refresh conversation to update checkmarks if there were any updates
    if (status_update_count > 0) {
        loadConversation(currentContact);
    }

    message_backup_free_messages(messages, count);
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onThemeIO() {
    ThemeManager::instance()->setTheme(THEME_CPUNK_IO);
    applyTheme("io");
}

void MainWindow::onThemeClub() {
    ThemeManager::instance()->setTheme(THEME_CPUNK_CLUB);
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

// Fullscreen support (F11 key or ESC to exit)
bool MainWindow::eventFilter(QObject *obj, QEvent *event) {
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->key() == Qt::Key_Escape && isFullscreen) {
            onToggleFullscreen();
            return true;
        }
    }
    return QMainWindow::eventFilter(obj, event);
}

void MainWindow::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_F11) {
        onToggleFullscreen();
        event->accept();
    } else {
        QMainWindow::keyPressEvent(event);
    }
}

void MainWindow::onToggleFullscreen() {
    if (isFullscreen) {
        // Exit fullscreen
        showNormal();
        if (!normalGeometry.isNull()) {
            setGeometry(normalGeometry);
        }
        isFullscreen = false;
        statusLabel->setText("Exited fullscreen");
    } else {
        // Enter fullscreen
        normalGeometry = geometry();
        showFullScreen();
        isFullscreen = true;
        statusLabel->setText("Fullscreen (Press F11 or ESC to exit)");
    }
}

// Window control buttons (kept for compatibility, but may not be used with native title bar)
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
        "   font-size: 12px;"
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
    // Open the CF20 Wallet Dialog showing all wallets
    WalletDialog walletDialog(this);
    walletDialog.exec();
}

void MainWindow::refreshWalletMenu() {
    // Clear existing menu items
    walletMenu->clear();

    // Load wallets from Cellframe wallet directory
    wallet_list_t *wallets = nullptr;
    if (wallet_list_cellframe(&wallets) == 0 && wallets && wallets->count > 0) {
        // Add each wallet as a menu item
        for (size_t i = 0; i < wallets->count; i++) {
            QString walletName = QString::fromUtf8(wallets->wallets[i].name);

            // Add status indicator
            QString displayName = walletName;
            if (wallets->wallets[i].status == WALLET_STATUS_PROTECTED) {
                displayName = QString::fromUtf8("🔒 ") + walletName;
            }

            QAction *walletAction = walletMenu->addAction(displayName);
            connect(walletAction, &QAction::triggered, this, [this, walletName]() {
                onWalletSelected(walletName);
            });
        }

        wallet_list_free(wallets);
    }

    // If no wallets found, show message
    if (!wallets || wallets->count == 0) {
        QAction *noWalletsAction = walletMenu->addAction(QString::fromUtf8("No wallets found"));
        noWalletsAction->setEnabled(false);
    }
}

void MainWindow::onWalletSelected(const QString &walletName) {
    // Open detached WalletDialog with the specified wallet
    WalletDialog *walletDialog = new WalletDialog(this, walletName);
    walletDialog->setAttribute(Qt::WA_DeleteOnClose);
    walletDialog->show();
    walletDialog->raise();
    walletDialog->activateWindow();
}

// ============================================================================
// IMAGE SUPPORT FUNCTIONS
// ============================================================================

void MainWindow::onAttachImage() {
    // Open file dialog to select image
    QString fileName = QFileDialog::getOpenFileName(
        this,
        "Select Image",
        QDir::homePath(),
        "Images (*.png *.jpg *.jpeg *.gif *.webp *.bmp);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;  // User cancelled
    }

    // Check file size (5MB limit before base64)
    QFileInfo fileInfo(fileName);
    qint64 fileSize = fileInfo.size();
    const qint64 MAX_SIZE = 5 * 1024 * 1024;  // 5MB

    if (fileSize > MAX_SIZE) {
        QMessageBox::warning(this, "Image Too Large",
            QString("Image is too large (%1 MB).\n"
                    "Maximum size is 5 MB.\n\n"
                    "Consider resizing the image.")
                .arg(fileSize / 1024.0 / 1024.0, 0, 'f', 2));
        return;
    }

    // Convert image to base64
    QString base64 = imageToBase64(fileName);
    if (base64.isEmpty()) {
        QMessageBox::critical(this, "Error", "Failed to load image.");
        return;
    }

    // Append to message input
    QString currentText = messageInput->text();
    if (!currentText.isEmpty() && !currentText.endsWith('\n')) {
        currentText += "\n";
    }
    currentText += "[IMG:" + base64 + "]";
    messageInput->setText(currentText);

    statusLabel->setText(QString("Image attached (%1 KB)")
        .arg(fileSize / 1024.0, 0, 'f', 1));
}

QString MainWindow::imageToBase64(const QString &imagePath) {
    // Load image
    QImage image(imagePath);
    if (image.isNull()) {
        return QString();
    }

    // Resize if too large (max 1920x1080)
    const int MAX_WIDTH = 1920;
    const int MAX_HEIGHT = 1080;

    if (image.width() > MAX_WIDTH || image.height() > MAX_HEIGHT) {
        image = image.scaled(MAX_WIDTH, MAX_HEIGHT, 
                            Qt::KeepAspectRatio, 
                            Qt::SmoothTransformation);
    }

    // Convert to PNG format (for lossless quality)
    QByteArray byteArray;
    QBuffer buffer(&byteArray);
    buffer.open(QIODevice::WriteOnly);

    // Determine format from file extension
    QString format = "PNG";
    QString suffix = QFileInfo(imagePath).suffix().toUpper();
    if (suffix == "JPG" || suffix == "JPEG") {
        format = "JPEG";
    } else if (suffix == "GIF") {
        format = "GIF";
    } else if (suffix == "WEBP") {
        format = "WEBP";
    }

    image.save(&buffer, format.toUtf8().constData(), 85);  // 85% quality for JPEG

    // Convert to base64 with data URI
    QString base64 = "data:image/" + format.toLower() + ";base64," + 
                     byteArray.toBase64();

    return base64;
}

QString MainWindow::processMessageForDisplay(const QString &messageText) {
    QString processed = messageText;

    // Find all [IMG:data:image/...] markers and replace with HTML img tags
    QRegularExpression imgRegex(R"(\[IMG:(data:image/[^]]+)\])");
    QRegularExpressionMatchIterator it = imgRegex.globalMatch(processed);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString fullMatch = match.captured(0);  // [IMG:data:...]
        QString dataUri = match.captured(1);     // data:image/...

        // Replace with HTML img tag (max width for display)
        QString imgTag = QString("<br><img src='%1' style='max-width: 400px; max-height: 300px; border-radius: 10px;'><br>")
                            .arg(dataUri);

        processed.replace(fullMatch, imgTag);
    }

    return processed;
}


// ============================================================================
// Phase 9.1b: P2P Integration Slots
// ============================================================================

void MainWindow::onRefreshP2PPresence() {
    if (!ctx || !ctx->p2p_enabled) {
        return;
    }

    // Refresh presence in DHT (re-announce our identity)
    if (messenger_p2p_refresh_presence(ctx) == 0) {
        printf("[P2P] Presence refreshed in DHT\n");
    } else {
        printf("[P2P] Failed to refresh presence\n");
    }
}

void MainWindow::onCheckPeerStatus() {
    if (!ctx || !ctx->p2p_enabled || currentContact.isEmpty()) {
        return;
    }

    // Check if current contact is online via P2P
    bool online = messenger_p2p_peer_online(ctx, currentContact.toUtf8().constData());

    if (online) {
        printf("[P2P] %s is ONLINE (P2P available)\n", currentContact.toUtf8().constData());
    }
}

void MainWindow::onCheckOfflineMessages() {
    if (!ctx || !ctx->p2p_enabled) {
        return;
    }

    // Check DHT for offline messages (Phase 9.2)
    size_t messages_received = 0;
    int result = messenger_p2p_check_offline_messages(ctx, &messages_received);

    if (result == 0 && messages_received > 0) {
        printf("[P2P] Retrieved %zu offline messages from DHT\n", messages_received);

        // Refresh message list to show newly delivered messages
        checkForNewMessages();
    }
}
