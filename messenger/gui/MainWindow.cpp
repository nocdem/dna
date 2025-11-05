/*
 * DNA Messenger - Qt GUI
 * Main Window Implementation
 */

#include "MainWindow.h"
#include "WalletDialog.h"
#include "SendTokensDialog.h"
#include "ThemeManager.h"
#include "RegisterDNANameDialog.h"
#include "ProfileEditorDialog.h"
#include "MessageWallDialog.h"

extern "C" {
    #include "../wallet.h"
    #include "../contacts_db.h"
    #include "../dht/dht_keyserver.h"
    #include "../dht/dna_profile.h"
    #include "../p2p/p2p_transport.h"
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
    QString searchPath = dnaDir.filePath("*.dsa");
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.toUtf8().constData(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return QString();  // No identity files found
    }

    // Extract identity from filename (remove .dsa suffix)
    QString filename = QString::fromUtf8(findData.cFileName);
    FindClose(hFind);

    if (filename.endsWith(".dsa")) {
        return filename.left(filename.length() - 4);  // Remove suffix (4 chars: ".dsa")
    }
    return QString();
#else
    // Unix: use glob
    QString pattern = dnaDir.filePath("*.dsa");
    glob_t globResult;

    if (glob(pattern.toUtf8().constData(), GLOB_NOSORT, NULL, &globResult) == 0 && globResult.gl_pathc > 0) {
        // Extract filename from path
        QString path = QString::fromUtf8(globResult.gl_pathv[0]);
        QString filename = QFileInfo(path).fileName();

        globfree(&globResult);

        if (filename.endsWith(".dsa")) {
            return filename.left(filename.length() - 4);  // Remove suffix (4 chars: ".dsa")
        }
    }

    globfree(&globResult);
    return QString();
#endif
}

// Phase 7: Get display name for sender (registered name or shortened fingerprint)
QString MainWindow::getDisplayNameForSender(const QString &senderFingerprint) {
    if (!ctx || senderFingerprint.isEmpty()) {
        return QString::fromUtf8("Unknown");
    }

    // Check if sender is in contacts first (fastest)
    if (contactItems.contains(senderFingerprint)) {
        return contactItems[senderFingerprint].name;
    }

    // Try DHT reverse lookup for registered name
    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (dht_ctx) {
        char *identity_result = nullptr;
        int ret = dht_keyserver_reverse_lookup(dht_ctx,
                                                senderFingerprint.toUtf8().constData(),
                                                &identity_result);

        if (ret == 0 && identity_result) {
            // Found registered name
            QString displayName = QString::fromUtf8(identity_result);
            free(identity_result);

            // Add verification indicator for registered names
            return displayName + QString::fromUtf8(" ✓");
        }
    }

    // No registered name, return shortened fingerprint (first 5 bytes + ... + last 5 bytes)
    if (senderFingerprint.length() > 20) {
        return senderFingerprint.left(10) + "..." + senderFingerprint.right(10);
    }

    return senderFingerprint;
}

MainWindow::MainWindow(const QString &identity, QWidget *parent)
    : QMainWindow(parent), ctx(nullptr), lastCheckedMessageId(0), currentGroupId(-1), currentContactType(TYPE_CONTACT), fontScale(1.5) {  // Changed default from 3.0 to 1.5

    // Remove native window frame for custom title bar
    // Use native window frame instead of custom frameless window
    // setWindowFlags(Qt::FramelessWindowHint);  // REMOVED: Using native title bar now

    // Use identity provided by IdentitySelectionDialog
    currentIdentity = identity;

    // Show shortened fingerprint in window title (first 5 chars ... last 5 chars)
    QString shortIdentity = currentIdentity.left(5) + "..." + currentIdentity.right(5);
    setWindowTitle(QString("DNA Messenger v%1 - %2").arg(PQSIGNUM_VERSION).arg(shortIdentity));

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

    // Initialize per-identity contacts database
    if (contacts_db_init(currentIdentity.toUtf8().constData()) != 0) {
        QMessageBox::critical(this, "Error",
                              QString("Failed to initialize contacts database for '%1'").arg(currentIdentity));
        QApplication::quit();
        return;
    }

    // Migrate from global contacts.db if needed (first time only)
    int migrated = contacts_db_migrate_from_global(currentIdentity.toUtf8().constData());
    if (migrated > 0) {
        QMessageBox::information(this, "Contacts Migrated",
                                QString("Migrated %1 contacts from global database to '%2'").arg(migrated).arg(currentIdentity));
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

    // Phase 7: Check DNA name expiration on startup (after 3 seconds delay)
    QTimer::singleShot(3000, this, &MainWindow::checkNameExpiration);

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

    // Initialize contact list sync timer (10 minutes)
    contactSyncTimer = new QTimer(this);
    connect(contactSyncTimer, &QTimer::timeout, this, &MainWindow::onAutoSyncContacts);
    contactSyncTimer->start(600000);  // 10 minutes = 600,000ms

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
    // Stop all timers to prevent events on destroyed window
    if (pollTimer) {
        pollTimer->stop();
        delete pollTimer;
    }
    if (statusPollTimer) {
        statusPollTimer->stop();
        delete statusPollTimer;
    }
    if (p2pPresenceTimer) {
        p2pPresenceTimer->stop();
        delete p2pPresenceTimer;
    }
    if (offlineMessageTimer) {
        offlineMessageTimer->stop();
        delete offlineMessageTimer;
    }
    if (contactSyncTimer) {
        contactSyncTimer->stop();
        delete contactSyncTimer;
    }

    // Clean up system tray icon
    if (trayIcon) {
        trayIcon->hide();
        delete trayIcon;
    }

    // Clean up notification sound
    if (notificationSound) {
        delete notificationSound;
    }

    // Shutdown messenger context
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

    // Sync Contacts action
    QAction *syncContactsAction = settingsMenu->addAction(QString::fromUtf8("🔄 Sync Contacts to DHT"));
    connect(syncContactsAction, &QAction::triggered, this, &MainWindow::onSyncContacts);

    // Register DNA Name action (Phase 4)
    QAction *registerNameAction = settingsMenu->addAction(QString::fromUtf8("🏷️ Register DNA Name"));
    connect(registerNameAction, &QAction::triggered, this, &MainWindow::onRegisterDNAName);

    // Edit Profile action (Phase 5)
    QAction *editProfileAction = settingsMenu->addAction(QString::fromUtf8("✏️ Edit Profile"));
    connect(editProfileAction, &QAction::triggered, this, &MainWindow::onEditProfile);

    // View My Message Wall action (Phase 6)
    QAction *viewMyWallAction = settingsMenu->addAction(QString::fromUtf8("📋 My Message Wall"));
    connect(viewMyWallAction, &QAction::triggered, this, &MainWindow::onViewMyMessageWall);
    settingsMenu->addSeparator();

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

    // User menu button at very top (show shortened fingerprint: 5 chars ... 5 chars)
    QString shortIdentity = currentIdentity.left(5) + "..." + currentIdentity.right(5);
    userMenuButton = new QPushButton(shortIdentity);
    userMenuButton->setIcon(QIcon(":/icons/user.svg"));
    userMenuButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    userMenuButton->setToolTip(QString("User Menu\n\nFull fingerprint:\n%1").arg(currentIdentity));
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

    // Add Contact button
    addContactButton = new QPushButton("Add Contact");
    addContactButton->setIcon(QIcon(":/icons/user.svg"));
    addContactButton->setIconSize(QSize(scaledIconSize(20), scaledIconSize(20)));
    addContactButton->setToolTip("Add a new contact");
    addContactButton->setStyleSheet(
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
    connect(addContactButton, &QPushButton::clicked, this, &MainWindow::onAddContact);
    leftLayout->addWidget(addContactButton);

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

    // Contact list sync status indicator
    syncStatusLabel = new QLabel(QString::fromUtf8("📇 Contacts: Local"));
    statusBar()->addPermanentWidget(syncStatusLabel);

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

            // Phase 4: Resolve display name and fingerprint
            char displayName[256] = {0};
            char fingerprint[129] = {0};

            // Get display name (registered name or shortened fingerprint)
            if (messenger_get_display_name(ctx, identities[i], displayName) == 0) {
                // Success
            } else {
                // Fallback to raw identity
                strncpy(displayName, identities[i], sizeof(displayName) - 1);
            }

            // Compute fingerprint
            if (messenger_compute_identity_fingerprint(identities[i], fingerprint) != 0) {
                // If computation fails, store the identity as-is
                strncpy(fingerprint, identities[i], sizeof(fingerprint) - 1);
            }

            QString displayText = QString::fromUtf8("") + QString::fromUtf8(displayName);
            QListWidgetItem *listItem = new QListWidgetItem(displayText);

            // Set tooltip with full fingerprint
            QString tooltipText = QString("Identity: %1\nFingerprint: %2")
                .arg(QString::fromUtf8(displayName))
                .arg(QString::fromUtf8(fingerprint));
            listItem->setToolTip(tooltipText);

            contactList->addItem(listItem);

            // Store contact metadata
            ContactItem item;
            item.type = TYPE_CONTACT;
            item.name = QString::fromUtf8(displayName);
            item.fingerprint = QString::fromUtf8(fingerprint);
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
                QString senderFingerprint = QString::fromUtf8(messages[i].sender);
                QString recipient = QString::fromUtf8(messages[i].recipient);
                QString timestamp = QString::fromUtf8(messages[i].timestamp);

                // Phase 7: Resolve sender display name (contacts + DHT registered names)
                QString sender = getDisplayNameForSender(senderFingerprint);

                // Format timestamp (extract time from "YYYY-MM-DD HH:MM:SS")
                QString timeOnly = timestamp.mid(11, 5);  // Extract "HH:MM"

                // Decrypt message if current user can decrypt it
                // This includes: received messages (recipient == currentIdentity)
                // AND sent messages (sender == currentIdentity, thanks to sender-as-first-recipient)
                QString messageText = "[encrypted]";
                if (recipient == currentIdentity || senderFingerprint == currentIdentity) {
                    char *plaintext = NULL;
                    size_t plaintext_len = 0;

                    if (messenger_decrypt_message(ctx, messages[i].id, &plaintext, &plaintext_len) == 0) {
                        messageText = QString::fromUtf8(plaintext, plaintext_len);
                        free(plaintext);
                    } else {
                        messageText = QString::fromUtf8("🔒 [decryption failed]");
                    }
                }

                if (senderFingerprint == currentIdentity) {
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
                QString senderFingerprint = QString::fromUtf8(messages[i].sender);
                QString timestamp = QString::fromUtf8(messages[i].timestamp);

                // Phase 7: Resolve sender display name (contacts + DHT registered names)
                QString sender = getDisplayNameForSender(senderFingerprint);

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

                if (senderFingerprint == currentIdentity) {
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

void MainWindow::onAddContact() {
    bool ok;
    QString identity = QInputDialog::getText(
        this,
        QString::fromUtf8("Add Contact"),
        QString::fromUtf8("Enter contact identity:"),
        QLineEdit::Normal,
        QString::fromUtf8(""),
        &ok
    );

    if (!ok || identity.trimmed().isEmpty()) {
        return;  // User cancelled or entered empty string
    }

    identity = identity.trimmed();

    // Check if contact already exists
    if (contacts_db_exists(identity.toUtf8().constData())) {
        QMessageBox::information(
            this,
            QString::fromUtf8("Contact Exists"),
            QString::fromUtf8("'%1' is already in your contacts.").arg(identity)
        );
        return;
    }

    // Verify identity exists on DHT by fetching public keys
    statusLabel->setText(QString::fromUtf8("Verifying '%1' on DHT...").arg(identity));
    QApplication::processEvents();  // Update UI

    uint8_t *signing_pubkey = NULL;
    size_t signing_pubkey_len = 0;
    uint8_t *encryption_pubkey = NULL;
    size_t encryption_pubkey_len = 0;
    char fingerprint[129] = {0};  // Buffer for fingerprint output

    int result = messenger_load_pubkey(
        ctx,
        identity.toUtf8().constData(),
        &signing_pubkey,
        &signing_pubkey_len,
        &encryption_pubkey,
        &encryption_pubkey_len,
        fingerprint  // Get fingerprint from DHT lookup
    );

    if (result != 0) {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Identity Not Found"),
            QString::fromUtf8(
                "Identity '%1' not found on DHT keyserver.\n\n"
                "Make sure the identity exists and has published their public keys."
            ).arg(identity)
        );
        statusLabel->setText(QString::fromUtf8("Identity not found on DHT"));
        return;
    }

    // Free the public keys (already cached by messenger_load_pubkey)
    free(signing_pubkey);
    free(encryption_pubkey);

    // Add contact to database using FINGERPRINT (not name!)
    result = contacts_db_add(fingerprint, NULL);
    if (result == 0) {
        QMessageBox::information(
            this,
            QString::fromUtf8("Success"),
            QString::fromUtf8(
                "Contact '%1' added successfully.\n\n"
                "Public keys verified and cached from DHT."
            ).arg(identity)
        );
        loadContacts();  // Refresh contact list
        statusLabel->setText(QString::fromUtf8("Contact added"));

        // Immediately sync to DHT after adding contact
        printf("[CONTACT_SYNC] Auto-syncing after contact add...\n");
        syncStatusLabel->setText(QString::fromUtf8("📇 Syncing..."));
        QApplication::processEvents();  // Update UI

        int sync_result = messenger_sync_contacts_to_dht(ctx);
        if (sync_result == 0) {
            printf("[CONTACT_SYNC] Successfully synced to DHT\n");
            syncStatusLabel->setText(QString::fromUtf8("📇 Synced ✓"));
        } else {
            printf("[CONTACT_SYNC] Failed to sync to DHT\n");
            syncStatusLabel->setText(QString::fromUtf8("📇 Sync failed"));
        }
    } else {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Error"),
            QString::fromUtf8("Failed to add contact '%1' to database.").arg(identity)
        );
        statusLabel->setText(QString::fromUtf8("Failed to add contact"));
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

    QAction *publishKeysAction = menu.addAction(QString::fromUtf8("📡 Publish Keys to DHT"));
    QAction *logoutAction = menu.addAction(QString::fromUtf8("Logout"));
    QAction *manageIdentitiesAction = menu.addAction(QString::fromUtf8("🔑 Manage Identities"));

    connect(publishKeysAction, &QAction::triggered, this, &MainWindow::onPublishKeys);
    connect(logoutAction, &QAction::triggered, this, &MainWindow::onLogout);
    connect(manageIdentitiesAction, &QAction::triggered, this, &MainWindow::onManageIdentities);

    // Show menu below the button
    QPoint globalPos = userMenuButton->mapToGlobal(QPoint(0, userMenuButton->height()));
    menu.exec(globalPos);
}

void MainWindow::onPublishKeys() {
    statusLabel->setText(QString::fromUtf8("Loading local keys..."));
    QApplication::processEvents();  // Update UI

    // Get home directory (platform-specific)
    QString homeDir = QDir::homePath();
    QString dilithiumPath = homeDir + "/.dna/" + currentIdentity + ".dsa";
    QString kyberPath = homeDir + "/.dna/" + currentIdentity + ".kem";

    // Load Dilithium public key (skip 276 byte header, then read 1952 bytes public key)
    // File format: [HEADER: 276 bytes][PUBLIC_KEY: 1952 bytes][PRIVATE_KEY: 4032 bytes]
    QFile dilithiumFile(dilithiumPath);
    if (!dilithiumFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Error"),
            QString::fromUtf8("Failed to open Dilithium key file:\n%1").arg(dilithiumPath)
        );
        statusLabel->setText(QString::fromUtf8("Failed to load keys"));
        return;
    }

    dilithiumFile.seek(276);  // Skip header (qgp_privkey_file_header_t = 276 bytes)
    QByteArray dilithiumPubkey = dilithiumFile.read(1952);
    dilithiumFile.close();

    if (dilithiumPubkey.size() != 1952) {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Error"),
            QString::fromUtf8("Invalid Dilithium key file (expected 1952 bytes public key)")
        );
        statusLabel->setText(QString::fromUtf8("Failed to load keys"));
        return;
    }

    // Load Kyber public key (skip 276 byte header, then read 800 bytes public key)
    // File format: [HEADER: 276 bytes][PUBLIC_KEY: 800 bytes][PRIVATE_KEY: 1632 bytes]
    QFile kyberFile(kyberPath);
    if (!kyberFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Error"),
            QString::fromUtf8("Failed to open Kyber key file:\n%1").arg(kyberPath)
        );
        statusLabel->setText(QString::fromUtf8("Failed to load keys"));
        return;
    }

    kyberFile.seek(276);  // Skip header (qgp_privkey_file_header_t = 276 bytes)
    QByteArray kyberPubkey = kyberFile.read(800);
    kyberFile.close();

    if (kyberPubkey.size() != 800) {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Error"),
            QString::fromUtf8("Invalid Kyber key file (expected 800 bytes public key)")
        );
        statusLabel->setText(QString::fromUtf8("Failed to load keys"));
        return;
    }

    // Publish keys to DHT
    statusLabel->setText(QString::fromUtf8("Publishing keys to DHT..."));
    QApplication::processEvents();

    int result = messenger_store_pubkey(
        ctx,
        currentIdentity.toUtf8().constData(),  // fingerprint (128 hex chars)
        NULL,  // no display name (user hasn't registered one yet)
        (const uint8_t*)dilithiumPubkey.constData(),
        dilithiumPubkey.size(),
        (const uint8_t*)kyberPubkey.constData(),
        kyberPubkey.size()
    );

    if (result == 0) {
        QMessageBox::information(
            this,
            QString::fromUtf8("Success"),
            QString::fromUtf8(
                "Public keys published to DHT successfully!\n\n"
                "Identity: %1\n"
                "Your keys are now discoverable by other users.\n\n"
                "Keys published:\n"
                "• Dilithium signing key (1952 bytes)\n"
                "• Kyber encryption key (800 bytes)"
            ).arg(currentIdentity)
        );
        statusLabel->setText(QString::fromUtf8("Keys published to DHT"));
    } else {
        QMessageBox::critical(
            this,
            QString::fromUtf8("Error"),
            QString::fromUtf8(
                "Failed to publish keys to DHT.\n\n"
                "Make sure P2P transport is initialized and DHT is connected."
            )
        );
        statusLabel->setText(QString::fromUtf8("Failed to publish keys"));
    }
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
        QStringList keyFiles = dnaDir.entryList(QStringList() << "*.dsa", QDir::Files);
        for (const QString &keyFile : keyFiles) {
            QString identity = keyFile;
            identity.remove(".dsa");

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

// Manual contact list sync to DHT
void MainWindow::onSyncContacts() {
    if (!ctx) {
        QMessageBox::warning(this, "Error", "Messenger context not initialized");
        return;
    }

    // Update status
    syncStatusLabel->setText(QString::fromUtf8("📇 Syncing..."));
    statusLabel->setText(QString::fromUtf8("Syncing contacts to DHT..."));
    QApplication::processEvents();  // Update UI

    // Sync contacts to DHT
    int result = messenger_sync_contacts_to_dht(ctx);

    if (result == 0) {
        syncStatusLabel->setText(QString::fromUtf8("📇 Synced ✓"));
        statusLabel->setText(QString::fromUtf8("Contacts synced to DHT successfully"));
        QMessageBox::information(
            this,
            QString::fromUtf8("Sync Complete"),
            QString::fromUtf8(
                "Your contact list has been synced to DHT.\n\n"
                "• Encrypted with your Kyber1024 public key\n"
                "• Signed with your Dilithium5 private key\n"
                "• Available on any device with your seed phrase"
            )
        );
    } else {
        syncStatusLabel->setText(QString::fromUtf8("📇 Sync Failed"));
        statusLabel->setText(QString::fromUtf8("Failed to sync contacts to DHT"));
        QMessageBox::critical(
            this,
            QString::fromUtf8("Sync Failed"),
            QString::fromUtf8(
                "Failed to sync contacts to DHT.\n\n"
                "Make sure P2P transport is enabled and DHT is connected."
            )
        );
    }

    // Reset status after 5 seconds
    QTimer::singleShot(5000, this, [this]() {
        syncStatusLabel->setText(QString::fromUtf8("📇 Contacts: Local"));
    });
}

// Phase 4: Open DNA name registration dialog
void MainWindow::onRegisterDNAName() {
    RegisterDNANameDialog *dialog = new RegisterDNANameDialog(ctx, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->exec();
}

// Phase 5: Open profile editor dialog
void MainWindow::onEditProfile() {
    ProfileEditorDialog *dialog = new ProfileEditorDialog(ctx, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->exec();
}

// Phase 6: View own message wall
void MainWindow::onViewMyMessageWall() {
    if (!ctx) {
        return;
    }

    // Get own fingerprint
    QString fingerprint = getLocalIdentity();
    if (fingerprint.isEmpty()) {
        QMessageBox::warning(this, "Error", "Could not determine your identity fingerprint.");
        return;
    }

    // Get display name (registered name or shortened fingerprint)
    QString displayName = QString::fromUtf8(ctx->identity);

    // Open message wall dialog (own wall, posting enabled)
    MessageWallDialog *dialog = new MessageWallDialog(ctx, fingerprint, displayName, true, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->exec();
}

// Phase 6: View contact's message wall
void MainWindow::onViewContactMessageWall() {
    if (!ctx || currentContactType != TYPE_CONTACT) {
        return;
    }

    // Get selected contact info
    if (!contactItems.contains(currentContact)) {
        return;
    }

    ContactItem item = contactItems[currentContact];

    // Open message wall dialog (contact's wall, read-only)
    MessageWallDialog *dialog = new MessageWallDialog(ctx, item.fingerprint, item.name, false, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->exec();
}

// Phase 7: Check DNA name expiration
void MainWindow::checkNameExpiration() {
    if (!ctx) {
        return;
    }

    // Get DHT context
    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        return;
    }

    // Load own identity from DHT
    QString fingerprint = getLocalIdentity();
    if (fingerprint.isEmpty()) {
        return;
    }

    dna_unified_identity_t *identity = nullptr;
    int ret = dna_load_identity(dht_ctx, fingerprint.toUtf8().constData(), &identity);

    if (ret != 0 || !identity) {
        return;  // No identity in DHT yet
    }

    // Check if name is registered
    if (!identity->has_registered_name) {
        dna_identity_free(identity);
        return;  // No name registered
    }

    // Check expiration
    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires_at = identity->name_expires_at;
    int64_t seconds_until_expiry = (int64_t)(expires_at - now);

    // Warn if expiring within 30 days (2,592,000 seconds)
    const int64_t THIRTY_DAYS = 30 * 24 * 60 * 60;

    if (seconds_until_expiry > 0 && seconds_until_expiry <= THIRTY_DAYS) {
        int days_remaining = seconds_until_expiry / (24 * 60 * 60);

        QString warningMessage = QString::fromUtf8(
            "Your DNA name \"%1\" will expire in %2 days.\n\n"
            "To keep your name, you need to renew it by paying 0.01 CPUNK.\n\n"
            "Would you like to renew it now?"
        ).arg(QString::fromUtf8(identity->registered_name)).arg(days_remaining);

        QMessageBox::StandardButton reply = QMessageBox::warning(
            this,
            "DNA Name Expiring Soon",
            warningMessage,
            QMessageBox::Yes | QMessageBox::No
        );

        if (reply == QMessageBox::Yes) {
            dna_identity_free(identity);
            onRenewName();
            return;
        }
    } else if (seconds_until_expiry <= 0) {
        // Name has already expired
        QString expiredMessage = QString::fromUtf8(
            "Your DNA name \"%1\" has expired.\n\n"
            "To reclaim it, you need to register it again by paying 0.01 CPUNK.\n\n"
            "Would you like to register it now?"
        ).arg(QString::fromUtf8(identity->registered_name));

        QMessageBox::StandardButton reply = QMessageBox::critical(
            this,
            "DNA Name Expired",
            expiredMessage,
            QMessageBox::Yes | QMessageBox::No
        );

        if (reply == QMessageBox::Yes) {
            dna_identity_free(identity);
            onRegisterDNAName();
            return;
        }
    }

    dna_identity_free(identity);
}

// Phase 7: Renew DNA name registration
void MainWindow::onRenewName() {
    // Renewal is the same as registration - just re-register with the same name
    // The RegisterDNANameDialog will handle pre-filling the current name
    onRegisterDNAName();
}

// Automatic contact list sync (timer-based)
void MainWindow::onAutoSyncContacts() {
    if (!ctx) {
        return;  // Silently skip if context not initialized
    }

    // Update status
    syncStatusLabel->setText(QString::fromUtf8("📇 Auto-sync..."));

    // Sync contacts to DHT (silent, no message box)
    int result = messenger_sync_contacts_to_dht(ctx);

    if (result == 0) {
        syncStatusLabel->setText(QString::fromUtf8("📇 Synced ✓"));
        printf("[GUI] Auto-synced contacts to DHT\n");
    } else {
        syncStatusLabel->setText(QString::fromUtf8("📇 Sync Failed"));
        fprintf(stderr, "[GUI] Failed to auto-sync contacts to DHT\n");
    }

    // Reset status after 5 seconds
    QTimer::singleShot(5000, this, [this]() {
        syncStatusLabel->setText(QString::fromUtf8("📇 Contacts: Local"));
    });
}
