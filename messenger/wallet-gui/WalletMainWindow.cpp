/*
 * cpunk-wallet-gui - Main Window Implementation
 */

#include "WalletMainWindow.h"
#include "SendTokensDialog.h"
#include "TransactionHistoryWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QMenu>
#include <QAction>
#include <json-c/json.h>

WalletMainWindow::WalletMainWindow(QWidget *parent)
    : QMainWindow(parent),
      wallets(nullptr),
      currentTheme(THEME_CPUNK_IO),
      selectedWalletIndex(-1),
      sendDialog(nullptr),
      transactionHistory(nullptr) {

    setupUI();
    loadWallets();
    applyTheme(currentTheme);
}

WalletMainWindow::~WalletMainWindow() {
    if (wallets) {
        wallet_list_free(wallets);
    }
}

// ============================================================================
// UI SETUP
// ============================================================================

void WalletMainWindow::setupUI() {
    setWindowTitle(QString::fromUtf8("💰 cpunk Wallet - CF20 Token Manager"));
    setMinimumSize(1000, 700);

    // Create central widget with tab widget
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    tabWidget = new QTabWidget(this);
    mainLayout->addWidget(tabWidget);

    setCentralWidget(centralWidget);

    // Create tabs
    createWalletsTab();
    createSendTab();
    createTransactionsTab();
    createSettingsTab();

    // Create menu bar
    createMenuBar();

    // Create status bar
    createStatusBar();
}

void WalletMainWindow::createMenuBar() {
    QMenu *fileMenu = menuBar()->addMenu(QString::fromUtf8("&File"));

    QAction *refreshAction = fileMenu->addAction(QString::fromUtf8("🔄 Refresh Wallets"));
    connect(refreshAction, &QAction::triggered, this, &WalletMainWindow::onRefreshWallets);

    fileMenu->addSeparator();

    QAction *quitAction = fileMenu->addAction(QString::fromUtf8("Quit"));
    quitAction->setShortcut(QKeySequence::Quit);
    connect(quitAction, &QAction::triggered, this, &WalletMainWindow::onQuit);

    QMenu *walletMenu = menuBar()->addMenu(QString::fromUtf8("&Wallet"));

    QAction *sendAction = walletMenu->addAction(QString::fromUtf8("💸 Send Tokens"));
    connect(sendAction, &QAction::triggered, this, &WalletMainWindow::onSendTokens);

    QAction *receiveAction = walletMenu->addAction(QString::fromUtf8("📥 Receive Tokens"));
    connect(receiveAction, &QAction::triggered, this, &WalletMainWindow::onReceiveTokens);

    walletMenu->addSeparator();

    QAction *balancesAction = walletMenu->addAction(QString::fromUtf8("🔄 Refresh Balances"));
    connect(balancesAction, &QAction::triggered, this, &WalletMainWindow::onRefreshBalances);

    QMenu *toolsMenu = menuBar()->addMenu(QString::fromUtf8("&Tools"));

    QAction *settingsAction = toolsMenu->addAction(QString::fromUtf8("⚙️ Settings"));
    connect(settingsAction, &QAction::triggered, this, &WalletMainWindow::onSettings);

    QMenu *helpMenu = menuBar()->addMenu(QString::fromUtf8("&Help"));

    QAction *aboutAction = helpMenu->addAction(QString::fromUtf8("About"));
    connect(aboutAction, &QAction::triggered, this, &WalletMainWindow::onAbout);
}

void WalletMainWindow::createWalletsTab() {
    walletsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(walletsTab);

    // Title
    QLabel *titleLabel = new QLabel(QString::fromUtf8("📂 My Wallets"), walletsTab);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);

    // Wallet table
    walletTable = new QTableWidget(walletsTab);
    walletTable->setColumnCount(6);
    walletTable->setHorizontalHeaderLabels({
        "Wallet Name",
        "Address",
        "CPUNK Balance",
        "CELL Balance",
        "KEL Balance",
        "Status"
    });

    walletTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    walletTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    walletTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect(walletTable, &QTableWidget::cellClicked, this, &WalletMainWindow::onWalletSelected);

    layout->addWidget(walletTable);

    // Status label
    walletsStatusLabel = new QLabel(QString::fromUtf8("Loading wallets..."), walletsTab);
    walletsStatusLabel->setStyleSheet("padding: 5px;");
    layout->addWidget(walletsStatusLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    refreshWalletsButton = new QPushButton(QString::fromUtf8("🔄 Refresh Wallets"), walletsTab);
    refreshBalancesButton = new QPushButton(QString::fromUtf8("💵 Refresh Balances"), walletsTab);
    receiveButton = new QPushButton(QString::fromUtf8("📥 Receive"), walletsTab);

    connect(refreshWalletsButton, &QPushButton::clicked, this, &WalletMainWindow::onRefreshWallets);
    connect(refreshBalancesButton, &QPushButton::clicked, this, &WalletMainWindow::onRefreshBalances);
    connect(receiveButton, &QPushButton::clicked, this, &WalletMainWindow::onReceiveTokens);

    buttonLayout->addWidget(refreshWalletsButton);
    buttonLayout->addWidget(refreshBalancesButton);
    buttonLayout->addWidget(receiveButton);
    buttonLayout->addStretch();

    layout->addLayout(buttonLayout);

    tabWidget->addTab(walletsTab, QString::fromUtf8("💼 Wallets"));
}

void WalletMainWindow::createSendTab() {
    sendTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(sendTab);

    QLabel *titleLabel = new QLabel(QString::fromUtf8("💸 Send CF20 Tokens"), sendTab);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);

    // Create SendTokensDialog
    sendDialog = new SendTokensDialog(wallets, sendTab);
    layout->addWidget(sendDialog);

    layout->addStretch();

    tabWidget->addTab(sendTab, QString::fromUtf8("💸 Send"));
}

void WalletMainWindow::createTransactionsTab() {
    transactionsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(transactionsTab);

    QLabel *titleLabel = new QLabel(QString::fromUtf8("📊 Transaction History"), transactionsTab);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);

    // Create TransactionHistoryWidget
    transactionHistory = new TransactionHistoryWidget(wallets, transactionsTab);
    layout->addWidget(transactionHistory);

    tabWidget->addTab(transactionsTab, QString::fromUtf8("📊 Transactions"));
}

void WalletMainWindow::createSettingsTab() {
    settingsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(settingsTab);

    QLabel *titleLabel = new QLabel(QString::fromUtf8("⚙️ Settings"), settingsTab);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);

    // Theme selector
    QHBoxLayout *themeLayout = new QHBoxLayout();
    QLabel *themeLabel = new QLabel(QString::fromUtf8("Theme:"), settingsTab);
    themeComboBox = new QComboBox(settingsTab);
    themeComboBox->addItem(QString::fromUtf8("cpunk.io (Cyan)"), THEME_CPUNK_IO);
    themeComboBox->addItem(QString::fromUtf8("cpunk.club (Orange)"), THEME_CPUNK_CLUB);
    connect(themeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WalletMainWindow::onThemeChanged);

    themeLayout->addWidget(themeLabel);
    themeLayout->addWidget(themeComboBox);
    themeLayout->addStretch();

    layout->addLayout(themeLayout);

    // Network selector
    QHBoxLayout *networkLayout = new QHBoxLayout();
    QLabel *networkLabel = new QLabel(QString::fromUtf8("Network:"), settingsTab);
    networkComboBox = new QComboBox(settingsTab);
    networkComboBox->addItem(QString::fromUtf8("Backbone"));
    networkComboBox->addItem(QString::fromUtf8("SubZero"));
    networkComboBox->addItem(QString::fromUtf8("KelVPN"));

    networkLayout->addWidget(networkLabel);
    networkLayout->addWidget(networkComboBox);
    networkLayout->addStretch();

    layout->addLayout(networkLayout);

    layout->addStretch();

    tabWidget->addTab(settingsTab, QString::fromUtf8("⚙️ Settings"));
}

void WalletMainWindow::createStatusBar() {
    networkStatusLabel = new QLabel(QString::fromUtf8("Network: Disconnected"), this);
    balanceStatusLabel = new QLabel(QString::fromUtf8("Total: 0.00 CELL"), this);

    statusBar()->addWidget(networkStatusLabel);
    statusBar()->addPermanentWidget(balanceStatusLabel);

    updateStatusBar();
}

// ============================================================================
// WALLET OPERATIONS
// ============================================================================

void WalletMainWindow::loadWallets() {
    walletsStatusLabel->setText(QString::fromUtf8("Loading wallets from %1...").arg(CELLFRAME_WALLET_PATH));

    int ret = wallet_list_cellframe(&wallets);

    if (ret != 0 || !wallets || wallets->count == 0) {
        walletsStatusLabel->setText(QString::fromUtf8("❌ No wallets found in %1").arg(CELLFRAME_WALLET_PATH));
        QMessageBox::warning(this, "No Wallets",
                           QString::fromUtf8("No Cellframe wallets found.\n\n"
                                            "Please create a wallet using cellframe-node-cli:\n"
                                            "cellframe-node-cli wallet new -w myWallet -sign dilithium"));
        return;
    }

    // Populate wallet table
    walletTable->setRowCount(wallets->count);

    for (size_t i = 0; i < wallets->count; i++) {
        cellframe_wallet_t *w = &wallets->wallets[i];

        // Wallet name
        walletTable->setItem(i, 0, new QTableWidgetItem(QString::fromUtf8(w->name)));

        // Address
        QString address;
        if (w->status == WALLET_STATUS_PROTECTED) {
            address = QString::fromUtf8("🔒 Password Required");
        } else if (w->address[0] != '\0') {
            address = QString::fromUtf8(w->address);
        } else {
            address = QString::fromUtf8("❌ No Address");
        }
        walletTable->setItem(i, 1, new QTableWidgetItem(address));

        // Balances (placeholder)
        walletTable->setItem(i, 2, new QTableWidgetItem(QString::fromUtf8("--")));
        walletTable->setItem(i, 3, new QTableWidgetItem(QString::fromUtf8("--")));
        walletTable->setItem(i, 4, new QTableWidgetItem(QString::fromUtf8("--")));

        // Status
        QString status = (w->status == WALLET_STATUS_PROTECTED) ?
                        QString::fromUtf8("🔒 Protected") :
                        QString::fromUtf8("✅ Ready");
        walletTable->setItem(i, 5, new QTableWidgetItem(status));
    }

    walletsStatusLabel->setText(QString::fromUtf8("✅ Loaded %1 wallet(s)").arg(wallets->count));
    updateStatusBar();

    // Update wallet list in other tabs
    if (transactionHistory) {
        transactionHistory->updateWalletList(wallets);
    }
    if (sendDialog) {
        sendDialog->updateWalletList(wallets);
    }
}

void WalletMainWindow::updateBalances() {
    if (!wallets || wallets->count == 0) {
        return;
    }

    walletsStatusLabel->setText(QString::fromUtf8("Refreshing balances..."));

    for (size_t i = 0; i < wallets->count; i++) {
        cellframe_wallet_t *w = &wallets->wallets[i];

        printf("[DEBUG] Checking wallet %s - status: %d, address: %s\n", w->name, w->status, w->address);

        if (w->status == WALLET_STATUS_PROTECTED || w->address[0] == '\0') {
            printf("[DEBUG] Skipping wallet %s (protected or no address)\n", w->name);
            continue;
        }

        // Query balance via RPC
        cellframe_rpc_response_t *response = nullptr;
        printf("[DEBUG] Querying balance for wallet %s, address: %s\n", w->name, w->address);
        if (cellframe_rpc_get_balance("Backbone", w->address, "CPUNK", &response) == 0 && response) {
            if (response->result) {
                json_object *jresult = response->result;
                printf("[DEBUG] Balance response for %s: %s\n", w->name,
                       json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY));

                if (json_object_is_type(jresult, json_type_array)) {
                    int len = json_object_array_length(jresult);
                    printf("[DEBUG] Result array length: %d\n", len);
                    if (len > 0) {
                        json_object *first = json_object_array_get_idx(jresult, 0);
                        printf("[DEBUG] First element type: %d (array=%d)\n",
                               json_object_get_type(first), json_type_array);
                        if (json_object_is_type(first, json_type_array) && json_object_array_length(first) > 0) {
                            json_object *wallet_obj = json_object_array_get_idx(first, 0);
                            printf("[DEBUG] Got wallet object\n");
                            json_object *tokens_obj = nullptr;

                            if (json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                                int token_count = json_object_array_length(tokens_obj);
                                printf("[DEBUG] Found %d tokens\n", token_count);

                                for (int t = 0; t < token_count; t++) {
                                    json_object *token = json_object_array_get_idx(tokens_obj, t);
                                    json_object *token_info = nullptr;
                                    json_object *coins_obj = nullptr;

                                    if (json_object_object_get_ex(token, "token", &token_info) &&
                                        json_object_object_get_ex(token, "coins", &coins_obj)) {
                                        json_object *ticker_obj = nullptr;
                                        if (json_object_object_get_ex(token_info, "ticker", &ticker_obj)) {
                                            QString ticker = QString::fromUtf8(json_object_get_string(ticker_obj));
                                            QString coins = QString::fromUtf8(json_object_get_string(coins_obj));

                                            printf("[DEBUG] Setting %s balance: %s (row %zu)\n",
                                                   ticker.toUtf8().constData(),
                                                   coins.toUtf8().constData(), i);

                                            if (ticker == "CPUNK") {
                                                walletTable->setItem(i, 2, new QTableWidgetItem(formatBalance(coins)));
                                            } else if (ticker == "CELL") {
                                                walletTable->setItem(i, 3, new QTableWidgetItem(formatBalance(coins)));
                                            } else if (ticker == "KEL") {
                                                walletTable->setItem(i, 4, new QTableWidgetItem(formatBalance(coins)));
                                            }
                                        }
                                    }
                                }
                            } else {
                                printf("[DEBUG] No tokens field found in wallet object\n");
                            }
                        }
                    }
                }
            }

            cellframe_rpc_response_free(response);
        } else {
            printf("[DEBUG] Failed to get balance for wallet %s\n", w->name);
        }
    }

    walletsStatusLabel->setText(QString::fromUtf8("✅ Balances updated"));
}

QString WalletMainWindow::formatBalance(const QString &coins) {
    if (coins.isEmpty() || coins == "0") {
        return QString::fromUtf8("0.00");
    }

    // RPC returns "coins" already in token format, just format to 2 decimals
    bool ok;
    double value = coins.toDouble(&ok);
    if (!ok) return coins;

    return QString::number(value, 'f', 2);
}

void WalletMainWindow::updateStatusBar() {
    networkStatusLabel->setText(QString::fromUtf8("Network: Backbone (Connected)"));

    // TODO: Calculate total balance across all wallets
    balanceStatusLabel->setText(QString::fromUtf8("Total: -- CELL"));
}

// ============================================================================
// THEME MANAGEMENT
// ============================================================================

void WalletMainWindow::applyTheme(CpunkTheme theme) {
    currentTheme = theme;

    // Set stylesheet on QApplication for global effect (required on Windows)
    qobject_cast<QApplication*>(QApplication::instance())->setStyleSheet(getCpunkStyleSheet(theme));
}

// ============================================================================
// SLOTS
// ============================================================================

void WalletMainWindow::onRefreshWallets() {
    if (wallets) {
        wallet_list_free(wallets);
        wallets = nullptr;
    }
    loadWallets();
}

void WalletMainWindow::onRefreshBalances() {
    updateBalances();
}

void WalletMainWindow::onSendTokens() {
    // Switch to send tab
    tabWidget->setCurrentWidget(sendTab);
}

void WalletMainWindow::onReceiveTokens() {
    int currentRow = walletTable->currentRow();
    if (currentRow < 0) {
        QMessageBox::information(this, "Select Wallet",
                               QString::fromUtf8("Please select a wallet to show the receive address."));
        return;
    }

    QTableWidgetItem *addrItem = walletTable->item(currentRow, 1);
    if (!addrItem) return;

    QString address = addrItem->text();

    if (address.startsWith(QString::fromUtf8("🔒")) || address.startsWith(QString::fromUtf8("❌"))) {
        QMessageBox::warning(this, "Invalid Wallet",
                           QString::fromUtf8("This wallet cannot receive tokens (protected or invalid)."));
        return;
    }

    // Copy address to clipboard
    QApplication::clipboard()->setText(address);

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(QString::fromUtf8("Receive Tokens"));
    msgBox.setText(QString::fromUtf8("📥 Wallet Address (copied to clipboard):\n\n%1\n\n"
                                     "Send CF20 tokens to this address on Cellframe Backbone network.").arg(address));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}

void WalletMainWindow::onSettings() {
    tabWidget->setCurrentWidget(settingsTab);
}

void WalletMainWindow::onAbout() {
    QMessageBox::about(this, "About cpunk Wallet",
                      QString::fromUtf8("cpunk Wallet - CF20 Token Manager\n\n"
                                       "Version: 0.1.0\n"
                                       "Built on: DNA Messenger Framework\n\n"
                                       "Supported Networks:\n"
                                       "- Cellframe Backbone\n"
                                       "- SubZero\n"
                                       "- KelVPN\n\n"
                                       "Visit: https://cpunk.io | https://cpunk.club"));
}

void WalletMainWindow::onQuit() {
    QApplication::quit();
}

void WalletMainWindow::onThemeChanged(int index) {
    CpunkTheme theme = static_cast<CpunkTheme>(themeComboBox->itemData(index).toInt());
    applyTheme(theme);
}

void WalletMainWindow::onWalletSelected(int row, int column) {
    selectedWalletIndex = row;
}
