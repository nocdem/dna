/*
 * DNA Messenger - Qt GUI
 * CF20 Wallet Dialog Implementation - Modern Card-Based Design
 */

#include "WalletDialog.h"
#include "ReceiveDialog.h"
#include "TransactionHistoryDialog.h"
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QTimer>
#include <QDateTime>
#include <QRegExp>
#include <QGraphicsDropShadowEffect>
#include <json-c/json.h>

WalletDialog::WalletDialog(QWidget *parent, const QString &specificWallet)
    : QDialog(parent), wallets(nullptr), specificWallet(specificWallet), currentWalletIndex(-1),
      currentTheme(THEME_CPUNK_IO) {

    setWindowTitle("💰 Wallet");
    setMinimumSize(420, 700);
    resize(420, 800);

    // Make it a proper detached window
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinMaxButtonsHint);

    // Get current theme from ThemeManager
    currentTheme = ThemeManager::instance()->currentTheme();

    // Apply theme IMMEDIATELY to prevent white background flash
    applyTheme(currentTheme);

    // Connect to theme changes
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &WalletDialog::onThemeChanged);

    setupUI();
    loadWallet();

    // Auto-refresh balances when wallet opens
    QTimer::singleShot(100, this, &WalletDialog::onRefreshBalances);
}

WalletDialog::~WalletDialog() {
    if (wallets) {
        wallet_list_free(wallets);
    }
}

void WalletDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    // Main scroll area
    QScrollArea *mainScrollArea = new QScrollArea(this);
    mainScrollArea->setWidgetResizable(true);
    mainScrollArea->setFrameShape(QFrame::NoFrame);
    mainScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QWidget *scrollContent = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);
    contentLayout->setSpacing(20);
    contentLayout->setContentsMargins(20, 20, 20, 20);

    // ===== HEADER SECTION =====
    QWidget *headerWidget = new QWidget();
    QVBoxLayout *headerLayout = new QVBoxLayout(headerWidget);
    headerLayout->setSpacing(10);
    headerLayout->setContentsMargins(20, 30, 20, 30);

    // Wallet name
    walletNameLabel = new QLabel("My Wallet", this);
    QFont nameFont;
    nameFont.setPointSize(14);
    nameFont.setBold(true);
    walletNameLabel->setFont(nameFont);
    walletNameLabel->setAlignment(Qt::AlignCenter);
    headerLayout->addWidget(walletNameLabel);

    // Total balance (big)
    totalBalanceLabel = new QLabel("0.00", this);
    QFont balanceFont;
    balanceFont.setPointSize(36);
    balanceFont.setBold(true);
    totalBalanceLabel->setFont(balanceFont);
    totalBalanceLabel->setAlignment(Qt::AlignCenter);
    headerLayout->addWidget(totalBalanceLabel);

    // USD value (placeholder)
    totalBalanceUsdLabel = new QLabel("≈ $0.00 USD", this);
    QFont usdFont;
    usdFont.setPointSize(12);
    totalBalanceUsdLabel->setFont(usdFont);
    totalBalanceUsdLabel->setAlignment(Qt::AlignCenter);
    headerLayout->addWidget(totalBalanceUsdLabel);

    // Theme will be applied later

    contentLayout->addWidget(headerWidget);

    // ===== ACTION BUTTONS =====
    sendButton = new QPushButton("💸 Send", this);
    receiveButton = new QPushButton("📥 Receive", this);
    dexButton = new QPushButton("🔄 DEX", this);
    historyButton = new QPushButton("📜 History", this);

    QString actionButtonStyle =
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.15);"
        "   color: #00D9FF;"
        "   border: 2px solid rgba(0, 217, 255, 0.3);"
        "   border-radius: 12px;"
        "   padding: 25px;"
        "   font-size: 15px;"
        "   font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.25);"
        "   border-color: #00D9FF;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.35);"
        "}";

    sendButton->setStyleSheet(actionButtonStyle);
    receiveButton->setStyleSheet(actionButtonStyle);
    dexButton->setStyleSheet(actionButtonStyle);
    historyButton->setStyleSheet(actionButtonStyle);

    sendButton->setCursor(Qt::PointingHandCursor);
    receiveButton->setCursor(Qt::PointingHandCursor);
    dexButton->setCursor(Qt::PointingHandCursor);
    historyButton->setCursor(Qt::PointingHandCursor);

    // First row: Send & Receive
    QHBoxLayout *topButtonLayout = new QHBoxLayout();
    topButtonLayout->setSpacing(15);
    topButtonLayout->addWidget(sendButton);
    topButtonLayout->addWidget(receiveButton);
    contentLayout->addLayout(topButtonLayout);

    // Second row: DEX & History
    QHBoxLayout *bottomButtonLayout = new QHBoxLayout();
    bottomButtonLayout->setSpacing(15);
    bottomButtonLayout->addWidget(dexButton);
    bottomButtonLayout->addWidget(historyButton);
    contentLayout->addLayout(bottomButtonLayout);

    // ===== ASSETS SECTION =====
    QLabel *assetsLabel = new QLabel("Assets", this);
    QFont assetsFont;
    assetsFont.setPointSize(14);
    assetsFont.setBold(true);
    assetsLabel->setFont(assetsFont);
    assetsLabel->setStyleSheet("color: #00D9FF; margin-top: 10px;");
    contentLayout->addWidget(assetsLabel);

    // Token cards (will be shown/hidden based on balance)
    cpunkCard = createTokenCard("🎭", "CPUNK", "ChipPunk");
    cellCard = createTokenCard("⚡", "CELL", "Cellframe");
    kelCard = createTokenCard("💎", "KEL", "KelVPN");

    // Initially hide all cards until balances are loaded
    cpunkCard->setVisible(false);
    cellCard->setVisible(false);
    kelCard->setVisible(false);

    contentLayout->addWidget(cpunkCard);
    contentLayout->addWidget(cellCard);
    contentLayout->addWidget(kelCard);

    // ===== TRANSACTIONS SECTION =====
    QLabel *transactionsLabel = new QLabel("Recent Transactions", this);
    transactionsLabel->setFont(assetsFont);
    transactionsLabel->setStyleSheet("color: #00D9FF; margin-top: 10px;");
    contentLayout->addWidget(transactionsLabel);

    // Transaction scroll area
    transactionScrollArea = new QScrollArea(this);
    transactionScrollArea->setWidgetResizable(true);
    transactionScrollArea->setFrameShape(QFrame::NoFrame);
    transactionScrollArea->setMinimumHeight(200);
    transactionScrollArea->setMaximumHeight(300);

    QWidget *transactionWidget = new QWidget();
    transactionLayout = new QVBoxLayout(transactionWidget);
    transactionLayout->setSpacing(10);
    transactionLayout->setContentsMargins(0, 0, 0, 0);
    transactionLayout->addStretch();

    transactionScrollArea->setWidget(transactionWidget);
    contentLayout->addWidget(transactionScrollArea);

    contentLayout->addStretch();

    // Status label at bottom
    statusLabel = new QLabel("Ready", this);
    statusLabel->setStyleSheet("color: #00D9FF; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 5px;");
    statusLabel->setAlignment(Qt::AlignCenter);
    contentLayout->addWidget(statusLabel);

    scrollContent->setLayout(contentLayout);
    mainScrollArea->setWidget(scrollContent);
    mainLayout->addWidget(mainScrollArea);

    // Connect signals
    connect(sendButton, &QPushButton::clicked, this, &WalletDialog::onSendTokens);
    connect(receiveButton, &QPushButton::clicked, this, &WalletDialog::onReceiveTokens);
    connect(dexButton, &QPushButton::clicked, this, &WalletDialog::onDexClicked);
    connect(historyButton, &QPushButton::clicked, this, &WalletDialog::onHistoryClicked);

    // Theme will be applied after setupUI in constructor
}

QWidget* WalletDialog::createTokenCard(const QString &icon, const QString &ticker, const QString &name) {
    QWidget *card = new QWidget();
    card->setCursor(Qt::PointingHandCursor);

    QHBoxLayout *cardLayout = new QHBoxLayout(card);
    cardLayout->setContentsMargins(20, 15, 20, 15);

    // Icon
    QLabel *iconLabel = new QLabel(icon, card);
    QFont iconFont;
    iconFont.setPointSize(28);
    iconLabel->setFont(iconFont);
    iconLabel->setFixedSize(50, 50);
    iconLabel->setAlignment(Qt::AlignCenter);
    iconLabel->setStyleSheet("background: rgba(0, 217, 255, 0.1); border-radius: 25px;");
    cardLayout->addWidget(iconLabel);

    // Token info
    QVBoxLayout *infoLayout = new QVBoxLayout();
    infoLayout->setSpacing(2);

    QLabel *tickerLabel = new QLabel(ticker, card);
    QFont tickerFont;
    tickerFont.setPointSize(14);
    tickerFont.setBold(true);
    tickerLabel->setFont(tickerFont);
    tickerLabel->setStyleSheet("color: #00D9FF;");

    QLabel *nameLabel = new QLabel(name, card);
    QFont nameFont;
    nameFont.setPointSize(10);
    nameLabel->setFont(nameFont);
    nameLabel->setStyleSheet("color: rgba(0, 217, 255, 0.6);");

    infoLayout->addWidget(tickerLabel);
    infoLayout->addWidget(nameLabel);
    cardLayout->addLayout(infoLayout);

    cardLayout->addStretch();

    // Balance
    QLabel *balanceLabel = new QLabel("0.00", card);
    QFont balanceFont;
    balanceFont.setPointSize(16);
    balanceFont.setBold(true);
    balanceLabel->setFont(balanceFont);
    balanceLabel->setStyleSheet("color: #00D9FF;");
    balanceLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    cardLayout->addWidget(balanceLabel);

    // Store balance label for later update
    if (ticker == "CPUNK") {
        cpunkBalanceLabel = balanceLabel;
    } else if (ticker == "CELL") {
        cellBalanceLabel = balanceLabel;
    } else if (ticker == "KEL") {
        kelBalanceLabel = balanceLabel;
    }

    card->setStyleSheet(
        "QWidget {"
        "   background: rgba(0, 217, 255, 0.08);"
        "   border: 1px solid rgba(0, 217, 255, 0.2);"
        "   border-radius: 12px;"
        "}"
        "QWidget:hover {"
        "   background: rgba(0, 217, 255, 0.12);"
        "   border-color: rgba(0, 217, 255, 0.4);"
        "}"
    );

    // Add shadow effect
    QGraphicsDropShadowEffect *shadow = new QGraphicsDropShadowEffect();
    shadow->setBlurRadius(15);
    shadow->setColor(QColor(0, 217, 255, 50));
    shadow->setOffset(0, 3);
    card->setGraphicsEffect(shadow);

    return card;
}

QWidget* WalletDialog::createTransactionItem(const QString &type, const QString &amount,
                                              const QString &token, const QString &address, const QString &time) {
    QWidget *item = new QWidget();
    QHBoxLayout *layout = new QHBoxLayout(item);
    layout->setContentsMargins(15, 12, 15, 12);

    // Type icon
    QLabel *iconLabel = new QLabel(type == "sent" ? "📤" : "📥", item);
    QFont iconFont;
    iconFont.setPointSize(20);
    iconLabel->setFont(iconFont);
    iconLabel->setFixedSize(40, 40);
    iconLabel->setAlignment(Qt::AlignCenter);
    iconLabel->setStyleSheet(
        QString("background: %1; border-radius: 20px;")
        .arg(type == "sent" ? "rgba(255, 100, 100, 0.2)" : "rgba(100, 255, 100, 0.2)")
    );
    layout->addWidget(iconLabel);

    // Transaction info
    QVBoxLayout *infoLayout = new QVBoxLayout();
    infoLayout->setSpacing(2);

    QLabel *typeLabel = new QLabel(type == "sent" ? "Sent" : "Received", item);
    QFont typeFont;
    typeFont.setPointSize(12);
    typeFont.setBold(true);
    typeLabel->setFont(typeFont);
    typeLabel->setStyleSheet("color: #00D9FF;");

    QLabel *addressLabel = new QLabel(address, item);
    QFont addressFont;
    addressFont.setPointSize(9);
    addressLabel->setFont(addressFont);
    addressLabel->setStyleSheet("color: rgba(0, 217, 255, 0.5);");

    infoLayout->addWidget(typeLabel);
    infoLayout->addWidget(addressLabel);
    layout->addLayout(infoLayout);

    layout->addStretch();

    // Amount
    QVBoxLayout *amountLayout = new QVBoxLayout();
    amountLayout->setSpacing(2);

    QLabel *amountLabel = new QLabel((type == "sent" ? "-" : "+") + amount + " " + token, item);
    QFont amountFont;
    amountFont.setPointSize(12);
    amountFont.setBold(true);
    amountLabel->setFont(amountFont);
    amountLabel->setStyleSheet(
        QString("color: %1;").arg(type == "sent" ? "#FF6B6B" : "#6BCF7F")
    );
    amountLabel->setAlignment(Qt::AlignRight);

    QLabel *timeLabel = new QLabel(time, item);
    QFont timeFont;
    timeFont.setPointSize(9);
    timeLabel->setFont(timeFont);
    timeLabel->setStyleSheet("color: rgba(0, 217, 255, 0.5);");
    timeLabel->setAlignment(Qt::AlignRight);

    amountLayout->addWidget(amountLabel);
    amountLayout->addWidget(timeLabel);
    layout->addLayout(amountLayout);

    item->setStyleSheet(
        "QWidget {"
        "   background: rgba(0, 217, 255, 0.05);"
        "   border: 1px solid rgba(0, 217, 255, 0.15);"
        "   border-radius: 10px;"
        "}"
        "QWidget:hover {"
        "   background: rgba(0, 217, 255, 0.1);"
        "}"
    );

    return item;
}

void WalletDialog::loadWallet() {
    statusLabel->setText("Loading wallet...");

    int ret = wallet_list_cellframe(&wallets);

    if (ret != 0 || !wallets || wallets->count == 0) {
        statusLabel->setText("❌ No wallets found");
        QMessageBox::warning(this, "No Wallets",
                           "No Cellframe wallets found.\n\n"
                           "Please create a wallet using cellframe-node-cli:\n"
                           "cellframe-node-cli wallet new -w myWallet -sign dilithium");
        return;
    }

    // Find the specific wallet or use first one
    if (!specificWallet.isEmpty()) {
        for (size_t i = 0; i < wallets->count; i++) {
            if (QString::fromUtf8(wallets->wallets[i].name) == specificWallet) {
                currentWalletIndex = i;
                break;
            }
        }

        if (currentWalletIndex == -1) {
            statusLabel->setText(QString("❌ Wallet '%1' not found").arg(specificWallet));
            QMessageBox::warning(this, "Wallet Not Found",
                               QString("Wallet '%1' was not found").arg(specificWallet));
            return;
        }
    } else {
        currentWalletIndex = 0;
    }

    // Update UI with wallet name
    cellframe_wallet_t *wallet = &wallets->wallets[currentWalletIndex];
    walletNameLabel->setText(QString::fromUtf8(wallet->name));
    setWindowTitle(QString("💰 %1").arg(QString::fromUtf8(wallet->name)));

    statusLabel->setText("Click 'Refresh' to load balances");
}

void WalletDialog::onRefreshBalances() {
    if (!wallets || currentWalletIndex < 0) {
        return;
    }

    statusLabel->setText("🔄 Refreshing balances...");

    cellframe_wallet_t *wallet = &wallets->wallets[currentWalletIndex];

    // Get wallet address
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        statusLabel->setText("❌ Failed to get wallet address");
        return;
    }

    // Query balance via RPC
    cellframe_rpc_response_t *response = nullptr;
    if (cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response) == 0 && response->result) {
        json_object *jresult = response->result;

        if (json_object_is_type(jresult, json_type_array)) {
            int len = json_object_array_length(jresult);
            if (len > 0) {
                json_object *first = json_object_array_get_idx(jresult, 0);
                if (json_object_is_type(first, json_type_array) && json_object_array_length(first) > 0) {
                    json_object *wallet_obj = json_object_array_get_idx(first, 0);
                    json_object *tokens_obj = nullptr;

                    if (json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                        int token_count = json_object_array_length(tokens_obj);

                        double totalBalance = 0.0;

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

                                    tokenBalances[ticker] = coins;

                                    double balance = coins.toDouble();
                                    totalBalance += balance;

                                    if (ticker == "CPUNK") {
                                        cpunkBalanceLabel->setText(formatBalance(coins));
                                        cpunkCard->setVisible(balance > 0.0);
                                    } else if (ticker == "CELL") {
                                        cellBalanceLabel->setText(formatBalance(coins));
                                        cellCard->setVisible(balance > 0.0);
                                    } else if (ticker == "KEL") {
                                        kelBalanceLabel->setText(formatBalance(coins));
                                        kelCard->setVisible(balance > 0.0);
                                    }
                                }
                            }
                        }

                        // Update total balance
                        totalBalanceLabel->setText(QString::number(totalBalance, 'f', 2));
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    }

    statusLabel->setText("✅ Balances updated");

    // Load transaction history
    loadTransactionHistory();
}

void WalletDialog::loadTransactionHistory() {
    if (!wallets || currentWalletIndex < 0) {
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[currentWalletIndex];

    // Get wallet address
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        return;
    }

    // Query transaction history via RPC
    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string("Backbone"));
    json_object_object_add(args, "addr", json_object_new_string(address));
    json_object_object_add(args, "chain", json_object_new_string("main"));

    cellframe_rpc_request_t req = {
        .method = "tx_history",
        .subcommand = "",
        .arguments = args,
        .id = 1
    };

    cellframe_rpc_response_t *response = nullptr;
    int ret = cellframe_rpc_call(&req, &response);
    json_object_put(args);

    // Clear existing transactions
    QLayoutItem *child;
    while ((child = transactionLayout->takeAt(0)) != nullptr) {
        if (child->widget()) {
            delete child->widget();
        }
        delete child;
    }

    if (ret == 0 && response && response->result) {
        json_object *jresult = response->result;

        // Response format: [[query_params, tx1, tx2, ...], summary]
        if (json_object_is_type(jresult, json_type_array)) {
            int result_len = json_object_array_length(jresult);

            if (result_len > 0) {
                json_object *tx_array = json_object_array_get_idx(jresult, 0);

                if (json_object_is_type(tx_array, json_type_array)) {
                    int array_len = json_object_array_length(tx_array);

                    // Skip first 2 items (query parameters), transactions start at index 2
                    int displayed = 0;
                    for (int i = 2; i < array_len && displayed < 3; i++) {
                        json_object *tx_obj = json_object_array_get_idx(tx_array, i);

                        // Check if this is a transaction object (has "status" field)
                        json_object *status_obj = nullptr;
                        if (!json_object_object_get_ex(tx_obj, "status", &status_obj)) {
                            continue;
                        }

                        // Extract transaction fields
                        json_object *hash_obj = nullptr, *timestamp_obj = nullptr, *data_obj = nullptr;
                        json_object_object_get_ex(tx_obj, "hash", &hash_obj);
                        json_object_object_get_ex(tx_obj, "tx_created", &timestamp_obj);
                        json_object_object_get_ex(tx_obj, "data", &data_obj);

                        QString hash = hash_obj ? QString::fromUtf8(json_object_get_string(hash_obj)) : "N/A";
                        QString shortHash = hash.left(12) + "...";

                        // Parse timestamp
                        QString timeStr = "Unknown";
                        if (timestamp_obj) {
                            QString ts_str = QString::fromUtf8(json_object_get_string(timestamp_obj));
                            // Parse timestamp like "Wed, 22 Oct 2025 21:10:25 +0000"
                            QDateTime txTime = QDateTime::fromString(ts_str, Qt::RFC2822Date);
                            if (txTime.isValid()) {
                                int64_t diff = QDateTime::currentSecsSinceEpoch() - txTime.toSecsSinceEpoch();
                                if (diff < 60) {
                                    timeStr = "Just now";
                                } else if (diff < 3600) {
                                    timeStr = QString::number(diff / 60) + "m ago";
                                } else if (diff < 86400) {
                                    timeStr = QString::number(diff / 3600) + "h ago";
                                } else {
                                    timeStr = QString::number(diff / 86400) + "d ago";
                                }
                            }
                        }

                        // Parse transaction data array
                        QString direction = "received";
                        QString amount = "0.00";
                        QString token = "UNKNOWN";
                        QString otherAddress = shortHash;

                        if (data_obj && json_object_is_type(data_obj, json_type_array)) {
                            int data_count = json_object_array_length(data_obj);
                            if (data_count > 0) {
                                json_object *first_data = json_object_array_get_idx(data_obj, 0);
                                json_object *tx_type_obj = nullptr, *token_obj = nullptr;
                                json_object *coins_obj = nullptr, *addr_obj = nullptr;

                                if (json_object_object_get_ex(first_data, "tx_type", &tx_type_obj)) {
                                    const char *tx_type_str = json_object_get_string(tx_type_obj);

                                    if (strcmp(tx_type_str, "recv") == 0) {
                                        direction = "received";
                                        if (json_object_object_get_ex(first_data, "recv_coins", &coins_obj)) {
                                            amount = QString::fromUtf8(json_object_get_string(coins_obj));
                                            // Keep original precision or show up to 8 decimals
                                            double amt = amount.toDouble();
                                            if (amt < 0.01) {
                                                amount = QString::number(amt, 'f', 8);
                                            } else if (amt < 1.0) {
                                                amount = QString::number(amt, 'f', 4);
                                            } else {
                                                amount = QString::number(amt, 'f', 2);
                                            }
                                            // Remove trailing zeros
                                            amount.remove(QRegExp("0+$"));
                                            amount.remove(QRegExp("\\.$"));
                                        }
                                        if (json_object_object_get_ex(first_data, "source_address", &addr_obj)) {
                                            otherAddress = QString::fromUtf8(json_object_get_string(addr_obj)).left(12) + "...";
                                        }
                                    } else if (strcmp(tx_type_str, "send") == 0) {
                                        direction = "sent";
                                        if (json_object_object_get_ex(first_data, "send_coins", &coins_obj)) {
                                            amount = QString::fromUtf8(json_object_get_string(coins_obj));
                                            // Keep original precision or show up to 8 decimals
                                            double amt = amount.toDouble();
                                            if (amt < 0.01) {
                                                amount = QString::number(amt, 'f', 8);
                                            } else if (amt < 1.0) {
                                                amount = QString::number(amt, 'f', 4);
                                            } else {
                                                amount = QString::number(amt, 'f', 2);
                                            }
                                            // Remove trailing zeros
                                            amount.remove(QRegExp("0+$"));
                                            amount.remove(QRegExp("\\.$"));
                                        }
                                        if (json_object_object_get_ex(first_data, "destination_address", &addr_obj)) {
                                            otherAddress = QString::fromUtf8(json_object_get_string(addr_obj)).left(12) + "...";
                                        }
                                    }

                                    if (json_object_object_get_ex(first_data, "token", &token_obj)) {
                                        token = QString::fromUtf8(json_object_get_string(token_obj));
                                    }
                                }
                            }
                        }

                        QWidget *txItem = createTransactionItem(
                            direction,
                            amount,
                            token,
                            otherAddress,
                            timeStr
                        );
                        transactionLayout->addWidget(txItem);
                        displayed++;
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    }

    transactionLayout->addStretch();
}

void WalletDialog::onSendTokens() {
    if (!wallets || currentWalletIndex < 0) {
        QMessageBox::warning(this, "No Wallet", "No wallet loaded.");
        return;
    }

    // Create and show SendTokensDialog with current wallet
    cellframe_wallet_t *wallet = &wallets->wallets[currentWalletIndex];
    SendTokensDialog *sendDialog = new SendTokensDialog(wallet, this);
    sendDialog->setWindowTitle("💸 Send Tokens");
    sendDialog->setMinimumWidth(750);
    sendDialog->setMinimumHeight(650);
    sendDialog->resize(800, 700);
    sendDialog->setAttribute(Qt::WA_DeleteOnClose);
    sendDialog->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint);
    sendDialog->setWindowModality(Qt::ApplicationModal);

    sendDialog->show();
    sendDialog->raise();
    sendDialog->activateWindow();
}

void WalletDialog::onReceiveTokens() {
    if (!wallets || currentWalletIndex < 0) {
        QMessageBox::warning(this, "No Wallet", "No wallet loaded.");
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[currentWalletIndex];

    // Show ReceiveDialog with QR code
    ReceiveDialog *receiveDialog = new ReceiveDialog(wallet, this);
    receiveDialog->setAttribute(Qt::WA_DeleteOnClose);
    receiveDialog->setWindowModality(Qt::ApplicationModal);
    receiveDialog->exec();
}

void WalletDialog::onTokenCardClicked(const QString &token) {
    // TODO: Show detailed view for specific token
    QMessageBox::information(this, "Token Details",
                            QString("Detailed view for %1 coming soon...").arg(token));
}

QString WalletDialog::formatBalance(const QString &coins) {
    if (coins.isEmpty() || coins == "0" || coins == "0.0") {
        return "0.00";
    }

    double balance = coins.toDouble();
    return QString::number(balance, 'f', 2);
}

void WalletDialog::applyTheme(CpunkTheme theme) {
    currentTheme = theme;

    // Use EXACT colors from cpunk_themes.h
    QString primary = (theme == THEME_CPUNK_IO) ? CPUNK_IO_PRIMARY : CPUNK_CLUB_PRIMARY;
    QString background = (theme == THEME_CPUNK_IO) ? CPUNK_IO_BACKGROUND : CPUNK_CLUB_BACKGROUND;
    QString secondary = (theme == THEME_CPUNK_IO) ? CPUNK_IO_SECONDARY : CPUNK_CLUB_SECONDARY;
    QString border = (theme == THEME_CPUNK_IO) ? CPUNK_IO_BORDER : CPUNK_CLUB_BORDER;
    QString text = (theme == THEME_CPUNK_IO) ? CPUNK_IO_TEXT : CPUNK_CLUB_TEXT;

    // Apply dialog theme using getCpunkStyleSheet
    setStyleSheet(getCpunkStyleSheet(theme));
}

void WalletDialog::onThemeChanged(CpunkTheme theme) {
    applyTheme(theme);
}

void WalletDialog::onDexClicked() {
    QMessageBox::information(this, "DEX", "DEX feature is under development.");
}

void WalletDialog::onHistoryClicked() {
    if (!wallets || currentWalletIndex < 0) {
        QMessageBox::warning(this, "No Wallet", "No wallet loaded.");
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[currentWalletIndex];
    TransactionHistoryDialog *historyDialog = new TransactionHistoryDialog(wallet, this);
    historyDialog->setAttribute(Qt::WA_DeleteOnClose);
    historyDialog->show();
}
