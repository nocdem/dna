/*
 * DNA Messenger - Qt GUI
 * CF20 Wallet Dialog Implementation
 */

#include "WalletDialog.h"
#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <json-c/json.h>

WalletDialog::WalletDialog(QWidget *parent)
    : QDialog(parent), wallets(nullptr) {
    setupUI();
    loadWallets();
}

WalletDialog::~WalletDialog() {
    if (wallets) {
        wallet_list_free(wallets);
    }
}

void WalletDialog::setupUI() {
    setWindowTitle(QString::fromUtf8("💰 CF20 Wallet"));
    setMinimumSize(900, 600);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Title
    QLabel *titleLabel = new QLabel(QString::fromUtf8("Cellframe CF20 Token Wallet"), this);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #00D9FF; margin: 10px;");
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    // Wallet table
    walletTable = new QTableWidget(this);
    walletTable->setColumnCount(5);
    walletTable->setHorizontalHeaderLabels({
        "Wallet Name",
        "Address",
        "CPUNK Balance",
        "CELL Balance",
        "KEL Balance"
    });

    walletTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    walletTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    walletTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    walletTable->setStyleSheet(
        "QTableWidget {"
        "   background: #0D3438;"
        "   color: #00D9FF;"
        "   gridline-color: rgba(0, 217, 255, 0.2);"
        "   border: 1px solid rgba(0, 217, 255, 0.3);"
        "}"
        "QTableWidget::item {"
        "   padding: 8px;"
        "}"
        "QTableWidget::item:selected {"
        "   background: rgba(0, 217, 255, 0.3);"
        "}"
        "QHeaderView::section {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   padding: 8px;"
        "   border: 1px solid rgba(0, 217, 255, 0.3);"
        "   font-weight: bold;"
        "}"
    );

    mainLayout->addWidget(walletTable);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8("Loading wallets..."), this);
    statusLabel->setStyleSheet("color: #00D9FF; padding: 5px;");
    mainLayout->addWidget(statusLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    refreshButton = new QPushButton(QString::fromUtf8("🔄 Refresh Balances"), this);
    sendButton = new QPushButton(QString::fromUtf8("💸 Send Tokens"), this);
    receiveButton = new QPushButton(QString::fromUtf8("📥 Receive (Show QR)"), this);
    closeButton = new QPushButton(QString::fromUtf8("Close"), this);

    QString buttonStyle =
        "QPushButton {"
        "   background: rgba(0, 217, 255, 0.2);"
        "   color: #00D9FF;"
        "   border: 1px solid rgba(0, 217, 255, 0.5);"
        "   border-radius: 4px;"
        "   padding: 10px 20px;"
        "   font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: rgba(0, 217, 255, 0.3);"
        "   border-color: #00D9FF;"
        "}"
        "QPushButton:pressed {"
        "   background: rgba(0, 217, 255, 0.4);"
        "}";

    refreshButton->setStyleSheet(buttonStyle);
    sendButton->setStyleSheet(buttonStyle);
    receiveButton->setStyleSheet(buttonStyle);
    closeButton->setStyleSheet(buttonStyle);

    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(sendButton);
    buttonLayout->addWidget(receiveButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);

    // Connect signals
    connect(refreshButton, &QPushButton::clicked, this, &WalletDialog::onRefreshBalances);
    connect(sendButton, &QPushButton::clicked, this, &WalletDialog::onSendTokens);
    connect(receiveButton, &QPushButton::clicked, this, &WalletDialog::onReceiveTokens);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);

    // Apply dark theme
    setStyleSheet(
        "QDialog {"
        "   background: #0A2428;"
        "   color: #00D9FF;"
        "}"
    );
}

void WalletDialog::loadWallets() {
    statusLabel->setText(QString::fromUtf8("Loading wallets from %1...").arg(CELLFRAME_WALLET_PATH));

    int ret = wallet_list_cellframe(&wallets);

    if (ret != 0 || !wallets || wallets->count == 0) {
        statusLabel->setText(QString::fromUtf8("❌ No wallets found in %1").arg(CELLFRAME_WALLET_PATH));
        QMessageBox::warning(this, "No Wallets",
                           QString::fromUtf8("No Cellframe wallets found.\n\n"
                                            "Please create a wallet using cellframe-node-cli:\n"
                                            "cellframe-node-cli wallet new -w myWallet -sign dilithium"));
        return;
    }

    statusLabel->setText(QString::fromUtf8("Found %1 wallet(s). Click 'Refresh Balances' to load token balances.").arg(wallets->count));

    walletTable->setRowCount(wallets->count);

    for (size_t i = 0; i < wallets->count; i++) {
        cellframe_wallet_t *wallet = &wallets->wallets[i];

        // Wallet name
        QTableWidgetItem *nameItem = new QTableWidgetItem(QString::fromUtf8(wallet->name));
        walletTable->setItem(i, 0, nameItem);

        // Get address
        char address[WALLET_ADDRESS_MAX];
        if (wallet_get_address(wallet, "Backbone", address) == 0) {
            QTableWidgetItem *addrItem = new QTableWidgetItem(QString::fromUtf8(address));
            addrItem->setToolTip(QString::fromUtf8("Click to copy address"));
            walletTable->setItem(i, 1, addrItem);
        } else {
            walletTable->setItem(i, 1, new QTableWidgetItem(QString::fromUtf8("Error")));
        }

        // Placeholders for balances
        walletTable->setItem(i, 2, new QTableWidgetItem(QString::fromUtf8("...")));
        walletTable->setItem(i, 3, new QTableWidgetItem(QString::fromUtf8("...")));
        walletTable->setItem(i, 4, new QTableWidgetItem(QString::fromUtf8("...")));
    }
}

void WalletDialog::onRefreshBalances() {
    if (!wallets || wallets->count == 0) {
        return;
    }

    statusLabel->setText(QString::fromUtf8("🔄 Refreshing balances from Cellframe RPC..."));
    refreshButton->setEnabled(false);

    for (size_t i = 0; i < wallets->count; i++) {
        QTableWidgetItem *addrItem = walletTable->item(i, 1);
        if (!addrItem) continue;

        QString address = addrItem->text();
        if (address == "Error") continue;

        // Query balance via RPC
        cellframe_rpc_response_t *response = nullptr;
        if (cellframe_rpc_get_balance("Backbone", address.toUtf8().constData(), "CPUNK", &response) == 0) {
            if (response->result) {
                // Parse JSON response to extract token balances
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
                            }
                        }
                    }
                }
            }

            cellframe_rpc_response_free(response);
        } else {
            // RPC failed, show error
            walletTable->setItem(i, 2, new QTableWidgetItem(QString::fromUtf8("RPC Error")));
            walletTable->setItem(i, 3, new QTableWidgetItem(QString::fromUtf8("RPC Error")));
            walletTable->setItem(i, 4, new QTableWidgetItem(QString::fromUtf8("RPC Error")));
        }
    }

    statusLabel->setText(QString::fromUtf8("✅ Balances updated from Cellframe Backbone network"));
    refreshButton->setEnabled(true);
}

void WalletDialog::onSendTokens() {
    QMessageBox::information(this, "Send Tokens",
                           QString::fromUtf8("🚧 Send CF20 Tokens - Coming Soon!\n\n"
                                            "This feature will allow you to send CF20 tokens directly from DNA Messenger."));
}

void WalletDialog::onReceiveTokens() {
    int currentRow = walletTable->currentRow();
    if (currentRow < 0) {
        QMessageBox::information(this, "Select Wallet",
                               QString::fromUtf8("Please select a wallet to show the receive address."));
        return;
    }

    QTableWidgetItem *addrItem = walletTable->item(currentRow, 1);
    if (!addrItem) return;

    QString address = addrItem->text();

    // Copy address to clipboard
    QApplication::clipboard()->setText(address);

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(QString::fromUtf8("Receive Tokens"));
    msgBox.setText(QString::fromUtf8("📥 Wallet Address (copied to clipboard):\n\n%1\n\n"
                                     "Send CF20 tokens to this address on Cellframe Backbone network.").arg(address));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}

QString WalletDialog::formatBalance(const QString &coins) {
    if (coins.isEmpty() || coins == "0" || coins == "0.0") {
        return "0.0";
    }
    return coins;
}
