/*
 * DNA Messenger - Qt GUI
 * CF20 Wallet Dialog Implementation
 */

#include "WalletDialog.h"
#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QTimer>
#include <json-c/json.h>

WalletDialog::WalletDialog(QWidget *parent, const QString &specificWallet)
    : QDialog(parent), wallets(nullptr), specificWallet(specificWallet) {
    setupUI();
    loadWallets();
}

WalletDialog::~WalletDialog() {
    if (wallets) {
        wallet_list_free(wallets);
    }
}

void WalletDialog::setupUI() {
    // Set window title based on whether showing specific wallet or all
    if (specificWallet.isEmpty()) {
        setWindowTitle(QString::fromUtf8("💰 CF20 Wallet - All Wallets"));
    } else {
        setWindowTitle(QString::fromUtf8("💰 CF20 Wallet - %1").arg(specificWallet));
    }
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

    // If specific wallet requested, filter to show only that wallet
    size_t displayCount = 0;
    int specificWalletIndex = -1;

    if (!specificWallet.isEmpty()) {
        // Find the specific wallet
        for (size_t i = 0; i < wallets->count; i++) {
            if (QString::fromUtf8(wallets->wallets[i].name) == specificWallet) {
                specificWalletIndex = i;
                displayCount = 1;
                break;
            }
        }

        if (specificWalletIndex == -1) {
            statusLabel->setText(QString::fromUtf8("❌ Wallet '%1' not found").arg(specificWallet));
            QMessageBox::warning(this, "Wallet Not Found",
                               QString::fromUtf8("Wallet '%1' was not found in %2")
                                   .arg(specificWallet)
                                   .arg(CELLFRAME_WALLET_PATH));
            return;
        }

        statusLabel->setText(QString::fromUtf8("Wallet: %1. Click 'Refresh Balances' to load token balances.").arg(specificWallet));
    } else {
        displayCount = wallets->count;
        statusLabel->setText(QString::fromUtf8("Found %1 wallet(s). Click 'Refresh Balances' to load token balances.").arg(wallets->count));
    }

    walletTable->setRowCount(displayCount);

    // Display wallets (either all or just the specific one)
    size_t displayRow = 0;
    for (size_t i = 0; i < wallets->count; i++) {
        // Skip if showing specific wallet and this isn't it
        if (!specificWallet.isEmpty() && (int)i != specificWalletIndex) {
            continue;
        }

        cellframe_wallet_t *wallet = &wallets->wallets[i];

        // Wallet name
        QTableWidgetItem *nameItem = new QTableWidgetItem(QString::fromUtf8(wallet->name));
        walletTable->setItem(displayRow, 0, nameItem);

        // Get address from wallet (generated from public key)
        // Protected wallets (version 2) require password and cannot generate addresses
        if (wallet->status == WALLET_STATUS_PROTECTED) {
            walletTable->setItem(displayRow, 1, new QTableWidgetItem(QString::fromUtf8("🔒 Protected - Password Required")));
        } else {
            char address[WALLET_ADDRESS_MAX];
            if (wallet_get_address(wallet, "Backbone", address) == 0) {
                walletTable->setItem(displayRow, 1, new QTableWidgetItem(QString::fromUtf8(address)));
            } else {
                walletTable->setItem(displayRow, 1, new QTableWidgetItem(QString::fromUtf8("Error generating address")));
            }
        }

        // Placeholders for balances - will be loaded when user clicks Refresh
        walletTable->setItem(displayRow, 2, new QTableWidgetItem(QString::fromUtf8("Click Refresh...")));
        walletTable->setItem(displayRow, 3, new QTableWidgetItem(QString::fromUtf8("Click Refresh...")));
        walletTable->setItem(displayRow, 4, new QTableWidgetItem(QString::fromUtf8("Click Refresh...")));

        displayRow++;
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
        if (address.startsWith("Error") || address.startsWith("Click")) continue;

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
    if (!wallets || wallets->count == 0) {
        QMessageBox::warning(this, "No Wallets", "No wallets available to send from.");
        return;
    }

    printf("[DEBUG] WalletDialog::onSendTokens() - wallets pointer: %p, count: %zu\n", (void*)wallets, wallets->count);

    // Create and show the SendTokensDialog (1-1 same as wallet GUI)
    // IMPORTANT: Pass 'this' as parent so dialog stays with WalletDialog
    SendTokensDialog *sendDialog = new SendTokensDialog(wallets, this);
    sendDialog->setWindowTitle(QString::fromUtf8("💸 Send CF20 Tokens"));
    sendDialog->setMinimumWidth(650);
    sendDialog->setMinimumHeight(550);
    sendDialog->resize(700, 600);
    sendDialog->setAttribute(Qt::WA_DeleteOnClose);  // Auto-delete when closed

    // Make it a dialog window that stays on top of parent
    sendDialog->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
    sendDialog->setWindowModality(Qt::WindowModal);  // Modal to parent only

    sendDialog->show();
    sendDialog->raise();  // Bring to front
    sendDialog->activateWindow();  // Give it focus
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
