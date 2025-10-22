/*
 * TransactionHistoryWidget.cpp - cpunk Wallet Transaction History
 */

#include "TransactionHistoryWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>
#include <QApplication>
#include <json-c/json.h>

TransactionHistoryWidget::TransactionHistoryWidget(wallet_list_t *wallets, QWidget *parent)
    : QWidget(parent),
      wallets(wallets),
      selectedWalletIndex(-1) {

    setupUI();

    if (wallets && wallets->count > 0) {
        onWalletChanged(0);
    }
}

TransactionHistoryWidget::~TransactionHistoryWidget() {
    // wallets is managed by parent
}

void TransactionHistoryWidget::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Top bar with wallet selector and refresh
    QHBoxLayout *topLayout = new QHBoxLayout();

    QLabel *walletLabel = new QLabel(QString::fromUtf8("Wallet:"), this);
    topLayout->addWidget(walletLabel);

    walletComboBox = new QComboBox(this);
    if (wallets) {
        for (size_t i = 0; i < wallets->count; i++) {
            QString walletName = QString::fromUtf8(wallets->wallets[i].name);
            walletComboBox->addItem(QString::fromUtf8("💼 %1").arg(walletName));
        }
    }
    connect(walletComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TransactionHistoryWidget::onWalletChanged);
    topLayout->addWidget(walletComboBox);

    topLayout->addStretch();

    refreshButton = new QPushButton(QString::fromUtf8("🔄 Refresh"), this);
    connect(refreshButton, &QPushButton::clicked, this, &TransactionHistoryWidget::onRefreshClicked);
    topLayout->addWidget(refreshButton);

    mainLayout->addLayout(topLayout);

    // Transaction table
    transactionTable = new QTableWidget(0, 6, this);
    transactionTable->setHorizontalHeaderLabels({
        QString::fromUtf8("Date/Time"),
        QString::fromUtf8("Type"),
        QString::fromUtf8("Amount"),
        QString::fromUtf8("From/To"),
        QString::fromUtf8("Status"),
        QString::fromUtf8("Hash")
    });

    transactionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    transactionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    transactionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    transactionTable->horizontalHeader()->setStretchLastSection(true);
    transactionTable->verticalHeader()->setVisible(false);

    // Set column widths
    transactionTable->setColumnWidth(0, 180);  // Date/Time
    transactionTable->setColumnWidth(1, 80);   // Type
    transactionTable->setColumnWidth(2, 120);  // Amount
    transactionTable->setColumnWidth(3, 200);  // From/To
    transactionTable->setColumnWidth(4, 100);  // Status

    connect(transactionTable, &QTableWidget::cellDoubleClicked,
            this, &TransactionHistoryWidget::onTransactionClicked);

    mainLayout->addWidget(transactionTable);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8("Select a wallet to view transactions"), this);
    statusLabel->setStyleSheet("padding: 5px; color: #888;");
    mainLayout->addWidget(statusLabel);
}

void TransactionHistoryWidget::onWalletChanged(int index) {
    selectedWalletIndex = index;
    refreshHistory();
}

void TransactionHistoryWidget::onRefreshClicked() {
    refreshHistory();
}

void TransactionHistoryWidget::refreshHistory() {
    if (!wallets || selectedWalletIndex < 0 || (size_t)selectedWalletIndex >= wallets->count) {
        transactionTable->setRowCount(0);
        statusLabel->setText(QString::fromUtf8("No wallet selected"));
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[selectedWalletIndex];
    char address[WALLET_ADDRESS_MAX];

    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        transactionTable->setRowCount(0);
        statusLabel->setText(QString::fromUtf8("❌ Failed to get wallet address"));
        return;
    }

    statusLabel->setText(QString::fromUtf8("🔄 Loading transactions..."));
    QApplication::processEvents();

    loadTransactionHistory(address);
}

void TransactionHistoryWidget::loadTransactionHistory(const char *address) {
    // Clear existing rows
    transactionTable->setRowCount(0);

    // Query transaction history via RPC
    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string("Backbone"));
    json_object_object_add(args, "-addr", json_object_new_string(address));
    json_object_object_add(args, "-chain", json_object_new_string("main"));

    cellframe_rpc_request_t req = {
        .method = "tx_history",
        .subcommand = "",
        .arguments = args,
        .id = 1
    };

    cellframe_rpc_response_t *response = nullptr;
    int ret = cellframe_rpc_call(&req, &response);
    json_object_put(args);

    if (ret != 0 || !response || !response->result) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to load transactions"));
        if (response) cellframe_rpc_response_free(response);
        return;
    }

    // Parse transactions
    if (json_object_is_type(response->result, json_type_array)) {
        int tx_count = json_object_array_length(response->result);

        if (tx_count == 0) {
            statusLabel->setText(QString::fromUtf8("No transactions found"));
        } else {
            for (int i = 0; i < tx_count; i++) {
                json_object *tx_obj = json_object_array_get_idx(response->result, i);
                parseAndDisplayTransaction(tx_obj);
            }
            statusLabel->setText(QString::fromUtf8("✓ Loaded %1 transactions").arg(tx_count));
        }
    }

    cellframe_rpc_response_free(response);
}

void TransactionHistoryWidget::parseAndDisplayTransaction(json_object *tx_obj) {
    if (!tx_obj) return;

    // Extract transaction fields
    json_object *hash_obj, *status_obj, *action_obj, *timestamp_obj, *items_obj;

    const char *hash = nullptr, *status = nullptr, *action = nullptr, *timestamp = nullptr;

    if (json_object_object_get_ex(tx_obj, "hash", &hash_obj)) {
        hash = json_object_get_string(hash_obj);
    }
    if (json_object_object_get_ex(tx_obj, "status", &status_obj)) {
        status = json_object_get_string(status_obj);
    }
    if (json_object_object_get_ex(tx_obj, "action", &action_obj)) {
        action = json_object_get_string(action_obj);
    }
    if (json_object_object_get_ex(tx_obj, "tx created", &timestamp_obj)) {
        timestamp = json_object_get_string(timestamp_obj);
    }

    // Determine transaction type and amount
    QString txType = "UNKNOWN";
    QString amount = "---";
    QString fromTo = "---";

    if (json_object_object_get_ex(tx_obj, "ITEMS", &items_obj)) {
        if (json_object_is_type(items_obj, json_type_array)) {
            int item_count = json_object_array_length(items_obj);

            for (int j = 0; j < item_count; j++) {
                json_object *item = json_object_array_get_idx(items_obj, j);
                json_object *item_type_obj, *coins_obj, *address_obj;

                if (json_object_object_get_ex(item, "item type", &item_type_obj)) {
                    const char *item_type = json_object_get_string(item_type_obj);

                    if (strstr(item_type, "OUT") && json_object_object_get_ex(item, "Coins", &coins_obj)) {
                        amount = QString::fromUtf8("%1 CELL").arg(json_object_get_string(coins_obj));

                        if (json_object_object_get_ex(item, "Address", &address_obj)) {
                            fromTo = formatAddress(QString::fromUtf8(json_object_get_string(address_obj)));
                        }
                    }
                }
            }
        }
    }

    // Add row to table
    int row = transactionTable->rowCount();
    transactionTable->insertRow(row);

    transactionTable->setItem(row, 0, new QTableWidgetItem(formatTimestamp(QString::fromUtf8(timestamp ? timestamp : "N/A"))));
    transactionTable->setItem(row, 1, new QTableWidgetItem(txType));
    transactionTable->setItem(row, 2, new QTableWidgetItem(amount));
    transactionTable->setItem(row, 3, new QTableWidgetItem(fromTo));
    transactionTable->setItem(row, 4, new QTableWidgetItem(QString::fromUtf8(status ? status : "UNKNOWN")));
    transactionTable->setItem(row, 5, new QTableWidgetItem(QString::fromUtf8(hash ? hash : "N/A")));

    // Color status
    if (status && strcmp(status, "ACCEPTED") == 0) {
        transactionTable->item(row, 4)->setForeground(QBrush(QColor("#00FF00")));
    } else {
        transactionTable->item(row, 4)->setForeground(QBrush(QColor("#FF4444")));
    }
}

QString TransactionHistoryWidget::formatTimestamp(const QString &timestamp) {
    // Already formatted from RPC, just return it
    return timestamp;
}

QString TransactionHistoryWidget::formatAddress(const QString &address) {
    if (address.length() > 20) {
        return address.left(10) + "..." + address.right(10);
    }
    return address;
}

void TransactionHistoryWidget::onTransactionClicked(int row, int column) {
    Q_UNUSED(column);

    QTableWidgetItem *hashItem = transactionTable->item(row, 5);
    if (!hashItem) return;

    QString hash = hashItem->text();

    if (hash == "N/A") {
        return;
    }

    // Open blockchain explorer
    QString url = QString("https://scan.cellframe.net/datum-details/%1?net=Backbone").arg(hash);
    QDesktopServices::openUrl(QUrl(url));
}
