/*
 * TransactionHistoryDialog.cpp - Full Transaction History Implementation
 */

#include "TransactionHistoryDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDateTime>
#include <QRegExp>
#include <QFrame>
#include <json-c/json.h>

extern "C" {
#include "../blockchain_rpc.h"
}

TransactionHistoryDialog::TransactionHistoryDialog(const cellframe_wallet_t *wallet, QWidget *parent)
    : QDialog(parent), currentTheme(THEME_CPUNK_IO) {

    if (wallet) {
        memcpy(&m_wallet, wallet, sizeof(cellframe_wallet_t));
    } else {
        memset(&m_wallet, 0, sizeof(cellframe_wallet_t));
    }

    setWindowTitle("Transaction History");
    setMinimumSize(600, 500);
    resize(700, 600);
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint);

    currentTheme = ThemeManager::instance()->currentTheme();

    setupUI();
    applyTheme(currentTheme);

    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &TransactionHistoryDialog::onThemeChanged);

    loadAllTransactions();
}

TransactionHistoryDialog::~TransactionHistoryDialog() {
}

void TransactionHistoryDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Title
    QLabel *titleLabel = new QLabel(QString("Transaction History - %1").arg(m_wallet.name), this);
    QFont titleFont;
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);

    // Scroll area for transactions
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QWidget *scrollContent = new QWidget();
    transactionLayout = new QVBoxLayout(scrollContent);
    transactionLayout->setSpacing(5);

    scrollContent->setLayout(transactionLayout);
    scrollArea->setWidget(scrollContent);
    mainLayout->addWidget(scrollArea);

    // Close button
    QPushButton *closeButton = new QPushButton("Close", this);
    closeButton->setMinimumHeight(40);
    closeButton->setCursor(Qt::PointingHandCursor);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    mainLayout->addWidget(closeButton);
}

void TransactionHistoryDialog::loadAllTransactions() {
    // Get wallet address
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(&m_wallet, "Backbone", address) != 0) {
        QLabel *errorLabel = new QLabel("Failed to get wallet address", this);
        transactionLayout->addWidget(errorLabel);
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

    if (ret == 0 && response && response->result) {
        json_object *jresult = response->result;

        if (json_object_is_type(jresult, json_type_array)) {
            int result_len = json_object_array_length(jresult);

            if (result_len > 0) {
                json_object *tx_array = json_object_array_get_idx(jresult, 0);

                if (json_object_is_type(tx_array, json_type_array)) {
                    int array_len = json_object_array_length(tx_array);
                    int displayed = 0;

                    // Skip first 2 items (query parameters), show ALL transactions
                    for (int i = 2; i < array_len; i++) {
                        json_object *tx_obj = json_object_array_get_idx(tx_array, i);

                        json_object *status_obj = nullptr;
                        if (!json_object_object_get_ex(tx_obj, "status", &status_obj)) {
                            continue;
                        }

                        json_object *hash_obj = nullptr, *timestamp_obj = nullptr, *data_obj = nullptr;
                        json_object_object_get_ex(tx_obj, "hash", &hash_obj);
                        json_object_object_get_ex(tx_obj, "tx_created", &timestamp_obj);
                        json_object_object_get_ex(tx_obj, "data", &data_obj);

                        QString hash = hash_obj ? QString::fromUtf8(json_object_get_string(hash_obj)) : "N/A";
                        QString shortHash = hash.left(12) + "...";
                        QString status = QString::fromUtf8(json_object_get_string(status_obj));

                        // Parse timestamp
                        QString timeStr = "Unknown";
                        if (timestamp_obj) {
                            QString ts_str = QString::fromUtf8(json_object_get_string(timestamp_obj));
                            QDateTime txTime = QDateTime::fromString(ts_str, Qt::RFC2822Date);
                            if (txTime.isValid()) {
                                int64_t diff = QDateTime::currentSecsSinceEpoch() - txTime.toSecsSinceEpoch();
                                if (diff < 60) {
                                    timeStr = "Just now";
                                } else if (diff < 3600) {
                                    timeStr = QString::number(diff / 60) + "m ago";
                                } else if (diff < 86400) {
                                    timeStr = QString::number(diff / 3600) + "h ago";
                                } else if (diff < 86400 * 30) {
                                    timeStr = QString::number(diff / 86400) + "d ago";
                                } else {
                                    timeStr = txTime.toString("MMM dd, yyyy");
                                }
                            }
                        }

                        // Parse transaction data
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
                                            double amt = amount.toDouble();
                                            if (amt < 0.01) {
                                                amount = QString::number(amt, 'f', 8);
                                            } else if (amt < 1.0) {
                                                amount = QString::number(amt, 'f', 4);
                                            } else {
                                                amount = QString::number(amt, 'f', 2);
                                            }
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
                                            double amt = amount.toDouble();
                                            if (amt < 0.01) {
                                                amount = QString::number(amt, 'f', 8);
                                            } else if (amt < 1.0) {
                                                amount = QString::number(amt, 'f', 4);
                                            } else {
                                                amount = QString::number(amt, 'f', 2);
                                            }
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

                        QWidget *txItem = createTransactionItem(direction, amount, token, otherAddress, timeStr, status);
                        transactionLayout->addWidget(txItem);
                        displayed++;
                    }

                    if (displayed == 0) {
                        QLabel *emptyLabel = new QLabel("No transactions found", this);
                        emptyLabel->setAlignment(Qt::AlignCenter);
                        transactionLayout->addWidget(emptyLabel);
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    } else {
        QLabel *errorLabel = new QLabel("Failed to load transaction history", this);
        transactionLayout->addWidget(errorLabel);
    }

    transactionLayout->addStretch();
}

QWidget* TransactionHistoryDialog::createTransactionItem(const QString &type, const QString &amount,
                                                          const QString &token, const QString &address,
                                                          const QString &time, const QString &status) {
    QFrame *frame = new QFrame(this);
    frame->setFrameShape(QFrame::StyledPanel);

    QHBoxLayout *layout = new QHBoxLayout(frame);
    layout->setContentsMargins(10, 8, 10, 8);

    // Direction icon
    QLabel *iconLabel = new QLabel(type == "sent" ? "↑" : "↓", frame);
    QFont iconFont;
    iconFont.setPointSize(16);
    iconLabel->setFont(iconFont);
    iconLabel->setFixedWidth(30);
    // Color: red for sent (outgoing), green for received (incoming)
    iconLabel->setStyleSheet(type == "sent" ? "color: #FF4444;" : "color: #00FF00;");
    layout->addWidget(iconLabel);

    // Transaction info
    QVBoxLayout *infoLayout = new QVBoxLayout();
    infoLayout->setSpacing(2);

    QLabel *amountLabel = new QLabel(QString("%1 %2").arg(amount).arg(token), frame);
    QFont amountFont;
    amountFont.setBold(true);
    amountFont.setPointSize(11);
    amountLabel->setFont(amountFont);
    infoLayout->addWidget(amountLabel);

    QLabel *addressLabel = new QLabel(address, frame);
    QFont addressFont;
    addressFont.setPointSize(9);
    addressLabel->setFont(addressFont);
    infoLayout->addWidget(addressLabel);

    layout->addLayout(infoLayout);
    layout->addStretch();

    // Time and status
    QVBoxLayout *rightLayout = new QVBoxLayout();
    rightLayout->setSpacing(2);
    rightLayout->setAlignment(Qt::AlignRight);

    QLabel *timeLabel = new QLabel(time, frame);
    QFont timeFont;
    timeFont.setPointSize(9);
    timeLabel->setFont(timeFont);
    timeLabel->setAlignment(Qt::AlignRight);
    rightLayout->addWidget(timeLabel);

    QLabel *statusLabel = new QLabel(status, frame);
    QFont statusFont;
    statusFont.setPointSize(8);
    statusLabel->setFont(statusFont);
    statusLabel->setAlignment(Qt::AlignRight);
    // Color status red if DECLINED
    if (status.toUpper().contains("DECLINED")) {
        statusLabel->setStyleSheet("color: #FF4444;");
    }
    rightLayout->addWidget(statusLabel);

    layout->addLayout(rightLayout);

    return frame;
}

void TransactionHistoryDialog::applyTheme(CpunkTheme theme) {
    currentTheme = theme;
    setStyleSheet(getCpunkStyleSheet(theme));
}

void TransactionHistoryDialog::onThemeChanged(CpunkTheme theme) {
    applyTheme(theme);
}
