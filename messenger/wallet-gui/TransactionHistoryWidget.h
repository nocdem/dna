/*
 * TransactionHistoryWidget.h - Transaction History Viewer
 *
 * Part of cpunk wallet - displays transaction history
 */

#ifndef TRANSACTIONHISTORYWIDGET_H
#define TRANSACTIONHISTORYWIDGET_H

#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>

extern "C" {
    #include "../wallet.h"
    #include "../cellframe_rpc.h"
}

class TransactionHistoryWidget : public QWidget {
    Q_OBJECT

public:
    explicit TransactionHistoryWidget(wallet_list_t *wallets, QWidget *parent = nullptr);
    ~TransactionHistoryWidget();

    void refreshHistory();

private slots:
    void onWalletChanged(int index);
    void onRefreshClicked();
    void onTransactionClicked(int row, int column);

private:
    void setupUI();
    void loadTransactionHistory(const char *address);
    void parseAndDisplayTransaction(json_object *tx_obj);
    QString formatTimestamp(const QString &timestamp);
    QString formatAddress(const QString &address);

    // UI Components
    QComboBox *walletComboBox;
    QTableWidget *transactionTable;
    QPushButton *refreshButton;
    QLabel *statusLabel;

    // Data
    wallet_list_t *wallets;
    int selectedWalletIndex;
};

#endif // TRANSACTIONHISTORYWIDGET_H
