/*
 * DNA Messenger - Qt GUI
 * CF20 Wallet Dialog
 */

#ifndef WALLETDIALOG_H
#define WALLETDIALOG_H

#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>

extern "C" {
    #include "../wallet.h"
    #include "../cellframe_rpc.h"
}

class WalletDialog : public QDialog {
    Q_OBJECT

public:
    explicit WalletDialog(QWidget *parent = nullptr);
    ~WalletDialog();

private slots:
    void onRefreshBalances();
    void onSendTokens();
    void onReceiveTokens();

private:
    void setupUI();
    void loadWallets();
    void updateBalances();
    QString formatBalance(const QString &coins);

    // UI Components
    QTableWidget *walletTable;
    QPushButton *refreshButton;
    QPushButton *sendButton;
    QPushButton *receiveButton;
    QPushButton *closeButton;
    QLabel *statusLabel;

    // Wallet data
    wallet_list_t *wallets;
};

#endif // WALLETDIALOG_H
