/*
 * DNA Messenger - Qt GUI
 * CF20 Wallet Dialog - Modern Card-Based Design
 */

#ifndef WALLETDIALOG_H
#define WALLETDIALOG_H

#include <QDialog>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QWidget>
#include "SendTokensDialog.h"
#include "ThemeManager.h"

extern "C" {
    #include "../wallet.h"
    #include "../blockchain_rpc.h"
}

// Token balance structure
struct TokenBalance {
    QString ticker;
    QString name;
    QString balance;
    QString icon;  // Emoji icon
};

class WalletDialog : public QDialog {
    Q_OBJECT

public:
    explicit WalletDialog(QWidget *parent = nullptr, const QString &specificWallet = QString());
    ~WalletDialog();

private slots:
    void onRefreshBalances();
    void onSendTokens();
    void onReceiveTokens();
    void onDexClicked();
    void onHistoryClicked();
    void onTokenCardClicked(const QString &token);
    void onThemeChanged(CpunkTheme theme);

private:
    void setupUI();
    void loadWallet();
    void updateBalances();
    void loadTransactionHistory();
    void applyTheme(CpunkTheme theme);
    QString formatBalance(const QString &coins);
    QWidget* createTokenCard(const QString &icon, const QString &ticker, const QString &name);
    QWidget* createTransactionItem(const QString &type, const QString &amount, const QString &token,
                                    const QString &address, const QString &time);

    // UI Components
    QLabel *walletNameLabel;
    QLabel *totalBalanceLabel;
    QLabel *totalBalanceUsdLabel;

    // Token cards
    QWidget *cpunkCard;
    QWidget *cellCard;
    QWidget *kelCard;
    QLabel *cpunkBalanceLabel;
    QLabel *cellBalanceLabel;
    QLabel *kelBalanceLabel;

    // Transaction feed
    QScrollArea *transactionScrollArea;
    QVBoxLayout *transactionLayout;

    // Action buttons
    QPushButton *sendButton;
    QPushButton *receiveButton;
    QPushButton *dexButton;
    QPushButton *historyButton;
    QLabel *statusLabel;

    // Wallet data
    wallet_list_t *wallets;
    QString specificWallet;  // If not empty, show only this wallet
    int currentWalletIndex;

    // Token balances
    QMap<QString, QString> tokenBalances;  // ticker -> balance

    // Theme
    CpunkTheme currentTheme;
};

#endif // WALLETDIALOG_H
