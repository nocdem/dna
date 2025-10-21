/*
 * cpunk-wallet-gui - Main Window
 *
 * Standalone CF20 wallet application for Cellframe blockchain
 */

#ifndef WALLETMAINWINDOW_H
#define WALLETMAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QMenuBar>
#include <QStatusBar>
#include <QComboBox>
#include "cpunk_themes.h"

extern "C" {
    #include "../wallet.h"
    #include "../cellframe_rpc.h"
}

// Forward declarations
class SendTokensDialog;
class TransactionHistoryWidget;
class WalletSettingsDialog;

class WalletMainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit WalletMainWindow(QWidget *parent = nullptr);
    ~WalletMainWindow();

private slots:
    // Menu actions
    void onRefreshWallets();
    void onRefreshBalances();
    void onSendTokens();
    void onReceiveTokens();
    void onSettings();
    void onAbout();
    void onQuit();

    // Theme switching
    void onThemeChanged(int index);

    // Wallet table interactions
    void onWalletSelected(int row, int column);

private:
    void setupUI();
    void createMenuBar();
    void createWalletsTab();
    void createSendTab();
    void createTransactionsTab();
    void createSettingsTab();
    void createStatusBar();

    void loadWallets();
    void updateBalances();
    void updateStatusBar();
    void applyTheme(CpunkTheme theme);
    QString formatBalance(const QString &coins);

    // UI Components
    QTabWidget *tabWidget;

    // Wallets Tab
    QWidget *walletsTab;
    QTableWidget *walletTable;
    QPushButton *refreshWalletsButton;
    QPushButton *refreshBalancesButton;
    QPushButton *receiveButton;
    QLabel *walletsStatusLabel;

    // Send Tab
    QWidget *sendTab;
    SendTokensDialog *sendDialog;

    // Transactions Tab
    QWidget *transactionsTab;
    TransactionHistoryWidget *transactionHistory;

    // Settings Tab
    QWidget *settingsTab;
    QComboBox *themeComboBox;
    QComboBox *networkComboBox;

    // Status bar
    QLabel *networkStatusLabel;
    QLabel *balanceStatusLabel;

    // Data
    wallet_list_t *wallets;
    CpunkTheme currentTheme;
    int selectedWalletIndex;
};

#endif // WALLETMAINWINDOW_H
