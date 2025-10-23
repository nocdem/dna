/*
 * TransactionHistoryDialog.h - Full Transaction History
 */

#ifndef TRANSACTIONHISTORYDIALOG_H
#define TRANSACTIONHISTORYDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include "ThemeManager.h"

extern "C" {
#include "../wallet.h"
}

class TransactionHistoryDialog : public QDialog {
    Q_OBJECT

public:
    explicit TransactionHistoryDialog(const cellframe_wallet_t *wallet, QWidget *parent = nullptr);
    ~TransactionHistoryDialog();

private slots:
    void onThemeChanged(CpunkTheme theme);

private:
    void setupUI();
    void loadAllTransactions();
    void applyTheme(CpunkTheme theme);
    QWidget* createTransactionItem(const QString &type, const QString &amount, const QString &token,
                                    const QString &address, const QString &time, const QString &status);

    cellframe_wallet_t m_wallet;
    QVBoxLayout *transactionLayout;
    CpunkTheme currentTheme;
};

#endif // TRANSACTIONHISTORYDIALOG_H
