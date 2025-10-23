/*
 * ReceiveDialog.h - Wallet Address Display with QR Code
 *
 * Shows wallet address in text and QR code format for receiving tokens
 */

#ifndef RECEIVEDIALOG_H
#define RECEIVEDIALOG_H

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QVBoxLayout>
#include "ThemeManager.h"

extern "C" {
#include "../wallet.h"
}

class ReceiveDialog : public QDialog {
    Q_OBJECT

public:
    explicit ReceiveDialog(const cellframe_wallet_t *wallet, QWidget *parent = nullptr);
    ~ReceiveDialog();

private slots:
    void onCopyAddress();
    void onThemeChanged(CpunkTheme theme);

private:
    void setupUI();
    void applyTheme(CpunkTheme theme);
    void generateQRCode();

    // Wallet info
    cellframe_wallet_t m_wallet;

    // UI Components
    QVBoxLayout *mainLayout;
    QLabel *titleLabel;
    QLabel *walletNameLabel;
    QLabel *qrCodeLabel;
    QLineEdit *addressLineEdit;
    QPushButton *copyButton;
    QPushButton *closeButton;
};

#endif // RECEIVEDIALOG_H
