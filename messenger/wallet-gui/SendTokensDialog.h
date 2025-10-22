/*
 * SendTokensDialog.h - Send CF20 Tokens Dialog
 *
 * Part of cpunk wallet - integrates transaction builder backend
 */

#ifndef SENDTOKENSDIALOG_H
#define SENDTOKENSDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QDoubleSpinBox>
#include <QTextEdit>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QCheckBox>

extern "C" {
    #include "../wallet.h"
    #include "../cellframe_tx_builder_minimal.h"
    #include "../cellframe_sign_minimal.h"
    #include "../cellframe_rpc.h"
    #include "../cellframe_addr.h"
}

class SendTokensDialog : public QDialog {
    Q_OBJECT

public:
    explicit SendTokensDialog(wallet_list_t *wallets, QWidget *parent = nullptr);
    ~SendTokensDialog();

    void updateWalletList(wallet_list_t *wallets);

private slots:
    void onWalletChanged(int index);
    void onSendClicked();
    void onCancelClicked();
    void onMaxAmountClicked();
    void onValidateAddress();
    void onTsdToggled(bool enabled);

private:
    void setupUI();
    void updateAvailableBalance();
    bool validateInputs();
    void buildAndSendTransaction();

    // UI Components
    QComboBox *walletComboBox;
    QLabel *balanceLabel;
    QLineEdit *recipientEdit;
    QLabel *addressValidationLabel;
    QDoubleSpinBox *amountSpinBox;
    QPushButton *maxAmountButton;
    QDoubleSpinBox *feeSpinBox;
    QLineEdit *networkFeeAddressEdit;
    QCheckBox *tsdCheckBox;
    QLineEdit *tsdDataEdit;
    QLabel *statusLabel;
    QPushButton *sendButton;
    QPushButton *cancelButton;

    // Data
    wallet_list_t *wallets;
    int selectedWalletIndex;
    double availableBalance;
};

#endif // SENDTOKENSDIALOG_H
