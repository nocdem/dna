/*
 * SendTokensDialog.h - Send CF20 Tokens Widget
 *
 * Part of cpunk wallet - integrates transaction builder backend
 */

#ifndef SENDTOKENSDIALOG_H
#define SENDTOKENSDIALOG_H

#include <QWidget>
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
    #include "../cellframe_json_minimal.h"
    #include "../cellframe_minimal.h"
    #include "../base58.h"
    #include <time.h>
}

class SendTokensDialog : public QWidget {
    Q_OBJECT

public:
    explicit SendTokensDialog(wallet_list_t *wallets, QWidget *parent = nullptr);
    ~SendTokensDialog();

    void updateWalletList(wallet_list_t *wallets);

private slots:
    void onWalletChanged(int index);
    void onSendClicked();
    void onMaxAmountClicked();
    void onValidateAddress();
    void onTsdToggled(bool enabled);

private:
    void setupUI();
    void updateBalanceFromWalletList();  // Use balance from wallet list (no RPC)
    bool validateInputs();
    void buildAndSendTransaction();  // Queries UTXOs and builds transaction

    // UI Components
    QComboBox *walletComboBox;
    QLabel *balanceLabel;
    QLineEdit *recipientEdit;
    QLabel *addressValidationLabel;
    QLineEdit *amountEdit;  // Changed from QDoubleSpinBox to avoid precision loss
    QPushButton *maxAmountButton;
    QLineEdit *feeEdit;  // Changed from QDoubleSpinBox to avoid precision loss
    QLineEdit *networkFeeAddressEdit;
    QCheckBox *tsdCheckBox;
    QLineEdit *tsdDataEdit;
    QLabel *statusLabel;
    QPushButton *sendButton;

    // Data
    wallet_list_t *wallets;
    int selectedWalletIndex;
    double availableBalance;
};

#endif // SENDTOKENSDIALOG_H
