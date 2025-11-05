/*
 * DNA Messenger - Register DNA Name Dialog
 * Phase 4: DNA Name Registration (0.01 CPUNK)
 */

#ifndef REGISTERDNANAMEDIALOG_H
#define REGISTERDNANAMEDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QTimer>
#include <QTextEdit>

extern "C" {
    #include "../messenger.h"
    #include "../wallet.h"
    #include "../cellframe_rpc.h"
}

class RegisterDNANameDialog : public QDialog {
    Q_OBJECT

public:
    explicit RegisterDNANameDialog(messenger_context_t *ctx, QWidget *parent = nullptr);
    ~RegisterDNANameDialog() override = default;

private slots:
    void onNameChanged();
    void onCheckAvailability();
    void onWalletSelected(int index);
    void onNetworkSelected(int index);
    void onRegister();
    void onCancel();

private:
    void setupUI();
    void loadWallets();
    void updateCost();
    bool validateName(const QString &name);
    void checkNameAvailability(const QString &name);
    void buildTransaction();
    void signAndSubmit();

    messenger_context_t *m_ctx;

    // UI Elements
    QLabel *fingerprintLabel;
    QLineEdit *nameInput;
    QLabel *availabilityLabel;
    QComboBox *walletSelector;
    QComboBox *networkSelector;
    QLabel *costLabel;
    QLabel *balanceLabel;
    QTextEdit *transactionPreview;
    QPushButton *registerButton;
    QPushButton *cancelButton;
    QLabel *statusLabel;

    // Data
    QTimer *availabilityTimer;
    QString currentFingerprint;
    QString selectedWallet;
    QString selectedNetwork;
    double walletBalance;
    bool nameAvailable;

    // Transaction data
    QString txHash;
};

#endif // REGISTERDNANAMEDIALOG_H
