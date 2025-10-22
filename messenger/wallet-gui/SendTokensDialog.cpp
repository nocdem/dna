/*
 * SendTokensDialog.cpp - cpunk Wallet Send Dialog Implementation
 */

#include "SendTokensDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QProgressDialog>
#include <QDesktopServices>
#include <QUrl>
#include <QApplication>
#include <json-c/json.h>

// Default network fee address (Backbone network fee collector)
#define DEFAULT_NETWORK_FEE_ADDR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"

SendTokensDialog::SendTokensDialog(wallet_list_t *wallets, QWidget *parent)
    : QDialog(parent),
      wallets(wallets),
      selectedWalletIndex(-1),
      availableBalance(0.0) {

    setWindowTitle(QString::fromUtf8("💸 Send CF20 Tokens"));
    setMinimumWidth(600);

    setupUI();

    if (wallets && wallets->count > 0) {
        onWalletChanged(0);
    }
}

SendTokensDialog::~SendTokensDialog() {
    // wallets is managed by parent, don't free
}

void SendTokensDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Form layout for inputs
    QFormLayout *formLayout = new QFormLayout();

    // Wallet selector
    walletComboBox = new QComboBox(this);
    if (wallets) {
        for (size_t i = 0; i < wallets->count; i++) {
            QString walletName = QString::fromUtf8(wallets->wallets[i].name);
            walletComboBox->addItem(QString::fromUtf8("💼 %1").arg(walletName));
        }
    }
    connect(walletComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SendTokensDialog::onWalletChanged);
    formLayout->addRow(QString::fromUtf8("From Wallet:"), walletComboBox);

    // Balance label
    balanceLabel = new QLabel(QString::fromUtf8("Balance: 0.0 CELL"), this);
    balanceLabel->setStyleSheet("font-weight: bold; color: #00D9FF;");
    formLayout->addRow(QString::fromUtf8("Available:"), balanceLabel);

    // Recipient address
    recipientEdit = new QLineEdit(this);
    recipientEdit->setPlaceholderText(QString::fromUtf8("Rj7J7MiX2bWy8sNy..."));
    connect(recipientEdit, &QLineEdit::textChanged, this, &SendTokensDialog::onValidateAddress);
    formLayout->addRow(QString::fromUtf8("To Address:"), recipientEdit);

    // Address validation label
    addressValidationLabel = new QLabel(this);
    formLayout->addRow("", addressValidationLabel);

    // Amount
    QHBoxLayout *amountLayout = new QHBoxLayout();
    amountSpinBox = new QDoubleSpinBox(this);
    amountSpinBox->setRange(0.000001, 1000000.0);
    amountSpinBox->setDecimals(6);
    amountSpinBox->setSuffix(" CELL");
    amountSpinBox->setValue(0.001);
    amountLayout->addWidget(amountSpinBox);

    maxAmountButton = new QPushButton(QString::fromUtf8("MAX"), this);
    maxAmountButton->setMaximumWidth(60);
    connect(maxAmountButton, &QPushButton::clicked, this, &SendTokensDialog::onMaxAmountClicked);
    amountLayout->addWidget(maxAmountButton);

    QWidget *amountWidget = new QWidget(this);
    amountWidget->setLayout(amountLayout);
    formLayout->addRow(QString::fromUtf8("Amount:"), amountWidget);

    // Fee
    feeSpinBox = new QDoubleSpinBox(this);
    feeSpinBox->setRange(0.001, 10.0);
    feeSpinBox->setDecimals(3);
    feeSpinBox->setSuffix(" CELL");
    feeSpinBox->setValue(0.01);
    formLayout->addRow(QString::fromUtf8("Validator Fee:"), feeSpinBox);

    // Network fee address
    networkFeeAddressEdit = new QLineEdit(this);
    networkFeeAddressEdit->setText(DEFAULT_NETWORK_FEE_ADDR);
    networkFeeAddressEdit->setToolTip(QString::fromUtf8("Network fee collector address (0.002 CELL)"));
    formLayout->addRow(QString::fromUtf8("Network Fee To:"), networkFeeAddressEdit);

    // Custom data (TSD)
    tsdCheckBox = new QCheckBox(QString::fromUtf8("Add Custom Message (TSD)"), this);
    connect(tsdCheckBox, &QCheckBox::toggled, this, &SendTokensDialog::onTsdToggled);
    formLayout->addRow("", tsdCheckBox);

    tsdDataEdit = new QLineEdit(this);
    tsdDataEdit->setPlaceholderText(QString::fromUtf8("Enter custom message (e.g., 'noob trader')"));
    tsdDataEdit->setEnabled(false);
    tsdDataEdit->setMaxLength(256);
    formLayout->addRow(QString::fromUtf8("Message:"), tsdDataEdit);

    mainLayout->addLayout(formLayout);

    // Status label
    statusLabel = new QLabel(this);
    statusLabel->setWordWrap(true);
    statusLabel->setStyleSheet("padding: 10px; background-color: #1a1a1a; border-radius: 5px;");
    mainLayout->addWidget(statusLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    cancelButton = new QPushButton(QString::fromUtf8("Cancel"), this);
    connect(cancelButton, &QPushButton::clicked, this, &SendTokensDialog::onCancelClicked);
    buttonLayout->addWidget(cancelButton);

    sendButton = new QPushButton(QString::fromUtf8("💸 Send Tokens"), this);
    sendButton->setStyleSheet("QPushButton { background-color: #00D9FF; color: black; font-weight: bold; padding: 10px; }");
    connect(sendButton, &QPushButton::clicked, this, &SendTokensDialog::onSendClicked);
    buttonLayout->addWidget(sendButton);

    mainLayout->addLayout(buttonLayout);
}

void SendTokensDialog::onWalletChanged(int index) {
    selectedWalletIndex = index;
    updateAvailableBalance();
}

void SendTokensDialog::updateAvailableBalance() {
    if (!wallets || selectedWalletIndex < 0 || (size_t)selectedWalletIndex >= wallets->count) {
        balanceLabel->setText(QString::fromUtf8("Balance: 0.0 CELL"));
        availableBalance = 0.0;
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[selectedWalletIndex];

    // Get balance from RPC
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        balanceLabel->setText(QString::fromUtf8("Balance: Error"));
        return;
    }

    cellframe_rpc_response_t *response = nullptr;
    int ret = cellframe_rpc_get_utxo("Backbone", address, "CELL", &response);

    if (ret == 0 && response && response->result) {
        uint64_t total_datoshi = 0;

        if (json_object_is_type(response->result, json_type_array)) {
            int len = json_object_array_length(response->result);
            for (int i = 0; i < len; i++) {
                json_object *item = json_object_array_get_idx(response->result, i);
                json_object *value_obj = nullptr;

                if (json_object_object_get_ex(item, "value", &value_obj)) {
                    const char *value_str = json_object_get_string(value_obj);
                    if (value_str) {
                        total_datoshi += strtoull(value_str, nullptr, 10);
                    }
                }
            }
        }

        availableBalance = (double)total_datoshi / 1e18;
        balanceLabel->setText(QString::fromUtf8("Balance: %1 CELL").arg(availableBalance, 0, 'f', 6));
    } else {
        balanceLabel->setText(QString::fromUtf8("Balance: 0.0 CELL"));
        availableBalance = 0.0;
    }

    if (response) {
        cellframe_rpc_response_free(response);
    }
}

void SendTokensDialog::onMaxAmountClicked() {
    // Set max amount minus fees (validator fee + network fee)
    double fee = feeSpinBox->value();
    double networkFee = 0.002; // Fixed network fee
    double maxAmount = availableBalance - fee - networkFee;

    if (maxAmount > 0) {
        amountSpinBox->setValue(maxAmount);
    } else {
        QMessageBox::warning(this, "Insufficient Balance",
                           QString::fromUtf8("Not enough balance to cover fees.\n"
                                            "Available: %1 CELL\n"
                                            "Required fees: %2 CELL")
                           .arg(availableBalance, 0, 'f', 6)
                           .arg(fee + networkFee, 0, 'f', 3));
    }
}

void SendTokensDialog::onValidateAddress() {
    QString address = recipientEdit->text().trimmed();

    if (address.isEmpty()) {
        addressValidationLabel->clear();
        return;
    }

    // Basic validation
    if (address.length() < 50 || !address.startsWith("Rj7J7MiX2bWy8sNy")) {
        addressValidationLabel->setText(QString::fromUtf8("❌ Invalid address format"));
        addressValidationLabel->setStyleSheet("color: #FF4444;");
    } else {
        addressValidationLabel->setText(QString::fromUtf8("✓ Address format OK"));
        addressValidationLabel->setStyleSheet("color: #00FF00;");
    }
}

void SendTokensDialog::onTsdToggled(bool enabled) {
    tsdDataEdit->setEnabled(enabled);
}

bool SendTokensDialog::validateInputs() {
    // Check wallet selection
    if (selectedWalletIndex < 0) {
        QMessageBox::warning(this, "No Wallet", "Please select a wallet.");
        return false;
    }

    // Check recipient address
    QString recipient = recipientEdit->text().trimmed();
    if (recipient.isEmpty()) {
        QMessageBox::warning(this, "No Recipient", "Please enter a recipient address.");
        return false;
    }

    // Check amount
    double amount = amountSpinBox->value();
    if (amount <= 0) {
        QMessageBox::warning(this, "Invalid Amount", "Amount must be greater than 0.");
        return false;
    }

    // Check balance
    double fee = feeSpinBox->value();
    double networkFee = 0.002;
    double total = amount + fee + networkFee;

    if (total > availableBalance) {
        QMessageBox::warning(this, "Insufficient Balance",
                           QString::fromUtf8("Insufficient balance.\n\n"
                                            "Required: %1 CELL\n"
                                            "Available: %2 CELL")
                           .arg(total, 0, 'f', 6)
                           .arg(availableBalance, 0, 'f', 6));
        return false;
    }

    return true;
}

void SendTokensDialog::onSendClicked() {
    if (!validateInputs()) {
        return;
    }

    // Confirm transaction
    QString recipient = recipientEdit->text().trimmed();
    double amount = amountSpinBox->value();
    double fee = feeSpinBox->value();
    QString tsdData = tsdCheckBox->isChecked() ? tsdDataEdit->text() : "";

    QString confirmMsg = QString::fromUtf8("Confirm Transaction:\n\n"
                                          "To: %1\n"
                                          "Amount: %2 CELL\n"
                                          "Validator Fee: %3 CELL\n"
                                          "Network Fee: 0.002 CELL\n"
                                          "Total: %4 CELL")
                        .arg(recipient.left(20) + "...")
                        .arg(amount, 0, 'f', 6)
                        .arg(fee, 0, 'f', 3)
                        .arg(amount + fee + 0.002, 0, 'f', 6);

    if (!tsdData.isEmpty()) {
        confirmMsg += QString::fromUtf8("\nMessage: \"%1\"").arg(tsdData);
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm Send", confirmMsg,
                                                              QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    buildAndSendTransaction();
}

void SendTokensDialog::buildAndSendTransaction() {
    statusLabel->setText(QString::fromUtf8("🔄 Building transaction..."));
    QApplication::processEvents();

    // This is a simplified version - in production, this should be done in a worker thread
    // For now, we'll call the backend directly

    QMessageBox::information(this, "Transaction Sent",
                           QString::fromUtf8("🚧 Transaction builder integration in progress!\n\n"
                                            "The backend is ready (cellframe_tx_builder_minimal),\n"
                                            "but needs to be properly wrapped for Qt GUI.\n\n"
                                            "Coming in next iteration!"));

    // TODO: Integrate actual transaction building:
    // 1. Load wallet keys
    // 2. Query UTXOs
    // 3. Build transaction using cellframe_tx_builder_minimal
    // 4. Sign with cellframe_sign_minimal
    // 5. Convert to JSON
    // 6. Submit via cellframe_rpc_submit_tx
    // 7. Show result with transaction hash

    statusLabel->clear();
}

void SendTokensDialog::onCancelClicked() {
    reject();
}
