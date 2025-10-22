/*
 * SendTokensDialog.cpp - cpunk Wallet Send Widget Implementation
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

// Network fee constants
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"
#define NETWORK_FEE_DATOSHI 2000000000000000ULL  // 0.002 CELL
// TSD_TYPE_CUSTOM_STRING is defined in cellframe_minimal.h (0x0001)

// UTXO structure for transaction building
typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} utxo_t;

SendTokensDialog::SendTokensDialog(wallet_list_t *wallets, QWidget *parent)
    : QWidget(parent),
      wallets(wallets),
      selectedWalletIndex(-1),
      availableBalance(0.0) {

    printf("[DEBUG] SendTokensDialog constructor called with %zu wallets\n", wallets ? wallets->count : 0);

    setupUI();

    // Don't query UTXOs on load - just update balance display from wallet list
    if (wallets && wallets->count > 0) {
        selectedWalletIndex = 0;
        updateBalanceFromWalletList();
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
    networkFeeAddressEdit->setText(NETWORK_FEE_COLLECTOR);
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

    // Send button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    sendButton = new QPushButton(QString::fromUtf8("💸 Send Tokens"), this);
    sendButton->setStyleSheet("QPushButton { background-color: #00D9FF; color: black; font-weight: bold; padding: 10px; }");
    connect(sendButton, &QPushButton::clicked, this, &SendTokensDialog::onSendClicked);
    buttonLayout->addWidget(sendButton);

    mainLayout->addLayout(buttonLayout);

    printf("[DEBUG] SendTokensDialog::setupUI() completed\n");
}

void SendTokensDialog::onWalletChanged(int index) {
    selectedWalletIndex = index;
    // Just update balance display from wallet list - don't query UTXOs yet
    updateBalanceFromWalletList();
}

void SendTokensDialog::updateBalanceFromWalletList() {
    if (!wallets || selectedWalletIndex < 0 || (size_t)selectedWalletIndex >= wallets->count) {
        balanceLabel->setText(QString::fromUtf8("Balance: ---"));
        availableBalance = 0.0;
        return;
    }

    // Don't query balance on load - will be checked when Send is clicked
    balanceLabel->setText(QString::fromUtf8("Balance: Click Send to verify"));
    availableBalance = 0.0;
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

    // Balance check will happen in buildAndSendTransaction() after querying UTXOs
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
    printf("[DEBUG] ========== Send Button Clicked - Starting Transaction Flow ==========\n");

    statusLabel->setText(QString::fromUtf8("🔄 Step 1/5: Querying UTXOs..."));
    QApplication::processEvents();

    cellframe_wallet_t *wallet = &wallets->wallets[selectedWalletIndex];
    char address[WALLET_ADDRESS_MAX];

    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to get wallet address"));
        return;
    }

    // STEP 1: Query UTXOs (only happens when user clicks Send)
    printf("[DEBUG] Step 1: Querying UTXOs for address: %s\n", address);

    cellframe_rpc_response_t *response = nullptr;
    int ret = cellframe_rpc_get_utxo("Backbone", address, "CELL", &response);

    if (ret != 0 || !response || !response->result) {
        printf("[DEBUG] Failed to query UTXOs\n");
        statusLabel->setText(QString::fromUtf8("❌ Failed to query UTXOs"));
        if (response) cellframe_rpc_response_free(response);
        return;
    }

    const char *utxo_str = json_object_to_json_string_ext(response->result, JSON_C_TO_STRING_PRETTY);
    printf("[DEBUG] UTXO Response:\n%s\n", utxo_str);

    // Parse UTXOs from response
    // Response format: [ [ { wallet_addr, total_value_coins, outs: [...] } ] ]

    utxo_t *selected_utxos = nullptr;
    int num_selected_utxos = 0;
    uint64_t total_input_u64 = 0;

    // Get transaction parameters
    double amount_d = amountSpinBox->value();
    double fee_d = feeSpinBox->value();

    // Convert to uint256_t (use fewer decimal places to avoid precision issues)
    uint256_t amount, fee;
    char amount_str[64], fee_str[64];
    snprintf(amount_str, sizeof(amount_str), "%.6f", amount_d);
    snprintf(fee_str, sizeof(fee_str), "%.3f", fee_d);

    printf("[DEBUG] Amount string: '%s' (from %.6f)\n", amount_str, amount_d);
    printf("[DEBUG] Fee string: '%s' (from %.3f)\n", fee_str, fee_d);

    if (cellframe_uint256_from_str(amount_str, &amount) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to parse amount"));
        QMessageBox::warning(this, "Parse Error", "Failed to parse amount value.");
        cellframe_rpc_response_free(response);
        return;
    }

    if (cellframe_uint256_from_str(fee_str, &fee) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to parse fee"));
        QMessageBox::warning(this, "Parse Error", "Failed to parse fee value.");
        cellframe_rpc_response_free(response);
        return;
    }

    printf("[DEBUG] Parsed amount: %lu datoshi (%.6f CELL)\n", amount.lo.lo, amount.lo.lo / 1e18);
    printf("[DEBUG] Parsed fee: %lu datoshi (%.3f CELL)\n", fee.lo.lo, fee.lo.lo / 1e18);

    // Calculate required amount
    uint64_t required_u64 = amount.lo.lo + NETWORK_FEE_DATOSHI + fee.lo.lo;

    // Parse UTXO response
    if (json_object_is_type(response->result, json_type_array) &&
        json_object_array_length(response->result) > 0) {

        json_object *first_array = json_object_array_get_idx(response->result, 0);
        if (first_array && json_object_is_type(first_array, json_type_array) &&
            json_object_array_length(first_array) > 0) {

            json_object *first_item = json_object_array_get_idx(first_array, 0);
            json_object *outs_obj = nullptr;

            if (first_item && json_object_object_get_ex(first_item, "outs", &outs_obj) &&
                json_object_is_type(outs_obj, json_type_array)) {

                int num_utxos = json_object_array_length(outs_obj);
                if (num_utxos == 0) {
                    statusLabel->setText(QString::fromUtf8("❌ No UTXOs available"));
                    QMessageBox::warning(this, "No UTXOs", "No UTXOs available for this wallet.");
                    cellframe_rpc_response_free(response);
                    return;
                }

                printf("[DEBUG] Found %d UTXO%s\n", num_utxos, num_utxos > 1 ? "s" : "");

                // Parse all UTXOs
                utxo_t *all_utxos = (utxo_t*)malloc(sizeof(utxo_t) * num_utxos);
                int valid_utxos = 0;

                for (int i = 0; i < num_utxos; i++) {
                    json_object *utxo_obj = json_object_array_get_idx(outs_obj, i);
                    json_object *jhash = nullptr, *jidx = nullptr, *jvalue = nullptr;

                    if (utxo_obj &&
                        json_object_object_get_ex(utxo_obj, "prev_hash", &jhash) &&
                        json_object_object_get_ex(utxo_obj, "out_prev_idx", &jidx) &&
                        json_object_object_get_ex(utxo_obj, "value_datoshi", &jvalue)) {

                        const char *hash_str = json_object_get_string(jhash);
                        const char *value_str = json_object_get_string(jvalue);

                        // Parse hash (hex string to binary)
                        if (hash_str && strlen(hash_str) >= 66 && hash_str[0] == '0' && hash_str[1] == 'x') {
                            for (int j = 0; j < 32; j++) {
                                sscanf(hash_str + 2 + (j * 2), "%2hhx", &all_utxos[valid_utxos].hash.raw[j]);
                            }
                            all_utxos[valid_utxos].idx = json_object_get_int(jidx);
                            cellframe_uint256_from_str(value_str, &all_utxos[valid_utxos].value);
                            valid_utxos++;
                        }
                    }
                }

                if (valid_utxos == 0) {
                    statusLabel->setText(QString::fromUtf8("❌ No valid UTXOs found"));
                    QMessageBox::warning(this, "No Valid UTXOs", "No valid UTXOs found.");
                    free(all_utxos);
                    cellframe_rpc_response_free(response);
                    return;
                }

                // Select UTXOs (greedy selection)
                selected_utxos = (utxo_t*)malloc(sizeof(utxo_t) * valid_utxos);
                for (int i = 0; i < valid_utxos; i++) {
                    selected_utxos[num_selected_utxos++] = all_utxos[i];
                    total_input_u64 += all_utxos[i].value.lo.lo;

                    if (total_input_u64 >= required_u64) {
                        break;  // Have enough
                    }
                }

                free(all_utxos);

                // Check if we have enough
                if (total_input_u64 < required_u64) {
                    statusLabel->setText(QString::fromUtf8("❌ Insufficient funds"));
                    QMessageBox::warning(this, "Insufficient Funds",
                                       QString::fromUtf8("Insufficient funds.\n\n"
                                                        "Available: %1 CELL\n"
                                                        "Required: %2 CELL")
                                       .arg((double)total_input_u64 / 1e18, 0, 'f', 6)
                                       .arg((double)required_u64 / 1e18, 0, 'f', 6));
                    free(selected_utxos);
                    cellframe_rpc_response_free(response);
                    return;
                }

                printf("[DEBUG] Selected %d UTXO%s (total: %lu datoshi)\n",
                       num_selected_utxos, num_selected_utxos > 1 ? "s" : "", total_input_u64);
            } else {
                statusLabel->setText(QString::fromUtf8("❌ Invalid UTXO response format"));
                cellframe_rpc_response_free(response);
                return;
            }
        } else {
            statusLabel->setText(QString::fromUtf8("❌ Invalid UTXO response structure"));
            cellframe_rpc_response_free(response);
            return;
        }
    } else {
        statusLabel->setText(QString::fromUtf8("❌ Invalid UTXO response"));
        cellframe_rpc_response_free(response);
        return;
    }

    cellframe_rpc_response_free(response);

    // STEP 2: Build transaction
    statusLabel->setText(QString::fromUtf8("🔄 Step 2/6: Building transaction..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 2: Building transaction\n");

    cellframe_tx_builder_t *builder = cellframe_tx_builder_new();
    if (!builder) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to create transaction builder"));
        free(selected_utxos);
        return;
    }

    // Set timestamp
    uint64_t ts = (uint64_t)time(nullptr);
    cellframe_tx_set_timestamp(builder, ts);
    printf("[DEBUG] Timestamp: %lu\n", ts);

    // Parse addresses from Base58
    QString recipient = recipientEdit->text().trimmed();
    QString tsdData = tsdCheckBox->isChecked() ? tsdDataEdit->text() : "";

    cellframe_addr_t recipient_addr, network_collector_addr, sender_addr;

    size_t decoded_size = base58_decode(recipient.toUtf8().constData(), &recipient_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        statusLabel->setText(QString::fromUtf8("❌ Invalid recipient address"));
        QMessageBox::warning(this, "Invalid Address", "Failed to decode recipient address.");
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    decoded_size = base58_decode(NETWORK_FEE_COLLECTOR, &network_collector_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        statusLabel->setText(QString::fromUtf8("❌ Invalid network collector address"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    decoded_size = base58_decode(address, &sender_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        statusLabel->setText(QString::fromUtf8("❌ Invalid sender address"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Calculate change
    uint64_t change_u64 = total_input_u64 - amount.lo.lo - NETWORK_FEE_DATOSHI - fee.lo.lo;
    uint256_t change = {0};
    change.lo.lo = change_u64;
    uint256_t network_fee = {0};
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    printf("[DEBUG] Transaction breakdown:\n");
    printf("  Total input:     %lu datoshi\n", total_input_u64);
    printf("  - Recipient:     %lu datoshi\n", amount.lo.lo);
    printf("  - Network fee:   %lu datoshi\n", NETWORK_FEE_DATOSHI);
    printf("  - Validator fee: %lu datoshi\n", fee.lo.lo);
    printf("  = Change:        %lu datoshi\n", change_u64);

    // Add all IN items
    for (int i = 0; i < num_selected_utxos; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            statusLabel->setText(QString::fromUtf8("❌ Failed to add IN item"));
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add OUT items
    if (cellframe_tx_add_out(builder, &recipient_addr, amount) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add recipient OUT"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    if (cellframe_tx_add_out(builder, &network_collector_addr, network_fee) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add network fee OUT"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add change output (if any)
    int has_change = (change.hi.hi != 0 || change.hi.lo != 0 || change.lo.hi != 0 || change.lo.lo != 0);
    if (has_change) {
        if (cellframe_tx_add_out(builder, &sender_addr, change) != 0) {
            statusLabel->setText(QString::fromUtf8("❌ Failed to add change OUT"));
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add TSD (if any)
    int has_tsd = 0;
    if (!tsdData.isEmpty()) {
        QByteArray tsd_bytes = tsdData.toUtf8();
        if (cellframe_tx_add_tsd(builder, TSD_TYPE_CUSTOM_STRING,
                                 (const uint8_t*)tsd_bytes.constData(), tsd_bytes.size()) != 0) {
            statusLabel->setText(QString::fromUtf8("❌ Failed to add TSD"));
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
        has_tsd = 1;
    }

    // Add validator fee
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add validator fee"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    printf("[DEBUG] Transaction items: %d IN + %d OUT + 1 FEE%s\n",
           num_selected_utxos, 2 + has_change, has_tsd ? " + 1 TSD" : "");

    free(selected_utxos);  // No longer needed

    // STEP 3: Sign transaction
    statusLabel->setText(QString::fromUtf8("🔄 Step 3/6: Signing transaction..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 3: Signing transaction\n");

    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to get transaction data"));
        cellframe_tx_builder_free(builder);
        return;
    }

    printf("[DEBUG] Transaction size: %zu bytes\n", tx_size);

    // Verify tx_items_size is 0 (critical for signature verification)
    // Structure: uint16_t version (0-1), uint64_t timestamp (2-9), uint32_t tx_items_size (10-13)
    if (tx_size >= 14) {
        uint32_t tx_items_size_in_data = *(uint32_t*)(tx_data + 10);
        printf("[DEBUG] tx_items_size in signing data: %u (MUST be 0)\n", tx_items_size_in_data);
        if (tx_items_size_in_data != 0) {
            printf("[ERROR] tx_items_size is NOT zero! This will cause signature verification to fail!\n");
        }
    }

    uint8_t *dap_sign = nullptr;
    size_t dap_sign_size = 0;
    if (cellframe_sign_transaction(tx_data, tx_size,
                                    wallet->private_key, wallet->private_key_size,
                                    wallet->public_key, wallet->public_key_size,
                                    &dap_sign, &dap_sign_size) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to sign transaction"));
        free((void*)tx_data);
        cellframe_tx_builder_free(builder);
        return;
    }

    free((void*)tx_data);  // Free temporary signing data

    printf("[DEBUG] Signature size: %zu bytes\n", dap_sign_size);

    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add signature"));
        free(dap_sign);
        cellframe_tx_builder_free(builder);
        return;
    }
    free(dap_sign);

    // STEP 4: Convert to JSON
    statusLabel->setText(QString::fromUtf8("🔄 Step 4/6: Converting to JSON..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 4: Converting to JSON\n");

    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to get signed transaction"));
        cellframe_tx_builder_free(builder);
        return;
    }

    char *json = nullptr;
    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to convert to JSON"));
        cellframe_tx_builder_free(builder);
        return;
    }

    printf("[DEBUG] JSON size: %zu bytes\n", strlen(json));
    printf("[DEBUG] JSON:\n%s\n", json);

    // STEP 5: Submit to network
    statusLabel->setText(QString::fromUtf8("🔄 Step 5/6: Submitting to network..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 5: Submitting to network\n");

    cellframe_rpc_response_t *submit_resp = nullptr;
    if (cellframe_rpc_submit_tx("Backbone", "main", json, &submit_resp) != 0 || !submit_resp) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to submit transaction"));
        QMessageBox::warning(this, "Submission Failed", "Failed to submit transaction to network.");
        free(json);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Extract transaction hash
    QString txHash = "N/A";
    if (submit_resp->result) {
        const char *result_str = json_object_to_json_string_ext(submit_resp->result, JSON_C_TO_STRING_PRETTY);
        printf("[DEBUG] RPC Response:\n%s\n", result_str);

        json_object *jhash = nullptr;
        if (json_object_object_get_ex(submit_resp->result, "hash", &jhash)) {
            const char *hash_str = json_object_get_string(jhash);
            if (hash_str) {
                txHash = QString::fromUtf8(hash_str);
            }
        }
    }

    cellframe_rpc_response_free(submit_resp);
    free(json);
    cellframe_tx_builder_free(builder);

    // Success!
    statusLabel->setText(QString::fromUtf8("✅ Transaction submitted successfully!"));

    QString explorerUrl = QString("https://scan.cellframe.net/datum-details/%1?net=Backbone").arg(txHash);

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Transaction Sent!");
    msgBox.setText(QString::fromUtf8("✅ Transaction submitted successfully!\n\n"
                                     "Transaction Hash:\n%1\n\n"
                                     "Amount: %2 CELL\n"
                                     "To: %3")
                   .arg(txHash)
                   .arg(amount_d, 0, 'f', 6)
                   .arg(recipient.left(20) + "..."));
    msgBox.setInformativeText(QString::fromUtf8("View on blockchain explorer?"));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::Yes);

    if (msgBox.exec() == QMessageBox::Yes) {
        QDesktopServices::openUrl(QUrl(explorerUrl));
    }

    printf("[DEBUG] ========== Transaction Flow Complete ==========\n");
}

void SendTokensDialog::updateWalletList(wallet_list_t *newWallets) {
    wallets = newWallets;

    // Clear and repopulate wallet combo box
    walletComboBox->clear();
    selectedWalletIndex = -1;
    availableBalance = 0.0;

    if (wallets && wallets->count > 0) {
        for (size_t i = 0; i < wallets->count; i++) {
            QString walletName = QString::fromUtf8(wallets->wallets[i].name);
            walletComboBox->addItem(QString::fromUtf8("💼 %1").arg(walletName));
        }

        // Select first wallet (will trigger onWalletChanged via signal)
        walletComboBox->setCurrentIndex(0);
    } else {
        balanceLabel->setText(QString::fromUtf8("No wallets found"));
    }
}
