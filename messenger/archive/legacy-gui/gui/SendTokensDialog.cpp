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
#include <QLabel>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
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

SendTokensDialog::SendTokensDialog(const cellframe_wallet_t *wallet, QWidget *parent)
    : QWidget(parent),
      availableBalance(0.0),
      currentTheme(THEME_CPUNK_IO) {

    if (wallet) {
        memcpy(&m_wallet, wallet, sizeof(cellframe_wallet_t));
    } else {
        memset(&m_wallet, 0, sizeof(cellframe_wallet_t));
    }

    // Get current theme from ThemeManager
    currentTheme = ThemeManager::instance()->currentTheme();

    // Apply theme
    applyTheme(currentTheme);

    // Connect to theme changes
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &SendTokensDialog::onThemeChanged);

    setupUI();
    updateBalance();
}

SendTokensDialog::~SendTokensDialog() {
}

void SendTokensDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Form layout for inputs
    QFormLayout *formLayout = new QFormLayout();

    // Wallet name label (read-only, already in this wallet)
    walletNameLabel = new QLabel(QString::fromUtf8("💼 %1").arg(m_wallet.name), this);
    QFont walletFont;
    walletFont.setPointSize(14);
    walletFont.setBold(true);
    walletNameLabel->setFont(walletFont);
    walletNameLabel->setStyleSheet("color: #00D9FF; padding: 10px;");
    formLayout->addRow(QString::fromUtf8("From Wallet:"), walletNameLabel);

    // Balance label
    balanceLabel = new QLabel(QString::fromUtf8("Balance: 0.0 CELL"), this);
    balanceLabel->setStyleSheet("font-weight: bold;");
    formLayout->addRow(QString::fromUtf8("Available:"), balanceLabel);

    // Recipient address
    recipientEdit = new QLineEdit(this);
    recipientEdit->setPlaceholderText(QString::fromUtf8("Rj7J7MiX2bWy8sNy..."));
    connect(recipientEdit, &QLineEdit::textChanged, this, &SendTokensDialog::onValidateAddress);
    formLayout->addRow(QString::fromUtf8("To Address:"), recipientEdit);

    // Address validation label
    addressValidationLabel = new QLabel(this);
    formLayout->addRow("", addressValidationLabel);

    // Amount - Using QLineEdit to avoid double precision loss
    QHBoxLayout *amountLayout = new QHBoxLayout();
    amountEdit = new QLineEdit(this);
    amountEdit->setPlaceholderText(QString::fromUtf8("0.001"));
    amountEdit->setText("0.001");
    // Validator: allow decimal numbers with up to 18 decimal places
    QRegularExpression amountRegex("^[0-9]+\\.?[0-9]{0,18}$|^\\.[0-9]{1,18}$");
    QRegularExpressionValidator *amountValidator = new QRegularExpressionValidator(amountRegex, this);
    amountEdit->setValidator(amountValidator);
    amountLayout->addWidget(amountEdit);

    QLabel *amountUnitLabel = new QLabel(QString::fromUtf8("CELL"), this);
    amountLayout->addWidget(amountUnitLabel);

    maxAmountButton = new QPushButton(QString::fromUtf8("MAX"), this);
    maxAmountButton->setMaximumWidth(60);
    connect(maxAmountButton, &QPushButton::clicked, this, &SendTokensDialog::onMaxAmountClicked);
    amountLayout->addWidget(maxAmountButton);

    QWidget *amountWidget = new QWidget(this);
    amountWidget->setLayout(amountLayout);
    formLayout->addRow(QString::fromUtf8("Amount:"), amountWidget);

    // Fee - Using QLineEdit to avoid double precision loss
    QHBoxLayout *feeLayout = new QHBoxLayout();
    feeEdit = new QLineEdit(this);
    feeEdit->setPlaceholderText(QString::fromUtf8("0.01"));
    feeEdit->setText("0.01");
    // Validator: allow decimal numbers with up to 18 decimal places
    QRegularExpression feeRegex("^[0-9]+\\.?[0-9]{0,18}$|^\\.[0-9]{1,18}$");
    QRegularExpressionValidator *feeValidator = new QRegularExpressionValidator(feeRegex, this);
    feeEdit->setValidator(feeValidator);
    feeLayout->addWidget(feeEdit);

    QLabel *feeUnitLabel = new QLabel(QString::fromUtf8("CELL"), this);
    feeLayout->addWidget(feeUnitLabel);

    QWidget *feeWidget = new QWidget(this);
    feeWidget->setLayout(feeLayout);
    formLayout->addRow(QString::fromUtf8("Validator Fee:"), feeWidget);

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
    statusLabel->setStyleSheet("padding: 10px; border: 1px solid rgba(0, 217, 255, 0.3); border-radius: 5px;");
    mainLayout->addWidget(statusLabel);

    // Send button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    sendButton = new QPushButton(QString::fromUtf8("💸 Send Tokens"), this);
    connect(sendButton, &QPushButton::clicked, this, &SendTokensDialog::onSendClicked);
    buttonLayout->addWidget(sendButton);

    mainLayout->addLayout(buttonLayout);

    printf("[DEBUG] SendTokensDialog::setupUI() completed\n");
}

void SendTokensDialog::updateBalance() {
    // Don't query balance on load - will be checked when Send is clicked
    balanceLabel->setText(QString::fromUtf8("Balance: Click Send to verify"));
    availableBalance = 0.0;
}

void SendTokensDialog::applyTheme(CpunkTheme theme) {
    currentTheme = theme;
    setStyleSheet(getCpunkStyleSheet(theme));
}

void SendTokensDialog::onThemeChanged(CpunkTheme theme) {
    applyTheme(theme);
}

void SendTokensDialog::onMaxAmountClicked() {
    // Set max amount minus fees (validator fee + network fee)
    QString feeStr = feeEdit->text().trimmed();
    double fee = feeStr.isEmpty() ? 0.01 : feeStr.toDouble();  // Default to 0.01 if empty
    double networkFee = 0.002; // Fixed network fee
    double maxAmount = availableBalance - fee - networkFee;

    if (maxAmount > 0) {
        // Format with appropriate precision and set as string
        amountEdit->setText(QString::number(maxAmount, 'f', 6));
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
        addressValidationLabel->setStyleSheet("");
        return;
    }

    // Basic validation
    if (address.length() < 50 || !address.startsWith("Rj7J7MiX2bWy8sNy")) {
        addressValidationLabel->setText(QString::fromUtf8("❌ Invalid address format"));
        addressValidationLabel->setStyleSheet("color: #FF6666; font-weight: bold;");
    } else {
        addressValidationLabel->setText(QString::fromUtf8("✓ Address format OK"));
        addressValidationLabel->setStyleSheet("color: #00FF88; font-weight: bold;");
    }
}

void SendTokensDialog::onTsdToggled(bool enabled) {
    tsdDataEdit->setEnabled(enabled);
}

bool SendTokensDialog::validateInputs() {
    // Check wallet is loaded
    if (m_wallet.name[0] == '\0') {
        QMessageBox::warning(this, "No Wallet", "No wallet loaded.");
        return false;
    }

    // Check recipient address
    QString recipient = recipientEdit->text().trimmed();
    if (recipient.isEmpty()) {
        QMessageBox::warning(this, "No Recipient", "Please enter a recipient address.");
        return false;
    }

    // Check amount - now using string input
    QString amountStr = amountEdit->text().trimmed();
    if (amountStr.isEmpty()) {
        QMessageBox::warning(this, "Invalid Amount", "Please enter an amount.");
        return false;
    }

    // Try to parse amount to verify it's valid
    double amount = amountStr.toDouble();
    if (amount <= 0) {
        QMessageBox::warning(this, "Invalid Amount", "Amount must be greater than 0.");
        return false;
    }

    // Check fee
    QString feeStr = feeEdit->text().trimmed();
    if (feeStr.isEmpty()) {
        QMessageBox::warning(this, "Invalid Fee", "Please enter a fee.");
        return false;
    }

    double fee = feeStr.toDouble();
    if (fee <= 0) {
        QMessageBox::warning(this, "Invalid Fee", "Fee must be greater than 0.");
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
    QString amountStr = amountEdit->text().trimmed();
    QString feeStr = feeEdit->text().trimmed();
    double amount = amountStr.toDouble();  // Only for display
    double fee = feeStr.toDouble();  // Only for display
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

    statusLabel->setText(QString::fromUtf8("🔄 Checking wallet..."));
    QApplication::processEvents();

    // Get wallet
    cellframe_wallet_t *wallet = &m_wallet;
    printf("[DEBUG] wallet pointer: %p\n", (void*)wallet);

    printf("[DEBUG] Wallet name: %s\n", wallet->name);
    printf("[DEBUG] Wallet status: %d (0=unprotected, 1=protected)\n", wallet->status);
    printf("[DEBUG] Wallet address field: '%s'\n", wallet->address);

    // Check if address is available
    if (wallet->address[0] == '\0') {
        statusLabel->setText(QString::fromUtf8("❌ Wallet address not available"));

        const char *error_msg;
        if (wallet->status == WALLET_STATUS_PROTECTED) {
            error_msg = "This wallet is password-protected.\n\n"
                       "Protected wallets cannot be used for sending.\n"
                       "Please use an unprotected wallet.";
        } else {
            error_msg = "Could not generate address for this wallet.\n\n"
                       "The wallet file may be corrupted or in an unsupported format.\n"
                       "Please check the wallet file or create a new wallet.";
        }

        QMessageBox::warning(this, "Wallet Address Error", QString::fromUtf8(error_msg));
        return;
    }

    char address[WALLET_ADDRESS_MAX];
    strncpy(address, wallet->address, WALLET_ADDRESS_MAX - 1);
    address[WALLET_ADDRESS_MAX - 1] = '\0';

    printf("[DEBUG] Using wallet address: %s\n", address);

    statusLabel->setText(QString::fromUtf8("🔄 Querying UTXOs..."));
    QApplication::processEvents();

    // Get parameters
    QString recipient = recipientEdit->text().trimmed();
    QString amountQStr = amountEdit->text().trimmed();
    QString feeQStr = feeEdit->text().trimmed();
    QString tsdData = tsdCheckBox->isChecked() ? tsdDataEdit->text() : "";

    // Convert to C strings
    QByteArray amountBytes = amountQStr.toUtf8();
    QByteArray feeBytes = feeQStr.toUtf8();
    const char *amount_str = amountBytes.constData();
    const char *fee_str = feeBytes.constData();

    printf("[DEBUG] Amount string: '%s'\n", amount_str);
    printf("[DEBUG] Fee string: '%s'\n", fee_str);

    // Parse amounts (EXACT COPY FROM CLI)
    uint256_t amount, fee;
    if (cellframe_uint256_from_str(amount_str, &amount) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to parse amount"));
        QMessageBox::warning(this, "Parse Error", "Failed to parse amount");
        return;
    }

    if (cellframe_uint256_from_str(fee_str, &fee) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to parse fee"));
        QMessageBox::warning(this, "Parse Error", "Failed to parse fee");
        return;
    }

    printf("[DEBUG] Parsed amount: %llu datoshi\n", (unsigned long long)amount.lo.lo);
    printf("[DEBUG] Parsed fee: %llu datoshi\n", (unsigned long long)fee.lo.lo);

    // STEP 1: Query UTXOs (EXACT COPY FROM CLI)
    utxo_t *selected_utxos = NULL;
    int num_selected_utxos = 0;
    uint64_t total_input_u64 = 0;

    uint64_t required_u64 = amount.lo.lo + NETWORK_FEE_DATOSHI + fee.lo.lo;

    cellframe_rpc_response_t *utxo_resp = NULL;
    if (cellframe_rpc_get_utxo("Backbone", address, "CELL", &utxo_resp) == 0 && utxo_resp) {
        if (utxo_resp->result) {
            // Parse UTXO response: result[0][0]["outs"][]
            if (json_object_is_type(utxo_resp->result, json_type_array) &&
                json_object_array_length(utxo_resp->result) > 0) {

                json_object *first_array = json_object_array_get_idx(utxo_resp->result, 0);
                if (first_array && json_object_is_type(first_array, json_type_array) &&
                    json_object_array_length(first_array) > 0) {

                    json_object *first_item = json_object_array_get_idx(first_array, 0);
                    json_object *outs_obj = NULL;

                    if (first_item && json_object_object_get_ex(first_item, "outs", &outs_obj) &&
                        json_object_is_type(outs_obj, json_type_array)) {

                        int num_utxos = json_object_array_length(outs_obj);
                        if (num_utxos == 0) {
                            statusLabel->setText(QString::fromUtf8("❌ No UTXOs available"));
                            QMessageBox::warning(this, "No UTXOs", "No UTXOs available");
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        printf("[DEBUG] Found %d UTXO%s\n", num_utxos, num_utxos > 1 ? "s" : "");

                        // Parse all UTXOs
                        utxo_t *all_utxos = (utxo_t*)malloc(sizeof(utxo_t) * num_utxos);
                        int valid_utxos = 0;

                        for (int i = 0; i < num_utxos; i++) {
                            json_object *utxo_obj = json_object_array_get_idx(outs_obj, i);
                            json_object *jhash = NULL, *jidx = NULL, *jvalue = NULL;

                            if (utxo_obj &&
                                json_object_object_get_ex(utxo_obj, "prev_hash", &jhash) &&
                                json_object_object_get_ex(utxo_obj, "out_prev_idx", &jidx) &&
                                json_object_object_get_ex(utxo_obj, "value_datoshi", &jvalue)) {

                                const char *hash_str = json_object_get_string(jhash);
                                const char *value_str = json_object_get_string(jvalue);

                                // Parse hash
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
                            statusLabel->setText(QString::fromUtf8("❌ No valid UTXOs"));
                            QMessageBox::warning(this, "Error", "No valid UTXOs found");
                            free(all_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        // Select UTXOs (greedy selection)
                        selected_utxos = (utxo_t*)malloc(sizeof(utxo_t) * valid_utxos);
                        for (int i = 0; i < valid_utxos; i++) {
                            selected_utxos[num_selected_utxos++] = all_utxos[i];
                            total_input_u64 += all_utxos[i].value.lo.lo;

                            if (total_input_u64 >= required_u64) {
                                break;
                            }
                        }

                        free(all_utxos);

                        // Check if we have enough
                        if (total_input_u64 < required_u64) {
                            statusLabel->setText(QString::fromUtf8("❌ Insufficient funds"));
                            QMessageBox::warning(this, "Insufficient Funds",
                                               QString("Need: %1 CELL\nHave: %2 CELL")
                                               .arg((double)required_u64 / 1e18, 0, 'f', 6)
                                               .arg((double)total_input_u64 / 1e18, 0, 'f', 6));
                            free(selected_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        printf("[DEBUG] Selected %d UTXO (total: %llu datoshi)\n", num_selected_utxos, (unsigned long long)total_input_u64);

                    } else {
                        statusLabel->setText(QString::fromUtf8("❌ Invalid UTXO response"));
                        cellframe_rpc_response_free(utxo_resp);
                        return;
                    }
                } else {
                    statusLabel->setText(QString::fromUtf8("❌ Invalid UTXO response"));
                    cellframe_rpc_response_free(utxo_resp);
                    return;
                }
            } else {
                statusLabel->setText(QString::fromUtf8("❌ Invalid UTXO response"));
                cellframe_rpc_response_free(utxo_resp);
                return;
            }
        }
        cellframe_rpc_response_free(utxo_resp);
    } else {
        statusLabel->setText(QString::fromUtf8("❌ Failed to query UTXOs"));
        QMessageBox::warning(this, "Error", "Failed to query UTXOs from RPC");
        return;
    }

    // STEP 2: Build transaction (EXACT COPY FROM CLI)
    statusLabel->setText(QString::fromUtf8("🔄 Building transaction..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 2: Building transaction\n");

    cellframe_tx_builder_t *builder = cellframe_tx_builder_new();
    if (!builder) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to create builder"));
        free(selected_utxos);
        return;
    }

    // Set timestamp
    uint64_t ts = (uint64_t)time(NULL);
    cellframe_tx_set_timestamp(builder, ts);
    printf("[DEBUG] Timestamp: %lu\n", ts);

    // Parse recipient address from Base58
    cellframe_addr_t recipient_addr;
    size_t decoded_size = base58_decode(recipient.toUtf8().constData(), &recipient_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        statusLabel->setText(QString::fromUtf8("❌ Invalid recipient address"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Parse network collector address
    cellframe_addr_t network_collector_addr;
    decoded_size = base58_decode(NETWORK_FEE_COLLECTOR, &network_collector_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        statusLabel->setText(QString::fromUtf8("❌ Invalid network collector address"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Parse sender address (for change)
    cellframe_addr_t sender_addr;
    decoded_size = base58_decode(address, &sender_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        statusLabel->setText(QString::fromUtf8("❌ Invalid sender address"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Calculate network fee
    uint256_t network_fee = {0};
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    // Calculate change
    uint64_t change_u64 = total_input_u64 - amount.lo.lo - NETWORK_FEE_DATOSHI - fee.lo.lo;
    uint256_t change = {0};
    change.lo.lo = change_u64;

    printf("[DEBUG] Transaction breakdown:\n");
    printf("  Total input:     %llu datoshi\n", (unsigned long long)total_input_u64);
    printf("  - Recipient:     %llu datoshi\n", (unsigned long long)amount.lo.lo);
    printf("  - Network fee:   %llu datoshi\n", (unsigned long long)NETWORK_FEE_DATOSHI);
    printf("  - Validator fee: %llu datoshi\n", (unsigned long long)fee.lo.lo);
    printf("  = Change:        %llu datoshi\n", (unsigned long long)change_u64);

    // Add all IN items
    for (int i = 0; i < num_selected_utxos; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            statusLabel->setText(QString::fromUtf8("❌ Failed to add IN item"));
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add OUT item (recipient)
    if (cellframe_tx_add_out(builder, &recipient_addr, amount) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add recipient OUT"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add OUT item (network fee collector)
    if (cellframe_tx_add_out(builder, &network_collector_addr, network_fee) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add network fee OUT"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add OUT item (change) - only if change > 0
    int has_change = 0;
    if (change.hi.hi != 0 || change.hi.lo != 0 || change.lo.hi != 0 || change.lo.lo != 0) {
        if (cellframe_tx_add_out(builder, &sender_addr, change) != 0) {
            statusLabel->setText(QString::fromUtf8("❌ Failed to add change OUT"));
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
        has_change = 1;
    }

    // Add TSD item (optional) - BEFORE the fee
    int has_tsd = 0;
    if (!tsdData.isEmpty()) {
        QByteArray tsd_bytes = tsdData.toUtf8();
        size_t tsd_len = tsd_bytes.size();  // NO null terminator
        if (cellframe_tx_add_tsd(builder, TSD_TYPE_CUSTOM_STRING,
                                 (const uint8_t*)tsd_bytes.constData(), tsd_len) != 0) {
            statusLabel->setText(QString::fromUtf8("❌ Failed to add TSD"));
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
        has_tsd = 1;
    }

    // Add OUT_COND item (validator fee)
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add validator fee"));
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    printf("[DEBUG] Transaction items: %d IN + %d OUT + 1 FEE%s\n",
           num_selected_utxos, 2 + has_change, has_tsd ? " + 1 TSD" : "");

    // Free selected UTXOs
    free(selected_utxos);

    // STEP 3: Sign transaction (EXACT COPY FROM CLI)
    statusLabel->setText(QString::fromUtf8("🔄 Signing transaction..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 3: Signing transaction\n");

    // Get signing data (TEMPORARY COPY with tx_items_size = 0)
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to get transaction data"));
        cellframe_tx_builder_free(builder);
        return;
    }

    printf("[DEBUG] Transaction size: %zu bytes\n", tx_size);

    // Verify tx_items_size is 0
    if (tx_size >= 12) {
        uint32_t tx_items_size_in_data = *(uint32_t*)(tx_data + 8);
        printf("[DEBUG] tx_items_size in signing data: %u (MUST be 0)\n", tx_items_size_in_data);
    }

    // Sign transaction
    uint8_t *dap_sign = NULL;
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

    // Free temporary signing data
    free((void*)tx_data);

    printf("[DEBUG] Signature size: %zu bytes\n", dap_sign_size);

    // Add signature to transaction
    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to add signature"));
        free(dap_sign);
        cellframe_tx_builder_free(builder);
        return;
    }
    free(dap_sign);

    // STEP 4: Convert to JSON (EXACT COPY FROM CLI)
    statusLabel->setText(QString::fromUtf8("🔄 Converting to JSON..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 4: Converting to JSON\n");

    // Get complete signed transaction
    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to get signed transaction"));
        cellframe_tx_builder_free(builder);
        return;
    }

    // Convert to JSON
    char *json = NULL;
    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        statusLabel->setText(QString::fromUtf8("❌ Failed to convert to JSON"));
        cellframe_tx_builder_free(builder);
        return;
    }

    printf("[DEBUG] JSON size: %zu bytes\n", strlen(json));
    printf("[DEBUG] JSON:\n%s\n", json);

    // STEP 5: Submit to RPC (EXACT COPY FROM CLI)
    statusLabel->setText(QString::fromUtf8("🔄 Submitting to RPC..."));
    QApplication::processEvents();

    printf("[DEBUG] Step 5: Submitting to RPC\n");

    cellframe_rpc_response_t *submit_resp = NULL;
    if (cellframe_rpc_submit_tx("Backbone", "main", json, &submit_resp) == 0 && submit_resp) {
        printf("      Transaction submitted successfully!\n\n");

        QString txHash = "N/A";
        bool txCreated = false;

        if (submit_resp->result) {
            const char *result_str = json_object_to_json_string_ext(submit_resp->result, JSON_C_TO_STRING_PRETTY);
            printf("=== RPC RESPONSE ===\n%s\n====================\n\n", result_str);

            // Response format: [ { "tx_create": true, "hash": "0x...", "total_items": 7 } ]
            // Extract transaction hash from array response
            if (json_object_is_type(submit_resp->result, json_type_array) &&
                json_object_array_length(submit_resp->result) > 0) {

                json_object *first_elem = json_object_array_get_idx(submit_resp->result, 0);
                if (first_elem) {
                    // Check tx_create status
                    json_object *jtx_create = NULL;
                    if (json_object_object_get_ex(first_elem, "tx_create", &jtx_create)) {
                        txCreated = json_object_get_boolean(jtx_create);
                        printf("[DEBUG] tx_create: %s\n", txCreated ? "true" : "false");
                    }

                    // Extract hash
                    json_object *jhash = NULL;
                    if (json_object_object_get_ex(first_elem, "hash", &jhash)) {
                        const char *tx_hash = json_object_get_string(jhash);
                        if (tx_hash) {
                            txHash = QString::fromUtf8(tx_hash);
                            printf("[DEBUG] Extracted hash: %s\n", tx_hash);
                        }
                    }
                }
            }
        }

        cellframe_rpc_response_free(submit_resp);

        // Check if transaction was actually created
        if (!txCreated) {
            statusLabel->setText(QString::fromUtf8("❌ Transaction failed to create"));
            QMessageBox::warning(this, "Transaction Failed",
                               QString::fromUtf8("The transaction was submitted but failed to create.\n"
                                                "This may indicate insufficient balance or other network issues."));
            free(json);
            cellframe_tx_builder_free(builder);
            return;
        }

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
                       .arg(amountQStr)
                       .arg(recipient.left(20) + "..."));
        msgBox.setInformativeText(QString::fromUtf8("View on blockchain explorer?"));
        msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        msgBox.setDefaultButton(QMessageBox::Yes);

        if (msgBox.exec() == QMessageBox::Yes) {
            QDesktopServices::openUrl(QUrl(explorerUrl));
        }

    } else {
        statusLabel->setText(QString::fromUtf8("❌ Failed to submit transaction"));
        QMessageBox::warning(this, "Error", "Failed to submit transaction to RPC");
        free(json);
        cellframe_tx_builder_free(builder);
        return;
    }

    free(json);
    cellframe_tx_builder_free(builder);

    printf("[DEBUG] ========== Transaction Flow Complete ==========\n");
}
