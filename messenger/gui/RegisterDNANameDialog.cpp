/*
 * DNA Messenger - Register DNA Name Dialog
 * Phase 4: DNA Name Registration (0.01 CPUNK)
 */

#include "RegisterDNANameDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QMessageBox>
#include <QApplication>
#include <QRegularExpression>

extern "C" {
    #include "../dht/dht_keyserver.h"
    #include "../p2p/p2p_transport.h"
}

RegisterDNANameDialog::RegisterDNANameDialog(messenger_context_t *ctx, QWidget *parent)
    : QDialog(parent)
    , m_ctx(ctx)
    , walletBalance(0.0)
    , nameAvailable(false)
{
    setWindowTitle(QString::fromUtf8("Register DNA Name"));
    setMinimumWidth(700);
    setMinimumHeight(600);

    // Get current fingerprint
    if (m_ctx && m_ctx->fingerprint) {
        currentFingerprint = QString::fromUtf8(m_ctx->fingerprint);
    } else {
        QMessageBox::critical(this, "Error", "Fingerprint not available. Please restart messenger.");
        reject();
        return;
    }

    setupUI();
    loadWallets();

    // Availability check timer (500ms delay after typing)
    availabilityTimer = new QTimer(this);
    availabilityTimer->setSingleShot(true);
    connect(availabilityTimer, &QTimer::timeout, this, &RegisterDNANameDialog::onCheckAvailability);

    // Apply current theme
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            [this](CpunkTheme) {
        // Theme will be reapplied on next window show
    });
}

void RegisterDNANameDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Header
    QLabel *headerLabel = new QLabel(QString::fromUtf8("Register DNA Name"));
    QFont headerFont;
    headerFont.setPointSize(18);
    headerFont.setBold(true);
    headerLabel->setFont(headerFont);
    headerLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(headerLabel);

    // Info text
    QLabel *infoLabel = new QLabel(QString::fromUtf8(
        "Register a human-readable name for your identity.\n"
        "Cost: 0.01 CPUNK • Expires: 365 days • Renewable"
    ));
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(infoLabel);

    mainLayout->addSpacing(20);

    // Fingerprint display
    QLabel *fpLabel = new QLabel(QString::fromUtf8("Your Fingerprint:"));
    mainLayout->addWidget(fpLabel);

    fingerprintLabel = new QLabel(currentFingerprint);
    fingerprintLabel->setWordWrap(true);
    fingerprintLabel->setStyleSheet("QLabel { font-family: monospace; font-size: 11px; }");
    mainLayout->addWidget(fingerprintLabel);

    mainLayout->addSpacing(10);

    // Name input
    QLabel *nameLabel = new QLabel(QString::fromUtf8("Desired Name:"));
    mainLayout->addWidget(nameLabel);

    nameInput = new QLineEdit();
    nameInput->setPlaceholderText("e.g., nocdem");
    nameInput->setMaxLength(32);
    connect(nameInput, &QLineEdit::textChanged, this, &RegisterDNANameDialog::onNameChanged);
    mainLayout->addWidget(nameInput);

    availabilityLabel = new QLabel(QString::fromUtf8(""));
    availabilityLabel->setWordWrap(true);
    mainLayout->addWidget(availabilityLabel);

    mainLayout->addSpacing(10);

    // Wallet selector
    QLabel *walletLabel = new QLabel(QString::fromUtf8("Payment Wallet:"));
    mainLayout->addWidget(walletLabel);

    walletSelector = new QComboBox();
    connect(walletSelector, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RegisterDNANameDialog::onWalletSelected);
    mainLayout->addWidget(walletSelector);

    balanceLabel = new QLabel(QString::fromUtf8("Balance: Checking..."));
    mainLayout->addWidget(balanceLabel);

    mainLayout->addSpacing(10);

    // Network selector
    QLabel *networkLabel = new QLabel(QString::fromUtf8("Network:"));
    mainLayout->addWidget(networkLabel);

    networkSelector = new QComboBox();
    networkSelector->addItem("Backbone (CPUNK)");
    networkSelector->setCurrentIndex(0);
    selectedNetwork = "Backbone";
    connect(networkSelector, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RegisterDNANameDialog::onNetworkSelected);
    mainLayout->addWidget(networkSelector);

    mainLayout->addSpacing(10);

    // Cost display
    costLabel = new QLabel(QString::fromUtf8("💰 Cost: 0.01 CPUNK"));
    QFont costFont;
    costFont.setPointSize(14);
    costFont.setBold(true);
    costLabel->setFont(costFont);
    mainLayout->addWidget(costLabel);

    mainLayout->addSpacing(10);

    // Transaction preview
    QLabel *previewLabel = new QLabel(QString::fromUtf8("Transaction Preview:"));
    mainLayout->addWidget(previewLabel);

    transactionPreview = new QTextEdit();
    transactionPreview->setReadOnly(true);
    transactionPreview->setMaximumHeight(120);
    transactionPreview->setText(QString::fromUtf8("Enter a name and select a wallet to preview transaction."));
    mainLayout->addWidget(transactionPreview);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8(""));
    statusLabel->setWordWrap(true);
    mainLayout->addWidget(statusLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    cancelButton = new QPushButton(QString::fromUtf8("Cancel"));
    connect(cancelButton, &QPushButton::clicked, this, &RegisterDNANameDialog::onCancel);
    buttonLayout->addWidget(cancelButton);

    registerButton = new QPushButton(QString::fromUtf8("Register & Pay 0.01 CPUNK"));
    registerButton->setEnabled(false);
    connect(registerButton, &QPushButton::clicked, this, &RegisterDNANameDialog::onRegister);
    buttonLayout->addWidget(registerButton);

    mainLayout->addLayout(buttonLayout);

    // Apply theme styles
    QString accentColor = ThemeManager::instance()->currentTheme() == THEME_CPUNK_CLUB ? "#FF8C42" : "#00D9FF";
    QString bgColor = "#0A1E21";
    QString textColor = accentColor;

    setStyleSheet(QString(
        "QDialog { background: %1; color: %2; font-family: 'Orbitron'; }"
        "QLabel { color: %2; font-size: 13px; }"
        "QLineEdit { background: #0D3438; border: 2px solid %2; border-radius: 8px; "
        "            padding: 10px; color: %2; font-size: 14px; }"
        "QLineEdit:focus { border-color: %2; }"
        "QComboBox { background: #0D3438; border: 2px solid %2; border-radius: 8px; "
        "            padding: 8px; color: %2; font-size: 13px; }"
        "QTextEdit { background: #0D3438; border: 2px solid %2; border-radius: 8px; "
        "            padding: 8px; color: %2; font-family: monospace; font-size: 11px; }"
        "QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %2, stop:1 rgba(0, 217, 255, 0.7)); "
        "              color: white; border: 2px solid %2; border-radius: 10px; "
        "              padding: 12px 24px; font-size: 14px; font-weight: bold; }"
        "QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 217, 255, 0.9), stop:1 %2); }"
        "QPushButton:disabled { background: #444; color: #888; border: 2px solid #666; }"
    ).arg(bgColor).arg(textColor));
}

void RegisterDNANameDialog::loadWallets() {
    wallet_list_t *wallet_list = NULL;
    if (wallet_list_cellframe(&wallet_list) != 0 || !wallet_list) {
        walletSelector->addItem("No wallets found");
        statusLabel->setText(QString::fromUtf8("⚠️ No wallets found in ~/.dna/ or system wallet directory"));
        return;
    }

    for (int i = 0; i < wallet_list->count; i++) {
        QString walletName = QString::fromUtf8(wallet_list->wallets[i].name);
        walletSelector->addItem(walletName);
    }

    wallet_list_free(wallet_list);

    if (walletSelector->count() > 0) {
        onWalletSelected(0);  // Select first wallet
    }
}

void RegisterDNANameDialog::onNameChanged() {
    QString name = nameInput->text().trimmed();

    if (name.isEmpty()) {
        availabilityLabel->setText("");
        registerButton->setEnabled(false);
        return;
    }

    // Validate name format
    if (!validateName(name)) {
        availabilityLabel->setText(QString::fromUtf8("❌ Invalid name (3-32 chars, lowercase alphanumeric only)"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; }");
        registerButton->setEnabled(false);
        return;
    }

    // Start availability check timer
    availabilityLabel->setText(QString::fromUtf8("⏳ Checking availability..."));
    availabilityLabel->setStyleSheet("QLabel { color: #FFA500; }");
    availabilityTimer->start(500);
}

void RegisterDNANameDialog::onCheckAvailability() {
    QString name = nameInput->text().trimmed().toLower();

    if (name.isEmpty() || !validateName(name)) {
        return;
    }

    checkNameAvailability(name);
}

bool RegisterDNANameDialog::validateName(const QString &name) {
    // Name must be 3-32 characters, lowercase alphanumeric only
    if (name.length() < 3 || name.length() > 32) {
        return false;
    }

    QRegularExpression regex("^[a-z0-9]+$");
    return regex.match(name).hasMatch();
}

void RegisterDNANameDialog::checkNameAvailability(const QString &name) {
    if (!m_ctx || !m_ctx->p2p_transport) {
        availabilityLabel->setText(QString::fromUtf8("❌ P2P transport not initialized"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; }");
        nameAvailable = false;
        registerButton->setEnabled(false);
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(m_ctx->p2p_transport);
    if (!dht_ctx) {
        availabilityLabel->setText(QString::fromUtf8("❌ DHT not connected"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; }");
        nameAvailable = false;
        registerButton->setEnabled(false);
        return;
    }

    // Query DHT for name
    char *fingerprint_result = NULL;
    int result = dna_lookup_by_name(dht_ctx, name.toUtf8().constData(), &fingerprint_result);

    if (result == 0 && fingerprint_result) {
        // Name is taken
        availabilityLabel->setText(QString::fromUtf8("❌ Name already registered"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; }");
        nameAvailable = false;
        free(fingerprint_result);
    } else {
        // Name is available
        availabilityLabel->setText(QString::fromUtf8("✅ Name available!"));
        availabilityLabel->setStyleSheet("QLabel { color: #00FF00; }");
        nameAvailable = true;
        buildTransaction();
    }

    // Enable register button if name is available and wallet is selected
    registerButton->setEnabled(nameAvailable && !selectedWallet.isEmpty() && walletBalance >= 0.01);
}

void RegisterDNANameDialog::onWalletSelected(int index) {
    if (index < 0 || walletSelector->count() == 0) {
        return;
    }

    selectedWallet = walletSelector->currentText();
    statusLabel->setText(QString::fromUtf8("Querying balance..."));

    // Query wallet balance
    cellframe_rpc_response_t *response = NULL;

    // Get wallet address for Backbone network
    wallet_list_t *wallet_list = NULL;
    if (wallet_list_cellframe(&wallet_list) != 0 || !wallet_list) {
        balanceLabel->setText(QString::fromUtf8("Balance: Error loading wallet"));
        return;
    }

    char wallet_address[256] = {0};
    bool found = false;
    for (int i = 0; i < wallet_list->count; i++) {
        if (QString::fromUtf8(wallet_list->wallets[i].name) == selectedWallet) {
            if (wallet_get_address(&wallet_list->wallets[i], "Backbone", wallet_address) == 0) {
                found = true;
            }
            break;
        }
    }
    wallet_list_free(wallet_list);

    if (!found) {
        balanceLabel->setText(QString::fromUtf8("Balance: Error getting address"));
        statusLabel->setText(QString::fromUtf8("⚠️ Failed to get wallet address"));
        return;
    }

    // Query balance via RPC
    int ret = cellframe_rpc_get_balance("Backbone", wallet_address, "CPUNK", &response);

    if (ret == 0 && response && response->result) {
        json_object *j_balance = json_object_array_get_idx(response->result, 0);
        if (j_balance) {
            const char *balance_str = json_object_get_string(j_balance);
            walletBalance = atof(balance_str);
            balanceLabel->setText(QString::fromUtf8("Balance: %1 CPUNK").arg(walletBalance, 0, 'f', 8));

            if (walletBalance < 0.01) {
                statusLabel->setText(QString::fromUtf8("⚠️ Insufficient balance (need 0.01 CPUNK)"));
                registerButton->setEnabled(false);
            } else {
                statusLabel->setText(QString::fromUtf8("✓ Wallet loaded"));
                registerButton->setEnabled(nameAvailable && !nameInput->text().trimmed().isEmpty());
            }
        }
        cellframe_rpc_response_free(response);
    } else {
        balanceLabel->setText(QString::fromUtf8("Balance: Query failed"));
        statusLabel->setText(QString::fromUtf8("⚠️ Failed to query balance"));
        if (response) cellframe_rpc_response_free(response);
    }

    buildTransaction();
}

void RegisterDNANameDialog::onNetworkSelected(int index) {
    Q_UNUSED(index);
    selectedNetwork = networkSelector->currentText().split(" ").first();  // Extract "Backbone"
    buildTransaction();
}

void RegisterDNANameDialog::buildTransaction() {
    QString name = nameInput->text().trimmed().toLower();

    if (name.isEmpty() || selectedWallet.isEmpty()) {
        transactionPreview->setText(QString::fromUtf8("Enter a name and select a wallet to preview transaction."));
        return;
    }

    QString preview = QString::fromUtf8(
        "Transaction Details:\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "From:      %1\n"
        "To:        %2\n"
        "Amount:    0.01 CPUNK\n"
        "Fee:       ~0.002 CELL\n"
        "Network:   %3\n"
        "Memo:      %4\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Purpose:   DNA Name Registration\n"
        "Duration:  365 days\n"
    )
    .arg(selectedWallet)
    .arg(QString::fromUtf8(DNA_REGISTRATION_ADDRESS).left(20) + "...")
    .arg(selectedNetwork)
    .arg(name);

    transactionPreview->setText(preview);
}

void RegisterDNANameDialog::onRegister() {
    QString name = nameInput->text().trimmed().toLower();

    if (!nameAvailable) {
        QMessageBox::warning(this, "Error", "Name is not available or not checked");
        return;
    }

    if (walletBalance < 0.01) {
        QMessageBox::warning(this, "Insufficient Balance",
            QString("Your wallet has %1 CPUNK, but 0.01 CPUNK is required for registration.")
            .arg(walletBalance, 0, 'f', 8));
        return;
    }

    // Confirm registration
    int ret = QMessageBox::question(this,
        QString::fromUtf8("Confirm Registration"),
        QString::fromUtf8("Register DNA name '%1' for 0.01 CPUNK?\n\n"
                          "This will create a blockchain transaction.\n"
                          "Transaction fee: ~0.002 CELL")
            .arg(name),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::Yes);

    if (ret != QMessageBox::Yes) {
        return;
    }

    signAndSubmit();
}

void RegisterDNANameDialog::signAndSubmit() {
    QString name = nameInput->text().trimmed().toLower();

    statusLabel->setText(QString::fromUtf8("🔨 Building transaction..."));
    registerButton->setEnabled(false);
    cancelButton->setEnabled(false);
    QApplication::processEvents();

    // TODO: Implement actual transaction building and submission
    // For now, show placeholder message

    QMessageBox::information(this,
        QString::fromUtf8("Registration in Progress"),
        QString::fromUtf8("DNA Name Registration is being implemented.\n\n"
                          "The transaction builder will:\n"
                          "1. Query UTXOs from wallet\n"
                          "2. Build transaction with memo '%1'\n"
                          "3. Sign with Dilithium5 key\n"
                          "4. Submit to Backbone network\n"
                          "5. Register name in DHT after confirmation")
            .arg(name));

    statusLabel->setText(QString::fromUtf8("⚠️ Registration not yet implemented"));
    registerButton->setEnabled(true);
    cancelButton->setEnabled(true);
}

void RegisterDNANameDialog::onCancel() {
    reject();
}

void RegisterDNANameDialog::updateCost() {
    // Cost is fixed at 0.01 CPUNK
    costLabel->setText(QString::fromUtf8("💰 Cost: 0.01 CPUNK"));
}
