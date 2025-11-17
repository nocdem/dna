/*
 * DNA Messenger - Register DNA Name Dialog
 * Phase 4: DNA Name Registration (Free for now)
 */

#include "RegisterDNANameDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
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
    , nameAvailable(false)
{
    setWindowTitle(QString::fromUtf8("Register DNA Name"));
    setMinimumWidth(600);
    setMinimumHeight(400);

    // Get current fingerprint
    if (m_ctx && m_ctx->fingerprint) {
        currentFingerprint = QString::fromUtf8(m_ctx->fingerprint);
    } else {
        QMessageBox::critical(this, "Error", "Fingerprint not available. Please restart messenger.");
        reject();
        return;
    }

    setupUI();

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
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(30, 30, 30, 30);

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
        "Others can find you by searching for this name."
    ));
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(infoLabel);

    mainLayout->addSpacing(20);

    // Fingerprint display
    QLabel *fpLabel = new QLabel(QString::fromUtf8("Your Fingerprint:"));
    mainLayout->addWidget(fpLabel);

    // Show shortened fingerprint with full tooltip
    QString shortFingerprint = currentFingerprint.left(10) + "..." + currentFingerprint.right(10);
    fingerprintLabel = new QLabel(shortFingerprint);
    fingerprintLabel->setToolTip(currentFingerprint);
    fingerprintLabel->setWordWrap(true);
    fingerprintLabel->setStyleSheet("QLabel { font-family: monospace; font-size: 12pt; font-weight: bold; }");
    mainLayout->addWidget(fingerprintLabel);

    mainLayout->addSpacing(10);

    // Name input
    QLabel *nameLabel = new QLabel(QString::fromUtf8("Desired Name:"));
    mainLayout->addWidget(nameLabel);

    nameInput = new QLineEdit();
    nameInput->setPlaceholderText("e.g., alice (3-20 chars, lowercase alphanumeric + underscore)");
    nameInput->setMaxLength(20);
    connect(nameInput, &QLineEdit::textChanged, this, &RegisterDNANameDialog::onNameChanged);
    mainLayout->addWidget(nameInput);

    availabilityLabel = new QLabel(QString::fromUtf8(""));
    availabilityLabel->setWordWrap(true);
    mainLayout->addWidget(availabilityLabel);

    mainLayout->addSpacing(10);

    // Cost display
    costLabel = new QLabel(QString::fromUtf8("💰 Cost: 1 CPUNK"));
    QFont costFont;
    costFont.setPointSize(14);
    costFont.setBold(true);
    costLabel->setFont(costFont);
    mainLayout->addWidget(costLabel);

    // Payment status
    paymentStatusLabel = new QLabel(QString::fromUtf8("⚠️ Payment: Free for now (not yet implemented)"));
    paymentStatusLabel->setWordWrap(true);
    QFont statusFont;
    statusFont.setPointSize(11);
    statusFont.setItalic(true);
    paymentStatusLabel->setFont(statusFont);
    mainLayout->addWidget(paymentStatusLabel);

    mainLayout->addSpacing(10);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8(""));
    statusLabel->setWordWrap(true);
    mainLayout->addWidget(statusLabel);

    mainLayout->addStretch();

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    cancelButton = new QPushButton(QString::fromUtf8("Cancel"));
    cancelButton->setMinimumHeight(40);
    connect(cancelButton, &QPushButton::clicked, this, &RegisterDNANameDialog::onCancel);
    buttonLayout->addWidget(cancelButton);

    registerButton = new QPushButton(QString::fromUtf8("Register Name (Free)"));
    registerButton->setMinimumHeight(40);
    registerButton->setEnabled(false);
    connect(registerButton, &QPushButton::clicked, this, &RegisterDNANameDialog::onRegister);
    buttonLayout->addWidget(registerButton);

    mainLayout->addLayout(buttonLayout);

    // Apply theme styles
    CpunkTheme theme = ThemeManager::instance()->currentTheme();
    QString accentColor = (theme == THEME_CPUNK_CLUB) ? "#FF8C42" : "#00D9FF";
    QString bgColor = (theme == THEME_CPUNK_IO) ? "#0f0f1e" : "#1a0f08";
    QString textColor = (theme == THEME_CPUNK_IO) ? "#ffffff" : "#fff5e6";

    setStyleSheet(QString(
        "QDialog { background: %1; color: %2; }"
        "QLabel { color: %2; }"
        "QLineEdit { background: %1; border: 2px solid %3; border-radius: 8px; "
        "            padding: 10px; color: %2; font-size: 13pt; }"
        "QLineEdit:focus { border-color: %3; }"
        "QPushButton { background: %3; color: %1; border: none; border-radius: 8px; "
        "              padding: 10px 20px; font-size: 12pt; font-weight: bold; }"
        "QPushButton:hover { background: %4; }"
        "QPushButton:disabled { background: #555555; color: #888888; }"
    ).arg(bgColor).arg(textColor).arg(accentColor).arg(accentColor));
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
        availabilityLabel->setText(QString::fromUtf8("❌ Invalid name (3-20 chars, alphanumeric + underscore only)"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; font-weight: bold; }");
        registerButton->setEnabled(false);
        return;
    }

    // Start availability check timer
    availabilityLabel->setText(QString::fromUtf8("⏳ Checking availability..."));
    availabilityLabel->setStyleSheet("QLabel { color: #FFA500; font-weight: bold; }");
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
    // Name must be 3-20 characters, alphanumeric + underscore
    if (name.length() < 3 || name.length() > 20) {
        return false;
    }

    QRegularExpression regex("^[a-zA-Z0-9_]+$");
    return regex.match(name).hasMatch();
}

void RegisterDNANameDialog::checkNameAvailability(const QString &name) {
    if (!m_ctx || !m_ctx->p2p_transport) {
        availabilityLabel->setText(QString::fromUtf8("❌ P2P transport not initialized"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; font-weight: bold; }");
        nameAvailable = false;
        registerButton->setEnabled(false);
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(m_ctx->p2p_transport);
    if (!dht_ctx) {
        availabilityLabel->setText(QString::fromUtf8("❌ DHT not connected"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; font-weight: bold; }");
        nameAvailable = false;
        registerButton->setEnabled(false);
        return;
    }

    // Query DHT for name
    dht_pubkey_entry_t *entry = NULL;
    int result = dht_keyserver_lookup(dht_ctx, name.toUtf8().constData(), &entry);

    if (result == 0 && entry) {
        // Name is taken
        availabilityLabel->setText(QString::fromUtf8("❌ Name already registered"));
        availabilityLabel->setStyleSheet("QLabel { color: #FF6B35; font-weight: bold; }");
        nameAvailable = false;
        dht_keyserver_free_entry(entry);
    } else {
        // Name is available
        availabilityLabel->setText(QString::fromUtf8("✅ Name available!"));
        availabilityLabel->setStyleSheet("QLabel { color: #00FF00; font-weight: bold; }");
        nameAvailable = true;
    }

    // Enable register button if name is available
    registerButton->setEnabled(nameAvailable);
}

void RegisterDNANameDialog::onRegister() {
    QString name = nameInput->text().trimmed();

    if (!nameAvailable || name.isEmpty()) {
        QMessageBox::warning(this, "Invalid Name", "Please enter a valid, available name.");
        return;
    }

    // Disable button during registration
    registerButton->setEnabled(false);
    statusLabel->setText(QString::fromUtf8("⏳ Registering name..."));
    QApplication::processEvents();

    // Call messenger_register_name
    QByteArray nameBytes = name.toUtf8();
    QByteArray fingerprintBytes = currentFingerprint.toUtf8();

    int result = messenger_register_name(m_ctx, fingerprintBytes.constData(), nameBytes.constData());

    if (result == 0) {
        statusLabel->setText(QString::fromUtf8("✓ Name registered successfully!"));
        QMessageBox::information(this, "Success",
            QString("Name '%1' has been registered to your identity!\n\n"
                    "Others can now find you by searching for this name.").arg(name));
        accept();
    } else {
        statusLabel->setText(QString::fromUtf8("❌ Registration failed"));
        QMessageBox::critical(this, "Error",
            QString("Failed to register name '%1'. Please try again.").arg(name));
        registerButton->setEnabled(true);
    }
}

void RegisterDNANameDialog::onCancel() {
    reject();
}
