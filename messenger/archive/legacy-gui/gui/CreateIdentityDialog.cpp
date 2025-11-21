#include "CreateIdentityDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QDir>
#include <QFile>
#include <QThread>
#include <cstring>

extern "C" {
    #include "../messenger.h"
    #include "../bip39.h"
}

CreateIdentityDialog::CreateIdentityDialog(QWidget *parent)
    : QDialog(parent)
    , stackedWidget(nullptr)
    , page1(nullptr)
    , page2(nullptr)
    , page3(nullptr)
    , page4(nullptr)
{
    setWindowTitle("Create New Identity");
    setMinimumSize(236, 700);
    setModal(true);

    setupUI();
    applyTheme();

    // Connect to theme manager
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &CreateIdentityDialog::applyTheme);
}

void CreateIdentityDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    stackedWidget = new QStackedWidget(this);
    mainLayout->addWidget(stackedWidget);

    createPage1_SeedPhrase();
    createPage2_Confirmation();
    createPage3_Progress();
    createPage4_Success();

    // Generate seed immediately
    onGenerateSeed();

    stackedWidget->setCurrentIndex(0);
}

void CreateIdentityDialog::createPage1_SeedPhrase()
{
    page1 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page1);
    layout->setContentsMargins(10, 30, 10, 30);
    layout->setSpacing(15);

    // Title
    titleLabel1 = new QLabel("Your Recovery Seed Phrase", page1);
    titleLabel1->setAlignment(Qt::AlignCenter);
    // Color and font will be set by applyTheme()
    layout->addWidget(titleLabel1);

    // Seed phrase widget
    seedPhraseWidget = new SeedPhraseWidget(page1);
    layout->addWidget(seedPhraseWidget);

    // Optional passphrase
    passphraseLabel = new QLabel("Optional Passphrase (Advanced):", page1);
    layout->addWidget(passphraseLabel);

    passphraseInput = new QLineEdit(page1);
    passphraseInput->setPlaceholderText("Leave empty for no passphrase");
    passphraseInput->setEchoMode(QLineEdit::Password);
    passphraseInput->setMinimumHeight(35);
    layout->addWidget(passphraseInput);

    // Confirmation checkbox
    confirmedCheckbox = new QCheckBox("I have written down my 24-word seed phrase securely", page1);
    confirmedCheckbox->setStyleSheet("font-size: 11pt; font-weight: bold;");
    layout->addWidget(confirmedCheckbox);

    // Next button
    nextButton1 = new QPushButton("Next →", page1);
    nextButton1->setMinimumHeight(40);
    nextButton1->setCursor(Qt::PointingHandCursor);
    connect(nextButton1, &QPushButton::clicked, this, &CreateIdentityDialog::onNextPage);
    connect(confirmedCheckbox, &QCheckBox::toggled, nextButton1, &QPushButton::setEnabled);
    nextButton1->setEnabled(false);
    layout->addWidget(nextButton1);

    stackedWidget->addWidget(page1);
}

void CreateIdentityDialog::createPage2_Confirmation()
{
    page2 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page2);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    // Title
    titleLabel2 = new QLabel("Final Confirmation", page2);
    titleLabel2->setAlignment(Qt::AlignCenter);
    titleLabel2->setStyleSheet("font-size: 18pt; font-weight: bold;");
    layout->addWidget(titleLabel2);

    // Confirmation text
    confirmationLabel = new QLabel(
        "You are about to create a new fingerprint-based identity.\n\n"
        "Your seed phrase has been generated and should be safely written down.\n\n"
        "Click \"Create Identity\" to proceed with key generation.", page2);
    confirmationLabel->setWordWrap(true);
    confirmationLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(confirmationLabel);

    // Warning
    warningLabel = new QLabel(
        "⚠ IMPORTANT:\n\n"
        "If you lose your seed phrase and this device, your identity will be PERMANENTLY LOST.\n"
        "There is NO way to recover it.\n\n"
        "Make sure you have written down your 24-word seed phrase in a secure location.", page2);
    warningLabel->setWordWrap(true);
    warningLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(warningLabel);

    // Final checkbox
    understandCheckbox = new QCheckBox("I understand and have securely stored my seed phrase", page2);
    understandCheckbox->setStyleSheet("font-size: 11pt; font-weight: bold;");
    layout->addWidget(understandCheckbox);

    layout->addStretch();

    // Navigation buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    previousButton2 = new QPushButton("← Previous", page2);
    previousButton2->setMinimumHeight(40);
    previousButton2->setCursor(Qt::PointingHandCursor);
    connect(previousButton2, &QPushButton::clicked, this, &CreateIdentityDialog::onPreviousPage);
    buttonLayout->addWidget(previousButton2);

    createButton = new QPushButton("Create Identity", page2);
    createButton->setMinimumHeight(40);
    createButton->setCursor(Qt::PointingHandCursor);
    createButton->setStyleSheet("font-weight: bold; font-size: 14pt;");
    connect(createButton, &QPushButton::clicked, this, &CreateIdentityDialog::onCreateIdentity);
    connect(understandCheckbox, &QCheckBox::toggled, createButton, &QPushButton::setEnabled);
    createButton->setEnabled(false);
    buttonLayout->addWidget(createButton);

    layout->addLayout(buttonLayout);

    stackedWidget->addWidget(page2);
}

void CreateIdentityDialog::createPage3_Progress()
{
    page3 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page3);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    // Title
    titleLabel3 = new QLabel("Creating Your Identity...", page3);
    titleLabel3->setAlignment(Qt::AlignCenter);
    titleLabel3->setStyleSheet("font-size: 18pt; font-weight: bold;");
    layout->addWidget(titleLabel3);

    layout->addSpacing(50);

    // Progress bar
    progressBar = new QProgressBar(page3);
    progressBar->setMinimum(0);
    progressBar->setMaximum(5);
    progressBar->setValue(0);
    progressBar->setMinimumHeight(30);
    progressBar->setTextVisible(true);
    layout->addWidget(progressBar);

    // Status label
    statusLabel = new QLabel("Initializing...", page3);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    layout->addStretch();

    stackedWidget->addWidget(page3);
}

void CreateIdentityDialog::createPage4_Success()
{
    page4 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page4);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    // Title
    titleLabel4 = new QLabel("✓ Identity Created Successfully!", page4);
    titleLabel4->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel4);

    layout->addSpacing(30);

    // Success message
    successLabel = new QLabel(page4);
    successLabel->setWordWrap(true);
    successLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(successLabel);

    // Reminder
    reminderLabel = new QLabel(
        "Remember:\n"
        "• Your seed phrase is stored NOWHERE except where you wrote it down\n"
        "• Keep it safe and never share it with anyone\n"
        "• You'll need it to recover your identity on other devices\n\n"
        "Note: To allow others to find you, register a name via Settings menu.", page4);
    reminderLabel->setWordWrap(true);
    reminderLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(reminderLabel);

    layout->addStretch();

    // Finish button
    finishButton = new QPushButton("Start Messaging →", page4);
    finishButton->setMinimumHeight(50);
    finishButton->setCursor(Qt::PointingHandCursor);
    finishButton->setStyleSheet("font-weight: bold; font-size: 14pt;");
    connect(finishButton, &QPushButton::clicked, this, &QDialog::accept);
    layout->addWidget(finishButton);

    stackedWidget->addWidget(page4);
}

void CreateIdentityDialog::onNextPage()
{
    int currentPage = stackedWidget->currentIndex();

    if (currentPage == 0) {
        // Move from seed phrase page to confirmation page
        stackedWidget->setCurrentIndex(1);
    }
}

void CreateIdentityDialog::onPreviousPage()
{
    int currentPage = stackedWidget->currentIndex();
    if (currentPage == 1) {
        // Move from confirmation back to seed phrase
        stackedWidget->setCurrentIndex(0);
    }
}

void CreateIdentityDialog::onGenerateSeed()
{
    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];

    // Generate 24-word BIP39 mnemonic
    if (bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic)) != 0) {
        QMessageBox::critical(this, "Error", "Failed to generate seed phrase. Please try again.");
        stackedWidget->setCurrentIndex(0);
        return;
    }

    generatedMnemonic = QString::fromUtf8(mnemonic);
    seedPhraseWidget->setSeedPhrase(generatedMnemonic);
}

void CreateIdentityDialog::onCreateIdentity()
{
    stackedWidget->setCurrentIndex(2);  // Show progress page

    // Perform key generation
    QThread::msleep(100);  // Brief delay to show progress page
    QApplication::processEvents();

    if (performKeyGeneration()) {
        // Success
        QString shortFingerprint = createdFingerprint.left(10) + "..." + createdFingerprint.right(10);
        successLabel->setText(QString(
            "Your identity has been created!\n\n"
            "Fingerprint: <b>%1</b>\n\n"
            "Your cryptographic keys have been generated.\n\n"
            "You can now start messaging.\n"
            "To allow others to find you, register a name via Settings menu.").arg(shortFingerprint));
        stackedWidget->setCurrentIndex(3);
    } else {
        // Error
        QMessageBox::critical(this, "Error",
                            "Failed to create identity. Please try again.");
        stackedWidget->setCurrentIndex(0);
    }
}

bool CreateIdentityDialog::performKeyGeneration()
{
    QString passphrase = passphraseInput->text();

    progressBar->setValue(1);
    statusLabel->setText("Deriving cryptographic seeds...");
    QApplication::processEvents();

    // Convert mnemonic and passphrase to C strings
    QByteArray mnemonicBytes = generatedMnemonic.toUtf8();
    QByteArray passphraseBytes = passphrase.toUtf8();

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    // Derive seeds from mnemonic
    if (qgp_derive_seeds_from_mnemonic(mnemonicBytes.data(),
                                        passphraseBytes.data(),
                                        signing_seed,
                                        encryption_seed) != 0) {
        return false;
    }

    progressBar->setValue(2);
    statusLabel->setText("Generating cryptographic keys...");
    QApplication::processEvents();

    // Ensure ~/.dna directory exists
    QString homeDir = QDir::homePath();
    QString dnaDir = homeDir + "/.dna";
    QDir().mkpath(dnaDir);

    // Create temporary context (no identity needed)
    messenger_context_t *ctx = messenger_init("temp");
    if (!ctx) {
        return false;
    }

    progressBar->setValue(3);
    statusLabel->setText("Saving keys...");
    QApplication::processEvents();

    // Generate keys from seeds (fingerprint-first, no name required)
    char fingerprint[129];
    int result = messenger_generate_keys_from_seeds(ctx, signing_seed, encryption_seed, fingerprint);

    // Securely wipe seeds from memory
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));

    if (result != 0) {
        messenger_free(ctx);
        return false;
    }

    createdFingerprint = QString::fromUtf8(fingerprint);

    progressBar->setValue(5);
    statusLabel->setText("Complete!");
    QApplication::processEvents();

    messenger_free(ctx);
    return true;
}

QString CreateIdentityDialog::getCreatedFingerprint() const
{
    return createdFingerprint;
}

void CreateIdentityDialog::applyTheme()
{
    CpunkTheme theme = ThemeManager::instance()->currentTheme();
    QString bgColor = (theme == THEME_CPUNK_IO) ? "#0f0f1e" : "#1a0f08";
    QString textColor = (theme == THEME_CPUNK_IO) ? "#ffffff" : "#fff5e6";
    QString mutedColor = (theme == THEME_CPUNK_IO) ? "#a0a0b0" : "#d4a574";
    QString errorColor = (theme == THEME_CPUNK_IO) ? "#ff6b9d" : "#ff5252";
    QString warningColor = (theme == THEME_CPUNK_IO) ? "#ff6b9d" : "#ff4444";
    QString successColor = (theme == THEME_CPUNK_IO) ? "#00ffaa" : "#00cc66";
    QString primaryColor = (theme == THEME_CPUNK_IO) ? "#00d9ff" : "#ff8c42";
    QString hoverColor = (theme == THEME_CPUNK_IO) ? "#00b8d4" : "#ff7028";

    setStyleSheet(QString("QDialog { background-color: %1; color: %2; }").arg(bgColor).arg(textColor));

    // Page 1: Seed Phrase
    if (titleLabel1) {
        titleLabel1->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (passphraseLabel) {
        passphraseLabel->setStyleSheet(QString("color: %1; font-size: 10pt;").arg(mutedColor));
    }

    // Page 2: Confirmation
    if (titleLabel2) {
        titleLabel2->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (confirmationLabel) {
        confirmationLabel->setStyleSheet(QString("font-size: 12pt; padding: 20px; color: %1;").arg(textColor));
    }
    if (warningLabel) {
        warningLabel->setStyleSheet(QString("color: %1; font-size: 11pt; font-weight: bold; padding: 20px; border: 2px solid %1; border-radius: 5px;").arg(warningColor));
    }

    // Page 3: Progress
    if (titleLabel3) {
        titleLabel3->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (statusLabel) {
        statusLabel->setStyleSheet(QString("font-size: 12pt; color: %1;").arg(mutedColor));
    }

    // Page 4: Success
    if (titleLabel4) {
        titleLabel4->setStyleSheet(QString("font-size: 20pt; font-weight: bold; color: %1;").arg(successColor));
    }
    if (successLabel) {
        successLabel->setStyleSheet(QString("font-size: 14pt; color: %1;").arg(textColor));
    }
    if (reminderLabel) {
        reminderLabel->setStyleSheet(QString("color: %1; font-size: 11pt; padding: 20px;").arg(mutedColor));
    }

    // Style buttons
    QString buttonStyle = QString(
        "QPushButton {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: none;"
        "  border-radius: 5px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background-color: %3;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    ).arg(primaryColor).arg(bgColor).arg(hoverColor);

    if (nextButton1) nextButton1->setStyleSheet(buttonStyle);
    if (previousButton2) previousButton2->setStyleSheet(buttonStyle);
    if (createButton) createButton->setStyleSheet(buttonStyle + " font-size: 14pt;");
    if (finishButton) finishButton->setStyleSheet(buttonStyle + " font-size: 14pt;");
}
