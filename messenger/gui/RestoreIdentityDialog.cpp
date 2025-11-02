#include "RestoreIdentityDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QDir>
#include <QFile>
#include <QThread>
#include <QClipboard>
#include <QApplication>
#include <cstring>

extern "C" {
    #include "../messenger.h"
    #include "../bip39.h"
    #include "../messenger/keyserver_register.h"
}

RestoreIdentityDialog::RestoreIdentityDialog(QWidget *parent)
    : QDialog(parent)
    , stackedWidget(nullptr)
    , wordCompleter(nullptr)
    , wordListModel(nullptr)
{
    setWindowTitle("Restore Identity from Seed");
    setMinimumSize(750, 650);
    setModal(true);

    setupUI();
    setupWordCompleter();
    applyTheme();

    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &RestoreIdentityDialog::applyTheme);
}

void RestoreIdentityDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    stackedWidget = new QStackedWidget(this);
    mainLayout->addWidget(stackedWidget);

    createPage1_IdentityName();
    createPage2_SeedPhrase();
    createPage3_Progress();
    createPage4_Success();

    stackedWidget->setCurrentIndex(0);
}

void RestoreIdentityDialog::setupWordCompleter()
{
    // Load BIP39 wordlist (2048 words)
    const char **wordlist = bip39_get_wordlist();
    QStringList wordList;
    for (int i = 0; i < 2048; i++) {
        wordList << QString::fromUtf8(wordlist[i]);
    }

    wordListModel = new QStringListModel(wordList, this);
    wordCompleter = new QCompleter(wordListModel, this);
    wordCompleter->setCaseSensitivity(Qt::CaseInsensitive);
    wordCompleter->setCompletionMode(QCompleter::InlineCompletion);
}

void RestoreIdentityDialog::createPage1_IdentityName()
{
    page1 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page1);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    titleLabel1 = new QLabel("Restore Your Identity", page1);
    titleLabel1->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel1);

    instructionsLabel = new QLabel(
        "Enter the identity name you used when creating this identity.\n\n"
        "This should be the same name you used originally.", page1);
    instructionsLabel->setWordWrap(true);
    instructionsLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(instructionsLabel);

    layout->addSpacing(20);

    inputLabel1 = new QLabel("Identity Name:", page1);
    layout->addWidget(inputLabel1);

    identityNameInput = new QLineEdit(page1);
    identityNameInput->setPlaceholderText("e.g., alice");
    identityNameInput->setMinimumHeight(40);
    identityNameInput->setStyleSheet("font-size: 14pt; padding: 5px;");
    connect(identityNameInput, &QLineEdit::textChanged, [this]() { errorLabel1->clear(); });
    layout->addWidget(identityNameInput);

    errorLabel1 = new QLabel(page1);
    errorLabel1->setWordWrap(true);
    layout->addWidget(errorLabel1);

    layout->addStretch();

    nextButton1 = new QPushButton("Next →", page1);
    nextButton1->setMinimumHeight(45);
    nextButton1->setCursor(Qt::PointingHandCursor);
    connect(nextButton1, &QPushButton::clicked, this, &RestoreIdentityDialog::onNextPage);
    layout->addWidget(nextButton1);

    stackedWidget->addWidget(page1);
}

void RestoreIdentityDialog::createPage2_SeedPhrase()
{
    page2 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page2);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(15);

    titleLabel2 = new QLabel("Enter Your 24-Word Seed Phrase", page2);
    titleLabel2->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel2);

    // Paste button
    pasteButton = new QPushButton("📋 Paste from Clipboard", page2);
    pasteButton->setMinimumHeight(35);
    pasteButton->setCursor(Qt::PointingHandCursor);
    connect(pasteButton, &QPushButton::clicked, this, &RestoreIdentityDialog::onPasteSeedPhrase);
    layout->addWidget(pasteButton);

    // Grid for 24 words
    QGridLayout *gridLayout = new QGridLayout();
    gridLayout->setSpacing(8);

    for (int i = 0; i < 24; i++) {
        int row = i % 12;
        int col = (i / 12) * 3;

        QLabel *numLabel = new QLabel(QString::number(i + 1) + ".", page2);
        numLabel->setAlignment(Qt::AlignRight);
        gridLayout->addWidget(numLabel, row, col);

        wordInputs[i] = new QLineEdit(page2);
        wordInputs[i]->setPlaceholderText("word");
        wordInputs[i]->setCompleter(wordCompleter);
        wordInputs[i]->setMinimumHeight(30);
        gridLayout->addWidget(wordInputs[i], row, col + 1);
    }

    layout->addLayout(gridLayout);

    // Optional passphrase
    passphraseLabel = new QLabel("Optional Passphrase (if you used one):", page2);
    layout->addWidget(passphraseLabel);

    passphraseInput = new QLineEdit(page2);
    passphraseInput->setPlaceholderText("Leave empty if no passphrase was used");
    passphraseInput->setEchoMode(QLineEdit::Password);
    passphraseInput->setMinimumHeight(35);
    layout->addWidget(passphraseInput);

    errorLabel2 = new QLabel(page2);
    errorLabel2->setWordWrap(true);
    layout->addWidget(errorLabel2);

    // Navigation buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    previousButton2 = new QPushButton("← Previous", page2);
    previousButton2->setMinimumHeight(40);
    previousButton2->setCursor(Qt::PointingHandCursor);
    connect(previousButton2, &QPushButton::clicked, this, &RestoreIdentityDialog::onPreviousPage);
    buttonLayout->addWidget(previousButton2);

    restoreButton = new QPushButton("Restore Identity", page2);
    restoreButton->setMinimumHeight(40);
    restoreButton->setCursor(Qt::PointingHandCursor);
    restoreButton->setStyleSheet("font-weight: bold; font-size: 14pt;");
    connect(restoreButton, &QPushButton::clicked, this, &RestoreIdentityDialog::onRestoreIdentity);
    buttonLayout->addWidget(restoreButton);

    layout->addLayout(buttonLayout);

    stackedWidget->addWidget(page2);
}

void RestoreIdentityDialog::createPage3_Progress()
{
    page3 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page3);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    titleLabel3 = new QLabel("Restoring Your Identity...", page3);
    titleLabel3->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel3);

    layout->addSpacing(50);

    progressBar = new QProgressBar(page3);
    progressBar->setMinimum(0);
    progressBar->setMaximum(5);
    progressBar->setValue(0);
    progressBar->setMinimumHeight(30);
    progressBar->setTextVisible(true);
    layout->addWidget(progressBar);

    statusLabel = new QLabel("Validating seed phrase...", page3);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    layout->addStretch();

    stackedWidget->addWidget(page3);
}

void RestoreIdentityDialog::createPage4_Success()
{
    page4 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page4);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    titleLabel4 = new QLabel("✓ Identity Restored Successfully!", page4);
    titleLabel4->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel4);

    layout->addSpacing(30);

    successLabel = new QLabel(page4);
    successLabel->setWordWrap(true);
    successLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(successLabel);

    layout->addStretch();

    finishButton = new QPushButton("Start Messaging →", page4);
    finishButton->setMinimumHeight(50);
    finishButton->setCursor(Qt::PointingHandCursor);
    finishButton->setStyleSheet("font-weight: bold; font-size: 14pt;");
    connect(finishButton, &QPushButton::clicked, this, &QDialog::accept);
    layout->addWidget(finishButton);

    stackedWidget->addWidget(page4);
}

void RestoreIdentityDialog::onNextPage()
{
    validateIdentityName();
    if (!errorLabel1->text().isEmpty()) {
        return;
    }
    stackedWidget->setCurrentIndex(1);
}

void RestoreIdentityDialog::onPreviousPage()
{
    int currentPage = stackedWidget->currentIndex();
    if (currentPage > 0) {
        stackedWidget->setCurrentIndex(currentPage - 1);
    }
}

void RestoreIdentityDialog::validateIdentityName()
{
    QString identity = identityNameInput->text().trimmed();

    if (identity.isEmpty()) {
        errorLabel1->setText("❌ Identity name cannot be empty");
        return;
    }

    if (identity.length() < 3 || identity.length() > 20) {
        errorLabel1->setText("❌ Identity name must be between 3 and 20 characters");
        return;
    }

    errorLabel1->clear();
}

bool RestoreIdentityDialog::validateSeedPhrase()
{
    // Build mnemonic from word inputs
    QStringList words;
    for (int i = 0; i < 24; i++) {
        QString word = wordInputs[i]->text().trimmed().toLower();
        if (word.isEmpty()) {
            errorLabel2->setText(QString("❌ Word %1 is missing").arg(i + 1));
            return false;
        }
        words << word;
    }

    QString mnemonic = words.join(" ");
    QByteArray mnemonicBytes = mnemonic.toUtf8();

    // Validate using BIP39 checksum
    if (bip39_validate_mnemonic(mnemonicBytes.data()) != 0) {
        errorLabel2->setText("❌ Invalid seed phrase. Please check your words and try again.");
        return false;
    }

    errorLabel2->clear();
    return true;
}

void RestoreIdentityDialog::onPasteSeedPhrase()
{
    QClipboard *clipboard = QApplication::clipboard();
    QString text = clipboard->text().simplified();

    QStringList words = text.split(QRegExp("\\s+"), Qt::SkipEmptyParts);

    if (words.size() != 24) {
        QMessageBox::warning(this, "Invalid Clipboard",
                            QString("Clipboard contains %1 words, but 24 are required.").arg(words.size()));
        return;
    }

    for (int i = 0; i < 24 && i < words.size(); i++) {
        wordInputs[i]->setText(words[i].toLower());
    }

    QMessageBox::information(this, "Pasted", "Seed phrase pasted from clipboard.");
}

void RestoreIdentityDialog::onRestoreIdentity()
{
    if (!validateSeedPhrase()) {
        return;
    }

    stackedWidget->setCurrentIndex(2);  // Show progress page
    QThread::msleep(100);
    QApplication::processEvents();

    if (performRestore()) {
        restoredIdentity = identityNameInput->text();
        successLabel->setText(QString(
            "Your identity <b>%1</b> has been restored!\n\n"
            "Your cryptographic keys have been regenerated from your seed phrase.\n\n"
            "You can now access your messages.").arg(restoredIdentity));
        stackedWidget->setCurrentIndex(3);
    } else {
        QMessageBox::critical(this, "Error",
                            "Failed to restore identity. Please check your seed phrase and try again.");
        stackedWidget->setCurrentIndex(1);
    }
}

bool RestoreIdentityDialog::performRestore()
{
    QString identity = identityNameInput->text();
    QString passphrase = passphraseInput->text();

    // Build mnemonic
    QStringList words;
    for (int i = 0; i < 24; i++) {
        words << wordInputs[i]->text().trimmed().toLower();
    }
    QString mnemonic = words.join(" ");

    progressBar->setValue(1);
    statusLabel->setText("Deriving cryptographic seeds...");
    QApplication::processEvents();

    QByteArray mnemonicBytes = mnemonic.toUtf8();
    QByteArray passphraseBytes = passphrase.toUtf8();
    QByteArray identityBytes = identity.toUtf8();

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(mnemonicBytes.data(),
                                        passphraseBytes.data(),
                                        signing_seed,
                                        encryption_seed) != 0) {
        return false;
    }

    progressBar->setValue(2);
    statusLabel->setText("Regenerating cryptographic keys...");
    QApplication::processEvents();

    QString homeDir = QDir::homePath();
    QString dnaDir = homeDir + "/.dna";
    QDir().mkpath(dnaDir);

    messenger_context_t *ctx = messenger_init(identityBytes.data());
    if (!ctx) {
        return false;
    }

    progressBar->setValue(3);
    statusLabel->setText("Registering to keyserver...");
    QApplication::processEvents();

    int result = messenger_generate_keys(ctx, identityBytes.data());
    if (result != 0) {
        messenger_free(ctx);
        return false;
    }

    progressBar->setValue(4);
    statusLabel->setText("Registering to cpunk.io keyserver...");
    QApplication::processEvents();

    if (register_to_keyserver(identityBytes.data()) != 0) {
        printf("[WARNING] Failed to register to cpunk.io keyserver\n");
    }

    progressBar->setValue(5);
    statusLabel->setText("Complete!");
    QApplication::processEvents();

    messenger_free(ctx);
    return true;
}

QString RestoreIdentityDialog::getRestoredIdentity() const
{
    return restoredIdentity;
}

void RestoreIdentityDialog::applyTheme()
{
    CpunkTheme theme = ThemeManager::instance()->currentTheme();
    QString bgColor = (theme == THEME_CPUNK_IO) ? "#0f0f1e" : "#1a0f08";
    QString textColor = (theme == THEME_CPUNK_IO) ? "#ffffff" : "#fff5e6";
    QString mutedColor = (theme == THEME_CPUNK_IO) ? "#a0a0b0" : "#d4a574";
    QString errorColor = (theme == THEME_CPUNK_IO) ? "#ff6b9d" : "#ff5252";
    QString successColor = (theme == THEME_CPUNK_IO) ? "#00ffaa" : "#00cc66";
    QString primaryColor = (theme == THEME_CPUNK_IO) ? "#00d9ff" : "#ff8c42";
    QString hoverColor = (theme == THEME_CPUNK_IO) ? "#00b8d4" : "#ff7028";

    setStyleSheet(QString("QDialog { background-color: %1; color: %2; }").arg(bgColor).arg(textColor));

    // Page 1: Identity Name
    if (titleLabel1) {
        titleLabel1->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (instructionsLabel) {
        instructionsLabel->setStyleSheet(QString("color: %1;").arg(textColor));
    }
    if (inputLabel1) {
        inputLabel1->setStyleSheet(QString("color: %1;").arg(textColor));
    }
    if (errorLabel1) {
        errorLabel1->setStyleSheet(QString("color: %1; font-weight: bold;").arg(errorColor));
    }

    // Page 2: Seed Phrase
    if (titleLabel2) {
        titleLabel2->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (passphraseLabel) {
        passphraseLabel->setStyleSheet(QString("color: %1; font-size: 10pt;").arg(mutedColor));
    }
    if (errorLabel2) {
        errorLabel2->setStyleSheet(QString("color: %1; font-weight: bold;").arg(errorColor));
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

    QString buttonStyle = QString(
        "QPushButton {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: none;"
        "  border-radius: 5px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover { background-color: %3; }"
        "QPushButton:disabled { background-color: #555555; color: #888888; }"
    ).arg(primaryColor).arg(bgColor).arg(hoverColor);

    if (nextButton1) nextButton1->setStyleSheet(buttonStyle);
    if (previousButton2) previousButton2->setStyleSheet(buttonStyle);
    if (restoreButton) restoreButton->setStyleSheet(buttonStyle + " font-size: 14pt;");
    if (finishButton) finishButton->setStyleSheet(buttonStyle + " font-size: 14pt;");
    if (pasteButton) pasteButton->setStyleSheet(buttonStyle);
}
