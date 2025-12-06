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

    createPage1_SeedPhrase();
    createPage2_Progress();
    createPage3_Success();

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

void RestoreIdentityDialog::createPage1_SeedPhrase()
{
    page1 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page1);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(15);

    titleLabel1 = new QLabel("Enter Your 24-Word Seed Phrase", page1);
    titleLabel1->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel1);

    // Paste button
    pasteButton = new QPushButton("📋 Paste from Clipboard", page1);
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

        QLabel *numLabel = new QLabel(QString::number(i + 1) + ".", page1);
        numLabel->setAlignment(Qt::AlignRight);
        gridLayout->addWidget(numLabel, row, col);

        wordInputs[i] = new QLineEdit(page1);
        wordInputs[i]->setPlaceholderText("word");
        wordInputs[i]->setCompleter(wordCompleter);
        wordInputs[i]->setMinimumHeight(30);
        gridLayout->addWidget(wordInputs[i], row, col + 1);
    }

    layout->addLayout(gridLayout);

    // Optional passphrase
    passphraseLabel = new QLabel("Optional Passphrase (if you used one):", page1);
    layout->addWidget(passphraseLabel);

    passphraseInput = new QLineEdit(page1);
    passphraseInput->setPlaceholderText("Leave empty if no passphrase was used");
    passphraseInput->setEchoMode(QLineEdit::Password);
    passphraseInput->setMinimumHeight(35);
    layout->addWidget(passphraseInput);

    errorLabel1 = new QLabel(page1);
    errorLabel1->setWordWrap(true);
    layout->addWidget(errorLabel1);

    layout->addStretch();

    // Restore button (no previous button since this is page 1)
    restoreButton = new QPushButton("Restore Identity", page1);
    restoreButton->setMinimumHeight(45);
    restoreButton->setCursor(Qt::PointingHandCursor);
    restoreButton->setStyleSheet("font-weight: bold; font-size: 14pt;");
    connect(restoreButton, &QPushButton::clicked, this, &RestoreIdentityDialog::onRestoreIdentity);
    layout->addWidget(restoreButton);

    stackedWidget->addWidget(page1);
}

void RestoreIdentityDialog::createPage2_Progress()
{
    page2 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page2);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    titleLabel2 = new QLabel("Restoring Your Identity...", page2);
    titleLabel2->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel2);

    layout->addSpacing(50);

    progressBar = new QProgressBar(page2);
    progressBar->setMinimum(0);
    progressBar->setMaximum(5);
    progressBar->setValue(0);
    progressBar->setMinimumHeight(30);
    progressBar->setTextVisible(true);
    layout->addWidget(progressBar);

    statusLabel = new QLabel("Validating seed phrase...", page2);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    layout->addStretch();

    stackedWidget->addWidget(page2);
}

void RestoreIdentityDialog::createPage3_Success()
{
    page3 = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page3);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(20);

    titleLabel3 = new QLabel("✓ Identity Restored Successfully!", page3);
    titleLabel3->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel3);

    layout->addSpacing(30);

    successLabel = new QLabel(page3);
    successLabel->setWordWrap(true);
    successLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(successLabel);

    layout->addStretch();

    finishButton = new QPushButton("Start Messaging →", page3);
    finishButton->setMinimumHeight(50);
    finishButton->setCursor(Qt::PointingHandCursor);
    finishButton->setStyleSheet("font-weight: bold; font-size: 14pt;");
    connect(finishButton, &QPushButton::clicked, this, &QDialog::accept);
    layout->addWidget(finishButton);

    stackedWidget->addWidget(page3);
}

bool RestoreIdentityDialog::validateSeedPhrase()
{
    // Build mnemonic from word inputs
    QStringList words;
    for (int i = 0; i < 24; i++) {
        QString word = wordInputs[i]->text().trimmed().toLower();
        if (word.isEmpty()) {
            errorLabel1->setText(QString("❌ Word %1 is missing").arg(i + 1));
            return false;
        }
        words << word;
    }

    QString mnemonic = words.join(" ");
    QByteArray mnemonicBytes = mnemonic.toUtf8();

    // Validate using BIP39 checksum
    if (bip39_validate_mnemonic(mnemonicBytes.data()) != 0) {
        errorLabel1->setText("❌ Invalid seed phrase. Please check your words and try again.");
        return false;
    }

    errorLabel1->clear();
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

    stackedWidget->setCurrentIndex(1);  // Show progress page (page 2)
    QThread::msleep(100);
    QApplication::processEvents();

    if (performRestore()) {
        QString shortFingerprint = restoredFingerprint.left(10) + "..." + restoredFingerprint.right(10);
        successLabel->setText(QString(
            "Your identity has been restored!\n\n"
            "Fingerprint: <b>%1</b>\n\n"
            "Your cryptographic keys have been regenerated from your seed phrase.\n\n"
            "You can now start messaging.\n"
            "To allow others to find you, register a name via Settings menu.").arg(shortFingerprint));
        stackedWidget->setCurrentIndex(2);  // Show success page (page 3)
    } else {
        QMessageBox::critical(this, "Error",
                            "Failed to restore identity. Please check your seed phrase and try again.");
        stackedWidget->setCurrentIndex(0);  // Back to seed phrase page (page 1)
    }
}

bool RestoreIdentityDialog::performRestore()
{
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

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(mnemonicBytes.data(),
                                        passphraseBytes.data(),
                                        signing_seed,
                                        encryption_seed,
                                        NULL) != 0) {
        return false;
    }

    progressBar->setValue(2);
    statusLabel->setText("Regenerating cryptographic keys...");
    QApplication::processEvents();

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

    restoredFingerprint = QString::fromUtf8(fingerprint);

    progressBar->setValue(5);
    statusLabel->setText("Complete!");
    QApplication::processEvents();

    messenger_free(ctx);
    return true;
}

QString RestoreIdentityDialog::getRestoredFingerprint() const
{
    return restoredFingerprint;
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

    // Page 1: Seed Phrase
    if (titleLabel1) {
        titleLabel1->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (passphraseLabel) {
        passphraseLabel->setStyleSheet(QString("color: %1; font-size: 10pt;").arg(mutedColor));
    }
    if (errorLabel1) {
        errorLabel1->setStyleSheet(QString("color: %1; font-weight: bold;").arg(errorColor));
    }

    // Page 2: Progress
    if (titleLabel2) {
        titleLabel2->setStyleSheet(QString("font-size: 18pt; font-weight: bold; color: %1;").arg(primaryColor));
    }
    if (statusLabel) {
        statusLabel->setStyleSheet(QString("font-size: 12pt; color: %1;").arg(mutedColor));
    }

    // Page 3: Success
    if (titleLabel3) {
        titleLabel3->setStyleSheet(QString("font-size: 20pt; font-weight: bold; color: %1;").arg(successColor));
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

    if (restoreButton) restoreButton->setStyleSheet(buttonStyle + " font-size: 14pt;");
    if (finishButton) finishButton->setStyleSheet(buttonStyle + " font-size: 14pt;");
    if (pasteButton) pasteButton->setStyleSheet(buttonStyle);
}
