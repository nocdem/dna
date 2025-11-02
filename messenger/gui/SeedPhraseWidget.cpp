#include "SeedPhraseWidget.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QFont>
#include <QFrame>
#include <cstdio>

SeedPhraseWidget::SeedPhraseWidget(QWidget *parent)
    : QWidget(parent)
    , gridLayout(nullptr)
    , copyButton(nullptr)
{
    printf("[DEBUG SEED] Constructor: parent=%p, parent visible=%d\n",
           parent, parent ? parent->isVisible() : -1);

    setupUI();

    // Connect to theme manager
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &SeedPhraseWidget::applyTheme);

    applyTheme();

    printf("[DEBUG SEED] Constructor done: this visible=%d\n", this->isVisible());
}

void SeedPhraseWidget::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Warning label
    warningLabel = new QLabel(this);
    warningLabel->setText("⚠ WRITE DOWN THESE 24 WORDS IN ORDER\n"
                          "This is the ONLY way to recover your identity if your device is lost!");
    warningLabel->setAlignment(Qt::AlignCenter);
    warningLabel->setWordWrap(true);
    mainLayout->addWidget(warningLabel);

    // Grid frame for seed words
    QFrame *gridFrame = new QFrame(this);
    gridFrame->setFrameShape(QFrame::Box);
    gridFrame->setLineWidth(2);

    gridLayout = new QGridLayout(gridFrame);
    gridLayout->setSpacing(10);
    gridLayout->setContentsMargins(15, 15, 15, 15);

    // Create 24 word labels in 2 columns (12 rows each)
    QFont monoFont("Courier New", 14);
    monoFont.setBold(true);

    for (int i = 0; i < 24; i++) {
        int row = i % 12;
        int col = (i / 12) * 2;  // 0 or 2 (two columns with spacing)

        // Number label
        numLabels[i] = new QLabel(QString::number(i + 1) + ".", gridFrame);
        numLabels[i]->setFont(monoFont);
        numLabels[i]->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        numLabels[i]->setMinimumWidth(30);
        gridLayout->addWidget(numLabels[i], row, col);

        // Word label
        wordLabels[i] = new QLabel("________", gridFrame);
        wordLabels[i]->setFont(monoFont);
        wordLabels[i]->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        wordLabels[i]->setMinimumWidth(100);
        wordLabels[i]->setTextInteractionFlags(Qt::TextSelectableByMouse);
        gridLayout->addWidget(wordLabels[i], row, col + 1);
    }

    mainLayout->addWidget(gridFrame);

    // Copy button
    copyButton = new QPushButton("📋 Copy to Clipboard", this);
    copyButton->setMinimumHeight(40);
    copyButton->setCursor(Qt::PointingHandCursor);
    connect(copyButton, &QPushButton::clicked, this, &SeedPhraseWidget::onCopyToClipboard);
    mainLayout->addWidget(copyButton);

    // Additional warnings
    securityWarning = new QLabel(this);
    securityWarning->setText("⚠ SECURITY WARNINGS:\n"
                            "• Never share this seed phrase with anyone\n"
                            "• Never store it digitally (no photos, no cloud storage)\n"
                            "• Store it in a secure physical location\n"
                            "• Anyone with this seed phrase can access your identity");
    securityWarning->setWordWrap(true);
    mainLayout->addWidget(securityWarning);

    mainLayout->addStretch();
}

void SeedPhraseWidget::setSeedPhrase(const QString &phrase)
{
    seedPhrase = phrase;
    printf("[DEBUG SEED] setSeedPhrase called with: '%s' (length: %d)\n",
           phrase.toUtf8().constData(), phrase.length());
    updateDisplay();
}

QString SeedPhraseWidget::getSeedPhrase() const
{
    return seedPhrase;
}

void SeedPhraseWidget::setShowCopyButton(bool show)
{
    if (copyButton) {
        copyButton->setVisible(show);
    }
}

void SeedPhraseWidget::updateDisplay()
{
    QStringList words = seedPhrase.split(' ', Qt::SkipEmptyParts);
    printf("[DEBUG SEED] updateDisplay: seedPhrase='%s', word count=%d\n",
           seedPhrase.toUtf8().constData(), words.size());

    for (int i = 0; i < 24; i++) {
        if (i < words.size()) {
            wordLabels[i]->setText(words[i]);
        } else {
            wordLabels[i]->setText("________");
        }
    }

    // Re-apply theme to ensure visibility and styling
    applyTheme();

    // Debug check visibility after applyTheme
    for (int i = 0; i < 24; i++) {
        printf("[DEBUG SEED] wordLabels[%d] = '%s', visible=%d, size=%dx%d\n",
               i, wordLabels[i]->text().toUtf8().constData(),
               wordLabels[i]->isVisible(),
               wordLabels[i]->width(), wordLabels[i]->height());
    }
}

void SeedPhraseWidget::onCopyToClipboard()
{
    if (seedPhrase.isEmpty()) {
        QMessageBox::warning(this, "Error", "No seed phrase to copy!");
        return;
    }

    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(seedPhrase);

    QMessageBox::information(this, "Copied",
                            "Seed phrase copied to clipboard!\n\n"
                            "⚠ Remember to clear your clipboard after saving the seed phrase securely.\n"
                            "⚠ Do not paste it into any digital storage.");

    emit seedPhraseCopied();
}

void SeedPhraseWidget::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    printf("[DEBUG SEED] ===== showEvent() CALLED - Widget NOW VISIBLE! =====\n");
    // Re-apply theme now that parent is visible
    applyTheme();
}

void SeedPhraseWidget::applyTheme()
{
    printf("[DEBUG SEED] ===== applyTheme() CALLED =====\n");

    CpunkTheme theme = ThemeManager::instance()->currentTheme();
    QString bgColor = (theme == THEME_CPUNK_IO) ? "#1a1a2e" : "#2c1810";
    QString textColor = (theme == THEME_CPUNK_IO) ? "#ffffff" : "#fff5e6";
    QString primaryColor = (theme == THEME_CPUNK_IO) ? "#00d9ff" : "#ff8c42";

    // Update warning labels - BRIGHT YELLOW/ORANGE for visibility
    if (warningLabel) {
        warningLabel->setStyleSheet(QString("color: #FFAA00; font-weight: bold; font-size: 14pt; padding: 10px;"));
        warningLabel->setVisible(true);
        printf("[DEBUG SEED] warningLabel visible set to: %d\n", warningLabel->isVisible());
    }
    if (securityWarning) {
        securityWarning->setStyleSheet(QString("color: #FFAA00; font-size: 11pt; padding: 10px;"));
        securityWarning->setVisible(true);
    }

    // Update grid frame style - NO QLabel selector that might hide children
    QFrame *gridFrame = findChild<QFrame*>();
    if (gridFrame) {
        gridFrame->setStyleSheet(QString("background-color: %1; border: 2px solid %2; border-radius: 5px;")
                                .arg(bgColor).arg(primaryColor));
        gridFrame->setVisible(true);
    }

    // Update number labels - BRIGHT and explicitly visible
    for (int i = 0; i < 24; i++) {
        if (numLabels[i]) {
            numLabels[i]->setStyleSheet(QString("color: #CCCCCC; font-size: 14pt; font-weight: bold;"));
            numLabels[i]->setVisible(true);
            printf("[DEBUG SEED] numLabels[%d] setVisible(true) -> isVisible=%d\n", i, numLabels[i]->isVisible());
        }
    }

    // Update word labels - MAXIMUM BRIGHTNESS and explicitly visible
    for (int i = 0; i < 24; i++) {
        wordLabels[i]->setStyleSheet(QString("color: #FFFFFF; font-size: 14pt; font-weight: bold;"));
        wordLabels[i]->setVisible(true);
        printf("[DEBUG SEED] wordLabels[%d] setVisible(true) -> isVisible=%d\n", i, wordLabels[i]->isVisible());
    }

    printf("[DEBUG SEED] ===== applyTheme() DONE =====\n");

    // Update copy button
    if (copyButton) {
        copyButton->setStyleSheet(QString(
            "QPushButton {"
            "  background-color: %1;"
            "  color: %2;"
            "  border: none;"
            "  border-radius: 5px;"
            "  font-weight: bold;"
            "  font-size: 12pt;"
            "}"
            "QPushButton:hover {"
            "  background-color: %3;"
            "}"
        ).arg(primaryColor).arg(bgColor).arg(primaryColor + "cc"));
    }
}
