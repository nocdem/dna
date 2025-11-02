#include "SeedPhraseWidget.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QFont>
#include <QFrame>

SeedPhraseWidget::SeedPhraseWidget(QWidget *parent)
    : QWidget(parent)
    , gridLayout(nullptr)
    , copyButton(nullptr)
{
    setupUI();

    // Connect to theme manager
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &SeedPhraseWidget::applyTheme);

    applyTheme();
}

void SeedPhraseWidget::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Warning label
    QLabel *warningLabel = new QLabel(this);
    warningLabel->setText("⚠ WRITE DOWN THESE 24 WORDS IN ORDER\n"
                          "This is the ONLY way to recover your identity if your device is lost!");
    warningLabel->setAlignment(Qt::AlignCenter);
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet("QLabel { color: #ff4444; font-weight: bold; font-size: 12pt; padding: 10px; }");
    mainLayout->addWidget(warningLabel);

    // Grid frame for seed words
    QFrame *gridFrame = new QFrame(this);
    gridFrame->setFrameShape(QFrame::Box);
    gridFrame->setLineWidth(2);

    gridLayout = new QGridLayout(gridFrame);
    gridLayout->setSpacing(10);
    gridLayout->setContentsMargins(15, 15, 15, 15);

    // Create 24 word labels in 2 columns (12 rows each)
    QFont monoFont("Courier New", 11);
    monoFont.setBold(true);

    for (int i = 0; i < 24; i++) {
        int row = i % 12;
        int col = (i / 12) * 2;  // 0 or 2 (two columns with spacing)

        // Number label
        QLabel *numLabel = new QLabel(QString::number(i + 1) + ".", gridFrame);
        numLabel->setFont(monoFont);
        numLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        numLabel->setMinimumWidth(30);
        gridLayout->addWidget(numLabel, row, col);

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
    QLabel *securityWarning = new QLabel(this);
    securityWarning->setText("⚠ SECURITY WARNINGS:\n"
                            "• Never share this seed phrase with anyone\n"
                            "• Never store it digitally (no photos, no cloud storage)\n"
                            "• Store it in a secure physical location\n"
                            "• Anyone with this seed phrase can access your identity");
    securityWarning->setWordWrap(true);
    securityWarning->setStyleSheet("QLabel { color: #ff6666; font-size: 10pt; padding: 10px; }");
    mainLayout->addWidget(securityWarning);

    mainLayout->addStretch();
}

void SeedPhraseWidget::setSeedPhrase(const QString &phrase)
{
    seedPhrase = phrase;
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

    for (int i = 0; i < 24; i++) {
        if (i < words.size()) {
            wordLabels[i]->setText(words[i]);
        } else {
            wordLabels[i]->setText("________");
        }
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

void SeedPhraseWidget::applyTheme()
{
    CpunkTheme theme = ThemeManager::instance()->currentTheme();
    QString bgColor = (theme == THEME_CPUNK_IO) ? "#1a1a2e" : "#2c1810";
    QString textColor = (theme == THEME_CPUNK_IO) ? "#ffffff" : "#fff5e6";
    QString primaryColor = (theme == THEME_CPUNK_IO) ? "#00d9ff" : "#ff8c42";

    // Update grid frame style
    QFrame *gridFrame = findChild<QFrame*>();
    if (gridFrame) {
        gridFrame->setStyleSheet(QString("QFrame { background-color: %1; border: 2px solid %2; border-radius: 5px; }")
                                .arg(bgColor).arg(primaryColor));
    }

    // Update word labels
    for (int i = 0; i < 24; i++) {
        wordLabels[i]->setStyleSheet(QString("QLabel { color: %1; background: transparent; }")
                                    .arg(textColor));
    }

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
