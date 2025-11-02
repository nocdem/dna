#include "SeedPhraseWidget.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QFont>
#include <QFrame>
#include <QPalette>
#include <QSizePolicy>

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
    mainLayout->setContentsMargins(15, 10, 15, 10);
    mainLayout->setSpacing(8);

    // Warning label - BRIGHT ORANGE, NO STYLESHEET
    warningLabel = new QLabel("⚠ WRITE DOWN THESE 24 WORDS IN ORDER\n"
                          "This is the ONLY way to recover your identity if your device is lost!", this);
    warningLabel->setAlignment(Qt::AlignCenter);
    warningLabel->setWordWrap(true);
    QPalette warnPal = warningLabel->palette();
    warnPal.setColor(QPalette::WindowText, QColor(255, 170, 0)); // Bright orange
    warningLabel->setPalette(warnPal);
    QFont warnFont = warningLabel->font();
    warnFont.setPointSize(10);
    warnFont.setBold(true);
    warningLabel->setFont(warnFont);
    mainLayout->addWidget(warningLabel);

    // Grid frame for seed words - SIMPLE, NO FANCY STYLING
    QFrame *gridFrame = new QFrame(this);
    gridFrame->setFrameShape(QFrame::Box);
    gridFrame->setLineWidth(2);

    // Set gridFrame palette DIRECTLY
    QPalette framePal = gridFrame->palette();
    framePal.setColor(QPalette::Window, QColor(26, 26, 46)); // Dark background
    framePal.setColor(QPalette::Base, QColor(26, 26, 46));
    gridFrame->setPalette(framePal);
    gridFrame->setAutoFillBackground(true);

    gridLayout = new QGridLayout(gridFrame);
    gridLayout->setSpacing(6);
    gridLayout->setContentsMargins(10, 10, 10, 10);

    // Create 24 word labels - USE PALETTE, NOT STYLESHEET
    QFont monoFont("Courier New", 7);
    monoFont.setBold(true);

    for (int i = 0; i < 24; i++) {
        int row = i % 12;
        int col = (i / 12) * 2;

        // Number label - LIGHT GRAY via palette
        numLabels[i] = new QLabel(QString::number(i + 1) + ".", gridFrame);
        numLabels[i]->setFont(monoFont);
        numLabels[i]->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        numLabels[i]->setAutoFillBackground(false);
        QPalette numPal = numLabels[i]->palette();
        numPal.setColor(QPalette::WindowText, QColor(204, 204, 204));
        numLabels[i]->setPalette(numPal);
        gridLayout->addWidget(numLabels[i], row, col);

        // Word label - BRIGHT WHITE via palette
        wordLabels[i] = new QLabel("________", gridFrame);
        wordLabels[i]->setFont(monoFont);
        wordLabels[i]->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        wordLabels[i]->setAutoFillBackground(false);
        wordLabels[i]->setTextInteractionFlags(Qt::TextSelectableByMouse);
        QPalette wordPal = wordLabels[i]->palette();
        wordPal.setColor(QPalette::WindowText, QColor(255, 255, 255));
        wordLabels[i]->setPalette(wordPal);
        gridLayout->addWidget(wordLabels[i], row, col + 1);
    }

    // Make grid frame smaller to fit in narrower dialog - 7pt font needs less space
    gridFrame->setMinimumSize(189, 300);
    gridFrame->setMaximumHeight(300);
    gridFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    mainLayout->addWidget(gridFrame, 0, Qt::AlignTop);
    mainLayout->addSpacing(10); // Add space before copy button

    // Copy button - COMPACT
    copyButton = new QPushButton("📋 Copy to Clipboard", this);
    copyButton->setMinimumHeight(30);
    copyButton->setCursor(Qt::PointingHandCursor);
    connect(copyButton, &QPushButton::clicked, this, &SeedPhraseWidget::onCopyToClipboard);
    mainLayout->addWidget(copyButton);
    mainLayout->addSpacing(5); // Small space before security warning

    // Security warnings - BRIGHT ORANGE via palette, VERY COMPACT
    securityWarning = new QLabel("⚠ Never share • Secure offline storage only", this);
    securityWarning->setAlignment(Qt::AlignCenter);
    QPalette secPal = securityWarning->palette();
    secPal.setColor(QPalette::WindowText, QColor(255, 170, 0));
    securityWarning->setPalette(secPal);
    QFont secFont = securityWarning->font();
    secFont.setPointSize(7);
    securityWarning->setFont(secFont);
    mainLayout->addWidget(securityWarning);
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

    // Re-apply theme to ensure visibility and styling
    applyTheme();
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
    // Re-apply theme now that parent is visible
    applyTheme();
}

void SeedPhraseWidget::applyTheme()
{
    // Force a repaint
    update();
}
