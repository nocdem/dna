#include "SeedPhraseWidget.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QFont>
#include <QFrame>
#include <QPalette>
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

    // Warning label - BRIGHT ORANGE, NO STYLESHEET
    warningLabel = new QLabel("⚠ WRITE DOWN THESE 24 WORDS IN ORDER\n"
                          "This is the ONLY way to recover your identity if your device is lost!", this);
    warningLabel->setAlignment(Qt::AlignCenter);
    warningLabel->setWordWrap(true);
    QPalette warnPal = warningLabel->palette();
    warnPal.setColor(QPalette::WindowText, QColor(255, 170, 0)); // Bright orange
    warningLabel->setPalette(warnPal);
    QFont warnFont = warningLabel->font();
    warnFont.setPointSize(14);
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
    gridLayout->setSpacing(10);
    gridLayout->setContentsMargins(15, 15, 15, 15);

    // Create 24 word labels - USE PALETTE, NOT STYLESHEET
    QFont monoFont("Courier New", 12);
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

    // Make grid frame expand to show all content
    gridFrame->setMinimumSize(600, 400);

    mainLayout->addWidget(gridFrame);

    // Copy button
    copyButton = new QPushButton("📋 Copy to Clipboard", this);
    copyButton->setMinimumHeight(40);
    copyButton->setCursor(Qt::PointingHandCursor);
    connect(copyButton, &QPushButton::clicked, this, &SeedPhraseWidget::onCopyToClipboard);
    mainLayout->addWidget(copyButton);

    // Security warnings - BRIGHT ORANGE via palette
    securityWarning = new QLabel("⚠ SECURITY WARNINGS:\n"
                            "• Never share this seed phrase with anyone\n"
                            "• Never store it digitally (no photos, no cloud storage)\n"
                            "• Store it in a secure physical location\n"
                            "• Anyone with this seed phrase can access your identity", this);
    securityWarning->setWordWrap(true);
    QPalette secPal = securityWarning->palette();
    secPal.setColor(QPalette::WindowText, QColor(255, 170, 0));
    securityWarning->setPalette(secPal);
    QFont secFont = securityWarning->font();
    secFont.setPointSize(11);
    securityWarning->setFont(secFont);
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
    printf("[DEBUG SEED] ===== applyTheme() CALLED - forcing update() =====\n");
    // Force a repaint
    update();

    // Debug first word label
    if (wordLabels[0]) {
        QPalette pal = wordLabels[0]->palette();
        printf("[DEBUG SEED] wordLabels[0]: text='%s', visible=%d\n",
               wordLabels[0]->text().toUtf8().constData(),
               wordLabels[0]->isVisible());
        printf("  palette WindowText=rgba(%d,%d,%d,%d)\n",
               pal.color(QPalette::WindowText).red(),
               pal.color(QPalette::WindowText).green(),
               pal.color(QPalette::WindowText).blue(),
               pal.color(QPalette::WindowText).alpha());
    }
}
