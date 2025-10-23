/*
 * ReceiveDialog.cpp - Wallet Address Display Implementation
 */

#include "ReceiveDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QPainter>
#include <QTimer>
#include <cstring>

ReceiveDialog::ReceiveDialog(const cellframe_wallet_t *wallet, QWidget *parent)
    : QDialog(parent) {

    if (wallet) {
        memcpy(&m_wallet, wallet, sizeof(cellframe_wallet_t));
    } else {
        memset(&m_wallet, 0, sizeof(cellframe_wallet_t));
    }

    setupUI();

    // Connect to theme changes
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &ReceiveDialog::onThemeChanged);

    // Apply current theme
    applyTheme(ThemeManager::instance()->currentTheme());

    setWindowTitle("Receive Tokens");
    resize(500, 600);
    setMinimumWidth(450);
}

ReceiveDialog::~ReceiveDialog() {
}

void ReceiveDialog::setupUI() {
    mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(30, 30, 30, 30);

    // Title
    titleLabel = new QLabel("Receive Tokens", this);
    QFont titleFont;
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    // Wallet name
    walletNameLabel = new QLabel(QString::fromUtf8("Wallet: %1").arg(m_wallet.name), this);
    QFont walletFont;
    walletFont.setPointSize(12);
    walletNameLabel->setFont(walletFont);
    walletNameLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(walletNameLabel);

    // Separator
    QFrame *separator1 = new QFrame(this);
    separator1->setFrameShape(QFrame::HLine);
    separator1->setFrameShadow(QFrame::Sunken);
    mainLayout->addWidget(separator1);

    // QR Code placeholder
    qrCodeLabel = new QLabel(this);
    qrCodeLabel->setAlignment(Qt::AlignCenter);
    qrCodeLabel->setMinimumSize(300, 300);
    qrCodeLabel->setMaximumSize(300, 300);
    qrCodeLabel->setStyleSheet("border: 2px solid #888; background: white; border-radius: 10px;");

    // Generate QR code
    generateQRCode();

    // Center the QR code
    QHBoxLayout *qrLayout = new QHBoxLayout();
    qrLayout->addStretch();
    qrLayout->addWidget(qrCodeLabel);
    qrLayout->addStretch();
    mainLayout->addLayout(qrLayout);

    // Address label
    QLabel *addressTitleLabel = new QLabel("Your Wallet Address:", this);
    QFont addressTitleFont;
    addressTitleFont.setPointSize(11);
    addressTitleFont.setBold(true);
    addressTitleLabel->setFont(addressTitleFont);
    mainLayout->addWidget(addressTitleLabel);

    // Address input (read-only)
    addressLineEdit = new QLineEdit(QString::fromUtf8(m_wallet.address), this);
    addressLineEdit->setReadOnly(true);
    addressLineEdit->setAlignment(Qt::AlignCenter);
    QFont addressFont;
    addressFont.setPointSize(10);
    addressFont.setFamily("monospace");
    addressLineEdit->setFont(addressFont);
    mainLayout->addWidget(addressLineEdit);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);

    copyButton = new QPushButton("📋 Copy Address", this);
    closeButton = new QPushButton("Close", this);

    QFont buttonFont;
    buttonFont.setPointSize(11);
    buttonFont.setBold(true);
    copyButton->setFont(buttonFont);
    closeButton->setFont(buttonFont);

    copyButton->setMinimumHeight(45);
    closeButton->setMinimumHeight(45);

    copyButton->setCursor(Qt::PointingHandCursor);
    closeButton->setCursor(Qt::PointingHandCursor);

    buttonLayout->addWidget(copyButton);
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);

    // Connect signals
    connect(copyButton, &QPushButton::clicked, this, &ReceiveDialog::onCopyAddress);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);

    mainLayout->addStretch();
}

void ReceiveDialog::generateQRCode() {
    // Create a simple placeholder for QR code
    // TODO: Integrate real QR code library (like qrencode or Qt's QR generator)

    QPixmap qrPixmap(280, 280);
    qrPixmap.fill(Qt::white);

    QPainter painter(&qrPixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    // Draw placeholder pattern
    painter.setPen(Qt::NoPen);
    painter.setBrush(Qt::black);

    // Simple grid pattern as placeholder
    int cellSize = 10;
    for (int i = 0; i < 28; i++) {
        for (int j = 0; j < 28; j++) {
            // Create a pattern based on address characters
            if ((i + j) % 3 == 0 || (i * j) % 7 == 0) {
                painter.drawRect(i * cellSize, j * cellSize, cellSize, cellSize);
            }
        }
    }

    // Draw corner markers (like real QR codes)
    painter.setBrush(Qt::black);
    int cornerSize = 70;
    // Top-left
    painter.drawRect(0, 0, cornerSize, cornerSize);
    painter.setBrush(Qt::white);
    painter.drawRect(10, 10, cornerSize - 20, cornerSize - 20);
    painter.setBrush(Qt::black);
    painter.drawRect(20, 20, cornerSize - 40, cornerSize - 40);

    // Top-right
    painter.setBrush(Qt::black);
    painter.drawRect(280 - cornerSize, 0, cornerSize, cornerSize);
    painter.setBrush(Qt::white);
    painter.drawRect(280 - cornerSize + 10, 10, cornerSize - 20, cornerSize - 20);
    painter.setBrush(Qt::black);
    painter.drawRect(280 - cornerSize + 20, 20, cornerSize - 40, cornerSize - 40);

    // Bottom-left
    painter.setBrush(Qt::black);
    painter.drawRect(0, 280 - cornerSize, cornerSize, cornerSize);
    painter.setBrush(Qt::white);
    painter.drawRect(10, 280 - cornerSize + 10, cornerSize - 20, cornerSize - 20);
    painter.setBrush(Qt::black);
    painter.drawRect(20, 280 - cornerSize + 20, cornerSize - 40, cornerSize - 40);

    // Draw "QR" text in center
    painter.setPen(Qt::gray);
    QFont font;
    font.setPointSize(8);
    font.setItalic(true);
    painter.setFont(font);
    painter.drawText(QRect(100, 130, 80, 20), Qt::AlignCenter, "QR Code");
    painter.drawText(QRect(90, 145, 100, 20), Qt::AlignCenter, "(Placeholder)");

    painter.end();

    qrCodeLabel->setPixmap(qrPixmap);
}

void ReceiveDialog::onCopyAddress() {
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(QString::fromUtf8(m_wallet.address));

    // Visual feedback
    copyButton->setText("✓ Copied!");
    QTimer::singleShot(2000, this, [this]() {
        copyButton->setText("📋 Copy Address");
    });
}

void ReceiveDialog::applyTheme(CpunkTheme theme) {
    // Use EXACT colors from cpunk_themes.h
    QString accentColor = (theme == THEME_CPUNK_IO) ? CPUNK_IO_PRIMARY : CPUNK_CLUB_PRIMARY;
    QString bgColor = (theme == THEME_CPUNK_IO) ? CPUNK_IO_BACKGROUND : CPUNK_CLUB_BACKGROUND;
    QString textColor = (theme == THEME_CPUNK_IO) ? CPUNK_IO_TEXT : CPUNK_CLUB_TEXT;

    // Dialog background
    setStyleSheet(QString(
        "QDialog {"
        "    background: %1;"
        "}"
        "QLabel {"
        "    color: %2;"
        "}"
    ).arg(bgColor).arg(textColor));

    // Address input
    addressLineEdit->setStyleSheet(QString(
        "QLineEdit {"
        "    background: %1;"
        "    color: %2;"
        "    border: 2px solid %3;"
        "    border-radius: 5px;"
        "    padding: 10px;"
        "    selection-background-color: %3;"
        "}"
    ).arg(bgColor + "cc").arg(textColor).arg(accentColor));

    // Buttons
    QString buttonStyle = QString(
        "QPushButton {"
        "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "        stop:0 %1, stop:1 %2);"
        "    color: white;"
        "    border: 2px solid %1;"
        "    border-radius: 8px;"
        "    padding: 10px;"
        "}"
        "QPushButton:hover {"
        "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "        stop:0 %2, stop:1 %1);"
        "    border: 2px solid white;"
        "}"
        "QPushButton:pressed {"
        "    background: %2;"
        "}"
    ).arg(accentColor).arg(accentColor + "cc");

    copyButton->setStyleSheet(buttonStyle);

    QString closeButtonStyle = QString(
        "QPushButton {"
        "    background: #555;"
        "    color: white;"
        "    border: 2px solid #777;"
        "    border-radius: 8px;"
        "    padding: 10px;"
        "}"
        "QPushButton:hover {"
        "    background: #777;"
        "    border: 2px solid white;"
        "}"
        "QPushButton:pressed {"
        "    background: #333;"
        "}"
    );
    closeButton->setStyleSheet(closeButtonStyle);
}

void ReceiveDialog::onThemeChanged(CpunkTheme theme) {
    applyTheme(theme);
}
