#include "IdentitySelectionDialog.h"
#include "CreateIdentityDialog.h"
#include "RestoreIdentityDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QFileInfo>
#include <QFile>
#include <QStandardPaths>
#include <QDebug>

IdentitySelectionDialog::IdentitySelectionDialog(QWidget *parent)
    : QDialog(parent)
    , identityList(nullptr)
    , selectButton(nullptr)
    , createButton(nullptr)
    , restoreButton(nullptr)
    , titleLabel(nullptr)
    , infoLabel(nullptr)
{
    setWindowTitle("DNA Messenger - Select Identity");
    setMinimumSize(500, 400);

    setupUI();
    loadIdentities();
    applyTheme();

    // Connect to theme manager
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &IdentitySelectionDialog::applyTheme);
}

void IdentitySelectionDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    mainLayout->setSpacing(20);

    // Title
    titleLabel = new QLabel("Welcome to DNA Messenger", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("font-size: 20pt; font-weight: bold;");
    mainLayout->addWidget(titleLabel);

    // Info label
    infoLabel = new QLabel("Select an existing identity or create a new one:", this);
    infoLabel->setAlignment(Qt::AlignCenter);
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);

    // Identity list
    identityList = new QListWidget(this);
    identityList->setMinimumHeight(150);
    identityList->setStyleSheet("QListWidget { font-size: 14pt; padding: 10px; }");
    connect(identityList, &QListWidget::itemSelectionChanged,
            this, &IdentitySelectionDialog::onIdentityListSelectionChanged);
    connect(identityList, &QListWidget::itemDoubleClicked,
            this, [this]() { onSelectIdentity(); });
    mainLayout->addWidget(identityList);

    // Button layout
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);

    selectButton = new QPushButton("Select Identity", this);
    selectButton->setMinimumHeight(45);
    selectButton->setEnabled(false);
    selectButton->setCursor(Qt::PointingHandCursor);
    connect(selectButton, &QPushButton::clicked, this, &IdentitySelectionDialog::onSelectIdentity);
    buttonLayout->addWidget(selectButton);

    createButton = new QPushButton("Create New Identity", this);
    createButton->setMinimumHeight(45);
    createButton->setCursor(Qt::PointingHandCursor);
    connect(createButton, &QPushButton::clicked, this, &IdentitySelectionDialog::onCreateNewIdentity);
    buttonLayout->addWidget(createButton);

    restoreButton = new QPushButton("Restore from Seed", this);
    restoreButton->setMinimumHeight(45);
    restoreButton->setCursor(Qt::PointingHandCursor);
    connect(restoreButton, &QPushButton::clicked, this, &IdentitySelectionDialog::onRestoreIdentity);
    buttonLayout->addWidget(restoreButton);

    mainLayout->addLayout(buttonLayout);

    // Help text
    helpLabel = new QLabel("If this is your first time, click \"Create New Identity\" to get started.", this);
    helpLabel->setAlignment(Qt::AlignCenter);
    helpLabel->setWordWrap(true);
    mainLayout->addWidget(helpLabel);
}

void IdentitySelectionDialog::loadIdentities()
{
    identityList->clear();

    QString homeDir = QDir::homePath();
    QString dnaDir = homeDir + "/.dna";

    QDir dir(dnaDir);
    if (!dir.exists()) {
        infoLabel->setText("No identities found. Create a new identity to get started.");
        return;
    }

    // Scan for *.dsa files
    QStringList filters;
    filters << "*.dsa";
    QFileInfoList files = dir.entryInfoList(filters, QDir::Files);

    if (files.isEmpty()) {
        infoLabel->setText("No identities found. Create a new identity to get started.");
        return;
    }

    // Extract identity names and verify both key files exist
    QStringList validIdentities;
    QStringList incompleteIdentities;

    for (const QFileInfo &fileInfo : files) {
        QString filename = fileInfo.fileName();
        // Remove ".dsa" suffix (4 characters)
        QString identity = filename.left(filename.length() - 4);

        // Verify both key files exist
        QString dilithiumKey = dnaDir + "/" + identity + ".dsa";
        QString kyberKey = dnaDir + "/" + identity + ".kem";

        if (QFile::exists(dilithiumKey) && QFile::exists(kyberKey)) {
            validIdentities << identity;
            identityList->addItem(identity);
        } else {
            incompleteIdentities << identity;
            qWarning() << "[Identity] Incomplete identity found:" << identity
                      << "(missing" << (QFile::exists(kyberKey) ? "dilithium3" : "kyber512") << "key)";
        }
    }

    // Show warning if incomplete identities found
    if (!incompleteIdentities.isEmpty()) {
        QString warning = QString("Warning: %1 incomplete identit%2 found: %3\n")
            .arg(incompleteIdentities.count())
            .arg(incompleteIdentities.count() == 1 ? "y" : "ies")
            .arg(incompleteIdentities.join(", "));
        qWarning() << warning;
    }

    if (validIdentities.isEmpty()) {
        infoLabel->setText("No complete identities found. Create a new identity to get started.");
        return;
    }

    if (identityList->count() > 0) {
        infoLabel->setText(QString("Found %1 identit%2. Select one to continue:")
                          .arg(identityList->count())
                          .arg(identityList->count() == 1 ? "y" : "ies"));
        identityList->setCurrentRow(0);
    }
}

void IdentitySelectionDialog::onIdentityListSelectionChanged()
{
    bool hasSelection = (identityList->currentItem() != nullptr);
    selectButton->setEnabled(hasSelection);
}

void IdentitySelectionDialog::onSelectIdentity()
{
    QListWidgetItem *item = identityList->currentItem();
    if (!item) {
        QMessageBox::warning(this, "No Selection", "Please select an identity or create a new one.");
        return;
    }

    selectedIdentity = item->text();
    accept();
}

void IdentitySelectionDialog::onCreateNewIdentity()
{
    CreateIdentityDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        QString newIdentity = dialog.getCreatedIdentity();
        if (!newIdentity.isEmpty()) {
            selectedIdentity = newIdentity;
            accept();
        }
    }
}

void IdentitySelectionDialog::onRestoreIdentity()
{
    RestoreIdentityDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        QString restoredIdentity = dialog.getRestoredIdentity();
        if (!restoredIdentity.isEmpty()) {
            selectedIdentity = restoredIdentity;
            accept();
        }
    }
}

QString IdentitySelectionDialog::getSelectedIdentity() const
{
    return selectedIdentity;
}

void IdentitySelectionDialog::applyTheme()
{
    CpunkTheme theme = ThemeManager::instance()->currentTheme();
    QString bgColor = (theme == THEME_CPUNK_IO) ? "#0f0f1e" : "#1a0f08";
    QString textColor = (theme == THEME_CPUNK_IO) ? "#ffffff" : "#fff5e6";
    QString mutedColor = (theme == THEME_CPUNK_IO) ? "#a0a0b0" : "#d4a574";
    QString primaryColor = (theme == THEME_CPUNK_IO) ? "#00d9ff" : "#ff8c42";
    QString hoverColor = (theme == THEME_CPUNK_IO) ? "#00b8d4" : "#ff7028";

    setStyleSheet(QString("QDialog { background-color: %1; color: %2; }").arg(bgColor).arg(textColor));

    if (titleLabel) {
        titleLabel->setStyleSheet(QString("font-size: 20pt; font-weight: bold; color: %1;").arg(primaryColor));
    }

    if (infoLabel) {
        infoLabel->setStyleSheet(QString("color: %1;").arg(textColor));
    }

    if (helpLabel) {
        helpLabel->setStyleSheet(QString("color: %1; font-size: 10pt;").arg(mutedColor));
    }

    if (identityList) {
        identityList->setStyleSheet(QString(
            "QListWidget {"
            "  background-color: %1;"
            "  color: %2;"
            "  border: 2px solid %3;"
            "  border-radius: 5px;"
            "  font-size: 14pt;"
            "  padding: 10px;"
            "}"
            "QListWidget::item:selected {"
            "  background-color: %3;"
            "  color: %1;"
            "}"
        ).arg(bgColor).arg(textColor).arg(primaryColor));
    }

    // Style buttons
    QString buttonStyle = QString(
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
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    ).arg(primaryColor).arg(bgColor).arg(hoverColor);

    if (selectButton) selectButton->setStyleSheet(buttonStyle);
    if (createButton) createButton->setStyleSheet(buttonStyle);
    if (restoreButton) restoreButton->setStyleSheet(buttonStyle);
}
