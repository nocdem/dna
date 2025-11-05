/*
 * DNA Messenger - Migrate Identity Dialog
 * Phase 4: Fingerprint-First Identity Migration
 */

#include "MigrateIdentityDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QApplication>

MigrateIdentityDialog::MigrateIdentityDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(QString::fromUtf8("Migrate Identities - Phase 4"));
    setMinimumWidth(700);
    setMinimumHeight(500);

    setupUI();
    loadOldIdentities();

    // Apply current theme
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            [this]() {
        // Theme will be reapplied on next window show
    });
}

void MigrateIdentityDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Info label
    infoLabel = new QLabel(QString::fromUtf8(
        "Phase 4 introduces fingerprint-based identities.\n"
        "Select identities to migrate from old naming format to SHA3-512 fingerprints.\n\n"
        "Migration creates backups in: ~/.dna/backup_pre_migration/"
    ));
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);

    // Identity list
    QLabel *listLabel = new QLabel(QString::fromUtf8("Old-Style Identities:"));
    mainLayout->addWidget(listLabel);

    identityList = new QListWidget();
    identityList->setSelectionMode(QAbstractItemView::MultiSelection);
    mainLayout->addWidget(identityList);

    connect(identityList, &QListWidget::itemSelectionChanged,
            this, &MigrateIdentityDialog::onItemSelectionChanged);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8("Select identities to migrate"));
    mainLayout->addWidget(statusLabel);

    // Progress bar
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    // Log output
    QLabel *logLabel = new QLabel(QString::fromUtf8("Migration Log:"));
    mainLayout->addWidget(logLabel);

    logOutput = new QTextEdit();
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    mainLayout->addWidget(logOutput);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    cancelButton = new QPushButton(QString::fromUtf8("Cancel"));
    connect(cancelButton, &QPushButton::clicked, this, &MigrateIdentityDialog::onCancel);
    buttonLayout->addWidget(cancelButton);

    migrateButton = new QPushButton(QString::fromUtf8("Migrate Selected"));
    migrateButton->setEnabled(false);
    connect(migrateButton, &QPushButton::clicked, this, &MigrateIdentityDialog::onMigrateSelected);
    buttonLayout->addWidget(migrateButton);

    mainLayout->addLayout(buttonLayout);

    // Apply theme styles
    QString accentColor = ThemeManager::instance()->currentTheme() == THEME_CPUNK_CLUB ? "#FF8C42" : "#00D9FF";
    QString bgColor = "#0A1E21";
    QString textColor = accentColor;

    setStyleSheet(QString(
        "QDialog { background: %1; color: %2; font-family: 'Orbitron'; }"
        "QLabel { color: %2; font-size: 14px; }"
        "QListWidget { background: #0D3438; border: 2px solid %2; border-radius: 8px; "
        "              padding: 8px; color: %2; font-size: 13px; }"
        "QListWidget::item { border: 1px solid rgba(0, 217, 255, 0.3); border-radius: 5px; "
        "                    padding: 8px; margin: 3px; }"
        "QListWidget::item:selected { background: rgba(0, 217, 255, 0.3); font-weight: bold; }"
        "QTextEdit { background: #0D3438; border: 2px solid %2; border-radius: 8px; "
        "            padding: 8px; color: %2; font-family: monospace; font-size: 11px; }"
        "QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %2, stop:1 rgba(0, 217, 255, 0.7)); "
        "              color: white; border: 2px solid %2; border-radius: 10px; "
        "              padding: 12px 24px; font-size: 14px; font-weight: bold; }"
        "QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 217, 255, 0.9), stop:1 %2); }"
        "QPushButton:disabled { background: #444; color: #888; border: 2px solid #666; }"
        "QProgressBar { border: 2px solid %2; border-radius: 8px; text-align: center; "
        "               background: #0D3438; color: white; }"
        "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %2, stop:1 rgba(0, 217, 255, 0.7)); }"
    ).arg(bgColor).arg(textColor));
}

void MigrateIdentityDialog::loadOldIdentities() {
    char **identities = NULL;
    int count = 0;

    if (messenger_detect_old_identities(&identities, &count) != 0) {
        logOutput->append(QString::fromUtf8("Error: Failed to detect old identities"));
        return;
    }

    if (count == 0) {
        statusLabel->setText(QString::fromUtf8("✓ No old-style identities found. All identities are up to date!"));
        infoLabel->setText(QString::fromUtf8("All identities are already using the new fingerprint-based format."));
        migrateButton->setEnabled(false);
        return;
    }

    for (int i = 0; i < count; i++) {
        QString identity = QString::fromUtf8(identities[i]);

        // Compute fingerprint preview
        char fingerprint[129] = {0};
        QString fingerprintPreview;
        if (messenger_compute_identity_fingerprint(identities[i], fingerprint) == 0) {
            fingerprintPreview = QString("→ %1...").arg(QString::fromUtf8(fingerprint).left(16));
        } else {
            fingerprintPreview = QString::fromUtf8("→ [fingerprint computation failed]");
        }

        QString displayText = QString("%1 %2").arg(identity).arg(fingerprintPreview);
        QListWidgetItem *item = new QListWidgetItem(displayText);
        item->setData(Qt::UserRole, identity);  // Store identity name
        identityList->addItem(item);

        free(identities[i]);
    }
    free(identities);

    statusLabel->setText(QString::fromUtf8("Found %1 old-style identit%2")
                         .arg(count)
                         .arg(count == 1 ? "y" : "ies"));
}

void MigrateIdentityDialog::onItemSelectionChanged() {
    int selectedCount = identityList->selectedItems().count();
    migrateButton->setEnabled(selectedCount > 0);
    statusLabel->setText(QString::fromUtf8("%1 identit%2 selected")
                         .arg(selectedCount)
                         .arg(selectedCount == 1 ? "y" : "ies"));
}

void MigrateIdentityDialog::onMigrateSelected() {
    QList<QListWidgetItem*> selectedItems = identityList->selectedItems();
    if (selectedItems.isEmpty()) {
        return;
    }

    // Confirm migration
    int ret = QMessageBox::question(this,
        QString::fromUtf8("Confirm Migration"),
        QString::fromUtf8("Migrate %1 identit%2?\n\n"
                          "Backups will be created in:\n"
                          "~/.dna/backup_pre_migration/")
            .arg(selectedItems.count())
            .arg(selectedItems.count() == 1 ? "y" : "ies"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::Yes);

    if (ret != QMessageBox::Yes) {
        return;
    }

    // Disable UI during migration
    migrateButton->setEnabled(false);
    cancelButton->setEnabled(false);
    identityList->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setMaximum(selectedItems.count());
    progressBar->setValue(0);

    logOutput->clear();
    logOutput->append(QString::fromUtf8("=== Starting Migration ===\n"));

    int successCount = 0;
    int failCount = 0;

    for (int i = 0; i < selectedItems.count(); i++) {
        QString oldName = selectedItems[i]->data(Qt::UserRole).toString();
        logOutput->append(QString::fromUtf8("Migrating: %1...").arg(oldName));
        QApplication::processEvents();  // Update UI

        migrateIdentity(oldName);
        progressBar->setValue(i + 1);
        QApplication::processEvents();
    }

    // Re-enable UI
    migrateButton->setEnabled(true);
    cancelButton->setEnabled(true);
    identityList->setEnabled(true);

    logOutput->append(QString::fromUtf8("\n=== Migration Complete ==="));
    logOutput->append(QString::fromUtf8("Please restart DNA Messenger to use the new fingerprint-based identities."));

    statusLabel->setText(QString::fromUtf8("Migration complete! Restart required."));

    // Show completion dialog
    QMessageBox::information(this,
        QString::fromUtf8("Migration Complete"),
        QString::fromUtf8("Identity migration complete!\n\n"
                          "Please restart DNA Messenger to use the new fingerprint-based identities.\n\n"
                          "Backups are stored in:\n"
                          "~/.dna/backup_pre_migration/"));

    accept();  // Close dialog
}

void MigrateIdentityDialog::migrateIdentity(const QString &oldName) {
    char fingerprint[129] = {0};

    int ret = messenger_migrate_identity_files(oldName.toUtf8().constData(), fingerprint);

    if (ret == 0) {
        logOutput->append(QString::fromUtf8("  ✓ Success: %1 → %2")
                          .arg(oldName)
                          .arg(QString::fromUtf8(fingerprint).left(16) + "..."));
    } else {
        logOutput->append(QString::fromUtf8("  ✗ Failed: %1 (error code: %2)")
                          .arg(oldName)
                          .arg(ret));
    }
}

void MigrateIdentityDialog::onCancel() {
    reject();
}
