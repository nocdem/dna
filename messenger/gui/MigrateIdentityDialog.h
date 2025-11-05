/*
 * DNA Messenger - Migrate Identity Dialog
 * Phase 4: Fingerprint-First Identity Migration
 */

#ifndef MIGRATEIDENTITYDIALOG_H
#define MIGRATEIDENTITYDIALOG_H

#include <QDialog>
#include <QListWidget>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QProgressBar>
#include <QTextEdit>

extern "C" {
    #include "../messenger.h"
}

class MigrateIdentityDialog : public QDialog {
    Q_OBJECT

public:
    explicit MigrateIdentityDialog(QWidget *parent = nullptr);
    ~MigrateIdentityDialog() override = default;

private slots:
    void onMigrateSelected();
    void onCancel();
    void onItemSelectionChanged();

private:
    void setupUI();
    void loadOldIdentities();
    void migrateIdentity(const QString &oldName);

    QListWidget *identityList;
    QPushButton *migrateButton;
    QPushButton *cancelButton;
    QLabel *infoLabel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    QTextEdit *logOutput;
};

#endif // MIGRATEIDENTITYDIALOG_H
