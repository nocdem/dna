#ifndef IDENTITYSELECTIONDIALOG_H
#define IDENTITYSELECTIONDIALOG_H

#include <QDialog>
#include <QListWidget>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDir>
#include <QMessageBox>

class IdentitySelectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit IdentitySelectionDialog(QWidget *parent = nullptr);

    // Get the selected identity name
    QString getSelectedIdentity() const;

private slots:
    void onSelectIdentity();
    void onCreateNewIdentity();
    void onRestoreIdentity();
    void onIdentityListSelectionChanged();

private:
    void setupUI();
    void loadIdentities();
    void applyTheme();
    QString scanForIdentities();

    QListWidget *identityList;
    QPushButton *selectButton;
    QPushButton *createButton;
    QPushButton *restoreButton;
    QLabel *titleLabel;
    QLabel *infoLabel;

    QString selectedIdentity;
};

#endif // IDENTITYSELECTIONDIALOG_H
