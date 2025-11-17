#ifndef RESTOREIDENTITYDIALOG_H
#define RESTOREIDENTITYDIALOG_H

#include <QDialog>
#include <QStackedWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QGridLayout>
#include <QMessageBox>
#include <QCompleter>
#include <QStringListModel>

class RestoreIdentityDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RestoreIdentityDialog(QWidget *parent = nullptr);

    // Get the restored identity fingerprint
    QString getRestoredFingerprint() const;

private slots:
    void onRestoreIdentity();
    void onPasteSeedPhrase();

private:
    void setupUI();
    void createPage1_SeedPhrase();
    void createPage2_Progress();
    void createPage3_Success();

    bool validateSeedPhrase();
    bool performRestore();
    void applyTheme();
    void setupWordCompleter();

    QStackedWidget *stackedWidget;

    // Page 1: Seed Phrase
    QWidget *page1;
    QLabel *titleLabel1;
    QLineEdit *wordInputs[24];
    QLineEdit *passphraseInput;
    QLabel *passphraseLabel;
    QPushButton *pasteButton;
    QLabel *errorLabel1;
    QPushButton *restoreButton;
    QCompleter *wordCompleter;
    QStringListModel *wordListModel;

    // Page 2: Progress
    QWidget *page2;
    QLabel *titleLabel2;
    QProgressBar *progressBar;
    QLabel *statusLabel;

    // Page 3: Success
    QWidget *page3;
    QLabel *titleLabel3;
    QLabel *successLabel;
    QPushButton *finishButton;

    QString restoredFingerprint;
};

#endif // RESTOREIDENTITYDIALOG_H
