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

    // Get the restored identity name
    QString getRestoredIdentity() const;

private slots:
    void onNextPage();
    void onPreviousPage();
    void onRestoreIdentity();
    void onPasteSeedPhrase();

private:
    void setupUI();
    void createPage1_IdentityName();
    void createPage2_SeedPhrase();
    void createPage3_Progress();
    void createPage4_Success();

    void validateIdentityName();
    bool validateSeedPhrase();
    bool performRestore();
    void applyTheme();
    void setupWordCompleter();

    QStackedWidget *stackedWidget;

    // Page 1: Identity Name
    QWidget *page1;
    QLabel *titleLabel1;
    QLabel *instructionsLabel;
    QLabel *inputLabel1;
    QLineEdit *identityNameInput;
    QPushButton *nextButton1;
    QLabel *errorLabel1;

    // Page 2: Seed Phrase
    QWidget *page2;
    QLabel *titleLabel2;
    QLineEdit *wordInputs[24];
    QLineEdit *passphraseInput;
    QLabel *passphraseLabel;
    QPushButton *pasteButton;
    QLabel *errorLabel2;
    QPushButton *previousButton2;
    QPushButton *restoreButton;
    QCompleter *wordCompleter;
    QStringListModel *wordListModel;

    // Page 3: Progress
    QWidget *page3;
    QLabel *titleLabel3;
    QProgressBar *progressBar;
    QLabel *statusLabel;

    // Page 4: Success
    QWidget *page4;
    QLabel *titleLabel4;
    QLabel *successLabel;
    QPushButton *finishButton;

    QString restoredIdentity;
};

#endif // RESTOREIDENTITYDIALOG_H
