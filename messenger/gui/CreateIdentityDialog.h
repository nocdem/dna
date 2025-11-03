#ifndef CREATEIDENTITYDIALOG_H
#define CREATEIDENTITYDIALOG_H

#include <QDialog>
#include <QStackedWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QMessageBox>
#include "SeedPhraseWidget.h"

class CreateIdentityDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateIdentityDialog(QWidget *parent = nullptr);

    // Get the created identity name
    QString getCreatedIdentity() const;

private slots:
    void onNextPage();
    void onPreviousPage();
    void onGenerateSeed();
    void onCreateIdentity();

private:
    void setupUI();
    void createPage1_IdentityName();
    void createPage2_SeedPhrase();
    void createPage3_Confirmation();
    void createPage4_Progress();
    void createPage5_Success();

    void validateIdentityName();
    bool performKeyGeneration();
    void applyTheme();

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
    SeedPhraseWidget *seedPhraseWidget;
    QCheckBox *confirmedCheckbox;
    QLineEdit *passphraseInput;
    QLabel *passphraseLabel;
    QPushButton *previousButton2;
    QPushButton *nextButton2;
    QString generatedMnemonic;

    // Page 3: Confirmation
    QWidget *page3;
    QLabel *titleLabel3;
    QLabel *confirmationLabel;
    QLabel *warningLabel;
    QLabel *reminderLabel;
    QCheckBox *understandCheckbox;
    QPushButton *previousButton3;
    QPushButton *createButton;

    // Page 4: Progress
    QWidget *page4;
    QLabel *titleLabel4;
    QProgressBar *progressBar;
    QLabel *statusLabel;

    // Page 5: Success
    QWidget *page5;
    QLabel *titleLabel5;
    QLabel *successLabel;
    QPushButton *finishButton;

    QString createdIdentity;
};

#endif // CREATEIDENTITYDIALOG_H
