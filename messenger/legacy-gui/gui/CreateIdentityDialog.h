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

    // Get the created identity fingerprint
    QString getCreatedFingerprint() const;

private slots:
    void onNextPage();
    void onPreviousPage();
    void onGenerateSeed();
    void onCreateIdentity();

private:
    void setupUI();
    void createPage1_SeedPhrase();
    void createPage2_Confirmation();
    void createPage3_Progress();
    void createPage4_Success();

    bool performKeyGeneration();
    void applyTheme();

    QStackedWidget *stackedWidget;

    // Page 1: Seed Phrase
    QWidget *page1;
    QLabel *titleLabel1;
    SeedPhraseWidget *seedPhraseWidget;
    QCheckBox *confirmedCheckbox;
    QLineEdit *passphraseInput;
    QLabel *passphraseLabel;
    QPushButton *nextButton1;
    QString generatedMnemonic;

    // Page 2: Confirmation
    QWidget *page2;
    QLabel *titleLabel2;
    QLabel *confirmationLabel;
    QLabel *warningLabel;
    QLabel *reminderLabel;
    QCheckBox *understandCheckbox;
    QPushButton *previousButton2;
    QPushButton *createButton;

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

    QString createdFingerprint;
};

#endif // CREATEIDENTITYDIALOG_H
