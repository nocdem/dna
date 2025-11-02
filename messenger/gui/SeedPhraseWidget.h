#ifndef SEEDPHRASEWIDGET_H
#define SEEDPHRASEWIDGET_H

#include <QWidget>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>

class SeedPhraseWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SeedPhraseWidget(QWidget *parent = nullptr);

    // Set the 24-word seed phrase (space-separated string)
    void setSeedPhrase(const QString &phrase);

    // Get the seed phrase as space-separated string
    QString getSeedPhrase() const;

    // Enable/disable copy button
    void setShowCopyButton(bool show);

signals:
    void seedPhraseCopied();

private slots:
    void onCopyToClipboard();

private:
    void setupUI();
    void updateDisplay();
    void applyTheme();

    QGridLayout *gridLayout;
    QLabel *warningLabel;
    QLabel *securityWarning;
    QLabel *numLabels[24];   // Number labels (1-24)
    QLabel *wordLabels[24];  // Word labels (1-24)
    QPushButton *copyButton;
    QString seedPhrase;
};

#endif // SEEDPHRASEWIDGET_H
