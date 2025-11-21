/*
 * DNA Messenger - Profile Editor Dialog
 * Phase 5: DNA Profile Management
 */

#ifndef PROFILEEDITORDIALOG_H
#define PROFILEEDITORDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QGroupBox>

extern "C" {
    #include "../messenger.h"
    #include "../dht/dht_keyserver.h"
}

class ProfileEditorDialog : public QDialog {
    Q_OBJECT

public:
    explicit ProfileEditorDialog(messenger_context_t *ctx, QWidget *parent = nullptr);
    ~ProfileEditorDialog() override = default;

private slots:
    void onSave();
    void onCancel();
    void onBioChanged();

private:
    void setupUI();
    void loadProfile();
    void saveProfile();
    bool validateProfile();

    messenger_context_t *m_ctx;

    // UI Elements
    QLabel *fingerprintLabel;
    QLabel *registeredNameLabel;

    // Cellframe Network Wallet Addresses
    QLineEdit *backboneAddressEdit;
    QLineEdit *kelvpnAddressEdit;
    QLineEdit *subzeroAddressEdit;
    QLineEdit *millixtAddressEdit;
    QLineEdit *backboneTestnetAddressEdit;
    QLineEdit *kelvpnTestnetAddressEdit;
    QLineEdit *subzeroTestnetAddressEdit;

    // External Wallet Addresses
    QLineEdit *btcAddressEdit;
    QLineEdit *ethAddressEdit;
    QLineEdit *solAddressEdit;
    QLineEdit *ltcAddressEdit;
    QLineEdit *dogeAddressEdit;

    // Social Media Links
    QLineEdit *telegramEdit;
    QLineEdit *twitterEdit;
    QLineEdit *githubEdit;
    QLineEdit *discordEdit;
    QLineEdit *websiteEdit;

    // Profile Picture (IPFS CID)
    QLineEdit *profilePicCIDEdit;

    // Bio
    QTextEdit *bioEdit;
    QLabel *bioCharCountLabel;

    // Buttons
    QPushButton *saveButton;
    QPushButton *cancelButton;
    QLabel *statusLabel;

    // Data
    QString currentFingerprint;
    dna_unified_identity_t *currentProfile;
};

#endif // PROFILEEDITORDIALOG_H
