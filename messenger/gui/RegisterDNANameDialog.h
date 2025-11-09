/*
 * DNA Messenger - Register DNA Name Dialog
 * Phase 4: DNA Name Registration (Free for now)
 */

#ifndef REGISTERDNANAMEDIALOG_H
#define REGISTERDNANAMEDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QTimer>

extern "C" {
    #include "../messenger.h"
}

class RegisterDNANameDialog : public QDialog {
    Q_OBJECT

public:
    explicit RegisterDNANameDialog(messenger_context_t *ctx, QWidget *parent = nullptr);
    ~RegisterDNANameDialog() override = default;

private slots:
    void onNameChanged();
    void onCheckAvailability();
    void onRegister();
    void onCancel();

private:
    void setupUI();
    bool validateName(const QString &name);
    void checkNameAvailability(const QString &name);

    messenger_context_t *m_ctx;

    // UI Elements
    QLabel *fingerprintLabel;
    QLineEdit *nameInput;
    QLabel *availabilityLabel;
    QLabel *costLabel;
    QLabel *paymentStatusLabel;
    QPushButton *registerButton;
    QPushButton *cancelButton;
    QLabel *statusLabel;

    // Data
    QTimer *availabilityTimer;
    QString currentFingerprint;
    bool nameAvailable;
};

#endif // REGISTERDNANAMEDIALOG_H
