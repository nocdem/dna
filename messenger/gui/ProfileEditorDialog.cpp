/*
 * DNA Messenger - Profile Editor Dialog
 * Phase 5: DNA Profile Management
 */

#include "ProfileEditorDialog.h"
#include "ThemeManager.h"
#include "cpunk_themes.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QMessageBox>
#include <QApplication>
#include <QThread>

extern "C" {
    #include "../p2p/p2p_transport.h"
    #include "../qgp_platform.h"
    #include "../qgp_types.h"
    #include "../qgp_dilithium.h"
    #include "../qgp_kyber.h"
}

ProfileEditorDialog::ProfileEditorDialog(messenger_context_t *ctx, QWidget *parent)
    : QDialog(parent)
    , m_ctx(ctx)
    , currentProfile(nullptr)
{
    setWindowTitle(QString::fromUtf8("Edit DNA Profile"));
    setMinimumWidth(800);
    setMinimumHeight(700);

    // Get current fingerprint
    if (m_ctx && m_ctx->fingerprint) {
        currentFingerprint = QString::fromUtf8(m_ctx->fingerprint);
    } else {
        QMessageBox::critical(this, "Error", "Fingerprint not available. Please restart messenger.");
        reject();
        return;
    }

    setupUI();
    loadProfile();

    // Apply current theme
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            [this](CpunkTheme) {
        // Theme will be reapplied on next window show
    });
}

void ProfileEditorDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Header
    QLabel *headerLabel = new QLabel(QString::fromUtf8("DNA Profile Editor"));
    QFont headerFont;
    headerFont.setPointSize(18);
    headerFont.setBold(true);
    headerLabel->setFont(headerFont);
    headerLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(headerLabel);

    // Info text
    QLabel *infoLabel = new QLabel(QString::fromUtf8(
        "Edit your public DNA profile. All changes are stored in the DHT."
    ));
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(infoLabel);

    mainLayout->addSpacing(10);

    // Scroll area for form
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget *scrollWidget = new QWidget();
    QVBoxLayout *scrollLayout = new QVBoxLayout(scrollWidget);

    // Fingerprint display
    QLabel *fpLabel = new QLabel(QString::fromUtf8("Your Fingerprint:"));
    scrollLayout->addWidget(fpLabel);

    fingerprintLabel = new QLabel(currentFingerprint);
    fingerprintLabel->setWordWrap(true);
    fingerprintLabel->setStyleSheet("QLabel { font-family: monospace; font-size: 11px; }");
    scrollLayout->addWidget(fingerprintLabel);

    // Registered name display
    registeredNameLabel = new QLabel(QString::fromUtf8("Registered Name: Checking..."));
    scrollLayout->addWidget(registeredNameLabel);

    scrollLayout->addSpacing(10);

    // === Cellframe Network Addresses ===
    QGroupBox *cellframeGroup = new QGroupBox(QString::fromUtf8("Cellframe Network Addresses"));
    QGridLayout *cellframeLayout = new QGridLayout(cellframeGroup);

    int row = 0;
    cellframeLayout->addWidget(new QLabel("Backbone:"), row, 0);
    backboneAddressEdit = new QLineEdit();
    backboneAddressEdit->setPlaceholderText("Your Backbone address");
    cellframeLayout->addWidget(backboneAddressEdit, row++, 1);

    cellframeLayout->addWidget(new QLabel("KelVPN:"), row, 0);
    kelvpnAddressEdit = new QLineEdit();
    kelvpnAddressEdit->setPlaceholderText("Your KelVPN address");
    cellframeLayout->addWidget(kelvpnAddressEdit, row++, 1);

    cellframeLayout->addWidget(new QLabel("Subzero:"), row, 0);
    subzeroAddressEdit = new QLineEdit();
    subzeroAddressEdit->setPlaceholderText("Your Subzero address");
    cellframeLayout->addWidget(subzeroAddressEdit, row++, 1);

    cellframeLayout->addWidget(new QLabel("Millixt:"), row, 0);
    millixtAddressEdit = new QLineEdit();
    millixtAddressEdit->setPlaceholderText("Your Millixt address");
    cellframeLayout->addWidget(millixtAddressEdit, row++, 1);

    cellframeLayout->addWidget(new QLabel("Backbone Testnet:"), row, 0);
    backboneTestnetAddressEdit = new QLineEdit();
    backboneTestnetAddressEdit->setPlaceholderText("Testnet address");
    cellframeLayout->addWidget(backboneTestnetAddressEdit, row++, 1);

    cellframeLayout->addWidget(new QLabel("KelVPN Testnet:"), row, 0);
    kelvpnTestnetAddressEdit = new QLineEdit();
    kelvpnTestnetAddressEdit->setPlaceholderText("Testnet address");
    cellframeLayout->addWidget(kelvpnTestnetAddressEdit, row++, 1);

    cellframeLayout->addWidget(new QLabel("Subzero Testnet:"), row, 0);
    subzeroTestnetAddressEdit = new QLineEdit();
    subzeroTestnetAddressEdit->setPlaceholderText("Testnet address");
    cellframeLayout->addWidget(subzeroTestnetAddressEdit, row++, 1);

    scrollLayout->addWidget(cellframeGroup);

    // === External Wallet Addresses ===
    QGroupBox *externalGroup = new QGroupBox(QString::fromUtf8("External Wallet Addresses"));
    QGridLayout *externalLayout = new QGridLayout(externalGroup);

    row = 0;
    externalLayout->addWidget(new QLabel("Bitcoin (BTC):"), row, 0);
    btcAddressEdit = new QLineEdit();
    btcAddressEdit->setPlaceholderText("bc1q...");
    externalLayout->addWidget(btcAddressEdit, row++, 1);

    externalLayout->addWidget(new QLabel("Ethereum (ETH):"), row, 0);
    ethAddressEdit = new QLineEdit();
    ethAddressEdit->setPlaceholderText("0x...");
    externalLayout->addWidget(ethAddressEdit, row++, 1);

    externalLayout->addWidget(new QLabel("Solana (SOL):"), row, 0);
    solAddressEdit = new QLineEdit();
    solAddressEdit->setPlaceholderText("Your Solana address");
    externalLayout->addWidget(solAddressEdit, row++, 1);

    externalLayout->addWidget(new QLabel("Litecoin (LTC):"), row, 0);
    ltcAddressEdit = new QLineEdit();
    ltcAddressEdit->setPlaceholderText("L...");
    externalLayout->addWidget(ltcAddressEdit, row++, 1);

    externalLayout->addWidget(new QLabel("Dogecoin (DOGE):"), row, 0);
    dogeAddressEdit = new QLineEdit();
    dogeAddressEdit->setPlaceholderText("D...");
    externalLayout->addWidget(dogeAddressEdit, row++, 1);

    scrollLayout->addWidget(externalGroup);

    // === Social Media Links ===
    QGroupBox *socialGroup = new QGroupBox(QString::fromUtf8("Social Media Links"));
    QGridLayout *socialLayout = new QGridLayout(socialGroup);

    row = 0;
    socialLayout->addWidget(new QLabel("Telegram:"), row, 0);
    telegramEdit = new QLineEdit();
    telegramEdit->setPlaceholderText("@username or https://t.me/username");
    socialLayout->addWidget(telegramEdit, row++, 1);

    socialLayout->addWidget(new QLabel("X (Twitter):"), row, 0);
    twitterEdit = new QLineEdit();
    twitterEdit->setPlaceholderText("@username or https://x.com/username");
    socialLayout->addWidget(twitterEdit, row++, 1);

    socialLayout->addWidget(new QLabel("GitHub:"), row, 0);
    githubEdit = new QLineEdit();
    githubEdit->setPlaceholderText("https://github.com/username");
    socialLayout->addWidget(githubEdit, row++, 1);

    socialLayout->addWidget(new QLabel("Discord:"), row, 0);
    discordEdit = new QLineEdit();
    discordEdit->setPlaceholderText("username#1234");
    socialLayout->addWidget(discordEdit, row++, 1);

    socialLayout->addWidget(new QLabel("Website:"), row, 0);
    websiteEdit = new QLineEdit();
    websiteEdit->setPlaceholderText("https://example.com");
    socialLayout->addWidget(websiteEdit, row++, 1);

    scrollLayout->addWidget(socialGroup);

    // === Profile Picture (IPFS CID) ===
    QGroupBox *pictureGroup = new QGroupBox(QString::fromUtf8("Profile Picture"));
    QVBoxLayout *pictureLayout = new QVBoxLayout(pictureGroup);

    QLabel *picLabel = new QLabel(QString::fromUtf8("IPFS CID (Content Identifier):"));
    pictureLayout->addWidget(picLabel);

    profilePicCIDEdit = new QLineEdit();
    profilePicCIDEdit->setPlaceholderText("QmXxxx... or bafyxxx...");
    pictureLayout->addWidget(profilePicCIDEdit);

    QLabel *picHint = new QLabel(QString::fromUtf8(
        "Upload your profile picture to IPFS and paste the CID here.\n"
        "Recommended: 512x512px or 1024x1024px"
    ));
    picHint->setWordWrap(true);
    picHint->setStyleSheet("QLabel { font-size: 11px; color: #888; }");
    pictureLayout->addWidget(picHint);

    scrollLayout->addWidget(pictureGroup);

    // === Bio ===
    QGroupBox *bioGroup = new QGroupBox(QString::fromUtf8("Bio"));
    QVBoxLayout *bioLayout = new QVBoxLayout(bioGroup);

    bioEdit = new QTextEdit();
    bioEdit->setPlaceholderText("Tell the world about yourself... (max 512 characters)");
    bioEdit->setMaximumHeight(120);
    connect(bioEdit, &QTextEdit::textChanged, this, &ProfileEditorDialog::onBioChanged);
    bioLayout->addWidget(bioEdit);

    bioCharCountLabel = new QLabel(QString::fromUtf8("0 / 512"));
    bioCharCountLabel->setAlignment(Qt::AlignRight);
    bioLayout->addWidget(bioCharCountLabel);

    scrollLayout->addWidget(bioGroup);

    scrollArea->setWidget(scrollWidget);
    mainLayout->addWidget(scrollArea);

    // Status label
    statusLabel = new QLabel(QString::fromUtf8(""));
    statusLabel->setWordWrap(true);
    mainLayout->addWidget(statusLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    cancelButton = new QPushButton(QString::fromUtf8("Cancel"));
    connect(cancelButton, &QPushButton::clicked, this, &ProfileEditorDialog::onCancel);
    buttonLayout->addWidget(cancelButton);

    saveButton = new QPushButton(QString::fromUtf8("💾 Save Profile to DHT"));
    connect(saveButton, &QPushButton::clicked, this, &ProfileEditorDialog::onSave);
    buttonLayout->addWidget(saveButton);

    mainLayout->addLayout(buttonLayout);

    // Apply theme styles
    QString accentColor = ThemeManager::instance()->currentTheme() == THEME_CPUNK_CLUB ? "#FF8C42" : "#00D9FF";
    QString bgColor = "#0A1E21";
    QString textColor = accentColor;

    setStyleSheet(QString(
        "QDialog { background: %1; color: %2; font-family: 'Orbitron'; }"
        "QLabel { color: %2; font-size: 12px; }"
        "QLineEdit { background: #0D3438; border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 6px; "
        "            padding: 8px; color: %2; font-size: 12px; }"
        "QLineEdit:focus { border-color: %2; }"
        "QTextEdit { background: #0D3438; border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 6px; "
        "            padding: 8px; color: %2; font-size: 12px; }"
        "QTextEdit:focus { border-color: %2; }"
        "QGroupBox { border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 8px; "
        "            margin-top: 12px; padding-top: 12px; color: %2; font-weight: bold; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }"
        "QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %2, stop:1 rgba(0, 217, 255, 0.7)); "
        "              color: white; border: 2px solid %2; border-radius: 10px; "
        "              padding: 12px 24px; font-size: 14px; font-weight: bold; }"
        "QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 217, 255, 0.9), stop:1 %2); }"
        "QScrollArea { border: none; }"
    ).arg(bgColor).arg(textColor));
}

void ProfileEditorDialog::loadProfile() {
    statusLabel->setText(QString::fromUtf8("Loading profile from DHT..."));
    QApplication::processEvents();

    if (!m_ctx || !m_ctx->p2p_transport) {
        statusLabel->setText(QString::fromUtf8("⚠️ P2P transport not initialized"));
        registeredNameLabel->setText(QString::fromUtf8("Registered Name: N/A (DHT not connected)"));
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(m_ctx->p2p_transport);
    if (!dht_ctx) {
        statusLabel->setText(QString::fromUtf8("⚠️ DHT not connected"));
        registeredNameLabel->setText(QString::fromUtf8("Registered Name: N/A (DHT not connected)"));
        return;
    }

    // Load profile from DHT
    dna_unified_identity_t *profile = nullptr;
    int ret = dna_load_identity(dht_ctx, currentFingerprint.toUtf8().constData(), &profile);

    if (ret == 0 && profile) {
        currentProfile = profile;

        // Display registered name
        if (profile->registered_name && strlen(profile->registered_name) > 0) {
            registeredNameLabel->setText(QString::fromUtf8("Registered Name: %1")
                                         .arg(QString::fromUtf8(profile->registered_name)));
        } else {
            registeredNameLabel->setText(QString::fromUtf8("Registered Name: Not registered"));
        }

        // Load wallet addresses
        if (profile->wallets.backbone[0] != '\0') {
            backboneAddressEdit->setText(QString::fromUtf8(profile->wallets.backbone));
        }
        if (profile->wallets.kelvpn[0] != '\0') {
            kelvpnAddressEdit->setText(QString::fromUtf8(profile->wallets.kelvpn));
        }
        if (profile->wallets.subzero[0] != '\0') {
            subzeroAddressEdit->setText(QString::fromUtf8(profile->wallets.subzero));
        }
        // Note: millixt field doesn't exist in dna_wallets_t

        // Testnet (only one field: cpunk_testnet)
        if (profile->wallets.cpunk_testnet[0] != '\0') {
            backboneTestnetAddressEdit->setText(QString::fromUtf8(profile->wallets.cpunk_testnet));
        }

        // Load external wallets (stored in same wallets structure)
        if (profile->wallets.btc[0] != '\0') {
            btcAddressEdit->setText(QString::fromUtf8(profile->wallets.btc));
        }
        if (profile->wallets.eth[0] != '\0') {
            ethAddressEdit->setText(QString::fromUtf8(profile->wallets.eth));
        }
        if (profile->wallets.sol[0] != '\0') {
            solAddressEdit->setText(QString::fromUtf8(profile->wallets.sol));
        }
        // Note: ltc and doge not in dna_wallets_t structure

        // Load social links
        if (profile->socials.telegram[0] != '\0') {
            telegramEdit->setText(QString::fromUtf8(profile->socials.telegram));
        }
        if (profile->socials.x[0] != '\0') {
            twitterEdit->setText(QString::fromUtf8(profile->socials.x));
        }
        if (profile->socials.github[0] != '\0') {
            githubEdit->setText(QString::fromUtf8(profile->socials.github));
        }
        // Note: discord and website fields not available in dna_socials_t

        // Load profile picture CID
        if (profile->profile_picture_ipfs[0] != '\0') {
            profilePicCIDEdit->setText(QString::fromUtf8(profile->profile_picture_ipfs));
        }

        // Load bio
        if (profile->bio[0] != '\0') {
            bioEdit->setPlainText(QString::fromUtf8(profile->bio));
        }

        statusLabel->setText(QString::fromUtf8("✓ Profile loaded from DHT"));
    } else if (ret == -2) {
        // Profile not found in DHT (user hasn't created profile yet)
        registeredNameLabel->setText(QString::fromUtf8("Registered Name: Not registered"));
        statusLabel->setText(QString::fromUtf8("No profile found. Create your first profile!"));
    } else {
        statusLabel->setText(QString::fromUtf8("⚠️ Failed to load profile from DHT"));
        registeredNameLabel->setText(QString::fromUtf8("Registered Name: Error loading"));
    }
}

void ProfileEditorDialog::onBioChanged() {
    QString bio = bioEdit->toPlainText();
    int length = bio.length();

    // Limit to 512 characters
    if (length > 512) {
        bio = bio.left(512);
        bioEdit->setPlainText(bio);
        QTextCursor cursor = bioEdit->textCursor();
        cursor.movePosition(QTextCursor::End);
        bioEdit->setTextCursor(cursor);
        length = 512;
    }

    bioCharCountLabel->setText(QString::fromUtf8("%1 / 512").arg(length));
}

void ProfileEditorDialog::onSave() {
    if (!validateProfile()) {
        return;
    }

    saveProfile();
}

bool ProfileEditorDialog::validateProfile() {
    // Basic validation (can be extended with format checks)
    QString bio = bioEdit->toPlainText();
    if (bio.length() > 512) {
        QMessageBox::warning(this, "Validation Error", "Bio exceeds 512 character limit.");
        return false;
    }

    // All fields are optional, so just return true
    return true;
}

void ProfileEditorDialog::saveProfile() {
    statusLabel->setText(QString::fromUtf8("💾 Saving profile to DHT..."));
    saveButton->setEnabled(false);
    cancelButton->setEnabled(false);
    QApplication::processEvents();

    if (!m_ctx || !m_ctx->p2p_transport) {
        statusLabel->setText(QString::fromUtf8("⚠️ P2P transport not initialized"));
        saveButton->setEnabled(true);
        cancelButton->setEnabled(true);
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(m_ctx->p2p_transport);
    if (!dht_ctx) {
        statusLabel->setText(QString::fromUtf8("⚠️ DHT not connected"));
        saveButton->setEnabled(true);
        cancelButton->setEnabled(true);
        return;
    }

    // Build profile data structure
    dna_profile_data_t profile_data = {0};

    // Wallet addresses
    QString backbone = backboneAddressEdit->text().trimmed();
    if (!backbone.isEmpty()) {
        strncpy(profile_data.wallets.backbone, backbone.toUtf8().constData(), sizeof(profile_data.wallets.backbone) - 1);
    }

    QString kelvpn = kelvpnAddressEdit->text().trimmed();
    if (!kelvpn.isEmpty()) {
        strncpy(profile_data.wallets.kelvpn, kelvpn.toUtf8().constData(), sizeof(profile_data.wallets.kelvpn) - 1);
    }

    QString subzero = subzeroAddressEdit->text().trimmed();
    if (!subzero.isEmpty()) {
        strncpy(profile_data.wallets.subzero, subzero.toUtf8().constData(), sizeof(profile_data.wallets.subzero) - 1);
    }

    // Note: millixt field doesn't exist in dna_wallets_t

    // Note: Individual testnet fields not available in dna_wallets_t
    // Only cpunk_testnet field exists
    QString testnet = backboneTestnetAddressEdit->text().trimmed();
    if (!testnet.isEmpty()) {
        strncpy(profile_data.wallets.cpunk_testnet, testnet.toUtf8().constData(), sizeof(profile_data.wallets.cpunk_testnet) - 1);
    }

    // External wallets (stored in same wallets structure)
    QString btc = btcAddressEdit->text().trimmed();
    if (!btc.isEmpty()) {
        strncpy(profile_data.wallets.btc, btc.toUtf8().constData(), sizeof(profile_data.wallets.btc) - 1);
    }

    QString eth = ethAddressEdit->text().trimmed();
    if (!eth.isEmpty()) {
        strncpy(profile_data.wallets.eth, eth.toUtf8().constData(), sizeof(profile_data.wallets.eth) - 1);
    }

    QString sol = solAddressEdit->text().trimmed();
    if (!sol.isEmpty()) {
        strncpy(profile_data.wallets.sol, sol.toUtf8().constData(), sizeof(profile_data.wallets.sol) - 1);
    }

    // Note: ltc and doge not in dna_wallets_t structure

    // Social links
    QString telegram = telegramEdit->text().trimmed();
    if (!telegram.isEmpty()) {
        strncpy(profile_data.socials.telegram, telegram.toUtf8().constData(), sizeof(profile_data.socials.telegram) - 1);
    }

    QString twitter = twitterEdit->text().trimmed();
    if (!twitter.isEmpty()) {
        strncpy(profile_data.socials.x, twitter.toUtf8().constData(), sizeof(profile_data.socials.x) - 1);
    }

    QString github = githubEdit->text().trimmed();
    if (!github.isEmpty()) {
        strncpy(profile_data.socials.github, github.toUtf8().constData(), sizeof(profile_data.socials.github) - 1);
    }

    // Note: discord and website fields not available in dna_socials_t

    // Profile picture CID
    QString profilePicCID = profilePicCIDEdit->text().trimmed();
    if (!profilePicCID.isEmpty()) {
        strncpy(profile_data.profile_picture_ipfs, profilePicCID.toUtf8().constData(), sizeof(profile_data.profile_picture_ipfs) - 1);
    }

    // Bio
    QString bio = bioEdit->toPlainText().trimmed();
    if (!bio.isEmpty()) {
        strncpy(profile_data.bio, bio.toUtf8().constData(), sizeof(profile_data.bio) - 1);
    }

    // Load private key for signing
    const char *home = qgp_platform_home_dir();
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home, m_ctx->identity);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        statusLabel->setText(QString::fromUtf8("⚠️ Failed to load private key for signing"));
        saveButton->setEnabled(true);
        cancelButton->setEnabled(true);
        return;
    }

    // Update profile in DHT
    int ret = dna_update_profile(dht_ctx, currentFingerprint.toUtf8().constData(),
                                 &profile_data, key->private_key);

    qgp_key_free(key);

    printf("[GUI] DEBUG: dna_update_profile returned: %d\n", ret);

    if (ret == 0) {
        statusLabel->setText(QString::fromUtf8("💾 Saving to DHT... (please wait 10 seconds)"));
        QApplication::processEvents();

        // Wait 10 seconds for DHT propagation (PUT is asynchronous and needs to replicate)
        printf("[GUI] Waiting 10 seconds for DHT propagation across bootstrap nodes...\n");
        QThread::sleep(10);

        statusLabel->setText(QString::fromUtf8("✓ Profile saved to DHT successfully!"));

        QMessageBox::information(this,
            QString::fromUtf8("Profile Saved"),
            QString::fromUtf8("Your DNA profile has been updated in the DHT.\n\n"
                              "Changes are now visible to all users.\n\n"
                              "⚠️  IMPORTANT: Please wait at least 30 seconds before closing\n"
                              "the app to ensure full DHT network propagation."));
        // Close dialog after successful save
        accept();
    } else {
        statusLabel->setText(QString::fromUtf8("⚠️ Failed to save profile to DHT"));
        QMessageBox::critical(this,
            QString::fromUtf8("Save Failed"),
            QString::fromUtf8("Failed to update profile in DHT.\n\n"
                              "Please check your connection and try again."));
        // Re-enable buttons so user can retry
        saveButton->setEnabled(true);
        cancelButton->setEnabled(true);
    }
}

void ProfileEditorDialog::onCancel() {
    if (currentProfile) {
        dna_identity_free(currentProfile);
        currentProfile = nullptr;
    }
    reject();
}
