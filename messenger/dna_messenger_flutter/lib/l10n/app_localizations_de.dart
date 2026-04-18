// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for German (`de`).
class AppLocalizationsDe extends AppLocalizations {
  AppLocalizationsDe([String locale = 'de']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Initialisierung...';

  @override
  String get failedToInitialize => 'Initialisierung fehlgeschlagen';

  @override
  String get makeSureNativeLibrary =>
      'Stellen Sie sicher, dass die native Bibliothek verfügbar ist.';

  @override
  String get navHome => 'Startseite';

  @override
  String get navChats => 'Chats';

  @override
  String get navWallet => 'Geldbörse';

  @override
  String get navMore => 'Mehr';

  @override
  String get messagesAll => 'Alle';

  @override
  String get messagesUnread => 'Ungelesen';

  @override
  String get messagesAllCaughtUp => 'Alles gelesen!';

  @override
  String get messagesNoUnread => 'Keine ungelesenen Nachrichten';

  @override
  String get messagesSearchHint => 'Chats durchsuchen...';

  @override
  String get contactsTitle => 'Kontakte';

  @override
  String get contactsEmpty => 'Noch keine Kontakte';

  @override
  String get contactsTapToAdd =>
      'Tippen Sie auf +, um einen Kontakt hinzuzufügen';

  @override
  String get contactsOnline => 'Online';

  @override
  String contactsLastSeen(String time) {
    return 'Zuletzt gesehen $time';
  }

  @override
  String get contactsOffline => 'Offline';

  @override
  String get contactsSyncing => 'Synchronisierung...';

  @override
  String get contactsFailedToLoad => 'Kontakte konnten nicht geladen werden';

  @override
  String get contactsRetry => 'Erneut versuchen';

  @override
  String get contactsHubContacts => 'Kontakte';

  @override
  String get contactsHubRequests => 'Anfragen';

  @override
  String get contactsHubBlocked => 'Gesperrt';

  @override
  String get contactsHubRemoveTitle => 'Kontakt entfernen?';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'Möchten Sie $name wirklich aus Ihren Kontakten entfernen?';
  }

  @override
  String get contactsHubRemove => 'Entfernen';

  @override
  String get contactsHubFingerprintCopied => 'Fingerabdruck kopiert';

  @override
  String get contactRequestsTitle => 'Kontaktanfragen';

  @override
  String get contactRequestsEmpty => 'Keine ausstehenden Anfragen';

  @override
  String get contactRequestsAccept => 'Annehmen';

  @override
  String get contactRequestsDeny => 'Ablehnen';

  @override
  String get contactRequestsBlock => 'Benutzer sperren';

  @override
  String get contactRequestsSent => 'Gesendet';

  @override
  String get contactRequestsReceived => 'Empfangen';

  @override
  String get addContactTitle => 'Kontakt hinzufügen';

  @override
  String get addContactHint => 'Name oder ID eingeben';

  @override
  String get addContactSearching => 'Suche...';

  @override
  String get addContactFoundOnNetwork => 'Im Netzwerk gefunden';

  @override
  String get addContactNotFound => 'Nicht gefunden';

  @override
  String get addContactSendRequest => 'Anfrage senden';

  @override
  String get addContactRequestSent => 'Kontaktanfrage gesendet';

  @override
  String get addContactAlreadyContact => 'Bereits in Ihren Kontakten';

  @override
  String get addContactCannotAddSelf =>
      'Sie können sich nicht selbst hinzufügen';

  @override
  String get chatSearchMessages => 'Nachrichten durchsuchen';

  @override
  String get chatOnline => 'Online';

  @override
  String get chatOffline => 'Offline';

  @override
  String get chatConnecting => 'Verbindung wird hergestellt...';

  @override
  String get chatTypeMessage => 'Nachricht eingeben';

  @override
  String get chatNoMessages => 'Noch keine Nachrichten';

  @override
  String get chatSendFirstMessage =>
      'Senden Sie eine Nachricht, um das Gespräch zu beginnen';

  @override
  String get chatPhotoLibrary => 'Fotobibliothek';

  @override
  String get chatCamera => 'Kamera';

  @override
  String get chatAddCaption => 'Bildunterschrift hinzufügen...';

  @override
  String get chatSendPhoto => 'Senden';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Bild zu groß (max. $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Nachricht gelöscht';

  @override
  String get chatLoadEarlier => 'Ältere Nachrichten laden';

  @override
  String chatLastSeen(String time) {
    return 'Zuletzt gesehen $time';
  }

  @override
  String get chatSendTokens => 'Token senden';

  @override
  String chatSendTokensTo(String name) {
    return 'an $name';
  }

  @override
  String get chatLookingUpWallets => 'Wallet-Adressen werden gesucht...';

  @override
  String get chatNoWalletAddresses =>
      'Kontakt hat keine Wallet-Adressen in seinem Profil';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Betrag';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Verfügbar: $balance $token';
  }

  @override
  String get chatSendMax => 'Max';

  @override
  String chatSendButton(String token) {
    return '$token senden';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return '$amount $token gesendet';
  }

  @override
  String get chatInvalidAmount => 'Bitte geben Sie einen gültigen Betrag ein';

  @override
  String chatInsufficientBalance(String token) {
    return 'Unzureichendes $token-Guthaben';
  }

  @override
  String get chatNoWalletForNetwork =>
      'Kontakt hat kein Wallet für dieses Netzwerk';

  @override
  String get chatSelectToken => 'Token auswählen';

  @override
  String get chatSelectNetwork => 'Netzwerk auswählen';

  @override
  String get chatEnterAmount => 'Betrag eingeben';

  @override
  String chatStepOf(String current, String total) {
    return 'Schritt $current von $total';
  }

  @override
  String get messageMenuReply => 'Antworten';

  @override
  String get messageMenuCopy => 'Kopieren';

  @override
  String get messageMenuForward => 'Weiterleiten';

  @override
  String get messageMenuStar => 'Markieren';

  @override
  String get messageMenuUnstar => 'Markierung aufheben';

  @override
  String get messageMenuRetry => 'Erneut versuchen';

  @override
  String get messageMenuDelete => 'Löschen';

  @override
  String get groupsTitle => 'Gruppen';

  @override
  String get groupsCreate => 'Gruppe erstellen';

  @override
  String get groupsEmpty => 'Noch keine Gruppen';

  @override
  String get groupsCreateOrJoin =>
      'Erstellen Sie eine Gruppe oder nehmen Sie eine Einladung an';

  @override
  String get groupsPendingInvitations => 'Ausstehende Einladungen';

  @override
  String get groupsYourGroups => 'Ihre Gruppen';

  @override
  String get groupsInfo => 'Gruppeninfo';

  @override
  String get groupsMembers => 'Mitglieder';

  @override
  String get groupsLeave => 'Gruppe verlassen';

  @override
  String get groupsDelete => 'Gruppe löschen';

  @override
  String get groupsInvite => 'Einladen';

  @override
  String get groupsAccept => 'Annehmen';

  @override
  String get groupsDecline => 'Ablehnen';

  @override
  String get groupsName => 'Gruppenname';

  @override
  String get groupsDescription => 'Beschreibung';

  @override
  String get groupsCreated => 'Gruppe erstellt';

  @override
  String get groupsOwner => 'Eigentümer';

  @override
  String get groupsMember => 'Mitglied';

  @override
  String get groupsAdmin => 'Admin';

  @override
  String get groupsRemoveMember => 'Mitglied entfernen';

  @override
  String groupsKickConfirm(String name) {
    return '$name aus der Gruppe entfernen?';
  }

  @override
  String get settingsTitle => 'Einstellungen';

  @override
  String get settingsAnonymous => 'Anonym';

  @override
  String get settingsNotLoaded => 'Nicht geladen';

  @override
  String get settingsTapToEditProfile => 'Tippen, um Profil zu bearbeiten';

  @override
  String get settingsAppearance => 'Darstellung';

  @override
  String get settingsDarkMode => 'Dunkelmodus';

  @override
  String get settingsDarkModeSubtitle =>
      'Zwischen dunklem und hellem Design wechseln';

  @override
  String get settingsLanguage => 'Sprache';

  @override
  String get settingsLanguageSubtitle => 'App-Sprache wählen';

  @override
  String get settingsLanguageSystem => 'Systemstandard';

  @override
  String get settingsLanguageEnglish => 'English';

  @override
  String get settingsLanguageTurkish => 'Türkçe';

  @override
  String get settingsLanguageItalian => 'Italiano';

  @override
  String get settingsLanguageSpanish => 'Español';

  @override
  String get settingsLanguageRussian => 'Русский';

  @override
  String get settingsLanguageDutch => 'Nederlands';

  @override
  String get settingsLanguageGerman => 'Deutsch';

  @override
  String get settingsLanguageChinese => '中文';

  @override
  String get settingsLanguageJapanese => '日本語';

  @override
  String get settingsLanguagePortuguese => 'Português';

  @override
  String get settingsLanguageArabic => 'العربية';

  @override
  String get settingsBattery => 'Akku';

  @override
  String get settingsDisableBatteryOpt => 'Akkuoptimierung deaktivieren';

  @override
  String get settingsBatteryChecking => 'Überprüfung...';

  @override
  String get settingsBatteryDisabled =>
      'Deaktiviert — App kann im Hintergrund laufen';

  @override
  String get settingsBatteryTapToKeep =>
      'Tippen, um die App im Hintergrund aktiv zu halten';

  @override
  String get settingsSecurity => 'Sicherheit';

  @override
  String get settingsExportSeedPhrase => 'Seed-Phrase exportieren';

  @override
  String get settingsExportSeedSubtitle =>
      'Sichern Sie Ihre Wiederherstellungsphrase';

  @override
  String get settingsAppLock => 'App-Sperre';

  @override
  String get settingsAppLockSubtitle => 'Authentifizierung erforderlich';

  @override
  String get settingsExportSeedWarning =>
      'Ihre Seed-Phrase gibt vollen Zugriff auf Ihre Identität. Teilen Sie sie niemals mit jemandem.';

  @override
  String get settingsShowSeed => 'Seed anzeigen';

  @override
  String get settingsYourSeedPhrase => 'Ihre Seed-Phrase';

  @override
  String get settingsSeedPhraseWarning =>
      'Schreiben Sie diese Wörter in der richtigen Reihenfolge auf und bewahren Sie sie sicher auf. Jeder mit dieser Phrase kann auf Ihre Identität zugreifen.';

  @override
  String get settingsSeedCopied => 'Seed-Phrase in die Zwischenablage kopiert';

  @override
  String get seedCopyConfirmTitle => 'Copy seed phrase?';

  @override
  String get seedCopyConfirmBody =>
      'Your seed phrase will be in the clipboard for 10 seconds. Do not switch apps or background the app during this time. Continue?';

  @override
  String get seedCopiedToast => 'Copied. Clipboard will clear in 10 seconds.';

  @override
  String get settingsSeedNotAvailable =>
      'Seed-Phrase für diese Identität nicht verfügbar. Sie wurde erstellt, bevor diese Funktion hinzugefügt wurde.';

  @override
  String get settingsSeedError => 'Seed-Phrase konnte nicht abgerufen werden';

  @override
  String get settingsWallet => 'Wallet';

  @override
  String get settingsHideZeroBalance => 'Nullguthaben ausblenden';

  @override
  String get settingsHideZeroBalanceSubtitle =>
      'Coins mit Nullguthaben ausblenden';

  @override
  String get settingsData => 'Daten';

  @override
  String get settingsAutoSync => 'Automatische Synchronisierung';

  @override
  String get settingsAutoSyncSubtitle =>
      'Nachrichten automatisch alle 15 Minuten synchronisieren';

  @override
  String settingsLastSync(String time) {
    return 'Letzte Synchronisierung: $time';
  }

  @override
  String get settingsSyncNow => 'Jetzt synchronisieren';

  @override
  String get settingsSyncNowSubtitle => 'Sofortige Synchronisierung erzwingen';

  @override
  String get settingsLogs => 'Protokolle';

  @override
  String get settingsOpenLogsFolder => 'Protokollordner öffnen';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Dateimanager im Protokollverzeichnis öffnen';

  @override
  String get settingsShareLogs => 'Protokolle teilen';

  @override
  String get settingsShareLogsSubtitle => 'Protokolldateien zippen und teilen';

  @override
  String get settingsDebugLog => 'Share Logs';

  @override
  String get settingsDebugLogSubtitle => 'Send to cpunk or share';

  @override
  String get debugLogExportToDevice => 'Share';

  @override
  String get debugLogExportToDeviceSubtitle => 'Save or share the log file';

  @override
  String get debugLogShareWithPunk => 'Send to cpunk';

  @override
  String get debugLogShareWithPunkSubtitle =>
      'Send the last 3 MB to the developer (secrets removed)';

  @override
  String get debugLogSendToDev => 'Send Debug Log to Developer';

  @override
  String get debugLogSendToDevSubtitle =>
      'Send the last 3 MB of the log (secrets removed)';

  @override
  String get debugLogSendConfirmTitle => 'Send debug log?';

  @override
  String get debugLogSendConfirmBody =>
      'Send the last 3 MB of the debug log to the developer? Secrets (passwords, keys, mnemonics) are automatically removed before sending.';

  @override
  String get debugLogSendSending => 'Sending debug log…';

  @override
  String get debugLogSendSuccess => 'Debug log sent';

  @override
  String debugLogSendFailed(String error) {
    return 'Send failed: $error';
  }

  @override
  String get debugLogSendTruncated => 'Log was truncated to 3 MB';

  @override
  String get settingsLogsFolderNotExist =>
      'Protokollordner existiert noch nicht';

  @override
  String get settingsNoLogFiles => 'Keine Protokolldateien gefunden';

  @override
  String get settingsFailedCreateZip =>
      'ZIP-Archiv konnte nicht erstellt werden';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Noch keine Protokolle. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Identität';

  @override
  String get settingsFingerprint => 'Fingerabdruck';

  @override
  String get settingsFingerprintCopied => 'Fingerabdruck kopiert';

  @override
  String get settingsDeleteAccount => 'Konto löschen';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Alle Daten dauerhaft vom Gerät löschen';

  @override
  String get settingsDeleteAccountConfirm => 'Konto löschen?';

  @override
  String get settingsDeleteAccountWarning =>
      'Dies löscht dauerhaft alle lokalen Daten:';

  @override
  String get settingsDeletePrivateKeys => 'Private Schlüssel';

  @override
  String get settingsDeleteWallets => 'Wallets';

  @override
  String get settingsDeleteMessages => 'Nachrichten';

  @override
  String get settingsDeleteContacts => 'Kontakte';

  @override
  String get settingsDeleteGroups => 'Gruppen';

  @override
  String get settingsDeleteSeedWarning =>
      'Stellen Sie sicher, dass Sie Ihre Seed-Phrase gesichert haben, bevor Sie löschen!';

  @override
  String get settingsDeleteSuccess => 'Konto erfolgreich gelöscht';

  @override
  String settingsDeleteFailed(String error) {
    return 'Konto konnte nicht gelöscht werden: $error';
  }

  @override
  String get settingsAbout => 'Über';

  @override
  String get settingsUpdateAvailable => 'Update verfügbar';

  @override
  String get settingsTapToDownload => 'Tippen zum Herunterladen';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Bibliothek v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Post-Quanten-verschlüsselte Kommunikation';

  @override
  String get settingsCryptoStack => 'KRYPTO-STACK';

  @override
  String get profileTitle => 'Profil bearbeiten';

  @override
  String get profileInfo => 'Profilinfos';

  @override
  String get profileBio => 'Biografie';

  @override
  String get profileLocation => 'Standort';

  @override
  String get profileWebsite => 'Website';

  @override
  String get profileWalletAddresses => 'Wallet-Adressen';

  @override
  String get profileSave => 'Profil speichern';

  @override
  String get profileShareQR => 'Meinen QR-Code teilen';

  @override
  String get profileAvatar => 'Avatar';

  @override
  String get profileTakeSelfie => 'Selfie aufnehmen';

  @override
  String get profileChooseFromGallery => 'Aus Galerie auswählen';

  @override
  String get profileSaved => 'Profil gespeichert';

  @override
  String profileSaveFailed(String error) {
    return 'Profil konnte nicht gespeichert werden: $error';
  }

  @override
  String get profileCropTitle => 'Avatar zuschneiden';

  @override
  String get profileCropSave => 'Speichern';

  @override
  String get contactProfileFailed => 'Profil konnte nicht geladen werden';

  @override
  String get contactProfileUnknownError => 'Unbekannter Fehler';

  @override
  String get contactProfileNickname => 'Spitzname';

  @override
  String get contactProfileNicknameNotSet =>
      'Nicht festgelegt (tippen zum Hinzufügen)';

  @override
  String contactProfileOriginal(String name) {
    return 'Original: $name';
  }

  @override
  String get contactProfileSetNickname => 'Spitzname festlegen';

  @override
  String contactProfileOriginalName(String name) {
    return 'Originalname: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Spitzname';

  @override
  String get contactProfileNicknameHint =>
      'Benutzerdefinierten Spitznamen eingeben';

  @override
  String get contactProfileNicknameHelper =>
      'Leer lassen, um den Originalnamen zu verwenden';

  @override
  String get contactProfileNicknameCleared => 'Spitzname gelöscht';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Spitzname auf \"$name\" gesetzt';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Spitzname konnte nicht gesetzt werden: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Fingerabdruck kopieren';

  @override
  String get contactProfileNoProfile => 'Kein Profil veröffentlicht';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Dieser Benutzer hat sein Profil noch nicht veröffentlicht.';

  @override
  String get contactProfileBio => 'Biografie';

  @override
  String get contactProfileInfo => 'Info';

  @override
  String get contactProfileWebsite => 'Website';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Willkommen bei DNA Connect';

  @override
  String get identityGenerateSeed => 'Neuen Seed generieren';

  @override
  String get identityHaveSeed => 'Ich habe eine Seed-Phrase';

  @override
  String get identityYourRecoveryPhrase => 'Ihre Wiederherstellungsphrase';

  @override
  String get identityRecoveryPhraseWarning =>
      'Schreiben Sie diese Wörter auf und bewahren Sie sie sicher auf. Sie sind die einzige Möglichkeit, Ihr Konto wiederherzustellen.';

  @override
  String get identityConfirmSaved =>
      'Ich habe meine Wiederherstellungsphrase gespeichert';

  @override
  String get identityEnterRecoveryPhrase => 'Wiederherstellungsphrase eingeben';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Geben Sie Ihre 12 oder 24 Wörter umfassende Wiederherstellungsphrase ein';

  @override
  String get identityChooseName => 'Namen wählen';

  @override
  String get identityChooseNameHint => 'Anzeigenamen eingeben';

  @override
  String get identityRegisterContinue => 'Registrieren & Fortfahren';

  @override
  String get identityRegistering => 'Registrierung...';

  @override
  String get identityNameTaken => 'Dieser Name ist bereits vergeben';

  @override
  String get identityNameInvalid => 'Name muss 3–20 Zeichen lang sein';

  @override
  String get identityCreating => 'Identität wird erstellt...';

  @override
  String get identityRestoring => 'Identität wird wiederhergestellt...';

  @override
  String get wallTitle => 'Startseite';

  @override
  String get wallWelcome => 'Willkommen auf Ihrer Zeitleiste!';

  @override
  String get wallWelcomeSubtitle =>
      'Folgen Sie Personen und Kanälen, um ihre Beiträge hier zu sehen.';

  @override
  String get wallNewPost => 'Neuer Beitrag';

  @override
  String get wallDeletePost => 'Beitrag löschen';

  @override
  String get wallDeletePostConfirm =>
      'Möchten Sie diesen Beitrag wirklich löschen?';

  @override
  String get wallRepost => 'Teilen';

  @override
  String get wallReposted => 'Geteilt';

  @override
  String get wallComments => 'Kommentare';

  @override
  String get wallNoComments => 'Noch keine Kommentare';

  @override
  String get wallLoadingComments => 'Kommentare werden geladen...';

  @override
  String get wallWriteComment => 'Kommentar schreiben...';

  @override
  String get wallWriteReply => 'Antwort schreiben...';

  @override
  String wallViewAllComments(int count) {
    return 'Alle $count Kommentare anzeigen';
  }

  @override
  String get wallPostDetail => 'Beitrag';

  @override
  String get wallCopy => 'Kopieren';

  @override
  String get wallReply => 'Antworten';

  @override
  String get wallDelete => 'Löschen';

  @override
  String get wallBlockUser => 'Block User';

  @override
  String wallBlockUserConfirm(String name) {
    return 'Block $name? You will no longer see their posts or messages.';
  }

  @override
  String wallUserBlocked(String name) {
    return '$name has been blocked';
  }

  @override
  String get wallSendContactRequest => 'Send Contact Request';

  @override
  String wallContactRequestSent(String name) {
    return 'Contact request sent to $name';
  }

  @override
  String get wallContactRequestMessage => 'Message (optional)';

  @override
  String get wallUnfriend => 'Remove from Contacts';

  @override
  String wallUnfriendConfirm(String name) {
    return 'Remove $name from your contacts?';
  }

  @override
  String wallUnfriended(String name) {
    return '$name removed from contacts';
  }

  @override
  String get wallFollow => 'Follow';

  @override
  String get wallUnfollow => 'Unfollow';

  @override
  String wallFollowed(String name) {
    return 'Now following $name';
  }

  @override
  String wallUnfollowed(String name) {
    return 'Unfollowed $name';
  }

  @override
  String get wallTip => 'Trinkgeld';

  @override
  String get wallTipTitle => 'Trinkgeld für diesen Beitrag';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Trinkgeld senden';

  @override
  String get wallTipCancel => 'Abbrechen';

  @override
  String get wallTipSuccess => 'Trinkgeld gesendet!';

  @override
  String wallTipFailed(String error) {
    return 'Trinkgeld fehlgeschlagen: $error';
  }

  @override
  String get wallTipNoWallet =>
      'Dieser Benutzer hat keine Wallet-Adresse in seinem Profil';

  @override
  String get wallTipInsufficientBalance => 'Unzureichendes CPUNK-Guthaben';

  @override
  String get wallTipSending => 'Trinkgeld wird gesendet...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK Trinkgeld';
  }

  @override
  String get wallTipPending => 'Ausstehend';

  @override
  String get wallTipVerified => 'Verifiziert';

  @override
  String get wallTipFailedStatus => 'Fehlgeschlagen';

  @override
  String get wallWhatsOnYourMind => 'Was denkst du gerade?';

  @override
  String get wallPost => 'Posten';

  @override
  String get wallPosting => 'Wird gepostet...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Mit allen teilen';

  @override
  String get wallBoosted => 'Geboostet';

  @override
  String get wallBoostLimitReached => 'Tägliches Boost-Limit erreicht';

  @override
  String get wallAddComment => 'Kommentar hinzufügen (optional)';

  @override
  String get wallCreatePostTitle => 'Beitrag erstellen';

  @override
  String get walletTitle => 'Wallet';

  @override
  String get walletTotalBalance => 'Gesamtguthaben';

  @override
  String get walletSend => 'Senden';

  @override
  String get walletReceive => 'Empfangen';

  @override
  String get walletHistory => 'Verlauf';

  @override
  String get walletNoTransactions => 'Noch keine Transaktionen';

  @override
  String get walletCopyAddress => 'Adresse kopieren';

  @override
  String get walletAddressCopied => 'Adresse kopiert';

  @override
  String walletSendTitle(String coin) {
    return '$coin senden';
  }

  @override
  String get walletRecipientAddress => 'Empfängeradresse';

  @override
  String get walletAmount => 'Betrag';

  @override
  String get walletMax => 'MAX';

  @override
  String get walletSendConfirm => 'Senden bestätigen';

  @override
  String get walletSending => 'Wird gesendet...';

  @override
  String get walletSendSuccess => 'Transaktion gesendet';

  @override
  String walletSendFailed(String error) {
    return 'Transaktion fehlgeschlagen: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return '$coin empfangen';
  }

  @override
  String get walletAddressBook => 'Adressbuch';

  @override
  String get walletAddAddress => 'Adresse hinzufügen';

  @override
  String get walletEditAddress => 'Adresse bearbeiten';

  @override
  String get walletDeleteAddress => 'Adresse löschen';

  @override
  String get walletLabel => 'Bezeichnung';

  @override
  String get walletAddress => 'Adresse';

  @override
  String get walletNetwork => 'Netzwerk';

  @override
  String get walletAllChains => 'Alle';

  @override
  String get walletAssets => 'Vermögen';

  @override
  String get walletPortfolio => 'Portfolio';

  @override
  String get walletMyWallet => 'Meine Wallet';

  @override
  String get walletTxToday => 'Heute';

  @override
  String get walletTxYesterday => 'Gestern';

  @override
  String get walletTxThisWeek => 'Diese Woche';

  @override
  String get walletTxEarlier => 'Früher';

  @override
  String get walletNoNonZeroBalances => 'Keine Vermögenswerte mit Guthaben';

  @override
  String get walletNoBalances => 'Kein Guthaben';

  @override
  String get qrScannerTitle => 'QR-Scanner';

  @override
  String get qrAddContact => 'Kontakt hinzufügen';

  @override
  String get qrAuthRequest => 'Autorisierungsanfrage';

  @override
  String get qrContent => 'QR-Inhalt';

  @override
  String get qrSendContactRequest => 'Kontaktanfrage senden';

  @override
  String get qrScanAnother => 'Weiteres scannen';

  @override
  String get qrCopyFingerprint => 'Kopieren';

  @override
  String get qrRequestSent => 'Kontaktanfrage gesendet';

  @override
  String get qrInvalidCode => 'Ungültiger QR-Code';

  @override
  String get moreTitle => 'Mehr';

  @override
  String get moreWallet => 'Wallet';

  @override
  String get moreQRScanner => 'QR-Scanner';

  @override
  String get moreAddresses => 'Adressen';

  @override
  String get moreStarred => 'Markiert';

  @override
  String get moreContacts => 'Kontakte';

  @override
  String get moreSettings => 'Einstellungen';

  @override
  String get moreAppLock => 'App-Sperre';

  @override
  String get moreInviteFriends => 'Freunde einladen';

  @override
  String inviteFriendsMessage(String username) {
    return 'Hey! Probier DNA Connect — ein quantensicherer verschlüsselter Messenger. Füge mich hinzu: $username — Download: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'PIN zum Entsperren eingeben';

  @override
  String get lockIncorrectPIN => 'Falscher PIN';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Zu viele Versuche. Versuche es in ${seconds}s erneut';
  }

  @override
  String get lockUseBiometrics => 'Biometrie zum Entsperren verwenden';

  @override
  String get appLockTitle => 'App-Sperre';

  @override
  String get appLockEnable => 'App-Sperre aktivieren';

  @override
  String get appLockUseBiometrics => 'Biometrie verwenden';

  @override
  String get appLockChangePIN => 'PIN ändern';

  @override
  String get appLockSetPIN => 'PIN festlegen';

  @override
  String get appLockConfirmPIN => 'PIN bestätigen';

  @override
  String get appLockPINMismatch => 'PINs stimmen nicht überein';

  @override
  String get appLockPINSet => 'PIN erfolgreich festgelegt';

  @override
  String get appLockPINChanged => 'PIN geändert';

  @override
  String get appLockEnterCurrentPIN => 'Aktuellen PIN eingeben';

  @override
  String get appLockEnterNewPIN => 'Neuen PIN eingeben';

  @override
  String get starredTitle => 'Markierte Nachrichten';

  @override
  String get starredEmpty => 'Keine markierten Nachrichten';

  @override
  String get blockedTitle => 'Gesperrte Benutzer';

  @override
  String get blockedEmpty => 'Keine gesperrten Benutzer';

  @override
  String get blockedUnblock => 'Entsperren';

  @override
  String blockedUnblockConfirm(String name) {
    return '$name entsperren?';
  }

  @override
  String get updateTitle => 'Update erforderlich';

  @override
  String get updateMessage =>
      'Eine neuere Version ist erforderlich, um DNA Connect weiterhin zu verwenden.';

  @override
  String get updateDownload => 'Update herunterladen';

  @override
  String get updateAvailableTitle => 'Neue Version verfügbar';

  @override
  String get updateAvailableMessage =>
      'Eine neue Version von DNA Connect ist verfügbar. Jetzt aktualisieren für die neuesten Funktionen und Verbesserungen.';

  @override
  String get updateLater => 'Später';

  @override
  String get cancel => 'Abbrechen';

  @override
  String get save => 'Speichern';

  @override
  String get delete => 'Löschen';

  @override
  String get done => 'Fertig';

  @override
  String get copy => 'Kopieren';

  @override
  String get ok => 'OK';

  @override
  String get yes => 'Ja';

  @override
  String get no => 'Nein';

  @override
  String get error => 'Fehler';

  @override
  String get success => 'Erfolg';

  @override
  String get loading => 'Laden...';

  @override
  String get pleaseWait => 'Bitte warten...';

  @override
  String get copied => 'Kopiert';

  @override
  String failed(String error) {
    return 'Fehlgeschlagen: $error';
  }

  @override
  String get retry => 'Erneut versuchen';

  @override
  String get continueButton => 'Weiter';

  @override
  String get approve => 'Genehmigen';

  @override
  String get deny => 'Ablehnen';

  @override
  String get verify => 'Verifizieren';

  @override
  String get copyToClipboard => 'In die Zwischenablage kopieren';

  @override
  String get copiedToClipboard => 'In die Zwischenablage kopiert';

  @override
  String get pasteFromClipboard => 'Aus Zwischenablage einfügen';

  @override
  String get biometricsSubtitle => 'Fingerabdruck oder Face ID';

  @override
  String get changePINSubtitle => 'Entsperr-PIN aktualisieren';

  @override
  String get biometricFailed => 'Biometrische Authentifizierung fehlgeschlagen';

  @override
  String get contactRequestsWillAppear =>
      'Kontaktanfragen werden hier angezeigt';

  @override
  String get blockedUsersWillAppear =>
      'Von Ihnen gesperrte Benutzer werden hier angezeigt';

  @override
  String get failedToLoadTimeline => 'Zeitleiste konnte nicht geladen werden';

  @override
  String get userUnblocked => 'Benutzer entsperrt';

  @override
  String get backupFound => 'Sicherung gefunden';

  @override
  String approvedContact(String name) {
    return '$name genehmigt';
  }

  @override
  String deniedContact(String name) {
    return '$name abgelehnt';
  }

  @override
  String blockedContact(String name) {
    return '$name gesperrt';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Von $name abmelden';
  }

  @override
  String get chatSenderDeletedThis => 'Absender hat dies gelöscht';

  @override
  String get chatDeleteMessageTitle => 'Nachricht löschen';

  @override
  String get chatDeleteMessageConfirm =>
      'Diese Nachricht von allen Ihren Geräten löschen und die andere Person benachrichtigen?';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => 'Gespräch löschen';

  @override
  String get chatDeleteConversationTitle => 'Gespräch löschen';

  @override
  String get chatDeleteConversationConfirm =>
      'Alle Nachrichten in diesem Gespräch löschen? Dies löscht von allen Ihren Geräten.';

  @override
  String get chatConversationDeleted => 'Gespräch gelöscht';

  @override
  String get chatDeleteConversationFailed =>
      'Gespräch konnte nicht gelöscht werden';

  @override
  String get settingsDeleteAllMessages => 'Alle Nachrichten löschen';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Alle Nachrichten von allen Geräten entfernen';

  @override
  String get settingsDeleteAllMessagesTitle => 'Alle Nachrichten löschen?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Dies löscht dauerhaft ALLE Nachrichten aus ALLEN Gesprächen auf allen Ihren Geräten. Dies kann nicht rückgängig gemacht werden.';

  @override
  String get settingsAllMessagesDeleted => 'Alle Nachrichten gelöscht';

  @override
  String get settingsDeleteAllMessagesFailed =>
      'Nachrichten konnten nicht gelöscht werden';

  @override
  String get settingsDeleteEverything => 'Alles löschen';

  @override
  String get settingsGeneral => 'Allgemein';

  @override
  String get settingsDataStorage => 'Daten & Speicher';

  @override
  String get settingsAccount => 'Konto';

  @override
  String get settingsClearCache => 'Cache leeren';

  @override
  String get settingsClearCacheSubtitle =>
      'Heruntergeladene Medien und zwischengespeicherte Daten löschen';

  @override
  String settingsCacheSize(String size) {
    return 'Lokaler Cache: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'Cache leeren?';

  @override
  String get settingsClearCacheWarning =>
      'Dies löscht alle zwischengespeicherten Medien (Bilder, Videos, Audio). Sie werden bei Bedarf erneut heruntergeladen.';

  @override
  String get settingsCacheCleared => 'Cache geleert';

  @override
  String get settingsClearCacheButton => 'Leeren';

  @override
  String get txDetailSent => 'Gesendet';

  @override
  String get txDetailReceived => 'Empfangen';

  @override
  String get txDetailDenied => 'Transaktion abgelehnt';

  @override
  String get txDetailFrom => 'Von';

  @override
  String get txDetailTo => 'An';

  @override
  String get txDetailTransactionHash => 'Transaktions-Hash';

  @override
  String get txDetailTime => 'Zeit';

  @override
  String get txDetailNetwork => 'Netzwerk';

  @override
  String get txDetailMemo => 'Memo';

  @override
  String get txDetailAddressCopied => 'Adresse kopiert';

  @override
  String get txDetailHashCopied => 'Hash kopiert';

  @override
  String get txDetailAddToAddressBook => 'Zum Adressbuch hinzufügen';

  @override
  String get txDetailClose => 'Schließen';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '\"$label\" zum Adressbuch hinzugefügt';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Hinzufügen fehlgeschlagen: $error';
  }

  @override
  String get chatVideoGallery => 'Video from Library';

  @override
  String get chatRecordVideo => 'Record Video';

  @override
  String get chatVideoTooLarge => 'Video exceeds 64MB limit';

  @override
  String get chatRecordingHold => 'Hold to record';

  @override
  String get chatRecordingRelease => 'Loslassen zum Stoppen';

  @override
  String get chatRecordingTap => 'Tippen zum Aufnehmen';

  @override
  String get chatRecordingInProgress => 'Aufnahme...';

  @override
  String get chatRecordingListening => 'Wiedergabe...';

  @override
  String get chatVoiceMessage => 'Voice message';

  @override
  String get chatDownloadingMedia => 'Downloading...';

  @override
  String get chatUploadFailed => 'Upload failed. Tap to retry.';

  @override
  String get chatTapToDownload => 'Tap to download';

  @override
  String get chatVideoComingSoon => 'Video playback coming soon';

  @override
  String get chatAudioComingSoon => 'Audio playback coming soon';

  @override
  String get chatMediaUnsupported => 'Unsupported media type';

  @override
  String get chatTapToPlay => 'Tap to play';

  @override
  String get chatVideoError => 'Video playback error';

  @override
  String get chatAudioError => 'Audio playback error';

  @override
  String get userProfileTitle => 'Profile';

  @override
  String get userProfileEditProfile => 'Edit Profile';

  @override
  String get userProfileMessage => 'Message';

  @override
  String get userProfilePosts => 'Posts';

  @override
  String get userProfileNoPosts => 'No posts yet';

  @override
  String get userProfileTotalTips => 'Tips';

  @override
  String get userProfileLastMonth => 'Last Month';

  @override
  String get dnacTitle => 'Digital Cash';

  @override
  String get dnacBalance => 'Balance';

  @override
  String get dnacConfirmed => 'Available';

  @override
  String get dnacPending => 'Pending';

  @override
  String get dnacLocked => 'Locked';

  @override
  String get dnacSend => 'Send';

  @override
  String get dnacReceive => 'Receive';

  @override
  String get dnacSync => 'Sync';

  @override
  String get dnacSyncing => 'Syncing...';

  @override
  String get dnacSyncSuccess => 'Wallet synced successfully';

  @override
  String get dnacSyncFailed => 'Sync failed';

  @override
  String get dnacHistory => 'History';

  @override
  String get dnacUtxos => 'Coins';

  @override
  String get dnacNoTransactions => 'No transactions yet';

  @override
  String get dnacNoUtxos => 'No coins yet';

  @override
  String get dnacSendTitle => 'Send Payment';

  @override
  String get dnacRecipient => 'Recipient';

  @override
  String get dnacRecipientHint => 'Recipient ID';

  @override
  String get dnacAmount => 'Amount';

  @override
  String get dnacAmountHint => '0.00';

  @override
  String get dnacMemo => 'Memo (optional)';

  @override
  String get dnacMemoHint => 'What is this for?';

  @override
  String get dnacFee => 'Fee';

  @override
  String get dnacEstimatingFee => 'Estimating fee...';

  @override
  String get dnacTotal => 'Total';

  @override
  String get dnacConfirmSend => 'Confirm Payment';

  @override
  String get dnacSending => 'Sending...';

  @override
  String get dnacSendSuccess => 'Payment sent successfully';

  @override
  String get dnacSendFailed => 'Payment failed';

  @override
  String get dnacInsufficientFunds => 'Insufficient funds';

  @override
  String get dnacInvalidRecipient => 'Invalid recipient';

  @override
  String get dnacInvalidAmount => 'Invalid amount';

  @override
  String get dnacPickContact => 'Choose from contacts';

  @override
  String get dnacHistoryTitle => 'Transaction History';

  @override
  String get dnacHistoryReceived => 'Received';

  @override
  String get dnacHistorySent => 'Sent';

  @override
  String get dnacHistoryGenesis => 'Genesis';

  @override
  String get dnacHistoryBurn => 'Burned';

  @override
  String get dnacUtxosTitle => 'Coin Details';

  @override
  String get dnacUtxoUnspent => 'Available';

  @override
  String get dnacUtxoPending => 'Pending';

  @override
  String get dnacUtxoSpent => 'Spent';

  @override
  String get dnacNotInitialized => 'Wallet is loading...';

  @override
  String get dnacToken => 'DNAC';

  @override
  String dnacAmountWithToken(String amount) {
    return '$amount DNAC';
  }

  @override
  String get dnacNetworkLabel => 'DNA Chain';

  @override
  String get dnacDetailTitle => 'DNAC Details';

  @override
  String get dnacTokens => 'Tokens';

  @override
  String get dnacNoTokens => 'No tokens on this chain';

  @override
  String get dnacTokenCreate => 'Create Token';

  @override
  String get dnacTokenBalance => 'Token Balance';

  @override
  String get dnacTokenCreateName => 'Token Name';

  @override
  String get dnacTokenCreateSymbol => 'Symbol';

  @override
  String get dnacTokenCreateDecimals => 'Decimals';

  @override
  String get dnacTokenCreateSupply => 'Total Supply';

  @override
  String get dnacTokenCreating => 'Creating token...';

  @override
  String get dnacTokenCreateSuccess => 'Token created successfully';

  @override
  String get dnacTokenCreateFailed => 'Token creation failed';

  @override
  String get dnacTokenCreateFee => 'Creating a token costs 1 DNAC';

  @override
  String get walletContacts => 'Contacts';

  @override
  String get settingsActiveChains => 'Active Chains';

  @override
  String get settingsActiveChainsSubtitle =>
      'Choose which networks to show in your wallet';

  @override
  String get invalidQrCode => 'Invalid QR code';

  @override
  String reactionAdded(String emoji) {
    return 'Reacted with $emoji';
  }

  @override
  String get reactionRemoved => 'Reaction removed';

  @override
  String reactionNotificationBody(String name, String emoji) {
    return '$name reacted $emoji to your message';
  }

  @override
  String get stakeDashboardTitle => 'Earners';

  @override
  String get stakeRefresh => 'Refresh';

  @override
  String get stakeEarnersHeader => 'People earning together';

  @override
  String stakeEarnersSubtitle(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count active earners',
      one: '1 active earner',
    );
    return '$_temp0';
  }

  @override
  String stakeEarnerName(String id) {
    return 'Earner $id';
  }

  @override
  String stakeEarnerCommission(String pct) {
    return 'Keeps $pct% of rewards';
  }

  @override
  String stakeEarnerTotalLocked(String amount) {
    return '$amount DNAC locked in support';
  }

  @override
  String get stakeTrustedBadge => 'Trusted';

  @override
  String get stakeNoEarners => 'No earners yet';

  @override
  String get stakeNoEarnersSubtitle =>
      'Come back in a few minutes — the network is getting started.';

  @override
  String get stakeLoadFailed => 'Couldn\'t load earners';

  @override
  String delegationTitle(String id) {
    return 'Support earner $id';
  }

  @override
  String delegationEarnerLabel(String id) {
    return 'Earner $id';
  }

  @override
  String get delegationAmountLabel => 'Amount';

  @override
  String get delegationAmountHelper => 'Minimum 100 DNAC';

  @override
  String get delegationAmountRequired => 'Enter an amount';

  @override
  String get delegationAmountInvalid => 'Enter a valid amount';

  @override
  String get delegationAmountTooSmall => 'Minimum is 100 DNAC';

  @override
  String get delegationHoldInfo =>
      'About a 10 minute hold before you can stop supporting this earner again.';

  @override
  String get delegationRewardInfo =>
      'You\'ll share in the earner\'s rewards every block.';

  @override
  String get delegationSupportButton => 'Support this earner';

  @override
  String get delegationStopButton => 'Stop supporting';

  @override
  String get delegationSubmitting => 'Working...';

  @override
  String get delegationSupportSuccess => 'You\'re now supporting this earner.';

  @override
  String get delegationSupportFailed =>
      'Couldn\'t complete — please try again.';

  @override
  String get delegationStopSuccess => 'Stopped supporting this earner.';

  @override
  String get delegationStopFailed => 'Couldn\'t stop — please try again.';

  @override
  String delegationStopDialogTitle(String id) {
    return 'Stop supporting earner $id';
  }

  @override
  String get delegationStopDialogBody =>
      'How much would you like to pull back? You\'ll get it back after a short hold.';
}
