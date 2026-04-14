// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Dutch Flemish (`nl`).
class AppLocalizationsNl extends AppLocalizations {
  AppLocalizationsNl([String locale = 'nl']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Initialiseren...';

  @override
  String get failedToInitialize => 'Initialisatie mislukt';

  @override
  String get makeSureNativeLibrary =>
      'Zorg ervoor dat de native bibliotheek beschikbaar is.';

  @override
  String get navHome => 'Startpagina';

  @override
  String get navChats => 'Chats';

  @override
  String get navWallet => 'Portemonnee';

  @override
  String get navMore => 'Meer';

  @override
  String get messagesAll => 'Alles';

  @override
  String get messagesUnread => 'Ongelezen';

  @override
  String get messagesAllCaughtUp => 'Alles bijgewerkt!';

  @override
  String get messagesNoUnread => 'Geen ongelezen berichten';

  @override
  String get messagesSearchHint => 'Chats zoeken...';

  @override
  String get contactsTitle => 'Contacten';

  @override
  String get contactsEmpty => 'Nog geen contacten';

  @override
  String get contactsTapToAdd => 'Tik op + om een contact toe te voegen';

  @override
  String get contactsOnline => 'Online';

  @override
  String contactsLastSeen(String time) {
    return 'Laatst gezien $time';
  }

  @override
  String get contactsOffline => 'Offline';

  @override
  String get contactsSyncing => 'Synchroniseren...';

  @override
  String get contactsFailedToLoad => 'Laden van contacten mislukt';

  @override
  String get contactsRetry => 'Opnieuw proberen';

  @override
  String get contactsHubContacts => 'Contacten';

  @override
  String get contactsHubRequests => 'Verzoeken';

  @override
  String get contactsHubBlocked => 'Geblokkeerd';

  @override
  String get contactsHubRemoveTitle => 'Contact verwijderen?';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'Weet je zeker dat je $name uit je contacten wilt verwijderen?';
  }

  @override
  String get contactsHubRemove => 'Verwijderen';

  @override
  String get contactsHubFingerprintCopied => 'Vingerafdruk gekopieerd';

  @override
  String get contactRequestsTitle => 'Contactverzoeken';

  @override
  String get contactRequestsEmpty => 'Geen openstaande verzoeken';

  @override
  String get contactRequestsAccept => 'Accepteren';

  @override
  String get contactRequestsDeny => 'Weigeren';

  @override
  String get contactRequestsBlock => 'Gebruiker blokkeren';

  @override
  String get contactRequestsSent => 'Verzonden';

  @override
  String get contactRequestsReceived => 'Ontvangen';

  @override
  String get addContactTitle => 'Contact toevoegen';

  @override
  String get addContactHint => 'Voer een naam of ID in';

  @override
  String get addContactSearching => 'Zoeken...';

  @override
  String get addContactFoundOnNetwork => 'Gevonden op het netwerk';

  @override
  String get addContactNotFound => 'Niet gevonden';

  @override
  String get addContactSendRequest => 'Verzoek verzenden';

  @override
  String get addContactRequestSent => 'Contactverzoek verzonden';

  @override
  String get addContactAlreadyContact => 'Al in je contacten';

  @override
  String get addContactCannotAddSelf => 'Je kunt jezelf niet toevoegen';

  @override
  String get chatSearchMessages => 'Berichten zoeken';

  @override
  String get chatOnline => 'Online';

  @override
  String get chatOffline => 'Offline';

  @override
  String get chatConnecting => 'Verbinden...';

  @override
  String get chatTypeMessage => 'Typ een bericht';

  @override
  String get chatNoMessages => 'Nog geen berichten';

  @override
  String get chatSendFirstMessage =>
      'Stuur een bericht om het gesprek te starten';

  @override
  String get chatPhotoLibrary => 'Fotobibliotheek';

  @override
  String get chatCamera => 'Camera';

  @override
  String get chatAddCaption => 'Bijschrift toevoegen...';

  @override
  String get chatSendPhoto => 'Verzenden';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Afbeelding te groot (max $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Bericht verwijderd';

  @override
  String get chatLoadEarlier => 'Eerdere berichten laden';

  @override
  String chatLastSeen(String time) {
    return 'Laatst gezien $time';
  }

  @override
  String get chatSendTokens => 'Tokens verzenden';

  @override
  String chatSendTokensTo(String name) {
    return 'aan $name';
  }

  @override
  String get chatLookingUpWallets => 'Walletadressen opzoeken...';

  @override
  String get chatNoWalletAddresses =>
      'Contact heeft geen walletadressen in hun profiel';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Bedrag';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Beschikbaar: $balance $token';
  }

  @override
  String get chatSendMax => 'Max';

  @override
  String chatSendButton(String token) {
    return '$token verzenden';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return '$amount $token verzonden';
  }

  @override
  String get chatInvalidAmount => 'Voer een geldig bedrag in';

  @override
  String chatInsufficientBalance(String token) {
    return 'Onvoldoende $token saldo';
  }

  @override
  String get chatNoWalletForNetwork =>
      'Contact heeft geen wallet voor dit netwerk';

  @override
  String get chatSelectToken => 'Token selecteren';

  @override
  String get chatSelectNetwork => 'Netwerk selecteren';

  @override
  String get chatEnterAmount => 'Bedrag invoeren';

  @override
  String chatStepOf(String current, String total) {
    return 'Stap $current van $total';
  }

  @override
  String get messageMenuReply => 'Beantwoorden';

  @override
  String get messageMenuCopy => 'Kopiëren';

  @override
  String get messageMenuForward => 'Doorsturen';

  @override
  String get messageMenuStar => 'Markeren';

  @override
  String get messageMenuUnstar => 'Markering verwijderen';

  @override
  String get messageMenuRetry => 'Opnieuw proberen';

  @override
  String get messageMenuDelete => 'Verwijderen';

  @override
  String get groupsTitle => 'Groepen';

  @override
  String get groupsCreate => 'Groep aanmaken';

  @override
  String get groupsEmpty => 'Nog geen groepen';

  @override
  String get groupsCreateOrJoin =>
      'Maak een groep aan of accepteer een uitnodiging';

  @override
  String get groupsPendingInvitations => 'Openstaande uitnodigingen';

  @override
  String get groupsYourGroups => 'Jouw groepen';

  @override
  String get groupsInfo => 'Groepsinfo';

  @override
  String get groupsMembers => 'Leden';

  @override
  String get groupsLeave => 'Groep verlaten';

  @override
  String get groupsDelete => 'Groep verwijderen';

  @override
  String get groupsInvite => 'Uitnodigen';

  @override
  String get groupsAccept => 'Accepteren';

  @override
  String get groupsDecline => 'Afwijzen';

  @override
  String get groupsName => 'Groepsnaam';

  @override
  String get groupsDescription => 'Beschrijving';

  @override
  String get groupsCreated => 'Groep aangemaakt';

  @override
  String get groupsOwner => 'Eigenaar';

  @override
  String get groupsMember => 'Lid';

  @override
  String get groupsAdmin => 'Beheerder';

  @override
  String get groupsRemoveMember => 'Lid verwijderen';

  @override
  String groupsKickConfirm(String name) {
    return '$name uit de groep verwijderen?';
  }

  @override
  String get settingsTitle => 'Instellingen';

  @override
  String get settingsAnonymous => 'Anoniem';

  @override
  String get settingsNotLoaded => 'Niet geladen';

  @override
  String get settingsTapToEditProfile => 'Tik om profiel te bewerken';

  @override
  String get settingsAppearance => 'Weergave';

  @override
  String get settingsDarkMode => 'Donkere modus';

  @override
  String get settingsDarkModeSubtitle => 'Schakel tussen donker en licht thema';

  @override
  String get settingsLanguage => 'Taal';

  @override
  String get settingsLanguageSubtitle => 'Kies de taal van de app';

  @override
  String get settingsLanguageSystem => 'Systeemstandaard';

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
  String get settingsBattery => 'Batterij';

  @override
  String get settingsDisableBatteryOpt => 'Batterijoptimalisatie uitschakelen';

  @override
  String get settingsBatteryChecking => 'Controleren...';

  @override
  String get settingsBatteryDisabled =>
      'Uitgeschakeld — app kan op de achtergrond draaien';

  @override
  String get settingsBatteryTapToKeep =>
      'Tik om app actief te houden op de achtergrond';

  @override
  String get settingsSecurity => 'Beveiliging';

  @override
  String get settingsExportSeedPhrase => 'Herstelzin exporteren';

  @override
  String get settingsExportSeedSubtitle => 'Maak een back-up van je herstelzin';

  @override
  String get settingsAppLock => 'App-vergrendeling';

  @override
  String get settingsAppLockSubtitle => 'Verificatie vereisen';

  @override
  String get settingsExportSeedWarning =>
      'Je herstelzin geeft volledige toegang tot je identiteit. Deel deze nooit met iemand.';

  @override
  String get settingsShowSeed => 'Herstelzin tonen';

  @override
  String get settingsYourSeedPhrase => 'Jouw herstelzin';

  @override
  String get settingsSeedPhraseWarning =>
      'Schrijf deze woorden op volgorde op en bewaar ze veilig. Iedereen met deze zin kan toegang krijgen tot je identiteit.';

  @override
  String get settingsSeedCopied => 'Herstelzin gekopieerd naar klembord';

  @override
  String get settingsSeedNotAvailable =>
      'Herstelzin niet beschikbaar voor deze identiteit. Ze is aangemaakt voordat deze functie werd toegevoegd.';

  @override
  String get settingsSeedError => 'Herstelzin kan niet worden opgehaald';

  @override
  String get settingsWallet => 'Wallet';

  @override
  String get settingsHideZeroBalance => 'Nulsaldo verbergen';

  @override
  String get settingsHideZeroBalanceSubtitle => 'Munten met nulsaldo verbergen';

  @override
  String get settingsData => 'Gegevens';

  @override
  String get settingsAutoSync => 'Automatisch synchroniseren';

  @override
  String get settingsAutoSyncSubtitle =>
      'Berichten automatisch synchroniseren elke 15 minuten';

  @override
  String settingsLastSync(String time) {
    return 'Laatste synchronisatie: $time';
  }

  @override
  String get settingsSyncNow => 'Nu synchroniseren';

  @override
  String get settingsSyncNowSubtitle => 'Directe synchronisatie afdwingen';

  @override
  String get settingsLogs => 'Logboeken';

  @override
  String get settingsOpenLogsFolder => 'Logboekmap openen';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Bestandsbeheer openen in de logboekmap';

  @override
  String get settingsShareLogs => 'Logboeken delen';

  @override
  String get settingsShareLogsSubtitle => 'Logbestanden inpakken en delen';

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
  String get settingsLogsFolderNotExist => 'Logboekmap bestaat nog niet';

  @override
  String get settingsNoLogFiles => 'Geen logbestanden gevonden';

  @override
  String get settingsFailedCreateZip => 'Maken van zip-archief mislukt';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Nog geen logboeken. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Identiteit';

  @override
  String get settingsFingerprint => 'Vingerafdruk';

  @override
  String get settingsFingerprintCopied => 'Vingerafdruk gekopieerd';

  @override
  String get settingsDeleteAccount => 'Account verwijderen';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Alle gegevens permanent verwijderen van het apparaat';

  @override
  String get settingsDeleteAccountConfirm => 'Account verwijderen?';

  @override
  String get settingsDeleteAccountWarning =>
      'Dit verwijdert alle lokale gegevens permanent:';

  @override
  String get settingsDeletePrivateKeys => 'Privésleutels';

  @override
  String get settingsDeleteWallets => 'Wallets';

  @override
  String get settingsDeleteMessages => 'Berichten';

  @override
  String get settingsDeleteContacts => 'Contacten';

  @override
  String get settingsDeleteGroups => 'Groepen';

  @override
  String get settingsDeleteSeedWarning =>
      'Zorg ervoor dat je een back-up hebt gemaakt van je herstelzin voordat je verwijdert!';

  @override
  String get settingsDeleteSuccess => 'Account succesvol verwijderd';

  @override
  String settingsDeleteFailed(String error) {
    return 'Verwijderen van account mislukt: $error';
  }

  @override
  String get settingsAbout => 'Over';

  @override
  String get settingsUpdateAvailable => 'Update beschikbaar';

  @override
  String get settingsTapToDownload => 'Tik om te downloaden';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Bibliotheek v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Post-kwantum versleutelde communicatie';

  @override
  String get settingsCryptoStack => 'CRYPTO STACK';

  @override
  String get profileTitle => 'Profiel bewerken';

  @override
  String get profileInfo => 'Profielinfo';

  @override
  String get profileBio => 'Bio';

  @override
  String get profileLocation => 'Locatie';

  @override
  String get profileWebsite => 'Website';

  @override
  String get profileWalletAddresses => 'Walletadressen';

  @override
  String get profileSave => 'Profiel opslaan';

  @override
  String get profileShareQR => 'Mijn QR-code delen';

  @override
  String get profileAvatar => 'Avatar';

  @override
  String get profileTakeSelfie => 'Selfie maken';

  @override
  String get profileChooseFromGallery => 'Kiezen uit galerij';

  @override
  String get profileSaved => 'Profiel opgeslagen';

  @override
  String profileSaveFailed(String error) {
    return 'Profiel opslaan mislukt: $error';
  }

  @override
  String get profileCropTitle => 'Avatar bijsnijden';

  @override
  String get profileCropSave => 'Opslaan';

  @override
  String get contactProfileFailed => 'Profiel laden mislukt';

  @override
  String get contactProfileUnknownError => 'Onbekende fout';

  @override
  String get contactProfileNickname => 'Bijnaam';

  @override
  String get contactProfileNicknameNotSet =>
      'Niet ingesteld (tik om toe te voegen)';

  @override
  String contactProfileOriginal(String name) {
    return 'Origineel: $name';
  }

  @override
  String get contactProfileSetNickname => 'Bijnaam instellen';

  @override
  String contactProfileOriginalName(String name) {
    return 'Originele naam: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Bijnaam';

  @override
  String get contactProfileNicknameHint => 'Aangepaste bijnaam invoeren';

  @override
  String get contactProfileNicknameHelper =>
      'Laat leeg om de originele naam te gebruiken';

  @override
  String get contactProfileNicknameCleared => 'Bijnaam gewist';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Bijnaam ingesteld op \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Bijnaam instellen mislukt: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Vingerafdruk kopiëren';

  @override
  String get contactProfileNoProfile => 'Geen profiel gepubliceerd';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Deze gebruiker heeft zijn profiel nog niet gepubliceerd.';

  @override
  String get contactProfileBio => 'Bio';

  @override
  String get contactProfileInfo => 'Info';

  @override
  String get contactProfileWebsite => 'Website';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Welkom bij DNA Connect';

  @override
  String get identityGenerateSeed => 'Nieuwe herstelzin genereren';

  @override
  String get identityHaveSeed => 'Ik heb een herstelzin';

  @override
  String get identityYourRecoveryPhrase => 'Jouw herstelzin';

  @override
  String get identityRecoveryPhraseWarning =>
      'Schrijf deze woorden op en bewaar ze veilig. Ze zijn de enige manier om je account te herstellen.';

  @override
  String get identityConfirmSaved => 'Ik heb mijn herstelzin opgeslagen';

  @override
  String get identityEnterRecoveryPhrase => 'Herstelzin invoeren';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Voer je herstelzin van 12 of 24 woorden in';

  @override
  String get identityChooseName => 'Kies je naam';

  @override
  String get identityChooseNameHint => 'Voer een weergavenaam in';

  @override
  String get identityRegisterContinue => 'Registreren & doorgaan';

  @override
  String get identityRegistering => 'Registreren...';

  @override
  String get identityNameTaken => 'Deze naam is al bezet';

  @override
  String get identityNameInvalid => 'Naam moet 3-20 tekens bevatten';

  @override
  String get identityCreating => 'Je identiteit aanmaken...';

  @override
  String get identityRestoring => 'Je identiteit herstellen...';

  @override
  String get wallTitle => 'Startpagina';

  @override
  String get wallWelcome => 'Welkom op je tijdlijn!';

  @override
  String get wallWelcomeSubtitle =>
      'Volg mensen en kanalen om hun berichten hier te zien.';

  @override
  String get wallNewPost => 'Nieuw bericht';

  @override
  String get wallDeletePost => 'Bericht verwijderen';

  @override
  String get wallDeletePostConfirm =>
      'Weet je zeker dat je dit bericht wilt verwijderen?';

  @override
  String get wallRepost => 'Opnieuw delen';

  @override
  String get wallReposted => 'Opnieuw gedeeld';

  @override
  String get wallComments => 'Reacties';

  @override
  String get wallNoComments => 'Nog geen reacties';

  @override
  String get wallLoadingComments => 'Reacties laden...';

  @override
  String get wallWriteComment => 'Schrijf een reactie...';

  @override
  String get wallWriteReply => 'Schrijf een antwoord...';

  @override
  String wallViewAllComments(int count) {
    return 'Alle $count reacties bekijken';
  }

  @override
  String get wallPostDetail => 'Bericht';

  @override
  String get wallCopy => 'Kopiëren';

  @override
  String get wallReply => 'Beantwoorden';

  @override
  String get wallDelete => 'Verwijderen';

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
  String get wallTip => 'Fooi';

  @override
  String get wallTipTitle => 'Geef een fooi voor dit bericht';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Fooi sturen';

  @override
  String get wallTipCancel => 'Annuleren';

  @override
  String get wallTipSuccess => 'Fooi verstuurd!';

  @override
  String wallTipFailed(String error) {
    return 'Fooi mislukt: $error';
  }

  @override
  String get wallTipNoWallet =>
      'Deze gebruiker heeft geen wallet-adres in het profiel';

  @override
  String get wallTipInsufficientBalance => 'Onvoldoende CPUNK-saldo';

  @override
  String get wallTipSending => 'Fooi wordt verstuurd...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK fooi';
  }

  @override
  String get wallTipPending => 'In afwachting';

  @override
  String get wallTipVerified => 'Geverifieerd';

  @override
  String get wallTipFailedStatus => 'Mislukt';

  @override
  String get wallWhatsOnYourMind => 'Waar denk je aan?';

  @override
  String get wallPost => 'Plaatsen';

  @override
  String get wallPosting => 'Plaatsen...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Deel met iedereen';

  @override
  String get wallBoosted => 'Geboost';

  @override
  String get wallBoostLimitReached => 'Dagelijkse boost-limiet bereikt';

  @override
  String get wallAddComment => 'Voeg een opmerking toe (optioneel)';

  @override
  String get wallCreatePostTitle => 'Bericht maken';

  @override
  String get walletTitle => 'Wallet';

  @override
  String get walletTotalBalance => 'Totaal saldo';

  @override
  String get walletSend => 'Verzenden';

  @override
  String get walletReceive => 'Ontvangen';

  @override
  String get walletHistory => 'Geschiedenis';

  @override
  String get walletNoTransactions => 'Nog geen transacties';

  @override
  String get walletCopyAddress => 'Adres kopiëren';

  @override
  String get walletAddressCopied => 'Adres gekopieerd';

  @override
  String walletSendTitle(String coin) {
    return '$coin verzenden';
  }

  @override
  String get walletRecipientAddress => 'Ontvangersadres';

  @override
  String get walletAmount => 'Bedrag';

  @override
  String get walletMax => 'MAX';

  @override
  String get walletSendConfirm => 'Verzending bevestigen';

  @override
  String get walletSending => 'Verzenden...';

  @override
  String get walletSendSuccess => 'Transactie verzonden';

  @override
  String walletSendFailed(String error) {
    return 'Transactie mislukt: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return '$coin ontvangen';
  }

  @override
  String get walletAddressBook => 'Adresboek';

  @override
  String get walletAddAddress => 'Adres toevoegen';

  @override
  String get walletEditAddress => 'Adres bewerken';

  @override
  String get walletDeleteAddress => 'Adres verwijderen';

  @override
  String get walletLabel => 'Label';

  @override
  String get walletAddress => 'Adres';

  @override
  String get walletNetwork => 'Netwerk';

  @override
  String get walletAllChains => 'Alles';

  @override
  String get walletAssets => 'Activa';

  @override
  String get walletPortfolio => 'Portfolio';

  @override
  String get walletMyWallet => 'Mijn Wallet';

  @override
  String get walletTxToday => 'Vandaag';

  @override
  String get walletTxYesterday => 'Gisteren';

  @override
  String get walletTxThisWeek => 'Deze Week';

  @override
  String get walletTxEarlier => 'Eerder';

  @override
  String get walletNoNonZeroBalances => 'Geen activa met saldo';

  @override
  String get walletNoBalances => 'Geen saldo';

  @override
  String get qrScannerTitle => 'QR-scanner';

  @override
  String get qrAddContact => 'Contact toevoegen';

  @override
  String get qrAuthRequest => 'Autorisatieverzoek';

  @override
  String get qrContent => 'QR-inhoud';

  @override
  String get qrSendContactRequest => 'Contactverzoek verzenden';

  @override
  String get qrScanAnother => 'Nog een scannen';

  @override
  String get qrCopyFingerprint => 'Kopiëren';

  @override
  String get qrRequestSent => 'Contactverzoek verzonden';

  @override
  String get qrInvalidCode => 'Ongeldige QR-code';

  @override
  String get moreTitle => 'Meer';

  @override
  String get moreWallet => 'Wallet';

  @override
  String get moreQRScanner => 'QR-scanner';

  @override
  String get moreAddresses => 'Adressen';

  @override
  String get moreStarred => 'Gemarkeerd';

  @override
  String get moreContacts => 'Contacten';

  @override
  String get moreSettings => 'Instellingen';

  @override
  String get moreAppLock => 'App-vergrendeling';

  @override
  String get moreInviteFriends => 'Vrienden uitnodigen';

  @override
  String inviteFriendsMessage(String username) {
    return 'Hey! Probeer DNA Connect — een kwantumveilige versleutelde messenger. Voeg me toe: $username — Download: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Voer PIN in om te ontgrendelen';

  @override
  String get lockIncorrectPIN => 'Onjuiste PIN';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Te veel pogingen. Probeer opnieuw over ${seconds}s';
  }

  @override
  String get lockUseBiometrics => 'Gebruik biometrie om te ontgrendelen';

  @override
  String get appLockTitle => 'App-vergrendeling';

  @override
  String get appLockEnable => 'App-vergrendeling inschakelen';

  @override
  String get appLockUseBiometrics => 'Biometrie gebruiken';

  @override
  String get appLockChangePIN => 'PIN wijzigen';

  @override
  String get appLockSetPIN => 'PIN instellen';

  @override
  String get appLockConfirmPIN => 'PIN bevestigen';

  @override
  String get appLockPINMismatch => 'PIN-codes komen niet overeen';

  @override
  String get appLockPINSet => 'PIN succesvol ingesteld';

  @override
  String get appLockPINChanged => 'PIN gewijzigd';

  @override
  String get appLockEnterCurrentPIN => 'Huidige PIN invoeren';

  @override
  String get appLockEnterNewPIN => 'Nieuwe PIN invoeren';

  @override
  String get starredTitle => 'Gemarkeerde berichten';

  @override
  String get starredEmpty => 'Geen gemarkeerde berichten';

  @override
  String get blockedTitle => 'Geblokkeerde gebruikers';

  @override
  String get blockedEmpty => 'Geen geblokkeerde gebruikers';

  @override
  String get blockedUnblock => 'Deblokkeren';

  @override
  String blockedUnblockConfirm(String name) {
    return '$name deblokkeren?';
  }

  @override
  String get updateTitle => 'Update vereist';

  @override
  String get updateMessage =>
      'Een nieuwere versie is vereist om DNA Connect te blijven gebruiken.';

  @override
  String get updateDownload => 'Update downloaden';

  @override
  String get updateAvailableTitle => 'Nieuwe versie beschikbaar';

  @override
  String get updateAvailableMessage =>
      'Er is een nieuwe versie van DNA Connect beschikbaar. Update nu voor de nieuwste functies en verbeteringen.';

  @override
  String get updateLater => 'Later';

  @override
  String get cancel => 'Annuleren';

  @override
  String get save => 'Opslaan';

  @override
  String get delete => 'Verwijderen';

  @override
  String get done => 'Klaar';

  @override
  String get copy => 'Kopiëren';

  @override
  String get ok => 'OK';

  @override
  String get yes => 'Ja';

  @override
  String get no => 'Nee';

  @override
  String get error => 'Fout';

  @override
  String get success => 'Geslaagd';

  @override
  String get loading => 'Laden...';

  @override
  String get pleaseWait => 'Even geduld...';

  @override
  String get copied => 'Gekopieerd';

  @override
  String failed(String error) {
    return 'Mislukt: $error';
  }

  @override
  String get retry => 'Opnieuw proberen';

  @override
  String get continueButton => 'Doorgaan';

  @override
  String get approve => 'Goedkeuren';

  @override
  String get deny => 'Weigeren';

  @override
  String get verify => 'Verifiëren';

  @override
  String get copyToClipboard => 'Kopiëren naar klembord';

  @override
  String get copiedToClipboard => 'Gekopieerd naar klembord';

  @override
  String get pasteFromClipboard => 'Plakken vanuit klembord';

  @override
  String get biometricsSubtitle => 'Vingerafdruk of Face ID';

  @override
  String get changePINSubtitle => 'Je ontgrendel-PIN bijwerken';

  @override
  String get biometricFailed => 'Biometrische verificatie mislukt';

  @override
  String get contactRequestsWillAppear => 'Contactverzoeken verschijnen hier';

  @override
  String get blockedUsersWillAppear =>
      'Gebruikers die je blokkeert verschijnen hier';

  @override
  String get failedToLoadTimeline => 'Tijdlijn laden mislukt';

  @override
  String get userUnblocked => 'Gebruiker gedeblokkeerd';

  @override
  String get backupFound => 'Back-up gevonden';

  @override
  String approvedContact(String name) {
    return '$name goedgekeurd';
  }

  @override
  String deniedContact(String name) {
    return '$name geweigerd';
  }

  @override
  String blockedContact(String name) {
    return '$name geblokkeerd';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Abonnement opzeggen op $name';
  }

  @override
  String get chatSenderDeletedThis => 'Afzender heeft dit verwijderd';

  @override
  String get chatDeleteMessageTitle => 'Bericht verwijderen';

  @override
  String get chatDeleteMessageConfirm =>
      'Dit bericht verwijderen van al je apparaten en de andere persoon hiervan op de hoogte stellen?';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => 'Gesprek verwijderen';

  @override
  String get chatDeleteConversationTitle => 'Gesprek verwijderen';

  @override
  String get chatDeleteConversationConfirm =>
      'Alle berichten in dit gesprek verwijderen? Dit wordt verwijderd van al je apparaten.';

  @override
  String get chatConversationDeleted => 'Gesprek verwijderd';

  @override
  String get chatDeleteConversationFailed => 'Gesprek verwijderen mislukt';

  @override
  String get settingsDeleteAllMessages => 'Alle berichten verwijderen';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Alle berichten van alle apparaten verwijderen';

  @override
  String get settingsDeleteAllMessagesTitle => 'Alle berichten verwijderen?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Dit verwijdert ALLE berichten uit ALLE gesprekken op al je apparaten permanent. Dit kan niet ongedaan worden gemaakt.';

  @override
  String get settingsAllMessagesDeleted => 'Alle berichten verwijderd';

  @override
  String get settingsDeleteAllMessagesFailed => 'Berichten verwijderen mislukt';

  @override
  String get settingsDeleteEverything => 'Alles verwijderen';

  @override
  String get settingsGeneral => 'Algemeen';

  @override
  String get settingsDataStorage => 'Gegevens en opslag';

  @override
  String get settingsAccount => 'Account';

  @override
  String get settingsClearCache => 'Cache wissen';

  @override
  String get settingsClearCacheSubtitle =>
      'Gedownloade media en gecachte gegevens verwijderen';

  @override
  String settingsCacheSize(String size) {
    return 'Lokale cache: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'Cache wissen?';

  @override
  String get settingsClearCacheWarning =>
      'Dit verwijdert alle gecachte media (afbeeldingen, video\'s, audio). Ze worden opnieuw gedownload wanneer nodig.';

  @override
  String get settingsCacheCleared => 'Cache gewist';

  @override
  String get settingsClearCacheButton => 'Wissen';

  @override
  String get txDetailSent => 'Verzonden';

  @override
  String get txDetailReceived => 'Ontvangen';

  @override
  String get txDetailDenied => 'Transactie geweigerd';

  @override
  String get txDetailFrom => 'Van';

  @override
  String get txDetailTo => 'Aan';

  @override
  String get txDetailTransactionHash => 'Transactiehash';

  @override
  String get txDetailTime => 'Tijd';

  @override
  String get txDetailNetwork => 'Netwerk';

  @override
  String get txDetailAddressCopied => 'Adres gekopieerd';

  @override
  String get txDetailHashCopied => 'Hash gekopieerd';

  @override
  String get txDetailAddToAddressBook => 'Toevoegen aan adresboek';

  @override
  String get txDetailClose => 'Sluiten';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '\"$label\" toegevoegd aan adresboek';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Toevoegen mislukt: $error';
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
  String get chatRecordingRelease => 'Loslaten om te stoppen';

  @override
  String get chatRecordingTap => 'Tik om op te nemen';

  @override
  String get chatRecordingInProgress => 'Opnemen...';

  @override
  String get chatRecordingListening => 'Afspelen...';

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
}
