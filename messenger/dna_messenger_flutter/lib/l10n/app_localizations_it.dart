// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Italian (`it`).
class AppLocalizationsIt extends AppLocalizations {
  AppLocalizationsIt([String locale = 'it']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Inizializzazione...';

  @override
  String get failedToInitialize => 'Inizializzazione fallita';

  @override
  String get makeSureNativeLibrary =>
      'Assicurati che la libreria nativa sia disponibile.';

  @override
  String get navHome => 'Home';

  @override
  String get navChats => 'Chat';

  @override
  String get navWallet => 'Portafoglio';

  @override
  String get navMore => 'Altro';

  @override
  String get messagesAll => 'Tutti';

  @override
  String get messagesUnread => 'Non letti';

  @override
  String get messagesAllCaughtUp => 'Sei in pari!';

  @override
  String get messagesNoUnread => 'Nessun messaggio non letto';

  @override
  String get messagesSearchHint => 'Cerca chat...';

  @override
  String get contactsTitle => 'Contatti';

  @override
  String get contactsEmpty => 'Nessun contatto';

  @override
  String get contactsTapToAdd => 'Tocca + per aggiungere un contatto';

  @override
  String get contactsOnline => 'Online';

  @override
  String contactsLastSeen(String time) {
    return 'Visto $time';
  }

  @override
  String get contactsOffline => 'Offline';

  @override
  String get contactsSyncing => 'Sincronizzazione...';

  @override
  String get contactsFailedToLoad => 'Caricamento contatti fallito';

  @override
  String get contactsRetry => 'Riprova';

  @override
  String get contactsHubContacts => 'Contatti';

  @override
  String get contactsHubRequests => 'Richieste';

  @override
  String get contactsHubBlocked => 'Bloccati';

  @override
  String get contactsHubRemoveTitle => 'Rimuovere il contatto?';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'Sei sicuro di voler rimuovere $name dai tuoi contatti?';
  }

  @override
  String get contactsHubRemove => 'Rimuovi';

  @override
  String get contactsHubFingerprintCopied => 'Impronta copiata';

  @override
  String get contactRequestsTitle => 'Richieste di contatto';

  @override
  String get contactRequestsEmpty => 'Nessuna richiesta in sospeso';

  @override
  String get contactRequestsAccept => 'Accetta';

  @override
  String get contactRequestsDeny => 'Rifiuta';

  @override
  String get contactRequestsBlock => 'Blocca utente';

  @override
  String get contactRequestsSent => 'Inviata';

  @override
  String get contactRequestsReceived => 'Ricevuta';

  @override
  String get addContactTitle => 'Aggiungi contatto';

  @override
  String get addContactHint => 'Inserisci un nome o ID';

  @override
  String get addContactSearching => 'Ricerca in corso...';

  @override
  String get addContactFoundOnNetwork => 'Trovato nella rete';

  @override
  String get addContactNotFound => 'Non trovato';

  @override
  String get addContactSendRequest => 'Invia richiesta';

  @override
  String get addContactRequestSent => 'Richiesta di contatto inviata';

  @override
  String get addContactAlreadyContact => 'Già nei tuoi contatti';

  @override
  String get addContactCannotAddSelf => 'Non puoi aggiungere te stesso';

  @override
  String get chatSearchMessages => 'Cerca messaggi';

  @override
  String get chatOnline => 'Online';

  @override
  String get chatOffline => 'Offline';

  @override
  String get chatConnecting => 'Connessione in corso...';

  @override
  String get chatTypeMessage => 'Scrivi un messaggio';

  @override
  String get chatNoMessages => 'Nessun messaggio';

  @override
  String get chatSendFirstMessage =>
      'Invia un messaggio per iniziare la conversazione';

  @override
  String get chatPhotoLibrary => 'Libreria foto';

  @override
  String get chatCamera => 'Fotocamera';

  @override
  String get chatAddCaption => 'Aggiungi didascalia...';

  @override
  String get chatSendPhoto => 'Invia';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Immagine troppo grande (max $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Messaggio eliminato';

  @override
  String get chatLoadEarlier => 'Carica messaggi precedenti';

  @override
  String chatLastSeen(String time) {
    return 'Visto $time';
  }

  @override
  String get chatSendTokens => 'Invia token';

  @override
  String chatSendTokensTo(String name) {
    return 'a $name';
  }

  @override
  String get chatLookingUpWallets => 'Ricerca indirizzi wallet...';

  @override
  String get chatNoWalletAddresses =>
      'Il contatto non ha indirizzi wallet nel profilo';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Importo';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Disponibile: $balance $token';
  }

  @override
  String get chatSendMax => 'Max';

  @override
  String chatSendButton(String token) {
    return 'Invia $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return 'Inviati $amount $token';
  }

  @override
  String get chatInvalidAmount => 'Inserisci un importo valido';

  @override
  String chatInsufficientBalance(String token) {
    return 'Saldo $token insufficiente';
  }

  @override
  String get chatNoWalletForNetwork =>
      'Il contatto non ha un wallet per questa rete';

  @override
  String get chatSelectToken => 'Seleziona token';

  @override
  String get chatSelectNetwork => 'Seleziona rete';

  @override
  String get chatEnterAmount => 'Inserisci importo';

  @override
  String chatStepOf(String current, String total) {
    return 'Passo $current di $total';
  }

  @override
  String get messageMenuReply => 'Rispondi';

  @override
  String get messageMenuCopy => 'Copia';

  @override
  String get messageMenuForward => 'Inoltra';

  @override
  String get messageMenuStar => 'Aggiungi stella';

  @override
  String get messageMenuUnstar => 'Rimuovi stella';

  @override
  String get messageMenuRetry => 'Riprova';

  @override
  String get messageMenuDelete => 'Elimina';

  @override
  String get groupsTitle => 'Gruppi';

  @override
  String get groupsCreate => 'Crea gruppo';

  @override
  String get groupsEmpty => 'Nessun gruppo';

  @override
  String get groupsCreateOrJoin => 'Crea un gruppo o accetta un invito';

  @override
  String get groupsPendingInvitations => 'Inviti in sospeso';

  @override
  String get groupsYourGroups => 'I tuoi gruppi';

  @override
  String get groupsInfo => 'Info gruppo';

  @override
  String get groupsMembers => 'Membri';

  @override
  String get groupsLeave => 'Lascia gruppo';

  @override
  String get groupsDelete => 'Elimina gruppo';

  @override
  String get groupsInvite => 'Invita';

  @override
  String get groupsAccept => 'Accetta';

  @override
  String get groupsDecline => 'Rifiuta';

  @override
  String get groupsName => 'Nome gruppo';

  @override
  String get groupsDescription => 'Descrizione';

  @override
  String get groupsCreated => 'Gruppo creato';

  @override
  String get groupsOwner => 'Proprietario';

  @override
  String get groupsMember => 'Membro';

  @override
  String get groupsAdmin => 'Admin';

  @override
  String get groupsRemoveMember => 'Rimuovi membro';

  @override
  String groupsKickConfirm(String name) {
    return 'Rimuovere $name dal gruppo?';
  }

  @override
  String get settingsTitle => 'Impostazioni';

  @override
  String get settingsAnonymous => 'Anonimo';

  @override
  String get settingsNotLoaded => 'Non caricato';

  @override
  String get settingsTapToEditProfile => 'Tocca per modificare il profilo';

  @override
  String get settingsAppearance => 'Aspetto';

  @override
  String get settingsDarkMode => 'Modalità scura';

  @override
  String get settingsDarkModeSubtitle => 'Passa tra tema scuro e chiaro';

  @override
  String get settingsLanguage => 'Lingua';

  @override
  String get settingsLanguageSubtitle => 'Scegli la lingua dell\'app';

  @override
  String get settingsLanguageSystem => 'Predefinito di sistema';

  @override
  String get settingsLanguageEnglish => 'English';

  @override
  String get settingsLanguageTurkish => 'Türkçe';

  @override
  String get settingsLanguageItalian => 'Italiano';

  @override
  String get settingsLanguageSpanish => 'Spagnolo';

  @override
  String get settingsLanguageRussian => 'Russo';

  @override
  String get settingsLanguageDutch => 'Olandese';

  @override
  String get settingsLanguageGerman => 'Tedesco';

  @override
  String get settingsLanguageChinese => 'Cinese';

  @override
  String get settingsLanguageJapanese => 'Giapponese';

  @override
  String get settingsLanguagePortuguese => 'Portoghese';

  @override
  String get settingsLanguageArabic => 'العربية';

  @override
  String get settingsBattery => 'Batteria';

  @override
  String get settingsDisableBatteryOpt => 'Disabilita ottimizzazione batteria';

  @override
  String get settingsBatteryChecking => 'Controllo in corso...';

  @override
  String get settingsBatteryDisabled =>
      'Disabilitata — l\'app può girare in background';

  @override
  String get settingsBatteryTapToKeep =>
      'Tocca per mantenere l\'app attiva in background';

  @override
  String get settingsSecurity => 'Sicurezza';

  @override
  String get settingsExportSeedPhrase => 'Esporta frase seed';

  @override
  String get settingsExportSeedSubtitle =>
      'Esegui il backup della frase di recupero';

  @override
  String get settingsAppLock => 'Blocco app';

  @override
  String get settingsAppLockSubtitle => 'Richiedi autenticazione';

  @override
  String get settingsExportSeedWarning =>
      'La tua frase seed fornisce accesso completo alla tua identità. Non condividerla mai con nessuno.';

  @override
  String get settingsShowSeed => 'Mostra seed';

  @override
  String get settingsYourSeedPhrase => 'La tua frase seed';

  @override
  String get settingsSeedPhraseWarning =>
      'Scrivi queste parole nell\'ordine corretto e conservale in sicurezza. Chiunque abbia questa frase può accedere alla tua identità.';

  @override
  String get settingsSeedCopied => 'Frase seed copiata negli appunti';

  @override
  String get settingsSeedNotAvailable =>
      'Frase seed non disponibile per questa identità. È stata creata prima che questa funzione venisse aggiunta.';

  @override
  String get settingsSeedError => 'Impossibile recuperare la frase seed';

  @override
  String get settingsWallet => 'Wallet';

  @override
  String get settingsHideZeroBalance => 'Nascondi saldo zero';

  @override
  String get settingsHideZeroBalanceSubtitle =>
      'Nascondi le monete con saldo zero';

  @override
  String get settingsData => 'Dati';

  @override
  String get settingsAutoSync => 'Sincronizzazione automatica';

  @override
  String get settingsAutoSyncSubtitle =>
      'Sincronizza i messaggi automaticamente ogni 15 minuti';

  @override
  String settingsLastSync(String time) {
    return 'Ultima sincronizzazione: $time';
  }

  @override
  String get settingsSyncNow => 'Sincronizza ora';

  @override
  String get settingsSyncNowSubtitle => 'Forza sincronizzazione immediata';

  @override
  String get settingsLogs => 'Log';

  @override
  String get settingsOpenLogsFolder => 'Apri cartella log';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Apri il gestore file nella directory dei log';

  @override
  String get settingsShareLogs => 'Condividi log';

  @override
  String get settingsShareLogsSubtitle => 'Comprimi e condividi i file di log';

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
  String get settingsLogsFolderNotExist => 'La cartella log non esiste ancora';

  @override
  String get settingsNoLogFiles => 'Nessun file di log trovato';

  @override
  String get settingsFailedCreateZip => 'Creazione archivio zip fallita';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Nessun log ancora. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Identità';

  @override
  String get settingsFingerprint => 'Impronta';

  @override
  String get settingsFingerprintCopied => 'Impronta copiata';

  @override
  String get settingsDeleteAccount => 'Elimina account';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Elimina definitivamente tutti i dati dal dispositivo';

  @override
  String get settingsDeleteAccountConfirm => 'Eliminare l\'account?';

  @override
  String get settingsDeleteAccountWarning =>
      'Questo eliminerà definitivamente tutti i dati locali:';

  @override
  String get settingsDeletePrivateKeys => 'Chiavi private';

  @override
  String get settingsDeleteWallets => 'Wallet';

  @override
  String get settingsDeleteMessages => 'Messaggi';

  @override
  String get settingsDeleteContacts => 'Contatti';

  @override
  String get settingsDeleteGroups => 'Gruppi';

  @override
  String get settingsDeleteSeedWarning =>
      'Assicurati di aver eseguito il backup della frase seed prima di eliminare!';

  @override
  String get settingsDeleteSuccess => 'Account eliminato con successo';

  @override
  String settingsDeleteFailed(String error) {
    return 'Eliminazione account fallita: $error';
  }

  @override
  String get settingsAbout => 'Informazioni';

  @override
  String get settingsUpdateAvailable => 'Aggiornamento disponibile';

  @override
  String get settingsTapToDownload => 'Tocca per scaricare';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Libreria v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Comunicazione con crittografia post-quantistica';

  @override
  String get settingsCryptoStack => 'STACK CRITTOGRAFICO';

  @override
  String get profileTitle => 'Modifica profilo';

  @override
  String get profileInfo => 'Info profilo';

  @override
  String get profileBio => 'Biografia';

  @override
  String get profileLocation => 'Posizione';

  @override
  String get profileWebsite => 'Sito web';

  @override
  String get profileWalletAddresses => 'Indirizzi wallet';

  @override
  String get profileSave => 'Salva profilo';

  @override
  String get profileShareQR => 'Condividi il mio QR';

  @override
  String get profileAvatar => 'Avatar';

  @override
  String get profileTakeSelfie => 'Scatta un selfie';

  @override
  String get profileChooseFromGallery => 'Scegli dalla galleria';

  @override
  String get profileSaved => 'Profilo salvato';

  @override
  String profileSaveFailed(String error) {
    return 'Salvataggio profilo fallito: $error';
  }

  @override
  String get profileCropTitle => 'Ritaglia avatar';

  @override
  String get profileCropSave => 'Salva';

  @override
  String get contactProfileFailed => 'Caricamento profilo fallito';

  @override
  String get contactProfileUnknownError => 'Errore sconosciuto';

  @override
  String get contactProfileNickname => 'Soprannome';

  @override
  String get contactProfileNicknameNotSet =>
      'Non impostato (tocca per aggiungere)';

  @override
  String contactProfileOriginal(String name) {
    return 'Originale: $name';
  }

  @override
  String get contactProfileSetNickname => 'Imposta soprannome';

  @override
  String contactProfileOriginalName(String name) {
    return 'Nome originale: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Soprannome';

  @override
  String get contactProfileNicknameHint =>
      'Inserisci un soprannome personalizzato';

  @override
  String get contactProfileNicknameHelper =>
      'Lascia vuoto per usare il nome originale';

  @override
  String get contactProfileNicknameCleared => 'Soprannome rimosso';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Soprannome impostato su \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Impostazione soprannome fallita: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Copia impronta';

  @override
  String get contactProfileNoProfile => 'Nessun profilo pubblicato';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Questo utente non ha ancora pubblicato il suo profilo.';

  @override
  String get contactProfileBio => 'Biografia';

  @override
  String get contactProfileInfo => 'Info';

  @override
  String get contactProfileWebsite => 'Sito web';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Benvenuto in DNA Connect';

  @override
  String get identityGenerateSeed => 'Genera nuovo seed';

  @override
  String get identityHaveSeed => 'Ho una frase seed';

  @override
  String get identityYourRecoveryPhrase => 'La tua frase di recupero';

  @override
  String get identityRecoveryPhraseWarning =>
      'Scrivi queste parole e conservale al sicuro. Sono l\'unico modo per recuperare il tuo account.';

  @override
  String get identityConfirmSaved => 'Ho salvato la mia frase di recupero';

  @override
  String get identityEnterRecoveryPhrase => 'Inserisci la frase di recupero';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Inserisci la tua frase di recupero di 12 o 24 parole';

  @override
  String get identityChooseName => 'Scegli il tuo nome';

  @override
  String get identityChooseNameHint => 'Inserisci un nome visualizzato';

  @override
  String get identityRegisterContinue => 'Registrati e continua';

  @override
  String get identityRegistering => 'Registrazione...';

  @override
  String get identityNameTaken => 'Questo nome è già in uso';

  @override
  String get identityNameInvalid =>
      'Il nome deve contenere da 3 a 20 caratteri';

  @override
  String get identityCreating => 'Creazione identità in corso...';

  @override
  String get identityRestoring => 'Ripristino identità in corso...';

  @override
  String get wallTitle => 'Home';

  @override
  String get wallWelcome => 'Benvenuto nella tua timeline!';

  @override
  String get wallWelcomeSubtitle =>
      'Segui persone e canali per vedere i loro post qui.';

  @override
  String get wallNewPost => 'Nuovo post';

  @override
  String get wallDeletePost => 'Elimina post';

  @override
  String get wallDeletePostConfirm =>
      'Sei sicuro di voler eliminare questo post?';

  @override
  String get wallRepost => 'Ricondividi';

  @override
  String get wallReposted => 'Ricondiviso';

  @override
  String get wallComments => 'Commenti';

  @override
  String get wallNoComments => 'Nessun commento';

  @override
  String get wallLoadingComments => 'Caricamento commenti...';

  @override
  String get wallWriteComment => 'Scrivi un commento...';

  @override
  String get wallWriteReply => 'Scrivi una risposta...';

  @override
  String wallViewAllComments(int count) {
    return 'Visualizza tutti i $count commenti';
  }

  @override
  String get wallPostDetail => 'Post';

  @override
  String get wallCopy => 'Copia';

  @override
  String get wallReply => 'Rispondi';

  @override
  String get wallDelete => 'Elimina';

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
  String get wallTip => 'Mancia';

  @override
  String get wallTipTitle => 'Dai una mancia a questo post';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Invia mancia';

  @override
  String get wallTipCancel => 'Annulla';

  @override
  String get wallTipSuccess => 'Mancia inviata!';

  @override
  String wallTipFailed(String error) {
    return 'Mancia fallita: $error';
  }

  @override
  String get wallTipNoWallet =>
      'Questo utente non ha un indirizzo wallet nel profilo';

  @override
  String get wallTipInsufficientBalance => 'Saldo CPUNK insufficiente';

  @override
  String get wallTipSending => 'Invio mancia...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK di mancia';
  }

  @override
  String get wallTipPending => 'In attesa';

  @override
  String get wallTipVerified => 'Verificato';

  @override
  String get wallTipFailedStatus => 'Fallito';

  @override
  String get wallWhatsOnYourMind => 'A cosa stai pensando?';

  @override
  String get wallPost => 'Pubblica';

  @override
  String get wallPosting => 'Pubblicazione...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Condividi con tutti';

  @override
  String get wallBoosted => 'Boostato';

  @override
  String get wallBoostLimitReached => 'Limite giornaliero di boost raggiunto';

  @override
  String get wallAddComment => 'Aggiungi un commento (facoltativo)';

  @override
  String get wallCreatePostTitle => 'Crea Post';

  @override
  String get walletTitle => 'Wallet';

  @override
  String get walletTotalBalance => 'Saldo totale';

  @override
  String get walletSend => 'Invia';

  @override
  String get walletReceive => 'Ricevi';

  @override
  String get walletHistory => 'Cronologia';

  @override
  String get walletNoTransactions => 'Nessuna transazione';

  @override
  String get walletCopyAddress => 'Copia indirizzo';

  @override
  String get walletAddressCopied => 'Indirizzo copiato';

  @override
  String walletSendTitle(String coin) {
    return 'Invia $coin';
  }

  @override
  String get walletRecipientAddress => 'Indirizzo destinatario';

  @override
  String get walletAmount => 'Importo';

  @override
  String get walletMax => 'MAX';

  @override
  String get walletSendConfirm => 'Conferma invio';

  @override
  String get walletSending => 'Invio in corso...';

  @override
  String get walletSendSuccess => 'Transazione inviata';

  @override
  String walletSendFailed(String error) {
    return 'Transazione fallita: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return 'Ricevi $coin';
  }

  @override
  String get walletAddressBook => 'Rubrica indirizzi';

  @override
  String get walletAddAddress => 'Aggiungi indirizzo';

  @override
  String get walletEditAddress => 'Modifica indirizzo';

  @override
  String get walletDeleteAddress => 'Elimina indirizzo';

  @override
  String get walletLabel => 'Etichetta';

  @override
  String get walletAddress => 'Indirizzo';

  @override
  String get walletNetwork => 'Rete';

  @override
  String get walletAllChains => 'Tutti';

  @override
  String get walletAssets => 'Risorse';

  @override
  String get walletPortfolio => 'Portafoglio';

  @override
  String get walletMyWallet => 'Il Mio Wallet';

  @override
  String get walletTxToday => 'Oggi';

  @override
  String get walletTxYesterday => 'Ieri';

  @override
  String get walletTxThisWeek => 'Questa Settimana';

  @override
  String get walletTxEarlier => 'Precedente';

  @override
  String get walletNoNonZeroBalances => 'Nessun asset con saldo';

  @override
  String get walletNoBalances => 'Nessun saldo';

  @override
  String get qrScannerTitle => 'Scanner QR';

  @override
  String get qrAddContact => 'Aggiungi contatto';

  @override
  String get qrAuthRequest => 'Richiesta di autorizzazione';

  @override
  String get qrContent => 'Contenuto QR';

  @override
  String get qrSendContactRequest => 'Invia richiesta di contatto';

  @override
  String get qrScanAnother => 'Scansiona un altro';

  @override
  String get qrCopyFingerprint => 'Copia';

  @override
  String get qrRequestSent => 'Richiesta di contatto inviata';

  @override
  String get qrInvalidCode => 'Codice QR non valido';

  @override
  String get moreTitle => 'Altro';

  @override
  String get moreWallet => 'Wallet';

  @override
  String get moreQRScanner => 'Scanner QR';

  @override
  String get moreAddresses => 'Indirizzi';

  @override
  String get moreStarred => 'Preferiti';

  @override
  String get moreContacts => 'Contatti';

  @override
  String get moreSettings => 'Impostazioni';

  @override
  String get moreAppLock => 'Blocco app';

  @override
  String get moreInviteFriends => 'Invita amici';

  @override
  String inviteFriendsMessage(String username) {
    return 'Ciao! Prova DNA Connect — un messenger crittografato a prova di quantum. Aggiungimi: $username — Scarica: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Inserisci il PIN per sbloccare';

  @override
  String get lockIncorrectPIN => 'PIN errato';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Troppi tentativi. Riprova tra ${seconds}s';
  }

  @override
  String get lockUseBiometrics => 'Usa biometria per sbloccare';

  @override
  String get appLockTitle => 'Blocco app';

  @override
  String get appLockEnable => 'Abilita blocco app';

  @override
  String get appLockUseBiometrics => 'Usa biometria';

  @override
  String get appLockChangePIN => 'Cambia PIN';

  @override
  String get appLockSetPIN => 'Imposta PIN';

  @override
  String get appLockConfirmPIN => 'Conferma PIN';

  @override
  String get appLockPINMismatch => 'I PIN non coincidono';

  @override
  String get appLockPINSet => 'PIN impostato con successo';

  @override
  String get appLockPINChanged => 'PIN modificato';

  @override
  String get appLockEnterCurrentPIN => 'Inserisci il PIN attuale';

  @override
  String get appLockEnterNewPIN => 'Inserisci il nuovo PIN';

  @override
  String get starredTitle => 'Messaggi con stella';

  @override
  String get starredEmpty => 'Nessun messaggio con stella';

  @override
  String get blockedTitle => 'Utenti bloccati';

  @override
  String get blockedEmpty => 'Nessun utente bloccato';

  @override
  String get blockedUnblock => 'Sblocca';

  @override
  String blockedUnblockConfirm(String name) {
    return 'Sbloccare $name?';
  }

  @override
  String get updateTitle => 'Aggiornamento richiesto';

  @override
  String get updateMessage =>
      'È necessaria una versione più recente per continuare a usare DNA Connect.';

  @override
  String get updateDownload => 'Scarica aggiornamento';

  @override
  String get updateAvailableTitle => 'Nuova versione disponibile';

  @override
  String get updateAvailableMessage =>
      'È disponibile una nuova versione di DNA Connect. Aggiorna ora per le ultime funzionalità e miglioramenti.';

  @override
  String get updateLater => 'Più tardi';

  @override
  String get cancel => 'Annulla';

  @override
  String get save => 'Salva';

  @override
  String get delete => 'Elimina';

  @override
  String get done => 'Fatto';

  @override
  String get copy => 'Copia';

  @override
  String get ok => 'OK';

  @override
  String get yes => 'Sì';

  @override
  String get no => 'No';

  @override
  String get error => 'Errore';

  @override
  String get success => 'Successo';

  @override
  String get loading => 'Caricamento...';

  @override
  String get pleaseWait => 'Attendere...';

  @override
  String get copied => 'Copiato';

  @override
  String failed(String error) {
    return 'Fallito: $error';
  }

  @override
  String get retry => 'Riprova';

  @override
  String get continueButton => 'Continua';

  @override
  String get approve => 'Approva';

  @override
  String get deny => 'Rifiuta';

  @override
  String get verify => 'Verifica';

  @override
  String get copyToClipboard => 'Copia negli appunti';

  @override
  String get copiedToClipboard => 'Copiato negli appunti';

  @override
  String get pasteFromClipboard => 'Incolla dagli appunti';

  @override
  String get biometricsSubtitle => 'Impronta digitale o Face ID';

  @override
  String get changePINSubtitle => 'Aggiorna il tuo PIN di sblocco';

  @override
  String get biometricFailed => 'Autenticazione biometrica fallita';

  @override
  String get contactRequestsWillAppear =>
      'Le richieste di contatto appariranno qui';

  @override
  String get blockedUsersWillAppear => 'Gli utenti che blocchi appariranno qui';

  @override
  String get failedToLoadTimeline => 'Caricamento timeline fallito';

  @override
  String get userUnblocked => 'Utente sbloccato';

  @override
  String get backupFound => 'Backup trovato';

  @override
  String approvedContact(String name) {
    return '$name approvato';
  }

  @override
  String deniedContact(String name) {
    return '$name rifiutato';
  }

  @override
  String blockedContact(String name) {
    return '$name bloccato';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Annulla iscrizione a $name';
  }

  @override
  String get chatSenderDeletedThis => 'Il mittente ha eliminato questo';

  @override
  String get chatDeleteMessageTitle => 'Elimina messaggio';

  @override
  String get chatDeleteMessageConfirm =>
      'Eliminare questo messaggio da tutti i tuoi dispositivi e notificare l\'altra persona?';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => 'Elimina conversazione';

  @override
  String get chatDeleteConversationTitle => 'Elimina conversazione';

  @override
  String get chatDeleteConversationConfirm =>
      'Eliminare tutti i messaggi in questa conversazione? Verrà eliminata da tutti i tuoi dispositivi.';

  @override
  String get chatConversationDeleted => 'Conversazione eliminata';

  @override
  String get chatDeleteConversationFailed =>
      'Eliminazione conversazione fallita';

  @override
  String get settingsDeleteAllMessages => 'Elimina tutti i messaggi';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Rimuovi tutti i messaggi da tutti i dispositivi';

  @override
  String get settingsDeleteAllMessagesTitle => 'Eliminare tutti i messaggi?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Questo eliminerà definitivamente TUTTI i messaggi da TUTTE le conversazioni su tutti i tuoi dispositivi. Questa operazione non può essere annullata.';

  @override
  String get settingsAllMessagesDeleted => 'Tutti i messaggi eliminati';

  @override
  String get settingsDeleteAllMessagesFailed => 'Eliminazione messaggi fallita';

  @override
  String get settingsDeleteEverything => 'Elimina tutto';

  @override
  String get settingsGeneral => 'Generale';

  @override
  String get settingsDataStorage => 'Dati e archiviazione';

  @override
  String get settingsAccount => 'Account';

  @override
  String get settingsClearCache => 'Svuota cache';

  @override
  String get settingsClearCacheSubtitle =>
      'Elimina media scaricati e dati memorizzati';

  @override
  String settingsCacheSize(String size) {
    return 'Cache locale: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'Svuotare la cache?';

  @override
  String get settingsClearCacheWarning =>
      'Questo eliminerà tutti i media nella cache (immagini, video, audio). Verranno scaricati nuovamente quando necessario.';

  @override
  String get settingsCacheCleared => 'Cache svuotata';

  @override
  String get settingsClearCacheButton => 'Svuota';

  @override
  String get txDetailSent => 'Inviato';

  @override
  String get txDetailReceived => 'Ricevuto';

  @override
  String get txDetailDenied => 'Transazione rifiutata';

  @override
  String get txDetailFrom => 'Da';

  @override
  String get txDetailTo => 'A';

  @override
  String get txDetailTransactionHash => 'Hash transazione';

  @override
  String get txDetailTime => 'Orario';

  @override
  String get txDetailNetwork => 'Rete';

  @override
  String get txDetailAddressCopied => 'Indirizzo copiato';

  @override
  String get txDetailHashCopied => 'Hash copiato';

  @override
  String get txDetailAddToAddressBook => 'Aggiungi alla rubrica';

  @override
  String get txDetailClose => 'Chiudi';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '\"$label\" aggiunto alla rubrica';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Aggiunta fallita: $error';
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
  String get chatRecordingRelease => 'Rilascia per fermare';

  @override
  String get chatRecordingTap => 'Tocca per registrare';

  @override
  String get chatRecordingInProgress => 'Registrazione...';

  @override
  String get chatRecordingListening => 'Riproduzione...';

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
