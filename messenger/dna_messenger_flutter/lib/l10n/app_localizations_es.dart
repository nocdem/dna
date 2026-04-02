// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Spanish Castilian (`es`).
class AppLocalizationsEs extends AppLocalizations {
  AppLocalizationsEs([String locale = 'es']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Inicializando...';

  @override
  String get failedToInitialize => 'Error al inicializar';

  @override
  String get makeSureNativeLibrary =>
      'Asegúrate de que la biblioteca nativa esté disponible.';

  @override
  String get navHome => 'Inicio';

  @override
  String get navChats => 'Chats';

  @override
  String get navWallet => 'Billetera';

  @override
  String get navMore => 'Más';

  @override
  String get messagesAll => 'Todos';

  @override
  String get messagesUnread => 'No leídos';

  @override
  String get messagesAllCaughtUp => '¡Estás al día!';

  @override
  String get messagesNoUnread => 'Sin mensajes no leídos';

  @override
  String get messagesSearchHint => 'Buscar chats...';

  @override
  String get contactsTitle => 'Contactos';

  @override
  String get contactsEmpty => 'Aún no hay contactos';

  @override
  String get contactsTapToAdd => 'Pulsa + para añadir un contacto';

  @override
  String get contactsOnline => 'En línea';

  @override
  String contactsLastSeen(String time) {
    return 'Última vez $time';
  }

  @override
  String get contactsOffline => 'Desconectado';

  @override
  String get contactsSyncing => 'Sincronizando...';

  @override
  String get contactsFailedToLoad => 'Error al cargar contactos';

  @override
  String get contactsRetry => 'Reintentar';

  @override
  String get contactsHubContacts => 'Contactos';

  @override
  String get contactsHubRequests => 'Solicitudes';

  @override
  String get contactsHubBlocked => 'Bloqueados';

  @override
  String get contactsHubRemoveTitle => '¿Eliminar contacto?';

  @override
  String contactsHubRemoveMessage(String name) {
    return '¿Seguro que quieres eliminar a $name de tus contactos?';
  }

  @override
  String get contactsHubRemove => 'Eliminar';

  @override
  String get contactsHubFingerprintCopied => 'Huella digital copiada';

  @override
  String get contactRequestsTitle => 'Solicitudes de contacto';

  @override
  String get contactRequestsEmpty => 'Sin solicitudes pendientes';

  @override
  String get contactRequestsAccept => 'Aceptar';

  @override
  String get contactRequestsDeny => 'Rechazar';

  @override
  String get contactRequestsBlock => 'Bloquear usuario';

  @override
  String get contactRequestsSent => 'Enviadas';

  @override
  String get contactRequestsReceived => 'Recibidas';

  @override
  String get addContactTitle => 'Añadir contacto';

  @override
  String get addContactHint => 'Introduce un nombre o ID';

  @override
  String get addContactSearching => 'Buscando...';

  @override
  String get addContactFoundOnNetwork => 'Encontrado en la red';

  @override
  String get addContactNotFound => 'No encontrado';

  @override
  String get addContactSendRequest => 'Enviar solicitud';

  @override
  String get addContactRequestSent => 'Solicitud de contacto enviada';

  @override
  String get addContactAlreadyContact => 'Ya está en tus contactos';

  @override
  String get addContactCannotAddSelf => 'No puedes añadirte a ti mismo';

  @override
  String get chatSearchMessages => 'Buscar mensajes';

  @override
  String get chatOnline => 'En línea';

  @override
  String get chatOffline => 'Desconectado';

  @override
  String get chatConnecting => 'Conectando...';

  @override
  String get chatTypeMessage => 'Escribe un mensaje';

  @override
  String get chatNoMessages => 'Aún no hay mensajes';

  @override
  String get chatSendFirstMessage =>
      'Envía un mensaje para iniciar la conversación';

  @override
  String get chatPhotoLibrary => 'Biblioteca de fotos';

  @override
  String get chatCamera => 'Cámara';

  @override
  String get chatAddCaption => 'Añadir descripción...';

  @override
  String get chatSendPhoto => 'Enviar';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Imagen demasiado grande (máx. $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Mensaje eliminado';

  @override
  String get chatLoadEarlier => 'Cargar mensajes anteriores';

  @override
  String chatLastSeen(String time) {
    return 'Última vez $time';
  }

  @override
  String get chatSendTokens => 'Enviar tokens';

  @override
  String chatSendTokensTo(String name) {
    return 'a $name';
  }

  @override
  String get chatLookingUpWallets => 'Buscando direcciones de billetera...';

  @override
  String get chatNoWalletAddresses =>
      'El contacto no tiene direcciones de billetera en su perfil';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Cantidad';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Disponible: $balance $token';
  }

  @override
  String get chatSendMax => 'Máx.';

  @override
  String chatSendButton(String token) {
    return 'Enviar $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return 'Enviado $amount $token';
  }

  @override
  String get chatInvalidAmount => 'Por favor introduce una cantidad válida';

  @override
  String chatInsufficientBalance(String token) {
    return 'Saldo de $token insuficiente';
  }

  @override
  String get chatNoWalletForNetwork =>
      'El contacto no tiene billetera para esta red';

  @override
  String get chatSelectToken => 'Seleccionar token';

  @override
  String get chatSelectNetwork => 'Seleccionar red';

  @override
  String get chatEnterAmount => 'Introducir cantidad';

  @override
  String chatStepOf(String current, String total) {
    return 'Paso $current de $total';
  }

  @override
  String get messageMenuReply => 'Responder';

  @override
  String get messageMenuCopy => 'Copiar';

  @override
  String get messageMenuForward => 'Reenviar';

  @override
  String get messageMenuStar => 'Destacar';

  @override
  String get messageMenuUnstar => 'Quitar destacado';

  @override
  String get messageMenuRetry => 'Reintentar';

  @override
  String get messageMenuDelete => 'Eliminar';

  @override
  String get groupsTitle => 'Grupos';

  @override
  String get groupsCreate => 'Crear grupo';

  @override
  String get groupsEmpty => 'Aún no hay grupos';

  @override
  String get groupsCreateOrJoin => 'Crea un grupo o acepta una invitación';

  @override
  String get groupsPendingInvitations => 'Invitaciones pendientes';

  @override
  String get groupsYourGroups => 'Tus grupos';

  @override
  String get groupsInfo => 'Información del grupo';

  @override
  String get groupsMembers => 'Miembros';

  @override
  String get groupsLeave => 'Salir del grupo';

  @override
  String get groupsDelete => 'Eliminar grupo';

  @override
  String get groupsInvite => 'Invitar';

  @override
  String get groupsAccept => 'Aceptar';

  @override
  String get groupsDecline => 'Rechazar';

  @override
  String get groupsName => 'Nombre del grupo';

  @override
  String get groupsDescription => 'Descripción';

  @override
  String get groupsCreated => 'Grupo creado';

  @override
  String get groupsOwner => 'Propietario';

  @override
  String get groupsMember => 'Miembro';

  @override
  String get groupsAdmin => 'Administrador';

  @override
  String get groupsRemoveMember => 'Eliminar miembro';

  @override
  String groupsKickConfirm(String name) {
    return '¿Eliminar a $name del grupo?';
  }

  @override
  String get settingsTitle => 'Ajustes';

  @override
  String get settingsAnonymous => 'Anónimo';

  @override
  String get settingsNotLoaded => 'No cargado';

  @override
  String get settingsTapToEditProfile => 'Pulsa para editar el perfil';

  @override
  String get settingsAppearance => 'Apariencia';

  @override
  String get settingsDarkMode => 'Modo oscuro';

  @override
  String get settingsDarkModeSubtitle => 'Cambiar entre tema oscuro y claro';

  @override
  String get settingsLanguage => 'Idioma';

  @override
  String get settingsLanguageSubtitle => 'Elegir el idioma de la app';

  @override
  String get settingsLanguageSystem => 'Predeterminado del sistema';

  @override
  String get settingsLanguageEnglish => 'English';

  @override
  String get settingsLanguageTurkish => 'Türkçe';

  @override
  String get settingsLanguageItalian => 'Italiano';

  @override
  String get settingsLanguageSpanish => 'Español';

  @override
  String get settingsLanguageRussian => 'Ruso';

  @override
  String get settingsLanguageDutch => 'Neerlandés';

  @override
  String get settingsLanguageGerman => 'Alemán';

  @override
  String get settingsLanguageChinese => 'Chino';

  @override
  String get settingsLanguageJapanese => 'Japonés';

  @override
  String get settingsLanguagePortuguese => 'Portugués';

  @override
  String get settingsLanguageArabic => 'العربية';

  @override
  String get settingsBattery => 'Batería';

  @override
  String get settingsDisableBatteryOpt => 'Desactivar optimización de batería';

  @override
  String get settingsBatteryChecking => 'Comprobando...';

  @override
  String get settingsBatteryDisabled =>
      'Desactivada — la app puede ejecutarse en segundo plano';

  @override
  String get settingsBatteryTapToKeep =>
      'Pulsa para mantener la app activa en segundo plano';

  @override
  String get settingsSecurity => 'Seguridad';

  @override
  String get settingsExportSeedPhrase => 'Exportar frase semilla';

  @override
  String get settingsExportSeedSubtitle =>
      'Haz una copia de seguridad de tu frase de recuperación';

  @override
  String get settingsAppLock => 'Bloqueo de app';

  @override
  String get settingsAppLockSubtitle => 'Requerir autenticación';

  @override
  String get settingsExportSeedWarning =>
      'Tu frase semilla da acceso completo a tu identidad. Nunca la compartas con nadie.';

  @override
  String get settingsShowSeed => 'Mostrar semilla';

  @override
  String get settingsYourSeedPhrase => 'Tu frase semilla';

  @override
  String get settingsSeedPhraseWarning =>
      'Escribe estas palabras en orden y guárdalas en un lugar seguro. Cualquiera con esta frase puede acceder a tu identidad.';

  @override
  String get settingsSeedCopied => 'Frase semilla copiada al portapapeles';

  @override
  String get settingsSeedNotAvailable =>
      'La frase semilla no está disponible para esta identidad. Fue creada antes de que se añadiera esta función.';

  @override
  String get settingsSeedError => 'No se puede recuperar la frase semilla';

  @override
  String get settingsWallet => 'Billetera';

  @override
  String get settingsHideZeroBalance => 'Ocultar saldo cero';

  @override
  String get settingsHideZeroBalanceSubtitle =>
      'Ocultar monedas con saldo cero';

  @override
  String get settingsData => 'Datos';

  @override
  String get settingsAutoSync => 'Sincronización automática';

  @override
  String get settingsAutoSyncSubtitle =>
      'Sincronizar mensajes automáticamente cada 15 minutos';

  @override
  String settingsLastSync(String time) {
    return 'Última sincronización: $time';
  }

  @override
  String get settingsSyncNow => 'Sincronizar ahora';

  @override
  String get settingsSyncNowSubtitle => 'Forzar sincronización inmediata';

  @override
  String get settingsLogs => 'Registros';

  @override
  String get settingsOpenLogsFolder => 'Abrir carpeta de registros';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Abrir el gestor de archivos en el directorio de registros';

  @override
  String get settingsShareLogs => 'Compartir registros';

  @override
  String get settingsShareLogsSubtitle =>
      'Comprimir y compartir archivos de registro';

  @override
  String get settingsLogsFolderNotExist =>
      'La carpeta de registros aún no existe';

  @override
  String get settingsNoLogFiles => 'No se encontraron archivos de registro';

  @override
  String get settingsFailedCreateZip => 'Error al crear el archivo zip';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Aún no hay registros. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Identidad';

  @override
  String get settingsFingerprint => 'Huella digital';

  @override
  String get settingsFingerprintCopied => 'Huella digital copiada';

  @override
  String get settingsDeleteAccount => 'Eliminar cuenta';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Eliminar permanentemente todos los datos del dispositivo';

  @override
  String get settingsDeleteAccountConfirm => '¿Eliminar cuenta?';

  @override
  String get settingsDeleteAccountWarning =>
      'Esto eliminará permanentemente todos los datos locales:';

  @override
  String get settingsDeletePrivateKeys => 'Claves privadas';

  @override
  String get settingsDeleteWallets => 'Billeteras';

  @override
  String get settingsDeleteMessages => 'Mensajes';

  @override
  String get settingsDeleteContacts => 'Contactos';

  @override
  String get settingsDeleteGroups => 'Grupos';

  @override
  String get settingsDeleteSeedWarning =>
      '¡Asegúrate de haber guardado tu frase semilla antes de eliminar!';

  @override
  String get settingsDeleteSuccess => 'Cuenta eliminada correctamente';

  @override
  String settingsDeleteFailed(String error) {
    return 'Error al eliminar la cuenta: $error';
  }

  @override
  String get settingsAbout => 'Acerca de';

  @override
  String get settingsUpdateAvailable => 'Actualización disponible';

  @override
  String get settingsTapToDownload => 'Pulsa para descargar';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Biblioteca v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Comunicación con cifrado post-cuántico';

  @override
  String get settingsCryptoStack => 'PILA CRIPTOGRÁFICA';

  @override
  String get profileTitle => 'Editar perfil';

  @override
  String get profileInfo => 'Información del perfil';

  @override
  String get profileBio => 'Biografía';

  @override
  String get profileLocation => 'Ubicación';

  @override
  String get profileWebsite => 'Sitio web';

  @override
  String get profileWalletAddresses => 'Direcciones de billetera';

  @override
  String get profileSave => 'Guardar perfil';

  @override
  String get profileShareQR => 'Compartir mi código QR';

  @override
  String get profileAvatar => 'Avatar';

  @override
  String get profileTakeSelfie => 'Tomar un selfie';

  @override
  String get profileChooseFromGallery => 'Elegir de la galería';

  @override
  String get profileSaved => 'Perfil guardado';

  @override
  String profileSaveFailed(String error) {
    return 'Error al guardar el perfil: $error';
  }

  @override
  String get profileCropTitle => 'Recortar avatar';

  @override
  String get profileCropSave => 'Guardar';

  @override
  String get contactProfileFailed => 'Error al cargar el perfil';

  @override
  String get contactProfileUnknownError => 'Error desconocido';

  @override
  String get contactProfileNickname => 'Apodo';

  @override
  String get contactProfileNicknameNotSet =>
      'No establecido (pulsa para añadir)';

  @override
  String contactProfileOriginal(String name) {
    return 'Original: $name';
  }

  @override
  String get contactProfileSetNickname => 'Establecer apodo';

  @override
  String contactProfileOriginalName(String name) {
    return 'Nombre original: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Apodo';

  @override
  String get contactProfileNicknameHint => 'Introduce un apodo personalizado';

  @override
  String get contactProfileNicknameHelper =>
      'Deja vacío para usar el nombre original';

  @override
  String get contactProfileNicknameCleared => 'Apodo eliminado';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Apodo establecido como \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Error al establecer el apodo: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Copiar huella digital';

  @override
  String get contactProfileNoProfile => 'No hay perfil publicado';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Este usuario aún no ha publicado su perfil.';

  @override
  String get contactProfileBio => 'Biografía';

  @override
  String get contactProfileInfo => 'Información';

  @override
  String get contactProfileWebsite => 'Sitio web';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Bienvenido a DNA Connect';

  @override
  String get identityGenerateSeed => 'Generar nueva semilla';

  @override
  String get identityHaveSeed => 'Tengo una frase semilla';

  @override
  String get identityYourRecoveryPhrase => 'Tu frase de recuperación';

  @override
  String get identityRecoveryPhraseWarning =>
      'Escribe estas palabras y guárdalas en un lugar seguro. Son la única forma de recuperar tu cuenta.';

  @override
  String get identityConfirmSaved => 'He guardado mi frase de recuperación';

  @override
  String get identityEnterRecoveryPhrase => 'Introducir frase de recuperación';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Introduce tu frase de recuperación de 12 o 24 palabras';

  @override
  String get identityChooseName => 'Elige tu nombre';

  @override
  String get identityChooseNameHint => 'Introduce un nombre para mostrar';

  @override
  String get identityRegisterContinue => 'Registrarse y continuar';

  @override
  String get identityRegistering => 'Registrando...';

  @override
  String get identityNameTaken => 'Este nombre ya está en uso';

  @override
  String get identityNameInvalid =>
      'El nombre debe tener entre 3 y 20 caracteres';

  @override
  String get identityCreating => 'Creando tu identidad...';

  @override
  String get identityRestoring => 'Restaurando tu identidad...';

  @override
  String get wallTitle => 'Inicio';

  @override
  String get wallWelcome => '¡Bienvenido a tu línea de tiempo!';

  @override
  String get wallWelcomeSubtitle =>
      'Sigue personas y canales para ver sus publicaciones aquí.';

  @override
  String get wallNewPost => 'Nueva publicación';

  @override
  String get wallDeletePost => 'Eliminar publicación';

  @override
  String get wallDeletePostConfirm =>
      '¿Seguro que quieres eliminar esta publicación?';

  @override
  String get wallRepost => 'Republicar';

  @override
  String get wallReposted => 'Republicado';

  @override
  String get wallComments => 'Comentarios';

  @override
  String get wallNoComments => 'Aún no hay comentarios';

  @override
  String get wallLoadingComments => 'Cargando comentarios...';

  @override
  String get wallWriteComment => 'Escribe un comentario...';

  @override
  String get wallWriteReply => 'Escribe una respuesta...';

  @override
  String wallViewAllComments(int count) {
    return 'Ver los $count comentarios';
  }

  @override
  String get wallPostDetail => 'Publicación';

  @override
  String get wallCopy => 'Copiar';

  @override
  String get wallReply => 'Responder';

  @override
  String get wallDelete => 'Eliminar';

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
  String get wallTip => 'Propina';

  @override
  String get wallTipTitle => 'Dar propina a esta publicación';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Enviar propina';

  @override
  String get wallTipCancel => 'Cancelar';

  @override
  String get wallTipSuccess => '¡Propina enviada!';

  @override
  String wallTipFailed(String error) {
    return 'Propina fallida: $error';
  }

  @override
  String get wallTipNoWallet =>
      'Este usuario no tiene dirección de billetera en su perfil';

  @override
  String get wallTipInsufficientBalance => 'Saldo CPUNK insuficiente';

  @override
  String get wallTipSending => 'Enviando propina...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK de propina';
  }

  @override
  String get wallTipPending => 'Pendiente';

  @override
  String get wallTipVerified => 'Verificado';

  @override
  String get wallTipFailedStatus => 'Fallido';

  @override
  String get wallWhatsOnYourMind => '¿Qué estás pensando?';

  @override
  String get wallPost => 'Publicar';

  @override
  String get wallPosting => 'Publicando...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Compartir con todos';

  @override
  String get wallBoosted => 'Boosted';

  @override
  String get wallBoostLimitReached => 'Límite diario de boost alcanzado';

  @override
  String get wallAddComment => 'Añadir un comentario (opcional)';

  @override
  String get wallCreatePostTitle => 'Crear Publicación';

  @override
  String get walletTitle => 'Billetera';

  @override
  String get walletTotalBalance => 'Saldo total';

  @override
  String get walletSend => 'Enviar';

  @override
  String get walletReceive => 'Recibir';

  @override
  String get walletHistory => 'Historial';

  @override
  String get walletNoTransactions => 'Aún no hay transacciones';

  @override
  String get walletCopyAddress => 'Copiar dirección';

  @override
  String get walletAddressCopied => 'Dirección copiada';

  @override
  String walletSendTitle(String coin) {
    return 'Enviar $coin';
  }

  @override
  String get walletRecipientAddress => 'Dirección del destinatario';

  @override
  String get walletAmount => 'Cantidad';

  @override
  String get walletMax => 'MÁX.';

  @override
  String get walletSendConfirm => 'Confirmar envío';

  @override
  String get walletSending => 'Enviando...';

  @override
  String get walletSendSuccess => 'Transacción enviada';

  @override
  String walletSendFailed(String error) {
    return 'Error en la transacción: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return 'Recibir $coin';
  }

  @override
  String get walletAddressBook => 'Libreta de direcciones';

  @override
  String get walletAddAddress => 'Añadir dirección';

  @override
  String get walletEditAddress => 'Editar dirección';

  @override
  String get walletDeleteAddress => 'Eliminar dirección';

  @override
  String get walletLabel => 'Etiqueta';

  @override
  String get walletAddress => 'Dirección';

  @override
  String get walletNetwork => 'Red';

  @override
  String get walletAllChains => 'Todos';

  @override
  String get walletAssets => 'Activos';

  @override
  String get walletPortfolio => 'Portafolio';

  @override
  String get walletMyWallet => 'Mi Billetera';

  @override
  String get walletTxToday => 'Hoy';

  @override
  String get walletTxYesterday => 'Ayer';

  @override
  String get walletTxThisWeek => 'Esta Semana';

  @override
  String get walletTxEarlier => 'Anterior';

  @override
  String get walletNoNonZeroBalances => 'Sin activos con saldo';

  @override
  String get walletNoBalances => 'Sin saldo';

  @override
  String get qrScannerTitle => 'Escáner QR';

  @override
  String get qrAddContact => 'Añadir contacto';

  @override
  String get qrAuthRequest => 'Solicitud de autorización';

  @override
  String get qrContent => 'Contenido QR';

  @override
  String get qrSendContactRequest => 'Enviar solicitud de contacto';

  @override
  String get qrScanAnother => 'Escanear otro';

  @override
  String get qrCopyFingerprint => 'Copiar';

  @override
  String get qrRequestSent => 'Solicitud de contacto enviada';

  @override
  String get qrInvalidCode => 'Código QR no válido';

  @override
  String get moreTitle => 'Más';

  @override
  String get moreWallet => 'Billetera';

  @override
  String get moreQRScanner => 'Escáner QR';

  @override
  String get moreAddresses => 'Direcciones';

  @override
  String get moreStarred => 'Destacados';

  @override
  String get moreContacts => 'Contactos';

  @override
  String get moreSettings => 'Ajustes';

  @override
  String get moreAppLock => 'Bloqueo de app';

  @override
  String get moreInviteFriends => 'Invitar amigos';

  @override
  String inviteFriendsMessage(String username) {
    return '¡Hola! Prueba DNA Connect — un mensajero cifrado a prueba de quantum. Agrégame: $username — Descarga: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Introduce el PIN para desbloquear';

  @override
  String get lockIncorrectPIN => 'PIN incorrecto';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Demasiados intentos. Intenta de nuevo en ${seconds}s';
  }

  @override
  String get lockUseBiometrics => 'Usar biometría para desbloquear';

  @override
  String get appLockTitle => 'Bloqueo de app';

  @override
  String get appLockEnable => 'Activar bloqueo de app';

  @override
  String get appLockUseBiometrics => 'Usar biometría';

  @override
  String get appLockChangePIN => 'Cambiar PIN';

  @override
  String get appLockSetPIN => 'Establecer PIN';

  @override
  String get appLockConfirmPIN => 'Confirmar PIN';

  @override
  String get appLockPINMismatch => 'Los PIN no coinciden';

  @override
  String get appLockPINSet => 'PIN establecido correctamente';

  @override
  String get appLockPINChanged => 'PIN cambiado';

  @override
  String get appLockEnterCurrentPIN => 'Introduce el PIN actual';

  @override
  String get appLockEnterNewPIN => 'Introduce el nuevo PIN';

  @override
  String get starredTitle => 'Mensajes destacados';

  @override
  String get starredEmpty => 'No hay mensajes destacados';

  @override
  String get blockedTitle => 'Usuarios bloqueados';

  @override
  String get blockedEmpty => 'No hay usuarios bloqueados';

  @override
  String get blockedUnblock => 'Desbloquear';

  @override
  String blockedUnblockConfirm(String name) {
    return '¿Desbloquear a $name?';
  }

  @override
  String get updateTitle => 'Actualización requerida';

  @override
  String get updateMessage =>
      'Se requiere una versión más reciente para continuar usando DNA Connect.';

  @override
  String get updateDownload => 'Descargar actualización';

  @override
  String get updateAvailableTitle => 'Nueva versión disponible';

  @override
  String get updateAvailableMessage =>
      'Hay una nueva versión de DNA Connect disponible. Actualiza ahora para obtener las últimas funciones y mejoras.';

  @override
  String get updateLater => 'Más tarde';

  @override
  String get cancel => 'Cancelar';

  @override
  String get save => 'Guardar';

  @override
  String get delete => 'Eliminar';

  @override
  String get done => 'Hecho';

  @override
  String get copy => 'Copiar';

  @override
  String get ok => 'Aceptar';

  @override
  String get yes => 'Sí';

  @override
  String get no => 'No';

  @override
  String get error => 'Error';

  @override
  String get success => 'Éxito';

  @override
  String get loading => 'Cargando...';

  @override
  String get pleaseWait => 'Por favor espera...';

  @override
  String get copied => 'Copiado';

  @override
  String failed(String error) {
    return 'Error: $error';
  }

  @override
  String get retry => 'Reintentar';

  @override
  String get continueButton => 'Continuar';

  @override
  String get approve => 'Aprobar';

  @override
  String get deny => 'Rechazar';

  @override
  String get verify => 'Verificar';

  @override
  String get copyToClipboard => 'Copiar al portapapeles';

  @override
  String get copiedToClipboard => 'Copiado al portapapeles';

  @override
  String get pasteFromClipboard => 'Pegar del portapapeles';

  @override
  String get biometricsSubtitle => 'Huella dactilar o Face ID';

  @override
  String get changePINSubtitle => 'Actualizar tu PIN de desbloqueo';

  @override
  String get biometricFailed => 'Error en la autenticación biométrica';

  @override
  String get contactRequestsWillAppear =>
      'Las solicitudes de contacto aparecerán aquí';

  @override
  String get blockedUsersWillAppear =>
      'Los usuarios que bloquees aparecerán aquí';

  @override
  String get failedToLoadTimeline => 'Error al cargar la línea de tiempo';

  @override
  String get userUnblocked => 'Usuario desbloqueado';

  @override
  String get backupFound => 'Copia de seguridad encontrada';

  @override
  String approvedContact(String name) {
    return '$name aprobado';
  }

  @override
  String deniedContact(String name) {
    return '$name rechazado';
  }

  @override
  String blockedContact(String name) {
    return '$name bloqueado';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Cancelar suscripción a $name';
  }

  @override
  String get chatSenderDeletedThis => 'El remitente eliminó esto';

  @override
  String get chatDeleteMessageTitle => 'Eliminar mensaje';

  @override
  String get chatDeleteMessageConfirm =>
      '¿Eliminar este mensaje de todos tus dispositivos y notificar a la otra persona?';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => 'Eliminar conversación';

  @override
  String get chatDeleteConversationTitle => 'Eliminar conversación';

  @override
  String get chatDeleteConversationConfirm =>
      '¿Eliminar todos los mensajes de esta conversación? Se eliminará de todos tus dispositivos.';

  @override
  String get chatConversationDeleted => 'Conversación eliminada';

  @override
  String get chatDeleteConversationFailed =>
      'Error al eliminar la conversación';

  @override
  String get settingsDeleteAllMessages => 'Eliminar todos los mensajes';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Eliminar todos los mensajes de todos los dispositivos';

  @override
  String get settingsDeleteAllMessagesTitle => '¿Eliminar todos los mensajes?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Esto eliminará permanentemente TODOS los mensajes de TODAS las conversaciones en todos tus dispositivos. Esta acción no se puede deshacer.';

  @override
  String get settingsAllMessagesDeleted => 'Todos los mensajes eliminados';

  @override
  String get settingsDeleteAllMessagesFailed =>
      'Error al eliminar los mensajes';

  @override
  String get settingsDeleteEverything => 'Eliminar todo';

  @override
  String get settingsGeneral => 'General';

  @override
  String get settingsDataStorage => 'Datos y almacenamiento';

  @override
  String get settingsAccount => 'Cuenta';

  @override
  String get settingsClearCache => 'Borrar caché';

  @override
  String get settingsClearCacheSubtitle =>
      'Eliminar medios descargados y datos en caché';

  @override
  String settingsCacheSize(String size) {
    return 'Caché local: $size';
  }

  @override
  String get settingsClearCacheConfirm => '¿Borrar caché?';

  @override
  String get settingsClearCacheWarning =>
      'Esto eliminará todos los medios en caché (imágenes, videos, audio). Se volverán a descargar cuando sea necesario.';

  @override
  String get settingsCacheCleared => 'Caché borrada';

  @override
  String get settingsClearCacheButton => 'Borrar';

  @override
  String get txDetailSent => 'Enviado';

  @override
  String get txDetailReceived => 'Recibido';

  @override
  String get txDetailDenied => 'Transacción rechazada';

  @override
  String get txDetailFrom => 'De';

  @override
  String get txDetailTo => 'Para';

  @override
  String get txDetailTransactionHash => 'Hash de transacción';

  @override
  String get txDetailTime => 'Hora';

  @override
  String get txDetailNetwork => 'Red';

  @override
  String get txDetailAddressCopied => 'Dirección copiada';

  @override
  String get txDetailHashCopied => 'Hash copiado';

  @override
  String get txDetailAddToAddressBook => 'Añadir a la libreta de direcciones';

  @override
  String get txDetailClose => 'Cerrar';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '\"$label\" añadido a la libreta de direcciones';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Error al añadir: $error';
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
  String get chatRecordingRelease => 'Suelta para detener';

  @override
  String get chatRecordingTap => 'Toca para grabar';

  @override
  String get chatRecordingInProgress => 'Grabando...';

  @override
  String get chatRecordingListening => 'Reproduciendo...';

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
}
