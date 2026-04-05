// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Russian (`ru`).
class AppLocalizationsRu extends AppLocalizations {
  AppLocalizationsRu([String locale = 'ru']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Инициализация...';

  @override
  String get failedToInitialize => 'Ошибка инициализации';

  @override
  String get makeSureNativeLibrary =>
      'Убедитесь, что нативная библиотека доступна.';

  @override
  String get navHome => 'Главная';

  @override
  String get navChats => 'Чаты';

  @override
  String get navWallet => 'Кошелёк';

  @override
  String get navMore => 'Ещё';

  @override
  String get messagesAll => 'Все';

  @override
  String get messagesUnread => 'Непрочитанные';

  @override
  String get messagesAllCaughtUp => 'Всё прочитано!';

  @override
  String get messagesNoUnread => 'Нет непрочитанных сообщений';

  @override
  String get messagesSearchHint => 'Поиск чатов...';

  @override
  String get contactsTitle => 'Контакты';

  @override
  String get contactsEmpty => 'Контактов пока нет';

  @override
  String get contactsTapToAdd => 'Нажмите +, чтобы добавить контакт';

  @override
  String get contactsOnline => 'В сети';

  @override
  String contactsLastSeen(String time) {
    return 'Был(а) в сети $time';
  }

  @override
  String get contactsOffline => 'Не в сети';

  @override
  String get contactsSyncing => 'Синхронизация...';

  @override
  String get contactsFailedToLoad => 'Не удалось загрузить контакты';

  @override
  String get contactsRetry => 'Повторить';

  @override
  String get contactsHubContacts => 'Контакты';

  @override
  String get contactsHubRequests => 'Запросы';

  @override
  String get contactsHubBlocked => 'Заблокированные';

  @override
  String get contactsHubRemoveTitle => 'Удалить контакт?';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'Вы уверены, что хотите удалить $name из контактов?';
  }

  @override
  String get contactsHubRemove => 'Удалить';

  @override
  String get contactsHubFingerprintCopied => 'Отпечаток скопирован';

  @override
  String get contactRequestsTitle => 'Запросы в контакты';

  @override
  String get contactRequestsEmpty => 'Нет ожидающих запросов';

  @override
  String get contactRequestsAccept => 'Принять';

  @override
  String get contactRequestsDeny => 'Отклонить';

  @override
  String get contactRequestsBlock => 'Заблокировать пользователя';

  @override
  String get contactRequestsSent => 'Отправленные';

  @override
  String get contactRequestsReceived => 'Полученные';

  @override
  String get addContactTitle => 'Добавить контакт';

  @override
  String get addContactHint => 'Введите имя или ID';

  @override
  String get addContactSearching => 'Поиск...';

  @override
  String get addContactFoundOnNetwork => 'Найден в сети';

  @override
  String get addContactNotFound => 'Не найден';

  @override
  String get addContactSendRequest => 'Отправить запрос';

  @override
  String get addContactRequestSent => 'Запрос в контакты отправлен';

  @override
  String get addContactAlreadyContact => 'Уже в ваших контактах';

  @override
  String get addContactCannotAddSelf => 'Нельзя добавить себя';

  @override
  String get chatSearchMessages => 'Поиск сообщений';

  @override
  String get chatOnline => 'В сети';

  @override
  String get chatOffline => 'Не в сети';

  @override
  String get chatConnecting => 'Подключение...';

  @override
  String get chatTypeMessage => 'Введите сообщение';

  @override
  String get chatNoMessages => 'Сообщений пока нет';

  @override
  String get chatSendFirstMessage =>
      'Отправьте сообщение, чтобы начать разговор';

  @override
  String get chatPhotoLibrary => 'Галерея';

  @override
  String get chatCamera => 'Камера';

  @override
  String get chatAddCaption => 'Добавить подпись...';

  @override
  String get chatSendPhoto => 'Отправить';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Изображение слишком большое (макс. $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Сообщение удалено';

  @override
  String get chatLoadEarlier => 'Загрузить более ранние сообщения';

  @override
  String chatLastSeen(String time) {
    return 'Был(а) в сети $time';
  }

  @override
  String get chatSendTokens => 'Отправить токены';

  @override
  String chatSendTokensTo(String name) {
    return 'кому $name';
  }

  @override
  String get chatLookingUpWallets => 'Поиск адресов кошельков...';

  @override
  String get chatNoWalletAddresses =>
      'У контакта нет адресов кошельков в профиле';

  @override
  String get chatTokenLabel => 'Токен';

  @override
  String get chatSendAmount => 'Сумма';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Доступно: $balance $token';
  }

  @override
  String get chatSendMax => 'Макс';

  @override
  String chatSendButton(String token) {
    return 'Отправить $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return 'Отправлено $amount $token';
  }

  @override
  String get chatInvalidAmount => 'Пожалуйста, введите корректную сумму';

  @override
  String chatInsufficientBalance(String token) {
    return 'Недостаточно $token';
  }

  @override
  String get chatNoWalletForNetwork => 'У контакта нет кошелька для этой сети';

  @override
  String get chatSelectToken => 'Выбрать токен';

  @override
  String get chatSelectNetwork => 'Выбрать сеть';

  @override
  String get chatEnterAmount => 'Введите сумму';

  @override
  String chatStepOf(String current, String total) {
    return 'Шаг $current из $total';
  }

  @override
  String get messageMenuReply => 'Ответить';

  @override
  String get messageMenuCopy => 'Копировать';

  @override
  String get messageMenuForward => 'Переслать';

  @override
  String get messageMenuStar => 'Отметить';

  @override
  String get messageMenuUnstar => 'Снять отметку';

  @override
  String get messageMenuRetry => 'Повторить';

  @override
  String get messageMenuDelete => 'Удалить';

  @override
  String get groupsTitle => 'Группы';

  @override
  String get groupsCreate => 'Создать группу';

  @override
  String get groupsEmpty => 'Групп пока нет';

  @override
  String get groupsCreateOrJoin => 'Создайте группу или примите приглашение';

  @override
  String get groupsPendingInvitations => 'Ожидающие приглашения';

  @override
  String get groupsYourGroups => 'Ваши группы';

  @override
  String get groupsInfo => 'Информация о группе';

  @override
  String get groupsMembers => 'Участники';

  @override
  String get groupsLeave => 'Покинуть группу';

  @override
  String get groupsDelete => 'Удалить группу';

  @override
  String get groupsInvite => 'Пригласить';

  @override
  String get groupsAccept => 'Принять';

  @override
  String get groupsDecline => 'Отклонить';

  @override
  String get groupsName => 'Название группы';

  @override
  String get groupsDescription => 'Описание';

  @override
  String get groupsCreated => 'Группа создана';

  @override
  String get groupsOwner => 'Владелец';

  @override
  String get groupsMember => 'Участник';

  @override
  String get groupsAdmin => 'Администратор';

  @override
  String get groupsRemoveMember => 'Удалить участника';

  @override
  String groupsKickConfirm(String name) {
    return 'Удалить $name из группы?';
  }

  @override
  String get settingsTitle => 'Настройки';

  @override
  String get settingsAnonymous => 'Аноним';

  @override
  String get settingsNotLoaded => 'Не загружено';

  @override
  String get settingsTapToEditProfile => 'Нажмите, чтобы редактировать профиль';

  @override
  String get settingsAppearance => 'Внешний вид';

  @override
  String get settingsDarkMode => 'Тёмный режим';

  @override
  String get settingsDarkModeSubtitle =>
      'Переключение между тёмной и светлой темой';

  @override
  String get settingsLanguage => 'Язык';

  @override
  String get settingsLanguageSubtitle => 'Выберите язык приложения';

  @override
  String get settingsLanguageSystem => 'По умолчанию системный';

  @override
  String get settingsLanguageEnglish => 'English';

  @override
  String get settingsLanguageTurkish => 'Türkçe';

  @override
  String get settingsLanguageItalian => 'Итальянский';

  @override
  String get settingsLanguageSpanish => 'Испанский';

  @override
  String get settingsLanguageRussian => 'Русский';

  @override
  String get settingsLanguageDutch => 'Нидерландский';

  @override
  String get settingsLanguageGerman => 'Немецкий';

  @override
  String get settingsLanguageChinese => 'Китайский';

  @override
  String get settingsLanguageJapanese => 'Японский';

  @override
  String get settingsLanguagePortuguese => 'Португальский';

  @override
  String get settingsLanguageArabic => 'العربية';

  @override
  String get settingsBattery => 'Батарея';

  @override
  String get settingsDisableBatteryOpt => 'Отключить оптимизацию батареи';

  @override
  String get settingsBatteryChecking => 'Проверка...';

  @override
  String get settingsBatteryDisabled =>
      'Отключено — приложение может работать в фоне';

  @override
  String get settingsBatteryTapToKeep =>
      'Нажмите, чтобы приложение работало в фоне';

  @override
  String get settingsSecurity => 'Безопасность';

  @override
  String get settingsExportSeedPhrase => 'Экспорт сид-фразы';

  @override
  String get settingsExportSeedSubtitle =>
      'Создайте резервную копию фразы восстановления';

  @override
  String get settingsAppLock => 'Блокировка приложения';

  @override
  String get settingsAppLockSubtitle => 'Требовать аутентификацию';

  @override
  String get settingsExportSeedWarning =>
      'Ваша сид-фраза даёт полный доступ к вашей личности. Никогда не передавайте её никому.';

  @override
  String get settingsShowSeed => 'Показать сид-фразу';

  @override
  String get settingsYourSeedPhrase => 'Ваша сид-фраза';

  @override
  String get settingsSeedPhraseWarning =>
      'Запишите эти слова по порядку и храните в надёжном месте. Любой, кто знает эту фразу, может получить доступ к вашей личности.';

  @override
  String get settingsSeedCopied => 'Сид-фраза скопирована в буфер обмена';

  @override
  String get settingsSeedNotAvailable =>
      'Сид-фраза недоступна для этой личности. Она была создана до добавления этой функции.';

  @override
  String get settingsSeedError => 'Не удалось получить сид-фразу';

  @override
  String get settingsWallet => 'Кошелёк';

  @override
  String get settingsHideZeroBalance => 'Скрыть нулевой баланс';

  @override
  String get settingsHideZeroBalanceSubtitle =>
      'Скрыть монеты с нулевым балансом';

  @override
  String get settingsData => 'Данные';

  @override
  String get settingsAutoSync => 'Автосинхронизация';

  @override
  String get settingsAutoSyncSubtitle =>
      'Автоматически синхронизировать сообщения каждые 15 минут';

  @override
  String settingsLastSync(String time) {
    return 'Последняя синхронизация: $time';
  }

  @override
  String get settingsSyncNow => 'Синхронизировать сейчас';

  @override
  String get settingsSyncNowSubtitle =>
      'Принудительная немедленная синхронизация';

  @override
  String get settingsLogs => 'Журналы';

  @override
  String get settingsOpenLogsFolder => 'Открыть папку журналов';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Открыть файловый менеджер в папке журналов';

  @override
  String get settingsShareLogs => 'Поделиться журналами';

  @override
  String get settingsShareLogsSubtitle => 'Сжать и поделиться файлами журналов';

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
  String get settingsLogsFolderNotExist => 'Папка журналов ещё не существует';

  @override
  String get settingsNoLogFiles => 'Файлы журналов не найдены';

  @override
  String get settingsFailedCreateZip => 'Не удалось создать zip-архив';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Журналов пока нет. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Личность';

  @override
  String get settingsFingerprint => 'Отпечаток';

  @override
  String get settingsFingerprintCopied => 'Отпечаток скопирован';

  @override
  String get settingsDeleteAccount => 'Удалить аккаунт';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Безвозвратно удалить все данные с устройства';

  @override
  String get settingsDeleteAccountConfirm => 'Удалить аккаунт?';

  @override
  String get settingsDeleteAccountWarning =>
      'Это действие безвозвратно удалит все локальные данные:';

  @override
  String get settingsDeletePrivateKeys => 'Приватные ключи';

  @override
  String get settingsDeleteWallets => 'Кошельки';

  @override
  String get settingsDeleteMessages => 'Сообщения';

  @override
  String get settingsDeleteContacts => 'Контакты';

  @override
  String get settingsDeleteGroups => 'Группы';

  @override
  String get settingsDeleteSeedWarning =>
      'Убедитесь, что вы сделали резервную копию сид-фразы перед удалением!';

  @override
  String get settingsDeleteSuccess => 'Аккаунт успешно удалён';

  @override
  String settingsDeleteFailed(String error) {
    return 'Не удалось удалить аккаунт: $error';
  }

  @override
  String get settingsAbout => 'О приложении';

  @override
  String get settingsUpdateAvailable => 'Доступно обновление';

  @override
  String get settingsTapToDownload => 'Нажмите для загрузки';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Библиотека v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Постквантовая зашифрованная коммуникация';

  @override
  String get settingsCryptoStack => 'КРИПТОСТЕК';

  @override
  String get profileTitle => 'Редактировать профиль';

  @override
  String get profileInfo => 'Информация профиля';

  @override
  String get profileBio => 'О себе';

  @override
  String get profileLocation => 'Местоположение';

  @override
  String get profileWebsite => 'Веб-сайт';

  @override
  String get profileWalletAddresses => 'Адреса кошельков';

  @override
  String get profileSave => 'Сохранить профиль';

  @override
  String get profileShareQR => 'Поделиться QR-кодом';

  @override
  String get profileAvatar => 'Аватар';

  @override
  String get profileTakeSelfie => 'Сделать селфи';

  @override
  String get profileChooseFromGallery => 'Выбрать из галереи';

  @override
  String get profileSaved => 'Профиль сохранён';

  @override
  String profileSaveFailed(String error) {
    return 'Не удалось сохранить профиль: $error';
  }

  @override
  String get profileCropTitle => 'Обрезать аватар';

  @override
  String get profileCropSave => 'Сохранить';

  @override
  String get contactProfileFailed => 'Не удалось загрузить профиль';

  @override
  String get contactProfileUnknownError => 'Неизвестная ошибка';

  @override
  String get contactProfileNickname => 'Псевдоним';

  @override
  String get contactProfileNicknameNotSet =>
      'Не задан (нажмите, чтобы добавить)';

  @override
  String contactProfileOriginal(String name) {
    return 'Оригинал: $name';
  }

  @override
  String get contactProfileSetNickname => 'Задать псевдоним';

  @override
  String contactProfileOriginalName(String name) {
    return 'Оригинальное имя: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Псевдоним';

  @override
  String get contactProfileNicknameHint => 'Введите псевдоним';

  @override
  String get contactProfileNicknameHelper =>
      'Оставьте пустым, чтобы использовать оригинальное имя';

  @override
  String get contactProfileNicknameCleared => 'Псевдоним удалён';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Псевдоним задан: \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Не удалось задать псевдоним: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Копировать отпечаток';

  @override
  String get contactProfileNoProfile => 'Профиль не опубликован';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Этот пользователь ещё не опубликовал свой профиль.';

  @override
  String get contactProfileBio => 'О себе';

  @override
  String get contactProfileInfo => 'Информация';

  @override
  String get contactProfileWebsite => 'Веб-сайт';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Добро пожаловать в DNA Connect';

  @override
  String get identityGenerateSeed => 'Сгенерировать новый сид';

  @override
  String get identityHaveSeed => 'У меня есть сид-фраза';

  @override
  String get identityYourRecoveryPhrase => 'Ваша фраза восстановления';

  @override
  String get identityRecoveryPhraseWarning =>
      'Запишите эти слова и сохраните их в надёжном месте. Это единственный способ восстановить аккаунт.';

  @override
  String get identityConfirmSaved => 'Я сохранил(а) фразу восстановления';

  @override
  String get identityEnterRecoveryPhrase => 'Введите фразу восстановления';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Введите 12 или 24 слова фразы восстановления';

  @override
  String get identityChooseName => 'Выберите имя';

  @override
  String get identityChooseNameHint => 'Введите отображаемое имя';

  @override
  String get identityRegisterContinue => 'Зарегистрироваться и продолжить';

  @override
  String get identityRegistering => 'Регистрация...';

  @override
  String get identityNameTaken => 'Это имя уже занято';

  @override
  String get identityNameInvalid => 'Имя должно содержать от 3 до 20 символов';

  @override
  String get identityCreating => 'Создание вашей личности...';

  @override
  String get identityRestoring => 'Восстановление вашей личности...';

  @override
  String get wallTitle => 'Главная';

  @override
  String get wallWelcome => 'Добро пожаловать в ленту!';

  @override
  String get wallWelcomeSubtitle =>
      'Подписывайтесь на людей и каналы, чтобы видеть их публикации здесь.';

  @override
  String get wallNewPost => 'Новый пост';

  @override
  String get wallDeletePost => 'Удалить пост';

  @override
  String get wallDeletePostConfirm =>
      'Вы уверены, что хотите удалить этот пост?';

  @override
  String get wallRepost => 'Репост';

  @override
  String get wallReposted => 'Опубликовано повторно';

  @override
  String get wallComments => 'Комментарии';

  @override
  String get wallNoComments => 'Комментариев пока нет';

  @override
  String get wallLoadingComments => 'Загрузка комментариев...';

  @override
  String get wallWriteComment => 'Написать комментарий...';

  @override
  String get wallWriteReply => 'Написать ответ...';

  @override
  String wallViewAllComments(int count) {
    return 'Показать все $count комментариев';
  }

  @override
  String get wallPostDetail => 'Пост';

  @override
  String get wallCopy => 'Копировать';

  @override
  String get wallReply => 'Ответить';

  @override
  String get wallDelete => 'Удалить';

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
  String get wallTip => 'Чаевые';

  @override
  String get wallTipTitle => 'Оставить чаевые за этот пост';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Отправить чаевые';

  @override
  String get wallTipCancel => 'Отмена';

  @override
  String get wallTipSuccess => 'Чаевые отправлены!';

  @override
  String wallTipFailed(String error) {
    return 'Ошибка чаевых: $error';
  }

  @override
  String get wallTipNoWallet =>
      'У этого пользователя нет адреса кошелька в профиле';

  @override
  String get wallTipInsufficientBalance => 'Недостаточный баланс CPUNK';

  @override
  String get wallTipSending => 'Отправка чаевых...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK чаевых';
  }

  @override
  String get wallTipPending => 'В ожидании';

  @override
  String get wallTipVerified => 'Подтверждено';

  @override
  String get wallTipFailedStatus => 'Ошибка';

  @override
  String get wallWhatsOnYourMind => 'О чём вы думаете?';

  @override
  String get wallPost => 'Опубликовать';

  @override
  String get wallPosting => 'Публикация...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Поделиться со всеми';

  @override
  String get wallBoosted => 'Продвинуто';

  @override
  String get wallBoostLimitReached => 'Дневной лимит boost исчерпан';

  @override
  String get wallAddComment => 'Добавить комментарий (необязательно)';

  @override
  String get wallCreatePostTitle => 'Создать запись';

  @override
  String get walletTitle => 'Кошелёк';

  @override
  String get walletTotalBalance => 'Общий баланс';

  @override
  String get walletSend => 'Отправить';

  @override
  String get walletReceive => 'Получить';

  @override
  String get walletHistory => 'История';

  @override
  String get walletNoTransactions => 'Транзакций пока нет';

  @override
  String get walletCopyAddress => 'Копировать адрес';

  @override
  String get walletAddressCopied => 'Адрес скопирован';

  @override
  String walletSendTitle(String coin) {
    return 'Отправить $coin';
  }

  @override
  String get walletRecipientAddress => 'Адрес получателя';

  @override
  String get walletAmount => 'Сумма';

  @override
  String get walletMax => 'МАКС';

  @override
  String get walletSendConfirm => 'Подтвердить отправку';

  @override
  String get walletSending => 'Отправка...';

  @override
  String get walletSendSuccess => 'Транзакция отправлена';

  @override
  String walletSendFailed(String error) {
    return 'Ошибка транзакции: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return 'Получить $coin';
  }

  @override
  String get walletAddressBook => 'Адресная книга';

  @override
  String get walletAddAddress => 'Добавить адрес';

  @override
  String get walletEditAddress => 'Редактировать адрес';

  @override
  String get walletDeleteAddress => 'Удалить адрес';

  @override
  String get walletLabel => 'Метка';

  @override
  String get walletAddress => 'Адрес';

  @override
  String get walletNetwork => 'Сеть';

  @override
  String get walletAllChains => 'Все';

  @override
  String get walletAssets => 'Активы';

  @override
  String get walletPortfolio => 'Портфель';

  @override
  String get walletMyWallet => 'Мой Кошелёк';

  @override
  String get walletTxToday => 'Сегодня';

  @override
  String get walletTxYesterday => 'Вчера';

  @override
  String get walletTxThisWeek => 'На этой неделе';

  @override
  String get walletTxEarlier => 'Ранее';

  @override
  String get walletNoNonZeroBalances => 'Нет активов с балансом';

  @override
  String get walletNoBalances => 'Нет баланса';

  @override
  String get qrScannerTitle => 'QR-сканер';

  @override
  String get qrAddContact => 'Добавить контакт';

  @override
  String get qrAuthRequest => 'Запрос авторизации';

  @override
  String get qrContent => 'Содержимое QR';

  @override
  String get qrSendContactRequest => 'Отправить запрос в контакты';

  @override
  String get qrScanAnother => 'Сканировать ещё';

  @override
  String get qrCopyFingerprint => 'Копировать';

  @override
  String get qrRequestSent => 'Запрос в контакты отправлен';

  @override
  String get qrInvalidCode => 'Недействительный QR-код';

  @override
  String get moreTitle => 'Ещё';

  @override
  String get moreWallet => 'Кошелёк';

  @override
  String get moreQRScanner => 'QR-сканер';

  @override
  String get moreAddresses => 'Адреса';

  @override
  String get moreStarred => 'Отмеченные';

  @override
  String get moreContacts => 'Контакты';

  @override
  String get moreSettings => 'Настройки';

  @override
  String get moreAppLock => 'Блокировка приложения';

  @override
  String get moreInviteFriends => 'Пригласить друзей';

  @override
  String inviteFriendsMessage(String username) {
    return 'Привет! Попробуй DNA Connect — квантово-безопасный зашифрованный мессенджер. Добавь меня: $username — Скачать: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Введите PIN для разблокировки';

  @override
  String get lockIncorrectPIN => 'Неверный PIN';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Слишком много попыток. Повторите через $secondsс';
  }

  @override
  String get lockUseBiometrics => 'Использовать биометрию для разблокировки';

  @override
  String get appLockTitle => 'Блокировка приложения';

  @override
  String get appLockEnable => 'Включить блокировку';

  @override
  String get appLockUseBiometrics => 'Использовать биометрию';

  @override
  String get appLockChangePIN => 'Изменить PIN';

  @override
  String get appLockSetPIN => 'Установить PIN';

  @override
  String get appLockConfirmPIN => 'Подтвердить PIN';

  @override
  String get appLockPINMismatch => 'PIN-коды не совпадают';

  @override
  String get appLockPINSet => 'PIN успешно установлен';

  @override
  String get appLockPINChanged => 'PIN изменён';

  @override
  String get appLockEnterCurrentPIN => 'Введите текущий PIN';

  @override
  String get appLockEnterNewPIN => 'Введите новый PIN';

  @override
  String get starredTitle => 'Отмеченные сообщения';

  @override
  String get starredEmpty => 'Нет отмеченных сообщений';

  @override
  String get blockedTitle => 'Заблокированные пользователи';

  @override
  String get blockedEmpty => 'Нет заблокированных пользователей';

  @override
  String get blockedUnblock => 'Разблокировать';

  @override
  String blockedUnblockConfirm(String name) {
    return 'Разблокировать $name?';
  }

  @override
  String get updateTitle => 'Требуется обновление';

  @override
  String get updateMessage =>
      'Для продолжения использования DNA Connect требуется более новая версия.';

  @override
  String get updateDownload => 'Загрузить обновление';

  @override
  String get updateAvailableTitle => 'Доступна новая версия';

  @override
  String get updateAvailableMessage =>
      'Доступна новая версия DNA Connect. Обновитесь сейчас, чтобы получить последние функции и улучшения.';

  @override
  String get updateLater => 'Позже';

  @override
  String get cancel => 'Отмена';

  @override
  String get save => 'Сохранить';

  @override
  String get delete => 'Удалить';

  @override
  String get done => 'Готово';

  @override
  String get copy => 'Копировать';

  @override
  String get ok => 'ОК';

  @override
  String get yes => 'Да';

  @override
  String get no => 'Нет';

  @override
  String get error => 'Ошибка';

  @override
  String get success => 'Успешно';

  @override
  String get loading => 'Загрузка...';

  @override
  String get pleaseWait => 'Пожалуйста, подождите...';

  @override
  String get copied => 'Скопировано';

  @override
  String failed(String error) {
    return 'Ошибка: $error';
  }

  @override
  String get retry => 'Повторить';

  @override
  String get continueButton => 'Продолжить';

  @override
  String get approve => 'Одобрить';

  @override
  String get deny => 'Отклонить';

  @override
  String get verify => 'Проверить';

  @override
  String get copyToClipboard => 'Копировать в буфер обмена';

  @override
  String get copiedToClipboard => 'Скопировано в буфер обмена';

  @override
  String get pasteFromClipboard => 'Вставить из буфера обмена';

  @override
  String get biometricsSubtitle => 'Отпечаток пальца или Face ID';

  @override
  String get changePINSubtitle => 'Обновить PIN разблокировки';

  @override
  String get biometricFailed => 'Биометрическая аутентификация не удалась';

  @override
  String get contactRequestsWillAppear => 'Запросы в контакты появятся здесь';

  @override
  String get blockedUsersWillAppear =>
      'Заблокированные пользователи появятся здесь';

  @override
  String get failedToLoadTimeline => 'Не удалось загрузить ленту';

  @override
  String get userUnblocked => 'Пользователь разблокирован';

  @override
  String get backupFound => 'Резервная копия найдена';

  @override
  String approvedContact(String name) {
    return 'Одобрен(а) $name';
  }

  @override
  String deniedContact(String name) {
    return 'Отклонён(а) $name';
  }

  @override
  String blockedContact(String name) {
    return 'Заблокирован(а) $name';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Отписаться от $name';
  }

  @override
  String get chatSenderDeletedThis => 'Отправитель удалил это';

  @override
  String get chatDeleteMessageTitle => 'Удалить сообщение';

  @override
  String get chatDeleteMessageConfirm =>
      'Удалить это сообщение со всех ваших устройств и уведомить другого человека?';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => 'Удалить переписку';

  @override
  String get chatDeleteConversationTitle => 'Удалить переписку';

  @override
  String get chatDeleteConversationConfirm =>
      'Удалить все сообщения в этой переписке? Это удалит их со всех ваших устройств.';

  @override
  String get chatConversationDeleted => 'Переписка удалена';

  @override
  String get chatDeleteConversationFailed => 'Не удалось удалить переписку';

  @override
  String get settingsDeleteAllMessages => 'Удалить все сообщения';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Удалить все сообщения со всех устройств';

  @override
  String get settingsDeleteAllMessagesTitle => 'Удалить все сообщения?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Это безвозвратно удалит ВСЕ сообщения из ВСЕХ переписок на всех ваших устройствах. Это действие нельзя отменить.';

  @override
  String get settingsAllMessagesDeleted => 'Все сообщения удалены';

  @override
  String get settingsDeleteAllMessagesFailed => 'Не удалось удалить сообщения';

  @override
  String get settingsDeleteEverything => 'Удалить всё';

  @override
  String get settingsGeneral => 'Основные';

  @override
  String get settingsDataStorage => 'Данные и хранилище';

  @override
  String get settingsAccount => 'Аккаунт';

  @override
  String get settingsClearCache => 'Очистить кэш';

  @override
  String get settingsClearCacheSubtitle =>
      'Удалить загруженные медиа и кэшированные данные';

  @override
  String settingsCacheSize(String size) {
    return 'Локальный кэш: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'Очистить кэш?';

  @override
  String get settingsClearCacheWarning =>
      'Это удалит все кэшированные медиафайлы (изображения, видео, аудио). Они будут загружены заново при необходимости.';

  @override
  String get settingsCacheCleared => 'Кэш очищен';

  @override
  String get settingsClearCacheButton => 'Очистить';

  @override
  String get txDetailSent => 'Отправлено';

  @override
  String get txDetailReceived => 'Получено';

  @override
  String get txDetailDenied => 'Транзакция отклонена';

  @override
  String get txDetailFrom => 'От';

  @override
  String get txDetailTo => 'Кому';

  @override
  String get txDetailTransactionHash => 'Хэш транзакции';

  @override
  String get txDetailTime => 'Время';

  @override
  String get txDetailNetwork => 'Сеть';

  @override
  String get txDetailAddressCopied => 'Адрес скопирован';

  @override
  String get txDetailHashCopied => 'Хэш скопирован';

  @override
  String get txDetailAddToAddressBook => 'Добавить в адресную книгу';

  @override
  String get txDetailClose => 'Закрыть';

  @override
  String txDetailAddedToAddressBook(String label) {
    return 'Добавлено \"$label\" в адресную книгу';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Не удалось добавить: $error';
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
  String get chatRecordingRelease => 'Отпустите, чтобы остановить';

  @override
  String get chatRecordingTap => 'Нажмите для записи';

  @override
  String get chatRecordingInProgress => 'Запись...';

  @override
  String get chatRecordingListening => 'Воспроизведение...';

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
