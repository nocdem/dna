// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Arabic (`ar`).
class AppLocalizationsAr extends AppLocalizations {
  AppLocalizationsAr([String locale = 'ar']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'جارٍ التهيئة...';

  @override
  String get failedToInitialize => 'فشل في التهيئة';

  @override
  String get makeSureNativeLibrary => 'تأكد من توفر المكتبة الأصلية.';

  @override
  String get navHome => 'الرئيسية';

  @override
  String get navChats => 'المحادثات';

  @override
  String get navWallet => 'المحفظة';

  @override
  String get navMore => 'المزيد';

  @override
  String get messagesAll => 'الكل';

  @override
  String get messagesUnread => 'غير مقروء';

  @override
  String get messagesAllCaughtUp => 'لا جديد!';

  @override
  String get messagesNoUnread => 'لا توجد رسائل غير مقروءة';

  @override
  String get messagesSearchHint => 'بحث في المحادثات...';

  @override
  String get contactsTitle => 'جهات الاتصال';

  @override
  String get contactsEmpty => 'لا توجد جهات اتصال بعد';

  @override
  String get contactsTapToAdd => 'اضغط + لإضافة جهة اتصال';

  @override
  String get contactsOnline => 'متصل';

  @override
  String contactsLastSeen(String time) {
    return 'آخر ظهور $time';
  }

  @override
  String get contactsOffline => 'غير متصل';

  @override
  String get contactsSyncing => 'جارٍ المزامنة...';

  @override
  String get contactsFailedToLoad => 'فشل في تحميل جهات الاتصال';

  @override
  String get contactsRetry => 'إعادة المحاولة';

  @override
  String get contactsHubContacts => 'جهات الاتصال';

  @override
  String get contactsHubRequests => 'الطلبات';

  @override
  String get contactsHubBlocked => 'المحظورون';

  @override
  String get contactsHubRemoveTitle => 'إزالة جهة الاتصال؟';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'هل أنت متأكد أنك تريد إزالة $name من جهات اتصالك؟';
  }

  @override
  String get contactsHubRemove => 'إزالة';

  @override
  String get contactsHubFingerprintCopied => 'تم نسخ البصمة';

  @override
  String get contactRequestsTitle => 'طلبات الاتصال';

  @override
  String get contactRequestsEmpty => 'لا توجد طلبات معلقة';

  @override
  String get contactRequestsAccept => 'قبول';

  @override
  String get contactRequestsDeny => 'رفض';

  @override
  String get contactRequestsBlock => 'حظر المستخدم';

  @override
  String get contactRequestsSent => 'مرسل';

  @override
  String get contactRequestsReceived => 'مستلم';

  @override
  String get addContactTitle => 'إضافة جهة اتصال';

  @override
  String get addContactHint => 'أدخل اسمًا أو معرّفًا';

  @override
  String get addContactSearching => 'جارٍ البحث...';

  @override
  String get addContactFoundOnNetwork => 'تم العثور عليه في الشبكة';

  @override
  String get addContactNotFound => 'غير موجود';

  @override
  String get addContactSendRequest => 'إرسال طلب';

  @override
  String get addContactRequestSent => 'تم إرسال طلب الاتصال';

  @override
  String get addContactAlreadyContact => 'موجود بالفعل في جهات اتصالك';

  @override
  String get addContactCannotAddSelf => 'لا يمكنك إضافة نفسك';

  @override
  String get chatSearchMessages => 'بحث في الرسائل';

  @override
  String get chatOnline => 'متصل';

  @override
  String get chatOffline => 'غير متصل';

  @override
  String get chatConnecting => 'جارٍ الاتصال...';

  @override
  String get chatTypeMessage => 'اكتب رسالة';

  @override
  String get chatNoMessages => 'لا توجد رسائل بعد';

  @override
  String get chatSendFirstMessage => 'أرسل رسالة لبدء المحادثة';

  @override
  String get chatPhotoLibrary => 'مكتبة الصور';

  @override
  String get chatCamera => 'الكاميرا';

  @override
  String get chatAddCaption => 'أضف تعليقًا...';

  @override
  String get chatSendPhoto => 'إرسال';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'الصورة كبيرة جدًا (الحد الأقصى $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'تم حذف الرسالة';

  @override
  String get chatLoadEarlier => 'تحميل رسائل أقدم';

  @override
  String chatLastSeen(String time) {
    return 'آخر ظهور $time';
  }

  @override
  String get chatSendTokens => 'إرسال رموز';

  @override
  String chatSendTokensTo(String name) {
    return 'إلى $name';
  }

  @override
  String get chatLookingUpWallets => 'جارٍ البحث عن عناوين المحفظة...';

  @override
  String get chatNoWalletAddresses => 'لا توجد عناوين محفظة لدى جهة الاتصال';

  @override
  String get chatTokenLabel => 'الرمز';

  @override
  String get chatSendAmount => 'المبلغ';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'المتاح: $balance $token';
  }

  @override
  String get chatSendMax => 'الأقصى';

  @override
  String chatSendButton(String token) {
    return 'إرسال $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return 'تم إرسال $amount $token';
  }

  @override
  String get chatInvalidAmount => 'يرجى إدخال مبلغ صالح';

  @override
  String chatInsufficientBalance(String token) {
    return 'رصيد $token غير كافٍ';
  }

  @override
  String get chatNoWalletForNetwork =>
      'لا توجد محفظة لدى جهة الاتصال لهذه الشبكة';

  @override
  String get chatSelectToken => 'اختر الرمز';

  @override
  String get chatSelectNetwork => 'اختر الشبكة';

  @override
  String get chatEnterAmount => 'أدخل المبلغ';

  @override
  String chatStepOf(String current, String total) {
    return 'الخطوة $current من $total';
  }

  @override
  String get messageMenuReply => 'رد';

  @override
  String get messageMenuCopy => 'نسخ';

  @override
  String get messageMenuForward => 'إعادة توجيه';

  @override
  String get messageMenuStar => 'تمييز';

  @override
  String get messageMenuUnstar => 'إلغاء التمييز';

  @override
  String get messageMenuRetry => 'إعادة المحاولة';

  @override
  String get messageMenuDelete => 'حذف';

  @override
  String get groupsTitle => 'المجموعات';

  @override
  String get groupsCreate => 'إنشاء مجموعة';

  @override
  String get groupsEmpty => 'لا توجد مجموعات بعد';

  @override
  String get groupsCreateOrJoin => 'أنشئ مجموعة أو اقبل دعوة';

  @override
  String get groupsPendingInvitations => 'الدعوات المعلقة';

  @override
  String get groupsYourGroups => 'مجموعاتك';

  @override
  String get groupsInfo => 'معلومات المجموعة';

  @override
  String get groupsMembers => 'الأعضاء';

  @override
  String get groupsLeave => 'مغادرة المجموعة';

  @override
  String get groupsDelete => 'حذف المجموعة';

  @override
  String get groupsInvite => 'دعوة';

  @override
  String get groupsAccept => 'قبول';

  @override
  String get groupsDecline => 'رفض';

  @override
  String get groupsName => 'اسم المجموعة';

  @override
  String get groupsDescription => 'الوصف';

  @override
  String get groupsCreated => 'تم إنشاء المجموعة';

  @override
  String get groupsOwner => 'المالك';

  @override
  String get groupsMember => 'عضو';

  @override
  String get groupsAdmin => 'مشرف';

  @override
  String get groupsRemoveMember => 'إزالة العضو';

  @override
  String groupsKickConfirm(String name) {
    return 'إزالة $name من المجموعة؟';
  }

  @override
  String get settingsTitle => 'الإعدادات';

  @override
  String get settingsAnonymous => 'مجهول';

  @override
  String get settingsNotLoaded => 'لم يتم التحميل';

  @override
  String get settingsTapToEditProfile => 'اضغط لتعديل الملف الشخصي';

  @override
  String get settingsAppearance => 'المظهر';

  @override
  String get settingsDarkMode => 'الوضع الداكن';

  @override
  String get settingsDarkModeSubtitle => 'التبديل بين المظهر الداكن والفاتح';

  @override
  String get settingsLanguage => 'اللغة';

  @override
  String get settingsLanguageSubtitle => 'اختر لغة التطبيق';

  @override
  String get settingsLanguageSystem => 'الافتراضي للنظام';

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
  String get settingsBattery => 'البطارية';

  @override
  String get settingsDisableBatteryOpt => 'تعطيل تحسين البطارية';

  @override
  String get settingsBatteryChecking => 'جارٍ الفحص...';

  @override
  String get settingsBatteryDisabled => 'معطل — يمكن للتطبيق العمل في الخلفية';

  @override
  String get settingsBatteryTapToKeep => 'اضغط لإبقاء التطبيق نشطًا في الخلفية';

  @override
  String get settingsSecurity => 'الأمان';

  @override
  String get settingsExportSeedPhrase => 'تصدير عبارة الاسترداد';

  @override
  String get settingsExportSeedSubtitle => 'نسخ احتياطي لعبارة الاسترداد';

  @override
  String get settingsAppLock => 'قفل التطبيق';

  @override
  String get settingsAppLockSubtitle => 'طلب المصادقة';

  @override
  String get settingsExportSeedWarning =>
      'عبارة الاسترداد تمنح وصولاً كاملاً لهويتك. لا تشاركها مع أي شخص.';

  @override
  String get settingsShowSeed => 'إظهار العبارة';

  @override
  String get settingsYourSeedPhrase => 'عبارة الاسترداد الخاصة بك';

  @override
  String get settingsSeedPhraseWarning =>
      'اكتب هذه الكلمات بالترتيب واحفظها بأمان. أي شخص يملك هذه العبارة يمكنه الوصول لهويتك.';

  @override
  String get settingsSeedCopied => 'تم نسخ عبارة الاسترداد إلى الحافظة';

  @override
  String get seedCopyConfirmTitle => 'Copy seed phrase?';

  @override
  String get seedCopyConfirmBody =>
      'Your seed phrase will be in the clipboard for 10 seconds. Do not switch apps or background the app during this time. Continue?';

  @override
  String get seedCopiedToast => 'Copied. Clipboard will clear in 10 seconds.';

  @override
  String get settingsSeedNotAvailable =>
      'عبارة الاسترداد غير متوفرة لهذه الهوية. تم إنشاؤها قبل إضافة هذه الميزة.';

  @override
  String get settingsSeedError => 'تعذر استرجاع عبارة الاسترداد';

  @override
  String get settingsWallet => 'المحفظة';

  @override
  String get settingsHideZeroBalance => 'إخفاء الرصيد الصفري';

  @override
  String get settingsHideZeroBalanceSubtitle =>
      'إخفاء العملات ذات الرصيد الصفري';

  @override
  String get settingsData => 'البيانات';

  @override
  String get settingsAutoSync => 'المزامنة التلقائية';

  @override
  String get settingsAutoSyncSubtitle => 'مزامنة الرسائل تلقائيًا كل 15 دقيقة';

  @override
  String settingsLastSync(String time) {
    return 'آخر مزامنة: $time';
  }

  @override
  String get settingsSyncNow => 'مزامنة الآن';

  @override
  String get settingsSyncNowSubtitle => 'فرض مزامنة فورية';

  @override
  String get settingsLogs => 'السجلات';

  @override
  String get settingsOpenLogsFolder => 'فتح مجلد السجلات';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'فتح مدير الملفات في مجلد السجلات';

  @override
  String get settingsShareLogs => 'مشاركة السجلات';

  @override
  String get settingsShareLogsSubtitle => 'ضغط ومشاركة ملفات السجلات';

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
  String get settingsLogsFolderNotExist => 'مجلد السجلات غير موجود بعد';

  @override
  String get settingsNoLogFiles => 'لم يتم العثور على ملفات سجلات';

  @override
  String get settingsFailedCreateZip => 'فشل في إنشاء أرشيف مضغوط';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'لا توجد سجلات بعد. $debugInfo';
  }

  @override
  String get settingsIdentity => 'الهوية';

  @override
  String get settingsFingerprint => 'البصمة';

  @override
  String get settingsFingerprintCopied => 'تم نسخ البصمة';

  @override
  String get settingsDeleteAccount => 'حذف الحساب';

  @override
  String get settingsDeleteAccountSubtitle =>
      'حذف جميع البيانات نهائيًا من الجهاز';

  @override
  String get settingsDeleteAccountConfirm => 'حذف الحساب؟';

  @override
  String get settingsDeleteAccountWarning =>
      'سيتم حذف جميع البيانات المحلية نهائيًا:';

  @override
  String get settingsDeletePrivateKeys => 'المفاتيح الخاصة';

  @override
  String get settingsDeleteWallets => 'المحافظ';

  @override
  String get settingsDeleteMessages => 'الرسائل';

  @override
  String get settingsDeleteContacts => 'جهات الاتصال';

  @override
  String get settingsDeleteGroups => 'المجموعات';

  @override
  String get settingsDeleteSeedWarning =>
      'تأكد من نسخ عبارة الاسترداد احتياطيًا قبل الحذف!';

  @override
  String get settingsDeleteSuccess => 'تم حذف الحساب بنجاح';

  @override
  String settingsDeleteFailed(String error) {
    return 'فشل في حذف الحساب: $error';
  }

  @override
  String get settingsAbout => 'حول';

  @override
  String get settingsUpdateAvailable => 'تحديث متوفر';

  @override
  String get settingsTapToDownload => 'اضغط للتنزيل';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect الإصدار $version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'المكتبة الإصدار $version';
  }

  @override
  String get settingsPostQuantumMessenger => 'اتصال مشفر ما بعد الكم';

  @override
  String get settingsCryptoStack => 'حزمة التشفير';

  @override
  String get profileTitle => 'تعديل الملف الشخصي';

  @override
  String get profileInfo => 'معلومات الملف الشخصي';

  @override
  String get profileBio => 'السيرة الذاتية';

  @override
  String get profileLocation => 'الموقع';

  @override
  String get profileWebsite => 'الموقع الإلكتروني';

  @override
  String get profileWalletAddresses => 'عناوين المحفظة';

  @override
  String get profileSave => 'حفظ الملف الشخصي';

  @override
  String get profileShareQR => 'مشاركة رمز QR';

  @override
  String get profileAvatar => 'الصورة الرمزية';

  @override
  String get profileTakeSelfie => 'التقاط صورة شخصية';

  @override
  String get profileChooseFromGallery => 'اختيار من المعرض';

  @override
  String get profileSaved => 'تم حفظ الملف الشخصي';

  @override
  String profileSaveFailed(String error) {
    return 'فشل في حفظ الملف الشخصي: $error';
  }

  @override
  String get profileCropTitle => 'قص الصورة الرمزية';

  @override
  String get profileCropSave => 'حفظ';

  @override
  String get contactProfileFailed => 'فشل في تحميل الملف الشخصي';

  @override
  String get contactProfileUnknownError => 'خطأ غير معروف';

  @override
  String get contactProfileNickname => 'الاسم المستعار';

  @override
  String get contactProfileNicknameNotSet => 'غير محدد (اضغط للإضافة)';

  @override
  String contactProfileOriginal(String name) {
    return 'الأصلي: $name';
  }

  @override
  String get contactProfileSetNickname => 'تعيين الاسم المستعار';

  @override
  String contactProfileOriginalName(String name) {
    return 'الاسم الأصلي: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'الاسم المستعار';

  @override
  String get contactProfileNicknameHint => 'أدخل اسمًا مستعارًا';

  @override
  String get contactProfileNicknameHelper =>
      'اتركه فارغًا لاستخدام الاسم الأصلي';

  @override
  String get contactProfileNicknameCleared => 'تم مسح الاسم المستعار';

  @override
  String contactProfileNicknameSet(String name) {
    return 'تم تعيين الاسم المستعار إلى \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'فشل في تعيين الاسم المستعار: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'نسخ البصمة';

  @override
  String get contactProfileNoProfile => 'لم يتم نشر ملف شخصي';

  @override
  String get contactProfileNoProfileSubtitle =>
      'لم ينشر هذا المستخدم ملفه الشخصي بعد.';

  @override
  String get contactProfileBio => 'السيرة الذاتية';

  @override
  String get contactProfileInfo => 'المعلومات';

  @override
  String get contactProfileWebsite => 'الموقع الإلكتروني';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'مرحبًا بك في DNA Connect';

  @override
  String get identityGenerateSeed => 'إنشاء عبارة جديدة';

  @override
  String get identityHaveSeed => 'لدي عبارة استرداد';

  @override
  String get identityYourRecoveryPhrase => 'عبارة الاسترداد الخاصة بك';

  @override
  String get identityRecoveryPhraseWarning =>
      'اكتب هذه الكلمات واحفظها بأمان. إنها الطريقة الوحيدة لاسترداد حسابك.';

  @override
  String get identityConfirmSaved => 'لقد حفظت عبارة الاسترداد';

  @override
  String get identityEnterRecoveryPhrase => 'أدخل عبارة الاسترداد';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'أدخل عبارة الاسترداد المكونة من 12 أو 24 كلمة';

  @override
  String get identityChooseName => 'اختر اسمك';

  @override
  String get identityChooseNameHint => 'أدخل اسم العرض';

  @override
  String get identityRegisterContinue => 'تسجيل ومتابعة';

  @override
  String get identityRegistering => 'جارٍ التسجيل...';

  @override
  String get identityNameTaken => 'هذا الاسم مستخدم بالفعل';

  @override
  String get identityNameInvalid => 'يجب أن يكون الاسم من 3 إلى 20 حرفًا';

  @override
  String get identityCreating => 'جارٍ إنشاء هويتك...';

  @override
  String get identityRestoring => 'جارٍ استعادة هويتك...';

  @override
  String get wallTitle => 'الرئيسية';

  @override
  String get wallWelcome => 'مرحبًا بك في خطك الزمني!';

  @override
  String get wallWelcomeSubtitle =>
      'تابع الأشخاص والقنوات لرؤية منشوراتهم هنا.';

  @override
  String get wallNewPost => 'منشور جديد';

  @override
  String get wallDeletePost => 'حذف المنشور';

  @override
  String get wallDeletePostConfirm => 'هل أنت متأكد أنك تريد حذف هذا المنشور؟';

  @override
  String get wallRepost => 'إعادة نشر';

  @override
  String get wallReposted => 'أعيد نشره';

  @override
  String get wallComments => 'التعليقات';

  @override
  String get wallNoComments => 'لا توجد تعليقات بعد';

  @override
  String get wallLoadingComments => 'جارٍ تحميل التعليقات...';

  @override
  String get wallWriteComment => 'اكتب تعليقًا...';

  @override
  String get wallWriteReply => 'اكتب ردًا...';

  @override
  String wallViewAllComments(int count) {
    return 'عرض جميع التعليقات ($count)';
  }

  @override
  String get wallPostDetail => 'المنشور';

  @override
  String get wallCopy => 'نسخ';

  @override
  String get wallReply => 'رد';

  @override
  String get wallDelete => 'حذف';

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
  String get wallTip => 'إكرامية';

  @override
  String get wallTipTitle => 'إكرامية لهذا المنشور';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'إرسال إكرامية';

  @override
  String get wallTipCancel => 'إلغاء';

  @override
  String get wallTipSuccess => 'تم إرسال الإكرامية!';

  @override
  String wallTipFailed(String error) {
    return 'فشل الإكرامية: $error';
  }

  @override
  String get wallTipNoWallet =>
      'لا يوجد عنوان محفظة لدى هذا المستخدم في ملفه الشخصي';

  @override
  String get wallTipInsufficientBalance => 'رصيد CPUNK غير كافٍ';

  @override
  String get wallTipSending => 'جارٍ إرسال الإكرامية...';

  @override
  String wallTippedAmount(String amount) {
    return 'إكرامية $amount CPUNK';
  }

  @override
  String get wallTipPending => 'قيد الانتظار';

  @override
  String get wallTipVerified => 'تم التحقق';

  @override
  String get wallTipFailedStatus => 'فشل';

  @override
  String get wallWhatsOnYourMind => 'بماذا تفكر؟';

  @override
  String get wallPost => 'نشر';

  @override
  String get wallPosting => 'جارٍ النشر...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'تعزيز';

  @override
  String get wallBoostDescription => 'مشاركة مع الجميع';

  @override
  String get wallBoosted => 'تم التعزيز';

  @override
  String get wallBoostLimitReached => 'تم الوصول لحد التعزيز اليومي';

  @override
  String get wallAddComment => 'أضف تعليقًا (اختياري)';

  @override
  String get wallCreatePostTitle => 'إنشاء منشور';

  @override
  String get walletTitle => 'المحفظة';

  @override
  String get walletTotalBalance => 'الرصيد الإجمالي';

  @override
  String get walletSend => 'إرسال';

  @override
  String get walletReceive => 'استلام';

  @override
  String get walletEarn => 'Earn';

  @override
  String get walletHistory => 'السجل';

  @override
  String get walletNoTransactions => 'لا توجد معاملات بعد';

  @override
  String get walletCopyAddress => 'نسخ العنوان';

  @override
  String get walletAddressCopied => 'تم نسخ العنوان';

  @override
  String walletSendTitle(String coin) {
    return 'إرسال $coin';
  }

  @override
  String get walletRecipientAddress => 'عنوان المستلم';

  @override
  String get walletAmount => 'المبلغ';

  @override
  String get walletMax => 'الأقصى';

  @override
  String get walletSendConfirm => 'تأكيد الإرسال';

  @override
  String get walletSending => 'جارٍ الإرسال...';

  @override
  String get walletSendSuccess => 'تم إرسال المعاملة';

  @override
  String walletSendFailed(String error) {
    return 'فشلت المعاملة: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return 'استلام $coin';
  }

  @override
  String get walletAddressBook => 'دفتر العناوين';

  @override
  String get walletAddAddress => 'إضافة عنوان';

  @override
  String get walletEditAddress => 'تعديل العنوان';

  @override
  String get walletDeleteAddress => 'حذف العنوان';

  @override
  String get walletLabel => 'التسمية';

  @override
  String get walletAddress => 'العنوان';

  @override
  String get walletNetwork => 'الشبكة';

  @override
  String get walletAllChains => 'الكل';

  @override
  String get walletAssets => 'الأصول';

  @override
  String get walletPortfolio => 'المحفظة';

  @override
  String get walletMyWallet => 'محفظتي';

  @override
  String get walletTxToday => 'اليوم';

  @override
  String get walletTxYesterday => 'أمس';

  @override
  String get walletTxThisWeek => 'هذا الأسبوع';

  @override
  String get walletTxEarlier => 'سابقاً';

  @override
  String get walletNoNonZeroBalances => 'لا توجد أصول برصيد';

  @override
  String get walletNoBalances => 'لا يوجد رصيد';

  @override
  String get qrScannerTitle => 'ماسح QR';

  @override
  String get qrAddContact => 'إضافة جهة اتصال';

  @override
  String get qrAuthRequest => 'طلب تفويض';

  @override
  String get qrContent => 'محتوى QR';

  @override
  String get qrSendContactRequest => 'إرسال طلب اتصال';

  @override
  String get qrScanAnother => 'مسح آخر';

  @override
  String get qrCopyFingerprint => 'نسخ';

  @override
  String get qrRequestSent => 'تم إرسال طلب الاتصال';

  @override
  String get qrInvalidCode => 'رمز QR غير صالح';

  @override
  String get moreTitle => 'المزيد';

  @override
  String get moreWallet => 'المحفظة';

  @override
  String get moreQRScanner => 'ماسح QR';

  @override
  String get moreAddresses => 'العناوين';

  @override
  String get moreStarred => 'المميز بنجمة';

  @override
  String get moreContacts => 'جهات الاتصال';

  @override
  String get moreSettings => 'الإعدادات';

  @override
  String get moreAppLock => 'قفل التطبيق';

  @override
  String get moreInviteFriends => 'دعوة الأصدقاء';

  @override
  String inviteFriendsMessage(String username) {
    return 'مرحبًا! جرّب DNA Connect — تطبيق مراسلة مشفر بتقنية ما بعد الكم. أضفني: $username — تحميل: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'أدخل رمز PIN للفتح';

  @override
  String get lockIncorrectPIN => 'رمز PIN غير صحيح';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'محاولات كثيرة جداً. حاول مرة أخرى بعد $seconds ثانية';
  }

  @override
  String get lockUseBiometrics => 'استخدم البصمة للفتح';

  @override
  String get appLockTitle => 'قفل التطبيق';

  @override
  String get appLockEnable => 'تفعيل قفل التطبيق';

  @override
  String get appLockUseBiometrics => 'استخدام البصمة';

  @override
  String get appLockChangePIN => 'تغيير رمز PIN';

  @override
  String get appLockSetPIN => 'تعيين رمز PIN';

  @override
  String get appLockConfirmPIN => 'تأكيد رمز PIN';

  @override
  String get appLockPINMismatch => 'رموز PIN غير متطابقة';

  @override
  String get appLockPINSet => 'تم تعيين رمز PIN بنجاح';

  @override
  String get appLockPINChanged => 'تم تغيير رمز PIN';

  @override
  String get appLockEnterCurrentPIN => 'أدخل رمز PIN الحالي';

  @override
  String get appLockEnterNewPIN => 'أدخل رمز PIN الجديد';

  @override
  String get starredTitle => 'الرسائل المميزة';

  @override
  String get starredEmpty => 'لا توجد رسائل مميزة';

  @override
  String get blockedTitle => 'المستخدمون المحظورون';

  @override
  String get blockedEmpty => 'لا يوجد مستخدمون محظورون';

  @override
  String get blockedUnblock => 'إلغاء الحظر';

  @override
  String blockedUnblockConfirm(String name) {
    return 'إلغاء حظر $name؟';
  }

  @override
  String get updateTitle => 'تحديث مطلوب';

  @override
  String get updateMessage => 'يلزم إصدار أحدث لمتابعة استخدام DNA Connect.';

  @override
  String get updateDownload => 'تنزيل التحديث';

  @override
  String get updateAvailableTitle => 'إصدار جديد متوفر';

  @override
  String get updateAvailableMessage =>
      'يتوفر إصدار جديد من DNA Connect. حدّث الآن للحصول على أحدث الميزات والتحسينات.';

  @override
  String get updateLater => 'لاحقًا';

  @override
  String get cancel => 'إلغاء';

  @override
  String get save => 'حفظ';

  @override
  String get delete => 'حذف';

  @override
  String get done => 'تم';

  @override
  String get copy => 'نسخ';

  @override
  String get ok => 'حسنًا';

  @override
  String get yes => 'نعم';

  @override
  String get no => 'لا';

  @override
  String get error => 'خطأ';

  @override
  String get success => 'نجاح';

  @override
  String get loading => 'جارٍ التحميل...';

  @override
  String get pleaseWait => 'يرجى الانتظار...';

  @override
  String get copied => 'تم النسخ';

  @override
  String failed(String error) {
    return 'فشل: $error';
  }

  @override
  String get retry => 'إعادة المحاولة';

  @override
  String get continueButton => 'متابعة';

  @override
  String get approve => 'موافقة';

  @override
  String get deny => 'رفض';

  @override
  String get verify => 'تحقق';

  @override
  String get copyToClipboard => 'نسخ إلى الحافظة';

  @override
  String get copiedToClipboard => 'تم النسخ إلى الحافظة';

  @override
  String get pasteFromClipboard => 'لصق من الحافظة';

  @override
  String get biometricsSubtitle => 'البصمة أو معرف الوجه';

  @override
  String get changePINSubtitle => 'تحديث رمز PIN للفتح';

  @override
  String get biometricFailed => 'فشل المصادقة البيومترية';

  @override
  String get contactRequestsWillAppear => 'ستظهر طلبات الاتصال هنا';

  @override
  String get blockedUsersWillAppear => 'سيظهر المستخدمون المحظورون هنا';

  @override
  String get failedToLoadTimeline => 'فشل في تحميل الخط الزمني';

  @override
  String get userUnblocked => 'تم إلغاء حظر المستخدم';

  @override
  String get backupFound => 'تم العثور على نسخة احتياطية';

  @override
  String approvedContact(String name) {
    return 'تمت الموافقة على $name';
  }

  @override
  String deniedContact(String name) {
    return 'تم رفض $name';
  }

  @override
  String blockedContact(String name) {
    return 'تم حظر $name';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'إلغاء الاشتراك من $name';
  }

  @override
  String get chatSenderDeletedThis => 'قام المرسل بحذف هذا';

  @override
  String get chatDeleteMessageTitle => 'حذف الرسالة';

  @override
  String get chatDeleteMessageConfirm =>
      'حذف هذه الرسالة من جميع أجهزتك وإخطار الطرف الآخر؟';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => 'حذف المحادثة';

  @override
  String get chatDeleteConversationTitle => 'حذف المحادثة';

  @override
  String get chatDeleteConversationConfirm =>
      'حذف جميع الرسائل في هذه المحادثة؟ سيتم الحذف من جميع أجهزتك.';

  @override
  String get chatConversationDeleted => 'تم حذف المحادثة';

  @override
  String get chatDeleteConversationFailed => 'فشل في حذف المحادثة';

  @override
  String get settingsDeleteAllMessages => 'حذف جميع الرسائل';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'إزالة جميع الرسائل من جميع الأجهزة';

  @override
  String get settingsDeleteAllMessagesTitle => 'حذف جميع الرسائل؟';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'سيتم حذف جميع الرسائل من جميع المحادثات عبر جميع أجهزتك نهائيًا. لا يمكن التراجع عن هذا.';

  @override
  String get settingsAllMessagesDeleted => 'تم حذف جميع الرسائل';

  @override
  String get settingsDeleteAllMessagesFailed => 'فشل في حذف الرسائل';

  @override
  String get settingsDeleteEverything => 'حذف كل شيء';

  @override
  String get settingsGeneral => 'عام';

  @override
  String get settingsDataStorage => 'البيانات والتخزين';

  @override
  String get settingsAccount => 'الحساب';

  @override
  String get settingsClearCache => 'مسح ذاكرة التخزين المؤقت';

  @override
  String get settingsClearCacheSubtitle =>
      'حذف الوسائط المحملة والبيانات المخزنة مؤقتاً';

  @override
  String settingsCacheSize(String size) {
    return 'ذاكرة التخزين المحلية: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'مسح ذاكرة التخزين المؤقت؟';

  @override
  String get settingsClearCacheWarning =>
      'سيؤدي هذا إلى حذف جميع الوسائط المخزنة مؤقتاً (صور، فيديو، صوت). سيتم إعادة تحميلها عند الحاجة.';

  @override
  String get settingsCacheCleared => 'تم مسح ذاكرة التخزين المؤقت';

  @override
  String get settingsClearCacheButton => 'مسح';

  @override
  String get txDetailSent => 'مرسل';

  @override
  String get txDetailReceived => 'مستلم';

  @override
  String get txDetailDenied => 'تم رفض المعاملة';

  @override
  String get txDetailFrom => 'من';

  @override
  String get txDetailTo => 'إلى';

  @override
  String get txDetailTransactionHash => 'هاش المعاملة';

  @override
  String get txDetailTime => 'الوقت';

  @override
  String get txDetailNetwork => 'الشبكة';

  @override
  String get txDetailMemo => 'Memo';

  @override
  String get txDetailAddressCopied => 'تم نسخ العنوان';

  @override
  String get txDetailHashCopied => 'تم نسخ الهاش';

  @override
  String get txDetailAddToAddressBook => 'إضافة إلى دفتر العناوين';

  @override
  String get txDetailClose => 'إغلاق';

  @override
  String txDetailAddedToAddressBook(String label) {
    return 'تمت إضافة \"$label\" إلى دفتر العناوين';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'فشل في الإضافة: $error';
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
  String get chatRecordingRelease => 'حرر للإيقاف';

  @override
  String get chatRecordingTap => 'اضغط للتسجيل';

  @override
  String get chatRecordingInProgress => 'جارٍ التسجيل...';

  @override
  String get chatRecordingListening => 'جارٍ التشغيل...';

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

  @override
  String get validatorPanelTitle => 'Earner settings';

  @override
  String get validatorPanelNotValidator =>
      'You\'re not running an earner right now. Start one from the DNAC command line.';

  @override
  String validatorStatusLabel(String id) {
    return 'Earner $id';
  }

  @override
  String get validatorFieldSelfStake => 'Your own stake';

  @override
  String get validatorFieldDelegated => 'Supporters\' stake';

  @override
  String get validatorFieldCommission => 'Fee you keep';

  @override
  String get validatorCommissionSection => 'Fee rate';

  @override
  String get validatorCommissionHelp =>
      'Decrease takes effect now. Increase takes effect at the next round so supporters can leave first.';

  @override
  String get validatorCommissionRange => '0 – 100';

  @override
  String get validatorCommissionInvalid => 'Enter a value between 0 and 100.';

  @override
  String get validatorNewCommissionLabel => 'New fee';

  @override
  String get validatorUpdateCommissionButton => 'Save fee';

  @override
  String get validatorUpdateSuccess => 'Fee updated.';

  @override
  String get validatorUpdateFailed =>
      'Couldn\'t update the fee — please try again.';

  @override
  String get validatorUnstakeSection => 'Shut down earner';

  @override
  String get validatorUnstakeWarning =>
      'This will stop your earner and start the cool-down. Your supporters will be notified and their stake will unwind.';

  @override
  String get validatorUnstakeButton => 'Shut down earner';

  @override
  String get validatorUnstakeConfirmTitle => 'Shut down this earner?';

  @override
  String get validatorUnstakeConfirmBody =>
      'This cannot be undone. Your self-stake will come back after the cool-down and your supporters will have their stake returned.';

  @override
  String get validatorUnstakeConfirmAction => 'Yes, shut down';

  @override
  String get validatorUnstakeSuccess => 'Earner shutting down.';

  @override
  String get validatorUnstakeFailed =>
      'Couldn\'t shut down — please try again.';
}
