// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Turkish (`tr`).
class AppLocalizationsTr extends AppLocalizations {
  AppLocalizationsTr([String locale = 'tr']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Başlatılıyor...';

  @override
  String get failedToInitialize => 'Başlatma başarısız';

  @override
  String get makeSureNativeLibrary =>
      'Yerel kütüphanenin mevcut olduğundan emin olun.';

  @override
  String get navHome => 'Ana Sayfa';

  @override
  String get navChats => 'Sohbetler';

  @override
  String get navWallet => 'Cüzdan';

  @override
  String get navMore => 'Diğer';

  @override
  String get messagesAll => 'Tümü';

  @override
  String get messagesUnread => 'Okunmamış';

  @override
  String get messagesAllCaughtUp => 'Hepsi tamam!';

  @override
  String get messagesNoUnread => 'Okunmamış mesaj yok';

  @override
  String get messagesSearchHint => 'Sohbetlerde ara...';

  @override
  String get contactsTitle => 'Kişiler';

  @override
  String get contactsEmpty => 'Henüz kişi yok';

  @override
  String get contactsTapToAdd => 'Kişi eklemek için + simgesine dokunun';

  @override
  String get contactsOnline => 'Çevrimiçi';

  @override
  String contactsLastSeen(String time) {
    return 'Son görülme $time';
  }

  @override
  String get contactsOffline => 'Çevrimdışı';

  @override
  String get contactsSyncing => 'Eşitleniyor...';

  @override
  String get contactsFailedToLoad => 'Kişiler yüklenemedi';

  @override
  String get contactsRetry => 'Tekrar Dene';

  @override
  String get contactsHubContacts => 'Kişiler';

  @override
  String get contactsHubRequests => 'İstekler';

  @override
  String get contactsHubBlocked => 'Engellenen';

  @override
  String get contactsHubRemoveTitle => 'Kişi Kaldırılsın mı?';

  @override
  String contactsHubRemoveMessage(String name) {
    return '$name adlı kişiyi kişilerinizden kaldırmak istediğinizden emin misiniz?';
  }

  @override
  String get contactsHubRemove => 'Kaldır';

  @override
  String get contactsHubFingerprintCopied => 'Kimlik kopyalandı';

  @override
  String get contactRequestsTitle => 'Kişi İstekleri';

  @override
  String get contactRequestsEmpty => 'Bekleyen istek yok';

  @override
  String get contactRequestsAccept => 'Kabul Et';

  @override
  String get contactRequestsDeny => 'Reddet';

  @override
  String get contactRequestsBlock => 'Kullanıcıyı Engelle';

  @override
  String get contactRequestsSent => 'Gönderilen';

  @override
  String get contactRequestsReceived => 'Alınan';

  @override
  String get addContactTitle => 'Kişi Ekle';

  @override
  String get addContactHint => 'Bir ad veya kimlik girin';

  @override
  String get addContactSearching => 'Aranıyor...';

  @override
  String get addContactFoundOnNetwork => 'Ağda bulundu';

  @override
  String get addContactNotFound => 'Bulunamadı';

  @override
  String get addContactSendRequest => 'İstek Gönder';

  @override
  String get addContactRequestSent => 'Kişi isteği gönderildi';

  @override
  String get addContactAlreadyContact => 'Zaten kişilerinizde';

  @override
  String get addContactCannotAddSelf => 'Kendinizi ekleyemezsiniz';

  @override
  String get chatSearchMessages => 'Mesajlarda ara';

  @override
  String get chatOnline => 'Çevrimiçi';

  @override
  String get chatOffline => 'Çevrimdışı';

  @override
  String get chatConnecting => 'Bağlanıyor...';

  @override
  String get chatTypeMessage => 'Bir mesaj yazın';

  @override
  String get chatNoMessages => 'Henüz mesaj yok';

  @override
  String get chatSendFirstMessage =>
      'Sohbeti başlatmak için bir mesaj gönderin';

  @override
  String get chatPhotoLibrary => 'Fotoğraf Galerisi';

  @override
  String get chatCamera => 'Kamera';

  @override
  String get chatAddCaption => 'Açıklama Ekle...';

  @override
  String get chatSendPhoto => 'Gönder';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Görsel çok büyük (maks. $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Mesaj silindi';

  @override
  String get chatLoadEarlier => 'Önceki mesajları yükle';

  @override
  String chatLastSeen(String time) {
    return 'Son görülme $time';
  }

  @override
  String get chatSendTokens => 'Token Gönder';

  @override
  String chatSendTokensTo(String name) {
    return '$name kişisine';
  }

  @override
  String get chatLookingUpWallets => 'Cüzdan adresleri aranıyor...';

  @override
  String get chatNoWalletAddresses => 'Kişinin profilinde cüzdan adresi yok';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Miktar';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Kullanılabilir: $balance $token';
  }

  @override
  String get chatSendMax => 'Maks';

  @override
  String chatSendButton(String token) {
    return '$token Gönder';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return '$amount $token gönderildi';
  }

  @override
  String get chatInvalidAmount => 'Lütfen geçerli bir miktar girin';

  @override
  String chatInsufficientBalance(String token) {
    return 'Yetersiz $token bakiyesi';
  }

  @override
  String get chatNoWalletForNetwork => 'Kişinin bu ağ için cüzdanı yok';

  @override
  String get chatSelectToken => 'Token Seç';

  @override
  String get chatSelectNetwork => 'Ağ Seç';

  @override
  String get chatEnterAmount => 'Miktar Gir';

  @override
  String chatStepOf(String current, String total) {
    return 'Adım $current / $total';
  }

  @override
  String get messageMenuReply => 'Yanıtla';

  @override
  String get messageMenuCopy => 'Kopyala';

  @override
  String get messageMenuForward => 'İlet';

  @override
  String get messageMenuStar => 'Yıldızla';

  @override
  String get messageMenuUnstar => 'Yıldızı Kaldır';

  @override
  String get messageMenuRetry => 'Tekrar Dene';

  @override
  String get messageMenuDelete => 'Sil';

  @override
  String get groupsTitle => 'Gruplar';

  @override
  String get groupsCreate => 'Grup Oluştur';

  @override
  String get groupsEmpty => 'Henüz grup yok';

  @override
  String get groupsCreateOrJoin =>
      'Bir grup oluşturun veya bir daveti kabul edin';

  @override
  String get groupsPendingInvitations => 'Bekleyen Davetler';

  @override
  String get groupsYourGroups => 'Gruplarınız';

  @override
  String get groupsInfo => 'Grup Bilgisi';

  @override
  String get groupsMembers => 'Üyeler';

  @override
  String get groupsLeave => 'Gruptan Ayrıl';

  @override
  String get groupsDelete => 'Grubu Sil';

  @override
  String get groupsInvite => 'Davet Et';

  @override
  String get groupsAccept => 'Kabul Et';

  @override
  String get groupsDecline => 'Reddet';

  @override
  String get groupsName => 'Grup Adı';

  @override
  String get groupsDescription => 'Açıklama';

  @override
  String get groupsCreated => 'Grup oluşturuldu';

  @override
  String get groupsOwner => 'Sahip';

  @override
  String get groupsMember => 'Üye';

  @override
  String get groupsAdmin => 'Yönetici';

  @override
  String get groupsRemoveMember => 'Üyeyi Çıkar';

  @override
  String groupsKickConfirm(String name) {
    return '$name gruptan çıkarılsın mı?';
  }

  @override
  String get settingsTitle => 'Ayarlar';

  @override
  String get settingsAnonymous => 'Anonim';

  @override
  String get settingsNotLoaded => 'Yüklenmedi';

  @override
  String get settingsTapToEditProfile => 'Profili düzenlemek için dokunun';

  @override
  String get settingsAppearance => 'Görünüm';

  @override
  String get settingsDarkMode => 'Karanlık Mod';

  @override
  String get settingsDarkModeSubtitle =>
      'Karanlık ve açık tema arasında geçiş yap';

  @override
  String get settingsLanguage => 'Dil';

  @override
  String get settingsLanguageSubtitle => 'Uygulama dilini seçin';

  @override
  String get settingsLanguageSystem => 'Sistem varsayılanı';

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
  String get settingsBattery => 'Pil';

  @override
  String get settingsDisableBatteryOpt => 'Pil Optimizasyonunu Kapat';

  @override
  String get settingsBatteryChecking => 'Kontrol ediliyor...';

  @override
  String get settingsBatteryDisabled =>
      'Kapalı — uygulama arka planda çalışabilir';

  @override
  String get settingsBatteryTapToKeep =>
      'Uygulamayı arka planda canlı tutmak için dokunun';

  @override
  String get settingsSecurity => 'Güvenlik';

  @override
  String get settingsExportSeedPhrase => 'Kurtarma İfadesini Dışa Aktar';

  @override
  String get settingsExportSeedSubtitle => 'Kurtarma ifadenizi yedekleyin';

  @override
  String get settingsAppLock => 'Uygulama Kilidi';

  @override
  String get settingsAppLockSubtitle => 'Kimlik doğrulama gerektir';

  @override
  String get settingsExportSeedWarning =>
      'Kurtarma ifadeniz kimliğinize tam erişim sağlar. Asla kimseyle paylaşmayın.';

  @override
  String get settingsShowSeed => 'İfadeyi Göster';

  @override
  String get settingsYourSeedPhrase => 'Kurtarma İfadeniz';

  @override
  String get settingsSeedPhraseWarning =>
      'Bu kelimeleri sırasıyla yazın ve güvenli bir yerde saklayın. Bu ifadeye sahip olan herkes kimliğinize erişebilir.';

  @override
  String get settingsSeedCopied => 'Kurtarma ifadesi panoya kopyalandı';

  @override
  String get settingsSeedNotAvailable =>
      'Bu kimlik için kurtarma ifadesi mevcut değil. Bu özellik eklenmeden önce oluşturulmuş.';

  @override
  String get settingsSeedError => 'Kurtarma ifadesi alınamadı';

  @override
  String get settingsWallet => 'Cüzdan';

  @override
  String get settingsHideZeroBalance => 'Sıfır Bakiyeyi Gizle';

  @override
  String get settingsHideZeroBalanceSubtitle =>
      'Bakiyesi sıfır olan koinleri gizle';

  @override
  String get settingsData => 'Veri';

  @override
  String get settingsAutoSync => 'Otomatik Eşitleme';

  @override
  String get settingsAutoSyncSubtitle =>
      'Mesajları her 15 dakikada otomatik eşitle';

  @override
  String settingsLastSync(String time) {
    return 'Son eşitleme: $time';
  }

  @override
  String get settingsSyncNow => 'Şimdi Eşitle';

  @override
  String get settingsSyncNowSubtitle => 'Hemen eşitlemeyi başlat';

  @override
  String get settingsLogs => 'Günlükler';

  @override
  String get settingsOpenLogsFolder => 'Günlük Klasörünü Aç';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Günlük dizininde dosya yöneticisini aç';

  @override
  String get settingsShareLogs => 'Günlükleri Paylaş';

  @override
  String get settingsShareLogsSubtitle =>
      'Günlük dosyalarını sıkıştır ve paylaş';

  @override
  String get settingsLogsFolderNotExist => 'Günlük klasörü henüz mevcut değil';

  @override
  String get settingsNoLogFiles => 'Günlük dosyası bulunamadı';

  @override
  String get settingsFailedCreateZip => 'Sıkıştırılmış arşiv oluşturulamadı';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Henüz günlük yok. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Kimlik';

  @override
  String get settingsFingerprint => 'Kimlik';

  @override
  String get settingsFingerprintCopied => 'Kimlik kopyalandı';

  @override
  String get settingsDeleteAccount => 'Hesabı Sil';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Cihazdaki tüm verileri kalıcı olarak sil';

  @override
  String get settingsDeleteAccountConfirm => 'Hesap Silinsin mi?';

  @override
  String get settingsDeleteAccountWarning =>
      'Bu işlem tüm yerel verileri kalıcı olarak silecektir:';

  @override
  String get settingsDeletePrivateKeys => 'Özel anahtarlar';

  @override
  String get settingsDeleteWallets => 'Cüzdanlar';

  @override
  String get settingsDeleteMessages => 'Mesajlar';

  @override
  String get settingsDeleteContacts => 'Kişiler';

  @override
  String get settingsDeleteGroups => 'Gruplar';

  @override
  String get settingsDeleteSeedWarning =>
      'Silmeden önce kurtarma ifadenizi yedeklediğinizden emin olun!';

  @override
  String get settingsDeleteSuccess => 'Hesap başarıyla silindi';

  @override
  String settingsDeleteFailed(String error) {
    return 'Hesap silinemedi: $error';
  }

  @override
  String get settingsAbout => 'Hakkında';

  @override
  String get settingsUpdateAvailable => 'Güncelleme Mevcut';

  @override
  String get settingsTapToDownload => 'İndirmek için dokunun';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Kütüphane v$version';
  }

  @override
  String get settingsPostQuantumMessenger => 'Kuantum Sonrası Şifreli İletişim';

  @override
  String get settingsCryptoStack => 'KRİPTO ALTYAPISI';

  @override
  String get profileTitle => 'Profili Düzenle';

  @override
  String get profileInfo => 'Profil Bilgisi';

  @override
  String get profileBio => 'Hakkımda';

  @override
  String get profileLocation => 'Konum';

  @override
  String get profileWebsite => 'Web Sitesi';

  @override
  String get profileWalletAddresses => 'Cüzdan Adresleri';

  @override
  String get profileSave => 'Profili Kaydet';

  @override
  String get profileShareQR => 'QR Kodumu Paylaş';

  @override
  String get profileAvatar => 'Profil Fotoğrafı';

  @override
  String get profileTakeSelfie => 'Fotoğraf Çek';

  @override
  String get profileChooseFromGallery => 'Galeriden Seç';

  @override
  String get profileSaved => 'Profil kaydedildi';

  @override
  String profileSaveFailed(String error) {
    return 'Profil kaydedilemedi: $error';
  }

  @override
  String get profileCropTitle => 'Fotoğrafı Kırp';

  @override
  String get profileCropSave => 'Kaydet';

  @override
  String get contactProfileFailed => 'Profil yüklenemedi';

  @override
  String get contactProfileUnknownError => 'Bilinmeyen hata';

  @override
  String get contactProfileNickname => 'Takma Ad';

  @override
  String get contactProfileNicknameNotSet =>
      'Ayarlanmamış (eklemek için dokunun)';

  @override
  String contactProfileOriginal(String name) {
    return 'Asıl ad: $name';
  }

  @override
  String get contactProfileSetNickname => 'Takma Ad Belirle';

  @override
  String contactProfileOriginalName(String name) {
    return 'Asıl ad: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Takma Ad';

  @override
  String get contactProfileNicknameHint => 'Özel takma ad girin';

  @override
  String get contactProfileNicknameHelper =>
      'Asıl adı kullanmak için boş bırakın';

  @override
  String get contactProfileNicknameCleared => 'Takma ad kaldırıldı';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Takma ad \"$name\" olarak ayarlandı';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Takma ad ayarlanamadı: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Kimliği kopyala';

  @override
  String get contactProfileNoProfile => 'Profil yayınlanmamış';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Bu kullanıcı henüz profilini yayınlamamış.';

  @override
  String get contactProfileBio => 'Hakkında';

  @override
  String get contactProfileInfo => 'Bilgi';

  @override
  String get contactProfileWebsite => 'Web Sitesi';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'DNA Connect\'e Hoş Geldiniz';

  @override
  String get identityGenerateSeed => 'Yeni Kurtarma İfadesi Oluştur';

  @override
  String get identityHaveSeed => 'Kurtarma İfadem Var';

  @override
  String get identityYourRecoveryPhrase => 'Kurtarma İfadeniz';

  @override
  String get identityRecoveryPhraseWarning =>
      'Bu kelimeleri yazın ve güvenli bir yerde saklayın. Hesabınızı kurtarmanın tek yolu budur.';

  @override
  String get identityConfirmSaved => 'Kurtarma ifademi kaydettim';

  @override
  String get identityEnterRecoveryPhrase => 'Kurtarma İfadesini Girin';

  @override
  String get identityEnterRecoveryPhraseHint =>
      '12 veya 24 kelimelik kurtarma ifadenizi girin';

  @override
  String get identityChooseName => 'Adınızı Seçin';

  @override
  String get identityChooseNameHint => 'Bir görünen ad girin';

  @override
  String get identityRegisterContinue => 'Kaydol ve Devam Et';

  @override
  String get identityRegistering => 'Kaydediliyor...';

  @override
  String get identityNameTaken => 'Bu ad zaten alınmış';

  @override
  String get identityNameInvalid => 'Ad 3-20 karakter olmalıdır';

  @override
  String get identityCreating => 'Kimliğiniz oluşturuluyor...';

  @override
  String get identityRestoring => 'Kimliğiniz geri yükleniyor...';

  @override
  String get wallTitle => 'Ana Sayfa';

  @override
  String get wallWelcome => 'Zaman tünelinize hoş geldiniz!';

  @override
  String get wallWelcomeSubtitle =>
      'Gönderilerini burada görmek için kişileri ve kanalları takip edin.';

  @override
  String get wallNewPost => 'Yeni Gönderi';

  @override
  String get wallDeletePost => 'Gönderiyi Sil';

  @override
  String get wallDeletePostConfirm =>
      'Bu gönderiyi silmek istediğinizden emin misiniz?';

  @override
  String get wallRepost => 'Paylaş';

  @override
  String get wallReposted => 'Paylaşıldı';

  @override
  String get wallComments => 'Yorumlar';

  @override
  String get wallNoComments => 'Henüz yorum yok';

  @override
  String get wallLoadingComments => 'Yorumlar yükleniyor...';

  @override
  String get wallWriteComment => 'Bir yorum yazın...';

  @override
  String get wallWriteReply => 'Bir yanıt yazın...';

  @override
  String wallViewAllComments(int count) {
    return 'Tüm $count yorumu görüntüle';
  }

  @override
  String get wallPostDetail => 'Gönderi';

  @override
  String get wallCopy => 'Kopyala';

  @override
  String get wallReply => 'Yanıtla';

  @override
  String get wallDelete => 'Sil';

  @override
  String get wallBlockUser => 'Kullanıcıyı Engelle';

  @override
  String wallBlockUserConfirm(String name) {
    return '$name engellensin mi? Artık gönderilerini ve mesajlarını görmeyeceksiniz.';
  }

  @override
  String wallUserBlocked(String name) {
    return '$name engellendi';
  }

  @override
  String get wallSendContactRequest => 'Kişi İsteği Gönder';

  @override
  String wallContactRequestSent(String name) {
    return '$name kişisine istek gönderildi';
  }

  @override
  String get wallContactRequestMessage => 'Mesaj (isteğe bağlı)';

  @override
  String get wallUnfriend => 'Kişilerden Çıkar';

  @override
  String wallUnfriendConfirm(String name) {
    return '$name kişilerinizden çıkarılsın mı?';
  }

  @override
  String wallUnfriended(String name) {
    return '$name kişilerden çıkarıldı';
  }

  @override
  String get wallFollow => 'Takip Et';

  @override
  String get wallUnfollow => 'Takibi Bırak';

  @override
  String wallFollowed(String name) {
    return '$name takip ediliyor';
  }

  @override
  String wallUnfollowed(String name) {
    return '$name takipten çıkarıldı';
  }

  @override
  String get wallTip => 'Bahşiş';

  @override
  String get wallTipTitle => 'Bu gönderiye bahşiş ver';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Bahşiş Gönder';

  @override
  String get wallTipCancel => 'İptal';

  @override
  String get wallTipSuccess => 'Bahşiş gönderildi!';

  @override
  String wallTipFailed(String error) {
    return 'Bahşiş başarısız: $error';
  }

  @override
  String get wallTipNoWallet => 'Bu kullanıcının profilinde cüzdan adresi yok';

  @override
  String get wallTipInsufficientBalance => 'Yetersiz CPUNK bakiyesi';

  @override
  String get wallTipSending => 'Bahşiş gönderiliyor...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK bahşiş verildi';
  }

  @override
  String get wallTipPending => 'Beklemede';

  @override
  String get wallTipVerified => 'Doğrulandı';

  @override
  String get wallTipFailedStatus => 'Başarısız';

  @override
  String get wallWhatsOnYourMind => 'Aklından ne geçiyor?';

  @override
  String get wallPost => 'Paylaş';

  @override
  String get wallPosting => 'Paylaşılıyor...';

  @override
  String get wallUploadingImage => 'Yükleniyor...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Herkesle paylaş';

  @override
  String get wallBoosted => 'Boost yapıldı';

  @override
  String get wallBoostLimitReached => 'Günlük boost limiti doldu';

  @override
  String get wallAddComment => 'Yorum ekle (isteğe bağlı)';

  @override
  String get wallCreatePostTitle => 'Gönderi Oluştur';

  @override
  String get walletTitle => 'Cüzdan';

  @override
  String get walletTotalBalance => 'Toplam Bakiye';

  @override
  String get walletSend => 'Gönder';

  @override
  String get walletReceive => 'Al';

  @override
  String get walletHistory => 'Geçmiş';

  @override
  String get walletNoTransactions => 'Henüz işlem yok';

  @override
  String get walletCopyAddress => 'Adresi Kopyala';

  @override
  String get walletAddressCopied => 'Adres kopyalandı';

  @override
  String walletSendTitle(String coin) {
    return '$coin Gönder';
  }

  @override
  String get walletRecipientAddress => 'Alıcı Adresi';

  @override
  String get walletAmount => 'Miktar';

  @override
  String get walletMax => 'MAKS';

  @override
  String get walletSendConfirm => 'Gönderimi Onayla';

  @override
  String get walletSending => 'Gönderiliyor...';

  @override
  String get walletSendSuccess => 'İşlem gönderildi';

  @override
  String walletSendFailed(String error) {
    return 'İşlem başarısız: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return '$coin Al';
  }

  @override
  String get walletAddressBook => 'Adres Defteri';

  @override
  String get walletAddAddress => 'Adres Ekle';

  @override
  String get walletEditAddress => 'Adresi Düzenle';

  @override
  String get walletDeleteAddress => 'Adresi Sil';

  @override
  String get walletLabel => 'Etiket';

  @override
  String get walletAddress => 'Adres';

  @override
  String get walletNetwork => 'Ağ';

  @override
  String get walletAllChains => 'Tümü';

  @override
  String get walletAssets => 'Varlıklar';

  @override
  String get walletPortfolio => 'Portföy';

  @override
  String get walletMyWallet => 'Cüzdanım';

  @override
  String get walletTxToday => 'Bugün';

  @override
  String get walletTxYesterday => 'Dün';

  @override
  String get walletTxThisWeek => 'Bu Hafta';

  @override
  String get walletTxEarlier => 'Daha Önce';

  @override
  String get walletNoNonZeroBalances => 'Bakiyesi olan varlık yok';

  @override
  String get walletNoBalances => 'Bakiye yok';

  @override
  String get qrScannerTitle => 'QR Tarayıcı';

  @override
  String get qrAddContact => 'Kişi Ekle';

  @override
  String get qrAuthRequest => 'Yetkilendirme İsteği';

  @override
  String get qrContent => 'QR İçeriği';

  @override
  String get qrSendContactRequest => 'Kişi İsteği Gönder';

  @override
  String get qrScanAnother => 'Başka Bir Tara';

  @override
  String get qrCopyFingerprint => 'Kopyala';

  @override
  String get qrRequestSent => 'Kişi isteği gönderildi';

  @override
  String get qrInvalidCode => 'Geçersiz QR kodu';

  @override
  String get moreTitle => 'Diğer';

  @override
  String get moreWallet => 'Cüzdan';

  @override
  String get moreQRScanner => 'QR Tarayıcı';

  @override
  String get moreAddresses => 'Adresler';

  @override
  String get moreStarred => 'Yıldızlı';

  @override
  String get moreContacts => 'Kişiler';

  @override
  String get moreSettings => 'Ayarlar';

  @override
  String get moreAppLock => 'Uygulama Kilidi';

  @override
  String get moreInviteFriends => 'Arkadaşlarını Davet Et';

  @override
  String inviteFriendsMessage(String username) {
    return 'Selam! DNA Connect\'i dene — kuantum güvenli şifreli mesajlaşma. Beni ekle: $username — İndir: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Kilit açmak için PIN girin';

  @override
  String get lockIncorrectPIN => 'Yanlış PIN';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Çok fazla deneme. $seconds saniye sonra tekrar deneyin';
  }

  @override
  String get lockUseBiometrics => 'Kilit açmak için biyometrik kullanın';

  @override
  String get appLockTitle => 'Uygulama Kilidi';

  @override
  String get appLockEnable => 'Uygulama Kilidini Etkinleştir';

  @override
  String get appLockUseBiometrics => 'Biyometrik Kullan';

  @override
  String get appLockChangePIN => 'PIN Değiştir';

  @override
  String get appLockSetPIN => 'PIN Belirle';

  @override
  String get appLockConfirmPIN => 'PIN Onayla';

  @override
  String get appLockPINMismatch => 'PIN\'ler eşleşmiyor';

  @override
  String get appLockPINSet => 'PIN başarıyla ayarlandı';

  @override
  String get appLockPINChanged => 'PIN değiştirildi';

  @override
  String get appLockEnterCurrentPIN => 'Mevcut PIN\'inizi girin';

  @override
  String get appLockEnterNewPIN => 'Yeni PIN girin';

  @override
  String get starredTitle => 'Yıldızlı Mesajlar';

  @override
  String get starredEmpty => 'Yıldızlı mesaj yok';

  @override
  String get blockedTitle => 'Engellenen Kullanıcılar';

  @override
  String get blockedEmpty => 'Engellenen kullanıcı yok';

  @override
  String get blockedUnblock => 'Engeli Kaldır';

  @override
  String blockedUnblockConfirm(String name) {
    return '$name engellensin mi?';
  }

  @override
  String get updateTitle => 'Güncelleme Gerekli';

  @override
  String get updateMessage =>
      'DNA Connect\'i kullanmaya devam etmek için daha yeni bir sürüm gereklidir.';

  @override
  String get updateDownload => 'Güncellemeyi İndir';

  @override
  String get updateAvailableTitle => 'Yeni Sürüm Mevcut';

  @override
  String get updateAvailableMessage =>
      'DNA Connect\'in yeni bir sürümü mevcut. En son özellikler ve iyileştirmeler için şimdi güncelleyin.';

  @override
  String get updateLater => 'Sonra';

  @override
  String get cancel => 'İptal';

  @override
  String get save => 'Kaydet';

  @override
  String get delete => 'Sil';

  @override
  String get done => 'Tamam';

  @override
  String get copy => 'Kopyala';

  @override
  String get ok => 'Tamam';

  @override
  String get yes => 'Evet';

  @override
  String get no => 'Hayır';

  @override
  String get error => 'Hata';

  @override
  String get success => 'Başarılı';

  @override
  String get loading => 'Yükleniyor...';

  @override
  String get pleaseWait => 'Lütfen bekleyin...';

  @override
  String get copied => 'Kopyalandı';

  @override
  String failed(String error) {
    return 'Başarısız: $error';
  }

  @override
  String get retry => 'Tekrar Dene';

  @override
  String get continueButton => 'Devam';

  @override
  String get approve => 'Onayla';

  @override
  String get deny => 'Reddet';

  @override
  String get verify => 'Doğrula';

  @override
  String get copyToClipboard => 'Panoya Kopyala';

  @override
  String get copiedToClipboard => 'Panoya kopyalandı';

  @override
  String get pasteFromClipboard => 'Panodan Yapıştır';

  @override
  String get biometricsSubtitle => 'Parmak İzi veya Yüz Tanıma';

  @override
  String get changePINSubtitle => 'Kilit açma PIN\'inizi güncelleyin';

  @override
  String get biometricFailed => 'Biyometrik doğrulama başarısız';

  @override
  String get contactRequestsWillAppear => 'Kişi istekleri burada görünecek';

  @override
  String get blockedUsersWillAppear =>
      'Engellediğiniz kullanıcılar burada görünecek';

  @override
  String get failedToLoadTimeline => 'Zaman tüneli yüklenemedi';

  @override
  String get userUnblocked => 'Kullanıcının engeli kaldırıldı';

  @override
  String get backupFound => 'Yedek Bulundu';

  @override
  String approvedContact(String name) {
    return '$name onaylandı';
  }

  @override
  String deniedContact(String name) {
    return '$name reddedildi';
  }

  @override
  String blockedContact(String name) {
    return '$name engellendi';
  }

  @override
  String unsubscribeFrom(String name) {
    return '$name aboneliğinden çık';
  }

  @override
  String get chatSenderDeletedThis => 'Gönderen bunu sildi';

  @override
  String get chatDeleteMessageTitle => 'Mesajı Sil';

  @override
  String get chatDeleteMessageConfirm =>
      'Bu mesajı tüm cihazlarınızdan silmek ve karşı tarafı bilgilendirmek istiyor musunuz?';

  @override
  String get chatViewProfile => 'Profili Görüntüle';

  @override
  String get chatSyncMessages => 'Mesajları Senkronize Et';

  @override
  String get chatDeleteConversation => 'Konuşmayı Sil';

  @override
  String get chatDeleteConversationTitle => 'Konuşmayı Sil';

  @override
  String get chatDeleteConversationConfirm =>
      'Bu konuşmadaki tüm mesajları silmek istediğinize emin misiniz? Tüm cihazlarınızdan silinecek.';

  @override
  String get chatConversationDeleted => 'Konuşma silindi';

  @override
  String get chatDeleteConversationFailed => 'Konuşma silinemedi';

  @override
  String get settingsDeleteAllMessages => 'Tüm Mesajları Sil';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Tüm cihazlardan tüm mesajları kaldır';

  @override
  String get settingsDeleteAllMessagesTitle => 'Tüm Mesajlar Silinsin mi?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Bu işlem tüm konuşmalardaki TÜM mesajları tüm cihazlarınızdan kalıcı olarak silecektir. Bu işlem geri alınamaz.';

  @override
  String get settingsAllMessagesDeleted => 'Tüm mesajlar silindi';

  @override
  String get settingsDeleteAllMessagesFailed => 'Mesajlar silinemedi';

  @override
  String get settingsDeleteEverything => 'Her Şeyi Sil';

  @override
  String get settingsGeneral => 'Genel';

  @override
  String get settingsDataStorage => 'Veri ve Depolama';

  @override
  String get settingsAccount => 'Hesap';

  @override
  String get settingsClearCache => 'Önbelleği Temizle';

  @override
  String get settingsClearCacheSubtitle =>
      'İndirilen medya ve önbellek verilerini sil';

  @override
  String settingsCacheSize(String size) {
    return 'Yerel Önbellek: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'Önbellek Temizlensin mi?';

  @override
  String get settingsClearCacheWarning =>
      'Bu işlem önbelleğe alınmış tüm medyayı (resim, video, ses) silecektir. Gerektiğinde tekrar indirileceklerdir.';

  @override
  String get settingsCacheCleared => 'Önbellek temizlendi';

  @override
  String get settingsClearCacheButton => 'Temizle';

  @override
  String get txDetailSent => 'Gönderildi';

  @override
  String get txDetailReceived => 'Alındı';

  @override
  String get txDetailDenied => 'İşlem Reddedildi';

  @override
  String get txDetailFrom => 'Kimden';

  @override
  String get txDetailTo => 'Kime';

  @override
  String get txDetailTransactionHash => 'İşlem Kodu';

  @override
  String get txDetailTime => 'Zaman';

  @override
  String get txDetailNetwork => 'Ağ';

  @override
  String get txDetailAddressCopied => 'Adres kopyalandı';

  @override
  String get txDetailHashCopied => 'İşlem kodu kopyalandı';

  @override
  String get txDetailAddToAddressBook => 'Adres Defterine Ekle';

  @override
  String get txDetailClose => 'Kapat';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '\"$label\" adres defterine eklendi';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Eklenemedi: $error';
  }

  @override
  String get chatVideoGallery => 'Kütüphaneden Video';

  @override
  String get chatRecordVideo => 'Video Çek';

  @override
  String get chatVideoTooLarge => 'Video 64MB limitini aşıyor';

  @override
  String get chatRecordingHold => 'Kayıt için basılı tutun';

  @override
  String get chatRecordingRelease => 'Durdurmak için bırakın';

  @override
  String get chatRecordingTap => 'Kayıt için dokunun';

  @override
  String get chatRecordingInProgress => 'Kaydediliyor...';

  @override
  String get chatRecordingListening => 'Dinleniyor...';

  @override
  String get chatVoiceMessage => 'Sesli mesaj';

  @override
  String get chatDownloadingMedia => 'İndiriliyor...';

  @override
  String get chatUploadFailed =>
      'Yükleme başarısız. Tekrar denemek için dokunun.';

  @override
  String get chatTapToDownload => 'İndirmek için dokunun';

  @override
  String get chatVideoComingSoon => 'Video oynatma yakında';

  @override
  String get chatAudioComingSoon => 'Ses oynatma yakında';

  @override
  String get chatMediaUnsupported => 'Desteklenmeyen medya türü';

  @override
  String get chatTapToPlay => 'Oynatmak için dokunun';

  @override
  String get chatVideoError => 'Video oynatma hatası';

  @override
  String get chatAudioError => 'Ses oynatma hatası';

  @override
  String get userProfileTitle => 'Profil';

  @override
  String get userProfileEditProfile => 'Profili Düzenle';

  @override
  String get userProfileMessage => 'Mesaj';

  @override
  String get userProfilePosts => 'Paylaşımlar';

  @override
  String get userProfileNoPosts => 'Henüz paylaşım yok';

  @override
  String get userProfileTotalTips => 'Bahşiş';

  @override
  String get userProfileLastMonth => 'Son 30 Gün';
}
