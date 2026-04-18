// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Japanese (`ja`).
class AppLocalizationsJa extends AppLocalizations {
  AppLocalizationsJa([String locale = 'ja']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => '初期化中...';

  @override
  String get failedToInitialize => '初期化に失敗しました';

  @override
  String get makeSureNativeLibrary => 'ネイティブライブラリが利用可能であることを確認してください。';

  @override
  String get navHome => 'ホーム';

  @override
  String get navChats => 'チャット';

  @override
  String get navWallet => 'ウォレット';

  @override
  String get navMore => 'その他';

  @override
  String get messagesAll => 'すべて';

  @override
  String get messagesUnread => '未読';

  @override
  String get messagesAllCaughtUp => 'すべて確認済み！';

  @override
  String get messagesNoUnread => '未読メッセージはありません';

  @override
  String get messagesSearchHint => 'チャットを検索...';

  @override
  String get contactsTitle => '連絡先';

  @override
  String get contactsEmpty => '連絡先がありません';

  @override
  String get contactsTapToAdd => '+ をタップして連絡先を追加';

  @override
  String get contactsOnline => 'オンライン';

  @override
  String contactsLastSeen(String time) {
    return '最終確認: $time';
  }

  @override
  String get contactsOffline => 'オフライン';

  @override
  String get contactsSyncing => '同期中...';

  @override
  String get contactsFailedToLoad => '連絡先の読み込みに失敗しました';

  @override
  String get contactsRetry => '再試行';

  @override
  String get contactsHubContacts => '連絡先';

  @override
  String get contactsHubRequests => 'リクエスト';

  @override
  String get contactsHubBlocked => 'ブロック済み';

  @override
  String get contactsHubRemoveTitle => '連絡先を削除しますか？';

  @override
  String contactsHubRemoveMessage(String name) {
    return '$name を連絡先から削除してよろしいですか？';
  }

  @override
  String get contactsHubRemove => '削除';

  @override
  String get contactsHubFingerprintCopied => 'フィンガープリントをコピーしました';

  @override
  String get contactRequestsTitle => '連絡先リクエスト';

  @override
  String get contactRequestsEmpty => '保留中のリクエストはありません';

  @override
  String get contactRequestsAccept => '承認';

  @override
  String get contactRequestsDeny => '拒否';

  @override
  String get contactRequestsBlock => 'ユーザーをブロック';

  @override
  String get contactRequestsSent => '送信済み';

  @override
  String get contactRequestsReceived => '受信済み';

  @override
  String get addContactTitle => '連絡先を追加';

  @override
  String get addContactHint => '名前またはIDを入力';

  @override
  String get addContactSearching => '検索中...';

  @override
  String get addContactFoundOnNetwork => 'ネットワークで見つかりました';

  @override
  String get addContactNotFound => '見つかりません';

  @override
  String get addContactSendRequest => 'リクエストを送信';

  @override
  String get addContactRequestSent => '連絡先リクエストを送信しました';

  @override
  String get addContactAlreadyContact => 'すでに連絡先に登録されています';

  @override
  String get addContactCannotAddSelf => '自分自身を追加することはできません';

  @override
  String get chatSearchMessages => 'メッセージを検索';

  @override
  String get chatOnline => 'オンライン';

  @override
  String get chatOffline => 'オフライン';

  @override
  String get chatConnecting => '接続中...';

  @override
  String get chatTypeMessage => 'メッセージを入力';

  @override
  String get chatNoMessages => 'メッセージはまだありません';

  @override
  String get chatSendFirstMessage => 'メッセージを送信して会話を始めましょう';

  @override
  String get chatPhotoLibrary => 'フォトライブラリ';

  @override
  String get chatCamera => 'カメラ';

  @override
  String get chatAddCaption => 'キャプションを追加...';

  @override
  String get chatSendPhoto => '送信';

  @override
  String chatImageTooLarge(String maxSize) {
    return '画像が大きすぎます（最大 $maxSize）';
  }

  @override
  String get chatMessageDeleted => 'メッセージが削除されました';

  @override
  String get chatLoadEarlier => '以前のメッセージを読み込む';

  @override
  String chatLastSeen(String time) {
    return '最終確認: $time';
  }

  @override
  String get chatSendTokens => 'トークンを送る';

  @override
  String chatSendTokensTo(String name) {
    return '$name へ';
  }

  @override
  String get chatLookingUpWallets => 'ウォレットアドレスを検索中...';

  @override
  String get chatNoWalletAddresses => '連絡先のプロフィールにウォレットアドレスがありません';

  @override
  String get chatTokenLabel => 'トークン';

  @override
  String get chatSendAmount => '金額';

  @override
  String chatSendAvailable(String balance, String token) {
    return '残高: $balance $token';
  }

  @override
  String get chatSendMax => '最大';

  @override
  String chatSendButton(String token) {
    return '$token を送る';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return '$amount $token を送信しました';
  }

  @override
  String get chatInvalidAmount => '有効な金額を入力してください';

  @override
  String chatInsufficientBalance(String token) {
    return '$token の残高が不足しています';
  }

  @override
  String get chatNoWalletForNetwork => '連絡先はこのネットワークのウォレットを持っていません';

  @override
  String get chatSelectToken => 'トークンを選択';

  @override
  String get chatSelectNetwork => 'ネットワークを選択';

  @override
  String get chatEnterAmount => '金額を入力';

  @override
  String chatStepOf(String current, String total) {
    return 'ステップ $current / $total';
  }

  @override
  String get messageMenuReply => '返信';

  @override
  String get messageMenuCopy => 'コピー';

  @override
  String get messageMenuForward => '転送';

  @override
  String get messageMenuStar => 'スター';

  @override
  String get messageMenuUnstar => 'スターを外す';

  @override
  String get messageMenuRetry => '再試行';

  @override
  String get messageMenuDelete => '削除';

  @override
  String get groupsTitle => 'グループ';

  @override
  String get groupsCreate => 'グループを作成';

  @override
  String get groupsEmpty => 'グループがありません';

  @override
  String get groupsCreateOrJoin => 'グループを作成するか招待を承認してください';

  @override
  String get groupsPendingInvitations => '保留中の招待';

  @override
  String get groupsYourGroups => 'あなたのグループ';

  @override
  String get groupsInfo => 'グループ情報';

  @override
  String get groupsMembers => 'メンバー';

  @override
  String get groupsLeave => 'グループを退出';

  @override
  String get groupsDelete => 'グループを削除';

  @override
  String get groupsInvite => '招待';

  @override
  String get groupsAccept => '承認';

  @override
  String get groupsDecline => '辞退';

  @override
  String get groupsName => 'グループ名';

  @override
  String get groupsDescription => '説明';

  @override
  String get groupsCreated => 'グループを作成しました';

  @override
  String get groupsOwner => 'オーナー';

  @override
  String get groupsMember => 'メンバー';

  @override
  String get groupsAdmin => '管理者';

  @override
  String get groupsRemoveMember => 'メンバーを削除';

  @override
  String groupsKickConfirm(String name) {
    return '$name をグループから削除しますか？';
  }

  @override
  String get settingsTitle => '設定';

  @override
  String get settingsAnonymous => '匿名';

  @override
  String get settingsNotLoaded => '読み込まれていません';

  @override
  String get settingsTapToEditProfile => 'タップしてプロフィールを編集';

  @override
  String get settingsAppearance => '外観';

  @override
  String get settingsDarkMode => 'ダークモード';

  @override
  String get settingsDarkModeSubtitle => 'ダークテーマとライトテーマを切り替える';

  @override
  String get settingsLanguage => '言語';

  @override
  String get settingsLanguageSubtitle => 'アプリの言語を選択';

  @override
  String get settingsLanguageSystem => 'システムデフォルト';

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
  String get settingsBattery => 'バッテリー';

  @override
  String get settingsDisableBatteryOpt => 'バッテリー最適化を無効にする';

  @override
  String get settingsBatteryChecking => '確認中...';

  @override
  String get settingsBatteryDisabled => '無効 — アプリはバックグラウンドで実行できます';

  @override
  String get settingsBatteryTapToKeep => 'タップしてアプリをバックグラウンドで維持する';

  @override
  String get settingsSecurity => 'セキュリティ';

  @override
  String get settingsExportSeedPhrase => 'シードフレーズをエクスポート';

  @override
  String get settingsExportSeedSubtitle => 'リカバリーフレーズをバックアップ';

  @override
  String get settingsAppLock => 'アプリロック';

  @override
  String get settingsAppLockSubtitle => '認証を要求する';

  @override
  String get settingsExportSeedWarning =>
      'シードフレーズはあなたのIDへの完全なアクセスを提供します。絶対に他人と共有しないでください。';

  @override
  String get settingsShowSeed => 'シードを表示';

  @override
  String get settingsYourSeedPhrase => 'あなたのシードフレーズ';

  @override
  String get settingsSeedPhraseWarning =>
      'これらの単語を順番に書き留め、安全な場所に保管してください。このフレーズを持つ人は誰でもあなたのIDにアクセスできます。';

  @override
  String get settingsSeedCopied => 'シードフレーズをクリップボードにコピーしました';

  @override
  String get seedCopyConfirmTitle => 'Copy seed phrase?';

  @override
  String get seedCopyConfirmBody =>
      'Your seed phrase will be in the clipboard for 10 seconds. Do not switch apps or background the app during this time. Continue?';

  @override
  String get seedCopiedToast => 'Copied. Clipboard will clear in 10 seconds.';

  @override
  String get settingsSeedNotAvailable =>
      'このIDのシードフレーズは利用できません。この機能が追加される前に作成されました。';

  @override
  String get settingsSeedError => 'シードフレーズを取得できません';

  @override
  String get settingsWallet => 'ウォレット';

  @override
  String get settingsHideZeroBalance => 'ゼロ残高を非表示';

  @override
  String get settingsHideZeroBalanceSubtitle => '残高がゼロのコインを非表示にする';

  @override
  String get settingsData => 'データ';

  @override
  String get settingsAutoSync => '自動同期';

  @override
  String get settingsAutoSyncSubtitle => '15分ごとにメッセージを自動的に同期する';

  @override
  String settingsLastSync(String time) {
    return '最終同期: $time';
  }

  @override
  String get settingsSyncNow => '今すぐ同期';

  @override
  String get settingsSyncNowSubtitle => '即座に同期を強制する';

  @override
  String get settingsLogs => 'ログ';

  @override
  String get settingsOpenLogsFolder => 'ログフォルダーを開く';

  @override
  String get settingsOpenLogsFolderSubtitle => 'ログディレクトリでファイルマネージャーを開く';

  @override
  String get settingsShareLogs => 'ログを共有';

  @override
  String get settingsShareLogsSubtitle => 'ログファイルをzip圧縮して共有する';

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
  String get settingsLogsFolderNotExist => 'ログフォルダーはまだ存在しません';

  @override
  String get settingsNoLogFiles => 'ログファイルが見つかりません';

  @override
  String get settingsFailedCreateZip => 'zipアーカイブの作成に失敗しました';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'ログがまだありません。$debugInfo';
  }

  @override
  String get settingsIdentity => 'ID';

  @override
  String get settingsFingerprint => 'フィンガープリント';

  @override
  String get settingsFingerprintCopied => 'フィンガープリントをコピーしました';

  @override
  String get settingsDeleteAccount => 'アカウントを削除';

  @override
  String get settingsDeleteAccountSubtitle => 'デバイスからすべてのデータを完全に削除';

  @override
  String get settingsDeleteAccountConfirm => 'アカウントを削除しますか？';

  @override
  String get settingsDeleteAccountWarning => 'これにより、すべてのローカルデータが完全に削除されます：';

  @override
  String get settingsDeletePrivateKeys => '秘密鍵';

  @override
  String get settingsDeleteWallets => 'ウォレット';

  @override
  String get settingsDeleteMessages => 'メッセージ';

  @override
  String get settingsDeleteContacts => '連絡先';

  @override
  String get settingsDeleteGroups => 'グループ';

  @override
  String get settingsDeleteSeedWarning =>
      '削除する前にシードフレーズをバックアップしていることを確認してください！';

  @override
  String get settingsDeleteSuccess => 'アカウントが正常に削除されました';

  @override
  String settingsDeleteFailed(String error) {
    return 'アカウントの削除に失敗しました: $error';
  }

  @override
  String get settingsAbout => 'このアプリについて';

  @override
  String get settingsUpdateAvailable => 'アップデートが利用可能';

  @override
  String get settingsTapToDownload => 'タップしてダウンロード';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'ライブラリ v$version';
  }

  @override
  String get settingsPostQuantumMessenger => 'ポスト量子暗号コミュニケーション';

  @override
  String get settingsCryptoStack => '暗号スタック';

  @override
  String get profileTitle => 'プロフィールを編集';

  @override
  String get profileInfo => 'プロフィール情報';

  @override
  String get profileBio => '自己紹介';

  @override
  String get profileLocation => '場所';

  @override
  String get profileWebsite => 'ウェブサイト';

  @override
  String get profileWalletAddresses => 'ウォレットアドレス';

  @override
  String get profileSave => 'プロフィールを保存';

  @override
  String get profileShareQR => 'QRコードを共有';

  @override
  String get profileAvatar => 'アバター';

  @override
  String get profileTakeSelfie => '自撮りを撮る';

  @override
  String get profileChooseFromGallery => 'ギャラリーから選択';

  @override
  String get profileSaved => 'プロフィールを保存しました';

  @override
  String profileSaveFailed(String error) {
    return 'プロフィールの保存に失敗しました: $error';
  }

  @override
  String get profileCropTitle => 'アバターをトリミング';

  @override
  String get profileCropSave => '保存';

  @override
  String get contactProfileFailed => 'プロフィールの読み込みに失敗しました';

  @override
  String get contactProfileUnknownError => '不明なエラー';

  @override
  String get contactProfileNickname => 'ニックネーム';

  @override
  String get contactProfileNicknameNotSet => '未設定（タップして追加）';

  @override
  String contactProfileOriginal(String name) {
    return '元の名前: $name';
  }

  @override
  String get contactProfileSetNickname => 'ニックネームを設定';

  @override
  String contactProfileOriginalName(String name) {
    return '元の名前: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'ニックネーム';

  @override
  String get contactProfileNicknameHint => 'カスタムニックネームを入力';

  @override
  String get contactProfileNicknameHelper => '元の名前を使用する場合は空のままにしてください';

  @override
  String get contactProfileNicknameCleared => 'ニックネームをクリアしました';

  @override
  String contactProfileNicknameSet(String name) {
    return 'ニックネームを「$name」に設定しました';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'ニックネームの設定に失敗しました: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'フィンガープリントをコピー';

  @override
  String get contactProfileNoProfile => 'プロフィールが公開されていません';

  @override
  String get contactProfileNoProfileSubtitle => 'このユーザーはまだプロフィールを公開していません。';

  @override
  String get contactProfileBio => '自己紹介';

  @override
  String get contactProfileInfo => '情報';

  @override
  String get contactProfileWebsite => 'ウェブサイト';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'DNA Connectへようこそ';

  @override
  String get identityGenerateSeed => '新しいシードを生成';

  @override
  String get identityHaveSeed => 'シードフレーズを持っています';

  @override
  String get identityYourRecoveryPhrase => 'あなたのリカバリーフレーズ';

  @override
  String get identityRecoveryPhraseWarning =>
      'これらの単語を書き留め、安全に保管してください。アカウントを復元する唯一の方法です。';

  @override
  String get identityConfirmSaved => 'リカバリーフレーズを保存しました';

  @override
  String get identityEnterRecoveryPhrase => 'リカバリーフレーズを入力';

  @override
  String get identityEnterRecoveryPhraseHint => '12語または24語のリカバリーフレーズを入力';

  @override
  String get identityChooseName => '名前を選択';

  @override
  String get identityChooseNameHint => '表示名を入力';

  @override
  String get identityRegisterContinue => '登録して続ける';

  @override
  String get identityRegistering => '登録中...';

  @override
  String get identityNameTaken => 'この名前はすでに使用されています';

  @override
  String get identityNameInvalid => '名前は3〜20文字でなければなりません';

  @override
  String get identityCreating => 'IDを作成中...';

  @override
  String get identityRestoring => 'IDを復元中...';

  @override
  String get wallTitle => 'ホーム';

  @override
  String get wallWelcome => 'タイムラインへようこそ！';

  @override
  String get wallWelcomeSubtitle => '人やチャンネルをフォローして投稿をここで確認できます。';

  @override
  String get wallNewPost => '新しい投稿';

  @override
  String get wallDeletePost => '投稿を削除';

  @override
  String get wallDeletePostConfirm => 'この投稿を削除してよろしいですか？';

  @override
  String get wallRepost => 'リポスト';

  @override
  String get wallReposted => 'リポストしました';

  @override
  String get wallComments => 'コメント';

  @override
  String get wallNoComments => 'コメントがまだありません';

  @override
  String get wallLoadingComments => 'コメントを読み込み中...';

  @override
  String get wallWriteComment => 'コメントを書く...';

  @override
  String get wallWriteReply => '返信を書く...';

  @override
  String wallViewAllComments(int count) {
    return '$count件のコメントをすべて表示';
  }

  @override
  String get wallPostDetail => '投稿';

  @override
  String get wallCopy => 'コピー';

  @override
  String get wallReply => '返信';

  @override
  String get wallDelete => '削除';

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
  String get wallTip => 'チップ';

  @override
  String get wallTipTitle => 'この投稿にチップを送る';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'チップを送る';

  @override
  String get wallTipCancel => 'キャンセル';

  @override
  String get wallTipSuccess => 'チップを送りました！';

  @override
  String wallTipFailed(String error) {
    return 'チップ失敗: $error';
  }

  @override
  String get wallTipNoWallet => 'このユーザーはプロフィールにウォレットアドレスがありません';

  @override
  String get wallTipInsufficientBalance => 'CPUNK残高不足';

  @override
  String get wallTipSending => 'チップを送信中...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNKチップ';
  }

  @override
  String get wallTipPending => '保留中';

  @override
  String get wallTipVerified => '確認済み';

  @override
  String get wallTipFailedStatus => '失敗';

  @override
  String get wallWhatsOnYourMind => '今何を考えていますか？';

  @override
  String get wallPost => '投稿';

  @override
  String get wallPosting => '投稿中...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'ブースト';

  @override
  String get wallBoostDescription => 'みんなに共有';

  @override
  String get wallBoosted => 'ブースト済み';

  @override
  String get wallBoostLimitReached => '1日のブースト上限に達しました';

  @override
  String get wallAddComment => 'コメントを追加（任意）';

  @override
  String get wallCreatePostTitle => '投稿を作成';

  @override
  String get walletTitle => 'ウォレット';

  @override
  String get walletTotalBalance => '合計残高';

  @override
  String get walletSend => '送る';

  @override
  String get walletReceive => '受け取る';

  @override
  String get walletHistory => '履歴';

  @override
  String get walletNoTransactions => '取引がまだありません';

  @override
  String get walletCopyAddress => 'アドレスをコピー';

  @override
  String get walletAddressCopied => 'アドレスをコピーしました';

  @override
  String walletSendTitle(String coin) {
    return '$coin を送る';
  }

  @override
  String get walletRecipientAddress => '受取人のアドレス';

  @override
  String get walletAmount => '金額';

  @override
  String get walletMax => '最大';

  @override
  String get walletSendConfirm => '送金を確認';

  @override
  String get walletSending => '送金中...';

  @override
  String get walletSendSuccess => '取引を送信しました';

  @override
  String walletSendFailed(String error) {
    return '取引に失敗しました: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return '$coin を受け取る';
  }

  @override
  String get walletAddressBook => 'アドレス帳';

  @override
  String get walletAddAddress => 'アドレスを追加';

  @override
  String get walletEditAddress => 'アドレスを編集';

  @override
  String get walletDeleteAddress => 'アドレスを削除';

  @override
  String get walletLabel => 'ラベル';

  @override
  String get walletAddress => 'アドレス';

  @override
  String get walletNetwork => 'ネットワーク';

  @override
  String get walletAllChains => 'すべて';

  @override
  String get walletAssets => '資産';

  @override
  String get walletPortfolio => 'ポートフォリオ';

  @override
  String get walletMyWallet => 'マイウォレット';

  @override
  String get walletTxToday => '今日';

  @override
  String get walletTxYesterday => '昨日';

  @override
  String get walletTxThisWeek => '今週';

  @override
  String get walletTxEarlier => 'それ以前';

  @override
  String get walletNoNonZeroBalances => '残高のある資産なし';

  @override
  String get walletNoBalances => '残高なし';

  @override
  String get qrScannerTitle => 'QRスキャナー';

  @override
  String get qrAddContact => '連絡先を追加';

  @override
  String get qrAuthRequest => '認証リクエスト';

  @override
  String get qrContent => 'QRコンテンツ';

  @override
  String get qrSendContactRequest => '連絡先リクエストを送信';

  @override
  String get qrScanAnother => '別のコードをスキャン';

  @override
  String get qrCopyFingerprint => 'コピー';

  @override
  String get qrRequestSent => '連絡先リクエストを送信しました';

  @override
  String get qrInvalidCode => '無効なQRコード';

  @override
  String get moreTitle => 'その他';

  @override
  String get moreWallet => 'ウォレット';

  @override
  String get moreQRScanner => 'QRスキャナー';

  @override
  String get moreAddresses => 'アドレス';

  @override
  String get moreStarred => 'スター付き';

  @override
  String get moreContacts => '連絡先';

  @override
  String get moreSettings => '設定';

  @override
  String get moreAppLock => 'アプリロック';

  @override
  String get moreInviteFriends => '友達を招待';

  @override
  String inviteFriendsMessage(String username) {
    return 'DNA Connectを試してみて — 量子安全な暗号化メッセンジャー。追加してね: $username — ダウンロード: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'PINを入力してロック解除';

  @override
  String get lockIncorrectPIN => 'PINが正しくありません';

  @override
  String lockTooManyAttempts(int seconds) {
    return '試行回数が多すぎます。$seconds秒後に再試行してください';
  }

  @override
  String get lockUseBiometrics => '生体認証でロック解除';

  @override
  String get appLockTitle => 'アプリロック';

  @override
  String get appLockEnable => 'アプリロックを有効にする';

  @override
  String get appLockUseBiometrics => '生体認証を使用';

  @override
  String get appLockChangePIN => 'PINを変更';

  @override
  String get appLockSetPIN => 'PINを設定';

  @override
  String get appLockConfirmPIN => 'PINを確認';

  @override
  String get appLockPINMismatch => 'PINが一致しません';

  @override
  String get appLockPINSet => 'PINを正常に設定しました';

  @override
  String get appLockPINChanged => 'PINを変更しました';

  @override
  String get appLockEnterCurrentPIN => '現在のPINを入力';

  @override
  String get appLockEnterNewPIN => '新しいPINを入力';

  @override
  String get starredTitle => 'スター付きメッセージ';

  @override
  String get starredEmpty => 'スター付きメッセージはありません';

  @override
  String get blockedTitle => 'ブロックしたユーザー';

  @override
  String get blockedEmpty => 'ブロックしたユーザーはありません';

  @override
  String get blockedUnblock => 'ブロックを解除';

  @override
  String blockedUnblockConfirm(String name) {
    return '$name のブロックを解除しますか？';
  }

  @override
  String get updateTitle => 'アップデートが必要です';

  @override
  String get updateMessage => 'DNA Connectを引き続き使用するには、新しいバージョンが必要です。';

  @override
  String get updateDownload => 'アップデートをダウンロード';

  @override
  String get updateAvailableTitle => '新しいバージョンが利用可能';

  @override
  String get updateAvailableMessage =>
      'DNA Connectの新しいバージョンが利用可能です。今すぐアップデートして最新の機能と改善を入手してください。';

  @override
  String get updateLater => '後で';

  @override
  String get cancel => 'キャンセル';

  @override
  String get save => '保存';

  @override
  String get delete => '削除';

  @override
  String get done => '完了';

  @override
  String get copy => 'コピー';

  @override
  String get ok => 'OK';

  @override
  String get yes => 'はい';

  @override
  String get no => 'いいえ';

  @override
  String get error => 'エラー';

  @override
  String get success => '成功';

  @override
  String get loading => '読み込み中...';

  @override
  String get pleaseWait => 'お待ちください...';

  @override
  String get copied => 'コピーしました';

  @override
  String failed(String error) {
    return '失敗: $error';
  }

  @override
  String get retry => '再試行';

  @override
  String get continueButton => '続ける';

  @override
  String get approve => '承認';

  @override
  String get deny => '拒否';

  @override
  String get verify => '確認';

  @override
  String get copyToClipboard => 'クリップボードにコピー';

  @override
  String get copiedToClipboard => 'クリップボードにコピーしました';

  @override
  String get pasteFromClipboard => 'クリップボードから貼り付け';

  @override
  String get biometricsSubtitle => '指紋またはFace ID';

  @override
  String get changePINSubtitle => 'ロック解除PINを更新する';

  @override
  String get biometricFailed => '生体認証に失敗しました';

  @override
  String get contactRequestsWillAppear => '連絡先リクエストがここに表示されます';

  @override
  String get blockedUsersWillAppear => 'ブロックしたユーザーがここに表示されます';

  @override
  String get failedToLoadTimeline => 'タイムラインの読み込みに失敗しました';

  @override
  String get userUnblocked => 'ユーザーのブロックを解除しました';

  @override
  String get backupFound => 'バックアップが見つかりました';

  @override
  String approvedContact(String name) {
    return '$name を承認しました';
  }

  @override
  String deniedContact(String name) {
    return '$name を拒否しました';
  }

  @override
  String blockedContact(String name) {
    return '$name をブロックしました';
  }

  @override
  String unsubscribeFrom(String name) {
    return '$name の登録を解除';
  }

  @override
  String get chatSenderDeletedThis => '送信者がこれを削除しました';

  @override
  String get chatDeleteMessageTitle => 'メッセージを削除';

  @override
  String get chatDeleteMessageConfirm => 'すべてのデバイスからこのメッセージを削除し、相手に通知しますか？';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => '会話を削除';

  @override
  String get chatDeleteConversationTitle => '会話を削除';

  @override
  String get chatDeleteConversationConfirm =>
      'この会話のすべてのメッセージを削除しますか？これにより、すべてのデバイスから削除されます。';

  @override
  String get chatConversationDeleted => '会話を削除しました';

  @override
  String get chatDeleteConversationFailed => '会話の削除に失敗しました';

  @override
  String get settingsDeleteAllMessages => 'すべてのメッセージを削除';

  @override
  String get settingsDeleteAllMessagesSubtitle => 'すべてのデバイスからすべてのメッセージを削除';

  @override
  String get settingsDeleteAllMessagesTitle => 'すべてのメッセージを削除しますか？';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'これにより、すべてのデバイス上のすべての会話のすべてのメッセージが完全に削除されます。この操作は元に戻せません。';

  @override
  String get settingsAllMessagesDeleted => 'すべてのメッセージを削除しました';

  @override
  String get settingsDeleteAllMessagesFailed => 'メッセージの削除に失敗しました';

  @override
  String get settingsDeleteEverything => 'すべてを削除';

  @override
  String get settingsGeneral => '一般';

  @override
  String get settingsDataStorage => 'データとストレージ';

  @override
  String get settingsAccount => 'アカウント';

  @override
  String get settingsClearCache => 'キャッシュを削除';

  @override
  String get settingsClearCacheSubtitle => 'ダウンロードしたメディアとキャッシュデータを削除';

  @override
  String settingsCacheSize(String size) {
    return 'ローカルキャッシュ: $size';
  }

  @override
  String get settingsClearCacheConfirm => 'キャッシュを削除しますか？';

  @override
  String get settingsClearCacheWarning =>
      'キャッシュされたすべてのメディア（画像、動画、音声）が削除されます。必要に応じて再ダウンロードされます。';

  @override
  String get settingsCacheCleared => 'キャッシュを削除しました';

  @override
  String get settingsClearCacheButton => '削除';

  @override
  String get txDetailSent => '送信済み';

  @override
  String get txDetailReceived => '受信済み';

  @override
  String get txDetailDenied => '取引が拒否されました';

  @override
  String get txDetailFrom => '送信元';

  @override
  String get txDetailTo => '送信先';

  @override
  String get txDetailTransactionHash => 'トランザクションハッシュ';

  @override
  String get txDetailTime => '時間';

  @override
  String get txDetailNetwork => 'ネットワーク';

  @override
  String get txDetailMemo => 'Memo';

  @override
  String get txDetailAddressCopied => 'アドレスをコピーしました';

  @override
  String get txDetailHashCopied => 'ハッシュをコピーしました';

  @override
  String get txDetailAddToAddressBook => 'アドレス帳に追加';

  @override
  String get txDetailClose => '閉じる';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '「$label」をアドレス帳に追加しました';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return '追加に失敗しました: $error';
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
  String get chatRecordingRelease => '離して停止';

  @override
  String get chatRecordingTap => 'タップして録音';

  @override
  String get chatRecordingInProgress => '録音中...';

  @override
  String get chatRecordingListening => '再生中...';

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
}
