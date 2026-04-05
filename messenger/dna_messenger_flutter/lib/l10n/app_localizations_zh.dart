// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Chinese (`zh`).
class AppLocalizationsZh extends AppLocalizations {
  AppLocalizationsZh([String locale = 'zh']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => '初始化中...';

  @override
  String get failedToInitialize => '初始化失败';

  @override
  String get makeSureNativeLibrary => '请确保本地库可用。';

  @override
  String get navHome => '主页';

  @override
  String get navChats => '聊天';

  @override
  String get navWallet => '钱包';

  @override
  String get navMore => '更多';

  @override
  String get messagesAll => '全部';

  @override
  String get messagesUnread => '未读';

  @override
  String get messagesAllCaughtUp => '全部已读！';

  @override
  String get messagesNoUnread => '没有未读消息';

  @override
  String get messagesSearchHint => '搜索聊天...';

  @override
  String get contactsTitle => '联系人';

  @override
  String get contactsEmpty => '暂无联系人';

  @override
  String get contactsTapToAdd => '点击 + 添加联系人';

  @override
  String get contactsOnline => '在线';

  @override
  String contactsLastSeen(String time) {
    return '最后在线 $time';
  }

  @override
  String get contactsOffline => '离线';

  @override
  String get contactsSyncing => '同步中...';

  @override
  String get contactsFailedToLoad => '加载联系人失败';

  @override
  String get contactsRetry => '重试';

  @override
  String get contactsHubContacts => '联系人';

  @override
  String get contactsHubRequests => '请求';

  @override
  String get contactsHubBlocked => '已屏蔽';

  @override
  String get contactsHubRemoveTitle => '移除联系人？';

  @override
  String contactsHubRemoveMessage(String name) {
    return '确定要将 $name 从联系人中移除吗？';
  }

  @override
  String get contactsHubRemove => '移除';

  @override
  String get contactsHubFingerprintCopied => '指纹已复制';

  @override
  String get contactRequestsTitle => '联系人请求';

  @override
  String get contactRequestsEmpty => '没有待处理的请求';

  @override
  String get contactRequestsAccept => '接受';

  @override
  String get contactRequestsDeny => '拒绝';

  @override
  String get contactRequestsBlock => '屏蔽用户';

  @override
  String get contactRequestsSent => '已发送';

  @override
  String get contactRequestsReceived => '已收到';

  @override
  String get addContactTitle => '添加联系人';

  @override
  String get addContactHint => '输入姓名或 ID';

  @override
  String get addContactSearching => '搜索中...';

  @override
  String get addContactFoundOnNetwork => '在网络上找到';

  @override
  String get addContactNotFound => '未找到';

  @override
  String get addContactSendRequest => '发送请求';

  @override
  String get addContactRequestSent => '联系人请求已发送';

  @override
  String get addContactAlreadyContact => '已在联系人列表中';

  @override
  String get addContactCannotAddSelf => '无法添加自己';

  @override
  String get chatSearchMessages => '搜索消息';

  @override
  String get chatOnline => '在线';

  @override
  String get chatOffline => '离线';

  @override
  String get chatConnecting => '连接中...';

  @override
  String get chatTypeMessage => '输入消息';

  @override
  String get chatNoMessages => '暂无消息';

  @override
  String get chatSendFirstMessage => '发送消息开始对话';

  @override
  String get chatPhotoLibrary => '相册';

  @override
  String get chatCamera => '相机';

  @override
  String get chatAddCaption => '添加说明...';

  @override
  String get chatSendPhoto => '发送';

  @override
  String chatImageTooLarge(String maxSize) {
    return '图片过大（最大 $maxSize）';
  }

  @override
  String get chatMessageDeleted => '消息已删除';

  @override
  String get chatLoadEarlier => '加载更早的消息';

  @override
  String chatLastSeen(String time) {
    return '最后在线 $time';
  }

  @override
  String get chatSendTokens => '发送代币';

  @override
  String chatSendTokensTo(String name) {
    return '发送给 $name';
  }

  @override
  String get chatLookingUpWallets => '正在查找钱包地址...';

  @override
  String get chatNoWalletAddresses => '联系人的个人资料中没有钱包地址';

  @override
  String get chatTokenLabel => '代币';

  @override
  String get chatSendAmount => '金额';

  @override
  String chatSendAvailable(String balance, String token) {
    return '可用：$balance $token';
  }

  @override
  String get chatSendMax => '最大';

  @override
  String chatSendButton(String token) {
    return '发送 $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return '已发送 $amount $token';
  }

  @override
  String get chatInvalidAmount => '请输入有效金额';

  @override
  String chatInsufficientBalance(String token) {
    return '$token 余额不足';
  }

  @override
  String get chatNoWalletForNetwork => '联系人没有此网络的钱包';

  @override
  String get chatSelectToken => '选择代币';

  @override
  String get chatSelectNetwork => '选择网络';

  @override
  String get chatEnterAmount => '输入金额';

  @override
  String chatStepOf(String current, String total) {
    return '第 $current 步，共 $total 步';
  }

  @override
  String get messageMenuReply => '回复';

  @override
  String get messageMenuCopy => '复制';

  @override
  String get messageMenuForward => '转发';

  @override
  String get messageMenuStar => '收藏';

  @override
  String get messageMenuUnstar => '取消收藏';

  @override
  String get messageMenuRetry => '重试';

  @override
  String get messageMenuDelete => '删除';

  @override
  String get groupsTitle => '群组';

  @override
  String get groupsCreate => '创建群组';

  @override
  String get groupsEmpty => '暂无群组';

  @override
  String get groupsCreateOrJoin => '创建群组或接受邀请';

  @override
  String get groupsPendingInvitations => '待处理邀请';

  @override
  String get groupsYourGroups => '我的群组';

  @override
  String get groupsInfo => '群组信息';

  @override
  String get groupsMembers => '成员';

  @override
  String get groupsLeave => '退出群组';

  @override
  String get groupsDelete => '删除群组';

  @override
  String get groupsInvite => '邀请';

  @override
  String get groupsAccept => '接受';

  @override
  String get groupsDecline => '拒绝';

  @override
  String get groupsName => '群组名称';

  @override
  String get groupsDescription => '描述';

  @override
  String get groupsCreated => '群组已创建';

  @override
  String get groupsOwner => '群主';

  @override
  String get groupsMember => '成员';

  @override
  String get groupsAdmin => '管理员';

  @override
  String get groupsRemoveMember => '移除成员';

  @override
  String groupsKickConfirm(String name) {
    return '将 $name 从群组中移除？';
  }

  @override
  String get settingsTitle => '设置';

  @override
  String get settingsAnonymous => '匿名';

  @override
  String get settingsNotLoaded => '未加载';

  @override
  String get settingsTapToEditProfile => '点击编辑个人资料';

  @override
  String get settingsAppearance => '外观';

  @override
  String get settingsDarkMode => '深色模式';

  @override
  String get settingsDarkModeSubtitle => '在深色和浅色主题之间切换';

  @override
  String get settingsLanguage => '语言';

  @override
  String get settingsLanguageSubtitle => '选择应用语言';

  @override
  String get settingsLanguageSystem => '系统默认';

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
  String get settingsBattery => '电池';

  @override
  String get settingsDisableBatteryOpt => '禁用电池优化';

  @override
  String get settingsBatteryChecking => '检查中...';

  @override
  String get settingsBatteryDisabled => '已禁用 — 应用可在后台运行';

  @override
  String get settingsBatteryTapToKeep => '点击以保持应用在后台运行';

  @override
  String get settingsSecurity => '安全';

  @override
  String get settingsExportSeedPhrase => '导出助记词';

  @override
  String get settingsExportSeedSubtitle => '备份您的恢复短语';

  @override
  String get settingsAppLock => '应用锁';

  @override
  String get settingsAppLockSubtitle => '需要身份验证';

  @override
  String get settingsExportSeedWarning => '您的助记词可完全访问您的身份。切勿与任何人分享。';

  @override
  String get settingsShowSeed => '显示助记词';

  @override
  String get settingsYourSeedPhrase => '您的助记词';

  @override
  String get settingsSeedPhraseWarning => '请按顺序写下这些词并安全保存。任何拥有此短语的人都可以访问您的身份。';

  @override
  String get settingsSeedCopied => '助记词已复制到剪贴板';

  @override
  String get settingsSeedNotAvailable => '此身份的助记词不可用。它是在添加此功能之前创建的。';

  @override
  String get settingsSeedError => '无法获取助记词';

  @override
  String get settingsWallet => '钱包';

  @override
  String get settingsHideZeroBalance => '隐藏零余额';

  @override
  String get settingsHideZeroBalanceSubtitle => '隐藏余额为零的币种';

  @override
  String get settingsData => '数据';

  @override
  String get settingsAutoSync => '自动同步';

  @override
  String get settingsAutoSyncSubtitle => '每15分钟自动同步消息';

  @override
  String settingsLastSync(String time) {
    return '上次同步：$time';
  }

  @override
  String get settingsSyncNow => '立即同步';

  @override
  String get settingsSyncNowSubtitle => '强制立即同步';

  @override
  String get settingsLogs => '日志';

  @override
  String get settingsOpenLogsFolder => '打开日志文件夹';

  @override
  String get settingsOpenLogsFolderSubtitle => '在文件管理器中打开日志目录';

  @override
  String get settingsShareLogs => '分享日志';

  @override
  String get settingsShareLogsSubtitle => '压缩并分享日志文件';

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
  String get settingsLogsFolderNotExist => '日志文件夹尚不存在';

  @override
  String get settingsNoLogFiles => '未找到日志文件';

  @override
  String get settingsFailedCreateZip => '创建压缩文件失败';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return '暂无日志。$debugInfo';
  }

  @override
  String get settingsIdentity => '身份';

  @override
  String get settingsFingerprint => '指纹';

  @override
  String get settingsFingerprintCopied => '指纹已复制';

  @override
  String get settingsDeleteAccount => '删除账户';

  @override
  String get settingsDeleteAccountSubtitle => '从设备上永久删除所有数据';

  @override
  String get settingsDeleteAccountConfirm => '删除账户？';

  @override
  String get settingsDeleteAccountWarning => '这将永久删除所有本地数据：';

  @override
  String get settingsDeletePrivateKeys => '私钥';

  @override
  String get settingsDeleteWallets => '钱包';

  @override
  String get settingsDeleteMessages => '消息';

  @override
  String get settingsDeleteContacts => '联系人';

  @override
  String get settingsDeleteGroups => '群组';

  @override
  String get settingsDeleteSeedWarning => '删除前请确保已备份您的助记词！';

  @override
  String get settingsDeleteSuccess => '账户删除成功';

  @override
  String settingsDeleteFailed(String error) {
    return '删除账户失败：$error';
  }

  @override
  String get settingsAbout => '关于';

  @override
  String get settingsUpdateAvailable => '有可用更新';

  @override
  String get settingsTapToDownload => '点击下载';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return '库版本 v$version';
  }

  @override
  String get settingsPostQuantumMessenger => '后量子加密通信';

  @override
  String get settingsCryptoStack => '加密技术栈';

  @override
  String get profileTitle => '编辑个人资料';

  @override
  String get profileInfo => '个人信息';

  @override
  String get profileBio => '简介';

  @override
  String get profileLocation => '位置';

  @override
  String get profileWebsite => '网站';

  @override
  String get profileWalletAddresses => '钱包地址';

  @override
  String get profileSave => '保存个人资料';

  @override
  String get profileShareQR => '分享我的 QR 码';

  @override
  String get profileAvatar => '头像';

  @override
  String get profileTakeSelfie => '拍摄自拍';

  @override
  String get profileChooseFromGallery => '从相册选择';

  @override
  String get profileSaved => '个人资料已保存';

  @override
  String profileSaveFailed(String error) {
    return '保存个人资料失败：$error';
  }

  @override
  String get profileCropTitle => '裁剪头像';

  @override
  String get profileCropSave => '保存';

  @override
  String get contactProfileFailed => '加载个人资料失败';

  @override
  String get contactProfileUnknownError => '未知错误';

  @override
  String get contactProfileNickname => '昵称';

  @override
  String get contactProfileNicknameNotSet => '未设置（点击添加）';

  @override
  String contactProfileOriginal(String name) {
    return '原始名称：$name';
  }

  @override
  String get contactProfileSetNickname => '设置昵称';

  @override
  String contactProfileOriginalName(String name) {
    return '原始名称：$name';
  }

  @override
  String get contactProfileNicknameLabel => '昵称';

  @override
  String get contactProfileNicknameHint => '输入自定义昵称';

  @override
  String get contactProfileNicknameHelper => '留空则使用原始名称';

  @override
  String get contactProfileNicknameCleared => '昵称已清除';

  @override
  String contactProfileNicknameSet(String name) {
    return '昵称已设置为\"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return '设置昵称失败：$error';
  }

  @override
  String get contactProfileCopyFingerprint => '复制指纹';

  @override
  String get contactProfileNoProfile => '未发布个人资料';

  @override
  String get contactProfileNoProfileSubtitle => '该用户尚未发布其个人资料。';

  @override
  String get contactProfileBio => '简介';

  @override
  String get contactProfileInfo => '信息';

  @override
  String get contactProfileWebsite => '网站';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => '欢迎使用 DNA Connect';

  @override
  String get identityGenerateSeed => '生成新助记词';

  @override
  String get identityHaveSeed => '我有助记词';

  @override
  String get identityYourRecoveryPhrase => '您的恢复短语';

  @override
  String get identityRecoveryPhraseWarning => '请写下这些词并妥善保管。这是恢复账户的唯一方式。';

  @override
  String get identityConfirmSaved => '我已保存恢复短语';

  @override
  String get identityEnterRecoveryPhrase => '输入恢复短语';

  @override
  String get identityEnterRecoveryPhraseHint => '输入您的 12 或 24 个词的恢复短语';

  @override
  String get identityChooseName => '选择您的名称';

  @override
  String get identityChooseNameHint => '输入显示名称';

  @override
  String get identityRegisterContinue => '注册并继续';

  @override
  String get identityRegistering => '注册中...';

  @override
  String get identityNameTaken => '此名称已被占用';

  @override
  String get identityNameInvalid => '名称必须为 3-20 个字符';

  @override
  String get identityCreating => '正在创建您的身份...';

  @override
  String get identityRestoring => '正在恢复您的身份...';

  @override
  String get wallTitle => '主页';

  @override
  String get wallWelcome => '欢迎来到您的时间线！';

  @override
  String get wallWelcomeSubtitle => '关注人和频道，在这里查看他们的帖子。';

  @override
  String get wallNewPost => '新帖子';

  @override
  String get wallDeletePost => '删除帖子';

  @override
  String get wallDeletePostConfirm => '确定要删除这篇帖子吗？';

  @override
  String get wallRepost => '转发';

  @override
  String get wallReposted => '已转发';

  @override
  String get wallComments => '评论';

  @override
  String get wallNoComments => '暂无评论';

  @override
  String get wallLoadingComments => '加载评论中...';

  @override
  String get wallWriteComment => '写评论...';

  @override
  String get wallWriteReply => '写回复...';

  @override
  String wallViewAllComments(int count) {
    return '查看全部 $count 条评论';
  }

  @override
  String get wallPostDetail => '帖子';

  @override
  String get wallCopy => '复制';

  @override
  String get wallReply => '回复';

  @override
  String get wallDelete => '删除';

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
  String get wallTip => '打赏';

  @override
  String get wallTipTitle => '打赏这篇帖子';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => '发送打赏';

  @override
  String get wallTipCancel => '取消';

  @override
  String get wallTipSuccess => '打赏已发送！';

  @override
  String wallTipFailed(String error) {
    return '打赏失败：$error';
  }

  @override
  String get wallTipNoWallet => '该用户的个人资料中没有钱包地址';

  @override
  String get wallTipInsufficientBalance => 'CPUNK余额不足';

  @override
  String get wallTipSending => '正在发送打赏...';

  @override
  String wallTippedAmount(String amount) {
    return '已打赏 $amount CPUNK';
  }

  @override
  String get wallTipPending => '待处理';

  @override
  String get wallTipVerified => '已验证';

  @override
  String get wallTipFailedStatus => '失败';

  @override
  String get wallWhatsOnYourMind => '你在想什么？';

  @override
  String get wallPost => '发布';

  @override
  String get wallPosting => '发布中...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => '推广';

  @override
  String get wallBoostDescription => '分享给所有人';

  @override
  String get wallBoosted => '已推广';

  @override
  String get wallBoostLimitReached => '已达每日推广上限';

  @override
  String get wallAddComment => '添加评论（可选）';

  @override
  String get wallCreatePostTitle => '创建帖子';

  @override
  String get walletTitle => '钱包';

  @override
  String get walletTotalBalance => '总余额';

  @override
  String get walletSend => '发送';

  @override
  String get walletReceive => '接收';

  @override
  String get walletHistory => '历史';

  @override
  String get walletNoTransactions => '暂无交易记录';

  @override
  String get walletCopyAddress => '复制地址';

  @override
  String get walletAddressCopied => '地址已复制';

  @override
  String walletSendTitle(String coin) {
    return '发送 $coin';
  }

  @override
  String get walletRecipientAddress => '收款地址';

  @override
  String get walletAmount => '金额';

  @override
  String get walletMax => '最大';

  @override
  String get walletSendConfirm => '确认发送';

  @override
  String get walletSending => '发送中...';

  @override
  String get walletSendSuccess => '交易已发送';

  @override
  String walletSendFailed(String error) {
    return '交易失败：$error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return '接收 $coin';
  }

  @override
  String get walletAddressBook => '地址簿';

  @override
  String get walletAddAddress => '添加地址';

  @override
  String get walletEditAddress => '编辑地址';

  @override
  String get walletDeleteAddress => '删除地址';

  @override
  String get walletLabel => '标签';

  @override
  String get walletAddress => '地址';

  @override
  String get walletNetwork => '网络';

  @override
  String get walletAllChains => '全部';

  @override
  String get walletAssets => '资产';

  @override
  String get walletPortfolio => '投资组合';

  @override
  String get walletMyWallet => '我的钱包';

  @override
  String get walletTxToday => '今天';

  @override
  String get walletTxYesterday => '昨天';

  @override
  String get walletTxThisWeek => '本周';

  @override
  String get walletTxEarlier => '更早';

  @override
  String get walletNoNonZeroBalances => '无有余额的资产';

  @override
  String get walletNoBalances => '无余额';

  @override
  String get qrScannerTitle => 'QR 扫描仪';

  @override
  String get qrAddContact => '添加联系人';

  @override
  String get qrAuthRequest => '授权请求';

  @override
  String get qrContent => 'QR 内容';

  @override
  String get qrSendContactRequest => '发送联系人请求';

  @override
  String get qrScanAnother => '再扫一个';

  @override
  String get qrCopyFingerprint => '复制';

  @override
  String get qrRequestSent => '联系人请求已发送';

  @override
  String get qrInvalidCode => '无效的 QR 码';

  @override
  String get moreTitle => '更多';

  @override
  String get moreWallet => '钱包';

  @override
  String get moreQRScanner => 'QR 扫描仪';

  @override
  String get moreAddresses => '地址';

  @override
  String get moreStarred => '已收藏';

  @override
  String get moreContacts => '联系人';

  @override
  String get moreSettings => '设置';

  @override
  String get moreAppLock => '应用锁';

  @override
  String get moreInviteFriends => '邀请好友';

  @override
  String inviteFriendsMessage(String username) {
    return '嗨！试试 DNA Connect — 量子安全加密通讯工具。添加我：$username — 下载：https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => '输入 PIN 解锁';

  @override
  String get lockIncorrectPIN => 'PIN 不正确';

  @override
  String lockTooManyAttempts(int seconds) {
    return '尝试次数过多。请在 $seconds 秒后重试';
  }

  @override
  String get lockUseBiometrics => '使用生物识别解锁';

  @override
  String get appLockTitle => '应用锁';

  @override
  String get appLockEnable => '启用应用锁';

  @override
  String get appLockUseBiometrics => '使用生物识别';

  @override
  String get appLockChangePIN => '更改 PIN';

  @override
  String get appLockSetPIN => '设置 PIN';

  @override
  String get appLockConfirmPIN => '确认 PIN';

  @override
  String get appLockPINMismatch => 'PIN 不匹配';

  @override
  String get appLockPINSet => 'PIN 设置成功';

  @override
  String get appLockPINChanged => 'PIN 已更改';

  @override
  String get appLockEnterCurrentPIN => '输入当前 PIN';

  @override
  String get appLockEnterNewPIN => '输入新 PIN';

  @override
  String get starredTitle => '已收藏消息';

  @override
  String get starredEmpty => '没有收藏的消息';

  @override
  String get blockedTitle => '已屏蔽用户';

  @override
  String get blockedEmpty => '没有已屏蔽的用户';

  @override
  String get blockedUnblock => '解除屏蔽';

  @override
  String blockedUnblockConfirm(String name) {
    return '解除屏蔽 $name？';
  }

  @override
  String get updateTitle => '需要更新';

  @override
  String get updateMessage => '需要较新版本才能继续使用 DNA Connect。';

  @override
  String get updateDownload => '下载更新';

  @override
  String get updateAvailableTitle => '有新版本可用';

  @override
  String get updateAvailableMessage => 'DNA Connect 有新版本可用。立即更新以获取最新功能和改进。';

  @override
  String get updateLater => '稍后';

  @override
  String get cancel => '取消';

  @override
  String get save => '保存';

  @override
  String get delete => '删除';

  @override
  String get done => '完成';

  @override
  String get copy => '复制';

  @override
  String get ok => '确定';

  @override
  String get yes => '是';

  @override
  String get no => '否';

  @override
  String get error => '错误';

  @override
  String get success => '成功';

  @override
  String get loading => '加载中...';

  @override
  String get pleaseWait => '请稍候...';

  @override
  String get copied => '已复制';

  @override
  String failed(String error) {
    return '失败：$error';
  }

  @override
  String get retry => '重试';

  @override
  String get continueButton => '继续';

  @override
  String get approve => '批准';

  @override
  String get deny => '拒绝';

  @override
  String get verify => '验证';

  @override
  String get copyToClipboard => '复制到剪贴板';

  @override
  String get copiedToClipboard => '已复制到剪贴板';

  @override
  String get pasteFromClipboard => '从剪贴板粘贴';

  @override
  String get biometricsSubtitle => '指纹或面部识别';

  @override
  String get changePINSubtitle => '更新您的解锁 PIN';

  @override
  String get biometricFailed => '生物识别验证失败';

  @override
  String get contactRequestsWillAppear => '联系人请求将显示在此处';

  @override
  String get blockedUsersWillAppear => '您屏蔽的用户将显示在此处';

  @override
  String get failedToLoadTimeline => '加载时间线失败';

  @override
  String get userUnblocked => '用户已解除屏蔽';

  @override
  String get backupFound => '找到备份';

  @override
  String approvedContact(String name) {
    return '已批准 $name';
  }

  @override
  String deniedContact(String name) {
    return '已拒绝 $name';
  }

  @override
  String blockedContact(String name) {
    return '已屏蔽 $name';
  }

  @override
  String unsubscribeFrom(String name) {
    return '取消订阅 $name';
  }

  @override
  String get chatSenderDeletedThis => '发送者已删除此消息';

  @override
  String get chatDeleteMessageTitle => '删除消息';

  @override
  String get chatDeleteMessageConfirm => '从您的所有设备删除此消息并通知对方？';

  @override
  String get chatViewProfile => 'View Profile';

  @override
  String get chatSyncMessages => 'Sync Messages';

  @override
  String get chatDeleteConversation => '删除对话';

  @override
  String get chatDeleteConversationTitle => '删除对话';

  @override
  String get chatDeleteConversationConfirm => '删除此对话中的所有消息？这将从您的所有设备中删除。';

  @override
  String get chatConversationDeleted => '对话已删除';

  @override
  String get chatDeleteConversationFailed => '删除对话失败';

  @override
  String get settingsDeleteAllMessages => '删除所有消息';

  @override
  String get settingsDeleteAllMessagesSubtitle => '从所有设备中删除所有消息';

  @override
  String get settingsDeleteAllMessagesTitle => '删除所有消息？';

  @override
  String get settingsDeleteAllMessagesWarning =>
      '这将永久删除所有对话中的所有消息，包括您所有设备上的消息。此操作无法撤销。';

  @override
  String get settingsAllMessagesDeleted => '所有消息已删除';

  @override
  String get settingsDeleteAllMessagesFailed => '删除消息失败';

  @override
  String get settingsDeleteEverything => '删除所有内容';

  @override
  String get settingsGeneral => '通用';

  @override
  String get settingsDataStorage => '数据与存储';

  @override
  String get settingsAccount => '账户';

  @override
  String get settingsClearCache => '清除缓存';

  @override
  String get settingsClearCacheSubtitle => '删除已下载的媒体和缓存数据';

  @override
  String settingsCacheSize(String size) {
    return '本地缓存：$size';
  }

  @override
  String get settingsClearCacheConfirm => '清除缓存？';

  @override
  String get settingsClearCacheWarning => '这将删除所有缓存的媒体文件（图片、视频、音频）。需要时会重新下载。';

  @override
  String get settingsCacheCleared => '缓存已清除';

  @override
  String get settingsClearCacheButton => '清除';

  @override
  String get txDetailSent => '已发送';

  @override
  String get txDetailReceived => '已接收';

  @override
  String get txDetailDenied => '交易被拒绝';

  @override
  String get txDetailFrom => '发件人';

  @override
  String get txDetailTo => '收件人';

  @override
  String get txDetailTransactionHash => '交易哈希';

  @override
  String get txDetailTime => '时间';

  @override
  String get txDetailNetwork => '网络';

  @override
  String get txDetailAddressCopied => '地址已复制';

  @override
  String get txDetailHashCopied => '哈希已复制';

  @override
  String get txDetailAddToAddressBook => '添加到地址簿';

  @override
  String get txDetailClose => '关闭';

  @override
  String txDetailAddedToAddressBook(String label) {
    return '已将\"$label\"添加到地址簿';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return '添加失败：$error';
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
  String get chatRecordingRelease => '松开停止';

  @override
  String get chatRecordingTap => '点击录音';

  @override
  String get chatRecordingInProgress => '录音中...';

  @override
  String get chatRecordingListening => '播放中...';

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
