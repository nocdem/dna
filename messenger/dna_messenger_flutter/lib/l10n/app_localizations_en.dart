// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Initializing...';

  @override
  String get failedToInitialize => 'Failed to initialize';

  @override
  String get makeSureNativeLibrary =>
      'Make sure the native library is available.';

  @override
  String get navHome => 'Home';

  @override
  String get navChats => 'Chats';

  @override
  String get navChannels => 'Channels';

  @override
  String get navMore => 'More';

  @override
  String get messagesAll => 'All';

  @override
  String get messagesUnread => 'Unread';

  @override
  String get messagesAllCaughtUp => 'All caught up!';

  @override
  String get messagesNoUnread => 'No unread messages';

  @override
  String get messagesSearchHint => 'Search chats...';

  @override
  String get contactsTitle => 'Contacts';

  @override
  String get contactsEmpty => 'No contacts yet';

  @override
  String get contactsTapToAdd => 'Tap + to add a contact';

  @override
  String get contactsOnline => 'Online';

  @override
  String contactsLastSeen(String time) {
    return 'Last seen $time';
  }

  @override
  String get contactsOffline => 'Offline';

  @override
  String get contactsSyncing => 'Syncing...';

  @override
  String get contactsFailedToLoad => 'Failed to load contacts';

  @override
  String get contactsRetry => 'Retry';

  @override
  String get contactsHubContacts => 'Contacts';

  @override
  String get contactsHubRequests => 'Requests';

  @override
  String get contactsHubBlocked => 'Blocked';

  @override
  String get contactsHubRemoveTitle => 'Remove Contact?';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'Are you sure you want to remove $name from your contacts?';
  }

  @override
  String get contactsHubRemove => 'Remove';

  @override
  String get contactsHubFingerprintCopied => 'Fingerprint copied';

  @override
  String get contactRequestsTitle => 'Contact Requests';

  @override
  String get contactRequestsEmpty => 'No pending requests';

  @override
  String get contactRequestsAccept => 'Accept';

  @override
  String get contactRequestsDeny => 'Deny';

  @override
  String get contactRequestsBlock => 'Block User';

  @override
  String get contactRequestsSent => 'Sent';

  @override
  String get contactRequestsReceived => 'Received';

  @override
  String get addContactTitle => 'Add Contact';

  @override
  String get addContactHint => 'Enter a name or ID';

  @override
  String get addContactSearching => 'Searching...';

  @override
  String get addContactFoundOnNetwork => 'Found on network';

  @override
  String get addContactNotFound => 'Not found';

  @override
  String get addContactSendRequest => 'Send Request';

  @override
  String get addContactRequestSent => 'Contact request sent';

  @override
  String get addContactAlreadyContact => 'Already in your contacts';

  @override
  String get addContactCannotAddSelf => 'You cannot add yourself';

  @override
  String get chatSearchMessages => 'Search messages';

  @override
  String get chatOnline => 'Online';

  @override
  String get chatOffline => 'Offline';

  @override
  String get chatConnecting => 'Connecting...';

  @override
  String get chatTypeMessage => 'Type a message';

  @override
  String get chatNoMessages => 'No messages yet';

  @override
  String get chatSendFirstMessage => 'Send a message to start the conversation';

  @override
  String get chatPhotoLibrary => 'Photo Library';

  @override
  String get chatCamera => 'Camera';

  @override
  String get chatAddCaption => 'Add Caption...';

  @override
  String get chatSendPhoto => 'Send';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Image too large (max $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Message deleted';

  @override
  String get chatLoadEarlier => 'Load earlier messages';

  @override
  String chatLastSeen(String time) {
    return 'Last seen $time';
  }

  @override
  String get chatSendTokens => 'Send Tokens';

  @override
  String chatSendTokensTo(String name) {
    return 'to $name';
  }

  @override
  String get chatLookingUpWallets => 'Looking up wallet addresses...';

  @override
  String get chatNoWalletAddresses =>
      'Contact has no wallet addresses in their profile';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Amount';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Available: $balance $token';
  }

  @override
  String get chatSendMax => 'Max';

  @override
  String chatSendButton(String token) {
    return 'Send $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return 'Sent $amount $token';
  }

  @override
  String get chatInvalidAmount => 'Please enter a valid amount';

  @override
  String chatInsufficientBalance(String token) {
    return 'Insufficient $token balance';
  }

  @override
  String get chatNoWalletForNetwork => 'Contact has no wallet for this network';

  @override
  String get chatSelectToken => 'Select Token';

  @override
  String get chatSelectNetwork => 'Select Network';

  @override
  String get chatEnterAmount => 'Enter Amount';

  @override
  String chatStepOf(String current, String total) {
    return 'Step $current of $total';
  }

  @override
  String get messageMenuReply => 'Reply';

  @override
  String get messageMenuCopy => 'Copy';

  @override
  String get messageMenuForward => 'Forward';

  @override
  String get messageMenuStar => 'Star';

  @override
  String get messageMenuUnstar => 'Unstar';

  @override
  String get messageMenuRetry => 'Retry';

  @override
  String get messageMenuDelete => 'Delete';

  @override
  String get channelsTitle => 'Channels';

  @override
  String get channelsEmpty => 'No channels yet';

  @override
  String get channelsCreateOrDiscover => 'Create or discover channels';

  @override
  String get channelsCreate => 'Create Channel';

  @override
  String get channelsDiscover => 'Discover Channels';

  @override
  String get channelName => 'Channel Name';

  @override
  String get channelDescription => 'Description';

  @override
  String get channelListPublicly => 'List publicly';

  @override
  String get channelListPubliclyHint => 'Allow others to discover this channel';

  @override
  String get channelSubscribe => 'Subscribe';

  @override
  String get channelSubscribed => 'Subscribed';

  @override
  String get channelUnsubscribe => 'Unsubscribe';

  @override
  String get channelWritePost => 'Write a post...';

  @override
  String get channelNoPosts => 'No posts yet';

  @override
  String get channelLoadOlderPosts => 'Load older posts';

  @override
  String get channelSearchChannels => 'Search channels...';

  @override
  String get channelNoPublicChannels => 'No public channels found';

  @override
  String get channelCreated => 'Channel created';

  @override
  String get channelReply => 'Reply';

  @override
  String get channelCopy => 'Copy';

  @override
  String get groupsTitle => 'Groups';

  @override
  String get groupsCreate => 'Create Group';

  @override
  String get groupsEmpty => 'No groups yet';

  @override
  String get groupsCreateOrJoin => 'Create a group or accept an invitation';

  @override
  String get groupsPendingInvitations => 'Pending Invitations';

  @override
  String get groupsYourGroups => 'Your Groups';

  @override
  String get groupsInfo => 'Group Info';

  @override
  String get groupsMembers => 'Members';

  @override
  String get groupsLeave => 'Leave Group';

  @override
  String get groupsDelete => 'Delete Group';

  @override
  String get groupsInvite => 'Invite';

  @override
  String get groupsAccept => 'Accept';

  @override
  String get groupsDecline => 'Decline';

  @override
  String get groupsName => 'Group Name';

  @override
  String get groupsDescription => 'Description';

  @override
  String get groupsCreated => 'Group created';

  @override
  String get groupsOwner => 'Owner';

  @override
  String get groupsMember => 'Member';

  @override
  String get groupsAdmin => 'Admin';

  @override
  String get groupsRemoveMember => 'Remove Member';

  @override
  String groupsKickConfirm(String name) {
    return 'Remove $name from the group?';
  }

  @override
  String get settingsTitle => 'Settings';

  @override
  String get settingsAnonymous => 'Anonymous';

  @override
  String get settingsNotLoaded => 'Not loaded';

  @override
  String get settingsTapToEditProfile => 'Tap to edit profile';

  @override
  String get settingsAppearance => 'Appearance';

  @override
  String get settingsDarkMode => 'Dark Mode';

  @override
  String get settingsDarkModeSubtitle => 'Switch between dark and light theme';

  @override
  String get settingsLanguage => 'Language';

  @override
  String get settingsLanguageSubtitle => 'Choose app language';

  @override
  String get settingsLanguageSystem => 'System default';

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
  String get settingsBattery => 'Battery';

  @override
  String get settingsDisableBatteryOpt => 'Disable Battery Optimization';

  @override
  String get settingsBatteryChecking => 'Checking...';

  @override
  String get settingsBatteryDisabled => 'Disabled — app can run in background';

  @override
  String get settingsBatteryTapToKeep => 'Tap to keep app alive in background';

  @override
  String get settingsSecurity => 'Security';

  @override
  String get settingsExportSeedPhrase => 'Export Seed Phrase';

  @override
  String get settingsExportSeedSubtitle => 'Back up your recovery phrase';

  @override
  String get settingsAppLock => 'App Lock';

  @override
  String get settingsAppLockSubtitle => 'Require authentication';

  @override
  String get settingsExportSeedWarning =>
      'Your seed phrase gives full access to your identity. Never share it with anyone.';

  @override
  String get settingsShowSeed => 'Show Seed';

  @override
  String get settingsYourSeedPhrase => 'Your Seed Phrase';

  @override
  String get settingsSeedPhraseWarning =>
      'Write these words down in order and store them safely. Anyone with this phrase can access your identity.';

  @override
  String get settingsSeedCopied => 'Seed phrase copied to clipboard';

  @override
  String get settingsSeedNotAvailable =>
      'Seed phrase not available for this identity. It was created before this feature was added.';

  @override
  String get settingsSeedError => 'Unable to retrieve seed phrase';

  @override
  String get settingsWallet => 'Wallet';

  @override
  String get settingsHideZeroBalance => 'Hide 0 Balance';

  @override
  String get settingsHideZeroBalanceSubtitle => 'Hide coins with zero balance';

  @override
  String get settingsData => 'Data';

  @override
  String get settingsAutoSync => 'Auto Sync';

  @override
  String get settingsAutoSyncSubtitle =>
      'Sync messages automatically every 15 minutes';

  @override
  String settingsLastSync(String time) {
    return 'Last sync: $time';
  }

  @override
  String get settingsSyncNow => 'Sync Now';

  @override
  String get settingsSyncNowSubtitle => 'Force immediate sync';

  @override
  String get settingsLogs => 'Logs';

  @override
  String get settingsOpenLogsFolder => 'Open Logs Folder';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Open file manager at logs directory';

  @override
  String get settingsShareLogs => 'Share Logs';

  @override
  String get settingsShareLogsSubtitle => 'Zip and share log files';

  @override
  String get settingsLogsFolderNotExist => 'Logs folder does not exist yet';

  @override
  String get settingsNoLogFiles => 'No log files found';

  @override
  String get settingsFailedCreateZip => 'Failed to create zip archive';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'No logs yet. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Identity';

  @override
  String get settingsFingerprint => 'Fingerprint';

  @override
  String get settingsFingerprintCopied => 'Fingerprint copied';

  @override
  String get settingsDeleteAccount => 'Delete Account';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Permanently delete all data from device';

  @override
  String get settingsDeleteAccountConfirm => 'Delete Account?';

  @override
  String get settingsDeleteAccountWarning =>
      'This will permanently delete all local data:';

  @override
  String get settingsDeletePrivateKeys => 'Private keys';

  @override
  String get settingsDeleteWallets => 'Wallets';

  @override
  String get settingsDeleteMessages => 'Messages';

  @override
  String get settingsDeleteContacts => 'Contacts';

  @override
  String get settingsDeleteGroups => 'Groups';

  @override
  String get settingsDeleteSeedWarning =>
      'Make sure you have backed up your seed phrase before deleting!';

  @override
  String get settingsDeleteSuccess => 'Account deleted successfully';

  @override
  String settingsDeleteFailed(String error) {
    return 'Failed to delete account: $error';
  }

  @override
  String get settingsAbout => 'About';

  @override
  String get settingsUpdateAvailable => 'Update Available';

  @override
  String get settingsTapToDownload => 'Tap to download';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Library v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Post-Quantum Encrypted Communication';

  @override
  String get settingsCryptoStack => 'CRYPTO STACK';

  @override
  String get profileTitle => 'Edit Profile';

  @override
  String get profileInfo => 'Profile Info';

  @override
  String get profileBio => 'Bio';

  @override
  String get profileLocation => 'Location';

  @override
  String get profileWebsite => 'Website';

  @override
  String get profileWalletAddresses => 'Wallet Addresses';

  @override
  String get profileSave => 'Save Profile';

  @override
  String get profileShareQR => 'Share My QR Code';

  @override
  String get profileAvatar => 'Avatar';

  @override
  String get profileTakeSelfie => 'Take a Selfie';

  @override
  String get profileChooseFromGallery => 'Choose from Gallery';

  @override
  String get profileSaved => 'Profile saved';

  @override
  String profileSaveFailed(String error) {
    return 'Failed to save profile: $error';
  }

  @override
  String get profileCropTitle => 'Crop Avatar';

  @override
  String get profileCropSave => 'Save';

  @override
  String get contactProfileFailed => 'Failed to load profile';

  @override
  String get contactProfileUnknownError => 'Unknown error';

  @override
  String get contactProfileNickname => 'Nickname';

  @override
  String get contactProfileNicknameNotSet => 'Not set (tap to add)';

  @override
  String contactProfileOriginal(String name) {
    return 'Original: $name';
  }

  @override
  String get contactProfileSetNickname => 'Set Nickname';

  @override
  String contactProfileOriginalName(String name) {
    return 'Original name: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Nickname';

  @override
  String get contactProfileNicknameHint => 'Enter custom nickname';

  @override
  String get contactProfileNicknameHelper => 'Leave empty to use original name';

  @override
  String get contactProfileNicknameCleared => 'Nickname cleared';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Nickname set to \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Failed to set nickname: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Copy fingerprint';

  @override
  String get contactProfileNoProfile => 'No profile published';

  @override
  String get contactProfileNoProfileSubtitle =>
      'This user has not published their profile yet.';

  @override
  String get contactProfileBio => 'Bio';

  @override
  String get contactProfileInfo => 'Info';

  @override
  String get contactProfileWebsite => 'Website';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Welcome to DNA Connect';

  @override
  String get identityGenerateSeed => 'Generate New Seed';

  @override
  String get identityHaveSeed => 'I Have a Seed Phrase';

  @override
  String get identityYourRecoveryPhrase => 'Your Recovery Phrase';

  @override
  String get identityRecoveryPhraseWarning =>
      'Write down these words and keep them safe. They are the only way to recover your account.';

  @override
  String get identityConfirmSaved => 'I have saved my recovery phrase';

  @override
  String get identityEnterRecoveryPhrase => 'Enter Recovery Phrase';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Enter your 12 or 24 word recovery phrase';

  @override
  String get identityChooseName => 'Choose Your Name';

  @override
  String get identityChooseNameHint => 'Enter a display name';

  @override
  String get identityRegisterContinue => 'Register & Continue';

  @override
  String get identityRegistering => 'Registering...';

  @override
  String get identityNameTaken => 'This name is already taken';

  @override
  String get identityNameInvalid => 'Name must be 3-20 characters';

  @override
  String get identityCreating => 'Creating your identity...';

  @override
  String get identityRestoring => 'Restoring your identity...';

  @override
  String get wallTitle => 'Home';

  @override
  String get wallWelcome => 'Welcome to your timeline!';

  @override
  String get wallWelcomeSubtitle =>
      'Follow people and channels to see their posts here.';

  @override
  String get wallNewPost => 'New Post';

  @override
  String get wallDeletePost => 'Delete Post';

  @override
  String get wallDeletePostConfirm =>
      'Are you sure you want to delete this post?';

  @override
  String get wallRepost => 'Repost';

  @override
  String get wallReposted => 'Reposted';

  @override
  String get wallComments => 'Comments';

  @override
  String get wallNoComments => 'No comments yet';

  @override
  String get wallLoadingComments => 'Loading comments...';

  @override
  String get wallWriteComment => 'Write a comment...';

  @override
  String get wallWriteReply => 'Write a reply...';

  @override
  String wallViewAllComments(int count) {
    return 'View all $count comments';
  }

  @override
  String get wallPostDetail => 'Post';

  @override
  String get wallCopy => 'Copy';

  @override
  String get wallReply => 'Reply';

  @override
  String get wallDelete => 'Delete';

  @override
  String get walletTitle => 'Wallet';

  @override
  String get walletTotalBalance => 'Total Balance';

  @override
  String get walletSend => 'Send';

  @override
  String get walletReceive => 'Receive';

  @override
  String get walletSwap => 'Swap';

  @override
  String get walletHistory => 'History';

  @override
  String get walletNoTransactions => 'No transactions yet';

  @override
  String get walletCopyAddress => 'Copy Address';

  @override
  String get walletAddressCopied => 'Address copied';

  @override
  String walletSendTitle(String coin) {
    return 'Send $coin';
  }

  @override
  String get walletRecipientAddress => 'Recipient Address';

  @override
  String get walletAmount => 'Amount';

  @override
  String get walletMax => 'MAX';

  @override
  String get walletSendConfirm => 'Confirm Send';

  @override
  String get walletSending => 'Sending...';

  @override
  String get walletSendSuccess => 'Transaction sent';

  @override
  String walletSendFailed(String error) {
    return 'Transaction failed: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return 'Receive $coin';
  }

  @override
  String get walletAddressBook => 'Address Book';

  @override
  String get walletAddAddress => 'Add Address';

  @override
  String get walletEditAddress => 'Edit Address';

  @override
  String get walletDeleteAddress => 'Delete Address';

  @override
  String get walletLabel => 'Label';

  @override
  String get walletAddress => 'Address';

  @override
  String get walletNetwork => 'Network';

  @override
  String get qrScannerTitle => 'QR Scanner';

  @override
  String get qrAddContact => 'Add Contact';

  @override
  String get qrAuthRequest => 'Authorization Request';

  @override
  String get qrContent => 'QR Content';

  @override
  String get qrSendContactRequest => 'Send Contact Request';

  @override
  String get qrScanAnother => 'Scan Another';

  @override
  String get qrCopyFingerprint => 'Copy';

  @override
  String get qrRequestSent => 'Contact request sent';

  @override
  String get qrInvalidCode => 'Invalid QR code';

  @override
  String get moreTitle => 'More';

  @override
  String get moreWallet => 'Wallet';

  @override
  String get moreQRScanner => 'QR Scanner';

  @override
  String get moreAddresses => 'Addresses';

  @override
  String get moreStarred => 'Starred';

  @override
  String get moreContacts => 'Contacts';

  @override
  String get moreSettings => 'Settings';

  @override
  String get moreAppLock => 'App Lock';

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Enter PIN to unlock';

  @override
  String get lockIncorrectPIN => 'Incorrect PIN';

  @override
  String get lockUseBiometrics => 'Use biometrics to unlock';

  @override
  String get appLockTitle => 'App Lock';

  @override
  String get appLockEnable => 'Enable App Lock';

  @override
  String get appLockUseBiometrics => 'Use Biometrics';

  @override
  String get appLockChangePIN => 'Change PIN';

  @override
  String get appLockSetPIN => 'Set PIN';

  @override
  String get appLockConfirmPIN => 'Confirm PIN';

  @override
  String get appLockPINMismatch => 'PINs do not match';

  @override
  String get appLockPINSet => 'PIN set successfully';

  @override
  String get appLockPINChanged => 'PIN changed';

  @override
  String get appLockEnterCurrentPIN => 'Enter current PIN';

  @override
  String get appLockEnterNewPIN => 'Enter new PIN';

  @override
  String get starredTitle => 'Starred Messages';

  @override
  String get starredEmpty => 'No starred messages';

  @override
  String get blockedTitle => 'Blocked Users';

  @override
  String get blockedEmpty => 'No blocked users';

  @override
  String get blockedUnblock => 'Unblock';

  @override
  String blockedUnblockConfirm(String name) {
    return 'Unblock $name?';
  }

  @override
  String get updateTitle => 'Update Required';

  @override
  String get updateMessage =>
      'A newer version is required to continue using DNA Connect.';

  @override
  String get updateDownload => 'Download Update';

  @override
  String get updateAvailableTitle => 'New Version Available';

  @override
  String get updateAvailableMessage =>
      'A new version of DNA Connect is available. Update now for the latest features and improvements.';

  @override
  String get updateLater => 'Later';

  @override
  String get cancel => 'Cancel';

  @override
  String get save => 'Save';

  @override
  String get delete => 'Delete';

  @override
  String get done => 'Done';

  @override
  String get copy => 'Copy';

  @override
  String get ok => 'OK';

  @override
  String get yes => 'Yes';

  @override
  String get no => 'No';

  @override
  String get error => 'Error';

  @override
  String get success => 'Success';

  @override
  String get loading => 'Loading...';

  @override
  String get pleaseWait => 'Please wait...';

  @override
  String get copied => 'Copied';

  @override
  String failed(String error) {
    return 'Failed: $error';
  }

  @override
  String get retry => 'Retry';

  @override
  String get continueButton => 'Continue';

  @override
  String get approve => 'Approve';

  @override
  String get deny => 'Deny';

  @override
  String get verify => 'Verify';

  @override
  String get copyToClipboard => 'Copy to Clipboard';

  @override
  String get copiedToClipboard => 'Copied to clipboard';

  @override
  String get pasteFromClipboard => 'Paste from Clipboard';

  @override
  String get biometricsSubtitle => 'Fingerprint or Face ID';

  @override
  String get changePINSubtitle => 'Update your unlock PIN';

  @override
  String get biometricFailed => 'Biometric authentication failed';

  @override
  String get contactRequestsWillAppear => 'Contact requests will appear here';

  @override
  String get blockedUsersWillAppear => 'Users you block will appear here';

  @override
  String get failedToLoadTimeline => 'Failed to load timeline';

  @override
  String get userUnblocked => 'User unblocked';

  @override
  String get backupFound => 'Backup Found';

  @override
  String approvedContact(String name) {
    return 'Approved $name';
  }

  @override
  String deniedContact(String name) {
    return 'Denied $name';
  }

  @override
  String blockedContact(String name) {
    return 'Blocked $name';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Unsubscribe from $name';
  }

  @override
  String get chatSenderDeletedThis => 'Sender deleted this';

  @override
  String get chatDeleteMessageTitle => 'Delete Message';

  @override
  String get chatDeleteMessageConfirm =>
      'Delete this message from all your devices and notify the other person?';

  @override
  String get chatDeleteConversation => 'Delete Conversation';

  @override
  String get chatDeleteConversationTitle => 'Delete Conversation';

  @override
  String get chatDeleteConversationConfirm =>
      'Delete all messages in this conversation? This will delete from all your devices.';

  @override
  String get chatConversationDeleted => 'Conversation deleted';

  @override
  String get chatDeleteConversationFailed => 'Failed to delete conversation';

  @override
  String get settingsDeleteAllMessages => 'Delete All Messages';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Remove all messages from all devices';

  @override
  String get settingsDeleteAllMessagesTitle => 'Delete All Messages?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'This will permanently delete ALL messages from ALL conversations across all your devices. This cannot be undone.';

  @override
  String get settingsAllMessagesDeleted => 'All messages deleted';

  @override
  String get settingsDeleteAllMessagesFailed => 'Failed to delete messages';

  @override
  String get settingsDeleteEverything => 'Delete Everything';

  @override
  String get txDetailSent => 'Sent';

  @override
  String get txDetailReceived => 'Received';

  @override
  String get txDetailDenied => 'Transaction Denied';

  @override
  String get txDetailFrom => 'From';

  @override
  String get txDetailTo => 'To';

  @override
  String get txDetailTransactionHash => 'Transaction Hash';

  @override
  String get txDetailTime => 'Time';

  @override
  String get txDetailNetwork => 'Network';

  @override
  String get txDetailAddressCopied => 'Address copied';

  @override
  String get txDetailHashCopied => 'Hash copied';

  @override
  String get txDetailAddToAddressBook => 'Add to Address Book';

  @override
  String get txDetailClose => 'Close';

  @override
  String txDetailAddedToAddressBook(String label) {
    return 'Added \"$label\" to address book';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Failed to add: $error';
  }

  @override
  String get swapTitle => 'Swap';

  @override
  String get swapConfirm => 'Confirm Swap';

  @override
  String get swapYouPay => 'You pay';

  @override
  String get swapYouReceive => 'You receive';

  @override
  String get swapGetQuote => 'Get Quote';

  @override
  String get swapNoQuotes => 'No quotes available';

  @override
  String get swapRate => 'Rate';

  @override
  String get swapSlippage => 'Slippage';

  @override
  String get swapFee => 'Fee';

  @override
  String get swapDex => 'DEX';

  @override
  String swapImpact(String value) {
    return 'Impact: $value%';
  }

  @override
  String swapFeeValue(String value) {
    return 'Fee: $value';
  }

  @override
  String swapBestPrice(int count) {
    return 'Best price from $count exchanges';
  }

  @override
  String swapSuccess(
    String amountIn,
    String fromToken,
    String amountOut,
    String toToken,
    String dex,
  ) {
    return 'Swapped $amountIn $fromToken → $amountOut $toToken via $dex';
  }

  @override
  String swapFailed(String error) {
    return 'Swap failed: $error';
  }
}
