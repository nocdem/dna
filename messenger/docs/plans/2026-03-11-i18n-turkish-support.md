# i18n Infrastructure + Turkish Language Support — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Flutter gen-l10n based i18n infrastructure with English (source) + Turkish, allowing easy future language additions.

**Architecture:** Flutter gen-l10n generates type-safe `AppLocalizations` class from `.arb` files. A Riverpod `localeProvider` persists user's language choice via SharedPreferences. MaterialApp receives locale + delegates. All ~35 screen files replace hardcoded strings with `AppLocalizations.of(context).key` calls.

**Tech Stack:** Flutter gen-l10n, flutter_localizations SDK, intl (already in pubspec), SharedPreferences (already in pubspec), Riverpod StateNotifier

**Design Doc:** `messenger/docs/plans/2026-03-11-i18n-turkish-support-design.md`

---

## Task 1: Infrastructure Setup (pubspec.yaml, l10n.yaml)

**Files:**
- Modify: `messenger/dna_messenger_flutter/pubspec.yaml`
- Create: `messenger/dna_messenger_flutter/l10n.yaml`

**Step 1: Add flutter_localizations dependency to pubspec.yaml**

Add under the `flutter` SDK dependency:

```yaml
  flutter_localizations:
    sdk: flutter
```

Also add `generate: true` under the `flutter:` section.

**Step 2: Create l10n.yaml in project root**

```yaml
arb-dir: lib/l10n
template-arb-file: app_en.arb
output-localization-file: app_localizations.dart
output-class: AppLocalizations
nullable-getter: false
```

**Step 3: Run `flutter pub get`**

Run: `cd messenger/dna_messenger_flutter && flutter pub get`
Expected: Dependencies resolve successfully.

**Step 4: Commit**

```bash
git add pubspec.yaml l10n.yaml
git commit -m "feat(i18n): add flutter_localizations + l10n.yaml config"
```

---

## Task 2: Create English ARB Source File (app_en.arb)

**Files:**
- Create: `messenger/dna_messenger_flutter/lib/l10n/app_en.arb`

**Step 1: Create lib/l10n/ directory and app_en.arb**

This is the master English string file. All keys are camelCase. Grouped by screen/domain with comments.

```json
{
  "@@locale": "en",

  "_comment_app": "=== App-level ===",
  "appTitle": "DNA Messenger",
  "initializing": "Initializing...",
  "failedToInitialize": "Failed to initialize",
  "makeSureNativeLibrary": "Make sure the native library is available.",

  "_comment_nav": "=== Navigation (home_screen bottom bar) ===",
  "navHome": "Home",
  "navChats": "Chats",
  "navChannels": "Channels",
  "navMore": "More",

  "_comment_messages": "=== Messages Screen ===",
  "messagesAll": "All",
  "messagesUnread": "Unread",
  "messagesAllCaughtUp": "All caught up!",
  "messagesNoUnread": "No unread messages",
  "messagesSearchHint": "Search chats...",

  "_comment_contacts": "=== Contacts ===",
  "contactsTitle": "Contacts",
  "contactsEmpty": "No contacts yet",
  "contactsTapToAdd": "Tap + to add a contact",
  "contactsOnline": "Online",
  "contactsLastSeen": "Last seen {time}",
  "@contactsLastSeen": {
    "placeholders": {
      "time": { "type": "String" }
    }
  },
  "contactsOffline": "Offline",
  "contactsSyncing": "Syncing...",
  "contactsFailedToLoad": "Failed to load contacts",
  "contactsRetry": "Retry",

  "_comment_contacts_hub": "=== Contacts Hub ===",
  "contactsHubContacts": "Contacts",
  "contactsHubRequests": "Requests",
  "contactsHubBlocked": "Blocked",
  "contactsHubRemoveTitle": "Remove Contact?",
  "contactsHubRemoveMessage": "Are you sure you want to remove {name} from your contacts?",
  "@contactsHubRemoveMessage": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },
  "contactsHubRemove": "Remove",
  "contactsHubFingerprintCopied": "Fingerprint copied",

  "_comment_contact_requests": "=== Contact Requests ===",
  "contactRequestsTitle": "Contact Requests",
  "contactRequestsEmpty": "No pending requests",
  "contactRequestsAccept": "Accept",
  "contactRequestsDeny": "Deny",
  "contactRequestsBlock": "Block User",
  "contactRequestsSent": "Sent",
  "contactRequestsReceived": "Received",

  "_comment_add_contact": "=== Add Contact Dialog ===",
  "addContactTitle": "Add Contact",
  "addContactHint": "Enter a name or ID",
  "addContactSearching": "Searching...",
  "addContactFoundOnNetwork": "Found on network",
  "addContactNotFound": "Not found",
  "addContactSendRequest": "Send Request",
  "addContactRequestSent": "Contact request sent",
  "addContactAlreadyContact": "Already in your contacts",
  "addContactCannotAddSelf": "You cannot add yourself",

  "_comment_chat": "=== Chat Screen ===",
  "chatSearchMessages": "Search messages",
  "chatOnline": "Online",
  "chatOffline": "Offline",
  "chatConnecting": "Connecting...",
  "chatTypeMessage": "Type a message",
  "chatNoMessages": "No messages yet",
  "chatSendFirstMessage": "Send a message to start the conversation",
  "chatPhotoLibrary": "Photo Library",
  "chatCamera": "Camera",
  "chatAddCaption": "Add Caption...",
  "chatSendPhoto": "Send",
  "chatImageTooLarge": "Image too large (max {maxSize})",
  "@chatImageTooLarge": {
    "placeholders": {
      "maxSize": { "type": "String" }
    }
  },
  "chatMessageDeleted": "Message deleted",
  "chatLoadEarlier": "Load earlier messages",
  "chatLastSeen": "Last seen {time}",
  "@chatLastSeen": {
    "placeholders": {
      "time": { "type": "String" }
    }
  },

  "_comment_message_menu": "=== Message Context Menu ===",
  "messageMenuReply": "Reply",
  "messageMenuCopy": "Copy",
  "messageMenuForward": "Forward",
  "messageMenuStar": "Star",
  "messageMenuUnstar": "Unstar",
  "messageMenuRetry": "Retry",
  "messageMenuDelete": "Delete",

  "_comment_channels": "=== Channels ===",
  "channelsTitle": "Channels",
  "channelsEmpty": "No channels yet",
  "channelsCreateOrDiscover": "Create or discover channels",
  "channelsCreate": "Create Channel",
  "channelsDiscover": "Discover Channels",
  "channelName": "Channel Name",
  "channelDescription": "Description",
  "channelListPublicly": "List publicly",
  "channelListPubliclyHint": "Allow others to discover this channel",
  "channelSubscribe": "Subscribe",
  "channelSubscribed": "Subscribed",
  "channelUnsubscribe": "Unsubscribe",
  "channelWritePost": "Write a post...",
  "channelNoPosts": "No posts yet",
  "channelLoadOlderPosts": "Load older posts",
  "channelSearchChannels": "Search channels...",
  "channelNoPublicChannels": "No public channels found",
  "channelCreated": "Channel created",
  "channelReply": "Reply",
  "channelCopy": "Copy",

  "_comment_groups": "=== Groups ===",
  "groupsTitle": "Groups",
  "groupsCreate": "Create Group",
  "groupsEmpty": "No groups yet",
  "groupsCreateOrJoin": "Create a group or accept an invitation",
  "groupsPendingInvitations": "Pending Invitations",
  "groupsYourGroups": "Your Groups",
  "groupsInfo": "Group Info",
  "groupsMembers": "Members",
  "groupsLeave": "Leave Group",
  "groupsDelete": "Delete Group",
  "groupsInvite": "Invite",
  "groupsAccept": "Accept",
  "groupsDecline": "Decline",
  "groupsName": "Group Name",
  "groupsDescription": "Description",
  "groupsCreated": "Group created",
  "groupsOwner": "Owner",
  "groupsMember": "Member",
  "groupsAdmin": "Admin",
  "groupsRemoveMember": "Remove Member",
  "groupsKickConfirm": "Remove {name} from the group?",
  "@groupsKickConfirm": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },

  "_comment_settings": "=== Settings ===",
  "settingsTitle": "Settings",
  "settingsAnonymous": "Anonymous",
  "settingsNotLoaded": "Not loaded",
  "settingsTapToEditProfile": "Tap to edit profile",

  "_comment_settings_appearance": "=== Settings: Appearance ===",
  "settingsAppearance": "Appearance",
  "settingsDarkMode": "Dark Mode",
  "settingsDarkModeSubtitle": "Switch between dark and light theme",

  "_comment_settings_language": "=== Settings: Language ===",
  "settingsLanguage": "Language",
  "settingsLanguageSubtitle": "Choose app language",
  "settingsLanguageSystem": "System default",
  "settingsLanguageEnglish": "English",
  "settingsLanguageTurkish": "Türkçe",

  "_comment_settings_battery": "=== Settings: Battery ===",
  "settingsBattery": "Battery",
  "settingsDisableBatteryOpt": "Disable Battery Optimization",
  "settingsBatteryChecking": "Checking...",
  "settingsBatteryDisabled": "Disabled — app can run in background",
  "settingsBatteryTapToKeep": "Tap to keep app alive in background",

  "_comment_settings_security": "=== Settings: Security ===",
  "settingsSecurity": "Security",
  "settingsExportSeedPhrase": "Export Seed Phrase",
  "settingsExportSeedSubtitle": "Back up your recovery phrase",
  "settingsAppLock": "App Lock",
  "settingsAppLockSubtitle": "Require authentication",
  "settingsExportSeedWarning": "Your seed phrase gives full access to your identity. Never share it with anyone.",
  "settingsShowSeed": "Show Seed",
  "settingsYourSeedPhrase": "Your Seed Phrase",
  "settingsSeedPhraseWarning": "Write these words down in order and store them safely. Anyone with this phrase can access your identity.",
  "settingsSeedCopied": "Seed phrase copied to clipboard",
  "settingsSeedNotAvailable": "Seed phrase not available for this identity. It was created before this feature was added.",
  "settingsSeedError": "Unable to retrieve seed phrase",

  "_comment_settings_wallet": "=== Settings: Wallet ===",
  "settingsWallet": "Wallet",
  "settingsHideZeroBalance": "Hide 0 Balance",
  "settingsHideZeroBalanceSubtitle": "Hide coins with zero balance",

  "_comment_settings_data": "=== Settings: Data ===",
  "settingsData": "Data",
  "settingsAutoSync": "Auto Sync",
  "settingsAutoSyncSubtitle": "Sync messages automatically every 15 minutes",
  "settingsLastSync": "Last sync: {time}",
  "@settingsLastSync": {
    "placeholders": {
      "time": { "type": "String" }
    }
  },
  "settingsSyncNow": "Sync Now",
  "settingsSyncNowSubtitle": "Force immediate sync",

  "_comment_settings_logs": "=== Settings: Logs ===",
  "settingsLogs": "Logs",
  "settingsOpenLogsFolder": "Open Logs Folder",
  "settingsOpenLogsFolderSubtitle": "Open file manager at logs directory",
  "settingsShareLogs": "Share Logs",
  "settingsShareLogsSubtitle": "Zip and share log files",
  "settingsLogsFolderNotExist": "Logs folder does not exist yet",
  "settingsNoLogFiles": "No log files found",
  "settingsFailedCreateZip": "Failed to create zip archive",

  "_comment_settings_identity": "=== Settings: Identity ===",
  "settingsIdentity": "Identity",
  "settingsFingerprint": "Fingerprint",
  "settingsFingerprintCopied": "Fingerprint copied",
  "settingsDeleteAccount": "Delete Account",
  "settingsDeleteAccountSubtitle": "Permanently delete all data from device",
  "settingsDeleteAccountConfirm": "Delete Account?",
  "settingsDeleteAccountWarning": "This will permanently delete all local data:",
  "settingsDeletePrivateKeys": "Private keys",
  "settingsDeleteWallets": "Wallets",
  "settingsDeleteMessages": "Messages",
  "settingsDeleteContacts": "Contacts",
  "settingsDeleteGroups": "Groups",
  "settingsDeleteSeedWarning": "Make sure you have backed up your seed phrase before deleting!",
  "settingsDeleteSuccess": "Account deleted successfully",
  "settingsDeleteFailed": "Failed to delete account: {error}",
  "@settingsDeleteFailed": {
    "placeholders": {
      "error": { "type": "String" }
    }
  },

  "_comment_settings_about": "=== Settings: About ===",
  "settingsAbout": "About",
  "settingsUpdateAvailable": "Update Available",
  "settingsTapToDownload": "Tap to download",
  "settingsAppVersion": "DNA Messenger v{version}",
  "@settingsAppVersion": {
    "placeholders": {
      "version": { "type": "String" }
    }
  },
  "settingsLibVersion": "Library v{version}",
  "@settingsLibVersion": {
    "placeholders": {
      "version": { "type": "String" }
    }
  },
  "settingsPostQuantumMessenger": "Post-Quantum Encrypted Messenger",
  "settingsCryptoStack": "CRYPTO STACK",

  "_comment_profile": "=== Profile Editor ===",
  "profileTitle": "Edit Profile",
  "profileInfo": "Profile Info",
  "profileBio": "Bio",
  "profileLocation": "Location",
  "profileWebsite": "Website",
  "profileWalletAddresses": "Wallet Addresses",
  "profileSave": "Save Profile",
  "profileShareQR": "Share My QR Code",
  "profileAvatar": "Avatar",
  "profileTakeSelfie": "Take a Selfie",
  "profileChooseFromGallery": "Choose from Gallery",
  "profileSaved": "Profile saved",
  "profileSaveFailed": "Failed to save profile: {error}",
  "@profileSaveFailed": {
    "placeholders": {
      "error": { "type": "String" }
    }
  },
  "profileCropTitle": "Crop Avatar",
  "profileCropSave": "Save",

  "_comment_contact_profile": "=== Contact Profile Dialog ===",
  "contactProfileFailed": "Failed to load profile",
  "contactProfileUnknownError": "Unknown error",
  "contactProfileNickname": "Nickname",
  "contactProfileNicknameNotSet": "Not set (tap to add)",
  "contactProfileOriginal": "Original: {name}",
  "@contactProfileOriginal": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },
  "contactProfileSetNickname": "Set Nickname",
  "contactProfileOriginalName": "Original name: {name}",
  "@contactProfileOriginalName": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },
  "contactProfileNicknameLabel": "Nickname",
  "contactProfileNicknameHint": "Enter custom nickname",
  "contactProfileNicknameHelper": "Leave empty to use original name",
  "contactProfileNicknameCleared": "Nickname cleared",
  "contactProfileNicknameSet": "Nickname set to \"{name}\"",
  "@contactProfileNicknameSet": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },
  "contactProfileNicknameFailed": "Failed to set nickname: {error}",
  "@contactProfileNicknameFailed": {
    "placeholders": {
      "error": { "type": "String" }
    }
  },
  "contactProfileCopyFingerprint": "Copy fingerprint",
  "contactProfileNoProfile": "No profile published",
  "contactProfileNoProfileSubtitle": "This user has not published their profile yet.",
  "contactProfileBio": "Bio",
  "contactProfileInfo": "Info",
  "contactProfileWebsite": "Website",

  "_comment_identity": "=== Identity Selection / Onboarding ===",
  "identityTitle": "DNA Messenger",
  "identityWelcome": "Welcome to DNA Messenger",
  "identityGenerateSeed": "Generate New Seed",
  "identityHaveSeed": "I Have a Seed Phrase",
  "identityYourRecoveryPhrase": "Your Recovery Phrase",
  "identityRecoveryPhraseWarning": "Write down these words and keep them safe. They are the only way to recover your account.",
  "identityConfirmSaved": "I have saved my recovery phrase",
  "identityEnterRecoveryPhrase": "Enter Recovery Phrase",
  "identityEnterRecoveryPhraseHint": "Enter your 12 or 24 word recovery phrase",
  "identityChooseName": "Choose Your Name",
  "identityChooseNameHint": "Enter a display name",
  "identityRegisterContinue": "Register & Continue",
  "identityRegistering": "Registering...",
  "identityNameTaken": "This name is already taken",
  "identityNameInvalid": "Name must be 3-20 characters",
  "identityCreating": "Creating your identity...",
  "identityRestoring": "Restoring your identity...",

  "_comment_wall": "=== Wall / Timeline ===",
  "wallTitle": "Home",
  "wallWelcome": "Welcome to your timeline!",
  "wallWelcomeSubtitle": "Follow people and channels to see their posts here.",
  "wallNewPost": "New Post",
  "wallDeletePost": "Delete Post",
  "wallDeletePostConfirm": "Are you sure you want to delete this post?",
  "wallRepost": "Repost",
  "wallReposted": "Reposted",
  "wallComments": "Comments",
  "wallNoComments": "No comments yet",
  "wallLoadingComments": "Loading comments...",
  "wallWriteComment": "Write a comment...",
  "wallWriteReply": "Write a reply...",
  "wallViewAllComments": "View all {count} comments",
  "@wallViewAllComments": {
    "placeholders": {
      "count": { "type": "int" }
    }
  },
  "wallPostDetail": "Post",
  "wallCopy": "Copy",
  "wallReply": "Reply",
  "wallDelete": "Delete",

  "_comment_wallet": "=== Wallet ===",
  "walletTitle": "Wallet",
  "walletTotalBalance": "Total Balance",
  "walletSend": "Send",
  "walletReceive": "Receive",
  "walletSwap": "Swap",
  "walletHistory": "History",
  "walletNoTransactions": "No transactions yet",
  "walletCopyAddress": "Copy Address",
  "walletAddressCopied": "Address copied",
  "walletSendTitle": "Send {coin}",
  "@walletSendTitle": {
    "placeholders": {
      "coin": { "type": "String" }
    }
  },
  "walletRecipientAddress": "Recipient Address",
  "walletAmount": "Amount",
  "walletMax": "MAX",
  "walletSendConfirm": "Confirm Send",
  "walletSending": "Sending...",
  "walletSendSuccess": "Transaction sent",
  "walletSendFailed": "Transaction failed: {error}",
  "@walletSendFailed": {
    "placeholders": {
      "error": { "type": "String" }
    }
  },
  "walletReceiveTitle": "Receive {coin}",
  "@walletReceiveTitle": {
    "placeholders": {
      "coin": { "type": "String" }
    }
  },
  "walletAddressBook": "Address Book",
  "walletAddAddress": "Add Address",
  "walletEditAddress": "Edit Address",
  "walletDeleteAddress": "Delete Address",
  "walletLabel": "Label",
  "walletAddress": "Address",
  "walletNetwork": "Network",

  "_comment_qr": "=== QR Screens ===",
  "qrScannerTitle": "QR Scanner",
  "qrAddContact": "Add Contact",
  "qrAuthRequest": "Authorization Request",
  "qrContent": "QR Content",
  "qrSendContactRequest": "Send Contact Request",
  "qrScanAnother": "Scan Another",
  "qrCopyFingerprint": "Copy",
  "qrRequestSent": "Contact request sent",
  "qrInvalidCode": "Invalid QR code",

  "_comment_more": "=== More Screen ===",
  "moreTitle": "More",
  "moreWallet": "Wallet",
  "moreQRScanner": "QR Scanner",
  "moreAddresses": "Addresses",
  "moreStarred": "Starred",
  "moreContacts": "Contacts",
  "moreSettings": "Settings",
  "moreAppLock": "App Lock",

  "_comment_lock": "=== Lock Screen ===",
  "lockTitle": "DNA Messenger",
  "lockEnterPIN": "Enter PIN to unlock",
  "lockIncorrectPIN": "Incorrect PIN",
  "lockUseBiometrics": "Use biometrics to unlock",

  "_comment_app_lock_settings": "=== App Lock Settings ===",
  "appLockTitle": "App Lock",
  "appLockEnable": "Enable App Lock",
  "appLockUseBiometrics": "Use Biometrics",
  "appLockChangePIN": "Change PIN",
  "appLockSetPIN": "Set PIN",
  "appLockConfirmPIN": "Confirm PIN",
  "appLockPINMismatch": "PINs do not match",
  "appLockPINSet": "PIN set successfully",
  "appLockPINChanged": "PIN changed",
  "appLockEnterCurrentPIN": "Enter current PIN",
  "appLockEnterNewPIN": "Enter new PIN",

  "_comment_starred": "=== Starred Messages ===",
  "starredTitle": "Starred Messages",
  "starredEmpty": "No starred messages",

  "_comment_blocked": "=== Blocked Users ===",
  "blockedTitle": "Blocked Users",
  "blockedEmpty": "No blocked users",
  "blockedUnblock": "Unblock",
  "blockedUnblockConfirm": "Unblock {name}?",
  "@blockedUnblockConfirm": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },

  "_comment_update": "=== Update Required ===",
  "updateTitle": "Update Required",
  "updateMessage": "A newer version is required to continue using DNA Messenger.",
  "updateDownload": "Download Update",

  "_comment_common": "=== Common / Shared ===",
  "cancel": "Cancel",
  "save": "Save",
  "delete": "Delete",
  "done": "Done",
  "copy": "Copy",
  "ok": "OK",
  "yes": "Yes",
  "no": "No",
  "error": "Error",
  "success": "Success",
  "loading": "Loading...",
  "pleaseWait": "Please wait...",
  "copied": "Copied",
  "failed": "Failed: {error}",
  "@failed": {
    "placeholders": {
      "error": { "type": "String" }
    }
  },
  "nCount": "{count}",
  "@nCount": {
    "placeholders": {
      "count": { "type": "int" }
    }
  }
}
```

**Step 2: Run `flutter gen-l10n` to verify ARB parses**

Run: `cd messenger/dna_messenger_flutter && flutter gen-l10n`
Expected: Generated files in `.dart_tool/flutter_gen/gen_l10n/`

**Step 3: Commit**

```bash
git add lib/l10n/app_en.arb
git commit -m "feat(i18n): add English ARB source file (~250 strings)"
```

---

## Task 3: Create Turkish ARB File (app_tr.arb)

**Files:**
- Create: `messenger/dna_messenger_flutter/lib/l10n/app_tr.arb`

**Step 1: Create app_tr.arb with Turkish translations**

Same keys as app_en.arb, Turkish values. Claude drafts, user reviews.

**Step 2: Run `flutter gen-l10n` to verify both ARBs parse**

Run: `cd messenger/dna_messenger_flutter && flutter gen-l10n`
Expected: Generates `AppLocalizations` with `en` and `tr` delegates.

**Step 3: Commit**

```bash
git add lib/l10n/app_tr.arb
git commit -m "feat(i18n): add Turkish ARB translations"
```

---

## Task 4: Create Locale Provider

**Files:**
- Create: `messenger/dna_messenger_flutter/lib/providers/locale_provider.dart`
- Modify: `messenger/dna_messenger_flutter/lib/providers/providers.dart`

**Step 1: Create locale_provider.dart**

Follow the same pattern as `theme_provider.dart` (Riverpod StateNotifier + SharedPreferences):

```dart
// Locale Provider - Language selection with persistence
import 'dart:ui';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Locale state — null = system default, Locale('en') = English, Locale('tr') = Turkish
final localeProvider = StateNotifierProvider<LocaleNotifier, Locale?>((ref) {
  return LocaleNotifier();
});

class LocaleNotifier extends StateNotifier<Locale?> {
  static const _key = 'app_locale';

  LocaleNotifier() : super(null) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final value = prefs.getString(_key);
    if (value != null) {
      state = Locale(value);
    }
    // null = system default
  }

  Future<void> setLocale(Locale? locale) async {
    state = locale;
    final prefs = await SharedPreferences.getInstance();
    if (locale == null) {
      await prefs.remove(_key);
    } else {
      await prefs.setString(_key, locale.languageCode);
    }
  }
}
```

**Step 2: Export from providers.dart**

Add to `lib/providers/providers.dart`:
```dart
export 'locale_provider.dart';
```

**Step 3: Commit**

```bash
git add lib/providers/locale_provider.dart lib/providers/providers.dart
git commit -m "feat(i18n): add locale provider with SharedPreferences persistence"
```

---

## Task 5: Wire MaterialApp with Localizations

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/main.dart`

**Step 1: Add imports and locale delegates to MaterialApp**

In `main.dart`, add import:
```dart
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
```

In `DnaMessengerApp.build()`, watch localeProvider and add to MaterialApp:
```dart
final locale = ref.watch(localeProvider);
return MaterialApp(
  // ...existing properties...
  localizationsDelegates: AppLocalizations.localizationsDelegates,
  supportedLocales: AppLocalizations.supportedLocales,
  locale: locale,
);
```

**Step 2: Run flutter build linux to verify compilation**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`
Expected: Build succeeds with no errors.

**Step 3: Commit**

```bash
git add lib/main.dart
git commit -m "feat(i18n): wire MaterialApp with localization delegates"
```

---

## Task 6: Add Language Setting to Settings Screen

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/settings/settings_screen.dart`

**Step 1: Add `_LanguageSection` widget after `_AppearanceSection`**

Insert a new section between Appearance and Notifications/Battery in the settings ListView:

```dart
class _LanguageSection extends ConsumerWidget {
  const _LanguageSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final locale = ref.watch(localeProvider);
    final l10n = AppLocalizations.of(context);

    String currentLabel;
    if (locale == null) {
      currentLabel = l10n.settingsLanguageSystem;
    } else if (locale.languageCode == 'tr') {
      currentLabel = l10n.settingsLanguageTurkish;
    } else {
      currentLabel = l10n.settingsLanguageEnglish;
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(l10n.settingsLanguage),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.language),
          title: Text(l10n.settingsLanguage),
          subtitle: Text(currentLabel),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () => _showLanguagePicker(context, ref, locale),
        ),
      ],
    );
  }

  void _showLanguagePicker(BuildContext context, WidgetRef ref, Locale? current) {
    final l10n = AppLocalizations.of(context);

    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            RadioListTile<Locale?>(
              title: Text(l10n.settingsLanguageSystem),
              value: null,
              groupValue: current,
              onChanged: (v) {
                ref.read(localeProvider.notifier).setLocale(null);
                Navigator.pop(context);
              },
            ),
            RadioListTile<Locale?>(
              title: const Text('English'),
              value: const Locale('en'),
              groupValue: current,
              onChanged: (v) {
                ref.read(localeProvider.notifier).setLocale(const Locale('en'));
                Navigator.pop(context);
              },
            ),
            RadioListTile<Locale?>(
              title: const Text('Türkçe'),
              value: const Locale('tr'),
              groupValue: current,
              onChanged: (v) {
                ref.read(localeProvider.notifier).setLocale(const Locale('tr'));
                Navigator.pop(context);
              },
            ),
          ],
        ),
      ),
    );
  }
}
```

Add `const _LanguageSection()` to the ListView in `SettingsScreen.build()` after `_AppearanceSection`.

Also add AppLocalizations import to the file.

**Step 2: Run flutter build linux to verify**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`
Expected: Build succeeds.

**Step 3: Commit**

```bash
git add lib/screens/settings/settings_screen.dart
git commit -m "feat(i18n): add language picker to Settings screen"
```

---

## Task 7: Replace Hardcoded Strings — main.dart + home_screen.dart

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/main.dart`
- Modify: `messenger/dna_messenger_flutter/lib/screens/home_screen.dart`

**Step 1: Replace strings in main.dart**

Replace all hardcoded strings in `_LoadingScreen` and `_ErrorScreen` with `AppLocalizations.of(context).xxx` calls.

Key replacements:
- `'DNA Messenger'` → `AppLocalizations.of(context).appTitle`
- `'Initializing...'` → `AppLocalizations.of(context).initializing`
- `'Failed to initialize'` → `AppLocalizations.of(context).failedToInitialize`
- `'Make sure the native library is available.'` → `AppLocalizations.of(context).makeSureNativeLibrary`

**Step 2: Replace strings in home_screen.dart**

Bottom navigation labels:
- `'Home'` → `AppLocalizations.of(context).navHome`
- `'Chats'` → `AppLocalizations.of(context).navChats`
- `'Channels'` → `AppLocalizations.of(context).navChannels`
- `'More'` → `AppLocalizations.of(context).navMore`

**Step 3: Build verify**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`

**Step 4: Commit**

```bash
git add lib/main.dart lib/screens/home_screen.dart
git commit -m "feat(i18n): localize main.dart + home_screen.dart"
```

---

## Task 8: Replace Hardcoded Strings — Messages + Chat Screens

**Files:**
- Modify: `lib/screens/messages/messages_screen.dart`
- Modify: `lib/screens/chat/chat_screen.dart`
- Modify: `lib/screens/chat/widgets/message_context_menu.dart`
- Modify: `lib/screens/chat/widgets/message_bubble.dart`
- Modify: `lib/screens/chat/contact_profile_dialog.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

Each file: add import, replace every user-visible hardcoded string.

**Step 2: Build verify**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`

**Step 3: Commit**

```bash
git add lib/screens/messages/ lib/screens/chat/
git commit -m "feat(i18n): localize messages + chat screens"
```

---

## Task 9: Replace Hardcoded Strings — Contacts Screens

**Files:**
- Modify: `lib/screens/contacts/contacts_screen.dart`
- Modify: `lib/screens/contacts/contacts_hub_screen.dart`
- Modify: `lib/screens/contacts/contact_requests_screen.dart`
- Modify: `lib/screens/contacts/add_contact_dialog.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/contacts/
git commit -m "feat(i18n): localize contacts screens"
```

---

## Task 10: Replace Hardcoded Strings — Channels Screens

**Files:**
- Modify: `lib/screens/channels/channel_list_screen.dart`
- Modify: `lib/screens/channels/create_channel_screen.dart`
- Modify: `lib/screens/channels/discover_channels_screen.dart`
- Modify: `lib/screens/channels/channel_detail_screen.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/channels/
git commit -m "feat(i18n): localize channel screens"
```

---

## Task 11: Replace Hardcoded Strings — Groups Screen

**Files:**
- Modify: `lib/screens/groups/groups_screen.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/groups/
git commit -m "feat(i18n): localize groups screen"
```

---

## Task 12: Replace Hardcoded Strings — Settings Screen (full)

**Files:**
- Modify: `lib/screens/settings/settings_screen.dart`
- Modify: `lib/screens/settings/app_lock_settings_screen.dart`
- Modify: `lib/screens/settings/starred_messages_screen.dart`
- Modify: `lib/screens/settings/blocked_users_screen.dart`
- Modify: `lib/screens/settings/contacts_management_screen.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

The settings screen is large — replace section by section (Appearance, Battery, Security, Wallet, Data, Logs, Identity, About).

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/settings/
git commit -m "feat(i18n): localize settings screens"
```

---

## Task 13: Replace Hardcoded Strings — Profile + Identity

**Files:**
- Modify: `lib/screens/profile/profile_editor_screen.dart`
- Modify: `lib/screens/profile/avatar_crop_screen.dart`
- Modify: `lib/screens/identity/identity_selection_screen.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/profile/ lib/screens/identity/
git commit -m "feat(i18n): localize profile + identity screens"
```

---

## Task 14: Replace Hardcoded Strings — Wall + Widgets

**Files:**
- Modify: `lib/screens/wall/wall_timeline_screen.dart`
- Modify: `lib/screens/wall/wall_post_detail_screen.dart`
- Modify: `lib/widgets/wall_post_tile.dart`
- Modify: `lib/widgets/wall_comment_tile.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/wall/ lib/widgets/wall_post_tile.dart lib/widgets/wall_comment_tile.dart
git commit -m "feat(i18n): localize wall + timeline screens"
```

---

## Task 15: Replace Hardcoded Strings — Wallet + QR + More + Lock + Update

**Files:**
- Modify: `lib/screens/wallet/wallet_screen.dart`
- Modify: `lib/screens/wallet/address_dialog.dart`
- Modify: `lib/screens/wallet/address_book_screen.dart`
- Modify: `lib/screens/qr/qr_scanner_screen.dart`
- Modify: `lib/screens/qr/qr_auth_screen.dart`
- Modify: `lib/screens/qr/qr_result_screen.dart`
- Modify: `lib/screens/more/more_screen.dart`
- Modify: `lib/screens/lock/lock_screen.dart`
- Modify: `lib/screens/update_required_screen.dart`

**Step 1: Replace all hardcoded strings with AppLocalizations calls**

**Step 2: Build verify**

**Step 3: Commit**

```bash
git add lib/screens/wallet/ lib/screens/qr/ lib/screens/more/ lib/screens/lock/ lib/screens/update_required_screen.dart
git commit -m "feat(i18n): localize wallet, QR, more, lock, update screens"
```

---

## Task 16: Final Build Verification + Missing Strings Audit

**Files:**
- May modify: `lib/l10n/app_en.arb`, `lib/l10n/app_tr.arb` (if missing strings found)

**Step 1: Run full Flutter Linux build**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`
Expected: Build succeeds with 0 errors, 0 warnings.

**Step 2: Grep for remaining hardcoded strings**

Run: `grep -rn "const Text(" lib/screens/ lib/widgets/ | grep -v "AppLocalizations" | grep -v "import"` to find any remaining hardcoded strings.

**Step 3: Fix any missing strings**

Add any missing keys to both ARB files and replace in code.

**Step 4: Final build + commit**

```bash
git add -A
git commit -m "feat(i18n): complete i18n audit — fix remaining hardcoded strings"
```

---

## Task 17: Version Bump + Documentation Update

**Files:**
- Modify: `messenger/dna_messenger_flutter/pubspec.yaml` (version bump)
- Modify: `messenger/docs/FLUTTER_UI.md` (document i18n system)

**Step 1: Bump Flutter app version**

Current: `1.0.0-rc11+10361` → `1.0.0-rc12+10362`

**Step 2: Update FLUTTER_UI.md**

Add section documenting the i18n system: file locations, how to add strings, how to add new languages.

**Step 3: Final commit**

```bash
git add pubspec.yaml docs/FLUTTER_UI.md
git commit -m "feat(i18n): complete i18n infrastructure + Turkish support (v1.0.0-rc12)"
```

---

## Summary

| Task | Description | Est. Files |
|------|-------------|-----------|
| 1 | Infrastructure (pubspec, l10n.yaml) | 2 |
| 2 | English ARB (~250 strings) | 1 |
| 3 | Turkish ARB (~250 strings) | 1 |
| 4 | Locale provider | 2 |
| 5 | MaterialApp wiring | 1 |
| 6 | Settings language picker | 1 |
| 7 | main.dart + home_screen | 2 |
| 8 | Messages + chat screens | 5 |
| 9 | Contacts screens | 4 |
| 10 | Channels screens | 4 |
| 11 | Groups screen | 1 |
| 12 | Settings screens | 5 |
| 13 | Profile + Identity | 3 |
| 14 | Wall + widgets | 4 |
| 15 | Wallet + QR + More + Lock + Update | 9 |
| 16 | Final audit | varies |
| 17 | Version bump + docs | 2 |

**Total: ~47 files modified/created across 17 tasks**
