import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_de.dart';
import 'app_localizations_en.dart';
import 'app_localizations_es.dart';
import 'app_localizations_it.dart';
import 'app_localizations_ja.dart';
import 'app_localizations_nl.dart';
import 'app_localizations_pt.dart';
import 'app_localizations_ru.dart';
import 'app_localizations_tr.dart';
import 'app_localizations_zh.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('de'),
    Locale('en'),
    Locale('es'),
    Locale('it'),
    Locale('ja'),
    Locale('nl'),
    Locale('pt'),
    Locale('ru'),
    Locale('tr'),
    Locale('zh'),
  ];

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'DNA Messenger'**
  String get appTitle;

  /// No description provided for @initializing.
  ///
  /// In en, this message translates to:
  /// **'Initializing...'**
  String get initializing;

  /// No description provided for @failedToInitialize.
  ///
  /// In en, this message translates to:
  /// **'Failed to initialize'**
  String get failedToInitialize;

  /// No description provided for @makeSureNativeLibrary.
  ///
  /// In en, this message translates to:
  /// **'Make sure the native library is available.'**
  String get makeSureNativeLibrary;

  /// No description provided for @navHome.
  ///
  /// In en, this message translates to:
  /// **'Home'**
  String get navHome;

  /// No description provided for @navChats.
  ///
  /// In en, this message translates to:
  /// **'Chats'**
  String get navChats;

  /// No description provided for @navChannels.
  ///
  /// In en, this message translates to:
  /// **'Channels'**
  String get navChannels;

  /// No description provided for @navMore.
  ///
  /// In en, this message translates to:
  /// **'More'**
  String get navMore;

  /// No description provided for @messagesAll.
  ///
  /// In en, this message translates to:
  /// **'All'**
  String get messagesAll;

  /// No description provided for @messagesUnread.
  ///
  /// In en, this message translates to:
  /// **'Unread'**
  String get messagesUnread;

  /// No description provided for @messagesAllCaughtUp.
  ///
  /// In en, this message translates to:
  /// **'All caught up!'**
  String get messagesAllCaughtUp;

  /// No description provided for @messagesNoUnread.
  ///
  /// In en, this message translates to:
  /// **'No unread messages'**
  String get messagesNoUnread;

  /// No description provided for @messagesSearchHint.
  ///
  /// In en, this message translates to:
  /// **'Search chats...'**
  String get messagesSearchHint;

  /// No description provided for @contactsTitle.
  ///
  /// In en, this message translates to:
  /// **'Contacts'**
  String get contactsTitle;

  /// No description provided for @contactsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No contacts yet'**
  String get contactsEmpty;

  /// No description provided for @contactsTapToAdd.
  ///
  /// In en, this message translates to:
  /// **'Tap + to add a contact'**
  String get contactsTapToAdd;

  /// No description provided for @contactsOnline.
  ///
  /// In en, this message translates to:
  /// **'Online'**
  String get contactsOnline;

  /// No description provided for @contactsLastSeen.
  ///
  /// In en, this message translates to:
  /// **'Last seen {time}'**
  String contactsLastSeen(String time);

  /// No description provided for @contactsOffline.
  ///
  /// In en, this message translates to:
  /// **'Offline'**
  String get contactsOffline;

  /// No description provided for @contactsSyncing.
  ///
  /// In en, this message translates to:
  /// **'Syncing...'**
  String get contactsSyncing;

  /// No description provided for @contactsFailedToLoad.
  ///
  /// In en, this message translates to:
  /// **'Failed to load contacts'**
  String get contactsFailedToLoad;

  /// No description provided for @contactsRetry.
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get contactsRetry;

  /// No description provided for @contactsHubContacts.
  ///
  /// In en, this message translates to:
  /// **'Contacts'**
  String get contactsHubContacts;

  /// No description provided for @contactsHubRequests.
  ///
  /// In en, this message translates to:
  /// **'Requests'**
  String get contactsHubRequests;

  /// No description provided for @contactsHubBlocked.
  ///
  /// In en, this message translates to:
  /// **'Blocked'**
  String get contactsHubBlocked;

  /// No description provided for @contactsHubRemoveTitle.
  ///
  /// In en, this message translates to:
  /// **'Remove Contact?'**
  String get contactsHubRemoveTitle;

  /// No description provided for @contactsHubRemoveMessage.
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to remove {name} from your contacts?'**
  String contactsHubRemoveMessage(String name);

  /// No description provided for @contactsHubRemove.
  ///
  /// In en, this message translates to:
  /// **'Remove'**
  String get contactsHubRemove;

  /// No description provided for @contactsHubFingerprintCopied.
  ///
  /// In en, this message translates to:
  /// **'Fingerprint copied'**
  String get contactsHubFingerprintCopied;

  /// No description provided for @contactRequestsTitle.
  ///
  /// In en, this message translates to:
  /// **'Contact Requests'**
  String get contactRequestsTitle;

  /// No description provided for @contactRequestsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No pending requests'**
  String get contactRequestsEmpty;

  /// No description provided for @contactRequestsAccept.
  ///
  /// In en, this message translates to:
  /// **'Accept'**
  String get contactRequestsAccept;

  /// No description provided for @contactRequestsDeny.
  ///
  /// In en, this message translates to:
  /// **'Deny'**
  String get contactRequestsDeny;

  /// No description provided for @contactRequestsBlock.
  ///
  /// In en, this message translates to:
  /// **'Block User'**
  String get contactRequestsBlock;

  /// No description provided for @contactRequestsSent.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get contactRequestsSent;

  /// No description provided for @contactRequestsReceived.
  ///
  /// In en, this message translates to:
  /// **'Received'**
  String get contactRequestsReceived;

  /// No description provided for @addContactTitle.
  ///
  /// In en, this message translates to:
  /// **'Add Contact'**
  String get addContactTitle;

  /// No description provided for @addContactHint.
  ///
  /// In en, this message translates to:
  /// **'Enter a name or ID'**
  String get addContactHint;

  /// No description provided for @addContactSearching.
  ///
  /// In en, this message translates to:
  /// **'Searching...'**
  String get addContactSearching;

  /// No description provided for @addContactFoundOnNetwork.
  ///
  /// In en, this message translates to:
  /// **'Found on network'**
  String get addContactFoundOnNetwork;

  /// No description provided for @addContactNotFound.
  ///
  /// In en, this message translates to:
  /// **'Not found'**
  String get addContactNotFound;

  /// No description provided for @addContactSendRequest.
  ///
  /// In en, this message translates to:
  /// **'Send Request'**
  String get addContactSendRequest;

  /// No description provided for @addContactRequestSent.
  ///
  /// In en, this message translates to:
  /// **'Contact request sent'**
  String get addContactRequestSent;

  /// No description provided for @addContactAlreadyContact.
  ///
  /// In en, this message translates to:
  /// **'Already in your contacts'**
  String get addContactAlreadyContact;

  /// No description provided for @addContactCannotAddSelf.
  ///
  /// In en, this message translates to:
  /// **'You cannot add yourself'**
  String get addContactCannotAddSelf;

  /// No description provided for @chatSearchMessages.
  ///
  /// In en, this message translates to:
  /// **'Search messages'**
  String get chatSearchMessages;

  /// No description provided for @chatOnline.
  ///
  /// In en, this message translates to:
  /// **'Online'**
  String get chatOnline;

  /// No description provided for @chatOffline.
  ///
  /// In en, this message translates to:
  /// **'Offline'**
  String get chatOffline;

  /// No description provided for @chatConnecting.
  ///
  /// In en, this message translates to:
  /// **'Connecting...'**
  String get chatConnecting;

  /// No description provided for @chatTypeMessage.
  ///
  /// In en, this message translates to:
  /// **'Type a message'**
  String get chatTypeMessage;

  /// No description provided for @chatNoMessages.
  ///
  /// In en, this message translates to:
  /// **'No messages yet'**
  String get chatNoMessages;

  /// No description provided for @chatSendFirstMessage.
  ///
  /// In en, this message translates to:
  /// **'Send a message to start the conversation'**
  String get chatSendFirstMessage;

  /// No description provided for @chatPhotoLibrary.
  ///
  /// In en, this message translates to:
  /// **'Photo Library'**
  String get chatPhotoLibrary;

  /// No description provided for @chatCamera.
  ///
  /// In en, this message translates to:
  /// **'Camera'**
  String get chatCamera;

  /// No description provided for @chatAddCaption.
  ///
  /// In en, this message translates to:
  /// **'Add Caption...'**
  String get chatAddCaption;

  /// No description provided for @chatSendPhoto.
  ///
  /// In en, this message translates to:
  /// **'Send'**
  String get chatSendPhoto;

  /// No description provided for @chatImageTooLarge.
  ///
  /// In en, this message translates to:
  /// **'Image too large (max {maxSize})'**
  String chatImageTooLarge(String maxSize);

  /// No description provided for @chatMessageDeleted.
  ///
  /// In en, this message translates to:
  /// **'Message deleted'**
  String get chatMessageDeleted;

  /// No description provided for @chatLoadEarlier.
  ///
  /// In en, this message translates to:
  /// **'Load earlier messages'**
  String get chatLoadEarlier;

  /// No description provided for @chatLastSeen.
  ///
  /// In en, this message translates to:
  /// **'Last seen {time}'**
  String chatLastSeen(String time);

  /// No description provided for @chatSendTokens.
  ///
  /// In en, this message translates to:
  /// **'Send Tokens'**
  String get chatSendTokens;

  /// No description provided for @chatSendTokensTo.
  ///
  /// In en, this message translates to:
  /// **'to {name}'**
  String chatSendTokensTo(String name);

  /// No description provided for @chatLookingUpWallets.
  ///
  /// In en, this message translates to:
  /// **'Looking up wallet addresses...'**
  String get chatLookingUpWallets;

  /// No description provided for @chatNoWalletAddresses.
  ///
  /// In en, this message translates to:
  /// **'Contact has no wallet addresses in their profile'**
  String get chatNoWalletAddresses;

  /// No description provided for @chatTokenLabel.
  ///
  /// In en, this message translates to:
  /// **'Token'**
  String get chatTokenLabel;

  /// No description provided for @chatSendAmount.
  ///
  /// In en, this message translates to:
  /// **'Amount'**
  String get chatSendAmount;

  /// No description provided for @chatSendAvailable.
  ///
  /// In en, this message translates to:
  /// **'Available: {balance} {token}'**
  String chatSendAvailable(String balance, String token);

  /// No description provided for @chatSendMax.
  ///
  /// In en, this message translates to:
  /// **'Max'**
  String get chatSendMax;

  /// No description provided for @chatSendButton.
  ///
  /// In en, this message translates to:
  /// **'Send {token}'**
  String chatSendButton(String token);

  /// No description provided for @chatSentSuccess.
  ///
  /// In en, this message translates to:
  /// **'Sent {amount} {token}'**
  String chatSentSuccess(String amount, String token);

  /// No description provided for @chatInvalidAmount.
  ///
  /// In en, this message translates to:
  /// **'Please enter a valid amount'**
  String get chatInvalidAmount;

  /// No description provided for @chatInsufficientBalance.
  ///
  /// In en, this message translates to:
  /// **'Insufficient {token} balance'**
  String chatInsufficientBalance(String token);

  /// No description provided for @chatNoWalletForNetwork.
  ///
  /// In en, this message translates to:
  /// **'Contact has no wallet for this network'**
  String get chatNoWalletForNetwork;

  /// No description provided for @chatSelectToken.
  ///
  /// In en, this message translates to:
  /// **'Select Token'**
  String get chatSelectToken;

  /// No description provided for @chatSelectNetwork.
  ///
  /// In en, this message translates to:
  /// **'Select Network'**
  String get chatSelectNetwork;

  /// No description provided for @chatEnterAmount.
  ///
  /// In en, this message translates to:
  /// **'Enter Amount'**
  String get chatEnterAmount;

  /// No description provided for @chatStepOf.
  ///
  /// In en, this message translates to:
  /// **'Step {current} of {total}'**
  String chatStepOf(String current, String total);

  /// No description provided for @messageMenuReply.
  ///
  /// In en, this message translates to:
  /// **'Reply'**
  String get messageMenuReply;

  /// No description provided for @messageMenuCopy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get messageMenuCopy;

  /// No description provided for @messageMenuForward.
  ///
  /// In en, this message translates to:
  /// **'Forward'**
  String get messageMenuForward;

  /// No description provided for @messageMenuStar.
  ///
  /// In en, this message translates to:
  /// **'Star'**
  String get messageMenuStar;

  /// No description provided for @messageMenuUnstar.
  ///
  /// In en, this message translates to:
  /// **'Unstar'**
  String get messageMenuUnstar;

  /// No description provided for @messageMenuRetry.
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get messageMenuRetry;

  /// No description provided for @messageMenuDelete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get messageMenuDelete;

  /// No description provided for @channelsTitle.
  ///
  /// In en, this message translates to:
  /// **'Channels'**
  String get channelsTitle;

  /// No description provided for @channelsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No channels yet'**
  String get channelsEmpty;

  /// No description provided for @channelsCreateOrDiscover.
  ///
  /// In en, this message translates to:
  /// **'Create or discover channels'**
  String get channelsCreateOrDiscover;

  /// No description provided for @channelsCreate.
  ///
  /// In en, this message translates to:
  /// **'Create Channel'**
  String get channelsCreate;

  /// No description provided for @channelsDiscover.
  ///
  /// In en, this message translates to:
  /// **'Discover Channels'**
  String get channelsDiscover;

  /// No description provided for @channelName.
  ///
  /// In en, this message translates to:
  /// **'Channel Name'**
  String get channelName;

  /// No description provided for @channelDescription.
  ///
  /// In en, this message translates to:
  /// **'Description'**
  String get channelDescription;

  /// No description provided for @channelListPublicly.
  ///
  /// In en, this message translates to:
  /// **'List publicly'**
  String get channelListPublicly;

  /// No description provided for @channelListPubliclyHint.
  ///
  /// In en, this message translates to:
  /// **'Allow others to discover this channel'**
  String get channelListPubliclyHint;

  /// No description provided for @channelSubscribe.
  ///
  /// In en, this message translates to:
  /// **'Subscribe'**
  String get channelSubscribe;

  /// No description provided for @channelSubscribed.
  ///
  /// In en, this message translates to:
  /// **'Subscribed'**
  String get channelSubscribed;

  /// No description provided for @channelUnsubscribe.
  ///
  /// In en, this message translates to:
  /// **'Unsubscribe'**
  String get channelUnsubscribe;

  /// No description provided for @channelWritePost.
  ///
  /// In en, this message translates to:
  /// **'Write a post...'**
  String get channelWritePost;

  /// No description provided for @channelNoPosts.
  ///
  /// In en, this message translates to:
  /// **'No posts yet'**
  String get channelNoPosts;

  /// No description provided for @channelLoadOlderPosts.
  ///
  /// In en, this message translates to:
  /// **'Load older posts'**
  String get channelLoadOlderPosts;

  /// No description provided for @channelSearchChannels.
  ///
  /// In en, this message translates to:
  /// **'Search channels...'**
  String get channelSearchChannels;

  /// No description provided for @channelNoPublicChannels.
  ///
  /// In en, this message translates to:
  /// **'No public channels found'**
  String get channelNoPublicChannels;

  /// No description provided for @channelCreated.
  ///
  /// In en, this message translates to:
  /// **'Channel created'**
  String get channelCreated;

  /// No description provided for @channelReply.
  ///
  /// In en, this message translates to:
  /// **'Reply'**
  String get channelReply;

  /// No description provided for @channelCopy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get channelCopy;

  /// No description provided for @groupsTitle.
  ///
  /// In en, this message translates to:
  /// **'Groups'**
  String get groupsTitle;

  /// No description provided for @groupsCreate.
  ///
  /// In en, this message translates to:
  /// **'Create Group'**
  String get groupsCreate;

  /// No description provided for @groupsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No groups yet'**
  String get groupsEmpty;

  /// No description provided for @groupsCreateOrJoin.
  ///
  /// In en, this message translates to:
  /// **'Create a group or accept an invitation'**
  String get groupsCreateOrJoin;

  /// No description provided for @groupsPendingInvitations.
  ///
  /// In en, this message translates to:
  /// **'Pending Invitations'**
  String get groupsPendingInvitations;

  /// No description provided for @groupsYourGroups.
  ///
  /// In en, this message translates to:
  /// **'Your Groups'**
  String get groupsYourGroups;

  /// No description provided for @groupsInfo.
  ///
  /// In en, this message translates to:
  /// **'Group Info'**
  String get groupsInfo;

  /// No description provided for @groupsMembers.
  ///
  /// In en, this message translates to:
  /// **'Members'**
  String get groupsMembers;

  /// No description provided for @groupsLeave.
  ///
  /// In en, this message translates to:
  /// **'Leave Group'**
  String get groupsLeave;

  /// No description provided for @groupsDelete.
  ///
  /// In en, this message translates to:
  /// **'Delete Group'**
  String get groupsDelete;

  /// No description provided for @groupsInvite.
  ///
  /// In en, this message translates to:
  /// **'Invite'**
  String get groupsInvite;

  /// No description provided for @groupsAccept.
  ///
  /// In en, this message translates to:
  /// **'Accept'**
  String get groupsAccept;

  /// No description provided for @groupsDecline.
  ///
  /// In en, this message translates to:
  /// **'Decline'**
  String get groupsDecline;

  /// No description provided for @groupsName.
  ///
  /// In en, this message translates to:
  /// **'Group Name'**
  String get groupsName;

  /// No description provided for @groupsDescription.
  ///
  /// In en, this message translates to:
  /// **'Description'**
  String get groupsDescription;

  /// No description provided for @groupsCreated.
  ///
  /// In en, this message translates to:
  /// **'Group created'**
  String get groupsCreated;

  /// No description provided for @groupsOwner.
  ///
  /// In en, this message translates to:
  /// **'Owner'**
  String get groupsOwner;

  /// No description provided for @groupsMember.
  ///
  /// In en, this message translates to:
  /// **'Member'**
  String get groupsMember;

  /// No description provided for @groupsAdmin.
  ///
  /// In en, this message translates to:
  /// **'Admin'**
  String get groupsAdmin;

  /// No description provided for @groupsRemoveMember.
  ///
  /// In en, this message translates to:
  /// **'Remove Member'**
  String get groupsRemoveMember;

  /// No description provided for @groupsKickConfirm.
  ///
  /// In en, this message translates to:
  /// **'Remove {name} from the group?'**
  String groupsKickConfirm(String name);

  /// No description provided for @settingsTitle.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get settingsTitle;

  /// No description provided for @settingsAnonymous.
  ///
  /// In en, this message translates to:
  /// **'Anonymous'**
  String get settingsAnonymous;

  /// No description provided for @settingsNotLoaded.
  ///
  /// In en, this message translates to:
  /// **'Not loaded'**
  String get settingsNotLoaded;

  /// No description provided for @settingsTapToEditProfile.
  ///
  /// In en, this message translates to:
  /// **'Tap to edit profile'**
  String get settingsTapToEditProfile;

  /// No description provided for @settingsAppearance.
  ///
  /// In en, this message translates to:
  /// **'Appearance'**
  String get settingsAppearance;

  /// No description provided for @settingsDarkMode.
  ///
  /// In en, this message translates to:
  /// **'Dark Mode'**
  String get settingsDarkMode;

  /// No description provided for @settingsDarkModeSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Switch between dark and light theme'**
  String get settingsDarkModeSubtitle;

  /// No description provided for @settingsLanguage.
  ///
  /// In en, this message translates to:
  /// **'Language'**
  String get settingsLanguage;

  /// No description provided for @settingsLanguageSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Choose app language'**
  String get settingsLanguageSubtitle;

  /// No description provided for @settingsLanguageSystem.
  ///
  /// In en, this message translates to:
  /// **'System default'**
  String get settingsLanguageSystem;

  /// No description provided for @settingsLanguageEnglish.
  ///
  /// In en, this message translates to:
  /// **'English'**
  String get settingsLanguageEnglish;

  /// No description provided for @settingsLanguageTurkish.
  ///
  /// In en, this message translates to:
  /// **'Türkçe'**
  String get settingsLanguageTurkish;

  /// No description provided for @settingsLanguageItalian.
  ///
  /// In en, this message translates to:
  /// **'Italiano'**
  String get settingsLanguageItalian;

  /// No description provided for @settingsLanguageSpanish.
  ///
  /// In en, this message translates to:
  /// **'Español'**
  String get settingsLanguageSpanish;

  /// No description provided for @settingsLanguageRussian.
  ///
  /// In en, this message translates to:
  /// **'Русский'**
  String get settingsLanguageRussian;

  /// No description provided for @settingsLanguageDutch.
  ///
  /// In en, this message translates to:
  /// **'Nederlands'**
  String get settingsLanguageDutch;

  /// No description provided for @settingsLanguageGerman.
  ///
  /// In en, this message translates to:
  /// **'Deutsch'**
  String get settingsLanguageGerman;

  /// No description provided for @settingsLanguageChinese.
  ///
  /// In en, this message translates to:
  /// **'中文'**
  String get settingsLanguageChinese;

  /// No description provided for @settingsLanguageJapanese.
  ///
  /// In en, this message translates to:
  /// **'日本語'**
  String get settingsLanguageJapanese;

  /// No description provided for @settingsLanguagePortuguese.
  ///
  /// In en, this message translates to:
  /// **'Português'**
  String get settingsLanguagePortuguese;

  /// No description provided for @settingsBattery.
  ///
  /// In en, this message translates to:
  /// **'Battery'**
  String get settingsBattery;

  /// No description provided for @settingsDisableBatteryOpt.
  ///
  /// In en, this message translates to:
  /// **'Disable Battery Optimization'**
  String get settingsDisableBatteryOpt;

  /// No description provided for @settingsBatteryChecking.
  ///
  /// In en, this message translates to:
  /// **'Checking...'**
  String get settingsBatteryChecking;

  /// No description provided for @settingsBatteryDisabled.
  ///
  /// In en, this message translates to:
  /// **'Disabled — app can run in background'**
  String get settingsBatteryDisabled;

  /// No description provided for @settingsBatteryTapToKeep.
  ///
  /// In en, this message translates to:
  /// **'Tap to keep app alive in background'**
  String get settingsBatteryTapToKeep;

  /// No description provided for @settingsSecurity.
  ///
  /// In en, this message translates to:
  /// **'Security'**
  String get settingsSecurity;

  /// No description provided for @settingsExportSeedPhrase.
  ///
  /// In en, this message translates to:
  /// **'Export Seed Phrase'**
  String get settingsExportSeedPhrase;

  /// No description provided for @settingsExportSeedSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Back up your recovery phrase'**
  String get settingsExportSeedSubtitle;

  /// No description provided for @settingsAppLock.
  ///
  /// In en, this message translates to:
  /// **'App Lock'**
  String get settingsAppLock;

  /// No description provided for @settingsAppLockSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Require authentication'**
  String get settingsAppLockSubtitle;

  /// No description provided for @settingsExportSeedWarning.
  ///
  /// In en, this message translates to:
  /// **'Your seed phrase gives full access to your identity. Never share it with anyone.'**
  String get settingsExportSeedWarning;

  /// No description provided for @settingsShowSeed.
  ///
  /// In en, this message translates to:
  /// **'Show Seed'**
  String get settingsShowSeed;

  /// No description provided for @settingsYourSeedPhrase.
  ///
  /// In en, this message translates to:
  /// **'Your Seed Phrase'**
  String get settingsYourSeedPhrase;

  /// No description provided for @settingsSeedPhraseWarning.
  ///
  /// In en, this message translates to:
  /// **'Write these words down in order and store them safely. Anyone with this phrase can access your identity.'**
  String get settingsSeedPhraseWarning;

  /// No description provided for @settingsSeedCopied.
  ///
  /// In en, this message translates to:
  /// **'Seed phrase copied to clipboard'**
  String get settingsSeedCopied;

  /// No description provided for @settingsSeedNotAvailable.
  ///
  /// In en, this message translates to:
  /// **'Seed phrase not available for this identity. It was created before this feature was added.'**
  String get settingsSeedNotAvailable;

  /// No description provided for @settingsSeedError.
  ///
  /// In en, this message translates to:
  /// **'Unable to retrieve seed phrase'**
  String get settingsSeedError;

  /// No description provided for @settingsWallet.
  ///
  /// In en, this message translates to:
  /// **'Wallet'**
  String get settingsWallet;

  /// No description provided for @settingsHideZeroBalance.
  ///
  /// In en, this message translates to:
  /// **'Hide 0 Balance'**
  String get settingsHideZeroBalance;

  /// No description provided for @settingsHideZeroBalanceSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Hide coins with zero balance'**
  String get settingsHideZeroBalanceSubtitle;

  /// No description provided for @settingsData.
  ///
  /// In en, this message translates to:
  /// **'Data'**
  String get settingsData;

  /// No description provided for @settingsAutoSync.
  ///
  /// In en, this message translates to:
  /// **'Auto Sync'**
  String get settingsAutoSync;

  /// No description provided for @settingsAutoSyncSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Sync messages automatically every 15 minutes'**
  String get settingsAutoSyncSubtitle;

  /// No description provided for @settingsLastSync.
  ///
  /// In en, this message translates to:
  /// **'Last sync: {time}'**
  String settingsLastSync(String time);

  /// No description provided for @settingsSyncNow.
  ///
  /// In en, this message translates to:
  /// **'Sync Now'**
  String get settingsSyncNow;

  /// No description provided for @settingsSyncNowSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Force immediate sync'**
  String get settingsSyncNowSubtitle;

  /// No description provided for @settingsLogs.
  ///
  /// In en, this message translates to:
  /// **'Logs'**
  String get settingsLogs;

  /// No description provided for @settingsOpenLogsFolder.
  ///
  /// In en, this message translates to:
  /// **'Open Logs Folder'**
  String get settingsOpenLogsFolder;

  /// No description provided for @settingsOpenLogsFolderSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Open file manager at logs directory'**
  String get settingsOpenLogsFolderSubtitle;

  /// No description provided for @settingsShareLogs.
  ///
  /// In en, this message translates to:
  /// **'Share Logs'**
  String get settingsShareLogs;

  /// No description provided for @settingsShareLogsSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Zip and share log files'**
  String get settingsShareLogsSubtitle;

  /// No description provided for @settingsLogsFolderNotExist.
  ///
  /// In en, this message translates to:
  /// **'Logs folder does not exist yet'**
  String get settingsLogsFolderNotExist;

  /// No description provided for @settingsNoLogFiles.
  ///
  /// In en, this message translates to:
  /// **'No log files found'**
  String get settingsNoLogFiles;

  /// No description provided for @settingsFailedCreateZip.
  ///
  /// In en, this message translates to:
  /// **'Failed to create zip archive'**
  String get settingsFailedCreateZip;

  /// No description provided for @settingsNoLogsYet.
  ///
  /// In en, this message translates to:
  /// **'No logs yet. {debugInfo}'**
  String settingsNoLogsYet(String debugInfo);

  /// No description provided for @settingsIdentity.
  ///
  /// In en, this message translates to:
  /// **'Identity'**
  String get settingsIdentity;

  /// No description provided for @settingsFingerprint.
  ///
  /// In en, this message translates to:
  /// **'Fingerprint'**
  String get settingsFingerprint;

  /// No description provided for @settingsFingerprintCopied.
  ///
  /// In en, this message translates to:
  /// **'Fingerprint copied'**
  String get settingsFingerprintCopied;

  /// No description provided for @settingsDeleteAccount.
  ///
  /// In en, this message translates to:
  /// **'Delete Account'**
  String get settingsDeleteAccount;

  /// No description provided for @settingsDeleteAccountSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Permanently delete all data from device'**
  String get settingsDeleteAccountSubtitle;

  /// No description provided for @settingsDeleteAccountConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete Account?'**
  String get settingsDeleteAccountConfirm;

  /// No description provided for @settingsDeleteAccountWarning.
  ///
  /// In en, this message translates to:
  /// **'This will permanently delete all local data:'**
  String get settingsDeleteAccountWarning;

  /// No description provided for @settingsDeletePrivateKeys.
  ///
  /// In en, this message translates to:
  /// **'Private keys'**
  String get settingsDeletePrivateKeys;

  /// No description provided for @settingsDeleteWallets.
  ///
  /// In en, this message translates to:
  /// **'Wallets'**
  String get settingsDeleteWallets;

  /// No description provided for @settingsDeleteMessages.
  ///
  /// In en, this message translates to:
  /// **'Messages'**
  String get settingsDeleteMessages;

  /// No description provided for @settingsDeleteContacts.
  ///
  /// In en, this message translates to:
  /// **'Contacts'**
  String get settingsDeleteContacts;

  /// No description provided for @settingsDeleteGroups.
  ///
  /// In en, this message translates to:
  /// **'Groups'**
  String get settingsDeleteGroups;

  /// No description provided for @settingsDeleteSeedWarning.
  ///
  /// In en, this message translates to:
  /// **'Make sure you have backed up your seed phrase before deleting!'**
  String get settingsDeleteSeedWarning;

  /// No description provided for @settingsDeleteSuccess.
  ///
  /// In en, this message translates to:
  /// **'Account deleted successfully'**
  String get settingsDeleteSuccess;

  /// No description provided for @settingsDeleteFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to delete account: {error}'**
  String settingsDeleteFailed(String error);

  /// No description provided for @settingsAbout.
  ///
  /// In en, this message translates to:
  /// **'About'**
  String get settingsAbout;

  /// No description provided for @settingsUpdateAvailable.
  ///
  /// In en, this message translates to:
  /// **'Update Available'**
  String get settingsUpdateAvailable;

  /// No description provided for @settingsTapToDownload.
  ///
  /// In en, this message translates to:
  /// **'Tap to download'**
  String get settingsTapToDownload;

  /// No description provided for @settingsAppVersion.
  ///
  /// In en, this message translates to:
  /// **'DNA Messenger v{version}'**
  String settingsAppVersion(String version);

  /// No description provided for @settingsLibVersion.
  ///
  /// In en, this message translates to:
  /// **'Library v{version}'**
  String settingsLibVersion(String version);

  /// No description provided for @settingsPostQuantumMessenger.
  ///
  /// In en, this message translates to:
  /// **'Post-Quantum Encrypted Messenger'**
  String get settingsPostQuantumMessenger;

  /// No description provided for @settingsCryptoStack.
  ///
  /// In en, this message translates to:
  /// **'CRYPTO STACK'**
  String get settingsCryptoStack;

  /// No description provided for @profileTitle.
  ///
  /// In en, this message translates to:
  /// **'Edit Profile'**
  String get profileTitle;

  /// No description provided for @profileInfo.
  ///
  /// In en, this message translates to:
  /// **'Profile Info'**
  String get profileInfo;

  /// No description provided for @profileBio.
  ///
  /// In en, this message translates to:
  /// **'Bio'**
  String get profileBio;

  /// No description provided for @profileLocation.
  ///
  /// In en, this message translates to:
  /// **'Location'**
  String get profileLocation;

  /// No description provided for @profileWebsite.
  ///
  /// In en, this message translates to:
  /// **'Website'**
  String get profileWebsite;

  /// No description provided for @profileWalletAddresses.
  ///
  /// In en, this message translates to:
  /// **'Wallet Addresses'**
  String get profileWalletAddresses;

  /// No description provided for @profileSave.
  ///
  /// In en, this message translates to:
  /// **'Save Profile'**
  String get profileSave;

  /// No description provided for @profileShareQR.
  ///
  /// In en, this message translates to:
  /// **'Share My QR Code'**
  String get profileShareQR;

  /// No description provided for @profileAvatar.
  ///
  /// In en, this message translates to:
  /// **'Avatar'**
  String get profileAvatar;

  /// No description provided for @profileTakeSelfie.
  ///
  /// In en, this message translates to:
  /// **'Take a Selfie'**
  String get profileTakeSelfie;

  /// No description provided for @profileChooseFromGallery.
  ///
  /// In en, this message translates to:
  /// **'Choose from Gallery'**
  String get profileChooseFromGallery;

  /// No description provided for @profileSaved.
  ///
  /// In en, this message translates to:
  /// **'Profile saved'**
  String get profileSaved;

  /// No description provided for @profileSaveFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to save profile: {error}'**
  String profileSaveFailed(String error);

  /// No description provided for @profileCropTitle.
  ///
  /// In en, this message translates to:
  /// **'Crop Avatar'**
  String get profileCropTitle;

  /// No description provided for @profileCropSave.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get profileCropSave;

  /// No description provided for @contactProfileFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to load profile'**
  String get contactProfileFailed;

  /// No description provided for @contactProfileUnknownError.
  ///
  /// In en, this message translates to:
  /// **'Unknown error'**
  String get contactProfileUnknownError;

  /// No description provided for @contactProfileNickname.
  ///
  /// In en, this message translates to:
  /// **'Nickname'**
  String get contactProfileNickname;

  /// No description provided for @contactProfileNicknameNotSet.
  ///
  /// In en, this message translates to:
  /// **'Not set (tap to add)'**
  String get contactProfileNicknameNotSet;

  /// No description provided for @contactProfileOriginal.
  ///
  /// In en, this message translates to:
  /// **'Original: {name}'**
  String contactProfileOriginal(String name);

  /// No description provided for @contactProfileSetNickname.
  ///
  /// In en, this message translates to:
  /// **'Set Nickname'**
  String get contactProfileSetNickname;

  /// No description provided for @contactProfileOriginalName.
  ///
  /// In en, this message translates to:
  /// **'Original name: {name}'**
  String contactProfileOriginalName(String name);

  /// No description provided for @contactProfileNicknameLabel.
  ///
  /// In en, this message translates to:
  /// **'Nickname'**
  String get contactProfileNicknameLabel;

  /// No description provided for @contactProfileNicknameHint.
  ///
  /// In en, this message translates to:
  /// **'Enter custom nickname'**
  String get contactProfileNicknameHint;

  /// No description provided for @contactProfileNicknameHelper.
  ///
  /// In en, this message translates to:
  /// **'Leave empty to use original name'**
  String get contactProfileNicknameHelper;

  /// No description provided for @contactProfileNicknameCleared.
  ///
  /// In en, this message translates to:
  /// **'Nickname cleared'**
  String get contactProfileNicknameCleared;

  /// No description provided for @contactProfileNicknameSet.
  ///
  /// In en, this message translates to:
  /// **'Nickname set to \"{name}\"'**
  String contactProfileNicknameSet(String name);

  /// No description provided for @contactProfileNicknameFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to set nickname: {error}'**
  String contactProfileNicknameFailed(String error);

  /// No description provided for @contactProfileCopyFingerprint.
  ///
  /// In en, this message translates to:
  /// **'Copy fingerprint'**
  String get contactProfileCopyFingerprint;

  /// No description provided for @contactProfileNoProfile.
  ///
  /// In en, this message translates to:
  /// **'No profile published'**
  String get contactProfileNoProfile;

  /// No description provided for @contactProfileNoProfileSubtitle.
  ///
  /// In en, this message translates to:
  /// **'This user has not published their profile yet.'**
  String get contactProfileNoProfileSubtitle;

  /// No description provided for @contactProfileBio.
  ///
  /// In en, this message translates to:
  /// **'Bio'**
  String get contactProfileBio;

  /// No description provided for @contactProfileInfo.
  ///
  /// In en, this message translates to:
  /// **'Info'**
  String get contactProfileInfo;

  /// No description provided for @contactProfileWebsite.
  ///
  /// In en, this message translates to:
  /// **'Website'**
  String get contactProfileWebsite;

  /// No description provided for @identityTitle.
  ///
  /// In en, this message translates to:
  /// **'DNA Messenger'**
  String get identityTitle;

  /// No description provided for @identityWelcome.
  ///
  /// In en, this message translates to:
  /// **'Welcome to DNA Messenger'**
  String get identityWelcome;

  /// No description provided for @identityGenerateSeed.
  ///
  /// In en, this message translates to:
  /// **'Generate New Seed'**
  String get identityGenerateSeed;

  /// No description provided for @identityHaveSeed.
  ///
  /// In en, this message translates to:
  /// **'I Have a Seed Phrase'**
  String get identityHaveSeed;

  /// No description provided for @identityYourRecoveryPhrase.
  ///
  /// In en, this message translates to:
  /// **'Your Recovery Phrase'**
  String get identityYourRecoveryPhrase;

  /// No description provided for @identityRecoveryPhraseWarning.
  ///
  /// In en, this message translates to:
  /// **'Write down these words and keep them safe. They are the only way to recover your account.'**
  String get identityRecoveryPhraseWarning;

  /// No description provided for @identityConfirmSaved.
  ///
  /// In en, this message translates to:
  /// **'I have saved my recovery phrase'**
  String get identityConfirmSaved;

  /// No description provided for @identityEnterRecoveryPhrase.
  ///
  /// In en, this message translates to:
  /// **'Enter Recovery Phrase'**
  String get identityEnterRecoveryPhrase;

  /// No description provided for @identityEnterRecoveryPhraseHint.
  ///
  /// In en, this message translates to:
  /// **'Enter your 12 or 24 word recovery phrase'**
  String get identityEnterRecoveryPhraseHint;

  /// No description provided for @identityChooseName.
  ///
  /// In en, this message translates to:
  /// **'Choose Your Name'**
  String get identityChooseName;

  /// No description provided for @identityChooseNameHint.
  ///
  /// In en, this message translates to:
  /// **'Enter a display name'**
  String get identityChooseNameHint;

  /// No description provided for @identityRegisterContinue.
  ///
  /// In en, this message translates to:
  /// **'Register & Continue'**
  String get identityRegisterContinue;

  /// No description provided for @identityRegistering.
  ///
  /// In en, this message translates to:
  /// **'Registering...'**
  String get identityRegistering;

  /// No description provided for @identityNameTaken.
  ///
  /// In en, this message translates to:
  /// **'This name is already taken'**
  String get identityNameTaken;

  /// No description provided for @identityNameInvalid.
  ///
  /// In en, this message translates to:
  /// **'Name must be 3-20 characters'**
  String get identityNameInvalid;

  /// No description provided for @identityCreating.
  ///
  /// In en, this message translates to:
  /// **'Creating your identity...'**
  String get identityCreating;

  /// No description provided for @identityRestoring.
  ///
  /// In en, this message translates to:
  /// **'Restoring your identity...'**
  String get identityRestoring;

  /// No description provided for @wallTitle.
  ///
  /// In en, this message translates to:
  /// **'Home'**
  String get wallTitle;

  /// No description provided for @wallWelcome.
  ///
  /// In en, this message translates to:
  /// **'Welcome to your timeline!'**
  String get wallWelcome;

  /// No description provided for @wallWelcomeSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Follow people and channels to see their posts here.'**
  String get wallWelcomeSubtitle;

  /// No description provided for @wallNewPost.
  ///
  /// In en, this message translates to:
  /// **'New Post'**
  String get wallNewPost;

  /// No description provided for @wallDeletePost.
  ///
  /// In en, this message translates to:
  /// **'Delete Post'**
  String get wallDeletePost;

  /// No description provided for @wallDeletePostConfirm.
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to delete this post?'**
  String get wallDeletePostConfirm;

  /// No description provided for @wallRepost.
  ///
  /// In en, this message translates to:
  /// **'Repost'**
  String get wallRepost;

  /// No description provided for @wallReposted.
  ///
  /// In en, this message translates to:
  /// **'Reposted'**
  String get wallReposted;

  /// No description provided for @wallComments.
  ///
  /// In en, this message translates to:
  /// **'Comments'**
  String get wallComments;

  /// No description provided for @wallNoComments.
  ///
  /// In en, this message translates to:
  /// **'No comments yet'**
  String get wallNoComments;

  /// No description provided for @wallLoadingComments.
  ///
  /// In en, this message translates to:
  /// **'Loading comments...'**
  String get wallLoadingComments;

  /// No description provided for @wallWriteComment.
  ///
  /// In en, this message translates to:
  /// **'Write a comment...'**
  String get wallWriteComment;

  /// No description provided for @wallWriteReply.
  ///
  /// In en, this message translates to:
  /// **'Write a reply...'**
  String get wallWriteReply;

  /// No description provided for @wallViewAllComments.
  ///
  /// In en, this message translates to:
  /// **'View all {count} comments'**
  String wallViewAllComments(int count);

  /// No description provided for @wallPostDetail.
  ///
  /// In en, this message translates to:
  /// **'Post'**
  String get wallPostDetail;

  /// No description provided for @wallCopy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get wallCopy;

  /// No description provided for @wallReply.
  ///
  /// In en, this message translates to:
  /// **'Reply'**
  String get wallReply;

  /// No description provided for @wallDelete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get wallDelete;

  /// No description provided for @walletTitle.
  ///
  /// In en, this message translates to:
  /// **'Wallet'**
  String get walletTitle;

  /// No description provided for @walletTotalBalance.
  ///
  /// In en, this message translates to:
  /// **'Total Balance'**
  String get walletTotalBalance;

  /// No description provided for @walletSend.
  ///
  /// In en, this message translates to:
  /// **'Send'**
  String get walletSend;

  /// No description provided for @walletReceive.
  ///
  /// In en, this message translates to:
  /// **'Receive'**
  String get walletReceive;

  /// No description provided for @walletSwap.
  ///
  /// In en, this message translates to:
  /// **'Swap'**
  String get walletSwap;

  /// No description provided for @walletHistory.
  ///
  /// In en, this message translates to:
  /// **'History'**
  String get walletHistory;

  /// No description provided for @walletNoTransactions.
  ///
  /// In en, this message translates to:
  /// **'No transactions yet'**
  String get walletNoTransactions;

  /// No description provided for @walletCopyAddress.
  ///
  /// In en, this message translates to:
  /// **'Copy Address'**
  String get walletCopyAddress;

  /// No description provided for @walletAddressCopied.
  ///
  /// In en, this message translates to:
  /// **'Address copied'**
  String get walletAddressCopied;

  /// No description provided for @walletSendTitle.
  ///
  /// In en, this message translates to:
  /// **'Send {coin}'**
  String walletSendTitle(String coin);

  /// No description provided for @walletRecipientAddress.
  ///
  /// In en, this message translates to:
  /// **'Recipient Address'**
  String get walletRecipientAddress;

  /// No description provided for @walletAmount.
  ///
  /// In en, this message translates to:
  /// **'Amount'**
  String get walletAmount;

  /// No description provided for @walletMax.
  ///
  /// In en, this message translates to:
  /// **'MAX'**
  String get walletMax;

  /// No description provided for @walletSendConfirm.
  ///
  /// In en, this message translates to:
  /// **'Confirm Send'**
  String get walletSendConfirm;

  /// No description provided for @walletSending.
  ///
  /// In en, this message translates to:
  /// **'Sending...'**
  String get walletSending;

  /// No description provided for @walletSendSuccess.
  ///
  /// In en, this message translates to:
  /// **'Transaction sent'**
  String get walletSendSuccess;

  /// No description provided for @walletSendFailed.
  ///
  /// In en, this message translates to:
  /// **'Transaction failed: {error}'**
  String walletSendFailed(String error);

  /// No description provided for @walletReceiveTitle.
  ///
  /// In en, this message translates to:
  /// **'Receive {coin}'**
  String walletReceiveTitle(String coin);

  /// No description provided for @walletAddressBook.
  ///
  /// In en, this message translates to:
  /// **'Address Book'**
  String get walletAddressBook;

  /// No description provided for @walletAddAddress.
  ///
  /// In en, this message translates to:
  /// **'Add Address'**
  String get walletAddAddress;

  /// No description provided for @walletEditAddress.
  ///
  /// In en, this message translates to:
  /// **'Edit Address'**
  String get walletEditAddress;

  /// No description provided for @walletDeleteAddress.
  ///
  /// In en, this message translates to:
  /// **'Delete Address'**
  String get walletDeleteAddress;

  /// No description provided for @walletLabel.
  ///
  /// In en, this message translates to:
  /// **'Label'**
  String get walletLabel;

  /// No description provided for @walletAddress.
  ///
  /// In en, this message translates to:
  /// **'Address'**
  String get walletAddress;

  /// No description provided for @walletNetwork.
  ///
  /// In en, this message translates to:
  /// **'Network'**
  String get walletNetwork;

  /// No description provided for @qrScannerTitle.
  ///
  /// In en, this message translates to:
  /// **'QR Scanner'**
  String get qrScannerTitle;

  /// No description provided for @qrAddContact.
  ///
  /// In en, this message translates to:
  /// **'Add Contact'**
  String get qrAddContact;

  /// No description provided for @qrAuthRequest.
  ///
  /// In en, this message translates to:
  /// **'Authorization Request'**
  String get qrAuthRequest;

  /// No description provided for @qrContent.
  ///
  /// In en, this message translates to:
  /// **'QR Content'**
  String get qrContent;

  /// No description provided for @qrSendContactRequest.
  ///
  /// In en, this message translates to:
  /// **'Send Contact Request'**
  String get qrSendContactRequest;

  /// No description provided for @qrScanAnother.
  ///
  /// In en, this message translates to:
  /// **'Scan Another'**
  String get qrScanAnother;

  /// No description provided for @qrCopyFingerprint.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get qrCopyFingerprint;

  /// No description provided for @qrRequestSent.
  ///
  /// In en, this message translates to:
  /// **'Contact request sent'**
  String get qrRequestSent;

  /// No description provided for @qrInvalidCode.
  ///
  /// In en, this message translates to:
  /// **'Invalid QR code'**
  String get qrInvalidCode;

  /// No description provided for @moreTitle.
  ///
  /// In en, this message translates to:
  /// **'More'**
  String get moreTitle;

  /// No description provided for @moreWallet.
  ///
  /// In en, this message translates to:
  /// **'Wallet'**
  String get moreWallet;

  /// No description provided for @moreQRScanner.
  ///
  /// In en, this message translates to:
  /// **'QR Scanner'**
  String get moreQRScanner;

  /// No description provided for @moreAddresses.
  ///
  /// In en, this message translates to:
  /// **'Addresses'**
  String get moreAddresses;

  /// No description provided for @moreStarred.
  ///
  /// In en, this message translates to:
  /// **'Starred'**
  String get moreStarred;

  /// No description provided for @moreContacts.
  ///
  /// In en, this message translates to:
  /// **'Contacts'**
  String get moreContacts;

  /// No description provided for @moreSettings.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get moreSettings;

  /// No description provided for @moreAppLock.
  ///
  /// In en, this message translates to:
  /// **'App Lock'**
  String get moreAppLock;

  /// No description provided for @lockTitle.
  ///
  /// In en, this message translates to:
  /// **'DNA Messenger'**
  String get lockTitle;

  /// No description provided for @lockEnterPIN.
  ///
  /// In en, this message translates to:
  /// **'Enter PIN to unlock'**
  String get lockEnterPIN;

  /// No description provided for @lockIncorrectPIN.
  ///
  /// In en, this message translates to:
  /// **'Incorrect PIN'**
  String get lockIncorrectPIN;

  /// No description provided for @lockUseBiometrics.
  ///
  /// In en, this message translates to:
  /// **'Use biometrics to unlock'**
  String get lockUseBiometrics;

  /// No description provided for @appLockTitle.
  ///
  /// In en, this message translates to:
  /// **'App Lock'**
  String get appLockTitle;

  /// No description provided for @appLockEnable.
  ///
  /// In en, this message translates to:
  /// **'Enable App Lock'**
  String get appLockEnable;

  /// No description provided for @appLockUseBiometrics.
  ///
  /// In en, this message translates to:
  /// **'Use Biometrics'**
  String get appLockUseBiometrics;

  /// No description provided for @appLockChangePIN.
  ///
  /// In en, this message translates to:
  /// **'Change PIN'**
  String get appLockChangePIN;

  /// No description provided for @appLockSetPIN.
  ///
  /// In en, this message translates to:
  /// **'Set PIN'**
  String get appLockSetPIN;

  /// No description provided for @appLockConfirmPIN.
  ///
  /// In en, this message translates to:
  /// **'Confirm PIN'**
  String get appLockConfirmPIN;

  /// No description provided for @appLockPINMismatch.
  ///
  /// In en, this message translates to:
  /// **'PINs do not match'**
  String get appLockPINMismatch;

  /// No description provided for @appLockPINSet.
  ///
  /// In en, this message translates to:
  /// **'PIN set successfully'**
  String get appLockPINSet;

  /// No description provided for @appLockPINChanged.
  ///
  /// In en, this message translates to:
  /// **'PIN changed'**
  String get appLockPINChanged;

  /// No description provided for @appLockEnterCurrentPIN.
  ///
  /// In en, this message translates to:
  /// **'Enter current PIN'**
  String get appLockEnterCurrentPIN;

  /// No description provided for @appLockEnterNewPIN.
  ///
  /// In en, this message translates to:
  /// **'Enter new PIN'**
  String get appLockEnterNewPIN;

  /// No description provided for @starredTitle.
  ///
  /// In en, this message translates to:
  /// **'Starred Messages'**
  String get starredTitle;

  /// No description provided for @starredEmpty.
  ///
  /// In en, this message translates to:
  /// **'No starred messages'**
  String get starredEmpty;

  /// No description provided for @blockedTitle.
  ///
  /// In en, this message translates to:
  /// **'Blocked Users'**
  String get blockedTitle;

  /// No description provided for @blockedEmpty.
  ///
  /// In en, this message translates to:
  /// **'No blocked users'**
  String get blockedEmpty;

  /// No description provided for @blockedUnblock.
  ///
  /// In en, this message translates to:
  /// **'Unblock'**
  String get blockedUnblock;

  /// No description provided for @blockedUnblockConfirm.
  ///
  /// In en, this message translates to:
  /// **'Unblock {name}?'**
  String blockedUnblockConfirm(String name);

  /// No description provided for @updateTitle.
  ///
  /// In en, this message translates to:
  /// **'Update Required'**
  String get updateTitle;

  /// No description provided for @updateMessage.
  ///
  /// In en, this message translates to:
  /// **'A newer version is required to continue using DNA Messenger.'**
  String get updateMessage;

  /// No description provided for @updateDownload.
  ///
  /// In en, this message translates to:
  /// **'Download Update'**
  String get updateDownload;

  /// No description provided for @updateAvailableTitle.
  ///
  /// In en, this message translates to:
  /// **'New Version Available'**
  String get updateAvailableTitle;

  /// No description provided for @updateAvailableMessage.
  ///
  /// In en, this message translates to:
  /// **'A new version of DNA Messenger is available. Update now for the latest features and improvements.'**
  String get updateAvailableMessage;

  /// No description provided for @updateLater.
  ///
  /// In en, this message translates to:
  /// **'Later'**
  String get updateLater;

  /// No description provided for @cancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// No description provided for @save.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// No description provided for @delete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get delete;

  /// No description provided for @done.
  ///
  /// In en, this message translates to:
  /// **'Done'**
  String get done;

  /// No description provided for @copy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get copy;

  /// No description provided for @ok.
  ///
  /// In en, this message translates to:
  /// **'OK'**
  String get ok;

  /// No description provided for @yes.
  ///
  /// In en, this message translates to:
  /// **'Yes'**
  String get yes;

  /// No description provided for @no.
  ///
  /// In en, this message translates to:
  /// **'No'**
  String get no;

  /// No description provided for @error.
  ///
  /// In en, this message translates to:
  /// **'Error'**
  String get error;

  /// No description provided for @success.
  ///
  /// In en, this message translates to:
  /// **'Success'**
  String get success;

  /// No description provided for @loading.
  ///
  /// In en, this message translates to:
  /// **'Loading...'**
  String get loading;

  /// No description provided for @pleaseWait.
  ///
  /// In en, this message translates to:
  /// **'Please wait...'**
  String get pleaseWait;

  /// No description provided for @copied.
  ///
  /// In en, this message translates to:
  /// **'Copied'**
  String get copied;

  /// No description provided for @failed.
  ///
  /// In en, this message translates to:
  /// **'Failed: {error}'**
  String failed(String error);

  /// No description provided for @retry.
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get retry;

  /// No description provided for @continueButton.
  ///
  /// In en, this message translates to:
  /// **'Continue'**
  String get continueButton;

  /// No description provided for @approve.
  ///
  /// In en, this message translates to:
  /// **'Approve'**
  String get approve;

  /// No description provided for @deny.
  ///
  /// In en, this message translates to:
  /// **'Deny'**
  String get deny;

  /// No description provided for @verify.
  ///
  /// In en, this message translates to:
  /// **'Verify'**
  String get verify;

  /// No description provided for @copyToClipboard.
  ///
  /// In en, this message translates to:
  /// **'Copy to Clipboard'**
  String get copyToClipboard;

  /// No description provided for @copiedToClipboard.
  ///
  /// In en, this message translates to:
  /// **'Copied to clipboard'**
  String get copiedToClipboard;

  /// No description provided for @pasteFromClipboard.
  ///
  /// In en, this message translates to:
  /// **'Paste from Clipboard'**
  String get pasteFromClipboard;

  /// No description provided for @biometricsSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Fingerprint or Face ID'**
  String get biometricsSubtitle;

  /// No description provided for @changePINSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Update your unlock PIN'**
  String get changePINSubtitle;

  /// No description provided for @biometricFailed.
  ///
  /// In en, this message translates to:
  /// **'Biometric authentication failed'**
  String get biometricFailed;

  /// No description provided for @contactRequestsWillAppear.
  ///
  /// In en, this message translates to:
  /// **'Contact requests will appear here'**
  String get contactRequestsWillAppear;

  /// No description provided for @blockedUsersWillAppear.
  ///
  /// In en, this message translates to:
  /// **'Users you block will appear here'**
  String get blockedUsersWillAppear;

  /// No description provided for @failedToLoadTimeline.
  ///
  /// In en, this message translates to:
  /// **'Failed to load timeline'**
  String get failedToLoadTimeline;

  /// No description provided for @userUnblocked.
  ///
  /// In en, this message translates to:
  /// **'User unblocked'**
  String get userUnblocked;

  /// No description provided for @backupFound.
  ///
  /// In en, this message translates to:
  /// **'Backup Found'**
  String get backupFound;

  /// No description provided for @approvedContact.
  ///
  /// In en, this message translates to:
  /// **'Approved {name}'**
  String approvedContact(String name);

  /// No description provided for @deniedContact.
  ///
  /// In en, this message translates to:
  /// **'Denied {name}'**
  String deniedContact(String name);

  /// No description provided for @blockedContact.
  ///
  /// In en, this message translates to:
  /// **'Blocked {name}'**
  String blockedContact(String name);

  /// No description provided for @unsubscribeFrom.
  ///
  /// In en, this message translates to:
  /// **'Unsubscribe from {name}'**
  String unsubscribeFrom(String name);

  /// No description provided for @chatSenderDeletedThis.
  ///
  /// In en, this message translates to:
  /// **'Sender deleted this'**
  String get chatSenderDeletedThis;

  /// No description provided for @chatDeleteMessageTitle.
  ///
  /// In en, this message translates to:
  /// **'Delete Message'**
  String get chatDeleteMessageTitle;

  /// No description provided for @chatDeleteMessageConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete this message from all your devices and notify the other person?'**
  String get chatDeleteMessageConfirm;

  /// No description provided for @chatDeleteConversation.
  ///
  /// In en, this message translates to:
  /// **'Delete Conversation'**
  String get chatDeleteConversation;

  /// No description provided for @chatDeleteConversationTitle.
  ///
  /// In en, this message translates to:
  /// **'Delete Conversation'**
  String get chatDeleteConversationTitle;

  /// No description provided for @chatDeleteConversationConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete all messages in this conversation? This will delete from all your devices.'**
  String get chatDeleteConversationConfirm;

  /// No description provided for @chatConversationDeleted.
  ///
  /// In en, this message translates to:
  /// **'Conversation deleted'**
  String get chatConversationDeleted;

  /// No description provided for @chatDeleteConversationFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to delete conversation'**
  String get chatDeleteConversationFailed;

  /// No description provided for @settingsDeleteAllMessages.
  ///
  /// In en, this message translates to:
  /// **'Delete All Messages'**
  String get settingsDeleteAllMessages;

  /// No description provided for @settingsDeleteAllMessagesSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Remove all messages from all devices'**
  String get settingsDeleteAllMessagesSubtitle;

  /// No description provided for @settingsDeleteAllMessagesTitle.
  ///
  /// In en, this message translates to:
  /// **'Delete All Messages?'**
  String get settingsDeleteAllMessagesTitle;

  /// No description provided for @settingsDeleteAllMessagesWarning.
  ///
  /// In en, this message translates to:
  /// **'This will permanently delete ALL messages from ALL conversations across all your devices. This cannot be undone.'**
  String get settingsDeleteAllMessagesWarning;

  /// No description provided for @settingsAllMessagesDeleted.
  ///
  /// In en, this message translates to:
  /// **'All messages deleted'**
  String get settingsAllMessagesDeleted;

  /// No description provided for @settingsDeleteAllMessagesFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to delete messages'**
  String get settingsDeleteAllMessagesFailed;

  /// No description provided for @settingsDeleteEverything.
  ///
  /// In en, this message translates to:
  /// **'Delete Everything'**
  String get settingsDeleteEverything;

  /// No description provided for @txDetailSent.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get txDetailSent;

  /// No description provided for @txDetailReceived.
  ///
  /// In en, this message translates to:
  /// **'Received'**
  String get txDetailReceived;

  /// No description provided for @txDetailDenied.
  ///
  /// In en, this message translates to:
  /// **'Transaction Denied'**
  String get txDetailDenied;

  /// No description provided for @txDetailFrom.
  ///
  /// In en, this message translates to:
  /// **'From'**
  String get txDetailFrom;

  /// No description provided for @txDetailTo.
  ///
  /// In en, this message translates to:
  /// **'To'**
  String get txDetailTo;

  /// No description provided for @txDetailTransactionHash.
  ///
  /// In en, this message translates to:
  /// **'Transaction Hash'**
  String get txDetailTransactionHash;

  /// No description provided for @txDetailTime.
  ///
  /// In en, this message translates to:
  /// **'Time'**
  String get txDetailTime;

  /// No description provided for @txDetailNetwork.
  ///
  /// In en, this message translates to:
  /// **'Network'**
  String get txDetailNetwork;

  /// No description provided for @txDetailAddressCopied.
  ///
  /// In en, this message translates to:
  /// **'Address copied'**
  String get txDetailAddressCopied;

  /// No description provided for @txDetailHashCopied.
  ///
  /// In en, this message translates to:
  /// **'Hash copied'**
  String get txDetailHashCopied;

  /// No description provided for @txDetailAddToAddressBook.
  ///
  /// In en, this message translates to:
  /// **'Add to Address Book'**
  String get txDetailAddToAddressBook;

  /// No description provided for @txDetailClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get txDetailClose;

  /// No description provided for @txDetailAddedToAddressBook.
  ///
  /// In en, this message translates to:
  /// **'Added \"{label}\" to address book'**
  String txDetailAddedToAddressBook(String label);

  /// No description provided for @txDetailFailedToAdd.
  ///
  /// In en, this message translates to:
  /// **'Failed to add: {error}'**
  String txDetailFailedToAdd(String error);

  /// No description provided for @swapTitle.
  ///
  /// In en, this message translates to:
  /// **'Swap'**
  String get swapTitle;

  /// No description provided for @swapConfirm.
  ///
  /// In en, this message translates to:
  /// **'Confirm Swap'**
  String get swapConfirm;

  /// No description provided for @swapYouPay.
  ///
  /// In en, this message translates to:
  /// **'You pay'**
  String get swapYouPay;

  /// No description provided for @swapYouReceive.
  ///
  /// In en, this message translates to:
  /// **'You receive'**
  String get swapYouReceive;

  /// No description provided for @swapGetQuote.
  ///
  /// In en, this message translates to:
  /// **'Get Quote'**
  String get swapGetQuote;

  /// No description provided for @swapNoQuotes.
  ///
  /// In en, this message translates to:
  /// **'No quotes available'**
  String get swapNoQuotes;

  /// No description provided for @swapRate.
  ///
  /// In en, this message translates to:
  /// **'Rate'**
  String get swapRate;

  /// No description provided for @swapSlippage.
  ///
  /// In en, this message translates to:
  /// **'Slippage'**
  String get swapSlippage;

  /// No description provided for @swapFee.
  ///
  /// In en, this message translates to:
  /// **'Fee'**
  String get swapFee;

  /// No description provided for @swapDex.
  ///
  /// In en, this message translates to:
  /// **'DEX'**
  String get swapDex;

  /// No description provided for @swapImpact.
  ///
  /// In en, this message translates to:
  /// **'Impact: {value}%'**
  String swapImpact(String value);

  /// No description provided for @swapFeeValue.
  ///
  /// In en, this message translates to:
  /// **'Fee: {value}'**
  String swapFeeValue(String value);

  /// No description provided for @swapBestPrice.
  ///
  /// In en, this message translates to:
  /// **'Best price from {count} exchanges'**
  String swapBestPrice(int count);

  /// No description provided for @swapSuccess.
  ///
  /// In en, this message translates to:
  /// **'Swapped {amountIn} {fromToken} → {amountOut} {toToken} via {dex}'**
  String swapSuccess(
    String amountIn,
    String fromToken,
    String amountOut,
    String toToken,
    String dex,
  );

  /// No description provided for @swapFailed.
  ///
  /// In en, this message translates to:
  /// **'Swap failed: {error}'**
  String swapFailed(String error);
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>[
    'de',
    'en',
    'es',
    'it',
    'ja',
    'nl',
    'pt',
    'ru',
    'tr',
    'zh',
  ].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'de':
      return AppLocalizationsDe();
    case 'en':
      return AppLocalizationsEn();
    case 'es':
      return AppLocalizationsEs();
    case 'it':
      return AppLocalizationsIt();
    case 'ja':
      return AppLocalizationsJa();
    case 'nl':
      return AppLocalizationsNl();
    case 'pt':
      return AppLocalizationsPt();
    case 'ru':
      return AppLocalizationsRu();
    case 'tr':
      return AppLocalizationsTr();
    case 'zh':
      return AppLocalizationsZh();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
