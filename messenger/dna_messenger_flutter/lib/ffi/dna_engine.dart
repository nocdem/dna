// High-level Dart wrapper for DNA Messenger Engine
// Converts C callbacks to Dart Futures/Streams

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'dna_bindings.dart';

// =============================================================================
// DART MODELS
// =============================================================================

/// Contact information
class Contact {
  final String fingerprint;
  final String displayName;
  final String nickname;
  final bool isOnline;
  final DateTime lastSeen;

  Contact({
    required this.fingerprint,
    required this.displayName,
    required this.nickname,
    required this.isOnline,
    required this.lastSeen,
  });

  /// Get effective display name (nickname if set, otherwise displayName)
  String get effectiveName => nickname.isNotEmpty ? nickname : displayName;

  factory Contact.fromNative(dna_contact_t native) {
    return Contact(
      fingerprint: native.fingerprint.toDartString(129),
      displayName: native.display_name.toDartString(256),
      nickname: native.nickname.toDartString(64),
      isOnline: native.is_online,
      lastSeen: DateTime.fromMillisecondsSinceEpoch(native.last_seen * 1000),
    );
  }

  /// Create a copy with updated fields
  Contact copyWith({
    String? fingerprint,
    String? displayName,
    String? nickname,
    bool? isOnline,
    DateTime? lastSeen,
  }) {
    return Contact(
      fingerprint: fingerprint ?? this.fingerprint,
      displayName: displayName ?? this.displayName,
      nickname: nickname ?? this.nickname,
      isOnline: isOnline ?? this.isOnline,
      lastSeen: lastSeen ?? this.lastSeen,
    );
  }
}

/// Address book entry (wallet addresses)
class AddressBookEntry {
  final int id;
  final String address;
  final String label;
  final String network;
  final String notes;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime lastUsed;
  final int useCount;

  AddressBookEntry({
    required this.id,
    required this.address,
    required this.label,
    required this.network,
    required this.notes,
    required this.createdAt,
    required this.updatedAt,
    required this.lastUsed,
    required this.useCount,
  });

  factory AddressBookEntry.fromNative(dna_addressbook_entry_t native) {
    return AddressBookEntry(
      id: native.id,
      address: native.address.toDartString(128),
      label: native.label.toDartString(64),
      network: native.network.toDartString(32),
      notes: native.notes.toDartString(256),
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
      updatedAt: DateTime.fromMillisecondsSinceEpoch(native.updated_at * 1000),
      lastUsed: DateTime.fromMillisecondsSinceEpoch(native.last_used * 1000),
      useCount: native.use_count,
    );
  }

  /// Create a copy with updated fields
  AddressBookEntry copyWith({
    int? id,
    String? address,
    String? label,
    String? network,
    String? notes,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? lastUsed,
    int? useCount,
  }) {
    return AddressBookEntry(
      id: id ?? this.id,
      address: address ?? this.address,
      label: label ?? this.label,
      network: network ?? this.network,
      notes: notes ?? this.notes,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      lastUsed: lastUsed ?? this.lastUsed,
      useCount: useCount ?? this.useCount,
    );
  }

  /// Get network display name
  String get networkDisplayName {
    switch (network.toLowerCase()) {
      case 'backbone':
        return 'Cellframe';
      case 'ethereum':
        return 'Ethereum';
      case 'solana':
        return 'Solana';
      case 'tron':
        return 'TRON';
      default:
        return network;
    }
  }
}

/// Group member information
class GroupMember {
  final String fingerprint;
  final DateTime addedAt;
  final bool isOwner;

  GroupMember({
    required this.fingerprint,
    required this.addedAt,
    required this.isOwner,
  });

  factory GroupMember.fromNative(dna_group_member_t native) {
    return GroupMember(
      fingerprint: native.fingerprint.toDartString(129),
      addedAt: DateTime.fromMillisecondsSinceEpoch(native.added_at * 1000),
      isOwner: native.is_owner,
    );
  }
}

/// Extended group information (includes GEK version)
class GroupInfo {
  final String uuid;
  final String name;
  final String creator;
  final int memberCount;
  final DateTime createdAt;
  final bool isOwner;
  final int gekVersion;

  GroupInfo({
    required this.uuid,
    required this.name,
    required this.creator,
    required this.memberCount,
    required this.createdAt,
    required this.isOwner,
    required this.gekVersion,
  });

  factory GroupInfo.fromNative(dna_group_info_t native) {
    return GroupInfo(
      uuid: native.uuid.toDartString(37),
      name: native.name.toDartString(256),
      creator: native.creator.toDartString(129),
      memberCount: native.member_count,
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
      isOwner: native.is_owner,
      gekVersion: native.gek_version,
    );
  }
}

/// Contact request information (ICQ-style request)
class ContactRequest {
  final String fingerprint;
  final String displayName;
  final String message;
  final DateTime requestedAt;
  final ContactRequestStatus status;

  ContactRequest({
    required this.fingerprint,
    required this.displayName,
    required this.message,
    required this.requestedAt,
    required this.status,
  });

  factory ContactRequest.fromNative(dna_contact_request_t native) {
    return ContactRequest(
      fingerprint: native.fingerprint.toDartString(129),
      displayName: native.display_name.toDartString(64),
      message: native.message.toDartString(256),
      requestedAt: DateTime.fromMillisecondsSinceEpoch(native.requested_at * 1000),
      status: ContactRequestStatus.values[native.status.clamp(0, 2)],
    );
  }
}

/// Contact request status
enum ContactRequestStatus {
  pending,   // 0
  approved,  // 1
  denied,    // 2
}

/// Blocked user information
class BlockedUser {
  final String fingerprint;
  final DateTime blockedAt;
  final String reason;

  BlockedUser({
    required this.fingerprint,
    required this.blockedAt,
    required this.reason,
  });

  factory BlockedUser.fromNative(dna_blocked_user_t native) {
    return BlockedUser(
      fingerprint: native.fingerprint.toDartString(129),
      blockedAt: DateTime.fromMillisecondsSinceEpoch(native.blocked_at * 1000),
      reason: native.reason.toDartString(256),
    );
  }
}

/// Message information
class Message {
  final int id;
  final String sender;
  final String recipient;
  final String plaintext;
  final DateTime timestamp;
  final bool isOutgoing;
  final MessageStatus status;
  final MessageType type;

  Message({
    required this.id,
    required this.sender,
    required this.recipient,
    required this.plaintext,
    required this.timestamp,
    required this.isOutgoing,
    required this.status,
    required this.type,
  });

  factory Message.fromNative(dna_message_t native) {
    return Message(
      id: native.id,
      sender: native.sender.toDartString(129),
      recipient: native.recipient.toDartString(129),
      plaintext: native.plaintext == nullptr
          ? ''
          : native.plaintext.toDartString(),
      timestamp: DateTime.fromMillisecondsSinceEpoch(native.timestamp * 1000),
      isOutgoing: native.is_outgoing,
      status: MessageStatus.values[native.status.clamp(0, 5)],
      type: native.message_type == 2
          ? MessageType.cpunkTransfer
          : (native.message_type == 1
              ? MessageType.groupInvitation
              : MessageType.chat),
    );
  }

  /// Create a pending outgoing message (for optimistic UI)
  factory Message.pending({
    required String sender,
    required String recipient,
    required String plaintext,
    MessageType type = MessageType.chat,
  }) {
    return Message(
      id: -DateTime.now().millisecondsSinceEpoch, // Negative temp ID
      sender: sender,
      recipient: recipient,
      plaintext: plaintext,
      timestamp: DateTime.now(),
      isOutgoing: true,
      status: MessageStatus.pending,
      type: type,
    );
  }

  /// Create a copy with updated status
  Message copyWith({MessageStatus? status, int? id}) {
    return Message(
      id: id ?? this.id,
      sender: sender,
      recipient: recipient,
      plaintext: plaintext,
      timestamp: timestamp,
      isOutgoing: isOutgoing,
      status: status ?? this.status,
      type: type,
    );
  }
}

enum MessageStatus { pending, sent, failed, delivered, read, stale }
enum MessageType { chat, groupInvitation, cpunkTransfer }

/// Result of paginated conversation query
class ConversationPage {
  final List<Message> messages;
  final int total;
  ConversationPage(this.messages, this.total);
}

/// Group information
class Group {
  final String uuid;
  final String name;
  final String creator;
  final int memberCount;
  final DateTime createdAt;

  Group({
    required this.uuid,
    required this.name,
    required this.creator,
    required this.memberCount,
    required this.createdAt,
  });

  factory Group.fromNative(dna_group_t native) {
    return Group(
      uuid: native.uuid.toDartString(37),
      name: native.name.toDartString(256),
      creator: native.creator.toDartString(129),
      memberCount: native.member_count,
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
    );
  }
}

/// Group invitation
class Invitation {
  final String groupUuid;
  final String groupName;
  final String inviter;
  final int memberCount;
  final DateTime invitedAt;

  Invitation({
    required this.groupUuid,
    required this.groupName,
    required this.inviter,
    required this.memberCount,
    required this.invitedAt,
  });

  factory Invitation.fromNative(dna_invitation_t native) {
    return Invitation(
      groupUuid: native.group_uuid.toDartString(37),
      groupName: native.group_name.toDartString(256),
      inviter: native.inviter.toDartString(129),
      memberCount: native.member_count,
      invitedAt: DateTime.fromMillisecondsSinceEpoch(native.invited_at * 1000),
    );
  }
}

/// Wallet information
class Wallet {
  final String name;
  final String address;
  final int sigType;
  final bool isProtected;

  Wallet({
    required this.name,
    required this.address,
    required this.sigType,
    required this.isProtected,
  });

  factory Wallet.fromNative(dna_wallet_t native) {
    return Wallet(
      name: native.name.toDartString(256),
      address: native.address.toDartString(120),
      sigType: native.sig_type,
      isProtected: native.is_protected,
    );
  }
}

/// Token balance
class Balance {
  final String token;
  final String balance;
  final String network;

  Balance({
    required this.token,
    required this.balance,
    required this.network,
  });

  factory Balance.fromNative(dna_balance_t native) {
    return Balance(
      token: native.token.toDartString(32),
      balance: native.balance.toDartString(64),
      network: native.network.toDartString(64),
    );
  }
}

/// Gas estimate for ETH transactions
class GasEstimate {
  final String feeEth;
  final int gasPrice;
  final int gasLimit;

  GasEstimate({
    required this.feeEth,
    required this.gasPrice,
    required this.gasLimit,
  });

  factory GasEstimate.fromNative(dna_gas_estimate_t native) {
    return GasEstimate(
      feeEth: native.fee_eth.toDartString(32),
      gasPrice: native.gas_price,
      gasLimit: native.gas_limit,
    );
  }
}

/// Transaction record
class Transaction {
  final String txHash;
  final String direction;
  final String amount;
  final String token;
  final String otherAddress;
  final String timestamp;
  final String status;

  Transaction({
    required this.txHash,
    required this.direction,
    required this.amount,
    required this.token,
    required this.otherAddress,
    required this.timestamp,
    required this.status,
  });

  factory Transaction.fromNative(dna_transaction_t native) {
    return Transaction(
      txHash: native.tx_hash.toDartString(128),
      direction: native.direction.toDartString(16),
      amount: native.amount.toDartString(64),
      token: native.token.toDartString(32),
      otherAddress: native.other_address.toDartString(120),
      timestamp: native.timestamp.toDartString(32),
      status: native.status.toDartString(32),
    );
  }
}

/// Feed channel information
class FeedChannel {
  final String channelId;
  final String name;
  final String description;
  final String creatorFingerprint;
  final DateTime createdAt;
  final int postCount;
  final int subscriberCount;
  final DateTime lastActivity;

  FeedChannel({
    required this.channelId,
    required this.name,
    required this.description,
    required this.creatorFingerprint,
    required this.createdAt,
    required this.postCount,
    required this.subscriberCount,
    required this.lastActivity,
  });

  factory FeedChannel.fromNative(dna_channel_info_t native) {
    return FeedChannel(
      channelId: native.channel_id.toDartString(65),
      name: native.name.toDartString(64),
      description: native.description.toDartString(512),
      creatorFingerprint: native.creator_fingerprint.toDartString(129),
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
      postCount: native.post_count,
      subscriberCount: native.subscriber_count,
      lastActivity: DateTime.fromMillisecondsSinceEpoch(native.last_activity * 1000),
    );
  }
}

/// Feed post information
class FeedPost {
  final String postId;
  final String channelId;
  final String authorFingerprint;
  final String text;
  final DateTime timestamp;
  final DateTime updated;
  final int commentCount;
  final int upvotes;
  final int downvotes;
  final int userVote;
  final bool verified;

  FeedPost({
    required this.postId,
    required this.channelId,
    required this.authorFingerprint,
    required this.text,
    required this.timestamp,
    required this.updated,
    required this.commentCount,
    required this.upvotes,
    required this.downvotes,
    required this.userVote,
    required this.verified,
  });

  factory FeedPost.fromNative(dna_post_info_t native) {
    return FeedPost(
      postId: native.post_id.toDartString(200),
      channelId: native.channel_id.toDartString(65),
      authorFingerprint: native.author_fingerprint.toDartString(129),
      text: native.text == nullptr ? '' : native.text.toDartString(),
      timestamp: DateTime.fromMillisecondsSinceEpoch(native.timestamp),
      updated: DateTime.fromMillisecondsSinceEpoch(native.updated),
      commentCount: native.comment_count,
      upvotes: native.upvotes,
      downvotes: native.downvotes,
      userVote: native.user_vote,
      verified: native.verified,
    );
  }

  /// Net score (upvotes - downvotes)
  int get score => upvotes - downvotes;

  /// Check if current user has voted
  bool get hasVoted => userVote != 0;

  /// Create a copy with updated vote data
  FeedPost copyWith({
    int? commentCount,
    int? upvotes,
    int? downvotes,
    int? userVote,
  }) {
    return FeedPost(
      postId: postId,
      channelId: channelId,
      authorFingerprint: authorFingerprint,
      text: text,
      timestamp: timestamp,
      updated: updated,
      commentCount: commentCount ?? this.commentCount,
      upvotes: upvotes ?? this.upvotes,
      downvotes: downvotes ?? this.downvotes,
      userVote: userVote ?? this.userVote,
      verified: verified,
    );
  }
}

/// Feed comment information (flat comments, no nesting)
class FeedComment {
  final String commentId;
  final String postId;
  final String authorFingerprint;
  final String text;
  final DateTime timestamp;
  final int upvotes;
  final int downvotes;
  final int userVote;
  final bool verified;

  FeedComment({
    required this.commentId,
    required this.postId,
    required this.authorFingerprint,
    required this.text,
    required this.timestamp,
    required this.upvotes,
    required this.downvotes,
    required this.userVote,
    required this.verified,
  });

  factory FeedComment.fromNative(dna_comment_info_t native) {
    return FeedComment(
      commentId: native.comment_id.toDartString(200),
      postId: native.post_id.toDartString(200),
      authorFingerprint: native.author_fingerprint.toDartString(129),
      text: native.text == nullptr ? '' : native.text.toDartString(),
      timestamp: DateTime.fromMillisecondsSinceEpoch(native.timestamp),
      upvotes: native.upvotes,
      downvotes: native.downvotes,
      userVote: native.user_vote,
      verified: native.verified,
    );
  }

  /// Net score (upvotes - downvotes)
  int get score => upvotes - downvotes;

  /// Check if current user has voted
  bool get hasVoted => userVote != 0;

  /// Create a copy with updated vote data
  FeedComment copyWith({
    int? upvotes,
    int? downvotes,
    int? userVote,
  }) {
    return FeedComment(
      commentId: commentId,
      postId: postId,
      authorFingerprint: authorFingerprint,
      text: text,
      timestamp: timestamp,
      upvotes: upvotes ?? this.upvotes,
      downvotes: downvotes ?? this.downvotes,
      userVote: userVote ?? this.userVote,
      verified: verified,
    );
  }
}

/// Debug log level
enum DebugLogLevel { debug, info, warn, error }

/// Debug log entry from ring buffer
class DebugLogEntry {
  final int timestampMs;
  final DebugLogLevel level;
  final String tag;
  final String message;

  DebugLogEntry({
    required this.timestampMs,
    required this.level,
    required this.tag,
    required this.message,
  });

  DateTime get timestamp => DateTime.fromMillisecondsSinceEpoch(timestampMs);

  String get levelString {
    switch (level) {
      case DebugLogLevel.debug:
        return 'DEBUG';
      case DebugLogLevel.info:
        return 'INFO';
      case DebugLogLevel.warn:
        return 'WARN';
      case DebugLogLevel.error:
        return 'ERROR';
    }
  }

  @override
  String toString() =>
      '${timestamp.toIso8601String()} [$levelString] $tag: $message';
}

/// Result of message backup/restore operations
class BackupResult {
  final int processedCount;
  final int skippedCount;
  final bool success;
  final String? errorMessage;

  BackupResult({
    required this.processedCount,
    required this.skippedCount,
    required this.success,
    this.errorMessage,
  });
}

/// Info about existing backup in DHT (v0.4.60)
class BackupInfo {
  final bool exists;
  final DateTime? timestamp;
  final int messageCount;

  BackupInfo({
    required this.exists,
    this.timestamp,
    required this.messageCount,
  });
}

/// User profile information (synced with DHT dna_unified_identity_t)
class UserProfile {
  // Cellframe wallets
  String backbone;
  String alvin;

  // External wallets
  String eth; // Also works for BSC, Polygon, etc.
  String sol;
  String trx; // TRON address (T...)

  // Socials
  String telegram;
  String twitter;
  String github;
  String facebook;
  String instagram;
  String linkedin;
  String google;

  // Profile info
  String displayName;
  String bio;
  String location;
  String website;
  String avatarBase64;

  // Cached decoded avatar (lazy, computed once on first access)
  Uint8List? _cachedAvatarBytes;
  bool _avatarDecoded = false;

  UserProfile({
    this.backbone = '',
    this.alvin = '',
    this.eth = '',
    this.sol = '',
    this.trx = '',
    this.telegram = '',
    this.twitter = '',
    this.github = '',
    this.facebook = '',
    this.instagram = '',
    this.linkedin = '',
    this.google = '',
    this.displayName = '',
    this.bio = '',
    this.location = '',
    this.website = '',
    this.avatarBase64 = '',
  });

  factory UserProfile.fromNative(dna_profile_t native) {
    final avatarBase64 = native.avatar_base64.toDartString(20484);

    return UserProfile(
      backbone: native.backbone.toDartString(120),
      alvin: native.alvin.toDartString(120),
      eth: native.eth.toDartString(128),
      sol: native.sol.toDartString(128),
      trx: native.trx.toDartString(128),
      telegram: native.telegram.toDartString(128),
      twitter: native.twitter.toDartString(128),
      github: native.github.toDartString(128),
      facebook: native.facebook.toDartString(128),
      instagram: native.instagram.toDartString(128),
      linkedin: native.linkedin.toDartString(128),
      google: native.google.toDartString(128),
      displayName: native.display_name.toDartString(128),
      bio: native.bio.toDartString(512),
      location: native.location.toDartString(128),
      website: native.website.toDartString(256),
      avatarBase64: avatarBase64,
    );
  }

  /// Copy profile data to native struct
  void toNative(Pointer<dna_profile_t> native) {
    _copyStringToArray(backbone, native.ref.backbone, 120);
    _copyStringToArray(alvin, native.ref.alvin, 120);
    _copyStringToArray(eth, native.ref.eth, 128);
    _copyStringToArray(sol, native.ref.sol, 128);
    _copyStringToArray(trx, native.ref.trx, 128);
    _copyStringToArray(telegram, native.ref.telegram, 128);
    _copyStringToArray(twitter, native.ref.twitter, 128);
    _copyStringToArray(github, native.ref.github, 128);
    _copyStringToArray(facebook, native.ref.facebook, 128);
    _copyStringToArray(instagram, native.ref.instagram, 128);
    _copyStringToArray(linkedin, native.ref.linkedin, 128);
    _copyStringToArray(google, native.ref.google, 128);
    _copyStringToArray(displayName, native.ref.display_name, 128);
    _copyStringToArray(bio, native.ref.bio, 512);
    _copyStringToArray(location, native.ref.location, 128);
    _copyStringToArray(website, native.ref.website, 256);
    _copyStringToArray(avatarBase64, native.ref.avatar_base64, 20484);
  }

  static void _copyStringToArray(String str, Array<Char> array, int maxLen) {
    final bytes = str.codeUnits;
    final len = bytes.length.clamp(0, maxLen - 1);
    for (var i = 0; i < len; i++) {
      array[i] = bytes[i];
    }
    array[len] = 0; // null terminator
  }

  /// Check if profile is empty
  bool get isEmpty =>
      backbone.isEmpty &&
      alvin.isEmpty &&
      eth.isEmpty &&
      sol.isEmpty &&
      trx.isEmpty &&
      telegram.isEmpty &&
      twitter.isEmpty &&
      github.isEmpty &&
      facebook.isEmpty &&
      instagram.isEmpty &&
      linkedin.isEmpty &&
      google.isEmpty &&
      displayName.isEmpty &&
      bio.isEmpty &&
      location.isEmpty &&
      website.isEmpty &&
      avatarBase64.isEmpty;

  /// Create a copy of this profile
  UserProfile copyWith({
    String? backbone,
    String? alvin,
    String? eth,
    String? sol,
    String? trx,
    String? telegram,
    String? twitter,
    String? github,
    String? facebook,
    String? instagram,
    String? linkedin,
    String? google,
    String? displayName,
    String? bio,
    String? location,
    String? website,
    String? avatarBase64,
  }) {
    return UserProfile(
      backbone: backbone ?? this.backbone,
      alvin: alvin ?? this.alvin,
      eth: eth ?? this.eth,
      sol: sol ?? this.sol,
      trx: trx ?? this.trx,
      telegram: telegram ?? this.telegram,
      twitter: twitter ?? this.twitter,
      github: github ?? this.github,
      facebook: facebook ?? this.facebook,
      instagram: instagram ?? this.instagram,
      linkedin: linkedin ?? this.linkedin,
      google: google ?? this.google,
      displayName: displayName ?? this.displayName,
      bio: bio ?? this.bio,
      location: location ?? this.location,
      website: website ?? this.website,
      avatarBase64: avatarBase64 ?? this.avatarBase64,
    );
  }

  /// Decode avatar base64 with padding fix (cached - only decodes once)
  /// Buffer limit is 20483 bytes which may truncate padding characters
  Uint8List? decodeAvatar() {
    // Return cached result if already decoded
    if (_avatarDecoded) return _cachedAvatarBytes;

    _avatarDecoded = true;
    if (avatarBase64.isEmpty) {
      _cachedAvatarBytes = null;
      return null;
    }
    try {
      var b64 = avatarBase64;
      final remainder = b64.length % 4;
      if (remainder > 0) {
        b64 = b64 + '=' * (4 - remainder);
      }
      _cachedAvatarBytes = base64Decode(b64);
      return _cachedAvatarBytes;
    } catch (e) {
      _cachedAvatarBytes = null;
      return null;
    }
  }
}

/// Version check result from DHT
class VersionCheckResult {
  final bool libraryUpdateAvailable;
  final bool appUpdateAvailable;
  final bool nodusUpdateAvailable;
  final String libraryCurrent;
  final String libraryMinimum;
  final String appCurrent;
  final String appMinimum;
  final String nodusCurrent;
  final String nodusMinimum;
  final int publishedAt;
  final String publisher;

  VersionCheckResult({
    required this.libraryUpdateAvailable,
    required this.appUpdateAvailable,
    required this.nodusUpdateAvailable,
    required this.libraryCurrent,
    required this.libraryMinimum,
    required this.appCurrent,
    required this.appMinimum,
    required this.nodusCurrent,
    required this.nodusMinimum,
    required this.publishedAt,
    required this.publisher,
  });

  factory VersionCheckResult.fromNative(dna_version_check_result_t native) {
    return VersionCheckResult(
      libraryUpdateAvailable: native.library_update_available,
      appUpdateAvailable: native.app_update_available,
      nodusUpdateAvailable: native.nodus_update_available,
      libraryCurrent: native.info.library_current.toDartString(32),
      libraryMinimum: native.info.library_minimum.toDartString(32),
      appCurrent: native.info.app_current.toDartString(32),
      appMinimum: native.info.app_minimum.toDartString(32),
      nodusCurrent: native.info.nodus_current.toDartString(32),
      nodusMinimum: native.info.nodus_minimum.toDartString(32),
      publishedAt: native.info.published_at,
      publisher: native.info.publisher.toDartString(129),
    );
  }

  /// Check if any update is available
  bool get hasUpdate => libraryUpdateAvailable || appUpdateAvailable || nodusUpdateAvailable;
}

/// Decode base64 string with padding fix for truncated avatar data
/// C buffer limit is 20484 bytes, strncpy copies max 20483, which may truncate padding
Uint8List? decodeBase64WithPadding(String base64Str) {
  if (base64Str.isEmpty) return null;
  try {
    var b64 = base64Str;
    final remainder = b64.length % 4;
    if (remainder > 0) {
      b64 = b64 + '=' * (4 - remainder);
    }
    return base64Decode(b64);
  } catch (e) {
    return null;
  }
}

// =============================================================================
// EVENTS
// =============================================================================

/// Base class for all DNA events
sealed class DnaEvent {}

class DhtConnectedEvent extends DnaEvent {}

class DhtDisconnectedEvent extends DnaEvent {}

class MessageReceivedEvent extends DnaEvent {
  final Message message;
  MessageReceivedEvent(this.message);
}

class MessageSentEvent extends DnaEvent {
  final int messageId;
  MessageSentEvent(this.messageId);
}

class MessageDeliveredEvent extends DnaEvent {
  final String contactFingerprint;
  MessageDeliveredEvent(this.contactFingerprint);
}

class MessageReadEvent extends DnaEvent {
  final int messageId;
  MessageReadEvent(this.messageId);
}

class ContactOnlineEvent extends DnaEvent {
  final String fingerprint;
  ContactOnlineEvent(this.fingerprint);
}

class ContactOfflineEvent extends DnaEvent {
  final String fingerprint;
  ContactOfflineEvent(this.fingerprint);
}

class GroupInvitationReceivedEvent extends DnaEvent {
  final Invitation invitation;
  GroupInvitationReceivedEvent(this.invitation);
}

class GroupMemberJoinedEvent extends DnaEvent {
  final String groupUuid;
  final String memberFingerprint;
  GroupMemberJoinedEvent(this.groupUuid, this.memberFingerprint);
}

class GroupMemberLeftEvent extends DnaEvent {
  final String groupUuid;
  final String memberFingerprint;
  GroupMemberLeftEvent(this.groupUuid, this.memberFingerprint);
}

class IdentityLoadedEvent extends DnaEvent {
  final String fingerprint;
  IdentityLoadedEvent(this.fingerprint);
}

class ErrorEvent extends DnaEvent {
  final int code;
  final String message;
  ErrorEvent(this.code, this.message);
}

/// Outbox updated event - contact has new offline messages for us
class OutboxUpdatedEvent extends DnaEvent {
  final String contactFingerprint;
  OutboxUpdatedEvent(this.contactFingerprint);
}

/// Contact request received event - someone sent us a contact request
class ContactRequestReceivedEvent extends DnaEvent {}

/// Group message received event - new messages in a group
class GroupMessageReceivedEvent extends DnaEvent {
  final String groupUuid;
  final int newCount;
  GroupMessageReceivedEvent(this.groupUuid, this.newCount);
}

// =============================================================================
// EXCEPTIONS
// =============================================================================

class DnaEngineException implements Exception {
  final int code;
  final String message;

  DnaEngineException(this.code, this.message);

  factory DnaEngineException.fromCode(int code, DnaBindings bindings) {
    final msgPtr = bindings.dna_engine_error_string(code);
    final message = msgPtr == nullptr ? 'Unknown error' : msgPtr.toDartString();
    return DnaEngineException(code, message);
  }

  @override
  String toString() => 'DnaEngineException($code): $message';
}

// =============================================================================
// DNA ENGINE
// =============================================================================

class DnaEngine {
  late final DnaBindings _bindings;
  late final Pointer<dna_engine_t> _engine;
  final _eventController = StreamController<DnaEvent>.broadcast();

  // Callback registry to prevent GC
  final Map<int, _PendingRequest> _pendingRequests = {};
  int _nextLocalId = 1;

  // Event callback storage
  NativeCallable<DnaEventCbNative>? _eventCallback;

  bool _isDisposed = false;

  /// Event stream for pushed notifications
  Stream<DnaEvent> get events => _eventController.stream;

  /// Check if engine is initialized
  bool get isInitialized => !_isDisposed;

  DnaEngine._();

  /// Create and initialize the DNA engine
  ///
  /// On Android (v0.5.5+): Checks for existing global engine first.
  /// If the background service already created an engine, this reuses it
  /// for seamless handoff between JNI and Flutter FFI.
  static Future<DnaEngine> create({String? dataDir}) async {
    final engine = DnaEngine._();
    engine._bindings = DnaBindings(_loadLibrary());

    // Android: Check for existing global engine (created by service)
    if (Platform.isAndroid) {
      final globalEngine = engine._bindings.dna_engine_get_global();
      if (globalEngine != nullptr) {
        engine._engine = globalEngine;
        engine._setupEventCallback();
        return engine;
      }
    }

    final dataDirPtr = dataDir?.toNativeUtf8() ?? nullptr;
    engine._engine = engine._bindings.dna_engine_create(dataDirPtr.cast());

    if (dataDir != null) {
      calloc.free(dataDirPtr);
    }

    if (engine._engine == nullptr) {
      throw DnaEngineException(-100, 'Failed to create engine');
    }

    // Android: Set as global so service can access it
    if (Platform.isAndroid) {
      engine._bindings.dna_engine_set_global(engine._engine);
    }

    engine._setupEventCallback();
    return engine;
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libdna_lib.so');
    } else if (Platform.isIOS || Platform.isMacOS) {
      return DynamicLibrary.process(); // Statically linked
    } else if (Platform.isLinux) {
      // Try common locations
      try {
        return DynamicLibrary.open('libdna_lib.so');
      } catch (_) {
        try {
          return DynamicLibrary.open('./libdna_lib.so');
        } catch (_) {
          // AppImage: library is in lib/ subdirectory
          return DynamicLibrary.open('./lib/libdna_lib.so');
        }
      }
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('dna_lib.dll');
    }
    throw UnsupportedError('Platform not supported');
  }

  void _setupEventCallback() {
    _eventCallback = NativeCallable<DnaEventCbNative>.listener(
      _onEventReceived,
    );

    _bindings.dna_engine_set_event_callback(
      _engine,
      _eventCallback!.nativeFunction.cast(),
      nullptr,
    );
  }

  void _onEventReceived(Pointer<dna_event_t> eventPtr, Pointer<Void> userData) {
    // DEBUG: Print to stdout/logcat immediately
    final event = eventPtr.ref;
    final type = event.type;
    print('[DART-EVENT] _onEventReceived called, type=$type, disposed=$_isDisposed');

    if (_isDisposed) return;

    DnaEvent? dartEvent;

    switch (type) {
      case DnaEventType.DNA_EVENT_DHT_CONNECTED:
        dartEvent = DhtConnectedEvent();
        break;
      case DnaEventType.DNA_EVENT_DHT_DISCONNECTED:
        dartEvent = DhtDisconnectedEvent();
        break;
      case DnaEventType.DNA_EVENT_MESSAGE_RECEIVED:
        // Parse message from union data
        // Dart struct now has _padding field matching C struct 8-byte alignment
        // dna_message_t layout: id(4) + sender[129] + recipient[129] + ptr(8) + timestamp(8) + bool(1+3pad) + status(4) + type(4)
        final senderBytes = <int>[];
        for (var i = 4; i < 132; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          senderBytes.add(byte);
        }
        final sender = String.fromCharCodes(senderBytes);

        final recipientBytes = <int>[];
        for (var i = 133; i < 261; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          recipientBytes.add(byte);
        }
        final recipient = String.fromCharCodes(recipientBytes);

        // is_outgoing is at union offset 280 (after plaintext ptr + timestamp)
        final isOutgoing = event.data[280] != 0;

        // message_type is at union offset 288 (0=chat, 1=group invitation)
        final msgTypeInt = event.data[288];
        final msgType = msgTypeInt == 1 ? MessageType.groupInvitation : MessageType.chat;

        dartEvent = MessageReceivedEvent(Message(
          id: 0,
          sender: sender,
          recipient: recipient,
          plaintext: '',  // Not available in event, fetched from DB
          timestamp: DateTime.now(),
          isOutgoing: isOutgoing,
          status: MessageStatus.delivered,
          type: msgType,
        ));
        break;
      case DnaEventType.DNA_EVENT_MESSAGE_SENT:
        // Message was successfully sent - trigger UI refresh
        // Dart struct now has _padding field matching C struct 8-byte alignment
        final messageId = event.data[0] | (event.data[1] << 8) |
                          (event.data[2] << 16) | (event.data[3] << 24);
        final status = event.data[4] | (event.data[5] << 8) |
                       (event.data[6] << 16) | (event.data[7] << 24);
        print('[DART-EVENT] MESSAGE_SENT: messageId=$messageId, status=$status');
        dartEvent = MessageSentEvent(messageId);
        break;
      case DnaEventType.DNA_EVENT_MESSAGE_DELIVERED:
        // Message delivered - parse recipient fingerprint from message_delivered.recipient
        // Dart struct now has _padding field matching C struct 8-byte alignment
        final deliveredFpBytes = <int>[];
        for (var i = 0; i < 128; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          deliveredFpBytes.add(byte);
        }
        final deliveredContactFp = String.fromCharCodes(deliveredFpBytes);
        dartEvent = MessageDeliveredEvent(deliveredContactFp);
        break;
      case DnaEventType.DNA_EVENT_CONTACT_ONLINE:
        // Parse fingerprint from contact_status.fingerprint
        // Dart struct now has _padding field matching C struct 8-byte alignment
        final onlineFpBytes = <int>[];
        for (var i = 0; i < 128; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          onlineFpBytes.add(byte);
        }
        final onlineFingerprint = String.fromCharCodes(onlineFpBytes);
        dartEvent = ContactOnlineEvent(onlineFingerprint);
        break;
      case DnaEventType.DNA_EVENT_CONTACT_OFFLINE:
        // Parse fingerprint from contact_status.fingerprint
        // Dart struct now has _padding field matching C struct 8-byte alignment
        final offlineFpBytes = <int>[];
        for (var i = 0; i < 128; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          offlineFpBytes.add(byte);
        }
        final offlineFingerprint = String.fromCharCodes(offlineFpBytes);
        dartEvent = ContactOfflineEvent(offlineFingerprint);
        break;
      case DnaEventType.DNA_EVENT_IDENTITY_LOADED:
        dartEvent = IdentityLoadedEvent('');
        break;
      case DnaEventType.DNA_EVENT_CONTACT_REQUEST_RECEIVED:
        // No data to parse - just signal that new request arrived
        dartEvent = ContactRequestReceivedEvent();
        break;
      case DnaEventType.DNA_EVENT_OUTBOX_UPDATED:
        // Parse contact fingerprint from union data
        // Dart struct now has _padding field matching C struct 8-byte alignment
        final fpBytes = <int>[];
        for (var i = 0; i < 128; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          fpBytes.add(byte);
        }
        final contactFp = String.fromCharCodes(fpBytes);
        dartEvent = OutboxUpdatedEvent(contactFp);
        break;
      case DnaEventType.DNA_EVENT_GROUP_MESSAGE_RECEIVED:
        // Parse group_uuid (37 bytes) and new_count (int32 at offset 40)
        // C struct: char group_uuid[37] + 3 padding bytes + int new_count
        final uuidBytes = <int>[];
        for (var i = 0; i < 36; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          uuidBytes.add(byte);
        }
        final groupUuid = String.fromCharCodes(uuidBytes);
        // new_count is at offset 40 (37 bytes + 3 padding for 4-byte alignment)
        final newCount = event.data[40] |
            (event.data[41] << 8) |
            (event.data[42] << 16) |
            (event.data[43] << 24);
        dartEvent = GroupMessageReceivedEvent(groupUuid, newCount);
        break;
      case DnaEventType.DNA_EVENT_ERROR:
        dartEvent = ErrorEvent(0, 'Error occurred');
        break;
      default:
        // Unknown event type
        break;
    }

    if (dartEvent != null) {
      print('[DART-EVENT] Adding to stream: ${dartEvent.runtimeType}');
      _eventController.add(dartEvent);
    }

    // Free the heap-allocated event from C
    _bindings.dna_free_event(eventPtr);
  }

  /// Get current identity fingerprint
  String? get fingerprint {
    final ptr = _bindings.dna_engine_get_fingerprint(_engine);
    if (ptr == nullptr) return null;
    return ptr.toDartString();
  }

  // ---------------------------------------------------------------------------
  // IDENTITY OPERATIONS
  // ---------------------------------------------------------------------------

  /// List available identities
  Future<List<String>> listIdentities() async {
    final completer = Completer<List<String>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Pointer<Utf8>> fingerprints,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <String>[];
        for (var i = 0; i < count; i++) {
          final fp = (fingerprints + i).value;
          if (fp != nullptr) {
            result.add(fp.toDartString());
          }
        }
        if (count > 0) {
          _bindings.dna_free_strings(fingerprints, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(
          DnaEngineException.fromCode(error, _bindings),
        );
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaIdentitiesCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_list_identities(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Create new identity from BIP39 seeds (synchronous)
  /// name is required - used for directory structure and wallet naming
  /// masterSeed is the 64-byte BIP39 master seed for multi-chain wallet derivation (ETH, SOL)
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  String createIdentitySync(String name, List<int> signingSeed, List<int> encryptionSeed, {List<int>? masterSeed, String? mnemonic}) {
    if (name.isEmpty) {
      throw ArgumentError('Name is required');
    }
    // Validate identity name: lowercase only (a-z, 0-9, underscore, hyphen)
    final validNameRegex = RegExp(r'^[a-z0-9_-]+$');
    if (!validNameRegex.hasMatch(name)) {
      throw ArgumentError('Identity name must be lowercase (a-z, 0-9, underscore, hyphen only). Use your profile to set a display name with any case.');
    }
    if (signingSeed.length != 32 || encryptionSeed.length != 32) {
      throw ArgumentError('Seeds must be 32 bytes each');
    }
    if (masterSeed != null && masterSeed.length != 64) {
      throw ArgumentError('Master seed must be 64 bytes');
    }

    final namePtr = name.toNativeUtf8();
    final sigSeedPtr = calloc<Uint8>(32);
    final encSeedPtr = calloc<Uint8>(32);
    final masterSeedPtr = masterSeed != null ? calloc<Uint8>(64) : nullptr;
    final mnemonicPtr = mnemonic != null ? mnemonic.toNativeUtf8() : nullptr;
    final fingerprintPtr = calloc<Uint8>(129); // 128 hex chars + null

    try {
      for (var i = 0; i < 32; i++) {
        sigSeedPtr[i] = signingSeed[i];
        encSeedPtr[i] = encryptionSeed[i];
      }
      if (masterSeed != null) {
        for (var i = 0; i < 64; i++) {
          masterSeedPtr[i] = masterSeed[i];
        }
      }

      final error = _bindings.dna_engine_create_identity_sync(
        _engine,
        namePtr.cast(),
        sigSeedPtr,
        encSeedPtr,
        masterSeedPtr,
        mnemonicPtr.cast(),
        fingerprintPtr.cast(),
      );

      if (error != 0) {
        throw DnaEngineException.fromCode(error, _bindings);
      }

      return fingerprintPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(namePtr);
      calloc.free(sigSeedPtr);
      calloc.free(encSeedPtr);
      if (masterSeed != null) {
        calloc.free(masterSeedPtr);
      }
      if (mnemonic != null) {
        calloc.free(mnemonicPtr);
      }
      calloc.free(fingerprintPtr);
    }
  }

  /// Create new identity from BIP39 seeds (async wrapper)
  /// name is required - used for directory structure and wallet naming
  /// masterSeed is the 64-byte BIP39 master seed for multi-chain wallet derivation (ETH, SOL)
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  Future<String> createIdentity(String name, List<int> signingSeed, List<int> encryptionSeed, {List<int>? masterSeed, String? mnemonic}) async {
    // Use sync version wrapped in compute to avoid blocking UI
    return createIdentitySync(name, signingSeed, encryptionSeed, masterSeed: masterSeed, mnemonic: mnemonic);
  }

  /// Restore identity from BIP39 seeds (synchronous)
  /// Creates keys and wallets locally without DHT name registration.
  /// Use this when restoring an existing identity from seed phrase.
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  String restoreIdentitySync(List<int> signingSeed, List<int> encryptionSeed, {List<int>? masterSeed, String? mnemonic}) {
    if (signingSeed.length != 32 || encryptionSeed.length != 32) {
      throw ArgumentError('Seeds must be 32 bytes each');
    }
    if (masterSeed != null && masterSeed.length != 64) {
      throw ArgumentError('Master seed must be 64 bytes');
    }

    final sigSeedPtr = calloc<Uint8>(32);
    final encSeedPtr = calloc<Uint8>(32);
    final masterSeedPtr = masterSeed != null ? calloc<Uint8>(64) : nullptr;
    final mnemonicPtr = mnemonic != null ? mnemonic.toNativeUtf8() : nullptr;
    final fingerprintPtr = calloc<Uint8>(129); // 128 hex chars + null

    try {
      for (var i = 0; i < 32; i++) {
        sigSeedPtr[i] = signingSeed[i];
        encSeedPtr[i] = encryptionSeed[i];
      }
      if (masterSeed != null) {
        for (var i = 0; i < 64; i++) {
          masterSeedPtr[i] = masterSeed[i];
        }
      }

      final error = _bindings.dna_engine_restore_identity_sync(
        _engine,
        sigSeedPtr,
        encSeedPtr,
        masterSeedPtr,
        mnemonicPtr.cast(),
        fingerprintPtr.cast(),
      );

      if (error != 0) {
        throw DnaEngineException.fromCode(error, _bindings);
      }

      return fingerprintPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(sigSeedPtr);
      calloc.free(encSeedPtr);
      if (masterSeed != null) {
        calloc.free(masterSeedPtr);
      }
      if (mnemonic != null) {
        calloc.free(mnemonicPtr);
      }
      calloc.free(fingerprintPtr);
    }
  }

  /// Restore identity from BIP39 seeds (async wrapper)
  /// Creates keys and wallets locally without DHT name registration.
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  Future<String> restoreIdentity(List<int> signingSeed, List<int> encryptionSeed, {List<int>? masterSeed, String? mnemonic}) async {
    return restoreIdentitySync(signingSeed, encryptionSeed, masterSeed: masterSeed, mnemonic: mnemonic);
  }

  /// Delete identity and all associated local data
  ///
  /// Deletes all local files for the specified identity:
  /// - Keys directory
  /// - Wallets directory
  /// - Database directory
  /// - Contacts database
  /// - Profiles cache
  /// - Groups database
  ///
  /// WARNING: This operation is irreversible! The identity cannot be
  /// recovered unless the user has backed up their seed phrase.
  ///
  /// Note: This does NOT delete data from the DHT network (name registration,
  /// profile, etc.). The identity can be restored from seed phrase.
  ///
  /// Throws [DnaEngineException] on error.
  void deleteIdentity(String fingerprint) {
    final fpPtr = fingerprint.toNativeUtf8();
    try {
      final error = _bindings.dna_engine_delete_identity_sync(_engine, fpPtr.cast());
      if (error != 0) {
        throw DnaEngineException.fromCode(error, _bindings);
      }
    } finally {
      calloc.free(fpPtr);
    }
  }

  /// Check if an identity exists (v0.3.0 single-user model)
  ///
  /// Returns true if keys/identity.dsa exists in the data directory.
  /// Use this to determine if onboarding is needed.
  bool hasIdentity() {
    return _bindings.dna_engine_has_identity(_engine);
  }

  /// Prepare DHT connection from mnemonic (before identity creation)
  ///
  /// v0.3.0+: Call this when user enters seed phrase and presses "Next".
  /// Starts DHT connection early so it's ready when identity is created.
  ///
  /// Flow:
  /// 1. User enters seed → presses Next
  /// 2. Call prepareDhtFromMnemonic() → DHT starts connecting
  /// 3. User enters nickname (DHT connects in background)
  /// 4. User presses Create → DHT is ready → name registration succeeds
  void prepareDhtFromMnemonic(String mnemonic) {
    final mnemonicPtr = mnemonic.toNativeUtf8();
    try {
      final result = _bindings.dna_engine_prepare_dht_from_mnemonic(_engine, mnemonicPtr);
      if (result != 0) {
        debugLog('DHT', 'Failed to prepare DHT from mnemonic: $result');
      }
    } finally {
      calloc.free(mnemonicPtr);
    }
  }

  /// Load and activate identity (v0.3.0 single-user model)
  ///
  /// [fingerprint] - Optional identity fingerprint (empty string = auto-detect)
  /// [password] - Optional password for encrypted keys (null if unencrypted)
  ///
  /// In v0.3.0 single-user model, fingerprint is optional. If not provided,
  /// the fingerprint will be computed from the flat key file.
  ///
  /// On Android (v0.5.5+): If identity was already loaded by the background
  /// service in BACKGROUND mode, this upgrades to FULL mode instead of
  /// reloading. This provides seamless handoff between service and Flutter.
  Future<void> loadIdentity({String? fingerprint, String? password}) async {
    // Android: Check if service already loaded identity in background mode
    if (Platform.isAndroid && isIdentityLoaded()) {
      final mode = getInitMode();
      if (mode == 1) {  // BACKGROUND mode
        // Upgrade to FULL mode instead of reloading
        final result = upgradeToForeground();
        if (result != 0) {
          throw DnaEngineException(result, 'Failed to upgrade to foreground mode');
        }
        return;
      }
      // Already in FULL mode, nothing to do
      return;
    }

    final completer = Completer<void>();
    final localId = _nextLocalId++;

    // v0.3.0: Empty string triggers auto-compute of fingerprint from flat key file
    final fpPtr = (fingerprint ?? '').toNativeUtf8();
    final pwPtr = password?.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(fpPtr);
      if (pwPtr != null) calloc.free(pwPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_load_identity(
      _engine,
      fpPtr.cast(),
      pwPtr?.cast() ?? nullptr,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      if (pwPtr != null) calloc.free(pwPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Check if identity is already loaded
  ///
  /// Returns true if identity is loaded, false otherwise.
  bool isIdentityLoaded() {
    return _bindings.dna_engine_is_identity_loaded(_engine);
  }

  /// Get the encrypted mnemonic (recovery phrase) for the current identity
  ///
  /// Returns the 24-word BIP39 mnemonic if stored, throws if not available.
  /// Note: Identities created before this feature won't have a stored mnemonic.
  String getMnemonic() {
    final mnemonicPtr = calloc<Uint8>(256);
    try {
      final result = _bindings.dna_engine_get_mnemonic(
        _engine,
        mnemonicPtr.cast(),
        256,
      );
      if (result != 0) {
        if (result == -110) {  // DNA_ENGINE_ERROR_NOT_FOUND
          throw DnaEngineException(result, 'Seed phrase not stored for this identity');
        }
        throw DnaEngineException.fromCode(result, _bindings);
      }
      return mnemonicPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(mnemonicPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // CONTACTS OPERATIONS
  // ---------------------------------------------------------------------------

  /// Get contact list
  Future<List<Contact>> getContacts() async {
    final completer = Completer<List<Contact>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_contact_t> contacts,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <Contact>[];
        for (var i = 0; i < count; i++) {
          result.add(Contact.fromNative((contacts + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_contacts(contacts, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaContactsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_contacts(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Add contact by fingerprint or registered name
  Future<void> addContact(String identifier) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final idPtr = identifier.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(idPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_add_contact(
      _engine,
      idPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(idPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Remove contact by fingerprint
  Future<void> removeContact(String fingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_remove_contact(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Set local nickname for a contact (synchronous, local-only)
  ///
  /// Sets a custom nickname that overrides the DHT display name.
  /// Pass null or empty string to clear the nickname.
  void setContactNickname(String fingerprint, String? nickname) {
    final fpPtr = fingerprint.toNativeUtf8();
    final hasNickname = nickname != null && nickname.isNotEmpty;
    final nicknamePtr = hasNickname ? nickname.toNativeUtf8() : nullptr;

    try {
      final result = _bindings.dna_engine_set_contact_nickname_sync(
        _engine,
        fpPtr.cast(),
        hasNickname ? nicknamePtr.cast() : nullptr,
      );
      if (result != 0) {
        throw DnaEngineException.fromCode(result, _bindings);
      }
    } finally {
      calloc.free(fpPtr);
      if (hasNickname) {
        calloc.free(nicknamePtr);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // CONTACT REQUESTS (ICQ-style)
  // ---------------------------------------------------------------------------

  /// Send contact request to another user
  Future<void> sendContactRequest(String recipientFingerprint, String? message) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final recipientPtr = recipientFingerprint.toNativeUtf8();
    final messagePtr = message?.toNativeUtf8() ?? nullptr;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(recipientPtr);
      if (messagePtr != nullptr) {
        calloc.free(messagePtr);
      }

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_send_contact_request(
      _engine,
      recipientPtr.cast(),
      messagePtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(recipientPtr);
      if (messagePtr != nullptr) {
        calloc.free(messagePtr);
      }
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get pending incoming contact requests
  Future<List<ContactRequest>> getContactRequests() async {
    final completer = Completer<List<ContactRequest>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_contact_request_t> requests,
        int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <ContactRequest>[];
        for (var i = 0; i < count; i++) {
          result.add(ContactRequest.fromNative((requests + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_contact_requests(requests, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaContactRequestsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_contact_requests(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get count of pending contact requests (synchronous)
  int getContactRequestCount() {
    return _bindings.dna_engine_get_contact_request_count(_engine);
  }

  /// Approve a contact request (makes mutual contact)
  Future<void> approveContactRequest(String fingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_approve_contact_request(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Deny a contact request (can retry later)
  Future<void> denyContactRequest(String fingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_deny_contact_request(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Block a user permanently
  Future<void> blockUser(String fingerprint, String? reason) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();
    final reasonPtr = reason?.toNativeUtf8() ?? nullptr;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(fpPtr);
      if (reasonPtr != nullptr) {
        calloc.free(reasonPtr);
      }

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_block_user(
      _engine,
      fpPtr.cast(),
      reasonPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      if (reasonPtr != nullptr) {
        calloc.free(reasonPtr);
      }
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Unblock a user
  Future<void> unblockUser(String fingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_unblock_user(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get list of blocked users
  Future<List<BlockedUser>> getBlockedUsers() async {
    final completer = Completer<List<BlockedUser>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_blocked_user_t> blocked,
        int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <BlockedUser>[];
        for (var i = 0; i < count; i++) {
          result.add(BlockedUser.fromNative((blocked + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_blocked_users(blocked, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaBlockedUsersCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_blocked_users(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Check if a user is blocked (synchronous)
  bool isUserBlocked(String fingerprint) {
    final fpPtr = fingerprint.toNativeUtf8();
    try {
      return _bindings.dna_engine_is_user_blocked(_engine, fpPtr.cast());
    } finally {
      calloc.free(fpPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // MESSAGING OPERATIONS
  // ---------------------------------------------------------------------------

  /// Send message to contact (async with callback)
  Future<void> sendMessage(String recipientFingerprint, String message) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final recipientPtr = recipientFingerprint.toNativeUtf8();
    final messagePtr = message.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(recipientPtr);
      calloc.free(messagePtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_send_message(
      _engine,
      recipientPtr.cast(),
      messagePtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(recipientPtr);
      calloc.free(messagePtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Queue message for async sending (returns immediately)
  ///
  /// Returns:
  /// - >= 0: queue slot ID (success)
  /// - -1: queue full (MessageQueueFullException)
  /// - -2: invalid args or not initialized
  int queueMessage(String recipientFingerprint, String message) {
    final recipientPtr = recipientFingerprint.toNativeUtf8();
    final messagePtr = message.toNativeUtf8();

    try {
      final result = _bindings.dna_engine_queue_message(
        _engine,
        recipientPtr.cast(),
        messagePtr.cast(),
      );
      return result;
    } finally {
      calloc.free(recipientPtr);
      calloc.free(messagePtr);
    }
  }

  /// Get message queue capacity
  int get messageQueueCapacity => _bindings.dna_engine_get_message_queue_capacity(_engine);

  /// Get current message queue size
  int get messageQueueSize => _bindings.dna_engine_get_message_queue_size(_engine);

  /// Set message queue capacity (1-100)
  bool setMessageQueueCapacity(int capacity) {
    return _bindings.dna_engine_set_message_queue_capacity(_engine, capacity) == 0;
  }

  /// Get conversation with contact
  Future<List<Message>> getConversation(String contactFingerprint) async {
    final completer = Completer<List<Message>>();
    final localId = _nextLocalId++;

    final contactPtr = contactFingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_message_t> messages,
                    int count, Pointer<Void> userData) {
      calloc.free(contactPtr);

      if (error == 0) {
        final result = <Message>[];
        for (var i = 0; i < count; i++) {
          result.add(Message.fromNative((messages + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_messages(messages, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaMessagesCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_conversation(
      _engine,
      contactPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(contactPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get conversation with contact (paginated)
  /// Messages are returned in DESC order (newest first)
  Future<ConversationPage> getConversationPage(
      String contactFingerprint, int limit, int offset) async {
    final completer = Completer<ConversationPage>();
    final localId = _nextLocalId++;

    final contactPtr = contactFingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_message_t> messages,
                    int count, int total, Pointer<Void> userData) {
      calloc.free(contactPtr);

      if (error == 0) {
        final result = <Message>[];
        for (var i = 0; i < count; i++) {
          result.add(Message.fromNative((messages + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_messages(messages, count);
        }
        completer.complete(ConversationPage(result, total));
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaMessagesPageCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_conversation_page(
      _engine,
      contactPtr.cast(),
      limit,
      offset,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(contactPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Delete a message from local database
  /// Returns true on success, false on error
  bool deleteMessage(int messageId) {
    return _bindings.dna_engine_delete_message_sync(_engine, messageId) == 0;
  }

  // ---------------------------------------------------------------------------
  // MESSAGE RETRY
  // ---------------------------------------------------------------------------

  /// Retry all pending/failed messages
  /// Called automatically on identity load and DHT reconnect.
  /// Can also be called manually to retry queued messages.
  /// Returns number of messages successfully retried, or -1 on error.
  int retryPendingMessages() {
    return _bindings.dna_engine_retry_pending_messages(_engine);
  }

  /// Retry a single failed message by ID
  /// Use this when user taps retry button on a failed message.
  /// Returns true on success, false on error.
  bool retryMessage(int messageId) {
    return _bindings.dna_engine_retry_message(_engine, messageId) == 0;
  }

  // ---------------------------------------------------------------------------
  // MESSAGE STATUS / READ RECEIPTS
  // ---------------------------------------------------------------------------

  /// Get unread message count for a specific contact (synchronous)
  int getUnreadCount(String contactFingerprint) {
    final contactPtr = contactFingerprint.toNativeUtf8();
    try {
      return _bindings.dna_engine_get_unread_count(_engine, contactPtr.cast());
    } finally {
      calloc.free(contactPtr);
    }
  }

  /// Mark all messages in conversation as read
  Future<void> markConversationRead(String contactFingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final contactPtr = contactFingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(contactPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_mark_conversation_read(
      _engine,
      contactPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(contactPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // GROUPS OPERATIONS
  // ---------------------------------------------------------------------------

  /// Get groups
  Future<List<Group>> getGroups() async {
    final completer = Completer<List<Group>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_group_t> groups,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <Group>[];
        for (var i = 0; i < count; i++) {
          result.add(Group.fromNative((groups + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_groups(groups, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaGroupsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_groups(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get pending invitations
  Future<List<Invitation>> getInvitations() async {
    final completer = Completer<List<Invitation>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_invitation_t> invitations,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <Invitation>[];
        for (var i = 0; i < count; i++) {
          result.add(Invitation.fromNative((invitations + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_invitations(invitations, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaInvitationsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_invitations(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // WALLET OPERATIONS
  // ---------------------------------------------------------------------------

  /// List wallets
  Future<List<Wallet>> listWallets() async {
    final completer = Completer<List<Wallet>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_wallet_t> wallets,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <Wallet>[];
        for (var i = 0; i < count; i++) {
          result.add(Wallet.fromNative((wallets + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_wallets(wallets, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaWalletsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_list_wallets(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get balances for wallet
  Future<List<Balance>> getBalances(int walletIndex) async {
    final completer = Completer<List<Balance>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_balance_t> balances,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <Balance>[];
        for (var i = 0; i < count; i++) {
          result.add(Balance.fromNative((balances + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_balances(balances, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaBalancesCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_balances(
      _engine,
      walletIndex,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get gas estimate for ETH transaction
  /// [gasSpeed]: 0=slow (0.8x), 1=normal (1x), 2=fast (1.5x)
  /// Returns null if estimate fails (e.g., network error)
  GasEstimate? estimateEthGas(int gasSpeed) {
    final estimatePtr = calloc<dna_gas_estimate_t>();
    try {
      final result = _bindings.dna_engine_estimate_eth_gas(gasSpeed, estimatePtr);
      if (result != 0) {
        return null;
      }
      return GasEstimate.fromNative(estimatePtr.ref);
    } finally {
      calloc.free(estimatePtr);
    }
  }

  /// Send tokens
  /// [gasSpeed]: 0=slow (0.8x), 1=normal (1x), 2=fast (1.5x)
  /// Returns the transaction hash on success
  Future<String> sendTokens({
    required int walletIndex,
    required String recipientAddress,
    required String amount,
    required String token,
    required String network,
    int gasSpeed = 1,
  }) async {
    final completer = Completer<String>();
    final localId = _nextLocalId++;

    final recipientPtr = recipientAddress.toNativeUtf8();
    final amountPtr = amount.toNativeUtf8();
    final tokenPtr = token.toNativeUtf8();
    final networkPtr = network.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Utf8> txHashPtr, Pointer<Void> userData) {
      calloc.free(recipientPtr);
      calloc.free(amountPtr);
      calloc.free(tokenPtr);
      calloc.free(networkPtr);

      if (error == 0) {
        final txHash = txHashPtr != nullptr ? txHashPtr.toDartString() : '';
        completer.complete(txHash);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaSendTokensCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_send_tokens(
      _engine,
      walletIndex,
      recipientPtr.cast(),
      amountPtr.cast(),
      tokenPtr.cast(),
      networkPtr.cast(),
      gasSpeed,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(recipientPtr);
      calloc.free(amountPtr);
      calloc.free(tokenPtr);
      calloc.free(networkPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get transaction history
  Future<List<Transaction>> getTransactions(int walletIndex, String network) async {
    final completer = Completer<List<Transaction>>();
    final localId = _nextLocalId++;

    final networkPtr = network.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_transaction_t> transactions,
                    int count, Pointer<Void> userData) {
      calloc.free(networkPtr);

      if (error == 0) {
        final result = <Transaction>[];
        for (var i = 0; i < count; i++) {
          result.add(Transaction.fromNative((transactions + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_transactions(transactions, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaTransactionsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_transactions(
      _engine,
      walletIndex,
      networkPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(networkPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // PRESENCE OPERATIONS
  // ---------------------------------------------------------------------------

  /// Lookup peer presence from DHT
  /// Returns DateTime when peer was last online, or epoch (1970) if not found
  Future<DateTime> lookupPresence(String fingerprint) async {
    final completer = Completer<DateTime>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, int lastSeen, Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        // Convert Unix timestamp (seconds) to DateTime
        if (lastSeen > 0) {
          completer.complete(DateTime.fromMillisecondsSinceEpoch(lastSeen * 1000));
        } else {
          // Not found - return epoch
          completer.complete(DateTime.fromMillisecondsSinceEpoch(0));
        }
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaPresenceCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_lookup_presence(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // OUTBOX LISTENERS (Real-time offline message notifications)
  // ---------------------------------------------------------------------------

  /// Start listening for updates to a contact's outbox
  ///
  /// Returns listener token (> 0 on success, 0 on failure).
  /// When the contact's outbox updates, DNA_EVENT_OUTBOX_UPDATED is fired.
  int listenOutbox(String contactFingerprint) {
    final fpPtr = contactFingerprint.toNativeUtf8();
    try {
      return _bindings.dna_engine_listen_outbox(_engine, fpPtr.cast());
    } finally {
      calloc.free(fpPtr);
    }
  }

  /// Cancel an active outbox listener
  void cancelOutboxListener(String contactFingerprint) {
    final fpPtr = contactFingerprint.toNativeUtf8();
    try {
      _bindings.dna_engine_cancel_outbox_listener(_engine, fpPtr.cast());
    } finally {
      calloc.free(fpPtr);
    }
  }

  /// Start listeners for all contacts' outboxes
  ///
  /// Convenience function that starts outbox listeners for all contacts
  /// in the local database. Call after loading identity.
  /// Returns number of listeners started.
  int listenAllContacts() {
    return _bindings.dna_engine_listen_all_contacts(_engine);
  }

  /// Cancel all active outbox listeners
  void cancelAllOutboxListeners() {
    _bindings.dna_engine_cancel_all_outbox_listeners(_engine);
  }

  // ---------------------------------------------------------------------------
  // BIP39 OPERATIONS
  // ---------------------------------------------------------------------------

  /// Generate a random 24-word BIP39 mnemonic
  String generateMnemonic() {
    final mnemonicPtr = calloc<Uint8>(BIP39_MAX_MNEMONIC_LENGTH);

    try {
      final result = _bindings.bip39_generate_mnemonic(
        BIP39_WORDS_24,
        mnemonicPtr.cast(),
        BIP39_MAX_MNEMONIC_LENGTH,
      );

      if (result != 0) {
        throw DnaEngineException(-1, 'Failed to generate mnemonic');
      }

      return mnemonicPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(mnemonicPtr);
    }
  }

  /// Validate a BIP39 mnemonic
  bool validateMnemonic(String mnemonic) {
    final mnemonicPtr = mnemonic.toNativeUtf8();

    try {
      return _bindings.bip39_validate_mnemonic(mnemonicPtr.cast());
    } finally {
      calloc.free(mnemonicPtr);
    }
  }

  /// Derive signing and encryption seeds from BIP39 mnemonic
  /// Returns a record with (signingSeed, encryptionSeed) as `List<int>`
  ({List<int> signingSeed, List<int> encryptionSeed}) deriveSeeds(
    String mnemonic, {
    String passphrase = '',
  }) {
    final mnemonicPtr = mnemonic.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final signingSeedPtr = calloc<Uint8>(32);
    final encryptionSeedPtr = calloc<Uint8>(32);

    try {
      final result = _bindings.qgp_derive_seeds_from_mnemonic(
        mnemonicPtr.cast(),
        passphrasePtr.cast(),
        signingSeedPtr,
        encryptionSeedPtr,
      );

      if (result != 0) {
        throw DnaEngineException(-1, 'Failed to derive seeds from mnemonic');
      }

      final signingSeed = <int>[];
      final encryptionSeed = <int>[];

      for (var i = 0; i < 32; i++) {
        signingSeed.add(signingSeedPtr[i]);
        encryptionSeed.add(encryptionSeedPtr[i]);
      }

      return (signingSeed: signingSeed, encryptionSeed: encryptionSeed);
    } finally {
      calloc.free(mnemonicPtr);
      calloc.free(passphrasePtr);
      calloc.free(signingSeedPtr);
      calloc.free(encryptionSeedPtr);
    }
  }

  /// Derive signing, encryption seeds AND 64-byte master seed from BIP39 mnemonic
  /// Returns a record with all seeds including masterSeed for multi-chain wallet derivation
  ({List<int> signingSeed, List<int> encryptionSeed, List<int> masterSeed}) deriveSeedsWithMaster(
    String mnemonic, {
    String passphrase = '',
  }) {
    final mnemonicPtr = mnemonic.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final signingSeedPtr = calloc<Uint8>(32);
    final encryptionSeedPtr = calloc<Uint8>(32);
    final masterSeedPtr = calloc<Uint8>(64);

    try {
      final result = _bindings.qgp_derive_seeds_with_master(
        mnemonicPtr.cast(),
        passphrasePtr.cast(),
        signingSeedPtr,
        encryptionSeedPtr,
        masterSeedPtr,
      );

      if (result != 0) {
        throw DnaEngineException(-1, 'Failed to derive seeds from mnemonic');
      }

      final signingSeed = <int>[];
      final encryptionSeed = <int>[];
      final masterSeed = <int>[];

      for (var i = 0; i < 32; i++) {
        signingSeed.add(signingSeedPtr[i]);
        encryptionSeed.add(encryptionSeedPtr[i]);
      }
      for (var i = 0; i < 64; i++) {
        masterSeed.add(masterSeedPtr[i]);
      }

      return (signingSeed: signingSeed, encryptionSeed: encryptionSeed, masterSeed: masterSeed);
    } finally {
      calloc.free(mnemonicPtr);
      calloc.free(passphrasePtr);
      calloc.free(signingSeedPtr);
      calloc.free(encryptionSeedPtr);
      calloc.free(masterSeedPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // IDENTITY OPERATIONS (continued)
  // ---------------------------------------------------------------------------

  /// Register a human-readable name in DHT
  Future<void> registerName(String name) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final namePtr = name.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(namePtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_register_name(
      _engine,
      namePtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(namePtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get display name for a fingerprint
  Future<String> getDisplayName(String fingerprint) async {
    final completer = Completer<String>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Utf8> displayName,
                    Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        if (displayName == nullptr) {
          completer.complete('');
        } else {
          try {
            completer.complete(displayName.toDartString());
          } catch (e) {
            completer.complete('');
          }
        }
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaDisplayNameCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_display_name(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get avatar for fingerprint
  /// Returns base64 encoded avatar, or null if no avatar set.
  Future<String?> getAvatar(String fingerprint) async {
    final completer = Completer<String?>();
    final localId = _nextLocalId++;

    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Utf8> avatar,
                    Pointer<Void> userData) {
      calloc.free(fpPtr);

      if (error == 0) {
        // nullptr means no avatar
        if (avatar == nullptr) {
          completer.complete(null);
        } else {
          try {
            final avatarStr = avatar.toDartString();
            completer.complete(avatarStr.isEmpty ? null : avatarStr);
          } catch (e) {
            completer.complete(null);
          }
        }
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaDisplayNameCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_avatar(
      _engine,
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Lookup name availability (name -> fingerprint)
  /// Returns fingerprint if name is taken, empty string if available.
  Future<String> lookupName(String name) async {
    final completer = Completer<String>();
    final localId = _nextLocalId++;

    final namePtr = name.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Utf8> fingerprint,
                    Pointer<Void> userData) {
      calloc.free(namePtr);

      if (error == 0) {
        // nullptr or empty string means name is available
        if (fingerprint == nullptr) {
          completer.complete('');
        } else {
          try {
            completer.complete(fingerprint.toDartString());
          } catch (e) {
            completer.complete('');
          }
        }
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaDisplayNameCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_lookup_name(
      _engine,
      namePtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(namePtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get registered name for current identity
  Future<String?> getRegisteredName() async {
    final completer = Completer<String?>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Utf8> displayName,
                    Pointer<Void> userData) {
      if (error == 0) {
        // Handle nullptr (no registered name)
        if (displayName == nullptr) {
          completer.complete(null);
        } else {
          try {
            final name = displayName.toDartString();
            completer.complete(name.isEmpty ? null : name);
          } catch (e) {
            // Invalid UTF-8 data - treat as no registered name
            completer.complete(null);
          }
        }
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaDisplayNameCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_registered_name(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // PROFILE OPERATIONS
  // ---------------------------------------------------------------------------

  /// Get current identity's profile from DHT
  Future<UserProfile> getProfile() async {
    final completer = Completer<UserProfile>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_profile_t> profile,
                    Pointer<Void> userData) {
      if (error == 0) {
        if (profile != nullptr) {
          final result = UserProfile.fromNative(profile.ref);
          _bindings.dna_free_profile(profile);
          completer.complete(result);
        } else {
          // No profile found, return empty profile
          completer.complete(UserProfile());
        }
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaProfileCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_profile(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Lookup any user's profile by fingerprint from DHT
  /// Use this to resolve a DNA fingerprint to their wallet address
  Future<UserProfile?> lookupProfile(String fingerprint) async {
    final completer = Completer<UserProfile?>();
    final localId = _nextLocalId++;

    final fingerprintPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_profile_t> profile,
                    Pointer<Void> userData) {
      calloc.free(fingerprintPtr);
      if (error == 0) {
        if (profile != nullptr) {
          final result = UserProfile.fromNative(profile.ref);
          _bindings.dna_free_profile(profile);
          completer.complete(result);
        } else {
          // No profile found
          completer.complete(null);
        }
      } else if (error == 5) {
        // DNA_ENGINE_ERROR_NOT_FOUND - return null instead of error
        completer.complete(null);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaProfileCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_lookup_profile(
      _engine,
      fingerprintPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fingerprintPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Refresh contact's profile from DHT (force, bypass cache)
  /// Use this when viewing a contact's profile to ensure up-to-date data
  Future<UserProfile?> refreshContactProfile(String fingerprint) async {
    final completer = Completer<UserProfile?>();
    final localId = _nextLocalId++;

    final fingerprintPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_profile_t> profile,
                    Pointer<Void> userData) {
      calloc.free(fingerprintPtr);
      if (error == 0) {
        if (profile != nullptr) {
          final result = UserProfile.fromNative(profile.ref);
          _bindings.dna_free_profile(profile);
          completer.complete(result);
        } else {
          completer.complete(null);
        }
      } else if (error == 5) {
        // DNA_ENGINE_ERROR_NOT_FOUND - return null instead of error
        completer.complete(null);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaProfileCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_refresh_contact_profile(
      _engine,
      fingerprintPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(fingerprintPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Update current identity's profile in DHT
  Future<void> updateProfile(UserProfile profile) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    // Allocate native profile struct
    final nativeProfile = calloc<dna_profile_t>();
    profile.toNative(nativeProfile);

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(nativeProfile);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_update_profile(
      _engine,
      nativeProfile,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(nativeProfile);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // GROUPS OPERATIONS (continued)
  // ---------------------------------------------------------------------------

  /// Create a new group
  Future<String> createGroup(String name, List<String> memberFingerprints) async {
    final completer = Completer<String>();
    final localId = _nextLocalId++;

    final namePtr = name.toNativeUtf8();

    // Allocate array of string pointers
    final membersPtr = calloc<Pointer<Utf8>>(memberFingerprints.length.clamp(1, 1000));
    for (var i = 0; i < memberFingerprints.length; i++) {
      membersPtr[i] = memberFingerprints[i].toNativeUtf8();
    }

    void onComplete(int requestId, int error, Pointer<Utf8> groupUuid,
                    Pointer<Void> userData) {
      // Free allocated memory (input params)
      calloc.free(namePtr);
      for (var i = 0; i < memberFingerprints.length; i++) {
        calloc.free(membersPtr[i]);
      }
      calloc.free(membersPtr);

      if (error == 0 && groupUuid != nullptr) {
        final uuid = groupUuid.toDartString();
        // Free C-allocated string (strdup'd in dna_handle_create_group)
        calloc.free(groupUuid);
        completer.complete(uuid);
      } else {
        if (groupUuid != nullptr) {
          calloc.free(groupUuid);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaGroupCreatedCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_create_group(
      _engine,
      namePtr.cast(),
      membersPtr,
      memberFingerprints.length,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(namePtr);
      for (var i = 0; i < memberFingerprints.length; i++) {
        calloc.free(membersPtr[i]);
      }
      calloc.free(membersPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Send message to a group
  Future<void> sendGroupMessage(String groupUuid, String message) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();
    final messagePtr = message.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(groupPtr);
      calloc.free(messagePtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_send_group_message(
      _engine,
      groupPtr.cast(),
      messagePtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      calloc.free(messagePtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get group conversation messages
  /// Messages are returned in ASC order (oldest first)
  Future<List<Message>> getGroupConversation(String groupUuid) async {
    final completer = Completer<List<Message>>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_message_t> messages,
                    int count, Pointer<Void> userData) {
      calloc.free(groupPtr);

      if (error == 0) {
        final result = <Message>[];
        for (var i = 0; i < count; i++) {
          result.add(Message.fromNative((messages + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_messages(messages, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaMessagesCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_group_conversation(
      _engine,
      groupPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Accept a group invitation
  Future<void> acceptInvitation(String groupUuid) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(groupPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_accept_invitation(
      _engine,
      groupPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Reject a group invitation
  Future<void> rejectInvitation(String groupUuid) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(groupPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_reject_invitation(
      _engine,
      groupPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Sync a group from DHT (metadata + GEK)
  /// Use this to recover GEK after app reinstall or database loss
  Future<void> syncGroupByUuid(String groupUuid) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(groupPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_sync_group_by_uuid(
      _engine,
      groupPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // FEED - CHANNELS
  // ---------------------------------------------------------------------------

  /// Get all feed channels from DHT registry
  Future<List<FeedChannel>> getFeedChannels() async {
    final completer = Completer<List<FeedChannel>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_channel_info_t> channels,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <FeedChannel>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedChannel.fromNative((channels + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_feed_channels(channels, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedChannelsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_feed_channels(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Create a new feed channel
  Future<FeedChannel> createFeedChannel(String name, String description) async {
    final completer = Completer<FeedChannel>();
    final localId = _nextLocalId++;

    final namePtr = name.toNativeUtf8();
    final descPtr = description.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_channel_info_t> channel,
                    Pointer<Void> userData) {
      calloc.free(namePtr);
      calloc.free(descPtr);

      if (error == 0 && channel != nullptr) {
        final result = FeedChannel.fromNative(channel.ref);
        _bindings.dna_free_feed_channels(channel, 1);
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedChannelCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_create_feed_channel(
      _engine,
      namePtr.cast(),
      descPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(namePtr);
      calloc.free(descPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Initialize default feed channels (#general, #announcements, etc.)
  Future<void> initDefaultChannels() async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_init_default_channels(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // FEED - POSTS
  // ---------------------------------------------------------------------------

  /// Get posts for a feed channel
  Future<List<FeedPost>> getFeedPosts(String channelId, {String? date}) async {
    final completer = Completer<List<FeedPost>>();
    final localId = _nextLocalId++;

    final channelPtr = channelId.toNativeUtf8();
    final datePtr = date?.toNativeUtf8() ?? nullptr;

    void onComplete(int requestId, int error, Pointer<dna_post_info_t> posts,
                    int count, Pointer<Void> userData) {
      calloc.free(channelPtr);
      if (date != null) calloc.free(datePtr);

      if (error == 0) {
        final result = <FeedPost>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedPost.fromNative((posts + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_feed_posts(posts, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedPostsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_feed_posts(
      _engine,
      channelPtr.cast(),
      datePtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(channelPtr);
      if (date != null) calloc.free(datePtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Create a new feed post
  Future<FeedPost> createFeedPost(String channelId, String text) async {
    final completer = Completer<FeedPost>();
    final localId = _nextLocalId++;

    final channelPtr = channelId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_post_info_t> post,
                    Pointer<Void> userData) {
      calloc.free(channelPtr);
      calloc.free(textPtr);

      if (error == 0 && post != nullptr) {
        final result = FeedPost.fromNative(post.ref);
        _bindings.dna_free_feed_post(post);
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedPostCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_create_feed_post(
      _engine,
      channelPtr.cast(),
      textPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(channelPtr);
      calloc.free(textPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // FEED - COMMENTS
  // ---------------------------------------------------------------------------

  /// Add a comment to a post
  Future<FeedComment> addFeedComment(String postId, String text) async {
    final completer = Completer<FeedComment>();
    final localId = _nextLocalId++;

    final postIdPtr = postId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_comment_info_t> comment,
                    Pointer<Void> userData) {
      calloc.free(postIdPtr);
      calloc.free(textPtr);

      if (error == 0 && comment != nullptr) {
        final result = FeedComment.fromNative(comment.ref);
        _bindings.dna_free_feed_comment(comment);
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedCommentCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_add_feed_comment(
      _engine,
      postIdPtr.cast(),
      textPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(postIdPtr);
      calloc.free(textPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get all comments for a post
  Future<List<FeedComment>> getFeedComments(String postId) async {
    final completer = Completer<List<FeedComment>>();
    final localId = _nextLocalId++;

    final postIdPtr = postId.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_comment_info_t> comments,
                    int count, Pointer<Void> userData) {
      calloc.free(postIdPtr);

      if (error == 0) {
        final result = <FeedComment>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedComment.fromNative((comments + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_feed_comments(comments, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedCommentsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_feed_comments(
      _engine,
      postIdPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(postIdPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // FEED - VOTES
  // ---------------------------------------------------------------------------

  /// Cast a vote on a feed post (+1 for upvote, -1 for downvote)
  Future<void> castFeedVote(String postId, int voteValue) async {
    if (voteValue != 1 && voteValue != -1) {
      throw DnaEngineException(-1, 'Vote value must be +1 or -1');
    }

    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final postIdPtr = postId.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(postIdPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_cast_feed_vote(
      _engine,
      postIdPtr.cast(),
      voteValue,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(postIdPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get vote counts for a post
  Future<FeedPost> getFeedVotes(String postId) async {
    final completer = Completer<FeedPost>();
    final localId = _nextLocalId++;

    final postIdPtr = postId.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_post_info_t> post,
                    Pointer<Void> userData) {
      calloc.free(postIdPtr);

      if (error == 0 && post != nullptr) {
        final result = FeedPost.fromNative(post.ref);
        _bindings.dna_free_feed_post(post);
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedPostCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_feed_votes(
      _engine,
      postIdPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(postIdPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // FEED - COMMENT VOTES
  // ---------------------------------------------------------------------------

  /// Cast a vote on a comment (+1 for upvote, -1 for downvote)
  Future<void> castCommentVote(String commentId, int voteValue) async {
    if (voteValue != 1 && voteValue != -1) {
      throw DnaEngineException(-1, 'Vote value must be +1 or -1');
    }

    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final commentIdPtr = commentId.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(commentIdPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_cast_comment_vote(
      _engine,
      commentIdPtr.cast(),
      voteValue,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(commentIdPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get vote counts for a comment
  Future<FeedComment> getCommentVotes(String commentId) async {
    final completer = Completer<FeedComment>();
    final localId = _nextLocalId++;

    final commentIdPtr = commentId.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_comment_info_t> comment,
                    Pointer<Void> userData) {
      calloc.free(commentIdPtr);

      if (error == 0 && comment != nullptr) {
        final result = FeedComment.fromNative(comment.ref);
        _bindings.dna_free_feed_comment(comment);
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedCommentCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_comment_votes(
      _engine,
      commentIdPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(commentIdPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // OFFLINE MESSAGE POLLING
  // ---------------------------------------------------------------------------

  /// Check DHT offline queue for new messages from contacts
  ///
  /// This polls all contacts' outboxes for messages addressed to this user.
  /// Should be called periodically (every 2 minutes) to catch messages when
  /// Tier 1 (TCP) and Tier 2 (ICE) connections fail.
  Future<void> checkOfflineMessages() async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_check_offline_messages(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Check for offline messages from a specific contact
  ///
  /// This queries only the specified contact's outbox instead of all contacts.
  /// Use this when entering a chat to get immediate updates from that contact.
  /// Faster than checkOfflineMessages() which checks all contacts.
  Future<void> checkOfflineMessagesFrom(String contactFingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;
    final fpNative = contactFingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
      calloc.free(fpNative);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_check_offline_messages_from(
      _engine,
      fpNative,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      calloc.free(fpNative);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Refresh presence in DHT (announce we're online)
  ///
  /// This publishes presence to DHT so peers can discover we're online.
  /// Should be called when app comes to foreground.
  Future<void> refreshPresence() async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_refresh_presence(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Pause presence updates (call when app goes to background)
  ///
  /// Stops the heartbeat thread that announces our presence.
  /// Should be called when Android app goes to background.
  void pausePresence() {
    _bindings.dna_engine_pause_presence(_engine);
  }

  /// Resume presence updates (call when app comes to foreground)
  ///
  /// Restarts the heartbeat thread that announces our presence.
  /// Should be called when Android app comes back to foreground.
  void resumePresence() {
    _bindings.dna_engine_resume_presence(_engine);
  }

  /// Handle network connectivity change
  ///
  /// Reinitializes the DHT connection when network changes (e.g., WiFi to cellular).
  /// This is called automatically by the Android ForegroundService when
  /// ConnectivityManager detects a network change.
  ///
  /// Returns 0 on success, -1 on error.
  int networkChanged() {
    return _bindings.dna_engine_network_changed(_engine);
  }

  // ---------------------------------------------------------------------------
  // VERSION
  // ---------------------------------------------------------------------------

  /// Get DNA Messenger version string from native library
  ///
  /// Returns version like "0.2.5" - single source of truth from version.h
  static String getVersion(DnaBindings bindings) {
    final ptr = bindings.dna_engine_get_version();
    if (ptr == nullptr) return 'unknown';
    return ptr.toDartString();
  }

  /// Get version (instance method)
  String get version {
    final ptr = _bindings.dna_engine_get_version();
    if (ptr == nullptr) return 'unknown';
    return ptr.toDartString();
  }

  /// Check for version updates from DHT
  ///
  /// Returns null if the check failed (e.g., no DHT connection or no version published).
  /// Returns VersionCheckResult with update flags if successful.
  VersionCheckResult? checkVersionDht() {
    final resultPtr = calloc<dna_version_check_result_t>();
    try {
      final ret = _bindings.dna_engine_check_version_dht(_engine, resultPtr);
      if (ret != 0) {
        return null;
      }
      return VersionCheckResult.fromNative(resultPtr.ref);
    } finally {
      calloc.free(resultPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // DHT STATUS
  // ---------------------------------------------------------------------------

  /// Check if DHT is currently connected
  ///
  /// Use this to query current DHT status, especially when the event-based
  /// status update may have been missed (e.g., on startup race condition).
  bool isDhtConnected() {
    return _bindings.dna_engine_is_dht_connected(_engine) != 0;
  }

  // ---------------------------------------------------------------------------
  // LOG CONFIGURATION
  // ---------------------------------------------------------------------------

  /// Get current log level
  String getLogLevel() {
    final ptr = _bindings.dna_engine_get_log_level();
    if (ptr == nullptr) return 'WARN';
    return ptr.toDartString();
  }

  /// Set log level
  /// Valid values: DEBUG, INFO, WARN, ERROR, NONE
  bool setLogLevel(String level) {
    final levelPtr = level.toNativeUtf8();
    try {
      final result = _bindings.dna_engine_set_log_level(levelPtr);
      return result == 0;
    } finally {
      calloc.free(levelPtr);
    }
  }

  /// Get current log tags filter
  /// Returns comma-separated tags (empty = show all)
  String getLogTags() {
    final ptr = _bindings.dna_engine_get_log_tags();
    if (ptr == nullptr) return '';
    return ptr.toDartString();
  }

  /// Set log tags filter
  /// Provide comma-separated tags to show (empty = show all)
  bool setLogTags(String tags) {
    final tagsPtr = tags.toNativeUtf8();
    try {
      final result = _bindings.dna_engine_set_log_tags(tagsPtr);
      return result == 0;
    } finally {
      calloc.free(tagsPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // DEBUG LOG RING BUFFER
  // ---------------------------------------------------------------------------

  /// Enable or disable debug log ring buffer
  /// When enabled, logs are captured for in-app viewing
  void debugLogEnable(bool enabled) {
    _bindings.dna_engine_debug_log_enable(enabled);
  }

  /// Check if debug logging is enabled
  bool debugLogIsEnabled() {
    return _bindings.dna_engine_debug_log_is_enabled();
  }

  /// Get debug log entries from ring buffer
  /// Returns list of DebugLogEntry objects
  List<DebugLogEntry> debugLogGetEntries({int maxEntries = 200}) {
    final entriesPtr = calloc<dna_debug_log_entry_t>(maxEntries);
    try {
      final count = _bindings.dna_engine_debug_log_get_entries(entriesPtr, maxEntries);
      final entries = <DebugLogEntry>[];
      for (var i = 0; i < count; i++) {
        final entry = entriesPtr[i];
        entries.add(DebugLogEntry(
          timestampMs: entry.timestamp_ms,
          level: DebugLogLevel.values[entry.level.clamp(0, 3)],
          tag: entry.tag.toDartString(32),
          message: entry.message.toDartString(256),
        ));
      }
      return entries;
    } finally {
      calloc.free(entriesPtr);
    }
  }

  /// Get number of entries in debug log buffer
  int debugLogCount() {
    return _bindings.dna_engine_debug_log_count();
  }

  /// Clear all debug log entries
  void debugLogClear() {
    _bindings.dna_engine_debug_log_clear();
  }

  /// Log a message to the debug ring buffer (visible in in-app log viewer)
  void debugLog(String tag, String message) {
    _bindings.dna_engine_debug_log_message(tag, message);
  }

  /// Log a message with explicit level to the debug ring buffer
  /// Level: 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
  void debugLogLevel(String tag, String message, int level) {
    _bindings.dna_engine_debug_log_message_level(tag, message, level);
  }

  /// Export debug logs to a file
  /// Returns true on success, false on error
  bool debugLogExport(String filepath) {
    return _bindings.dna_engine_debug_log_export(filepath) == 0;
  }

  // ---------------------------------------------------------------------------
  // MESSAGE BACKUP/RESTORE
  // ---------------------------------------------------------------------------

  /// Result of a backup or restore operation
  /// [processedCount] - Number of messages backed up or restored
  /// [skippedCount] - Number of duplicates skipped (restore only)
  /// [success] - True if operation completed successfully
  /// [errorMessage] - Error message if operation failed

  /// Backup all messages to DHT
  /// Returns the number of messages backed up
  /// Throws [DnaEngineException] on error
  Future<BackupResult> backupMessages() async {
    final completer = Completer<BackupResult>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, int processedCount, int skippedCount, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete(BackupResult(
          processedCount: processedCount,
          skippedCount: skippedCount,
          success: true,
        ));
      } else {
        completer.complete(BackupResult(
          processedCount: 0,
          skippedCount: 0,
          success: false,
          errorMessage: error == -2 ? 'No backup found' : 'Backup failed (error: $error)',
        ));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaBackupResultCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_backup_messages(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit backup request');
    }

    return completer.future;
  }

  /// Restore messages from DHT
  /// Returns the number of messages restored and skipped duplicates
  /// Throws [DnaEngineException] on error
  Future<BackupResult> restoreMessages() async {
    final completer = Completer<BackupResult>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, int processedCount, int skippedCount, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete(BackupResult(
          processedCount: processedCount,
          skippedCount: skippedCount,
          success: true,
        ));
      } else if (error == -2) {
        completer.complete(BackupResult(
          processedCount: 0,
          skippedCount: 0,
          success: false,
          errorMessage: 'No backup found in DHT',
        ));
      } else {
        completer.complete(BackupResult(
          processedCount: 0,
          skippedCount: 0,
          success: false,
          errorMessage: 'Restore failed (error: $error)',
        ));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaBackupResultCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_restore_messages(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit restore request');
    }

    return completer.future;
  }

  /// Check if message backup exists in DHT (v0.4.60)
  /// Returns backup info without downloading the full backup
  /// Used for new device restore flow
  Future<BackupInfo> checkBackupExists() async {
    final completer = Completer<BackupInfo>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_backup_info_t> info, Pointer<Void> userData) {
      if (error == 0 && info != nullptr) {
        final infoRef = info.ref;
        completer.complete(BackupInfo(
          exists: infoRef.exists,
          timestamp: infoRef.timestamp > 0
              ? DateTime.fromMillisecondsSinceEpoch(infoRef.timestamp * 1000)
              : null,
          messageCount: infoRef.message_count,
        ));
      } else {
        // No backup found or error - return exists=false
        completer.complete(BackupInfo(
          exists: false,
          messageCount: 0,
        ));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaBackupInfoCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_check_backup_exists(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      // Return no backup instead of throwing - graceful degradation
      return BackupInfo(exists: false, messageCount: 0);
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // ADDRESS BOOK OPERATIONS
  // ---------------------------------------------------------------------------

  /// Get all address book entries
  Future<List<AddressBookEntry>> getAddressBook() async {
    final completer = Completer<List<AddressBookEntry>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error,
        Pointer<dna_addressbook_entry_t> entries, int count,
        Pointer<Void> userData) {
      if (error == 0) {
        final result = <AddressBookEntry>[];
        for (var i = 0; i < count; i++) {
          result.add(AddressBookEntry.fromNative((entries + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_addressbook_entries(entries, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback =
        NativeCallable<DnaAddressbookCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_addressbook(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get address book entries filtered by network
  Future<List<AddressBookEntry>> getAddressBookByNetwork(String network) async {
    final completer = Completer<List<AddressBookEntry>>();
    final localId = _nextLocalId++;
    final networkPtr = network.toNativeUtf8();

    void onComplete(int requestId, int error,
        Pointer<dna_addressbook_entry_t> entries, int count,
        Pointer<Void> userData) {
      calloc.free(networkPtr);

      if (error == 0) {
        final result = <AddressBookEntry>[];
        for (var i = 0; i < count; i++) {
          result.add(AddressBookEntry.fromNative((entries + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_addressbook_entries(entries, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback =
        NativeCallable<DnaAddressbookCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_addressbook_by_network(
      _engine,
      networkPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(networkPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get recently used addresses
  Future<List<AddressBookEntry>> getRecentAddresses({int limit = 10}) async {
    final completer = Completer<List<AddressBookEntry>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error,
        Pointer<dna_addressbook_entry_t> entries, int count,
        Pointer<Void> userData) {
      if (error == 0) {
        final result = <AddressBookEntry>[];
        for (var i = 0; i < count; i++) {
          result.add(AddressBookEntry.fromNative((entries + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_addressbook_entries(entries, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback =
        NativeCallable<DnaAddressbookCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_recent_addresses(
      _engine,
      limit,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Add a new address to the address book
  /// Returns the new entry ID on success, or throws on failure
  int addAddress({
    required String address,
    required String label,
    required String network,
    String notes = '',
  }) {
    final addressPtr = address.toNativeUtf8();
    final labelPtr = label.toNativeUtf8();
    final networkPtr = network.toNativeUtf8();
    final notesPtr = notes.toNativeUtf8();

    try {
      final result = _bindings.dna_engine_add_address(
        _engine,
        addressPtr.cast(),
        labelPtr.cast(),
        networkPtr.cast(),
        notesPtr.cast(),
      );
      if (result < 0) {
        throw DnaEngineException(result, 'Failed to add address');
      }
      return result;
    } finally {
      calloc.free(addressPtr);
      calloc.free(labelPtr);
      calloc.free(networkPtr);
      calloc.free(notesPtr);
    }
  }

  /// Update an existing address in the address book
  void updateAddress({
    required int id,
    required String label,
    String notes = '',
  }) {
    final labelPtr = label.toNativeUtf8();
    final notesPtr = notes.toNativeUtf8();

    try {
      final result = _bindings.dna_engine_update_address(
        _engine,
        id,
        labelPtr.cast(),
        notesPtr.cast(),
      );
      if (result != 0) {
        throw DnaEngineException(result, 'Failed to update address');
      }
    } finally {
      calloc.free(labelPtr);
      calloc.free(notesPtr);
    }
  }

  /// Remove an address from the address book
  void removeAddress(int id) {
    final result = _bindings.dna_engine_remove_address(_engine, id);
    if (result != 0) {
      throw DnaEngineException(result, 'Failed to remove address');
    }
  }

  /// Check if an address exists in the address book
  bool addressExists(String address, String network) {
    final addressPtr = address.toNativeUtf8();
    final networkPtr = network.toNativeUtf8();

    try {
      return _bindings.dna_engine_address_exists(
        _engine,
        addressPtr.cast(),
        networkPtr.cast(),
      );
    } finally {
      calloc.free(addressPtr);
      calloc.free(networkPtr);
    }
  }

  /// Look up an address and return its entry if found
  AddressBookEntry? lookupAddress(String address, String network) {
    final addressPtr = address.toNativeUtf8();
    final networkPtr = network.toNativeUtf8();
    final entryPtr = calloc<dna_addressbook_entry_t>();

    try {
      final result = _bindings.dna_engine_lookup_address(
        _engine,
        addressPtr.cast(),
        networkPtr.cast(),
        entryPtr,
      );
      if (result == 0) {
        return AddressBookEntry.fromNative(entryPtr.ref);
      }
      return null;
    } finally {
      calloc.free(addressPtr);
      calloc.free(networkPtr);
      calloc.free(entryPtr);
    }
  }

  /// Increment the usage count for an address
  void incrementAddressUsage(int id) {
    final result = _bindings.dna_engine_increment_address_usage(_engine, id);
    if (result != 0) {
      throw DnaEngineException(result, 'Failed to increment address usage');
    }
  }

  /// Sync address book to DHT (backup)
  Future<void> syncAddressBookToDht() async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_sync_addressbook_to_dht(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit sync request');
    }

    return completer.future;
  }

  /// Sync address book from DHT (restore)
  Future<void> syncAddressBookFromDht() async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else if (error == -2) {
        // No data in DHT - not an error, just empty
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_sync_addressbook_from_dht(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit sync request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // SIGNING (for QR Auth)
  // ---------------------------------------------------------------------------

  /// Sign arbitrary data with the loaded identity's Dilithium5 key
  ///
  /// Used for QR-based authentication flows where the app needs to prove
  /// identity to external services.
  ///
  /// Returns the signature as Uint8List (up to 4627 bytes for Dilithium5).
  /// Throws [DnaEngineException] on error.
  /// Dilithium5 max signature size is 4627 bytes
  static const int _dilithium5MaxSigLen = 4627;

  Uint8List signData(Uint8List data) {
    final dataPtr = calloc<Uint8>(data.length);
    final signaturePtr = calloc<Uint8>(_dilithium5MaxSigLen);
    final sigLenPtr = calloc<Size>();

    try {
      // Copy input data
      dataPtr.asTypedList(data.length).setAll(0, data);

      final rc = _bindings.dna_engine_sign_data(
        _engine,
        dataPtr,
        data.length,
        signaturePtr,
        sigLenPtr,
      );

      if (rc != 0) {
        throw DnaEngineException.fromCode(rc, _bindings);
      }

      final sigLen = sigLenPtr.value;

      // HARDEN: validate returned length
      if (sigLen == 0 || sigLen > _dilithium5MaxSigLen) {
        throw DnaEngineException(-1, 'Invalid signature length: $sigLen');
      }

      // Fast copy
      return Uint8List.fromList(signaturePtr.asTypedList(sigLen));
    } finally {
      calloc.free(dataPtr);
      calloc.free(signaturePtr);
      calloc.free(sigLenPtr);
    }
  }

  /// Dilithium5 public key size is 2592 bytes
  static const int _dilithium5PubKeyLen = 2592;

  /// Get the loaded identity's Dilithium5 signing public key
  ///
  /// Returns the raw public key bytes (2592 bytes for Dilithium5).
  /// Throws [DnaEngineException] on error (e.g., no identity loaded).
  Uint8List get signingPublicKey {
    // Use 4096 buffer to be safe
    const bufferSize = 4096;
    final pubkeyPtr = calloc<Uint8>(bufferSize);

    try {
      final rc = _bindings.dna_engine_get_signing_public_key(
        _engine,
        pubkeyPtr,
        bufferSize,
      );

      if (rc < 0) {
        throw DnaEngineException.fromCode(rc, _bindings);
      }

      // rc is the number of bytes written
      if (rc == 0 || rc > bufferSize) {
        throw DnaEngineException(-1, 'Invalid public key length: $rc');
      }

      // Fast copy
      return Uint8List.fromList(pubkeyPtr.asTypedList(rc));
    } finally {
      calloc.free(pubkeyPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // GROUP INFO OPERATIONS
  // ---------------------------------------------------------------------------

  /// Get extended group information including GEK version
  Future<GroupInfo> getGroupInfo(String groupUuid) async {
    final completer = Completer<GroupInfo>();
    final localId = _nextLocalId++;

    final uuidPtr = groupUuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_group_info_t> info,
        Pointer<Void> userData) {
      calloc.free(uuidPtr);

      if (error == 0 && info != nullptr) {
        final result = GroupInfo.fromNative(info.ref);
        _bindings.dna_free_group_info(info);
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaGroupInfoCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_group_info(
      _engine,
      uuidPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(uuidPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get list of group members
  Future<List<GroupMember>> getGroupMembers(String groupUuid) async {
    final completer = Completer<List<GroupMember>>();
    final localId = _nextLocalId++;

    final uuidPtr = groupUuid.toNativeUtf8();

    void onComplete(int requestId, int error,
        Pointer<dna_group_member_t> members, int count, Pointer<Void> userData) {
      calloc.free(uuidPtr);

      if (error == 0) {
        final result = <GroupMember>[];
        for (var i = 0; i < count; i++) {
          result.add(GroupMember.fromNative((members + i).ref));
        }
        if (count > 0) {
          _bindings.dna_free_group_members(members, count);
        }
        completer.complete(result);
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback =
        NativeCallable<DnaGroupMembersCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_group_members(
      _engine,
      uuidPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(uuidPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // CLEANUP
  // ---------------------------------------------------------------------------

  void _cleanupRequest(int localId) {
    final request = _pendingRequests.remove(localId);
    request?.callback.close();
  }

  /// Detach the event callback (call when app goes to background)
  /// This prevents crashes when native code tries to invoke a deleted Dart callback
  /// after Flutter is killed but ForegroundService continues running.
  void detachEventCallback() {
    if (_isDisposed) return;
    _bindings.dna_engine_set_event_callback(_engine, nullptr, nullptr);
  }

  /// Re-attach the event callback (call when app comes back to foreground)
  void attachEventCallback() {
    if (_isDisposed || _eventCallback == null) return;
    _bindings.dna_engine_set_event_callback(
      _engine,
      _eventCallback!.nativeFunction.cast(),
      nullptr,
    );
  }

  /// Dispose the engine and release all resources
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    _eventController.close();

    // IMPORTANT: Clear the C callback pointer BEFORE closing the Dart callback
    // This prevents the C code from invoking a deleted callback when the app
    // goes to background but the background service is still running
    _bindings.dna_engine_set_event_callback(_engine, nullptr, nullptr);
    _eventCallback?.close();

    // Clean up pending requests
    for (final request in _pendingRequests.values) {
      request.callback.close();
    }
    _pendingRequests.clear();

    _bindings.dna_engine_destroy(_engine);
  }
}

// =============================================================================
// HELPERS
// =============================================================================

class _PendingRequest {
  final NativeCallable callback;

  _PendingRequest({required this.callback});
}
