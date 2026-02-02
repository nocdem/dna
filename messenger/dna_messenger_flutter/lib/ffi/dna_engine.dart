// High-level Dart wrapper for DNA Messenger Engine
// Converts C callbacks to Dart Futures/Streams

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart' show kDebugMode;

import 'dna_bindings.dart';

// Debug logging helper - only prints in debug mode
void _debugLog(String message) {
  if (kDebugMode) {
    // ignore: avoid_print
    print(message);
  }
}

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
      // v15: Map native status to new 4-state enum (0-3)
      // Legacy migration: old DELIVERED(3)/READ(4) → RECEIVED(2), old STALE(5) → FAILED(3)
      status: _mapNativeStatus(native.status),
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

/// Message status (v15: simplified 4-state model)
/// - pending: Queued locally, not yet sent to DHT
/// - sent: Successfully published to DHT (single checkmark)
/// - received: Recipient ACK'd (double checkmark)
/// - failed: Failed to publish (will auto-retry)
enum MessageStatus { pending, sent, received, failed }

/// Map native status value to MessageStatus enum
/// Handles legacy values from old 6-state model
MessageStatus _mapNativeStatus(int status) {
  switch (status) {
    case 0: return MessageStatus.pending;
    case 1: return MessageStatus.sent;
    case 2: return MessageStatus.received;
    case 3: return MessageStatus.failed;
    // Legacy migration:
    case 4: return MessageStatus.received;  // Old READ → RECEIVED
    case 5: return MessageStatus.failed;    // Old STALE → FAILED
    default: return MessageStatus.pending;
  }
}
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

  // Profile info (NOTE: displayName removed in v0.6.24 - use registered name only)
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
    // NOTE: display_name removed in v0.6.24 - only registered name is used
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

// =============================================================================
// FEED v2 MODELS (Topics, Comments, Subscriptions)
// =============================================================================

/// Feed topic information (v0.6.91+)
class FeedTopic {
  final String uuid;
  final String authorFingerprint;
  final String title;
  final String body;
  final String categoryId;
  final List<String> tags;
  final DateTime createdAt;
  final bool deleted;
  final DateTime? deletedAt;

  FeedTopic({
    required this.uuid,
    required this.authorFingerprint,
    required this.title,
    required this.body,
    required this.categoryId,
    required this.tags,
    required this.createdAt,
    required this.deleted,
    this.deletedAt,
  });

  factory FeedTopic.fromNative(dna_feed_topic_info_t native) {
    // Parse tags from flattened array - up to 5 tags, 33 chars each (32 + null)
    final tags = <String>[];
    for (int i = 0; i < native.tag_count && i < 5; i++) {
      final bytes = <int>[];
      for (int j = 0; j < 33; j++) {
        final char = native.tags_flat[i * 33 + j];
        if (char == 0) break;
        bytes.add(char & 0xFF);
      }
      if (bytes.isNotEmpty) {
        tags.add(utf8.decode(bytes, allowMalformed: true));
      }
    }

    return FeedTopic(
      uuid: native.topic_uuid.toDartString(37),
      authorFingerprint: native.author_fingerprint.toDartString(129),
      title: native.title != nullptr ? native.title.toDartString() : '',
      body: native.body != nullptr ? native.body.toDartString() : '',
      categoryId: native.category_id.toDartString(65),
      tags: tags,
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
      deleted: native.deleted,
      deletedAt: native.deleted_at > 0
          ? DateTime.fromMillisecondsSinceEpoch(native.deleted_at * 1000)
          : null,
    );
  }

  /// Returns the category name (lowercased from category_id)
  String get categoryName => categoryId.toLowerCase();
}

/// Feed comment information (v0.6.91+, with reply support v0.6.96+)
class FeedComment {
  final String uuid;
  final String topicUuid;
  final String? parentCommentUuid; // Reply-to comment UUID (null = top-level)
  final String authorFingerprint;
  final String body;
  final List<String> mentions;
  final DateTime createdAt;

  FeedComment({
    required this.uuid,
    required this.topicUuid,
    this.parentCommentUuid,
    required this.authorFingerprint,
    required this.body,
    required this.mentions,
    required this.createdAt,
  });

  /// True if this is a reply to another comment
  bool get isReply => parentCommentUuid != null && parentCommentUuid!.isNotEmpty;

  factory FeedComment.fromNative(dna_feed_comment_info_t native) {
    // Parse mentions from flattened array - up to 10 mentions, 129 chars each
    final mentions = <String>[];
    for (int i = 0; i < native.mention_count && i < 10; i++) {
      final bytes = <int>[];
      for (int j = 0; j < 129; j++) {
        final char = native.mentions_flat[i * 129 + j];
        if (char == 0) break;
        bytes.add(char & 0xFF);
      }
      if (bytes.isNotEmpty) {
        mentions.add(utf8.decode(bytes, allowMalformed: true));
      }
    }

    // Parse parent_comment_uuid (empty = top-level)
    final parentUuid = native.parent_comment_uuid.toDartString(37);

    return FeedComment(
      uuid: native.comment_uuid.toDartString(37),
      topicUuid: native.topic_uuid.toDartString(37),
      parentCommentUuid: parentUuid.isNotEmpty ? parentUuid : null,
      authorFingerprint: native.author_fingerprint.toDartString(129),
      body: native.body != nullptr ? native.body.toDartString() : '',
      mentions: mentions,
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
    );
  }
}

/// Feed subscription information (v0.6.91+)
class FeedSubscription {
  final String topicUuid;
  final DateTime subscribedAt;
  final DateTime? lastSynced;

  FeedSubscription({
    required this.topicUuid,
    required this.subscribedAt,
    this.lastSynced,
  });

  factory FeedSubscription.fromNative(dna_feed_subscription_info_t native) {
    return FeedSubscription(
      topicUuid: native.topic_uuid.toDartString(37),
      subscribedAt: DateTime.fromMillisecondsSinceEpoch(native.subscribed_at * 1000),
      lastSynced: native.last_synced > 0
          ? DateTime.fromMillisecondsSinceEpoch(native.last_synced * 1000)
          : null,
    );
  }
}

/// Default feed categories
class FeedCategories {
  static const general = 'general';
  static const technology = 'technology';
  static const help = 'help';
  static const announcements = 'announcements';
  static const trading = 'trading';
  static const offtopic = 'offtopic';

  static const all = [general, technology, help, announcements, trading, offtopic];

  /// SHA256 hash → display name lookup
  /// C library stores category_id as SHA256(lowercase(name)), Flutter needs to reverse-map
  static final Map<String, String> _hashToName = {
    _computeCategoryHash(general): 'General',
    _computeCategoryHash(technology): 'Technology',
    _computeCategoryHash(help): 'Help',
    _computeCategoryHash(announcements): 'Announcements',
    _computeCategoryHash(trading): 'Trading',
    _computeCategoryHash(offtopic): 'Off-Topic',
  };

  /// Compute SHA256 hash of category name (matches C library's dna_feed_make_category_id)
  static String _computeCategoryHash(String name) {
    final bytes = utf8.encode(name.toLowerCase());
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  /// Get display name for a category (handles both name and SHA256 hash)
  static String displayName(String category) {
    // Check hash map first (C stores 64-char SHA256 hashes)
    if (category.length == 64 && _hashToName.containsKey(category)) {
      return _hashToName[category]!;
    }

    // Fall back to name matching
    switch (category.toLowerCase()) {
      case general:
        return 'General';
      case technology:
        return 'Technology';
      case help:
        return 'Help';
      case announcements:
        return 'Announcements';
      case trading:
        return 'Trading';
      case offtopic:
        return 'Off-Topic';
      default:
        return category;
    }
  }
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

/// Groups synced from DHT event - triggered when groups are restored on new device
class GroupsSyncedEvent extends DnaEvent {
  final int groupsRestored;
  GroupsSyncedEvent(this.groupsRestored);
}

/// Contacts synced from DHT event - triggered when contacts are restored on new device
class ContactsSyncedEvent extends DnaEvent {
  final int contactsSynced;
  ContactsSyncedEvent(this.contactsSynced);
}

/// GEKs synced from DHT event - triggered when group encryption keys are restored
class GeksSyncedEvent extends DnaEvent {
  final int geksSynced;
  GeksSyncedEvent(this.geksSynced);
}

/// Feed topic comment event - new comment on a subscribed topic (v0.6.91+)
class FeedTopicCommentEvent extends DnaEvent {
  final String topicUuid;
  final String commentUuid;
  final String authorFingerprint;
  FeedTopicCommentEvent(this.topicUuid, this.commentUuid, this.authorFingerprint);
}

/// Feed subscriptions synced from DHT event (v0.6.91+)
class FeedSubscriptionsSyncedEvent extends DnaEvent {
  final int subscriptionsSynced;
  FeedSubscriptionsSyncedEvent(this.subscriptionsSynced);
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
  late Pointer<dna_engine_t> _engine;
  final _eventController = StreamController<DnaEvent>.broadcast();

  // Callback registry to prevent GC
  final Map<int, _PendingRequest> _pendingRequests = {};
  int _nextLocalId = 1;

  // Event callback storage
  NativeCallable<DnaEventCbNative>? _eventCallback;

  // Async creation tracking (for cancellation on early dispose)
  // Stored to prevent GC of NativeCallable during async creation
  // ignore: unused_field
  NativeCallable<DnaEngineCreatedCbNative>? _createCallback;
  Pointer<Bool>? _createCancelledPtr;

  bool _isDisposed = false;

  /// Event stream for pushed notifications
  Stream<DnaEvent> get events => _eventController.stream;

  /// Check if engine is initialized
  bool get isInitialized => !_isDisposed;

  /// Check if engine has been disposed
  bool get isDisposed => _isDisposed;

  DnaEngine._();

  /// Create and initialize the DNA engine
  ///
  /// v0.6.0+: Each caller (Flutter/Service) owns its own engine and DHT context.
  /// The identity lock mechanism in C code prevents simultaneous access.
  /// When identity is loaded, the engine acquires a file lock and creates
  /// its own DHT context - no global sharing needed.
  ///
  /// v0.6.18+: Uses async C function with cancellation support to avoid UI freeze.
  /// If disposed before completion, the cancelled flag prevents callback crash.
  static Future<DnaEngine> create({String? dataDir}) async {
    final engine = DnaEngine._();
    engine._bindings = DnaBindings(_loadLibrary());

    final completer = Completer<void>();
    final dataDirPtr = dataDir?.toNativeUtf8() ?? nullptr;

    // Allocate cancelled flag in native memory (C thread checks this atomically)
    final cancelledPtr = calloc<Bool>();
    cancelledPtr.value = false;
    engine._createCancelledPtr = cancelledPtr;

    // Callback receives engine pointer from background thread
    void onEngineCreated(Pointer<dna_engine_t> enginePtr, int error, Pointer<Void> userData) {
      // Check if we were cancelled (shouldn't happen - C checks first, but be safe)
      if (cancelledPtr.value || completer.isCompleted) {
        return;
      }

      if (error != 0 || enginePtr == nullptr) {
        completer.completeError(DnaEngineException(error, 'Failed to create engine'));
        return;
      }

      engine._engine = enginePtr;
      completer.complete();
    }

    // Create native callback that can be called from any thread
    final callback = NativeCallable<DnaEngineCreatedCbNative>.listener(onEngineCreated);
    engine._createCallback = callback;

    // Start async engine creation (returns immediately, runs on background thread)
    engine._bindings.dna_engine_create_async(
      dataDirPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
      cancelledPtr,
    );

    // Wait for creation to complete (UI thread stays responsive)
    try {
      await completer.future;
    } finally {
      // Free data dir string (C made its own copy)
      if (dataDir != null) {
        calloc.free(dataDirPtr);
      }
      // Clean up tracking (callback/cancelled pointer freed in dispose or here)
      callback.close();
      calloc.free(cancelledPtr);
      engine._createCallback = null;
      engine._createCancelledPtr = null;
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
    // CRITICAL: Check _isDisposed BEFORE dereferencing any pointers!
    // After dispose, C memory may be freed - dereferencing would crash.
    if (_isDisposed) {
      _debugLog('[DART-EVENT] Callback invoked after dispose, ignoring');
      return;
    }

    final event = eventPtr.ref;
    final type = event.type;
    _debugLog('[DART-EVENT] _onEventReceived called, type=$type');

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
          status: MessageStatus.received,
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
        _debugLog('[DART-EVENT] MESSAGE_SENT: messageId=$messageId, status=$status');
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
      case DnaEventType.DNA_EVENT_GROUPS_SYNCED:
        // Parse groups_restored (int32 at offset 0)
        final groupsRestored = event.data[0] |
            (event.data[1] << 8) |
            (event.data[2] << 16) |
            (event.data[3] << 24);
        dartEvent = GroupsSyncedEvent(groupsRestored);
        break;
      case DnaEventType.DNA_EVENT_CONTACTS_SYNCED:
        // Parse contacts_synced (int32 at offset 0)
        final contactsSynced = event.data[0] |
            (event.data[1] << 8) |
            (event.data[2] << 16) |
            (event.data[3] << 24);
        dartEvent = ContactsSyncedEvent(contactsSynced);
        break;
      case DnaEventType.DNA_EVENT_GEKS_SYNCED:
        // Parse geks_synced (int32 at offset 0)
        final geksSynced = event.data[0] |
            (event.data[1] << 8) |
            (event.data[2] << 16) |
            (event.data[3] << 24);
        dartEvent = GeksSyncedEvent(geksSynced);
        break;
      case DnaEventType.DNA_EVENT_FEED_TOPIC_COMMENT:
        // Parse feed_topic_comment event data:
        // - topic_uuid: 37 bytes at offset 0
        // - comment_uuid: 37 bytes at offset 40 (aligned)
        // - author_fingerprint: 129 bytes at offset 80
        final topicUuidBytes = <int>[];
        for (var i = 0; i < 37; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          topicUuidBytes.add(byte);
        }
        final topicUuid = String.fromCharCodes(topicUuidBytes);

        final commentUuidBytes = <int>[];
        for (var i = 40; i < 77; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          commentUuidBytes.add(byte);
        }
        final commentUuid = String.fromCharCodes(commentUuidBytes);

        final authorFpBytes = <int>[];
        for (var i = 80; i < 209; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          authorFpBytes.add(byte);
        }
        final authorFp = String.fromCharCodes(authorFpBytes);

        dartEvent = FeedTopicCommentEvent(topicUuid, commentUuid, authorFp);
        break;
      case DnaEventType.DNA_EVENT_FEED_SUBSCRIPTIONS_SYNCED:
        // Parse subscriptions_synced (int32 at offset 0)
        final subscriptionsSynced = event.data[0] |
            (event.data[1] << 8) |
            (event.data[2] << 16) |
            (event.data[3] << 24);
        dartEvent = FeedSubscriptionsSyncedEvent(subscriptionsSynced);
        break;
      case DnaEventType.DNA_EVENT_ERROR:
        dartEvent = ErrorEvent(0, 'Error occurred');
        break;
      default:
        // Unknown event type
        break;
    }

    if (dartEvent != null) {
      _debugLog('[DART-EVENT] Adding to stream: ${dartEvent.runtimeType}');
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
  /// Single-owner model (v0.5.24+): Flutter owns the engine when app is open.
  /// If identity is already loaded with transport ready, this is a no-op.
  /// If identity is loaded but transport not ready (minimal mode), will upgrade to full mode.
  Future<void> loadIdentity({String? fingerprint, String? password}) async {
    // Check if identity already loaded
    if (isIdentityLoaded()) {
      // If transport is ready, nothing to do
      if (isTransportReady()) {
        return;
      }
      // Transport not ready (loaded in minimal mode by service)
      // Proceed with full load to initialize transport
      debugLog('IDENTITY', 'Identity loaded but transport not ready - upgrading to full mode');
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

  /// Check if transport layer is ready
  ///
  /// Returns false if identity was loaded in minimal mode (DHT only).
  /// When false, offline message fetching won't work.
  bool isTransportReady() {
    return _bindings.dna_engine_is_transport_ready(_engine);
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

  /// Queue group message for async sending (returns immediately)
  ///
  /// Returns:
  /// - >= 0: queue slot ID (success)
  /// - -1: queue full
  /// - -2: invalid args or not initialized
  int queueGroupMessage(String groupUuid, String message) {
    final groupPtr = groupUuid.toNativeUtf8();
    final messagePtr = message.toNativeUtf8();

    try {
      final result = _bindings.dna_engine_queue_group_message(
        _engine,
        groupPtr.cast(),
        messagePtr.cast(),
      );
      return result;
    } finally {
      calloc.free(groupPtr);
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
  // IDENTITY OPERATIONS (continued)
  // ---------------------------------------------------------------------------
  // NOTE: BIP39 operations (generateMnemonic, validateMnemonic, deriveSeedsWithMaster)
  // moved to crypto_isolate.dart to run in separate isolates and avoid blocking UI.

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

  /// Add a member to a group (owner only)
  /// Automatically rotates GEK for forward secrecy
  Future<void> addGroupMember(String groupUuid, String fingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();
    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(groupPtr);
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

    final requestId = _bindings.dna_engine_add_group_member(
      _engine,
      groupPtr.cast(),
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      calloc.free(fpPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Remove a member from a group (owner only)
  /// Automatically rotates GEK for forward secrecy
  Future<void> removeGroupMember(String groupUuid, String fingerprint) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final groupPtr = groupUuid.toNativeUtf8();
    final fpPtr = fingerprint.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(groupPtr);
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

    final requestId = _bindings.dna_engine_remove_group_member(
      _engine,
      groupPtr.cast(),
      fpPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(groupPtr);
      calloc.free(fpPtr);
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

  // ---------------------------------------------------------------------------
  // ENGINE PAUSE/RESUME (v0.6.50+)
  // ---------------------------------------------------------------------------

  /// Pause engine for background mode
  ///
  /// Suspends DHT listeners and presence heartbeat while keeping the engine
  /// alive. This allows fast resume (<500ms) when the app returns to foreground,
  /// avoiding the expensive full reinitialization (2-40 seconds).
  ///
  /// What stays alive during pause:
  /// - DHT connection
  /// - Identity lock
  /// - Databases
  /// - Worker threads (idle)
  ///
  /// What gets suspended:
  /// - DHT listeners (can be resubscribed quickly)
  /// - Presence heartbeat (stops marking us as online)
  ///
  /// Returns true on success, false on failure (e.g., no identity loaded).
  bool pause() {
    if (_isDisposed) return false;
    final result = _bindings.dna_engine_pause(_engine);
    return result == 0;
  }

  /// Resume engine from background mode
  ///
  /// Reactivates a paused engine by resubscribing DHT listeners and
  /// resuming presence heartbeat. This is much faster than destroying
  /// and recreating the engine.
  ///
  /// Returns true on success, false on failure.
  Future<bool> resume() async {
    if (_isDisposed) return false;
    final result = _bindings.dna_engine_resume(_engine);
    // Note: Don't call checkOfflineMessages() here!
    // C-side resume() spawns a background thread to resubscribe DHT listeners.
    // checkOfflineMessages() requires DHT to be ready, but background thread
    // hasn't finished yet. Awaiting would block forever.
    // contacts_provider._completeInitialLoad() handles this with proper timeout.
    return result == 0;
  }

  /// Check if engine is currently paused
  ///
  /// Returns true if engine is in paused state, false otherwise.
  bool get isPaused {
    if (_isDisposed) return false;
    return _bindings.dna_engine_is_paused(_engine);
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

  /// Sync contacts from DHT to local database
  ///
  /// Fetches user's contact list from DHT and replaces local contacts.
  /// DHT is authoritative - deletions propagate.
  Future<void> syncContactsFromDht() async {
    final localId = _nextLocalId++;
    final completer = Completer<void>();

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

    final requestId = _bindings.dna_engine_sync_contacts_from_dht(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit sync contacts request');
    }

    return completer.future;
  }

  /// Restore groups from DHT grouplist to local database
  ///
  /// Fetches user's personal group list from DHT and restores
  /// group metadata to local database. Used for multi-device sync.
  Future<void> restoreGroupsFromDht() async {
    final localId = _nextLocalId++;
    final completer = Completer<void>();

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

    final requestId = _bindings.dna_engine_restore_groups_from_dht(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit restore groups request');
    }

    return completer.future;
  }

  /// Sync local groups to DHT (push)
  ///
  /// Publishes the user's group membership list to DHT for multi-device sync.
  /// This is the PUSH direction - local -> DHT.
  Future<void> syncGroupsToDht() async {
    final localId = _nextLocalId++;
    final completer = Completer<void>();

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

    final requestId = _bindings.dna_engine_sync_groups_to_dht(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit sync groups to DHT request');
    }

    return completer.future;
  }

  /// Sync groups FROM DHT (pull latest metadata)
  ///
  /// Fetches the latest group metadata from DHT and updates local cache.
  /// This is the PULL direction - DHT -> local.
  /// Use this for background sync after loading local cache.
  Future<void> syncGroups() async {
    final localId = _nextLocalId++;
    final completer = Completer<void>();

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

    final requestId = _bindings.dna_engine_sync_groups(
      _engine,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit sync groups request');
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
  // FEED v2 - Topics, Comments, Subscriptions (v0.6.91+)
  // ---------------------------------------------------------------------------

  /// Create a new feed topic
  ///
  /// [title] - Topic title (max 200 chars)
  /// [body] - Topic body (max 4000 chars)
  /// [category] - Category name (e.g., "general", "technology")
  /// [tags] - Optional list of tags (max 5 tags, 32 chars each)
  ///
  /// Returns the created topic on success.
  Future<FeedTopic> feedCreateTopic(
    String title,
    String body,
    String category, {
    List<String> tags = const [],
  }) async {
    final completer = Completer<FeedTopic>();
    final localId = _nextLocalId++;

    final titlePtr = title.toNativeUtf8();
    final bodyPtr = body.toNativeUtf8();
    final categoryPtr = category.toNativeUtf8();

    // Convert tags to JSON array
    final tagsJson = tags.isEmpty ? '[]' : '["${tags.join('","')}"]';
    final tagsPtr = tagsJson.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_feed_topic_info_t> topic,
                    Pointer<Void> userData) {
      calloc.free(titlePtr);
      calloc.free(bodyPtr);
      calloc.free(categoryPtr);
      calloc.free(tagsPtr);

      if (error == 0 && topic != nullptr) {
        final result = FeedTopic.fromNative(topic.ref);
        _bindings.dna_free_feed_topic(topic);
        completer.complete(result);
      } else {
        if (topic != nullptr) {
          _bindings.dna_free_feed_topic(topic);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedTopicCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_create_topic(
      _engine,
      titlePtr.cast(),
      bodyPtr.cast(),
      categoryPtr.cast(),
      tagsPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(titlePtr);
      calloc.free(bodyPtr);
      calloc.free(categoryPtr);
      calloc.free(tagsPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get a specific feed topic by UUID
  Future<FeedTopic> feedGetTopic(String uuid) async {
    final completer = Completer<FeedTopic>();
    final localId = _nextLocalId++;

    final uuidPtr = uuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_feed_topic_info_t> topic,
                    Pointer<Void> userData) {
      calloc.free(uuidPtr);

      if (error == 0 && topic != nullptr) {
        final result = FeedTopic.fromNative(topic.ref);
        _bindings.dna_free_feed_topic(topic);
        completer.complete(result);
      } else {
        if (topic != nullptr) {
          _bindings.dna_free_feed_topic(topic);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedTopicCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_get_topic(
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

  /// Delete a feed topic (soft delete - author only)
  Future<void> feedDeleteTopic(String uuid) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final uuidPtr = uuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      calloc.free(uuidPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_delete_topic(
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

  /// Add a comment to a feed topic (optionally as a reply)
  ///
  /// [topicUuid] - UUID of the topic to comment on
  /// [body] - Comment text (max 2000 chars)
  /// [parentCommentUuid] - UUID of parent comment for replies (null = top-level)
  /// [mentions] - Optional list of fingerprints to @mention
  ///
  /// Returns the created comment on success.
  Future<FeedComment> feedAddComment(
    String topicUuid,
    String body, {
    String? parentCommentUuid,
    List<String> mentions = const [],
  }) async {
    final completer = Completer<FeedComment>();
    final localId = _nextLocalId++;

    final topicPtr = topicUuid.toNativeUtf8();
    final parentPtr = parentCommentUuid?.toNativeUtf8();
    final bodyPtr = body.toNativeUtf8();

    // Convert mentions to JSON array
    final mentionsJson = mentions.isEmpty ? '[]' : '["${mentions.join('","')}"]';
    final mentionsPtr = mentionsJson.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_feed_comment_info_t> comment,
                    Pointer<Void> userData) {
      calloc.free(topicPtr);
      if (parentPtr != null) calloc.free(parentPtr);
      calloc.free(bodyPtr);
      calloc.free(mentionsPtr);

      if (error == 0 && comment != nullptr) {
        final result = FeedComment.fromNative(comment.ref);
        _bindings.dna_free_feed_comment(comment);
        completer.complete(result);
      } else {
        if (comment != nullptr) {
          _bindings.dna_free_feed_comment(comment);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedCommentCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_add_comment(
      _engine,
      topicPtr.cast(),
      parentPtr?.cast() ?? nullptr,
      bodyPtr.cast(),
      mentionsPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(topicPtr);
      if (parentPtr != null) calloc.free(parentPtr);
      calloc.free(bodyPtr);
      calloc.free(mentionsPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get all comments for a feed topic
  Future<List<FeedComment>> feedGetComments(String topicUuid) async {
    final completer = Completer<List<FeedComment>>();
    final localId = _nextLocalId++;

    final topicPtr = topicUuid.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_feed_comment_info_t> comments,
                    int count, Pointer<Void> userData) {
      calloc.free(topicPtr);

      if (error == 0) {
        final result = <FeedComment>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedComment.fromNative(comments[i]));
        }
        if (comments != nullptr && count > 0) {
          _bindings.dna_free_feed_comments(comments, count);
        }
        completer.complete(result);
      } else {
        if (comments != nullptr && count > 0) {
          _bindings.dna_free_feed_comments(comments, count);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedCommentsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_get_comments(
      _engine,
      topicPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(topicPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get feed topics by category
  ///
  /// [category] - Category name (e.g., "general", "technology")
  /// [daysBack] - Number of days to look back (default 7)
  Future<List<FeedTopic>> feedGetCategory(String category, {int daysBack = 7}) async {
    final completer = Completer<List<FeedTopic>>();
    final localId = _nextLocalId++;

    final categoryPtr = category.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<dna_feed_topic_info_t> topics,
                    int count, Pointer<Void> userData) {
      calloc.free(categoryPtr);

      if (error == 0) {
        final result = <FeedTopic>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedTopic.fromNative(topics[i]));
        }
        if (topics != nullptr && count > 0) {
          _bindings.dna_free_feed_topics(topics, count);
        }
        completer.complete(result);
      } else {
        if (topics != nullptr && count > 0) {
          _bindings.dna_free_feed_topics(topics, count);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedTopicsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_get_category(
      _engine,
      categoryPtr.cast(),
      daysBack,
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(categoryPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit request');
    }

    return completer.future;
  }

  /// Get all recent feed topics across all categories
  ///
  /// [daysBack] - Number of days to look back (default 7)
  Future<List<FeedTopic>> feedGetAll({int daysBack = 7}) async {
    final completer = Completer<List<FeedTopic>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_feed_topic_info_t> topics,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <FeedTopic>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedTopic.fromNative(topics[i]));
        }
        if (topics != nullptr && count > 0) {
          _bindings.dna_free_feed_topics(topics, count);
        }
        completer.complete(result);
      } else {
        if (topics != nullptr && count > 0) {
          _bindings.dna_free_feed_topics(topics, count);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedTopicsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_get_all(
      _engine,
      daysBack,
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
  // FEED v2 - Subscriptions (v0.6.91+)
  // ---------------------------------------------------------------------------

  /// Subscribe to a feed topic (receive notifications for new comments)
  ///
  /// Returns true on success, false if already subscribed.
  bool feedSubscribe(String topicUuid) {
    final uuidPtr = topicUuid.toNativeUtf8();
    try {
      final result = _bindings.dna_engine_feed_subscribe(_engine, uuidPtr.cast());
      return result == 0;
    } finally {
      calloc.free(uuidPtr);
    }
  }

  /// Unsubscribe from a feed topic
  ///
  /// Returns true on success, false if not subscribed.
  bool feedUnsubscribe(String topicUuid) {
    final uuidPtr = topicUuid.toNativeUtf8();
    try {
      final result = _bindings.dna_engine_feed_unsubscribe(_engine, uuidPtr.cast());
      return result == 0;
    } finally {
      calloc.free(uuidPtr);
    }
  }

  /// Check if subscribed to a feed topic
  bool feedIsSubscribed(String topicUuid) {
    final uuidPtr = topicUuid.toNativeUtf8();
    try {
      final result = _bindings.dna_engine_feed_is_subscribed(_engine, uuidPtr.cast());
      return result != 0;
    } finally {
      calloc.free(uuidPtr);
    }
  }

  /// Get all feed subscriptions
  Future<List<FeedSubscription>> feedGetSubscriptions() async {
    final completer = Completer<List<FeedSubscription>>();
    final localId = _nextLocalId++;

    void onComplete(int requestId, int error, Pointer<dna_feed_subscription_info_t> subs,
                    int count, Pointer<Void> userData) {
      if (error == 0) {
        final result = <FeedSubscription>[];
        for (var i = 0; i < count; i++) {
          result.add(FeedSubscription.fromNative(subs[i]));
        }
        if (subs != nullptr && count > 0) {
          _bindings.dna_free_feed_subscriptions(subs, count);
        }
        completer.complete(result);
      } else {
        if (subs != nullptr && count > 0) {
          _bindings.dna_free_feed_subscriptions(subs, count);
        }
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaFeedSubscriptionsCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_feed_get_subscriptions(
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

  /// Sync feed subscriptions to DHT (for multi-device)
  Future<void> feedSyncSubscriptionsToDht() async {
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

    final requestId = _bindings.dna_engine_feed_sync_subscriptions_to_dht(
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

  /// Sync feed subscriptions from DHT (for multi-device)
  Future<void> feedSyncSubscriptionsFromDht() async {
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

    final requestId = _bindings.dna_engine_feed_sync_subscriptions_from_dht(
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
  ///
  /// On Android, the C code releases the identity lock FIRST before any cleanup
  /// that might crash due to DHT callback races. This allows ForegroundService
  /// to take over immediately. Any crash after lock release doesn't matter -
  /// the process will die anyway and OS cleans up memory.
  void dispose() {
    _debugLog('[DART-DISPOSE] dispose() called, _isDisposed=$_isDisposed');
    if (_isDisposed) {
      _debugLog('[DART-DISPOSE] Already disposed, returning');
      return;
    }
    _isDisposed = true;
    _debugLog('[DART-DISPOSE] Set _isDisposed=true');

    // Check if async creation is still in progress
    // If so, set cancelled flag - C thread will destroy engine and skip callback
    if (_createCancelledPtr != null) {
      _debugLog('[DART-DISPOSE] Async creation in progress, setting cancelled flag');
      _createCancelledPtr!.value = true;
      // Don't close callback or free pointer here - create()'s finally block will do it
      // Don't call dna_engine_destroy - we don't have an engine yet
      // The C thread will check the flag and destroy the engine itself
      _debugLog('[DART-DISPOSE] Cancelled flag set, returning early');
      return;
    }

    // Clear the C callback pointer to prevent new callbacks
    _debugLog('[DART-DISPOSE] Clearing C event callback...');
    _bindings.dna_engine_set_event_callback(_engine, nullptr, nullptr);
    _debugLog('[DART-DISPOSE] C event callback cleared');

    // Clear pending requests
    _debugLog('[DART-DISPOSE] Clearing ${_pendingRequests.length} pending requests...');
    _pendingRequests.clear();
    _debugLog('[DART-DISPOSE] Pending requests cleared');

    // Close the event controller
    _debugLog('[DART-DISPOSE] Closing event controller...');
    _eventController.close();
    _debugLog('[DART-DISPOSE] Event controller closed');

    // Call destroy - on Android, the C code releases the identity lock FIRST
    // before any cleanup that might crash. Even if a crash occurs later,
    // the lock is already free and ForegroundService can take over.
    _debugLog('[DART-DISPOSE] Calling dna_engine_destroy()...');
    _bindings.dna_engine_destroy(_engine);
    _debugLog('[DART-DISPOSE] dna_engine_destroy() returned');

    // On Android, skip NativeCallable cleanup - process will die anyway
    // and closing these while callbacks might be in flight causes crashes.
    if (!Platform.isAndroid) {
      _eventCallback?.close();
      _eventCallback = null;
    }
    _engine = nullptr;
    _debugLog('[DART-DISPOSE] dispose() complete');
  }
}

// =============================================================================
// HELPERS
// =============================================================================

class _PendingRequest {
  final NativeCallable callback;

  _PendingRequest({required this.callback});
}
