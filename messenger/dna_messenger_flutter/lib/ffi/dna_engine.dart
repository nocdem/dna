// High-level Dart wrapper for DNA Messenger Engine
// Converts C callbacks to Dart Futures/Streams

import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'dna_bindings.dart';

// =============================================================================
// DART MODELS
// =============================================================================

/// Contact information
class Contact {
  final String fingerprint;
  final String displayName;
  final bool isOnline;
  final DateTime lastSeen;

  Contact({
    required this.fingerprint,
    required this.displayName,
    required this.isOnline,
    required this.lastSeen,
  });

  factory Contact.fromNative(dna_contact_t native) {
    return Contact(
      fingerprint: native.fingerprint.toDartString(129),
      displayName: native.display_name.toDartString(256),
      isOnline: native.is_online,
      lastSeen: DateTime.fromMillisecondsSinceEpoch(native.last_seen * 1000),
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
      status: MessageStatus.values[native.status.clamp(0, 4)],
      type: native.message_type == 0 ? MessageType.chat : MessageType.groupInvitation,
    );
  }

  /// Create a pending outgoing message (for optimistic UI)
  factory Message.pending({
    required String sender,
    required String recipient,
    required String plaintext,
  }) {
    return Message(
      id: -DateTime.now().millisecondsSinceEpoch, // Negative temp ID
      sender: sender,
      recipient: recipient,
      plaintext: plaintext,
      timestamp: DateTime.now(),
      isOutgoing: true,
      status: MessageStatus.pending,
      type: MessageType.chat,
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

enum MessageStatus { pending, sent, failed, delivered, read }
enum MessageType { chat, groupInvitation }

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

/// User profile information (synced with DHT dna_unified_identity_t)
class UserProfile {
  // Cellframe wallets
  String backbone;
  String alvin;

  // External wallets
  String btc;
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

  UserProfile({
    this.backbone = '',
    this.alvin = '',
    this.btc = '',
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
    return UserProfile(
      backbone: native.backbone.toDartString(120),
      alvin: native.alvin.toDartString(120),
      btc: native.btc.toDartString(128),
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
      avatarBase64: native.avatar_base64.toDartString(20484),
    );
  }

  /// Copy profile data to native struct
  void toNative(Pointer<dna_profile_t> native) {
    _copyStringToArray(backbone, native.ref.backbone, 120);
    _copyStringToArray(alvin, native.ref.alvin, 120);
    _copyStringToArray(btc, native.ref.btc, 128);
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
      btc.isEmpty &&
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
    String? btc,
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
      btc: btc ?? this.btc,
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
  final int messageId;
  MessageDeliveredEvent(this.messageId);
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
  static Future<DnaEngine> create({String? dataDir}) async {
    final engine = DnaEngine._();
    engine._bindings = DnaBindings(_loadLibrary());

    final dataDirPtr = dataDir?.toNativeUtf8() ?? nullptr;
    engine._engine = engine._bindings.dna_engine_create(dataDirPtr.cast());

    if (dataDir != null) {
      calloc.free(dataDirPtr);
    }

    if (engine._engine == nullptr) {
      throw DnaEngineException(-100, 'Failed to create engine');
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
    if (_isDisposed) return;

    final event = eventPtr.ref;
    final type = event.type;

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
        // Note: Union parsing requires careful offset calculation
        // For now, we'll handle this in a simplified way
        dartEvent = MessageReceivedEvent(Message(
          id: 0,
          sender: '',
          recipient: '',
          plaintext: 'New message received',
          timestamp: DateTime.now(),
          isOutgoing: false,
          status: MessageStatus.delivered,
          type: MessageType.chat,
        ));
        break;
      case DnaEventType.DNA_EVENT_CONTACT_ONLINE:
        // Parse fingerprint from union data
        dartEvent = ContactOnlineEvent('');
        break;
      case DnaEventType.DNA_EVENT_CONTACT_OFFLINE:
        dartEvent = ContactOfflineEvent('');
        break;
      case DnaEventType.DNA_EVENT_IDENTITY_LOADED:
        dartEvent = IdentityLoadedEvent('');
        break;
      case DnaEventType.DNA_EVENT_ERROR:
        dartEvent = ErrorEvent(0, 'Error occurred');
        break;
      default:
        // Unknown event type
        break;
    }

    if (dartEvent != null) {
      _eventController.add(dartEvent);
    }
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
  /// walletSeed is DEPRECATED - use mnemonic for Cellframe wallet instead
  /// masterSeed is the 64-byte BIP39 master seed for multi-chain wallet derivation (ETH, SOL)
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  String createIdentitySync(String name, List<int> signingSeed, List<int> encryptionSeed, List<int>? walletSeed, {List<int>? masterSeed, String? mnemonic}) {
    if (name.isEmpty) {
      throw ArgumentError('Name is required');
    }
    if (signingSeed.length != 32 || encryptionSeed.length != 32) {
      throw ArgumentError('Seeds must be 32 bytes each');
    }
    if (walletSeed != null && walletSeed.length != 32) {
      throw ArgumentError('Wallet seed must be 32 bytes');
    }
    if (masterSeed != null && masterSeed.length != 64) {
      throw ArgumentError('Master seed must be 64 bytes');
    }

    final namePtr = name.toNativeUtf8();
    final sigSeedPtr = calloc<Uint8>(32);
    final encSeedPtr = calloc<Uint8>(32);
    final walletSeedPtr = walletSeed != null ? calloc<Uint8>(32) : nullptr;
    final masterSeedPtr = masterSeed != null ? calloc<Uint8>(64) : nullptr;
    final mnemonicPtr = mnemonic != null ? mnemonic.toNativeUtf8() : nullptr;
    final fingerprintPtr = calloc<Uint8>(129); // 128 hex chars + null

    try {
      for (var i = 0; i < 32; i++) {
        sigSeedPtr[i] = signingSeed[i];
        encSeedPtr[i] = encryptionSeed[i];
        if (walletSeed != null) {
          walletSeedPtr[i] = walletSeed[i];
        }
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
        walletSeedPtr,
        masterSeedPtr,
        mnemonicPtr?.cast() ?? nullptr,
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
      if (walletSeed != null) {
        calloc.free(walletSeedPtr);
      }
      if (masterSeed != null) {
        calloc.free(masterSeedPtr);
      }
      if (mnemonicPtr != null) {
        calloc.free(mnemonicPtr);
      }
      calloc.free(fingerprintPtr);
    }
  }

  /// Create new identity from BIP39 seeds (async wrapper)
  /// name is required - used for directory structure and wallet naming
  /// walletSeed is DEPRECATED - use mnemonic for Cellframe wallet instead
  /// masterSeed is the 64-byte BIP39 master seed for multi-chain wallet derivation (ETH, SOL)
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  Future<String> createIdentity(String name, List<int> signingSeed, List<int> encryptionSeed, {List<int>? walletSeed, List<int>? masterSeed, String? mnemonic}) async {
    // Use sync version wrapped in compute to avoid blocking UI
    return createIdentitySync(name, signingSeed, encryptionSeed, walletSeed, masterSeed: masterSeed, mnemonic: mnemonic);
  }

  /// Restore identity from BIP39 seeds (synchronous)
  /// Creates keys and wallets locally without DHT name registration.
  /// Use this when restoring an existing identity from seed phrase.
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  String restoreIdentitySync(List<int> signingSeed, List<int> encryptionSeed, List<int>? walletSeed, {List<int>? masterSeed, String? mnemonic}) {
    if (signingSeed.length != 32 || encryptionSeed.length != 32) {
      throw ArgumentError('Seeds must be 32 bytes each');
    }
    if (walletSeed != null && walletSeed.length != 32) {
      throw ArgumentError('Wallet seed must be 32 bytes');
    }
    if (masterSeed != null && masterSeed.length != 64) {
      throw ArgumentError('Master seed must be 64 bytes');
    }

    final sigSeedPtr = calloc<Uint8>(32);
    final encSeedPtr = calloc<Uint8>(32);
    final walletSeedPtr = walletSeed != null ? calloc<Uint8>(32) : nullptr;
    final masterSeedPtr = masterSeed != null ? calloc<Uint8>(64) : nullptr;
    final mnemonicPtr = mnemonic != null ? mnemonic.toNativeUtf8() : nullptr;
    final fingerprintPtr = calloc<Uint8>(129); // 128 hex chars + null

    try {
      for (var i = 0; i < 32; i++) {
        sigSeedPtr[i] = signingSeed[i];
        encSeedPtr[i] = encryptionSeed[i];
        if (walletSeed != null) {
          walletSeedPtr[i] = walletSeed[i];
        }
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
        walletSeedPtr,
        masterSeedPtr,
        mnemonicPtr?.cast() ?? nullptr,
        fingerprintPtr.cast(),
      );

      if (error != 0) {
        throw DnaEngineException.fromCode(error, _bindings);
      }

      return fingerprintPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(sigSeedPtr);
      calloc.free(encSeedPtr);
      if (walletSeed != null) {
        calloc.free(walletSeedPtr);
      }
      if (masterSeed != null) {
        calloc.free(masterSeedPtr);
      }
      if (mnemonicPtr != null) {
        calloc.free(mnemonicPtr);
      }
      calloc.free(fingerprintPtr);
    }
  }

  /// Restore identity from BIP39 seeds (async wrapper)
  /// Creates keys and wallets locally without DHT name registration.
  /// mnemonic is the space-separated BIP39 mnemonic for Cellframe wallet (SHA3-256 derivation)
  Future<String> restoreIdentity(List<int> signingSeed, List<int> encryptionSeed, {List<int>? walletSeed, List<int>? masterSeed, String? mnemonic}) async {
    return restoreIdentitySync(signingSeed, encryptionSeed, walletSeed, masterSeed: masterSeed, mnemonic: mnemonic);
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

  /// Load and activate identity
  Future<void> loadIdentity(String fingerprint) async {
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

    final requestId = _bindings.dna_engine_load_identity(
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
          result.add(ContactRequest.fromNative(requests[i]));
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
          result.add(BlockedUser.fromNative(blocked[i]));
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
  Future<void> sendTokens({
    required int walletIndex,
    required String recipientAddress,
    required String amount,
    required String token,
    required String network,
    int gasSpeed = 1,
  }) async {
    print('[DART] sendTokens: wallet=$walletIndex to=$recipientAddress amount=$amount token=$token network=$network gas=$gasSpeed');

    final completer = Completer<void>();
    final localId = _nextLocalId++;

    print('[DART] Creating native pointers...');
    final recipientPtr = recipientAddress.toNativeUtf8();
    final amountPtr = amount.toNativeUtf8();
    final tokenPtr = token.toNativeUtf8();
    final networkPtr = network.toNativeUtf8();
    print('[DART] Pointers created');

    void onComplete(int requestId, int error, Pointer<Void> userData) {
      print('[DART] onComplete callback: requestId=$requestId error=$error');
      calloc.free(recipientPtr);
      calloc.free(amountPtr);
      calloc.free(tokenPtr);
      calloc.free(networkPtr);

      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, _bindings));
      }
      _cleanupRequest(localId);
    }

    print('[DART] Creating NativeCallable...');
    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);
    print('[DART] Calling FFI dna_engine_send_tokens...');

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
    print('[DART] FFI returned requestId=$requestId');

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
  /// Returns a record with (signingSeed, encryptionSeed, walletSeed) as List<int>
  ({List<int> signingSeed, List<int> encryptionSeed, List<int> walletSeed}) deriveSeeds(
    String mnemonic, {
    String passphrase = '',
  }) {
    final mnemonicPtr = mnemonic.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final signingSeedPtr = calloc<Uint8>(32);
    final encryptionSeedPtr = calloc<Uint8>(32);
    final walletSeedPtr = calloc<Uint8>(32);

    try {
      final result = _bindings.qgp_derive_seeds_from_mnemonic(
        mnemonicPtr.cast(),
        passphrasePtr.cast(),
        signingSeedPtr,
        encryptionSeedPtr,
        walletSeedPtr,
      );

      if (result != 0) {
        throw DnaEngineException(-1, 'Failed to derive seeds from mnemonic');
      }

      final signingSeed = <int>[];
      final encryptionSeed = <int>[];
      final walletSeed = <int>[];

      for (var i = 0; i < 32; i++) {
        signingSeed.add(signingSeedPtr[i]);
        encryptionSeed.add(encryptionSeedPtr[i]);
        walletSeed.add(walletSeedPtr[i]);
      }

      return (signingSeed: signingSeed, encryptionSeed: encryptionSeed, walletSeed: walletSeed);
    } finally {
      calloc.free(mnemonicPtr);
      calloc.free(passphrasePtr);
      calloc.free(signingSeedPtr);
      calloc.free(encryptionSeedPtr);
      calloc.free(walletSeedPtr);
    }
  }

  /// Derive signing, encryption, wallet seeds AND 64-byte master seed from BIP39 mnemonic
  /// Returns a record with all seeds including masterSeed for multi-chain wallet derivation
  ({List<int> signingSeed, List<int> encryptionSeed, List<int> walletSeed, List<int> masterSeed}) deriveSeedsWithMaster(
    String mnemonic, {
    String passphrase = '',
  }) {
    final mnemonicPtr = mnemonic.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final signingSeedPtr = calloc<Uint8>(32);
    final encryptionSeedPtr = calloc<Uint8>(32);
    final walletSeedPtr = calloc<Uint8>(32);
    final masterSeedPtr = calloc<Uint8>(64);

    try {
      final result = _bindings.qgp_derive_seeds_with_master(
        mnemonicPtr.cast(),
        passphrasePtr.cast(),
        signingSeedPtr,
        encryptionSeedPtr,
        walletSeedPtr,
        masterSeedPtr,
      );

      if (result != 0) {
        throw DnaEngineException(-1, 'Failed to derive seeds from mnemonic');
      }

      final signingSeed = <int>[];
      final encryptionSeed = <int>[];
      final walletSeed = <int>[];
      final masterSeed = <int>[];

      for (var i = 0; i < 32; i++) {
        signingSeed.add(signingSeedPtr[i]);
        encryptionSeed.add(encryptionSeedPtr[i]);
        walletSeed.add(walletSeedPtr[i]);
      }
      for (var i = 0; i < 64; i++) {
        masterSeed.add(masterSeedPtr[i]);
      }

      return (signingSeed: signingSeed, encryptionSeed: encryptionSeed, walletSeed: walletSeed, masterSeed: masterSeed);
    } finally {
      calloc.free(mnemonicPtr);
      calloc.free(passphrasePtr);
      calloc.free(signingSeedPtr);
      calloc.free(encryptionSeedPtr);
      calloc.free(walletSeedPtr);
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
      // Free allocated memory
      calloc.free(namePtr);
      for (var i = 0; i < memberFingerprints.length; i++) {
        calloc.free(membersPtr[i]);
      }
      calloc.free(membersPtr);

      if (error == 0) {
        completer.complete(groupUuid.toDartString());
      } else {
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
  // CLEANUP
  // ---------------------------------------------------------------------------

  void _cleanupRequest(int localId) {
    final request = _pendingRequests.remove(localId);
    request?.callback.close();
  }

  /// Dispose the engine and release all resources
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    _eventController.close();
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
