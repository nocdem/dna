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
      status: MessageStatus.values[native.status.clamp(0, 3)],
      type: native.message_type == 0 ? MessageType.chat : MessageType.groupInvitation,
    );
  }
}

enum MessageStatus { pending, sent, delivered, read }
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
        return DynamicLibrary.open('./libdna_lib.so');
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
  String createIdentitySync(List<int> signingSeed, List<int> encryptionSeed) {
    if (signingSeed.length != 32 || encryptionSeed.length != 32) {
      throw ArgumentError('Seeds must be 32 bytes each');
    }

    final sigSeedPtr = calloc<Uint8>(32);
    final encSeedPtr = calloc<Uint8>(32);
    final fingerprintPtr = calloc<Uint8>(129); // 128 hex chars + null

    try {
      for (var i = 0; i < 32; i++) {
        sigSeedPtr[i] = signingSeed[i];
        encSeedPtr[i] = encryptionSeed[i];
      }

      final error = _bindings.dna_engine_create_identity_sync(
        _engine,
        sigSeedPtr,
        encSeedPtr,
        fingerprintPtr.cast(),
      );

      if (error != 0) {
        throw DnaEngineException.fromCode(error, _bindings);
      }

      return fingerprintPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(sigSeedPtr);
      calloc.free(encSeedPtr);
      calloc.free(fingerprintPtr);
    }
  }

  /// Create new identity from BIP39 seeds (async wrapper)
  Future<String> createIdentity(List<int> signingSeed, List<int> encryptionSeed) async {
    // Use sync version wrapped in compute to avoid blocking UI
    return createIdentitySync(signingSeed, encryptionSeed);
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
  // MESSAGING OPERATIONS
  // ---------------------------------------------------------------------------

  /// Send message to contact
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

  /// Send tokens
  Future<void> sendTokens({
    required int walletIndex,
    required String recipientAddress,
    required String amount,
    required String token,
    required String network,
  }) async {
    final completer = Completer<void>();
    final localId = _nextLocalId++;

    final recipientPtr = recipientAddress.toNativeUtf8();
    final amountPtr = amount.toNativeUtf8();
    final tokenPtr = token.toNativeUtf8();
    final networkPtr = network.toNativeUtf8();

    void onComplete(int requestId, int error, Pointer<Void> userData) {
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

    final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_send_tokens(
      _engine,
      walletIndex,
      recipientPtr.cast(),
      amountPtr.cast(),
      tokenPtr.cast(),
      networkPtr.cast(),
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
  /// Returns a record with (signingSeed, encryptionSeed) as List<int>
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
        completer.complete(displayName.toDartString());
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
        completer.complete(fingerprint.toDartString());
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
        final name = displayName.toDartString();
        completer.complete(name.isEmpty ? null : name);
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
