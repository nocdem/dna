// DNA Messenger Engine FFI Bindings
// Hand-written bindings for dna_engine.h
// ignore_for_file: non_constant_identifier_names, camel_case_types, constant_identifier_names

import 'dart:convert';
import 'dart:ffi';
import 'package:ffi/ffi.dart';

// =============================================================================
// OPAQUE TYPES
// =============================================================================

/// Opaque engine handle
final class dna_engine extends Opaque {}

typedef dna_engine_t = dna_engine;
typedef dna_request_id_t = Uint64;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Contact information
final class dna_contact_t extends Struct {
  @Array(129)
  external Array<Char> fingerprint;

  @Array(256)
  external Array<Char> display_name;

  @Bool()
  external bool is_online;

  @Uint64()
  external int last_seen;
}

/// Contact request information (ICQ-style request)
final class dna_contact_request_t extends Struct {
  @Array(129)
  external Array<Char> fingerprint;

  @Array(64)
  external Array<Char> display_name;

  @Array(256)
  external Array<Char> message;

  @Uint64()
  external int requested_at;

  @Int32()
  external int status; // 0=pending, 1=approved, 2=denied
}

/// Blocked user information
final class dna_blocked_user_t extends Struct {
  @Array(129)
  external Array<Char> fingerprint;

  @Uint64()
  external int blocked_at;

  @Array(256)
  external Array<Char> reason;
}

/// Message information
final class dna_message_t extends Struct {
  @Int32()
  external int id;

  @Array(129)
  external Array<Char> sender;

  @Array(129)
  external Array<Char> recipient;

  external Pointer<Utf8> plaintext;

  @Uint64()
  external int timestamp;

  @Bool()
  external bool is_outgoing;

  @Int32()
  external int status;

  @Int32()
  external int message_type;
}

/// Group information
final class dna_group_t extends Struct {
  @Array(37)
  external Array<Char> uuid;

  @Array(256)
  external Array<Char> name;

  @Array(129)
  external Array<Char> creator;

  @Int32()
  external int member_count;

  @Uint64()
  external int created_at;
}

/// Group invitation
final class dna_invitation_t extends Struct {
  @Array(37)
  external Array<Char> group_uuid;

  @Array(256)
  external Array<Char> group_name;

  @Array(129)
  external Array<Char> inviter;

  @Int32()
  external int member_count;

  @Uint64()
  external int invited_at;
}

/// Wallet information
final class dna_wallet_t extends Struct {
  @Array(256)
  external Array<Char> name;

  @Array(120)
  external Array<Char> address;

  @Int32()
  external int sig_type;

  @Bool()
  external bool is_protected;
}

/// Token balance
final class dna_balance_t extends Struct {
  @Array(32)
  external Array<Char> token;

  @Array(64)
  external Array<Char> balance;

  @Array(64)
  external Array<Char> network;
}

/// Gas estimate for ETH transactions
final class dna_gas_estimate_t extends Struct {
  @Array(32)
  external Array<Char> fee_eth;

  @Uint64()
  external int gas_price;

  @Uint64()
  external int gas_limit;
}

/// Transaction record
final class dna_transaction_t extends Struct {
  @Array(128)
  external Array<Char> tx_hash;

  @Array(16)
  external Array<Char> direction;

  @Array(64)
  external Array<Char> amount;

  @Array(32)
  external Array<Char> token;

  @Array(120)
  external Array<Char> other_address;

  @Array(32)
  external Array<Char> timestamp;

  @Array(32)
  external Array<Char> status;
}

/// Feed channel information
final class dna_channel_info_t extends Struct {
  @Array(65)
  external Array<Char> channel_id;

  @Array(64)
  external Array<Char> name;

  @Array(512)
  external Array<Char> description;

  @Array(129)
  external Array<Char> creator_fingerprint;

  @Uint64()
  external int created_at;

  @Int32()
  external int post_count;

  @Int32()
  external int subscriber_count;

  @Uint64()
  external int last_activity;
}

/// Feed post information
final class dna_post_info_t extends Struct {
  @Array(200)
  external Array<Char> post_id;

  @Array(65)
  external Array<Char> channel_id;

  @Array(129)
  external Array<Char> author_fingerprint;

  external Pointer<Utf8> text;

  @Uint64()
  external int timestamp;

  @Uint64()
  external int updated;

  @Int32()
  external int comment_count;

  @Int32()
  external int upvotes;

  @Int32()
  external int downvotes;

  @Int32()
  external int user_vote;

  @Bool()
  external bool verified;
}

/// Feed comment information
final class dna_comment_info_t extends Struct {
  @Array(200)
  external Array<Char> comment_id;

  @Array(200)
  external Array<Char> post_id;

  @Array(129)
  external Array<Char> author_fingerprint;

  external Pointer<Utf8> text;

  @Uint64()
  external int timestamp;

  @Int32()
  external int upvotes;

  @Int32()
  external int downvotes;

  @Int32()
  external int user_vote;

  @Bool()
  external bool verified;
}

/// Debug log entry (for in-app log viewing)
final class dna_debug_log_entry_t extends Struct {
  @Uint64()
  external int timestamp_ms;

  @Int32()
  external int level; // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR

  @Array(32)
  external Array<Char> tag;

  @Array(256)
  external Array<Char> message;
}

/// User profile information (synced with DHT dna_unified_identity_t)
final class dna_profile_t extends Struct {
  // Cellframe wallets
  @Array(120)
  external Array<Char> backbone;

  @Array(120)
  external Array<Char> alvin;

  // External wallets
  @Array(128)
  external Array<Char> eth;

  @Array(128)
  external Array<Char> sol;

  @Array(128)
  external Array<Char> trx;

  // Socials
  @Array(128)
  external Array<Char> telegram;

  @Array(128)
  external Array<Char> twitter;

  @Array(128)
  external Array<Char> github;

  @Array(128)
  external Array<Char> facebook;

  @Array(128)
  external Array<Char> instagram;

  @Array(128)
  external Array<Char> linkedin;

  @Array(128)
  external Array<Char> google;

  // Profile info
  @Array(128)
  external Array<Char> display_name;

  @Array(512)
  external Array<Char> bio;

  @Array(128)
  external Array<Char> location;

  @Array(256)
  external Array<Char> website;

  @Array(20484)
  external Array<Char> avatar_base64;
}

// =============================================================================
// EVENT TYPES
// =============================================================================

/// Event type enum
abstract class DnaEventType {
  static const int DNA_EVENT_DHT_CONNECTED = 0;
  static const int DNA_EVENT_DHT_DISCONNECTED = 1;
  static const int DNA_EVENT_MESSAGE_RECEIVED = 2;
  static const int DNA_EVENT_MESSAGE_SENT = 3;
  static const int DNA_EVENT_MESSAGE_DELIVERED = 4;
  static const int DNA_EVENT_MESSAGE_READ = 5;
  static const int DNA_EVENT_CONTACT_ONLINE = 6;
  static const int DNA_EVENT_CONTACT_OFFLINE = 7;
  static const int DNA_EVENT_GROUP_INVITATION_RECEIVED = 8;
  static const int DNA_EVENT_GROUP_MEMBER_JOINED = 9;
  static const int DNA_EVENT_GROUP_MEMBER_LEFT = 10;
  static const int DNA_EVENT_IDENTITY_LOADED = 11;
  static const int DNA_EVENT_CONTACT_REQUEST_RECEIVED = 12;
  static const int DNA_EVENT_OUTBOX_UPDATED = 13;  // Contact's outbox has new messages
  static const int DNA_EVENT_ERROR = 14;
}

/// Event data union - message received
final class dna_event_message_received extends Struct {
  external dna_message_t message;
}

/// Event data union - message status
final class dna_event_message_status extends Struct {
  @Int32()
  external int message_id;

  @Int32()
  external int new_status;
}

/// Event data union - contact status
final class dna_event_contact_status extends Struct {
  @Array(129)
  external Array<Char> fingerprint;
}

/// Event data union - group invitation
final class dna_event_group_invitation extends Struct {
  external dna_invitation_t invitation;
}

/// Event data union - group member
final class dna_event_group_member extends Struct {
  @Array(37)
  external Array<Char> group_uuid;

  @Array(129)
  external Array<Char> member;
}

/// Event data union - identity loaded
final class dna_event_identity_loaded extends Struct {
  @Array(129)
  external Array<Char> fingerprint;
}

/// Event data union - outbox updated
final class dna_event_outbox_updated extends Struct {
  @Array(129)
  external Array<Char> contact_fingerprint;
}

/// Event data union - error
final class dna_event_error extends Struct {
  @Int32()
  external int code;

  @Array(256)
  external Array<Char> message;
}

/// Event structure (simplified - union handling requires manual parsing)
final class dna_event_t extends Struct {
  @Int32()
  external int type;

  // Union data starts here - 512 bytes reserved for largest union member
  @Array(512)
  external Array<Uint8> data;
}

/// Version info from DHT
final class dna_version_info_t extends Struct {
  @Array(32)
  external Array<Char> library_current;

  @Array(32)
  external Array<Char> library_minimum;

  @Array(32)
  external Array<Char> app_current;

  @Array(32)
  external Array<Char> app_minimum;

  @Array(32)
  external Array<Char> nodus_current;

  @Array(32)
  external Array<Char> nodus_minimum;

  @Uint64()
  external int published_at;

  @Array(129)
  external Array<Char> publisher;
}

/// Version check result
final class dna_version_check_result_t extends Struct {
  @Bool()
  external bool library_update_available;

  @Bool()
  external bool app_update_available;

  @Bool()
  external bool nodus_update_available;

  external dna_version_info_t info;
}

// =============================================================================
// CALLBACK TYPEDEFS - Native (FFI) types
// =============================================================================

/// Generic completion callback - Native
typedef DnaCompletionCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Void> user_data,
);
typedef DnaCompletionCb = NativeFunction<DnaCompletionCbNative>;

/// Send tokens callback - Native (returns tx_hash on success)
typedef DnaSendTokensCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Utf8> tx_hash,
  Pointer<Void> user_data,
);
typedef DnaSendTokensCb = NativeFunction<DnaSendTokensCbNative>;

/// Identities list callback - Native
typedef DnaIdentitiesCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Pointer<Utf8>> fingerprints,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaIdentitiesCb = NativeFunction<DnaIdentitiesCbNative>;

/// Identity created callback - Native
typedef DnaIdentityCreatedCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Utf8> fingerprint,
  Pointer<Void> user_data,
);
typedef DnaIdentityCreatedCb = NativeFunction<DnaIdentityCreatedCbNative>;

/// Display name callback - Native
typedef DnaDisplayNameCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Utf8> display_name,
  Pointer<Void> user_data,
);
typedef DnaDisplayNameCb = NativeFunction<DnaDisplayNameCbNative>;

/// Contacts callback - Native
typedef DnaContactsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_contact_t> contacts,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaContactsCb = NativeFunction<DnaContactsCbNative>;

/// Contact requests callback - Native (ICQ-style)
typedef DnaContactRequestsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_contact_request_t> requests,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaContactRequestsCb = NativeFunction<DnaContactRequestsCbNative>;

/// Blocked users callback - Native
typedef DnaBlockedUsersCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_blocked_user_t> blocked,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaBlockedUsersCb = NativeFunction<DnaBlockedUsersCbNative>;

/// Messages callback - Native
typedef DnaMessagesCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_message_t> messages,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaMessagesCb = NativeFunction<DnaMessagesCbNative>;

/// Groups callback - Native
typedef DnaGroupsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_group_t> groups,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaGroupsCb = NativeFunction<DnaGroupsCbNative>;

/// Group created callback - Native
typedef DnaGroupCreatedCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Utf8> group_uuid,
  Pointer<Void> user_data,
);
typedef DnaGroupCreatedCb = NativeFunction<DnaGroupCreatedCbNative>;

/// Invitations callback - Native
typedef DnaInvitationsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_invitation_t> invitations,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaInvitationsCb = NativeFunction<DnaInvitationsCbNative>;

/// Wallets callback - Native
typedef DnaWalletsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wallet_t> wallets,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaWalletsCb = NativeFunction<DnaWalletsCbNative>;

/// Balances callback - Native
typedef DnaBalancesCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_balance_t> balances,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaBalancesCb = NativeFunction<DnaBalancesCbNative>;

/// Transactions callback - Native
typedef DnaTransactionsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_transaction_t> transactions,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaTransactionsCb = NativeFunction<DnaTransactionsCbNative>;

/// Feed channels callback - Native
typedef DnaFeedChannelsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_info_t> channels,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaFeedChannelsCb = NativeFunction<DnaFeedChannelsCbNative>;

/// Feed channel callback (single) - Native
typedef DnaFeedChannelCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_info_t> channel,
  Pointer<Void> user_data,
);
typedef DnaFeedChannelCb = NativeFunction<DnaFeedChannelCbNative>;

/// Feed posts callback - Native
typedef DnaFeedPostsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_post_info_t> posts,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaFeedPostsCb = NativeFunction<DnaFeedPostsCbNative>;

/// Feed post callback (single) - Native
typedef DnaFeedPostCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_post_info_t> post,
  Pointer<Void> user_data,
);
typedef DnaFeedPostCb = NativeFunction<DnaFeedPostCbNative>;

/// Feed comments callback - Native
typedef DnaFeedCommentsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_comment_info_t> comments,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaFeedCommentsCb = NativeFunction<DnaFeedCommentsCbNative>;

/// Feed comment callback (single) - Native
typedef DnaFeedCommentCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_comment_info_t> comment,
  Pointer<Void> user_data,
);
typedef DnaFeedCommentCb = NativeFunction<DnaFeedCommentCbNative>;

/// Profile callback - Native
typedef DnaProfileCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_profile_t> profile,
  Pointer<Void> user_data,
);
typedef DnaProfileCb = NativeFunction<DnaProfileCbNative>;

/// Presence lookup callback - Native
typedef DnaPresenceCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Uint64 last_seen,
  Pointer<Void> user_data,
);
typedef DnaPresenceCb = NativeFunction<DnaPresenceCbNative>;

/// Backup result callback - Native
typedef DnaBackupResultCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Int32 processed_count,
  Int32 skipped_count,
  Pointer<Void> user_data,
);
typedef DnaBackupResultCb = NativeFunction<DnaBackupResultCbNative>;

/// Event callback - Native
typedef DnaEventCbNative = Void Function(
  Pointer<dna_event_t> event,
  Pointer<Void> user_data,
);
typedef DnaEventCb = NativeFunction<DnaEventCbNative>;

// =============================================================================
// CALLBACK TYPEDEFS - Dart types (for NativeCallable)
// =============================================================================

typedef DnaCompletionCbDart = void Function(
  int requestId,
  int error,
  Pointer<Void> userData,
);

typedef DnaSendTokensCbDart = void Function(
  int requestId,
  int error,
  Pointer<Utf8> txHash,
  Pointer<Void> userData,
);

typedef DnaIdentitiesCbDart = void Function(
  int requestId,
  int error,
  Pointer<Pointer<Utf8>> fingerprints,
  int count,
  Pointer<Void> userData,
);

typedef DnaIdentityCreatedCbDart = void Function(
  int requestId,
  int error,
  Pointer<Utf8> fingerprint,
  Pointer<Void> userData,
);

typedef DnaDisplayNameCbDart = void Function(
  int requestId,
  int error,
  Pointer<Utf8> displayName,
  Pointer<Void> userData,
);

typedef DnaContactsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_contact_t> contacts,
  int count,
  Pointer<Void> userData,
);

typedef DnaMessagesCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_message_t> messages,
  int count,
  Pointer<Void> userData,
);

typedef DnaGroupsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_group_t> groups,
  int count,
  Pointer<Void> userData,
);

typedef DnaGroupCreatedCbDart = void Function(
  int requestId,
  int error,
  Pointer<Utf8> groupUuid,
  Pointer<Void> userData,
);

typedef DnaInvitationsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_invitation_t> invitations,
  int count,
  Pointer<Void> userData,
);

typedef DnaWalletsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_wallet_t> wallets,
  int count,
  Pointer<Void> userData,
);

typedef DnaBalancesCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_balance_t> balances,
  int count,
  Pointer<Void> userData,
);

typedef DnaTransactionsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_transaction_t> transactions,
  int count,
  Pointer<Void> userData,
);

typedef DnaFeedChannelsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_info_t> channels,
  int count,
  Pointer<Void> userData,
);

typedef DnaFeedChannelCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_info_t> channel,
  Pointer<Void> userData,
);

typedef DnaFeedPostsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_post_info_t> posts,
  int count,
  Pointer<Void> userData,
);

typedef DnaFeedPostCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_post_info_t> post,
  Pointer<Void> userData,
);

typedef DnaFeedCommentsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_comment_info_t> comments,
  int count,
  Pointer<Void> userData,
);

typedef DnaFeedCommentCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_comment_info_t> comment,
  Pointer<Void> userData,
);

typedef DnaProfileCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_profile_t> profile,
  Pointer<Void> userData,
);

typedef DnaPresenceCbDart = void Function(
  int requestId,
  int error,
  int lastSeen,
  Pointer<Void> userData,
);

typedef DnaBackupResultCbDart = void Function(
  int requestId,
  int error,
  int processedCount,
  int skippedCount,
  Pointer<Void> userData,
);

typedef DnaEventCbDart = void Function(
  Pointer<dna_event_t> event,
  Pointer<Void> userData,
);

// =============================================================================
// BIP39 CONSTANTS
// =============================================================================

const int BIP39_WORDS_24 = 24;
const int BIP39_MAX_MNEMONIC_LENGTH = 256;
const int BIP39_SEED_SIZE = 64;

// =============================================================================
// BINDINGS CLASS
// =============================================================================

class DnaBindings {
  final DynamicLibrary _lib;

  DnaBindings(this._lib);

  // ---------------------------------------------------------------------------
  // LIFECYCLE
  // ---------------------------------------------------------------------------

  late final _dna_engine_create = _lib.lookupFunction<
      Pointer<dna_engine_t> Function(Pointer<Utf8>),
      Pointer<dna_engine_t> Function(Pointer<Utf8>)>('dna_engine_create');

  Pointer<dna_engine_t> dna_engine_create(Pointer<Utf8> data_dir) {
    return _dna_engine_create(data_dir);
  }

  late final _dna_engine_destroy = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>),
      void Function(Pointer<dna_engine_t>)>('dna_engine_destroy');

  void dna_engine_destroy(Pointer<dna_engine_t> engine) {
    _dna_engine_destroy(engine);
  }

  late final _dna_engine_set_event_callback = _lib.lookupFunction<
      Void Function(
          Pointer<dna_engine_t>, Pointer<DnaEventCb>, Pointer<Void>),
      void Function(Pointer<dna_engine_t>, Pointer<DnaEventCb>,
          Pointer<Void>)>('dna_engine_set_event_callback');

  void dna_engine_set_event_callback(
    Pointer<dna_engine_t> engine,
    Pointer<DnaEventCb> callback,
    Pointer<Void> user_data,
  ) {
    _dna_engine_set_event_callback(engine, callback, user_data);
  }

  late final _dna_engine_get_fingerprint = _lib.lookupFunction<
      Pointer<Utf8> Function(Pointer<dna_engine_t>),
      Pointer<Utf8> Function(Pointer<dna_engine_t>)>('dna_engine_get_fingerprint');

  Pointer<Utf8> dna_engine_get_fingerprint(Pointer<dna_engine_t> engine) {
    return _dna_engine_get_fingerprint(engine);
  }

  late final _dna_engine_error_string = _lib.lookupFunction<
      Pointer<Utf8> Function(Int32),
      Pointer<Utf8> Function(int)>('dna_engine_error_string');

  Pointer<Utf8> dna_engine_error_string(int error) {
    return _dna_engine_error_string(error);
  }

  // ---------------------------------------------------------------------------
  // IDENTITY
  // ---------------------------------------------------------------------------

  late final _dna_engine_list_identities = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaIdentitiesCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaIdentitiesCb>,
          Pointer<Void>)>('dna_engine_list_identities');

  int dna_engine_list_identities(
    Pointer<dna_engine_t> engine,
    Pointer<DnaIdentitiesCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_list_identities(engine, callback, user_data);
  }

  late final _dna_engine_create_identity = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<DnaIdentityCreatedCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<DnaIdentityCreatedCb>, Pointer<Void>)>('dna_engine_create_identity');

  int dna_engine_create_identity(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> signing_seed,
    Pointer<Uint8> encryption_seed,
    Pointer<DnaIdentityCreatedCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_create_identity(
        engine, signing_seed, encryption_seed, callback, user_data);
  }

  late final _dna_engine_create_identity_sync = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<Uint8>, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<Uint8>, Pointer<Utf8>, Pointer<Utf8>)>('dna_engine_create_identity_sync');

  int dna_engine_create_identity_sync(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> name,
    Pointer<Uint8> signing_seed,
    Pointer<Uint8> encryption_seed,
    Pointer<Uint8> master_seed,
    Pointer<Utf8> mnemonic,
    Pointer<Utf8> fingerprint_out,
  ) {
    return _dna_engine_create_identity_sync(
        engine, name, signing_seed, encryption_seed, master_seed, mnemonic, fingerprint_out);
  }

  late final _dna_engine_restore_identity_sync = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<Uint8>, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<Uint8>, Pointer<Utf8>, Pointer<Utf8>)>('dna_engine_restore_identity_sync');

  int dna_engine_restore_identity_sync(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> signing_seed,
    Pointer<Uint8> encryption_seed,
    Pointer<Uint8> master_seed,
    Pointer<Utf8> mnemonic,
    Pointer<Utf8> fingerprint_out,
  ) {
    return _dna_engine_restore_identity_sync(
        engine, signing_seed, encryption_seed, master_seed, mnemonic, fingerprint_out);
  }

  late final _dna_engine_delete_identity_sync = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_delete_identity_sync');

  /// Delete identity and all associated local data
  /// Returns 0 on success, negative error code on failure
  int dna_engine_delete_identity_sync(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
  ) {
    return _dna_engine_delete_identity_sync(engine, fingerprint);
  }

  late final _dna_engine_has_identity = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>),
      bool Function(Pointer<dna_engine_t>)>('dna_engine_has_identity');

  /// Check if an identity exists (v0.3.0 single-user model)
  /// Returns true if keys/identity.dsa exists
  bool dna_engine_has_identity(Pointer<dna_engine_t> engine) {
    return _dna_engine_has_identity(engine);
  }

  late final _dna_engine_prepare_dht_from_mnemonic = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_prepare_dht_from_mnemonic');

  /// Prepare DHT connection from mnemonic (before identity creation)
  /// Call this when user validates seed phrase, before creating identity
  int dna_engine_prepare_dht_from_mnemonic(Pointer<dna_engine_t> engine, Pointer<Utf8> mnemonic) {
    return _dna_engine_prepare_dht_from_mnemonic(engine, mnemonic);
  }

  late final _dna_engine_load_identity = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_load_identity');

  int dna_engine_load_identity(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<Utf8> password,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_load_identity(engine, fingerprint, password, callback, user_data);
  }

  late final _dna_engine_get_mnemonic = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Size),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int)>('dna_engine_get_mnemonic');

  /// Get the encrypted mnemonic (recovery phrase) for the current identity
  /// Returns 0 on success, negative error code on failure
  int dna_engine_get_mnemonic(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> mnemonic_out,
    int mnemonic_size,
  ) {
    return _dna_engine_get_mnemonic(engine, mnemonic_out, mnemonic_size);
  }

  late final _dna_engine_register_name = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_register_name');

  int dna_engine_register_name(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> name,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_register_name(engine, name, callback, user_data);
  }

  late final _dna_engine_get_display_name = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaDisplayNameCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaDisplayNameCb>, Pointer<Void>)>('dna_engine_get_display_name');

  int dna_engine_get_display_name(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaDisplayNameCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_display_name(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_get_avatar = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaDisplayNameCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaDisplayNameCb>, Pointer<Void>)>('dna_engine_get_avatar');

  int dna_engine_get_avatar(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaDisplayNameCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_avatar(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_lookup_name = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaDisplayNameCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaDisplayNameCb>, Pointer<Void>)>('dna_engine_lookup_name');

  int dna_engine_lookup_name(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> name,
    Pointer<DnaDisplayNameCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_lookup_name(engine, name, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // PROFILE
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_profile = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaProfileCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaProfileCb>,
          Pointer<Void>)>('dna_engine_get_profile');

  int dna_engine_get_profile(
    Pointer<dna_engine_t> engine,
    Pointer<DnaProfileCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_profile(engine, callback, user_data);
  }

  late final _dna_engine_lookup_profile = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaProfileCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaProfileCb>, Pointer<Void>)>('dna_engine_lookup_profile');

  int dna_engine_lookup_profile(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaProfileCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_lookup_profile(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_refresh_contact_profile = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaProfileCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaProfileCb>, Pointer<Void>)>('dna_engine_refresh_contact_profile');

  int dna_engine_refresh_contact_profile(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaProfileCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_refresh_contact_profile(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_update_profile = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<dna_profile_t>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<dna_profile_t>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_update_profile');

  int dna_engine_update_profile(
    Pointer<dna_engine_t> engine,
    Pointer<dna_profile_t> profile,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_update_profile(engine, profile, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // CONTACTS
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_contacts = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaContactsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaContactsCb>,
          Pointer<Void>)>('dna_engine_get_contacts');

  int dna_engine_get_contacts(
    Pointer<dna_engine_t> engine,
    Pointer<DnaContactsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_contacts(engine, callback, user_data);
  }

  late final _dna_engine_add_contact = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_add_contact');

  int dna_engine_add_contact(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> identifier,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_add_contact(engine, identifier, callback, user_data);
  }

  late final _dna_engine_remove_contact = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_remove_contact');

  int dna_engine_remove_contact(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_remove_contact(engine, fingerprint, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // CONTACT REQUESTS (ICQ-style)
  // ---------------------------------------------------------------------------

  late final _dna_engine_send_contact_request = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_send_contact_request');

  int dna_engine_send_contact_request(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> recipient_fingerprint,
    Pointer<Utf8> message,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_send_contact_request(
        engine, recipient_fingerprint, message, callback, user_data);
  }

  late final _dna_engine_get_contact_requests = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaContactRequestsCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaContactRequestsCb>,
          Pointer<Void>)>('dna_engine_get_contact_requests');

  int dna_engine_get_contact_requests(
    Pointer<dna_engine_t> engine,
    Pointer<DnaContactRequestsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_contact_requests(engine, callback, user_data);
  }

  late final _dna_engine_get_contact_request_count = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_get_contact_request_count');

  int dna_engine_get_contact_request_count(Pointer<dna_engine_t> engine) {
    return _dna_engine_get_contact_request_count(engine);
  }

  late final _dna_engine_approve_contact_request = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_approve_contact_request');

  int dna_engine_approve_contact_request(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_approve_contact_request(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_deny_contact_request = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_deny_contact_request');

  int dna_engine_deny_contact_request(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_deny_contact_request(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_block_user = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_block_user');

  int dna_engine_block_user(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<Utf8> reason,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_block_user(engine, fingerprint, reason, callback, user_data);
  }

  late final _dna_engine_unblock_user = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_unblock_user');

  int dna_engine_unblock_user(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_unblock_user(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_get_blocked_users = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaBlockedUsersCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaBlockedUsersCb>,
          Pointer<Void>)>('dna_engine_get_blocked_users');

  int dna_engine_get_blocked_users(
    Pointer<dna_engine_t> engine,
    Pointer<DnaBlockedUsersCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_blocked_users(engine, callback, user_data);
  }

  late final _dna_engine_is_user_blocked = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      bool Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_is_user_blocked');

  bool dna_engine_is_user_blocked(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
  ) {
    return _dna_engine_is_user_blocked(engine, fingerprint);
  }

  // ---------------------------------------------------------------------------
  // MESSAGING
  // ---------------------------------------------------------------------------

  late final _dna_engine_send_message = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_send_message');

  int dna_engine_send_message(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> recipient_fingerprint,
    Pointer<Utf8> message,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_send_message(
        engine, recipient_fingerprint, message, callback, user_data);
  }

  // Queue message for async sending (returns immediately)
  late final _dna_engine_queue_message = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<Utf8>)>('dna_engine_queue_message');

  int dna_engine_queue_message(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> recipient_fingerprint,
    Pointer<Utf8> message,
  ) {
    return _dna_engine_queue_message(engine, recipient_fingerprint, message);
  }

  // Get message queue capacity
  late final _dna_engine_get_message_queue_capacity = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_get_message_queue_capacity');

  int dna_engine_get_message_queue_capacity(Pointer<dna_engine_t> engine) {
    return _dna_engine_get_message_queue_capacity(engine);
  }

  // Get current message queue size
  late final _dna_engine_get_message_queue_size = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_get_message_queue_size');

  int dna_engine_get_message_queue_size(Pointer<dna_engine_t> engine) {
    return _dna_engine_get_message_queue_size(engine);
  }

  // Set message queue capacity
  late final _dna_engine_set_message_queue_capacity = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Int32),
      int Function(Pointer<dna_engine_t>, int)>('dna_engine_set_message_queue_capacity');

  int dna_engine_set_message_queue_capacity(Pointer<dna_engine_t> engine, int capacity) {
    return _dna_engine_set_message_queue_capacity(engine, capacity);
  }

  late final _dna_engine_get_conversation = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaMessagesCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaMessagesCb>, Pointer<Void>)>('dna_engine_get_conversation');

  int dna_engine_get_conversation(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contact_fingerprint,
    Pointer<DnaMessagesCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_conversation(
        engine, contact_fingerprint, callback, user_data);
  }

  late final _dna_engine_check_offline_messages = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_check_offline_messages');

  int dna_engine_check_offline_messages(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_check_offline_messages(engine, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // MESSAGE STATUS / READ RECEIPTS
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_unread_count = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_get_unread_count');

  /// Get unread message count for a specific contact (synchronous)
  int dna_engine_get_unread_count(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contact_fingerprint,
  ) {
    return _dna_engine_get_unread_count(engine, contact_fingerprint);
  }

  late final _dna_engine_mark_conversation_read = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_mark_conversation_read');

  /// Mark all messages in conversation as read (async callback)
  int dna_engine_mark_conversation_read(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contact_fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_mark_conversation_read(
        engine, contact_fingerprint, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // GROUPS
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_groups = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaGroupsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaGroupsCb>,
          Pointer<Void>)>('dna_engine_get_groups');

  int dna_engine_get_groups(
    Pointer<dna_engine_t> engine,
    Pointer<DnaGroupsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_groups(engine, callback, user_data);
  }

  late final _dna_engine_send_group_message = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_send_group_message');

  int dna_engine_send_group_message(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<Utf8> message,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_send_group_message(
        engine, group_uuid, message, callback, user_data);
  }

  late final _dna_engine_get_invitations = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaInvitationsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaInvitationsCb>,
          Pointer<Void>)>('dna_engine_get_invitations');

  int dna_engine_get_invitations(
    Pointer<dna_engine_t> engine,
    Pointer<DnaInvitationsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_invitations(engine, callback, user_data);
  }

  late final _dna_engine_accept_invitation = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_accept_invitation');

  int dna_engine_accept_invitation(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_accept_invitation(
        engine, group_uuid, callback, user_data);
  }

  late final _dna_engine_reject_invitation = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_reject_invitation');

  int dna_engine_reject_invitation(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_reject_invitation(
        engine, group_uuid, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // WALLET
  // ---------------------------------------------------------------------------

  late final _dna_engine_list_wallets = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaWalletsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaWalletsCb>,
          Pointer<Void>)>('dna_engine_list_wallets');

  int dna_engine_list_wallets(
    Pointer<dna_engine_t> engine,
    Pointer<DnaWalletsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_list_wallets(engine, callback, user_data);
  }

  late final _dna_engine_get_balances = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Pointer<DnaBalancesCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<DnaBalancesCb>,
          Pointer<Void>)>('dna_engine_get_balances');

  int dna_engine_get_balances(
    Pointer<dna_engine_t> engine,
    int wallet_index,
    Pointer<DnaBalancesCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_balances(engine, wallet_index, callback, user_data);
  }

  late final _dna_engine_estimate_eth_gas = _lib.lookupFunction<
      Int32 Function(Int32, Pointer<dna_gas_estimate_t>),
      int Function(int, Pointer<dna_gas_estimate_t>)>('dna_engine_estimate_eth_gas');

  int dna_engine_estimate_eth_gas(
    int gas_speed,
    Pointer<dna_gas_estimate_t> estimate_out,
  ) {
    return _dna_engine_estimate_eth_gas(gas_speed, estimate_out);
  }

  late final _dna_engine_send_tokens = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>,
          Int32,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Int32,
          Pointer<DnaSendTokensCb>,
          Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>,
          int,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          int,
          Pointer<DnaSendTokensCb>,
          Pointer<Void>)>('dna_engine_send_tokens');

  int dna_engine_send_tokens(
    Pointer<dna_engine_t> engine,
    int wallet_index,
    Pointer<Utf8> recipient_address,
    Pointer<Utf8> amount,
    Pointer<Utf8> token,
    Pointer<Utf8> network,
    int gas_speed,
    Pointer<DnaSendTokensCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_send_tokens(engine, wallet_index, recipient_address,
        amount, token, network, gas_speed, callback, user_data);
  }

  late final _dna_engine_get_transactions = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Pointer<Utf8>,
          Pointer<DnaTransactionsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<Utf8>,
          Pointer<DnaTransactionsCb>, Pointer<Void>)>('dna_engine_get_transactions');

  int dna_engine_get_transactions(
    Pointer<dna_engine_t> engine,
    int wallet_index,
    Pointer<Utf8> network,
    Pointer<DnaTransactionsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_transactions(
        engine, wallet_index, network, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // P2P & PRESENCE
  // ---------------------------------------------------------------------------

  late final _dna_engine_refresh_presence = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_refresh_presence');

  int dna_engine_refresh_presence(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_refresh_presence(engine, callback, user_data);
  }

  late final _dna_engine_is_peer_online = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      bool Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_is_peer_online');

  bool dna_engine_is_peer_online(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
  ) {
    return _dna_engine_is_peer_online(engine, fingerprint);
  }

  /// Pause presence updates (call when app goes to background)
  late final _dna_engine_pause_presence = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>),
      void Function(Pointer<dna_engine_t>)>('dna_engine_pause_presence');

  void dna_engine_pause_presence(Pointer<dna_engine_t> engine) {
    _dna_engine_pause_presence(engine);
  }

  /// Resume presence updates (call when app comes to foreground)
  late final _dna_engine_resume_presence = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>),
      void Function(Pointer<dna_engine_t>)>('dna_engine_resume_presence');

  void dna_engine_resume_presence(Pointer<dna_engine_t> engine) {
    _dna_engine_resume_presence(engine);
  }

  late final _dna_engine_lookup_presence = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaPresenceCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaPresenceCb>,
          Pointer<Void>)>('dna_engine_lookup_presence');

  int dna_engine_lookup_presence(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaPresenceCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_lookup_presence(engine, fingerprint, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // OUTBOX LISTENERS (Real-time offline message notifications)
  // ---------------------------------------------------------------------------

  late final _dna_engine_listen_outbox = _lib.lookupFunction<
      Size Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_listen_outbox');

  /// Start listening for updates to a contact's outbox
  /// Returns listener token (> 0 on success, 0 on failure)
  int dna_engine_listen_outbox(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contact_fingerprint,
  ) {
    return _dna_engine_listen_outbox(engine, contact_fingerprint);
  }

  late final _dna_engine_cancel_outbox_listener = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      void Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_cancel_outbox_listener');

  /// Cancel an active outbox listener
  void dna_engine_cancel_outbox_listener(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contact_fingerprint,
  ) {
    _dna_engine_cancel_outbox_listener(engine, contact_fingerprint);
  }

  late final _dna_engine_listen_all_contacts = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_listen_all_contacts');

  /// Start listeners for all contacts' outboxes
  /// Returns number of listeners started
  int dna_engine_listen_all_contacts(Pointer<dna_engine_t> engine) {
    return _dna_engine_listen_all_contacts(engine);
  }

  late final _dna_engine_cancel_all_outbox_listeners = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>),
      void Function(Pointer<dna_engine_t>)>('dna_engine_cancel_all_outbox_listeners');

  /// Cancel all active outbox listeners
  void dna_engine_cancel_all_outbox_listeners(Pointer<dna_engine_t> engine) {
    _dna_engine_cancel_all_outbox_listeners(engine);
  }

  // ---------------------------------------------------------------------------
  // MEMORY MANAGEMENT
  // ---------------------------------------------------------------------------

  late final _dna_free_event = _lib.lookupFunction<
      Void Function(Pointer<dna_event_t>),
      void Function(Pointer<dna_event_t>)>('dna_free_event');

  void dna_free_event(Pointer<dna_event_t> event) {
    _dna_free_event(event);
  }

  late final _dna_free_strings = _lib.lookupFunction<
      Void Function(Pointer<Pointer<Utf8>>, Int32),
      void Function(Pointer<Pointer<Utf8>>, int)>('dna_free_strings');

  void dna_free_strings(Pointer<Pointer<Utf8>> strings, int count) {
    _dna_free_strings(strings, count);
  }

  late final _dna_free_contacts = _lib.lookupFunction<
      Void Function(Pointer<dna_contact_t>, Int32),
      void Function(Pointer<dna_contact_t>, int)>('dna_free_contacts');

  void dna_free_contacts(Pointer<dna_contact_t> contacts, int count) {
    _dna_free_contacts(contacts, count);
  }

  late final _dna_free_messages = _lib.lookupFunction<
      Void Function(Pointer<dna_message_t>, Int32),
      void Function(Pointer<dna_message_t>, int)>('dna_free_messages');

  void dna_free_messages(Pointer<dna_message_t> messages, int count) {
    _dna_free_messages(messages, count);
  }

  late final _dna_free_groups = _lib.lookupFunction<
      Void Function(Pointer<dna_group_t>, Int32),
      void Function(Pointer<dna_group_t>, int)>('dna_free_groups');

  void dna_free_groups(Pointer<dna_group_t> groups, int count) {
    _dna_free_groups(groups, count);
  }

  late final _dna_free_invitations = _lib.lookupFunction<
      Void Function(Pointer<dna_invitation_t>, Int32),
      void Function(Pointer<dna_invitation_t>, int)>('dna_free_invitations');

  void dna_free_invitations(Pointer<dna_invitation_t> invitations, int count) {
    _dna_free_invitations(invitations, count);
  }

  late final _dna_free_contact_requests = _lib.lookupFunction<
      Void Function(Pointer<dna_contact_request_t>, Int32),
      void Function(Pointer<dna_contact_request_t>, int)>('dna_free_contact_requests');

  void dna_free_contact_requests(Pointer<dna_contact_request_t> requests, int count) {
    _dna_free_contact_requests(requests, count);
  }

  late final _dna_free_blocked_users = _lib.lookupFunction<
      Void Function(Pointer<dna_blocked_user_t>, Int32),
      void Function(Pointer<dna_blocked_user_t>, int)>('dna_free_blocked_users');

  void dna_free_blocked_users(Pointer<dna_blocked_user_t> blocked, int count) {
    _dna_free_blocked_users(blocked, count);
  }

  late final _dna_free_wallets = _lib.lookupFunction<
      Void Function(Pointer<dna_wallet_t>, Int32),
      void Function(Pointer<dna_wallet_t>, int)>('dna_free_wallets');

  void dna_free_wallets(Pointer<dna_wallet_t> wallets, int count) {
    _dna_free_wallets(wallets, count);
  }

  late final _dna_free_balances = _lib.lookupFunction<
      Void Function(Pointer<dna_balance_t>, Int32),
      void Function(Pointer<dna_balance_t>, int)>('dna_free_balances');

  void dna_free_balances(Pointer<dna_balance_t> balances, int count) {
    _dna_free_balances(balances, count);
  }

  late final _dna_free_transactions = _lib.lookupFunction<
      Void Function(Pointer<dna_transaction_t>, Int32),
      void Function(Pointer<dna_transaction_t>, int)>('dna_free_transactions');

  void dna_free_transactions(Pointer<dna_transaction_t> transactions, int count) {
    _dna_free_transactions(transactions, count);
  }

  late final _dna_free_profile = _lib.lookupFunction<
      Void Function(Pointer<dna_profile_t>),
      void Function(Pointer<dna_profile_t>)>('dna_free_profile');

  void dna_free_profile(Pointer<dna_profile_t> profile) {
    _dna_free_profile(profile);
  }

  // ---------------------------------------------------------------------------
  // GROUPS - CREATE GROUP (was missing)
  // ---------------------------------------------------------------------------

  late final _dna_engine_create_group = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Pointer<Utf8>>,
          Int32,
          Pointer<DnaGroupCreatedCb>,
          Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Pointer<Utf8>>,
          int,
          Pointer<DnaGroupCreatedCb>,
          Pointer<Void>)>('dna_engine_create_group');

  int dna_engine_create_group(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> name,
    Pointer<Pointer<Utf8>> member_fingerprints,
    int member_count,
    Pointer<DnaGroupCreatedCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_create_group(
        engine, name, member_fingerprints, member_count, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // IDENTITY - GET REGISTERED NAME (was missing)
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_registered_name = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaDisplayNameCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaDisplayNameCb>,
          Pointer<Void>)>('dna_engine_get_registered_name');

  int dna_engine_get_registered_name(
    Pointer<dna_engine_t> engine,
    Pointer<DnaDisplayNameCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_registered_name(engine, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // BIP39 FUNCTIONS
  // ---------------------------------------------------------------------------

  late final _bip39_generate_mnemonic = _lib.lookupFunction<
      Int32 Function(Int32, Pointer<Utf8>, Size),
      int Function(int, Pointer<Utf8>, int)>('bip39_generate_mnemonic');

  /// Generate random BIP39 mnemonic
  /// Returns 0 on success, -1 on error
  int bip39_generate_mnemonic(
    int word_count,
    Pointer<Utf8> mnemonic,
    int mnemonic_size,
  ) {
    return _bip39_generate_mnemonic(word_count, mnemonic, mnemonic_size);
  }

  late final _bip39_validate_mnemonic = _lib.lookupFunction<
      Bool Function(Pointer<Utf8>),
      bool Function(Pointer<Utf8>)>('bip39_validate_mnemonic');

  /// Validate BIP39 mnemonic
  bool bip39_validate_mnemonic(Pointer<Utf8> mnemonic) {
    return _bip39_validate_mnemonic(mnemonic);
  }

  late final _qgp_derive_seeds_from_mnemonic = _lib.lookupFunction<
      Int32 Function(
          Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, Pointer<Uint8>),
      int Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>,
          Pointer<Uint8>)>('qgp_derive_seeds_from_mnemonic');

  /// Derive signing and encryption seeds from BIP39 mnemonic
  /// Returns 0 on success, -1 on error
  int qgp_derive_seeds_from_mnemonic(
    Pointer<Utf8> mnemonic,
    Pointer<Utf8> passphrase,
    Pointer<Uint8> signing_seed,
    Pointer<Uint8> encryption_seed,
  ) {
    return _qgp_derive_seeds_from_mnemonic(
        mnemonic, passphrase, signing_seed, encryption_seed);
  }

  late final _qgp_derive_seeds_with_master = _lib.lookupFunction<
      Int32 Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<Uint8>),
      int Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, Pointer<Uint8>,
          Pointer<Uint8>)>('qgp_derive_seeds_with_master');

  /// Derive signing, encryption seeds AND 64-byte master seed from BIP39 mnemonic
  /// master_seed_out receives the 64-byte BIP39 master seed for multi-chain wallet derivation
  /// Returns 0 on success, -1 on error
  int qgp_derive_seeds_with_master(
    Pointer<Utf8> mnemonic,
    Pointer<Utf8> passphrase,
    Pointer<Uint8> signing_seed,
    Pointer<Uint8> encryption_seed,
    Pointer<Uint8> master_seed_out,
  ) {
    return _qgp_derive_seeds_with_master(
        mnemonic, passphrase, signing_seed, encryption_seed, master_seed_out);
  }

  // ---------------------------------------------------------------------------
  // FEED - CHANNELS
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_feed_channels = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaFeedChannelsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaFeedChannelsCb>,
          Pointer<Void>)>('dna_engine_get_feed_channels');

  int dna_engine_get_feed_channels(
    Pointer<dna_engine_t> engine,
    Pointer<DnaFeedChannelsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_feed_channels(engine, callback, user_data);
  }

  late final _dna_engine_create_feed_channel = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedChannelCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedChannelCb>, Pointer<Void>)>('dna_engine_create_feed_channel');

  int dna_engine_create_feed_channel(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> name,
    Pointer<Utf8> description,
    Pointer<DnaFeedChannelCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_create_feed_channel(
        engine, name, description, callback, user_data);
  }

  late final _dna_engine_init_default_channels = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_init_default_channels');

  int dna_engine_init_default_channels(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_init_default_channels(engine, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // FEED - POSTS
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_feed_posts = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedPostsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedPostsCb>, Pointer<Void>)>('dna_engine_get_feed_posts');

  int dna_engine_get_feed_posts(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channel_id,
    Pointer<Utf8> date,
    Pointer<DnaFeedPostsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_feed_posts(
        engine, channel_id, date, callback, user_data);
  }

  late final _dna_engine_create_feed_post = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedPostCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedPostCb>, Pointer<Void>)>('dna_engine_create_feed_post');

  int dna_engine_create_feed_post(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channel_id,
    Pointer<Utf8> text,
    Pointer<DnaFeedPostCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_create_feed_post(
        engine, channel_id, text, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // FEED - COMMENTS
  // ---------------------------------------------------------------------------

  late final _dna_engine_add_feed_comment = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedCommentCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaFeedCommentCb>, Pointer<Void>)>('dna_engine_add_feed_comment');

  int dna_engine_add_feed_comment(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> post_id,
    Pointer<Utf8> text,
    Pointer<DnaFeedCommentCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_add_feed_comment(
        engine, post_id, text, callback, user_data);
  }

  late final _dna_engine_get_feed_comments = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaFeedCommentsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaFeedCommentsCb>, Pointer<Void>)>('dna_engine_get_feed_comments');

  int dna_engine_get_feed_comments(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> post_id,
    Pointer<DnaFeedCommentsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_feed_comments(engine, post_id, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // FEED - VOTES
  // ---------------------------------------------------------------------------

  late final _dna_engine_cast_feed_vote = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Int8,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_cast_feed_vote');

  int dna_engine_cast_feed_vote(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> post_id,
    int vote_value,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_cast_feed_vote(
        engine, post_id, vote_value, callback, user_data);
  }

  late final _dna_engine_get_feed_votes = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaFeedPostCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaFeedPostCb>, Pointer<Void>)>('dna_engine_get_feed_votes');

  int dna_engine_get_feed_votes(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> post_id,
    Pointer<DnaFeedPostCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_feed_votes(engine, post_id, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // FEED - COMMENT VOTES
  // ---------------------------------------------------------------------------

  late final _dna_engine_cast_comment_vote = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Int8,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_cast_comment_vote');

  int dna_engine_cast_comment_vote(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> comment_id,
    int vote_value,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_cast_comment_vote(
        engine, comment_id, vote_value, callback, user_data);
  }

  late final _dna_engine_get_comment_votes = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaFeedCommentCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaFeedCommentCb>, Pointer<Void>)>('dna_engine_get_comment_votes');

  int dna_engine_get_comment_votes(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> comment_id,
    Pointer<DnaFeedCommentCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_comment_votes(engine, comment_id, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // FEED - MEMORY MANAGEMENT
  // ---------------------------------------------------------------------------

  late final _dna_free_feed_channels = _lib.lookupFunction<
      Void Function(Pointer<dna_channel_info_t>, Int32),
      void Function(Pointer<dna_channel_info_t>, int)>('dna_free_feed_channels');

  void dna_free_feed_channels(Pointer<dna_channel_info_t> channels, int count) {
    _dna_free_feed_channels(channels, count);
  }

  late final _dna_free_feed_posts = _lib.lookupFunction<
      Void Function(Pointer<dna_post_info_t>, Int32),
      void Function(Pointer<dna_post_info_t>, int)>('dna_free_feed_posts');

  void dna_free_feed_posts(Pointer<dna_post_info_t> posts, int count) {
    _dna_free_feed_posts(posts, count);
  }

  late final _dna_free_feed_post = _lib.lookupFunction<
      Void Function(Pointer<dna_post_info_t>),
      void Function(Pointer<dna_post_info_t>)>('dna_free_feed_post');

  void dna_free_feed_post(Pointer<dna_post_info_t> post) {
    _dna_free_feed_post(post);
  }

  late final _dna_free_feed_comments = _lib.lookupFunction<
      Void Function(Pointer<dna_comment_info_t>, Int32),
      void Function(Pointer<dna_comment_info_t>, int)>('dna_free_feed_comments');

  void dna_free_feed_comments(Pointer<dna_comment_info_t> comments, int count) {
    _dna_free_feed_comments(comments, count);
  }

  late final _dna_free_feed_comment = _lib.lookupFunction<
      Void Function(Pointer<dna_comment_info_t>),
      void Function(Pointer<dna_comment_info_t>)>('dna_free_feed_comment');

  void dna_free_feed_comment(Pointer<dna_comment_info_t> comment) {
    _dna_free_feed_comment(comment);
  }

  // ---------------------------------------------------------------------------
  // VERSION
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_version = _lib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('dna_engine_get_version');

  Pointer<Utf8> dna_engine_get_version() {
    return _dna_engine_get_version();
  }

  late final _dna_engine_check_version_dht = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<dna_version_check_result_t>),
      int Function(Pointer<dna_engine_t>, Pointer<dna_version_check_result_t>)>('dna_engine_check_version_dht');

  int dna_engine_check_version_dht(Pointer<dna_engine_t> engine, Pointer<dna_version_check_result_t> result) {
    return _dna_engine_check_version_dht(engine, result);
  }

  // ---------------------------------------------------------------------------
  // DHT STATUS
  // ---------------------------------------------------------------------------

  late final _dna_engine_is_dht_connected = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_is_dht_connected');

  int dna_engine_is_dht_connected(Pointer<dna_engine_t> engine) {
    return _dna_engine_is_dht_connected(engine);
  }

  // ---------------------------------------------------------------------------
  // LOG CONFIGURATION
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_log_level = _lib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('dna_engine_get_log_level');

  Pointer<Utf8> dna_engine_get_log_level() {
    return _dna_engine_get_log_level();
  }

  late final _dna_engine_set_log_level = _lib.lookupFunction<
      Int32 Function(Pointer<Utf8>),
      int Function(Pointer<Utf8>)>('dna_engine_set_log_level');

  int dna_engine_set_log_level(Pointer<Utf8> level) {
    return _dna_engine_set_log_level(level);
  }

  late final _dna_engine_get_log_tags = _lib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('dna_engine_get_log_tags');

  Pointer<Utf8> dna_engine_get_log_tags() {
    return _dna_engine_get_log_tags();
  }

  late final _dna_engine_set_log_tags = _lib.lookupFunction<
      Int32 Function(Pointer<Utf8>),
      int Function(Pointer<Utf8>)>('dna_engine_set_log_tags');

  int dna_engine_set_log_tags(Pointer<Utf8> tags) {
    return _dna_engine_set_log_tags(tags);
  }

  // ---------------------------------------------------------------------------
  // DEBUG LOG RING BUFFER
  // ---------------------------------------------------------------------------

  late final _dna_engine_debug_log_enable = _lib.lookupFunction<
      Void Function(Bool),
      void Function(bool)>('dna_engine_debug_log_enable');

  void dna_engine_debug_log_enable(bool enabled) {
    _dna_engine_debug_log_enable(enabled);
  }

  late final _dna_engine_debug_log_is_enabled = _lib.lookupFunction<
      Bool Function(),
      bool Function()>('dna_engine_debug_log_is_enabled');

  bool dna_engine_debug_log_is_enabled() {
    return _dna_engine_debug_log_is_enabled();
  }

  late final _dna_engine_debug_log_get_entries = _lib.lookupFunction<
      Int32 Function(Pointer<dna_debug_log_entry_t>, Int32),
      int Function(Pointer<dna_debug_log_entry_t>, int)>('dna_engine_debug_log_get_entries');

  int dna_engine_debug_log_get_entries(Pointer<dna_debug_log_entry_t> entries, int maxEntries) {
    return _dna_engine_debug_log_get_entries(entries, maxEntries);
  }

  late final _dna_engine_debug_log_count = _lib.lookupFunction<
      Int32 Function(),
      int Function()>('dna_engine_debug_log_count');

  int dna_engine_debug_log_count() {
    return _dna_engine_debug_log_count();
  }

  late final _dna_engine_debug_log_clear = _lib.lookupFunction<
      Void Function(),
      void Function()>('dna_engine_debug_log_clear');

  void dna_engine_debug_log_clear() {
    _dna_engine_debug_log_clear();
  }

  late final _dna_engine_debug_log_message = _lib.lookupFunction<
      Void Function(Pointer<Utf8>, Pointer<Utf8>),
      void Function(Pointer<Utf8>, Pointer<Utf8>)>('dna_engine_debug_log_message');

  void dna_engine_debug_log_message(String tag, String message) {
    final tagPtr = tag.toNativeUtf8();
    final msgPtr = message.toNativeUtf8();
    _dna_engine_debug_log_message(tagPtr, msgPtr);
    malloc.free(tagPtr);
    malloc.free(msgPtr);
  }

  late final _dna_engine_debug_log_export = _lib.lookupFunction<
      Int32 Function(Pointer<Utf8>),
      int Function(Pointer<Utf8>)>('dna_engine_debug_log_export');

  int dna_engine_debug_log_export(String filepath) {
    final pathPtr = filepath.toNativeUtf8();
    final result = _dna_engine_debug_log_export(pathPtr);
    malloc.free(pathPtr);
    return result;
  }

  // ===========================================================================
  // MESSAGE BACKUP/RESTORE
  // ===========================================================================

  late final _dna_engine_backup_messages = _lib.lookupFunction<
      Uint64 Function(
        Pointer<dna_engine_t>,
        Pointer<DnaBackupResultCb>,
        Pointer<Void>,
      ),
      int Function(
        Pointer<dna_engine_t>,
        Pointer<DnaBackupResultCb>,
        Pointer<Void>,
      )>('dna_engine_backup_messages');

  int dna_engine_backup_messages(
    Pointer<dna_engine_t> engine,
    Pointer<DnaBackupResultCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_backup_messages(engine, callback, user_data);
  }

  late final _dna_engine_restore_messages = _lib.lookupFunction<
      Uint64 Function(
        Pointer<dna_engine_t>,
        Pointer<DnaBackupResultCb>,
        Pointer<Void>,
      ),
      int Function(
        Pointer<dna_engine_t>,
        Pointer<DnaBackupResultCb>,
        Pointer<Void>,
      )>('dna_engine_restore_messages');

  int dna_engine_restore_messages(
    Pointer<dna_engine_t> engine,
    Pointer<DnaBackupResultCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_restore_messages(engine, callback, user_data);
  }
}

// =============================================================================
// HELPER EXTENSIONS
// =============================================================================

/// Helper to convert char array to String
extension CharArrayToString on Array<Char> {
  String toDartString(int maxLength) {
    // Collect bytes first, then decode as UTF-8
    final bytes = <int>[];
    for (var i = 0; i < maxLength; i++) {
      final char = this[i];
      if (char == 0) break;
      // Handle signed char by converting to unsigned (0-255)
      bytes.add(char & 0xFF);
    }
    if (bytes.isEmpty) return '';
    // Decode as UTF-8, replacing invalid sequences with empty
    return utf8.decode(bytes, allowMalformed: true);
  }
}
