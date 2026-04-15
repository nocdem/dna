// DNA Connect Engine FFI Bindings
// Hand-written bindings for dna_engine.h
// ignore_for_file: non_constant_identifier_names, camel_case_types, constant_identifier_names, unused_field

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

  @Array(64)
  external Array<Char> nickname;

  @Bool()
  external bool is_online;

  // 6 bytes padding to align uint64_t to 8-byte boundary (450 -> 456)
  @Array(6)
  external Array<Uint8> _padding1;

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

  // 7 bytes padding to align uint64_t to 8-byte boundary (449 -> 456)
  @Array(7)
  external Array<Uint8> _padding1;

  @Uint64()
  external int requested_at;

  @Int32()
  external int status; // 0=pending, 1=approved, 2=denied
}

/// Blocked user information
final class dna_blocked_user_t extends Struct {
  @Array(129)
  external Array<Char> fingerprint;

  // 7 bytes padding to align uint64_t to 8-byte boundary (129 -> 136)
  @Array(7)
  external Array<Uint8> _padding1;

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

  // 2 bytes padding to align pointer to 8-byte boundary (262 -> 264)
  @Array(2)
  external Array<Uint8> _padding1;

  external Pointer<Utf8> plaintext;

  @Uint64()
  external int timestamp;

  @Bool()
  external bool is_outgoing;

  // 3 bytes padding to align int to 4-byte boundary (281 -> 284)
  @Array(3)
  external Array<Uint8> _padding2;

  @Int32()
  external int status;

  @Int32()
  external int message_type;

  @Bool()
  external bool deleted_by_sender;

  // v0.9.194: content_hash (SHA3-256 hex, 64 chars + null = 65 bytes)
  // Offset 293, ends at 358.
  @Array(65)
  external Array<Char> content_hash;

  // Padding to align struct to 8-byte boundary (plaintext pointer alignment).
  // Struct total size 360; after content_hash we're at 358, need 2 bytes pad.
  @Array(2)
  external Array<Uint8> _padding3;
}

/// Reaction entry (one reactor applying one emoji to one target message)
final class dna_reaction_t extends Struct {
  @Array(129)
  external Array<Char> reactor_fp;

  @Array(8)
  external Array<Char> emoji;

  // 7 bytes padding to align uint64 to 8-byte boundary (137 -> 144)
  @Array(7)
  external Array<Uint8> _padding1;

  @Uint64()
  external int timestamp;
}

/// Group information
final class dna_group_t extends Struct {
  @Array(37)
  external Array<Char> uuid;

  @Array(256)
  external Array<Char> name;

  @Array(129)
  external Array<Char> creator;

  // 2 bytes padding to align int to 4-byte boundary (422 -> 424)
  @Array(2)
  external Array<Uint8> _padding1;

  @Int32()
  external int member_count;

  // 4 bytes padding to align uint64_t to 8-byte boundary (428 -> 432)
  @Array(4)
  external Array<Uint8> _padding2;

  @Uint64()
  external int created_at;
}

/// Group member information
final class dna_group_member_t extends Struct {
  @Array(129)
  external Array<Char> fingerprint;

  // 7 bytes padding to align uint64_t to 8-byte boundary (129 -> 136)
  @Array(7)
  external Array<Uint8> _padding1;

  @Uint64()
  external int added_at;

  @Bool()
  external bool is_owner;
}

/// Extended group information (includes GEK version)
final class dna_group_info_t extends Struct {
  @Array(37)
  external Array<Char> uuid;

  @Array(256)
  external Array<Char> name;

  @Array(129)
  external Array<Char> creator;

  // 2 bytes padding (422 -> 424)
  @Array(2)
  external Array<Uint8> _padding1;

  @Int32()
  external int member_count;

  // 4 bytes padding to align uint64_t (428 -> 432)
  @Array(4)
  external Array<Uint8> _padding2;

  @Uint64()
  external int created_at;

  @Bool()
  external bool is_owner;

  // 3 bytes padding to align uint32_t (441 -> 444)
  @Array(3)
  external Array<Uint8> _padding3;

  @Uint32()
  external int gek_version;
}

/// Group invitation
final class dna_invitation_t extends Struct {
  @Array(37)
  external Array<Char> group_uuid;

  @Array(256)
  external Array<Char> group_name;

  @Array(129)
  external Array<Char> inviter;

  // 2 bytes padding to align int to 4-byte boundary (422 -> 424)
  @Array(2)
  external Array<Uint8> _padding1;

  @Int32()
  external int member_count;

  // 4 bytes padding to align uint64_t to 8-byte boundary (428 -> 432)
  @Array(4)
  external Array<Uint8> _padding2;

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

/// Gas estimates for all 3 speeds (single RPC call)
final class dna_gas_estimates_t extends Struct {
  external dna_gas_estimate_t slow;
  external dna_gas_estimate_t normal;
  external dna_gas_estimate_t fast;
}

/// DEX quote result
final class dna_dex_quote_t extends Struct {
  @Array(16)
  external Array<Char> from_token;

  @Array(16)
  external Array<Char> to_token;

  @Array(64)
  external Array<Char> amount_in;

  @Array(64)
  external Array<Char> amount_out;

  @Array(64)
  external Array<Char> price;

  @Array(16)
  external Array<Char> price_impact;

  @Array(64)
  external Array<Char> fee;

  @Array(48)
  external Array<Char> pool_address;

  @Array(32)
  external Array<Char> dex_name;

  @Array(8)
  external Array<Char> chain;

  @Array(128)
  external Array<Char> warning;
}

/// DEX swap result
final class dna_dex_swap_result_t extends Struct {
  @Array(128)
  external Array<Char> tx_signature;

  @Array(64)
  external Array<Char> amount_in;

  @Array(64)
  external Array<Char> amount_out;

  @Array(16)
  external Array<Char> from_token;

  @Array(16)
  external Array<Char> to_token;

  @Array(32)
  external Array<Char> dex_name;

  @Array(16)
  external Array<Char> price_impact;
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

/// Address book entry (wallet addresses)
final class dna_addressbook_entry_t extends Struct {
  @Int32()
  external int id;

  @Array(128)
  external Array<Char> address;

  @Array(64)
  external Array<Char> label;

  @Array(32)
  external Array<Char> network;

  @Array(256)
  external Array<Char> notes;

  // 4 bytes padding to align uint64_t to 8-byte boundary (484 -> 488)
  @Array(4)
  external Array<Uint8> _padding1;

  @Uint64()
  external int created_at;

  @Uint64()
  external int updated_at;

  @Uint64()
  external int last_used;

  @Uint32()
  external int use_count;
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

/// Backup info structure for check_backup_exists (v0.4.60)
final class dna_backup_info_t extends Struct {
  @Bool()
  external bool exists;

  // 7 bytes padding to align uint64_t to 8-byte boundary (C struct alignment)
  @Array(7)
  external Array<Uint8> _padding1;

  @Uint64()
  external int timestamp;

  @Int32()
  external int message_count;
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

  @Array(128)
  external Array<Char> bsc;

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

  // Profile info (NOTE: display_name removed in v0.6.24 - only registered name is used)
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
// CHANNEL DATA STRUCTURES
// =============================================================================

/// Channel information
/// Matches dna_channel_info_t from dna_engine.h
final class dna_channel_info_t extends Struct {
  @Array(37)
  external Array<Char> channel_uuid;

  @Array(101)
  external Array<Char> name;

  // Padding for pointer alignment (37+101=138, next 8-byte boundary=144)
  @Array(6)
  external Array<Uint8> _padding1;

  external Pointer<Utf8> description;

  @Array(129)
  external Array<Char> creator_fingerprint;

  // Padding for uint64_t alignment (129 bytes, next 8-byte boundary needs 7)
  @Array(7)
  external Array<Uint8> _padding2;

  @Uint64()
  external int created_at;

  @Bool()
  external bool is_public;

  @Bool()
  external bool deleted;

  // Padding for uint64_t alignment (2 bools = 2 bytes, need 6 more)
  @Array(6)
  external Array<Uint8> _padding3;

  @Uint64()
  external int deleted_at;

  @Bool()
  external bool verified;
}

/// Channel post information
/// Matches dna_channel_post_info_t from dna_engine.h
final class dna_channel_post_info_t extends Struct {
  @Array(37)
  external Array<Char> post_uuid;

  @Array(37)
  external Array<Char> channel_uuid;

  @Array(129)
  external Array<Char> author_fingerprint;

  // Padding for pointer alignment (37+37+129=203, next 8-byte boundary=208)
  @Array(5)
  external Array<Uint8> _padding1;

  external Pointer<Utf8> body;

  @Uint64()
  external int created_at;

  @Bool()
  external bool verified;
}

/// Channel subscription information
/// Matches dna_channel_subscription_info_t from dna_engine.h
final class dna_channel_subscription_info_t extends Struct {
  @Array(37)
  external Array<Char> channel_uuid;

  // Padding for uint64_t alignment (37 bytes, next 8-byte boundary=40)
  @Array(3)
  external Array<Uint8> _padding1;

  @Uint64()
  external int subscribed_at;

  @Uint64()
  external int last_synced;

  @Uint64()
  external int last_read_at;
}

// =============================================================================
// WALL DATA STRUCTURES
// =============================================================================

/// Wall post information
/// Matches dna_wall_post_info_t from dna_engine.h
final class dna_wall_post_info_t extends Struct {
  @Array(37)
  external Array<Char> uuid;

  @Array(129)
  external Array<Char> author_fingerprint;

  @Array(65)
  external Array<Char> author_name;

  @Array(2048)
  external Array<Char> text;

  /// Heap-allocated image JSON, nullptr if no image (v0.7.0+)
  external Pointer<Utf8> image_json;

  @Uint64()
  external int timestamp;

  @Bool()
  external bool verified;

  @Bool()
  external bool is_boosted;
}

/// Wall comment information (v0.7.0+)
/// Matches dna_wall_comment_info_t from dna_engine.h
final class dna_wall_comment_info_t extends Struct {
  @Array(37)
  external Array<Char> comment_uuid;

  @Array(37)
  external Array<Char> post_uuid;

  @Array(37)
  external Array<Char> parent_comment_uuid;

  @Array(129)
  external Array<Char> author_fingerprint;

  @Array(65)
  external Array<Char> author_name;

  @Array(2001)
  external Array<Char> body;

  @Uint64()
  external int created_at;

  @Bool()
  external bool verified;

  @Uint32()
  external int comment_type;
}

/// Wall like information (v0.9.52+)
/// Matches dna_wall_like_info_t from dna_engine.h
final class dna_wall_like_info_t extends Struct {
  @Array(129)
  external Array<Char> author_fingerprint;

  @Array(65)
  external Array<Char> author_name;

  @Uint64()
  external int timestamp;

  @Bool()
  external bool verified;
}

/// Wall engagement data (v0.9.123+ batch)
/// Matches dna_wall_engagement_t from dna_engine.h
final class dna_wall_engagement_t extends Struct {
  @Array(37)
  external Array<Char> post_uuid;

  external Pointer<dna_wall_comment_info_t> comments;

  @Int32()
  external int comment_count;

  @Int32()
  external int like_count;

  @Bool()
  external bool is_liked_by_me;
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
  static const int DNA_EVENT_GROUP_MESSAGE_RECEIVED = 14;  // New group messages via DHT listen
  static const int DNA_EVENT_GROUPS_SYNCED = 15;  // Groups restored from DHT to local cache
  static const int DNA_EVENT_CONTACTS_SYNCED = 16;  // Contacts restored from DHT to local cache
  static const int DNA_EVENT_GEKS_SYNCED = 17;  // GEKs restored from DHT to local cache
  static const int DNA_EVENT_DHT_PUBLISH_COMPLETE = 18;  // Async DHT publish completed
  static const int DNA_EVENT_DHT_PUBLISH_FAILED = 19;  // Async DHT publish failed
  static const int DNA_EVENT_WALL_NEW_POST = 20;  // New wall post from a contact
  static const int DNA_EVENT_CHANNEL_NEW_POST = 21;  // New post in subscribed channel
  static const int DNA_EVENT_CHANNEL_SUBS_SYNCED = 22;  // Channel subscriptions synced from DHT
  static const int DNA_EVENT_MEDIA_UPLOAD_PROGRESS = 23;  // Media upload byte progress
  static const int DNA_EVENT_ERROR = 24;
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

/// Event data union - message delivered
final class dna_event_message_delivered extends Struct {
  @Array(129)
  external Array<Char> recipient;

  // 7 bytes padding to align uint64_t to 8-byte boundary (129 -> 136)
  @Array(7)
  external Array<Uint8> _padding1;

  @Uint64()
  external int seq_num;

  @Uint64()
  external int timestamp;
}

/// Event data union - contact request received
final class dna_event_contact_request_received extends Struct {
  external dna_contact_request_t request;
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

  // Padding for 8-byte alignment of union (matches C struct layout on 64-bit)
  @Array(4)
  external Array<Uint8> _padding;

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

  @Bool()
  external bool library_below_minimum;

  @Bool()
  external bool app_below_minimum;

  // 3 bytes padding to align embedded struct to 8-byte boundary (5 -> 8)
  // dna_version_info_t has 8-byte alignment due to uint64_t published_at
  @Array(3)
  external Array<Uint8> _padding1;

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

/// Engine creation callback - Native (v0.6.16)
typedef DnaEngineCreatedCbNative = Void Function(
  Pointer<dna_engine_t> engine,
  Int32 error,
  Pointer<Void> user_data,
);
typedef DnaEngineCreatedCb = NativeFunction<DnaEngineCreatedCbNative>;

/// Send tokens callback - Native (returns tx_hash on success)
typedef DnaSendTokensCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Utf8> tx_hash,
  Pointer<Void> user_data,
);
typedef DnaSendTokensCb = NativeFunction<DnaSendTokensCbNative>;

/// TX status callback - Native (error is string on failure, NULL on success)
typedef DnaTxStatusCbNative = Void Function(
  Uint64 request_id,
  Pointer<Utf8> error,
  Pointer<Utf8> tx_hash,
  Int32 status,
  Pointer<Void> user_data,
);
typedef DnaTxStatusCb = NativeFunction<DnaTxStatusCbNative>;

/// Gas estimates callback - Native (all 3 speeds)
typedef DnaGasEstimatesCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_gas_estimates_t> estimates,
  Pointer<Void> user_data,
);
typedef DnaGasEstimatesCb = NativeFunction<DnaGasEstimatesCbNative>;

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

/// Messages page callback (with total count) - Native
typedef DnaMessagesPageCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_message_t> messages,
  Int32 count,
  Int32 total,
  Pointer<Void> user_data,
);
typedef DnaMessagesPageCb = NativeFunction<DnaMessagesPageCbNative>;

/// Reactions callback - Native
typedef DnaReactionsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_reaction_t> reactions,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaReactionsCb = NativeFunction<DnaReactionsCbNative>;

/// Groups callback - Native
typedef DnaGroupsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_group_t> groups,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaGroupsCb = NativeFunction<DnaGroupsCbNative>;

/// Group info callback - Native
typedef DnaGroupInfoCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_group_info_t> info,
  Pointer<Void> user_data,
);
typedef DnaGroupInfoCb = NativeFunction<DnaGroupInfoCbNative>;

/// Group members callback - Native
typedef DnaGroupMembersCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_group_member_t> members,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaGroupMembersCb = NativeFunction<DnaGroupMembersCbNative>;

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

/// DEX quote callback - Native
typedef DnaDexQuoteCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_dex_quote_t> quotes,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaDexQuoteCb = NativeFunction<DnaDexQuoteCbNative>;

/// DEX swap callback - Native
typedef DnaDexSwapCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_dex_swap_result_t> result,
  Pointer<Void> user_data,
);
typedef DnaDexSwapCb = NativeFunction<DnaDexSwapCbNative>;

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

/// Backup info callback - Native (v0.4.60 for check_backup_exists)
typedef DnaBackupInfoCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_backup_info_t> info,
  Pointer<Void> user_data,
);
typedef DnaBackupInfoCb = NativeFunction<DnaBackupInfoCbNative>;

/// Address book callback - Native
typedef DnaAddressbookCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_addressbook_entry_t> entries,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaAddressbookCb = NativeFunction<DnaAddressbookCbNative>;

/// Channel: Single channel callback - Native
typedef DnaChannelCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_info_t> channel,
  Pointer<Void> user_data,
);
typedef DnaChannelCb = NativeFunction<DnaChannelCbNative>;

/// Channel: Channels list callback - Native
typedef DnaChannelsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_info_t> channels,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaChannelsCb = NativeFunction<DnaChannelsCbNative>;

/// Channel: Single post callback - Native
typedef DnaChannelPostCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_post_info_t> post,
  Pointer<Void> user_data,
);
typedef DnaChannelPostCb = NativeFunction<DnaChannelPostCbNative>;

/// Channel: Posts list callback - Native
typedef DnaChannelPostsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_post_info_t> posts,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaChannelPostsCb = NativeFunction<DnaChannelPostsCbNative>;

/// Channel: Subscriptions list callback - Native
typedef DnaChannelSubscriptionsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_channel_subscription_info_t> subscriptions,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaChannelSubscriptionsCb = NativeFunction<DnaChannelSubscriptionsCbNative>;

/// Wall: Single post callback - Native
typedef DnaWallPostCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wall_post_info_t> post,
  Pointer<Void> user_data,
);
typedef DnaWallPostCb = NativeFunction<DnaWallPostCbNative>;

/// Wall: Posts list callback - Native
typedef DnaWallPostsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wall_post_info_t> posts,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaWallPostsCb = NativeFunction<DnaWallPostsCbNative>;

/// Wall: Comment callback (single comment) - Native
typedef DnaWallCommentCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wall_comment_info_t> comment,
  Pointer<Void> user_data,
);
typedef DnaWallCommentCb = NativeFunction<DnaWallCommentCbNative>;

/// Wall: Comments list callback - Native
typedef DnaWallCommentsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wall_comment_info_t> comments,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaWallCommentsCb = NativeFunction<DnaWallCommentsCbNative>;

/// Wall: Likes list callback - Native (v0.9.52+)
typedef DnaWallLikesCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wall_like_info_t> likes,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaWallLikesCb = NativeFunction<DnaWallLikesCbNative>;

/// Wall: Engagement batch callback - Native (v0.9.123+)
typedef DnaWallEngagementCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_wall_engagement_t> engagements,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaWallEngagementCb = NativeFunction<DnaWallEngagementCbNative>;

/// Wall: Image fetch callback - Native (v0.9.142+)
typedef DnaWallImageCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Utf8> image_json,
  Pointer<Void> user_data,
);
typedef DnaWallImageCb = NativeFunction<DnaWallImageCbNative>;

/// Media: Upload callback - Native (v0.9.146+)
typedef DnaMediaUploadCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Uint8> content_hash,
  Pointer<Void> user_data,
);
typedef DnaMediaUploadCb = NativeFunction<DnaMediaUploadCbNative>;

/// Media: Download callback - Native (v0.9.146+)
typedef DnaMediaDownloadCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<Uint8> data,
  Uint64 data_len,
  Pointer<Void> user_data,
);
typedef DnaMediaDownloadCb = NativeFunction<DnaMediaDownloadCbNative>;

/// Media: Exists callback - Native (v0.9.146+)
typedef DnaMediaExistsCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Bool exists,
  Pointer<Void> user_data,
);
typedef DnaMediaExistsCb = NativeFunction<DnaMediaExistsCbNative>;

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

typedef DnaGroupInfoCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_group_info_t> info,
  Pointer<Void> userData,
);

typedef DnaGroupMembersCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_group_member_t> members,
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

typedef DnaBackupInfoCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_backup_info_t> info,
  Pointer<Void> userData,
);

typedef DnaAddressbookCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_addressbook_entry_t> entries,
  int count,
  Pointer<Void> userData,
);

typedef DnaChannelCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_info_t> channel,
  Pointer<Void> userData,
);

typedef DnaChannelsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_info_t> channels,
  int count,
  Pointer<Void> userData,
);

typedef DnaChannelPostCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_post_info_t> post,
  Pointer<Void> userData,
);

typedef DnaChannelPostsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_post_info_t> posts,
  int count,
  Pointer<Void> userData,
);

typedef DnaChannelSubscriptionsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_channel_subscription_info_t> subscriptions,
  int count,
  Pointer<Void> userData,
);

typedef DnaWallPostCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_wall_post_info_t> post,
  Pointer<Void> userData,
);

typedef DnaWallPostsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_wall_post_info_t> posts,
  int count,
  Pointer<Void> userData,
);

typedef DnaWallCommentCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_wall_comment_info_t> comment,
  Pointer<Void> userData,
);

typedef DnaWallCommentsCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_wall_comment_info_t> comments,
  int count,
  Pointer<Void> userData,
);

typedef DnaWallLikesCbDart = void Function(
  int requestId,
  int error,
  Pointer<dna_wall_like_info_t> likes,
  int count,
  Pointer<Void> userData,
);

typedef DnaWallImageCbDart = void Function(
  int requestId,
  int error,
  Pointer<Utf8> imageJson,
  Pointer<Void> userData,
);

typedef DnaMediaUploadCbDart = void Function(
  int requestId,
  int error,
  Pointer<Uint8> contentHash,
  Pointer<Void> userData,
);

typedef DnaMediaDownloadCbDart = void Function(
  int requestId,
  int error,
  Pointer<Uint8> data,
  int dataLen,
  Pointer<Void> userData,
);

typedef DnaMediaExistsCbDart = void Function(
  int requestId,
  int error,
  bool exists,
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

  // v0.6.18: Async engine creation (non-blocking) with cancellation support
  late final _dna_engine_create_async = _lib.lookupFunction<
      Void Function(Pointer<Utf8>, Pointer<DnaEngineCreatedCb>, Pointer<Void>, Pointer<Bool>),
      void Function(Pointer<Utf8>, Pointer<DnaEngineCreatedCb>, Pointer<Void>, Pointer<Bool>)>('dna_engine_create_async');

  void dna_engine_create_async(
    Pointer<Utf8> data_dir,
    Pointer<DnaEngineCreatedCb> callback,
    Pointer<Void> user_data,
    Pointer<Bool> cancelled,
  ) {
    _dna_engine_create_async(data_dir, callback, user_data, cancelled);
  }

  late final _dna_engine_destroy = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>),
      void Function(Pointer<dna_engine_t>)>('dna_engine_destroy');

  void dna_engine_destroy(Pointer<dna_engine_t> engine) {
    _dna_engine_destroy(engine);
  }

  // Global engine for seamless JNI/FFI handoff (Android v0.5.5+)
  late final _dna_engine_get_global = _lib.lookupFunction<
      Pointer<dna_engine_t> Function(),
      Pointer<dna_engine_t> Function()>('dna_engine_get_global');

  Pointer<dna_engine_t> dna_engine_get_global() {
    return _dna_engine_get_global();
  }

  late final _dna_engine_set_global = _lib.lookupFunction<
      Void Function(Pointer<dna_engine_t>),
      void Function(Pointer<dna_engine_t>)>('dna_engine_set_global');

  void dna_engine_set_global(Pointer<dna_engine_t> engine) {
    _dna_engine_set_global(engine);
  }

  // Android-only: Check if identity loaded (v0.5.5+)
  late final _dna_engine_is_identity_loaded = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>),
      bool Function(Pointer<dna_engine_t>)>('dna_engine_is_identity_loaded');

  bool dna_engine_is_identity_loaded(Pointer<dna_engine_t> engine) {
    return _dna_engine_is_identity_loaded(engine);
  }

  late final _dna_engine_is_transport_ready = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>),
      bool Function(Pointer<dna_engine_t>)>('dna_engine_is_transport_ready');

  bool dna_engine_is_transport_ready(Pointer<dna_engine_t> engine) {
    return _dna_engine_is_transport_ready(engine);
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

  // Set contact nickname (synchronous)
  late final _dna_engine_set_contact_nickname_sync = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>)>(
      'dna_engine_set_contact_nickname_sync');

  int dna_engine_set_contact_nickname_sync(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<Utf8> nickname,
  ) {
    return _dna_engine_set_contact_nickname_sync(engine, fingerprint, nickname);
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
  // FOLLOWING
  // ---------------------------------------------------------------------------

  late final _dna_engine_follow = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_follow');

  int dna_engine_follow(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_follow(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_unfollow = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_unfollow');

  int dna_engine_unfollow(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_unfollow(engine, fingerprint, callback, user_data);
  }

  late final _dna_engine_is_following = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      bool Function(Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_is_following');

  bool dna_engine_is_following(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
  ) {
    return _dna_engine_is_following(engine, fingerprint);
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

  late final _dna_engine_send_reaction = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<Utf8>, Pointer<DnaCompletionCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<Utf8>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_send_reaction');

  int dna_engine_send_reaction(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> recipient_fingerprint,
    Pointer<Utf8> target_content_hash,
    Pointer<Utf8> emoji,
    Pointer<Utf8> op,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_send_reaction(engine, recipient_fingerprint,
        target_content_hash, emoji, op, callback, user_data);
  }

  late final _dna_engine_get_reactions = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaReactionsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaReactionsCb>, Pointer<Void>)>('dna_engine_get_reactions');

  int dna_engine_get_reactions(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> target_content_hash,
    Pointer<DnaReactionsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_reactions(
        engine, target_content_hash, callback, user_data);
  }

  late final _dna_free_reactions = _lib.lookupFunction<
      Void Function(Pointer<dna_reaction_t>, Int32),
      void Function(Pointer<dna_reaction_t>, int)>('dna_free_reactions');

  void dna_free_reactions(Pointer<dna_reaction_t> reactions, int count) {
    _dna_free_reactions(reactions, count);
  }

  // Send debug log to a receiver's debug inbox
  late final _dna_engine_debug_log_send = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Uint8>,
          Size, Pointer<Utf8>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Uint8>, int,
          Pointer<Utf8>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_debug_log_send');

  int dna_engine_debug_log_send(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> receiver_fp_hex,
    Pointer<Uint8> log_body,
    int log_len,
    Pointer<Utf8> hint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_debug_log_send(
        engine, receiver_fp_hex, log_body, log_len, hint, callback, user_data);
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

  // Queue group message for async sending (returns immediately)
  late final _dna_engine_queue_group_message = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<Utf8>)>('dna_engine_queue_group_message');

  int dna_engine_queue_group_message(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<Utf8> message,
  ) {
    return _dna_engine_queue_group_message(engine, group_uuid, message);
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

  late final _dna_engine_get_conversation_page = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Int32, Int32,
          Pointer<DnaMessagesPageCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int, int,
          Pointer<DnaMessagesPageCb>, Pointer<Void>)>('dna_engine_get_conversation_page');

  int dna_engine_get_conversation_page(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contact_fingerprint,
    int limit,
    int offset,
    Pointer<DnaMessagesPageCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_conversation_page(
        engine, contact_fingerprint, limit, offset, callback, user_data);
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

  // Check offline messages from a specific contact
  late final _dna_engine_check_offline_messages_from = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>(
      'dna_engine_check_offline_messages_from');

  int dna_engine_check_offline_messages_from(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contactFingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_check_offline_messages_from(
        engine, contactFingerprint, callback, user_data);
  }

  // Delete a message from local database
  late final _dna_engine_delete_message_sync = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Int32),
      int Function(Pointer<dna_engine_t>, int)>('dna_engine_delete_message_sync');

  /// Delete a message from local database (synchronous)
  /// Returns 0 on success, -1 on error
  int dna_engine_delete_message_sync(
    Pointer<dna_engine_t> engine,
    int messageId,
  ) {
    return _dna_engine_delete_message_sync(engine, messageId);
  }

  // Delete a message with full pipeline (local + DHT + notices)
  late final _dna_engine_delete_message = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Bool,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, bool,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_delete_message');

  /// Delete a message with full pipeline (local + DHT + notices, async)
  int dna_engine_delete_message(
    Pointer<dna_engine_t> engine,
    int messageId,
    bool sendNotices,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_delete_message(engine, messageId, sendNotices, callback, user_data);
  }

  // Delete all messages with a contact (purge conversation)
  late final _dna_engine_delete_conversation = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Bool,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, bool,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_delete_conversation');

  /// Delete all messages with a contact (async)
  int dna_engine_delete_conversation(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> contactFingerprint,
    bool sendNotices,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_delete_conversation(engine, contactFingerprint, sendNotices, callback, user_data);
  }

  // Delete all messages (purge everything)
  late final _dna_engine_delete_all_messages = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Bool,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, bool,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_delete_all_messages');

  /// Delete all messages (async)
  int dna_engine_delete_all_messages(
    Pointer<dna_engine_t> engine,
    bool sendNotices,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_delete_all_messages(engine, sendNotices, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // MESSAGE RETRY
  // ---------------------------------------------------------------------------

  late final _dna_engine_retry_pending_messages = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_retry_pending_messages');

  /// Retry all pending/failed messages
  /// Returns number of messages successfully retried, or -1 on error
  int dna_engine_retry_pending_messages(Pointer<dna_engine_t> engine) {
    return _dna_engine_retry_pending_messages(engine);
  }

  late final _dna_engine_retry_message = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Int32),
      int Function(Pointer<dna_engine_t>, int)>('dna_engine_retry_message');

  /// Retry a single failed message by ID
  /// Returns 0 on success, -1 on error
  int dna_engine_retry_message(
    Pointer<dna_engine_t> engine,
    int messageId,
  ) {
    return _dna_engine_retry_message(engine, messageId);
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

  late final _dna_engine_get_group_info = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaGroupInfoCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaGroupInfoCb>, Pointer<Void>)>('dna_engine_get_group_info');

  int dna_engine_get_group_info(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<DnaGroupInfoCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_group_info(engine, group_uuid, callback, user_data);
  }

  late final _dna_engine_get_group_members = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaGroupMembersCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaGroupMembersCb>, Pointer<Void>)>('dna_engine_get_group_members');

  int dna_engine_get_group_members(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<DnaGroupMembersCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_group_members(engine, group_uuid, callback, user_data);
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

  late final _dna_engine_get_group_conversation = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaMessagesCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaMessagesCb>, Pointer<Void>)>('dna_engine_get_group_conversation');

  int dna_engine_get_group_conversation(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<DnaMessagesCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_group_conversation(engine, group_uuid, callback, user_data);
  }

  late final _dna_engine_add_group_member = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_add_group_member');

  int dna_engine_add_group_member(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_add_group_member(
        engine, group_uuid, fingerprint, callback, user_data);
  }

  late final _dna_engine_remove_group_member = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_remove_group_member');

  int dna_engine_remove_group_member(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<Utf8> fingerprint,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_remove_group_member(
        engine, group_uuid, fingerprint, callback, user_data);
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

  late final _dna_engine_get_cached_balances = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Pointer<DnaBalancesCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<DnaBalancesCb>,
          Pointer<Void>)>('dna_engine_get_cached_balances');

  int dna_engine_get_cached_balances(
    Pointer<dna_engine_t> engine,
    int wallet_index,
    Pointer<DnaBalancesCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_cached_balances(engine, wallet_index, callback, user_data);
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

  late final _dna_engine_estimate_gas_async = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaGasEstimatesCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaGasEstimatesCb>, Pointer<Void>)>('dna_engine_estimate_gas_async');

  int dna_engine_estimate_gas_async(
    Pointer<dna_engine_t> engine,
    Pointer<DnaGasEstimatesCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_estimate_gas_async(engine, callback, user_data);
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

  late final _dna_engine_get_tx_status = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<DnaTxStatusCb>,
          Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<DnaTxStatusCb>,
          Pointer<Void>)>('dna_engine_get_tx_status');

  int dna_engine_get_tx_status(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> tx_hash,
    Pointer<Utf8> chain,
    Pointer<DnaTxStatusCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_tx_status(engine, tx_hash, chain, callback, user_data);
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

  late final _dna_engine_get_cached_transactions = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Pointer<Utf8>,
          Pointer<DnaTransactionsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<Utf8>,
          Pointer<DnaTransactionsCb>, Pointer<Void>)>('dna_engine_get_cached_transactions');

  int dna_engine_get_cached_transactions(
    Pointer<dna_engine_t> engine,
    int wallet_index,
    Pointer<Utf8> network,
    Pointer<DnaTransactionsCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_cached_transactions(
        engine, wallet_index, network, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // DEX
  // ---------------------------------------------------------------------------

  late final _dna_engine_dex_quote = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<Utf8>, Pointer<DnaDexQuoteCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<Utf8>, Pointer<DnaDexQuoteCb>, Pointer<Void>)>('dna_engine_dex_quote');

  int dna_engine_dex_quote(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> from_token,
    Pointer<Utf8> to_token,
    Pointer<Utf8> amount_in,
    Pointer<Utf8> dex_filter,
    Pointer<DnaDexQuoteCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dex_quote(
        engine, from_token, to_token, amount_in, dex_filter, callback, user_data);
  }

  late final _dna_engine_dex_swap = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<DnaDexSwapCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<DnaDexSwapCb>, Pointer<Void>)>('dna_engine_dex_swap');

  int dna_engine_dex_swap(
    Pointer<dna_engine_t> engine,
    int wallet_index,
    Pointer<Utf8> from_token,
    Pointer<Utf8> to_token,
    Pointer<Utf8> amount_in,
    Pointer<DnaDexSwapCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dex_swap(
        engine, wallet_index, from_token, to_token, amount_in, callback, user_data);
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

  /// Pause engine for background mode (v0.6.50+)
  /// Suspends DHT listeners while keeping engine alive for fast resume
  late final _dna_engine_pause = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_pause');

  int dna_engine_pause(Pointer<dna_engine_t> engine) {
    return _dna_engine_pause(engine);
  }

  /// Resume engine from background mode (v0.6.50+)
  /// Resubscribes DHT listeners for fast return to foreground
  late final _dna_engine_resume = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_resume');

  int dna_engine_resume(Pointer<dna_engine_t> engine) {
    return _dna_engine_resume(engine);
  }

  /// Check if engine is paused (v0.6.50+)
  late final _dna_engine_is_paused = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>),
      bool Function(Pointer<dna_engine_t>)>('dna_engine_is_paused');

  bool dna_engine_is_paused(Pointer<dna_engine_t> engine) {
    return _dna_engine_is_paused(engine);
  }

  /// Handle network connectivity change (reinitialize DHT)
  late final _dna_engine_network_changed = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>),
      int Function(Pointer<dna_engine_t>)>('dna_engine_network_changed');

  int dna_engine_network_changed(Pointer<dna_engine_t> engine) {
    return _dna_engine_network_changed(engine);
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

  late final _dna_free_group_info = _lib.lookupFunction<
      Void Function(Pointer<dna_group_info_t>),
      void Function(Pointer<dna_group_info_t>)>('dna_free_group_info');

  void dna_free_group_info(Pointer<dna_group_info_t> info) {
    _dna_free_group_info(info);
  }

  late final _dna_free_group_members = _lib.lookupFunction<
      Void Function(Pointer<dna_group_member_t>, Int32),
      void Function(Pointer<dna_group_member_t>, int)>('dna_free_group_members');

  void dna_free_group_members(Pointer<dna_group_member_t> members, int count) {
    _dna_free_group_members(members, count);
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
  // GROUPS - SYNC GROUP BY UUID
  // ---------------------------------------------------------------------------

  late final _dna_engine_sync_group_by_uuid = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_sync_group_by_uuid');

  int dna_engine_sync_group_by_uuid(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> group_uuid,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_sync_group_by_uuid(engine, group_uuid, callback, user_data);
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

  late final _dna_engine_debug_log_message_level = _lib.lookupFunction<
      Void Function(Pointer<Utf8>, Pointer<Utf8>, Int32),
      void Function(Pointer<Utf8>, Pointer<Utf8>, int)>('dna_engine_debug_log_message_level');

  void dna_engine_debug_log_message_level(String tag, String message, int level) {
    final tagPtr = tag.toNativeUtf8();
    final msgPtr = message.toNativeUtf8();
    _dna_engine_debug_log_message_level(tagPtr, msgPtr, level);
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

  late final _dna_engine_check_backup_exists = _lib.lookupFunction<
      Uint64 Function(
        Pointer<dna_engine_t>,
        Pointer<DnaBackupInfoCb>,
        Pointer<Void>,
      ),
      int Function(
        Pointer<dna_engine_t>,
        Pointer<DnaBackupInfoCb>,
        Pointer<Void>,
      )>('dna_engine_check_backup_exists');

  int dna_engine_check_backup_exists(
    Pointer<dna_engine_t> engine,
    Pointer<DnaBackupInfoCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_check_backup_exists(engine, callback, user_data);
  }

  // ---------------------------------------------------------------------------
  // ADDRESS BOOK
  // ---------------------------------------------------------------------------

  late final _dna_engine_get_addressbook = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaAddressbookCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaAddressbookCb>,
          Pointer<Void>)>('dna_engine_get_addressbook');

  int dna_engine_get_addressbook(
    Pointer<dna_engine_t> engine,
    Pointer<DnaAddressbookCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_addressbook(engine, callback, user_data);
  }

  late final _dna_engine_get_addressbook_by_network = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaAddressbookCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaAddressbookCb>, Pointer<Void>)>(
      'dna_engine_get_addressbook_by_network');

  int dna_engine_get_addressbook_by_network(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> network,
    Pointer<DnaAddressbookCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_addressbook_by_network(
        engine, network, callback, user_data);
  }

  late final _dna_engine_get_recent_addresses = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32, Pointer<DnaAddressbookCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<DnaAddressbookCb>,
          Pointer<Void>)>('dna_engine_get_recent_addresses');

  int dna_engine_get_recent_addresses(
    Pointer<dna_engine_t> engine,
    int limit,
    Pointer<DnaAddressbookCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_recent_addresses(engine, limit, callback, user_data);
  }

  late final _dna_engine_add_address = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<Utf8>)>('dna_engine_add_address');

  int dna_engine_add_address(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> address,
    Pointer<Utf8> label,
    Pointer<Utf8> network,
    Pointer<Utf8> notes,
  ) {
    return _dna_engine_add_address(engine, address, label, network, notes);
  }

  late final _dna_engine_update_address = _lib.lookupFunction<
      Int32 Function(
          Pointer<dna_engine_t>, Int32, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<dna_engine_t>, int, Pointer<Utf8>,
          Pointer<Utf8>)>('dna_engine_update_address');

  int dna_engine_update_address(
    Pointer<dna_engine_t> engine,
    int id,
    Pointer<Utf8> label,
    Pointer<Utf8> notes,
  ) {
    return _dna_engine_update_address(engine, id, label, notes);
  }

  late final _dna_engine_remove_address = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Int32),
      int Function(Pointer<dna_engine_t>, int)>('dna_engine_remove_address');

  int dna_engine_remove_address(
    Pointer<dna_engine_t> engine,
    int id,
  ) {
    return _dna_engine_remove_address(engine, id);
  }

  late final _dna_engine_address_exists = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>),
      bool Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<Utf8>)>('dna_engine_address_exists');

  bool dna_engine_address_exists(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> address,
    Pointer<Utf8> network,
  ) {
    return _dna_engine_address_exists(engine, address, network);
  }

  late final _dna_engine_lookup_address = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<dna_addressbook_entry_t>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<dna_addressbook_entry_t>)>('dna_engine_lookup_address');

  int dna_engine_lookup_address(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> address,
    Pointer<Utf8> network,
    Pointer<dna_addressbook_entry_t> entry_out,
  ) {
    return _dna_engine_lookup_address(engine, address, network, entry_out);
  }

  late final _dna_engine_increment_address_usage = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Int32),
      int Function(
          Pointer<dna_engine_t>, int)>('dna_engine_increment_address_usage');

  int dna_engine_increment_address_usage(
    Pointer<dna_engine_t> engine,
    int id,
  ) {
    return _dna_engine_increment_address_usage(engine, id);
  }

  late final _dna_engine_sync_addressbook_to_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_sync_addressbook_to_dht');

  int dna_engine_sync_addressbook_to_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_sync_addressbook_to_dht(engine, callback, user_data);
  }

  late final _dna_engine_sync_addressbook_from_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_sync_addressbook_from_dht');

  int dna_engine_sync_addressbook_from_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_sync_addressbook_from_dht(engine, callback, user_data);
  }

  // Sync contacts from DHT (v0.6.10+)
  late final _dna_engine_sync_contacts_from_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_sync_contacts_from_dht');

  int dna_engine_sync_contacts_from_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_sync_contacts_from_dht(engine, callback, user_data);
  }

  // Restore groups from DHT grouplist (v0.6.10+)
  late final _dna_engine_restore_groups_from_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_restore_groups_from_dht');

  int dna_engine_restore_groups_from_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_restore_groups_from_dht(engine, callback, user_data);
  }

  late final _dna_engine_sync_groups_to_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_sync_groups_to_dht');

  int dna_engine_sync_groups_to_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_sync_groups_to_dht(engine, callback, user_data);
  }

  /// Sync groups FROM DHT (pull latest metadata)
  late final _dna_engine_sync_groups = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_sync_groups');

  int dna_engine_sync_groups(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_sync_groups(engine, callback, user_data);
  }

  late final _dna_free_addressbook_entries = _lib.lookupFunction<
      Void Function(Pointer<dna_addressbook_entry_t>, Int32),
      void Function(
          Pointer<dna_addressbook_entry_t>, int)>('dna_free_addressbook_entries');

  void dna_free_addressbook_entries(
      Pointer<dna_addressbook_entry_t> entries, int count) {
    _dna_free_addressbook_entries(entries, count);
  }

  // ==========================================================================
  // SIGNING API (for QR Auth)
  // ==========================================================================

  /// Sign data with the loaded identity's Dilithium5 key
  late final _dna_engine_sign_data = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Uint8>, Size,
          Pointer<Uint8>, Pointer<Size>),
      int Function(Pointer<dna_engine_t>, Pointer<Uint8>, int, Pointer<Uint8>,
          Pointer<Size>)>('dna_engine_sign_data');

  int dna_engine_sign_data(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> data,
    int dataLen,
    Pointer<Uint8> signatureOut,
    Pointer<Size> sigLenOut,
  ) {
    return _dna_engine_sign_data(engine, data, dataLen, signatureOut, sigLenOut);
  }

  /// Get the loaded identity's Dilithium5 signing public key
  late final _dna_engine_get_signing_public_key = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Uint8>, Size),
      int Function(Pointer<dna_engine_t>, Pointer<Uint8>, int)>(
      'dna_engine_get_signing_public_key');

  int dna_engine_get_signing_public_key(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> pubkeyOut,
    int pubkeyOutLen,
  ) {
    return _dna_engine_get_signing_public_key(engine, pubkeyOut, pubkeyOutLen);
  }

  // Feed v2 API removed - replaced by Channels system
  // (dna_engine_feed_* function lookups and dna_free_feed_* all removed)

  // ===========================================================================
  // CHANNEL API (RSS-like public channels via DHT)
  // ===========================================================================

  // --- Channel CRUD ---

  late final _dna_engine_channel_create = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Bool, Pointer<DnaChannelCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          bool, Pointer<DnaChannelCb>, Pointer<Void>)>(
      'dna_engine_channel_create');

  int dna_engine_channel_create(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> name,
    Pointer<Utf8> description,
    bool isPublic,
    Pointer<DnaChannelCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_create(
        engine, name, description, isPublic, callback, userData);
  }

  late final _dna_engine_channel_get = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaChannelCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaChannelCb>, Pointer<Void>)>('dna_engine_channel_get');

  int dna_engine_channel_get(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> uuid,
    Pointer<DnaChannelCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_get(engine, uuid, callback, userData);
  }

  // channel_get_batch
  late final _dna_engine_channel_get_batch = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Pointer<Utf8>>, Int32,
          Pointer<DnaChannelsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Pointer<Utf8>>, int,
          Pointer<DnaChannelsCb>, Pointer<Void>)>(
      'dna_engine_channel_get_batch');

  int dna_engine_channel_get_batch(
    Pointer<dna_engine_t> engine,
    Pointer<Pointer<Utf8>> uuids,
    int count,
    Pointer<DnaChannelsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_get_batch(engine, uuids, count, callback, userData);
  }

  late final _dna_engine_channel_delete = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>(
      'dna_engine_channel_delete');

  int dna_engine_channel_delete(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> uuid,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_delete(engine, uuid, callback, userData);
  }

  late final _dna_engine_channel_discover = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Int32,
          Pointer<DnaChannelsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int,
          Pointer<DnaChannelsCb>, Pointer<Void>)>(
      'dna_engine_channel_discover');

  int dna_engine_channel_discover(
    Pointer<dna_engine_t> engine,
    int daysBack,
    Pointer<DnaChannelsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_discover(engine, daysBack, callback, userData);
  }

  late final _dna_engine_channel_search = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Int32, Int32,
          Pointer<DnaChannelsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int, int,
          Pointer<DnaChannelsCb>, Pointer<Void>)>(
      'dna_engine_channel_search');

  int dna_engine_channel_search(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> query,
    int offset,
    int limit,
    Pointer<DnaChannelsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_search(engine, query, offset, limit, callback, userData);
  }

  // --- Channel posts ---

  late final _dna_engine_channel_post = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaChannelPostCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaChannelPostCb>, Pointer<Void>)>(
      'dna_engine_channel_post');

  int dna_engine_channel_post(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channelUuid,
    Pointer<Utf8> body,
    Pointer<DnaChannelPostCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_post(
        engine, channelUuid, body, callback, userData);
  }

  late final _dna_engine_channel_get_posts = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Int32,
          Pointer<DnaChannelPostsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int,
          Pointer<DnaChannelPostsCb>, Pointer<Void>)>(
      'dna_engine_channel_get_posts');

  int dna_engine_channel_get_posts(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channelUuid,
    int daysBack,
    Pointer<DnaChannelPostsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_get_posts(
        engine, channelUuid, daysBack, callback, userData);
  }

  // --- Channel subscriptions (synchronous) ---

  late final _dna_engine_channel_subscribe = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(
          Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_channel_subscribe');

  int dna_engine_channel_subscribe(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channelUuid,
  ) {
    return _dna_engine_channel_subscribe(engine, channelUuid);
  }

  late final _dna_engine_channel_unsubscribe = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(
          Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_channel_unsubscribe');

  int dna_engine_channel_unsubscribe(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channelUuid,
  ) {
    return _dna_engine_channel_unsubscribe(engine, channelUuid);
  }

  late final _dna_engine_channel_is_subscribed = _lib.lookupFunction<
      Bool Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      bool Function(Pointer<dna_engine_t>,
          Pointer<Utf8>)>('dna_engine_channel_is_subscribed');

  bool dna_engine_channel_is_subscribed(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channelUuid,
  ) {
    return _dna_engine_channel_is_subscribed(engine, channelUuid);
  }

  late final _dna_engine_channel_mark_read = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Utf8>),
      int Function(
          Pointer<dna_engine_t>, Pointer<Utf8>)>('dna_engine_channel_mark_read');

  int dna_engine_channel_mark_read(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> channelUuid,
  ) {
    return _dna_engine_channel_mark_read(engine, channelUuid);
  }

  // --- Channel subscriptions (async) ---

  late final _dna_engine_channel_get_subscriptions = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaChannelSubscriptionsCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaChannelSubscriptionsCb>,
          Pointer<Void>)>('dna_engine_channel_get_subscriptions');

  int dna_engine_channel_get_subscriptions(
    Pointer<dna_engine_t> engine,
    Pointer<DnaChannelSubscriptionsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_get_subscriptions(engine, callback, userData);
  }

  late final _dna_engine_channel_sync_subs_to_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_channel_sync_subs_to_dht');

  int dna_engine_channel_sync_subs_to_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_sync_subs_to_dht(engine, callback, userData);
  }

  late final _dna_engine_channel_sync_subs_from_dht = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_channel_sync_subs_from_dht');

  int dna_engine_channel_sync_subs_from_dht(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_channel_sync_subs_from_dht(engine, callback, userData);
  }

  // ===========================================================================
  // CHANNEL MEMORY CLEANUP
  // ===========================================================================

  late final _dna_free_channel_info = _lib.lookupFunction<
      Void Function(Pointer<dna_channel_info_t>),
      void Function(Pointer<dna_channel_info_t>)>('dna_free_channel_info');

  void dna_free_channel_info(Pointer<dna_channel_info_t> channel) {
    _dna_free_channel_info(channel);
  }

  late final _dna_free_channel_infos = _lib.lookupFunction<
      Void Function(Pointer<dna_channel_info_t>, Int32),
      void Function(
          Pointer<dna_channel_info_t>, int)>('dna_free_channel_infos');

  void dna_free_channel_infos(Pointer<dna_channel_info_t> channels, int count) {
    _dna_free_channel_infos(channels, count);
  }

  late final _dna_free_channel_post = _lib.lookupFunction<
      Void Function(Pointer<dna_channel_post_info_t>),
      void Function(Pointer<dna_channel_post_info_t>)>('dna_free_channel_post');

  void dna_free_channel_post(Pointer<dna_channel_post_info_t> post) {
    _dna_free_channel_post(post);
  }

  late final _dna_free_channel_posts = _lib.lookupFunction<
      Void Function(Pointer<dna_channel_post_info_t>, Int32),
      void Function(
          Pointer<dna_channel_post_info_t>, int)>('dna_free_channel_posts');

  void dna_free_channel_posts(
      Pointer<dna_channel_post_info_t> posts, int count) {
    _dna_free_channel_posts(posts, count);
  }

  late final _dna_free_channel_subscriptions = _lib.lookupFunction<
      Void Function(Pointer<dna_channel_subscription_info_t>, Int32),
      void Function(Pointer<dna_channel_subscription_info_t>,
          int)>('dna_free_channel_subscriptions');

  void dna_free_channel_subscriptions(
      Pointer<dna_channel_subscription_info_t> subscriptions, int count) {
    _dna_free_channel_subscriptions(subscriptions, count);
  }

  // ===========================================================================
  // WALL API
  // ===========================================================================

  late final _dna_engine_wall_post = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaWallPostCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaWallPostCb>,
          Pointer<Void>)>('dna_engine_wall_post');

  int dna_engine_wall_post(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> text,
    Pointer<DnaWallPostCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_post(engine, text, callback, userData);
  }

  late final _dna_engine_wall_delete = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaCompletionCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_wall_delete');

  int dna_engine_wall_delete(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_delete(engine, postUuid, callback, userData);
  }

  late final _dna_engine_wall_load = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaWallPostsCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallPostsCb>, Pointer<Void>)>('dna_engine_wall_load');

  int dna_engine_wall_load(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaWallPostsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_load(engine, fingerprint, callback, userData);
  }

  late final _dna_engine_wall_timeline = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<DnaWallPostsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaWallPostsCb>,
          Pointer<Void>)>('dna_engine_wall_timeline');

  int dna_engine_wall_timeline(
    Pointer<dna_engine_t> engine,
    Pointer<DnaWallPostsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_timeline(engine, callback, userData);
  }

  late final _dna_engine_wall_timeline_cached = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaWallPostsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<DnaWallPostsCb>,
          Pointer<Void>)>('dna_engine_wall_timeline_cached');

  int dna_engine_wall_timeline_cached(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<DnaWallPostsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_timeline_cached(engine, fingerprint, callback, userData);
  }

  late final _dna_free_wall_posts = _lib.lookupFunction<
      Void Function(Pointer<dna_wall_post_info_t>, Int32),
      void Function(
          Pointer<dna_wall_post_info_t>, int)>('dna_free_wall_posts');

  void dna_free_wall_posts(
      Pointer<dna_wall_post_info_t> posts, int count) {
    _dna_free_wall_posts(posts, count);
  }

  // ── Wall: Post with image (v0.7.0+) ──

  late final _dna_engine_wall_post_with_image = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaWallPostCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaWallPostCb>, Pointer<Void>)>(
      'dna_engine_wall_post_with_image');

  int dna_engine_wall_post_with_image(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> text,
    Pointer<Utf8> imageJson,
    Pointer<DnaWallPostCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_post_with_image(
        engine, text, imageJson, callback, userData);
  }

  // ── Wall Boost (v0.9.71+) ──

  late final _dna_engine_wall_boost_post = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallPostCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallPostCb>, Pointer<Void>)>(
      'dna_engine_wall_boost_post');

  int dna_engine_wall_boost_post(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> text,
    Pointer<DnaWallPostCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_boost_post(engine, text, callback, userData);
  }

  late final _dna_engine_wall_boost_post_with_image = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaWallPostCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaWallPostCb>, Pointer<Void>)>(
      'dna_engine_wall_boost_post_with_image');

  int dna_engine_wall_boost_post_with_image(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> text,
    Pointer<Utf8> imageJson,
    Pointer<DnaWallPostCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_boost_post_with_image(
        engine, text, imageJson, callback, userData);
  }

  late final _dna_engine_wall_boost_timeline = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaWallPostsCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaWallPostsCb>,
          Pointer<Void>)>('dna_engine_wall_boost_timeline');

  int dna_engine_wall_boost_timeline(
    Pointer<dna_engine_t> engine,
    Pointer<DnaWallPostsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_boost_timeline(engine, callback, userData);
  }

  // ── Wall Load Day (v0.9.141+) ──

  late final _dna_engine_wall_load_day = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaWallPostsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<DnaWallPostsCb>, Pointer<Void>)>('dna_engine_wall_load_day');

  int dna_engine_wall_load_day(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> fingerprint,
    Pointer<Utf8> dateStr,
    Pointer<DnaWallPostsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_load_day(engine, fingerprint, dateStr, callback, userData);
  }

  // ── Wall Comments (v0.7.0+) ──

  late final _dna_engine_wall_add_comment = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<DnaWallCommentCb>, Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<DnaWallCommentCb>,
          Pointer<Void>)>('dna_engine_wall_add_comment');

  int dna_engine_wall_add_comment(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<Utf8> parentCommentUuid,
    Pointer<Utf8> body,
    Pointer<DnaWallCommentCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_add_comment(
        engine, postUuid, parentCommentUuid, body, callback, userData);
  }

  late final _dna_engine_wall_add_tip_comment = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<Utf8>, Pointer<DnaWallCommentCb>, Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<DnaWallCommentCb>,
          Pointer<Void>)>('dna_engine_wall_add_tip_comment');

  int dna_engine_wall_add_tip_comment(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<Utf8> body,
    Pointer<DnaWallCommentCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_add_tip_comment(
        engine, postUuid, body, callback, userData);
  }

  late final _dna_engine_wall_get_comments = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallCommentsCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallCommentsCb>, Pointer<Void>)>(
      'dna_engine_wall_get_comments');

  int dna_engine_wall_get_comments(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<DnaWallCommentsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_get_comments(
        engine, postUuid, callback, userData);
  }

  late final _dna_free_wall_comments = _lib.lookupFunction<
      Void Function(Pointer<dna_wall_comment_info_t>, Int32),
      void Function(
          Pointer<dna_wall_comment_info_t>, int)>('dna_free_wall_comments');

  void dna_free_wall_comments(
      Pointer<dna_wall_comment_info_t> comments, int count) {
    _dna_free_wall_comments(comments, count);
  }

  // ── Wall Likes (v0.9.52+) ──

  late final _dna_engine_wall_like = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallLikesCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallLikesCb>, Pointer<Void>)>('dna_engine_wall_like');

  int dna_engine_wall_like(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<DnaWallLikesCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_like(engine, postUuid, callback, userData);
  }

  late final _dna_engine_wall_get_likes = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallLikesCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallLikesCb>, Pointer<Void>)>(
      'dna_engine_wall_get_likes');

  int dna_engine_wall_get_likes(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<DnaWallLikesCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_get_likes(engine, postUuid, callback, userData);
  }

  late final _dna_free_wall_likes = _lib.lookupFunction<
      Void Function(Pointer<dna_wall_like_info_t>, Int32),
      void Function(
          Pointer<dna_wall_like_info_t>, int)>('dna_free_wall_likes');

  void dna_free_wall_likes(
      Pointer<dna_wall_like_info_t> likes, int count) {
    _dna_free_wall_likes(likes, count);
  }

  // Wall Engagement Batch (v0.9.123+)
  late final _dna_engine_wall_get_engagement = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Pointer<Utf8>>, Int32,
          Pointer<DnaWallEngagementCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Pointer<Utf8>>, int,
          Pointer<DnaWallEngagementCb>, Pointer<Void>)>(
      'dna_engine_wall_get_engagement');

  int dna_engine_wall_get_engagement(
    Pointer<dna_engine_t> engine,
    Pointer<Pointer<Utf8>> postUuids,
    int postCount,
    Pointer<DnaWallEngagementCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_get_engagement(
        engine, postUuids, postCount, callback, userData);
  }

  // Wall Engagement Batch — cache-only variant (v0.10.7+)
  late final _dna_engine_wall_get_engagement_cached = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Pointer<Utf8>>, Int32,
          Pointer<DnaWallEngagementCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Pointer<Utf8>>, int,
          Pointer<DnaWallEngagementCb>, Pointer<Void>)>(
      'dna_engine_wall_get_engagement_cached');

  int dna_engine_wall_get_engagement_cached(
    Pointer<dna_engine_t> engine,
    Pointer<Pointer<Utf8>> postUuids,
    int postCount,
    Pointer<DnaWallEngagementCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_get_engagement_cached(
        engine, postUuids, postCount, callback, userData);
  }

  late final _dna_free_wall_engagement = _lib.lookupFunction<
      Void Function(Pointer<dna_wall_engagement_t>, Int32),
      void Function(
          Pointer<dna_wall_engagement_t>, int)>('dna_free_wall_engagement');

  void dna_free_wall_engagement(
      Pointer<dna_wall_engagement_t> engagements, int count) {
    _dna_free_wall_engagement(engagements, count);
  }

  // ── Wall Image Fetch (v0.9.142+) ──

  late final _dna_engine_wall_get_image = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallImageCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>,
          Pointer<DnaWallImageCb>, Pointer<Void>)>(
      'dna_engine_wall_get_image');

  int dna_engine_wall_get_image(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> postUuid,
    Pointer<DnaWallImageCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_wall_get_image(
        engine, postUuid, callback, userData);
  }

  // ===========================================================================
  // MEDIA API (v0.9.146+)
  // ===========================================================================

  late final _dna_engine_media_upload = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Uint8>, Uint64,
          Pointer<Uint8>, Uint8, Bool, Uint32, Uint32,
          Pointer<DnaMediaUploadCb>, Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>, Pointer<Uint8>, int,
          Pointer<Uint8>, int, bool, int, int,
          Pointer<DnaMediaUploadCb>, Pointer<Void>)>(
      'dna_engine_media_upload');

  int dna_engine_media_upload(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> data,
    int dataLen,
    Pointer<Uint8> contentHash,
    int mediaType,
    bool encrypted,
    int ttl,
    int startChunk,
    Pointer<DnaMediaUploadCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_media_upload(
        engine, data, dataLen, contentHash, mediaType, encrypted, ttl,
        startChunk, callback, userData);
  }

  late final _dna_engine_media_download = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Uint8>,
          Pointer<DnaMediaDownloadCb>, Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>, Pointer<Uint8>,
          Pointer<DnaMediaDownloadCb>, Pointer<Void>)>(
      'dna_engine_media_download');

  int dna_engine_media_download(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> contentHash,
    Pointer<DnaMediaDownloadCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_media_download(
        engine, contentHash, callback, userData);
  }

  late final _dna_engine_media_exists = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>, Pointer<Uint8>,
          Pointer<DnaMediaExistsCb>, Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>, Pointer<Uint8>,
          Pointer<DnaMediaExistsCb>, Pointer<Void>)>(
      'dna_engine_media_exists');

  int dna_engine_media_exists(
    Pointer<dna_engine_t> engine,
    Pointer<Uint8> contentHash,
    Pointer<DnaMediaExistsCb> callback,
    Pointer<Void> userData,
  ) {
    return _dna_engine_media_exists(
        engine, contentHash, callback, userData);
  }

  // ===========================================================================
  // DNAC (Digital Cash) Functions
  // ===========================================================================

  late final _dna_engine_dnac_get_balance = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaDnacBalanceCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaDnacBalanceCb>,
          Pointer<Void>)>('dna_engine_dnac_get_balance');

  int dna_engine_dnac_get_balance(
    Pointer<dna_engine_t> engine,
    Pointer<DnaDnacBalanceCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dnac_get_balance(engine, callback, user_data);
  }

  late final _dna_engine_dnac_send = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Uint64,
          Pointer<Utf8>, Pointer<Uint8>, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, int,
          Pointer<Utf8>, Pointer<Uint8>, Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_dnac_send');

  int dna_engine_dnac_send(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> recipient_fingerprint,
    int amount,
    Pointer<Utf8> memo,
    Pointer<Uint8> token_id,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dnac_send(engine, recipient_fingerprint, amount, memo, token_id, callback, user_data);
  }

  // Phase 13 / Task 13.5 — fetch the witness receipt of the most recent
  // dnac_send. Synchronous; call from Dart after the send completion
  // future resolves successfully.
  late final _dna_engine_dnac_last_send_receipt = _lib.lookupFunction<
      Int32 Function(Pointer<dna_engine_t>, Pointer<Uint64>,
          Pointer<Uint32>, Pointer<Uint8>),
      int Function(Pointer<dna_engine_t>, Pointer<Uint64>,
          Pointer<Uint32>, Pointer<Uint8>)>('dna_engine_dnac_last_send_receipt');

  int dna_engine_dnac_last_send_receipt(
    Pointer<dna_engine_t> engine,
    Pointer<Uint64> blockHeightOut,
    Pointer<Uint32> txIndexOut,
    Pointer<Uint8> txHashOut,
  ) {
    return _dna_engine_dnac_last_send_receipt(engine, blockHeightOut, txIndexOut, txHashOut);
  }

  late final _dna_engine_dnac_sync = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaCompletionCb>,
          Pointer<Void>)>('dna_engine_dnac_sync');

  int dna_engine_dnac_sync(
    Pointer<dna_engine_t> engine,
    Pointer<DnaCompletionCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dnac_sync(engine, callback, user_data);
  }

  late final _dna_engine_dnac_get_history = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaDnacHistoryCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaDnacHistoryCb>,
          Pointer<Void>)>('dna_engine_dnac_get_history');

  int dna_engine_dnac_get_history(
    Pointer<dna_engine_t> engine,
    Pointer<DnaDnacHistoryCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dnac_get_history(engine, callback, user_data);
  }

  late final _dna_engine_dnac_get_utxos = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaDnacUtxosCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaDnacUtxosCb>,
          Pointer<Void>)>('dna_engine_dnac_get_utxos');

  int dna_engine_dnac_get_utxos(
    Pointer<dna_engine_t> engine,
    Pointer<DnaDnacUtxosCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dnac_get_utxos(engine, callback, user_data);
  }

  late final _dna_engine_dnac_estimate_fee = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Uint64, Pointer<DnaDnacFeeCb>,
          Pointer<Void>),
      int Function(Pointer<dna_engine_t>, int, Pointer<DnaDnacFeeCb>,
          Pointer<Void>)>('dna_engine_dnac_estimate_fee');

  int dna_engine_dnac_estimate_fee(
    Pointer<dna_engine_t> engine,
    int amount,
    Pointer<DnaDnacFeeCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_dnac_estimate_fee(engine, amount, callback, user_data);
  }

  late final _dna_engine_dnac_free_history = _lib.lookupFunction<
      Void Function(Pointer<dna_dnac_history_t>, Int32),
      void Function(Pointer<dna_dnac_history_t>, int)>('dna_engine_dnac_free_history');

  void dna_engine_dnac_free_history(Pointer<dna_dnac_history_t> history, int count) {
    _dna_engine_dnac_free_history(history, count);
  }

  late final _dna_engine_dnac_free_utxos = _lib.lookupFunction<
      Void Function(Pointer<dna_dnac_utxo_t>, Int32),
      void Function(Pointer<dna_dnac_utxo_t>, int)>('dna_engine_dnac_free_utxos');

  void dna_engine_dnac_free_utxos(Pointer<dna_dnac_utxo_t> utxos, int count) {
    _dna_engine_dnac_free_utxos(utxos, count);
  }

  // DNAC Multi-Token Functions

  late final _dna_engine_dnac_token_list = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<DnaDnacTokenListCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<DnaDnacTokenListCb>, Pointer<Void>)>('dna_engine_dnac_token_list');

  int dna_engine_dnac_token_list(Pointer<dna_engine_t> engine, Pointer<DnaDnacTokenListCb> callback, Pointer<Void> user_data) {
    return _dna_engine_dnac_token_list(engine, callback, user_data);
  }

  late final _dna_engine_dnac_token_create = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>, Uint8, Uint64, Pointer<DnaCompletionCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Utf8>, Pointer<Utf8>, int, int, Pointer<DnaCompletionCb>, Pointer<Void>)>('dna_engine_dnac_token_create');

  int dna_engine_dnac_token_create(Pointer<dna_engine_t> engine, Pointer<Utf8> name, Pointer<Utf8> symbol, int decimals, int supply, Pointer<DnaCompletionCb> callback, Pointer<Void> user_data) {
    return _dna_engine_dnac_token_create(engine, name, symbol, decimals, supply, callback, user_data);
  }

  late final _dna_engine_dnac_token_balance = _lib.lookupFunction<
      Uint64 Function(Pointer<dna_engine_t>, Pointer<Uint8>, Pointer<DnaDnacBalanceCb>, Pointer<Void>),
      int Function(Pointer<dna_engine_t>, Pointer<Uint8>, Pointer<DnaDnacBalanceCb>, Pointer<Void>)>('dna_engine_dnac_token_balance');

  int dna_engine_dnac_token_balance(Pointer<dna_engine_t> engine, Pointer<Uint8> token_id, Pointer<DnaDnacBalanceCb> callback, Pointer<Void> user_data) {
    return _dna_engine_dnac_token_balance(engine, token_id, callback, user_data);
  }

  late final _dna_engine_dnac_free_tokens = _lib.lookupFunction<
      Void Function(Pointer<dna_dnac_token_t>, Int32),
      void Function(Pointer<dna_dnac_token_t>, int)>('dna_engine_dnac_free_tokens');

  void dna_engine_dnac_free_tokens(Pointer<dna_dnac_token_t> tokens, int count) {
    _dna_engine_dnac_free_tokens(tokens, count);
  }
}

// =============================================================================
// DNAC (DIGITAL CASH) STRUCTS
// =============================================================================

/// DNAC balance information
final class dna_dnac_balance_t extends Struct {
  @Uint64()
  external int confirmed;

  @Uint64()
  external int pending;

  @Uint64()
  external int locked;

  @Int32()
  external int utxo_count;
}

/// DNAC transaction history entry
final class dna_dnac_history_t extends Struct {
  @Array(64)
  external Array<Uint8> tx_hash;

  @Int32()
  external int type;

  @Array(129)
  external Array<Char> counterparty;

  // 3 bytes padding to align int64_t
  @Array(3)
  external Array<Uint8> _padding1;

  @Int64()
  external int amount_delta;

  @Uint64()
  external int fee;

  @Uint64()
  external int timestamp;

  @Array(256)
  external Array<Char> memo;

  @Array(64)
  external Array<Uint8> token_id;
}

/// DNAC UTXO entry
final class dna_dnac_utxo_t extends Struct {
  @Array(64)
  external Array<Uint8> tx_hash;

  @Uint32()
  external int output_index;

  // 4 bytes padding to align uint64_t
  @Array(4)
  external Array<Uint8> _padding1;

  @Uint64()
  external int amount;

  @Int32()
  external int status;

  // 4 bytes padding to align uint64_t
  @Array(4)
  external Array<Uint8> _padding2;

  @Uint64()
  external int received_at;
}

/// DNAC token information
final class dna_dnac_token_t extends Struct {
  @Array(64)
  external Array<Uint8> token_id;
  @Array(33)
  external Array<Char> name;
  @Array(9)
  external Array<Char> symbol;
  @Uint8()
  external int decimals;
  @Array(5)
  external Array<Uint8> _padding1;
  @Int64()
  external int supply;
  @Array(129)
  external Array<Char> creator_fp;
  @Array(7)
  external Array<Uint8> _padding2;
}

// =============================================================================
// DNAC CALLBACK TYPES
// =============================================================================

/// DNAC balance callback - Native
typedef DnaDnacBalanceCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_dnac_balance_t> balance,
  Pointer<Void> user_data,
);
typedef DnaDnacBalanceCb = NativeFunction<DnaDnacBalanceCbNative>;

/// DNAC history callback - Native
typedef DnaDnacHistoryCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_dnac_history_t> history,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaDnacHistoryCb = NativeFunction<DnaDnacHistoryCbNative>;

/// DNAC UTXOs callback - Native
typedef DnaDnacUtxosCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Pointer<dna_dnac_utxo_t> utxos,
  Int32 count,
  Pointer<Void> user_data,
);
typedef DnaDnacUtxosCb = NativeFunction<DnaDnacUtxosCbNative>;

/// DNAC fee callback - Native
typedef DnaDnacFeeCbNative = Void Function(
  Uint64 request_id,
  Int32 error,
  Uint64 fee,
  Pointer<Void> user_data,
);
typedef DnaDnacFeeCb = NativeFunction<DnaDnacFeeCbNative>;

/// DNAC token list callback
typedef DnaDnacTokenListCbNative = Void Function(Uint64 request_id, Int32 error, Pointer<dna_dnac_token_t> tokens, Int32 count, Pointer<Void> user_data);
typedef DnaDnacTokenListCb = NativeFunction<DnaDnacTokenListCbNative>;

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
