// Channel data models for the RSS-like channel system.

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../ffi/dna_bindings.dart';

class Channel {
  final String uuid;
  final String name;
  final String description;
  final String creatorFingerprint;
  final DateTime createdAt;
  final bool isPublic;
  final bool deleted;
  final DateTime? deletedAt;
  final bool verified;

  Channel({
    required this.uuid,
    required this.name,
    required this.description,
    required this.creatorFingerprint,
    required this.createdAt,
    required this.isPublic,
    required this.deleted,
    this.deletedAt,
    this.verified = false,
  });

  factory Channel.fromNative(dna_channel_info_t native) {
    return Channel(
      uuid: native.channel_uuid.toDartString(37),
      name: native.name.toDartString(101),
      description: native.description != nullptr
          ? native.description.toDartString()
          : '',
      creatorFingerprint: native.creator_fingerprint.toDartString(129),
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
      isPublic: native.is_public,
      deleted: native.deleted,
      deletedAt: native.deleted_at > 0
          ? DateTime.fromMillisecondsSinceEpoch(native.deleted_at * 1000)
          : null,
      verified: native.verified,
    );
  }
}

class ChannelPost {
  final String uuid;
  final String channelUuid;
  final String authorFingerprint;
  final String body;
  final DateTime createdAt;
  final bool verified;

  ChannelPost({
    required this.uuid,
    required this.channelUuid,
    required this.authorFingerprint,
    required this.body,
    required this.createdAt,
    this.verified = false,
  });

  factory ChannelPost.fromNative(dna_channel_post_info_t native) {
    return ChannelPost(
      uuid: native.post_uuid.toDartString(37),
      channelUuid: native.channel_uuid.toDartString(37),
      authorFingerprint: native.author_fingerprint.toDartString(129),
      body: native.body != nullptr ? native.body.toDartString() : '',
      createdAt: DateTime.fromMillisecondsSinceEpoch(native.created_at * 1000),
      verified: native.verified,
    );
  }
}

class ChannelSubscription {
  final String channelUuid;
  final DateTime subscribedAt;
  final DateTime? lastSynced;
  final DateTime? lastReadAt;

  ChannelSubscription({
    required this.channelUuid,
    required this.subscribedAt,
    this.lastSynced,
    this.lastReadAt,
  });

  factory ChannelSubscription.fromNative(dna_channel_subscription_info_t native) {
    return ChannelSubscription(
      channelUuid: native.channel_uuid.toDartString(37),
      subscribedAt: DateTime.fromMillisecondsSinceEpoch(native.subscribed_at * 1000),
      lastSynced: native.last_synced > 0
          ? DateTime.fromMillisecondsSinceEpoch(native.last_synced * 1000)
          : null,
      lastReadAt: native.last_read_at > 0
          ? DateTime.fromMillisecondsSinceEpoch(native.last_read_at * 1000)
          : null,
    );
  }
}
