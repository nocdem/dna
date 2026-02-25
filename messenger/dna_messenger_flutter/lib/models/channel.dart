/// Channel data models for the RSS-like channel system.

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
}
