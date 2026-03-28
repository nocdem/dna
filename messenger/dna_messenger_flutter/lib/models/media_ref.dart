// MediaRef — reference to media stored on Nodus DHT.
// Sent inside messages instead of inline base64 data.

import 'dart:convert';

/// Reference to media stored on Nodus DHT.
/// Contains metadata + thumbnail for display, plus content hash for retrieval.
class MediaRef {
  /// 128-char hex string (SHA3-512 of uploaded data)
  final String contentHash;

  /// 0=image, 1=video, 2=audio
  final int mediaType;

  /// e.g. "image/jpeg", "video/mp4"
  final String mimeType;

  /// Size of uploaded data in bytes (after encryption if encrypted)
  final int size;

  /// Pixel width (0 for audio)
  final int width;

  /// Pixel height (0 for audio)
  final int height;

  /// Duration in seconds (0 for images)
  final int duration;

  /// Base64-encoded mini JPEG thumbnail (~10-20KB)
  final String thumbnail;

  /// Optional caption text
  final String? caption;

  /// Base64-encoded AES-256 key (null for wall/public media)
  final String? encryptionKey;

  const MediaRef({
    required this.contentHash,
    required this.mediaType,
    required this.mimeType,
    required this.size,
    this.width = 0,
    this.height = 0,
    this.duration = 0,
    required this.thumbnail,
    this.caption,
    this.encryptionKey,
  });

  /// Serialize to JSON map
  Map<String, dynamic> toJson() => {
        'type': 'media_ref',
        'content_hash': contentHash,
        'media_type': mediaType,
        'mime_type': mimeType,
        'size': size,
        'width': width,
        'height': height,
        'duration': duration,
        'thumbnail': thumbnail,
        if (caption != null && caption!.isNotEmpty) 'caption': caption,
        if (encryptionKey != null) 'encryption_key': encryptionKey,
      };

  /// Serialize to JSON string for embedding in a message
  String toMessageJson() => jsonEncode(toJson());

  /// Deserialize from JSON map. Returns null if type != 'media_ref'.
  static MediaRef? fromJson(Map<String, dynamic> json) {
    if (json['type'] != 'media_ref') return null;
    return MediaRef(
      contentHash: json['content_hash'] as String,
      mediaType: json['media_type'] as int,
      mimeType: json['mime_type'] as String? ?? 'application/octet-stream',
      size: json['size'] as int,
      width: json['width'] as int? ?? 0,
      height: json['height'] as int? ?? 0,
      duration: json['duration'] as int? ?? 0,
      thumbnail: json['thumbnail'] as String,
      caption: json['caption'] as String?,
      encryptionKey: json['encryption_key'] as String?,
    );
  }

  /// Deserialize from a JSON string. Returns null on parse error or wrong type.
  static MediaRef? fromMessageJson(String jsonStr) {
    try {
      final data = jsonDecode(jsonStr) as Map<String, dynamic>;
      return fromJson(data);
    } catch (_) {
      return null;
    }
  }

  bool get isEncrypted => encryptionKey != null;
  bool get isImage => mediaType == 0;
  bool get isVideo => mediaType == 1;
  bool get isAudio => mediaType == 2;
}
