/// QR Code payload parser for DNA Messenger
///
/// Parses QR codes and determines the appropriate action:
/// - Contact onboarding (dna://contact, dna://onboard, JSON)
/// - Authorization (dna://auth, dna://login, JSON)
/// - Plain text/unknown content
library;

import 'dart:convert';

/// Type of QR payload detected
enum QrPayloadType {
  contact,
  auth,
  plainText,
}

/// Parsed QR payload with extracted data
class QrPayload {
  final QrPayloadType type;
  final String rawContent;

  // Contact fields
  final String? fingerprint;
  final String? displayName;

  // Auth fields (per QR-core auth spec)
  final String? appName;
  final String? origin;       // Domain/origin of the requesting service
  final String? sessionId;    // Session identifier from server
  final String? nonce;        // Challenge nonce for replay protection
  final int? expiresAt;       // Unix epoch seconds when request expires
  final List<String>? scopes; // Requested permissions (optional)
  final String? callbackUrl;  // HTTPS callback URL for auth response

  // Legacy aliases (for backwards compatibility)
  String? get domain => origin;
  String? get challenge => nonce;

  // Detection hints for plain text
  final bool looksLikeUrl;
  final bool looksLikeFingerprint;

  const QrPayload({
    required this.type,
    required this.rawContent,
    this.fingerprint,
    this.displayName,
    this.appName,
    this.origin,
    this.sessionId,
    this.nonce,
    this.expiresAt,
    this.scopes,
    this.callbackUrl,
    this.looksLikeUrl = false,
    this.looksLikeFingerprint = false,
  });

  /// Check if this auth payload has the minimum required fields for signing
  bool get hasRequiredAuthFields =>
      origin != null &&
      sessionId != null &&
      nonce != null &&
      callbackUrl != null;

  /// Check if the auth request has expired
  bool get isExpired {
    if (expiresAt == null) return false;
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return now > expiresAt!;
  }

  @override
  String toString() => 'QrPayload(type: $type, raw: ${rawContent.length > 50 ? '${rawContent.substring(0, 50)}...' : rawContent})';
}

/// Parse a QR code payload and determine its type and contents
QrPayload parseQrPayload(String content) {
  final trimmed = content.trim();

  // Try DNA URI scheme first
  if (trimmed.toLowerCase().startsWith('dna://')) {
    return _parseDnaUri(trimmed);
  }

  // Try JSON parsing
  if (trimmed.startsWith('{')) {
    try {
      final json = jsonDecode(trimmed) as Map<String, dynamic>;
      return _parseJsonPayload(trimmed, json);
    } catch (_) {
      // Not valid JSON, fall through to plain text
    }
  }

  // Plain text - detect if it looks like a URL or fingerprint
  return QrPayload(
    type: QrPayloadType.plainText,
    rawContent: trimmed,
    looksLikeUrl: _looksLikeUrl(trimmed),
    looksLikeFingerprint: _isValidFingerprint(trimmed),
  );
}

/// Parse dna:// URI scheme
QrPayload _parseDnaUri(String uri) {
  final parsed = Uri.tryParse(uri);
  if (parsed == null) {
    return QrPayload(
      type: QrPayloadType.plainText,
      rawContent: uri,
      looksLikeUrl: false,
      looksLikeFingerprint: false,
    );
  }

  final host = parsed.host.toLowerCase();
  final params = parsed.queryParameters;

  // Contact onboarding: dna://contact or dna://onboard
  if (host == 'contact' || host == 'onboard') {
    final fp = params['fp'] ?? params['fingerprint'];
    final name = params['name'] ?? params['displayName'] ?? params['display_name'];

    if (fp != null && _isValidFingerprint(fp)) {
      return QrPayload(
        type: QrPayloadType.contact,
        rawContent: uri,
        fingerprint: fp.toLowerCase(),
        displayName: name,
      );
    }
  }

  // Authorization: dna://auth or dna://login
  if (host == 'auth' || host == 'login') {
    return QrPayload(
      type: QrPayloadType.auth,
      rawContent: uri,
      appName: params['app'] ?? params['appName'] ?? params['app_name'],
      origin: params['origin'] ?? params['domain'] ?? params['service'],
      sessionId: params['session_id'] ?? params['sessionId'] ?? params['session'],
      nonce: params['nonce'] ?? params['challenge'],
      expiresAt: _parseExpiresAt(params['expires_at'] ?? params['expiresAt'] ?? params['expires']),
      scopes: params['scopes']?.split(',') ?? params['scope']?.split(','),
      callbackUrl: params['callback'] ?? params['callback_url'] ?? params['callbackUrl'],
    );
  }

  // Unknown dna:// URI - treat as plain text
  return QrPayload(
    type: QrPayloadType.plainText,
    rawContent: uri,
    looksLikeUrl: true,
    looksLikeFingerprint: false,
  );
}

/// Parse JSON payload
QrPayload _parseJsonPayload(String raw, Map<String, dynamic> json) {
  final type = (json['type'] as String?)?.toLowerCase();

  if (type == 'contact' || type == 'onboard') {
    final fp = json['fingerprint'] as String? ?? json['fp'] as String?;
    final name = json['name'] as String? ?? json['displayName'] as String? ?? json['display_name'] as String?;

    if (fp != null && _isValidFingerprint(fp)) {
      return QrPayload(
        type: QrPayloadType.contact,
        rawContent: raw,
        fingerprint: fp.toLowerCase(),
        displayName: name,
      );
    }
  }

  if (type == 'auth' || type == 'login' || type == 'dna.auth.request') {
    final scopesRaw = json['scopes'] ?? json['scope'] ?? json['requested_scope'];
    List<String>? scopes;
    if (scopesRaw is List) {
      scopes = scopesRaw.cast<String>();
    } else if (scopesRaw is String) {
      scopes = scopesRaw.split(',');
    }

    return QrPayload(
      type: QrPayloadType.auth,
      rawContent: raw,
      appName: json['app'] as String? ?? json['appName'] as String? ?? json['app_name'] as String?,
      origin: json['origin'] as String? ?? json['domain'] as String? ?? json['service'] as String?,
      sessionId: json['session_id'] as String? ?? json['sessionId'] as String? ?? json['session'] as String?,
      nonce: json['nonce'] as String? ?? json['challenge'] as String?,
      expiresAt: _parseExpiresAtDynamic(json['expires_at'] ?? json['expiresAt'] ?? json['expires']),
      scopes: scopes,
      callbackUrl: json['callback'] as String? ?? json['callback_url'] as String? ?? json['callbackUrl'] as String?,
    );
  }

  // Unknown JSON type - treat as plain text
  return QrPayload(
    type: QrPayloadType.plainText,
    rawContent: raw,
    looksLikeUrl: false,
    looksLikeFingerprint: false,
  );
}

/// Parse expires_at from string (URI param)
int? _parseExpiresAt(String? value) {
  if (value == null) return null;
  return int.tryParse(value);
}

/// Parse expires_at from dynamic (JSON value - could be int or string)
int? _parseExpiresAtDynamic(dynamic value) {
  if (value == null) return null;
  if (value is int) return value;
  if (value is String) return int.tryParse(value);
  return null;
}

/// Check if string is a valid DNA fingerprint (128 hex characters)
bool _isValidFingerprint(String input) {
  if (input.length != 128) return false;
  return RegExp(r'^[0-9a-fA-F]+$').hasMatch(input);
}

/// Check if string looks like a URL
bool _looksLikeUrl(String input) {
  final lower = input.toLowerCase();
  return lower.startsWith('http://') ||
      lower.startsWith('https://') ||
      lower.startsWith('www.') ||
      RegExp(r'^[a-z0-9][-a-z0-9]*\.[a-z]{2,}', caseSensitive: false).hasMatch(input);
}
