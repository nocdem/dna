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

  // Auth fields
  final String? appName;
  final String? domain;
  final String? challenge;
  final List<String>? scopes;
  final String? callbackUrl;

  // Detection hints for plain text
  final bool looksLikeUrl;
  final bool looksLikeFingerprint;

  const QrPayload({
    required this.type,
    required this.rawContent,
    this.fingerprint,
    this.displayName,
    this.appName,
    this.domain,
    this.challenge,
    this.scopes,
    this.callbackUrl,
    this.looksLikeUrl = false,
    this.looksLikeFingerprint = false,
  });

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
      domain: params['domain'] ?? params['service'],
      challenge: params['challenge'] ?? params['nonce'],
      scopes: params['scopes']?.split(','),
      callbackUrl: params['callback'] ?? params['callback_url'],
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

  if (type == 'auth' || type == 'login') {
    final scopesRaw = json['scopes'];
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
      domain: json['domain'] as String? ?? json['service'] as String?,
      challenge: json['challenge'] as String? ?? json['nonce'] as String?,
      scopes: scopes,
      callbackUrl: json['callback'] as String? ?? json['callback_url'] as String?,
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
