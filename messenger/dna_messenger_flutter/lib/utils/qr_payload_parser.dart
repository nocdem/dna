// lib/utils/qr_payload_parser.dart
//
// v3: parse rp_id_hash + require presence in validateRpBinding()
library;

import 'dart:convert';

enum QrPayloadType {
  contact,
  auth,
  plainText,
}

class QrPayload {
  final QrPayloadType type;
  final String rawContent;

  final String? fingerprint;
  final String? displayName;

  final String? appName;

  final String? origin;

  final String? rpId;
  final String? rpName;

  // v3: base64(sha256(rp_id))
  final String? rpIdHash;

  final int? v;

  final String? sessionId;
  final String? nonce;
  final int? expiresAt;
  final List<String>? scopes;

  final String? callbackUrl;

  String? get domain => origin;
  String? get challenge => nonce;

  final bool looksLikeUrl;
  final bool looksLikeFingerprint;

  const QrPayload({
    required this.type,
    required this.rawContent,
    this.fingerprint,
    this.displayName,
    this.appName,
    this.origin,
    this.rpId,
    this.rpName,
    this.rpIdHash,
    this.v,
    this.sessionId,
    this.nonce,
    this.expiresAt,
    this.scopes,
    this.callbackUrl,
    this.looksLikeUrl = false,
    this.looksLikeFingerprint = false,
  });

  bool get hasRequiredAuthFields =>
      origin != null && sessionId != null && nonce != null && callbackUrl != null;

  Uri? get originUri => origin == null ? null : Uri.tryParse(origin!);
  Uri? get callbackUri => callbackUrl == null ? null : Uri.tryParse(callbackUrl!);

  bool get isExpired {
    if (expiresAt == null) return false;
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return now > expiresAt!;
  }

  @override
  String toString() => 'QrPayload(type: $type, raw: ${rawContent.length > 50 ? '${rawContent.substring(0, 50)}...' : rawContent})';
}

QrPayload parseQrPayload(String content) {
  final trimmed = content.trim();

  if (trimmed.toLowerCase().startsWith('dna://')) {
    return _parseDnaUri(trimmed);
  }

  if (trimmed.startsWith('{')) {
    try {
      final json = jsonDecode(trimmed) as Map<String, dynamic>;
      return _parseJsonPayload(trimmed, json);
    } catch (_) {}
  }

  return QrPayload(
    type: QrPayloadType.plainText,
    rawContent: trimmed,
    looksLikeUrl: _looksLikeUrl(trimmed),
    looksLikeFingerprint: _isValidFingerprint(trimmed),
  );
}

QrPayload _parseDnaUri(String uri) {
  final parsed = Uri.tryParse(uri);
  if (parsed == null) {
    return QrPayload(type: QrPayloadType.plainText, rawContent: uri);
  }

  final host = parsed.host.toLowerCase();
  final params = parsed.queryParameters;

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

  if (host == 'auth' || host == 'login') {
    return QrPayload(
      type: QrPayloadType.auth,
      rawContent: uri,
      v: _parseInt(params['v']),
      appName: params['app'] ?? params['appName'] ?? params['app_name'],
      origin: params['origin'] ?? params['domain'] ?? params['service'],
      rpId: params['rp_id'] ?? params['rpId'],
      rpName: params['rp_name'] ?? params['rpName'],
      rpIdHash: params['rp_id_hash'] ?? params['rpIdHash'],
      sessionId: params['session_id'] ?? params['sessionId'] ?? params['session'],
      nonce: params['nonce'] ?? params['challenge'],
      expiresAt: _parseExpiresAt(params['expires_at'] ?? params['expiresAt'] ?? params['expires']),
      scopes: _parseScopes(params['scopes'] ?? params['scope']),
      callbackUrl: params['callback'] ?? params['callback_url'] ?? params['callbackUrl'],
    );
  }

  return QrPayload(type: QrPayloadType.plainText, rawContent: uri, looksLikeUrl: true);
}

QrPayload _parseJsonPayload(String raw, Map<String, dynamic> json) {
  final type = (json['type'] as String?)?.toLowerCase();

  if (type == 'contact' || type == 'onboard') {
    final fp = json['fingerprint'] as String? ?? json['fp'] as String?;
    final name = json['name'] as String? ?? json['displayName'] as String? ?? json['display_name'] as String?;
    if (fp != null && _isValidFingerprint(fp)) {
      return QrPayload(type: QrPayloadType.contact, rawContent: raw, fingerprint: fp.toLowerCase(), displayName: name);
    }
  }

  if (type == 'auth' || type == 'login' || type == 'dna.auth.request') {
    final scopesRaw = json['scopes'] ?? json['scope'] ?? json['requested_scope'];
    List<String>? scopes;
    if (scopesRaw is List) {
      scopes = scopesRaw.cast<String>();
    } else if (scopesRaw is String) {
      scopes = _parseScopes(scopesRaw);
    }

    return QrPayload(
      type: QrPayloadType.auth,
      rawContent: raw,
      v: _parseInt(json['v']?.toString()),
      appName: json['app'] as String? ?? json['appName'] as String? ?? json['app_name'] as String?,
      origin: json['origin'] as String? ?? json['domain'] as String? ?? json['service'] as String?,
      rpId: json['rp_id'] as String? ?? json['rpId'] as String?,
      rpName: json['rp_name'] as String? ?? json['rpName'] as String?,
      rpIdHash: json['rp_id_hash'] as String? ?? json['rpIdHash'] as String?,
      sessionId: json['session_id'] as String? ?? json['sessionId'] as String? ?? json['session'] as String?,
      nonce: json['nonce'] as String? ?? json['challenge'] as String?,
      expiresAt: _parseExpiresAtDynamic(json['expires_at'] ?? json['expiresAt'] ?? json['expires']),
      scopes: scopes,
      callbackUrl: json['callback'] as String? ?? json['callback_url'] as String? ?? json['callbackUrl'] as String?,
    );
  }

  return QrPayload(type: QrPayloadType.plainText, rawContent: raw);
}

String? validateRpBinding(QrPayload p) {
  if (p.type != QrPayloadType.auth) return null;

  final pv = p.v ?? 1;
  if (pv <= 1) return null;

  if (p.rpId == null || p.rpId!.trim().isEmpty) {
    return 'Missing rp_id in QR payload (v2+)';
  }

  if (pv >= 3) {
    if (p.rpIdHash == null || p.rpIdHash!.trim().isEmpty) {
      return 'Missing rp_id_hash in QR payload (v3)';
    }
  }

  final originUri = p.originUri;
  final cbUri = p.callbackUri;

  if (originUri == null || originUri.host.isEmpty) return 'Invalid origin in QR payload';
  if (cbUri == null || cbUri.host.isEmpty) return 'Invalid callback URL in QR payload';
  if (cbUri.scheme.toLowerCase() != 'https') return 'Callback URL must use HTTPS';

  final rp = p.rpId!.toLowerCase().trim();
  final originHost = originUri.host.toLowerCase();
  final cbHost = cbUri.host.toLowerCase();

  if (!_hostMatchesRp(originHost, rp)) return 'Origin host does not match rp_id';
  if (!_hostMatchesRp(cbHost, rp)) return 'Callback host does not match rp_id';

  return null;
}

bool _hostMatchesRp(String host, String rpId) {
  if (host == rpId) return true;
  if (host.endsWith('.$rpId')) return true;
  return false;
}

int? _parseExpiresAt(String? value) => value == null ? null : int.tryParse(value);

int? _parseExpiresAtDynamic(dynamic value) {
  if (value == null) return null;
  if (value is int) return value;
  if (value is String) return int.tryParse(value);
  return null;
}

List<String>? _parseScopes(String? scopes) {
  if (scopes == null) return null;
  final parts = scopes.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
  return parts.isEmpty ? null : parts;
}

int? _parseInt(String? v) => v == null ? null : int.tryParse(v);

bool _isValidFingerprint(String input) =>
    input.length == 128 && RegExp(r'^[0-9a-fA-F]+$').hasMatch(input);

bool _looksLikeUrl(String input) {
  final lower = input.toLowerCase();
  return lower.startsWith('http://') ||
      lower.startsWith('https://') ||
      lower.startsWith('www.') ||
      RegExp(r'^[a-z0-9][-a-z0-9]*\.[a-z]{2,}', caseSensitive: false).hasMatch(input);
}
