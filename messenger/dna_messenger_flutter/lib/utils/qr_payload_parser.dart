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

  // v4: stateless token (v4.<b64url(payload)>.<b64url(sig)>)
  final String? st;

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
    this.st,
    this.v,
    this.sessionId,
    this.nonce,
    this.expiresAt,
    this.scopes,
    this.callbackUrl,
    this.looksLikeUrl = false,
    this.looksLikeFingerprint = false,
  });

  bool get hasRequiredAuthFields {
    final pv = v ?? 1;
    if (pv >= 4) {
      // v4: only st required (origin/nonce/etc come from decoded st)
      return st != null && st!.trim().isNotEmpty;
    }
    // v1-v3: require origin, session_id, nonce, callback
    return origin != null && sessionId != null && nonce != null && callbackUrl != null;
  }

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
      st: params['st'] ?? params['session_token'] ?? params['token'],
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
      st: json['st'] as String? ?? json['session_token'] as String? ?? json['token'] as String?,
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

  // v4: binding is inside st payload, skip host checks here
  if (pv >= 4) {
    if (p.st == null || p.st!.trim().isEmpty) {
      return 'Missing st token in QR payload (v4)';
    }
    return null;
  }

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

// ──────────────────────────────────────────────────────────────────────────
// SEC-03 defense-in-depth: strict validator for v3 auth payloads.
//
// Rejects malformed, oversized, or charset-violating payloads BEFORE they
// are signed or shown in the UI. Returns a stable `errorKey` that the UI
// layer maps to `AppLocalizations.invalidQrCode` for display.
// ──────────────────────────────────────────────────────────────────────────

/// Result of [validateAuthPayload]. `ok == true` means the payload passed
/// every strict check; `ok == false` means it was rejected and [errorKey]
/// holds a stable i18n key (e.g. `'invalidQrCode'`) for the UI to render.
class QrPayloadValidationResult {
  final bool ok;
  final String? errorKey;

  const QrPayloadValidationResult.success()
      : ok = true,
        errorKey = null;

  const QrPayloadValidationResult.failure(this.errorKey) : ok = false;
}

/// Allowed keys in a v3 auth payload. Anything else → reject.
const Set<String> _kAuthPayloadAllowedKeys = <String>{
  'expires_at',
  'issued_at',
  'nonce',
  'origin',
  'rp_id',
  'rp_id_hash',
  'session_id',
};

const Set<String> _kAuthPayloadRequiredKeys = <String>{
  'expires_at',
  'issued_at',
  'nonce',
  'origin',
  'session_id',
};

// Length bounds per field (SEC-03 D-03).
const int _kNonceMaxLen = 128;
const int _kOriginMaxLen = 2048;
const int _kRpIdMaxLen = 253; // DNS label max
const int _kRpIdHashMaxLen = 256;
const int _kSessionIdMaxLen = 128;

final RegExp _kNonceCharset = RegExp(r'^[A-Za-z0-9_\-]+$');
final RegExp _kSessionIdCharset = RegExp(r'^[A-Za-z0-9_\-]+$');

/// Stable i18n key for any validation failure. The UI layer converts this
/// to `AppLocalizations.of(context).invalidQrCode` at render time.
const String _kErrorKeyInvalidQrCode = 'invalidQrCode';

QrPayloadValidationResult _reject() =>
    const QrPayloadValidationResult.failure(_kErrorKeyInvalidQrCode);

/// Strict validator for a decoded v3 auth payload `Map<String, dynamic>`.
///
/// Defense-in-depth for SEC-03. Callers should invoke this before signing
/// the payload or displaying any of its fields in the UI. A failure result
/// carries `errorKey = 'invalidQrCode'` which the UI layer maps to the
/// localized `AppLocalizations.invalidQrCode` message (English + Turkish).
QrPayloadValidationResult validateAuthPayload(Map<String, dynamic> raw) {
  // 1. Unexpected-field rejection.
  for (final k in raw.keys) {
    if (!_kAuthPayloadAllowedKeys.contains(k)) return _reject();
  }

  // 2. Required-field presence (rp_id and rp_id_hash are optional).
  for (final req in _kAuthPayloadRequiredKeys) {
    if (!raw.containsKey(req) || raw[req] == null) return _reject();
  }

  // 3. Type checks.
  final expiresAt = raw['expires_at'];
  final issuedAt = raw['issued_at'];
  final nonce = raw['nonce'];
  final origin = raw['origin'];
  final sessionId = raw['session_id'];
  final rpId = raw['rp_id'];
  final rpIdHash = raw['rp_id_hash'];

  if (expiresAt is! int) return _reject();
  if (issuedAt is! int) return _reject();
  if (nonce is! String) return _reject();
  if (origin is! String) return _reject();
  if (sessionId is! String) return _reject();
  if (rpId != null && rpId is! String) return _reject();
  if (rpIdHash != null && rpIdHash is! String) return _reject();

  // 4. Length bounds.
  if (nonce.isEmpty || nonce.length > _kNonceMaxLen) return _reject();
  if (origin.isEmpty || origin.length > _kOriginMaxLen) return _reject();
  if (sessionId.isEmpty || sessionId.length > _kSessionIdMaxLen) {
    return _reject();
  }
  if (rpId is String && (rpId.isEmpty || rpId.length > _kRpIdMaxLen)) {
    return _reject();
  }
  if (rpIdHash is String &&
      (rpIdHash.isEmpty || rpIdHash.length > _kRpIdHashMaxLen)) {
    return _reject();
  }

  // 5. Charset / URI checks.
  if (!_kNonceCharset.hasMatch(nonce)) return _reject();
  if (!_kSessionIdCharset.hasMatch(sessionId)) return _reject();

  final originUri = Uri.tryParse(origin);
  if (originUri == null) return _reject();
  final scheme = originUri.scheme.toLowerCase();
  if (scheme != 'http' && scheme != 'https') return _reject();
  if (originUri.host.isEmpty) return _reject();

  return const QrPayloadValidationResult.success();
}
