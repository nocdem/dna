// lib/services/qr_auth_service.dart
//
// v3: include rp_id_hash in signed payload and canonical message
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

import '../ffi/dna_engine.dart';
import '../utils/qr_payload_parser.dart';

class QrAuthResult {
  final bool success;
  final String? errorMessage;
  final int? statusCode;

  const QrAuthResult.success()
      : success = true,
        errorMessage = null,
        statusCode = null;

  const QrAuthResult.failure(this.errorMessage, {this.statusCode})
      : success = false;

  @override
  String toString() => success
      ? 'QrAuthResult.success()'
      : 'QrAuthResult.failure($errorMessage, statusCode: $statusCode)';
}

class QrAuthService {
  final DnaEngine _engine;
  QrAuthService(this._engine);

  Uint8List _sha256Bytes(String s) {
    final digest = sha256.convert(utf8.encode(s));
    return Uint8List.fromList(digest.bytes);
  }

  String _rpIdHashB64(String rpIdLower) {
    // Standard base64 (matches python server expectation)
    return base64Encode(_sha256Bytes(rpIdLower));
  }

  Future<QrAuthResult> approve(QrPayload payload) async {
    if (!payload.hasRequiredAuthFields) {
      return const QrAuthResult.failure(
        'Missing required auth fields (origin, session_id, nonce, or callback)',
      );
    }

    // v4 stateless flow: st token present
    final pv = payload.v ?? 1;
    final isV4 = pv >= 4 && payload.st != null && payload.st!.trim().isNotEmpty;
    if (isV4) {
      return await _approveV4(payload);
    }

    if (payload.isExpired) {
      return const QrAuthResult.failure('Auth request has expired');
    }

    final callbackUri = Uri.tryParse(payload.callbackUrl!);
    if (callbackUri == null) {
      return const QrAuthResult.failure('Invalid callback URL');
    }
    if (callbackUri.scheme.toLowerCase() != 'https') {
      return const QrAuthResult.failure('Callback URL must use HTTPS');
    }

    // Enforce RP binding (v2+) and require rp_id_hash presence (v3)
    final rpError = validateRpBinding(payload);
    if (rpError != null) {
      return QrAuthResult.failure(rpError);
    }

    // If v3, require rp_id_hash in the QR (and also recompute for signing)
    if (pv >= 3 && (payload.rpIdHash == null || payload.rpIdHash!.trim().isEmpty)) {
      return const QrAuthResult.failure('Missing rp_id_hash in QR payload (v3)');
    }

    try {
      final fingerprint = _engine.fingerprint;
      if (fingerprint == null || fingerprint.isEmpty) {
        return const QrAuthResult.failure('No identity loaded');
      }

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final expiresAt = payload.expiresAt ?? (now + 120);

      final includeRp = pv >= 2 && (payload.rpId != null && payload.rpId!.isNotEmpty);
      final includeRpHash = pv >= 3 && includeRp;

      final normRpId = includeRp ? payload.rpId!.trim().toLowerCase() : null;

      // Recompute rp_id_hash deterministically from rp_id for what we SIGN.
      // (We still *require* it to exist in the QR for v3.)
      final rpIdHashB64 = includeRpHash ? _rpIdHashB64(normRpId!) : null;

      final signedPayloadStr = _buildCanonicalSignedPayload(
        origin: payload.origin!,
        sessionId: payload.sessionId!,
        nonce: payload.nonce!,
        issuedAt: now,
        expiresAt: expiresAt,
        rpId: normRpId,
        rpIdHashB64: rpIdHashB64,
      );

      final payloadBytes = utf8.encode(signedPayloadStr);
      final payloadHash = sha256.convert(payloadBytes).toString();
      debugPrint(
        'QR_AUTH: payload_v=$pv payload_len=${payloadBytes.length} payload_sha256=$payloadHash',
      );

      final signature = _engine.signData(Uint8List.fromList(payloadBytes));
      final signatureBase64 = base64Encode(signature);
      final pubkeyB64 = base64Encode(_engine.signingPublicKey);

      final signedPayloadObj = <String, dynamic>{
        'origin': payload.origin!.trim(),
        'session_id': payload.sessionId!,
        'nonce': payload.nonce!,
        'issued_at': now,
        'expires_at': expiresAt,
      };

      if (includeRp) {
        signedPayloadObj['rp_id'] = normRpId;
      }
      if (includeRpHash) {
        signedPayloadObj['rp_id_hash'] = rpIdHashB64;
      }

      final responseBody = _buildResponseBody(
        sessionId: payload.sessionId!,
        fingerprint: fingerprint,
        pubkeyB64: pubkeyB64,
        signature: signatureBase64,
        signedPayload: signedPayloadObj,
        v: pv >= 3 ? 3 : (pv >= 2 ? 2 : 1),
      );

      return await _postToCallback(payload.callbackUrl!, responseBody);
    } on DnaEngineException catch (e) {
      return QrAuthResult.failure('Signing failed: ${e.message}');
    } catch (e) {
      return QrAuthResult.failure('Unexpected error: $e');
    }
  }

  String _buildCanonicalSignedPayload({
    required String origin,
    required String sessionId,
    required String nonce,
    required int issuedAt,
    required int expiresAt,
    String? rpId,
    String? rpIdHashB64,
  }) {
    final normOrigin = origin.trim();

    final hasRp = rpId != null && rpId.trim().isNotEmpty;
    final hasRpHash = rpIdHashB64 != null && rpIdHashB64.trim().isNotEmpty;

    if (hasRp && hasRpHash) {
      final normRpId = rpId.trim().toLowerCase();
      final normRpHash = rpIdHashB64.trim();
      // alphabetical: expires_at, issued_at, nonce, origin, rp_id, rp_id_hash, session_id
      return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$normOrigin","rp_id":"$normRpId","rp_id_hash":"$normRpHash","session_id":"$sessionId"}';
    }

    if (hasRp) {
      final normRpId = rpId.trim().toLowerCase();
      // alphabetical: expires_at, issued_at, nonce, origin, rp_id, session_id
      return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$normOrigin","rp_id":"$normRpId","session_id":"$sessionId"}';
    }

    return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$normOrigin","session_id":"$sessionId"}';
  }

  String _buildResponseBody({
    required String sessionId,
    required String fingerprint,
    required String pubkeyB64,
    required String signature,
    required Map<String, dynamic> signedPayload,
    required int v,
  }) {
    final response = {
      'type': 'dna.auth.response',
      'v': v,
      'session_id': sessionId,
      'fingerprint': fingerprint,
      'pubkey_b64': pubkeyB64,
      'signature': signature,
      'signed_payload': signedPayload,
    };
    return jsonEncode(response);
  }

  Future<QrAuthResult> _postToCallback(String url, String body) async {
    HttpClient? client;
    try {
      client = HttpClient()..connectionTimeout = const Duration(seconds: 15);

      final uri = Uri.parse(url);
      final request = await client.postUrl(uri);
      request.headers.set('Content-Type', 'application/json');
      request.headers.set('Accept', 'application/json');
      request.write(body);

      final response = await request.close().timeout(
        const Duration(seconds: 15),
        onTimeout: () => throw const SocketException('Connection timed out'),
      );

      final statusCode = response.statusCode;
      final respText = await utf8.decoder.bind(response).join();

      if (statusCode >= 200 && statusCode < 300) {
        return const QrAuthResult.success();
      }

      String msg = 'Server returned $statusCode';
      try {
        final decoded = jsonDecode(respText);
        if (decoded is Map && decoded['detail'] != null) {
          final detail = decoded['detail'];
          if (detail is Map && detail['message'] is String) {
            msg = detail['message'] as String;
          }
        }
      } catch (_) {}

      return QrAuthResult.failure(msg, statusCode: statusCode);
    } on SocketException catch (e) {
      return QrAuthResult.failure('Network error: ${e.message}');
    } on HandshakeException catch (e) {
      return QrAuthResult.failure('TLS/SSL error: ${e.message}');
    } on HttpException catch (e) {
      return QrAuthResult.failure('HTTP error: ${e.message}');
    } catch (e) {
      return QrAuthResult.failure('Network error: $e');
    } finally {
      client?.close();
    }
  }

  void deny(QrPayload payload) {
    debugPrint('QR_AUTH: Auth request denied by user: ${payload.origin}');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // v4 stateless flow
  // ─────────────────────────────────────────────────────────────────────────

  Future<QrAuthResult> _approveV4(QrPayload payload) async {
    try {
      final fingerprint = _engine.fingerprint;
      if (fingerprint == null || fingerprint.isEmpty) {
        return const QrAuthResult.failure('No identity loaded');
      }

      final st = payload.st!.trim();

      // Decode st payload
      final stPayload = _decodeStPayload(st);
      if (stPayload == null) {
        return const QrAuthResult.failure('Invalid st token format');
      }

      // Extract required fields
      final sid = stPayload['sid'] as String?;
      final origin = (stPayload['origin'] as String?)?.trim();
      final rpIdHash = stPayload['rp_id_hash'] as String?;
      final nonce = stPayload['nonce'] as String?;
      final issuedAt = stPayload['issued_at'] as int?;
      final expiresAt = stPayload['expires_at'] as int?;

      if (sid == null || sid.isEmpty) {
        return const QrAuthResult.failure('Missing sid in st payload');
      }
      if (origin == null || origin.isEmpty) {
        return const QrAuthResult.failure('Missing origin in st payload');
      }
      if (rpIdHash == null || rpIdHash.isEmpty) {
        return const QrAuthResult.failure('Missing rp_id_hash in st payload');
      }
      if (nonce == null || nonce.isEmpty) {
        return const QrAuthResult.failure('Missing nonce in st payload');
      }
      if (issuedAt == null) {
        return const QrAuthResult.failure('Missing issued_at in st payload');
      }
      if (expiresAt == null) {
        return const QrAuthResult.failure('Missing expires_at in st payload');
      }

      // Check expiry locally
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      if (now > expiresAt) {
        return const QrAuthResult.failure('Auth request has expired');
      }

      // Compute st_hash = base64(sha256(utf8(st))) - STANDARD base64
      final stHash = _sha256B64Std(st);

      // session_id = sid for compatibility
      final sessionId = sid;

      // Build canonical v4 payload - exact key order:
      // expires_at, issued_at, nonce, origin, rp_id_hash, session_id, sid, st_hash
      final canonicalStr = _buildCanonicalV4Payload(
        expiresAt: expiresAt,
        issuedAt: issuedAt,
        nonce: nonce,
        origin: origin,
        rpIdHash: rpIdHash,
        sessionId: sessionId,
        sid: sid,
        stHash: stHash,
      );

      final payloadBytes = utf8.encode(canonicalStr);
      final payloadHash = sha256.convert(payloadBytes).toString();
      debugPrint(
        'QR_AUTH_V4: sid=$sid payload_sha256=$payloadHash',
      );

      // Sign with Dilithium5
      final signature = _engine.signData(Uint8List.fromList(payloadBytes));
      final signatureBase64 = base64Encode(signature);
      final pubkeyB64 = base64Encode(_engine.signingPublicKey);

      // Build signed_payload object for response
      final signedPayloadObj = <String, dynamic>{
        'sid': sid,
        'origin': origin,
        'rp_id_hash': rpIdHash,
        'nonce': nonce,
        'issued_at': issuedAt,
        'expires_at': expiresAt,
        'st_hash': stHash,
        'session_id': sessionId,
      };

      // Build request body
      final requestBody = {
        'type': 'dna.auth.response',
        'v': 4,
        'st': st,
        'session_id': sessionId,
        'fingerprint': fingerprint,
        'pubkey_b64': pubkeyB64,
        'signature': signatureBase64,
        'signed_payload': signedPayloadObj,
      };

      // POST to {origin}/api/v5/verify  (phase-1: payload is still v4-shaped, server accepts it)
      final verifyUrl = origin.endsWith('/')
          ? '${origin}api/v5/verify'
        : '$origin/api/v5/verify';

      debugPrint('QR_AUTH_V4: verifyUrl=$verifyUrl');

      return await _postToCallback(verifyUrl, jsonEncode(requestBody));
    } on DnaEngineException catch (e) {
      return QrAuthResult.failure('Signing failed: ${e.message}');
    } catch (e) {
      return QrAuthResult.failure('Unexpected error: $e');
    }
  }

  /// Decode st token: "v4.{b64url(payload_json)}.{b64url(sig)}"
  Map<String, dynamic>? _decodeStPayload(String st) {
    try {
      final parts = st.split('.');
      if (parts.length != 3 || parts[0] != 'v4') {
        return null;
      }

      final payloadB64Url = parts[1];
      final payloadBytes = _b64UrlDecode(payloadB64Url);
      final payloadStr = utf8.decode(payloadBytes);
      final payload = jsonDecode(payloadStr) as Map<String, dynamic>;
      return payload;
    } catch (e) {
      debugPrint('QR_AUTH_V4: Failed to decode st payload: $e');
      return null;
    }
  }

  /// Decode base64url (RFC 4648 §5) to bytes
  Uint8List _b64UrlDecode(String input) {
    // Replace URL-safe chars with standard base64 chars
    String s = input.replaceAll('-', '+').replaceAll('_', '/');
    // Add padding if needed
    switch (s.length % 4) {
      case 2:
        s += '==';
        break;
      case 3:
        s += '=';
        break;
    }
    return base64Decode(s);
  }

  /// SHA-256 hash of UTF-8 string, returned as standard base64
  String _sha256B64Std(String input) {
    final digest = sha256.convert(utf8.encode(input));
    return base64Encode(digest.bytes);
  }

  /// Build canonical v4 payload string with exact key order
  String _buildCanonicalV4Payload({
    required int expiresAt,
    required int issuedAt,
    required String nonce,
    required String origin,
    required String rpIdHash,
    required String sessionId,
    required String sid,
    required String stHash,
  }) {
    // Alphabetical key order:
    // expires_at, issued_at, nonce, origin, rp_id_hash, session_id, sid, st_hash
    return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$origin","rp_id_hash":"$rpIdHash","session_id":"$sessionId","sid":"$sid","st_hash":"$stHash"}';
  }
}
