// lib/services/qr_auth_service.dart
//
// v3: include rp_id_hash in signed payload and canonical message
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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
    final pv = payload.v ?? 1;
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
      final normRpId = rpId!.trim().toLowerCase();
      final normRpHash = rpIdHashB64!.trim();
      // alphabetical: expires_at, issued_at, nonce, origin, rp_id, rp_id_hash, session_id
      return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$normOrigin","rp_id":"$normRpId","rp_id_hash":"$normRpHash","session_id":"$sessionId"}';
    }

    if (hasRp) {
      final normRpId = rpId!.trim().toLowerCase();
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
}
