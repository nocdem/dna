/// QR Auth Service for DNA Messenger
///
/// Handles the QR-based authentication flow:
/// 1. Validates QR payload
/// 2. Enforces RP/origin binding rules (v2+)
/// 3. Builds canonical signed_payload JSON
/// 4. Signs with Dilithium5 via FFI
/// 5. POSTs to callback URL
/// 6. Returns success/failure status
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

import '../ffi/dna_engine.dart';
import '../utils/qr_payload_parser.dart';

/// Result of an auth approval operation
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

/// Service for handling QR-based authentication
class QrAuthService {
  final DnaEngine _engine;

  QrAuthService(this._engine);

  /// Approve an auth request by signing and POSTing to the callback URL
  ///
  /// Returns [QrAuthResult] indicating success or failure.
  Future<QrAuthResult> approve(QrPayload payload) async {
    // Validate payload has required fields
    if (!payload.hasRequiredAuthFields) {
      return const QrAuthResult.failure(
        'Missing required auth fields (origin, session_id, nonce, or callback)',
      );
    }

    // Check if request has expired
    if (payload.isExpired) {
      return const QrAuthResult.failure('Auth request has expired');
    }

    // Validate callback URL is HTTPS
    final callbackUri = Uri.tryParse(payload.callbackUrl!);
    if (callbackUri == null) {
      return const QrAuthResult.failure('Invalid callback URL');
    }
    if (callbackUri.scheme.toLowerCase() != 'https') {
      return const QrAuthResult.failure('Callback URL must use HTTPS');
    }

    // WebAuthn-style RP/origin binding enforcement (v2+ payloads).
    // This is the "browser-enforced" part in WebAuthn terms: refuse to sign
    // if origin/callback do not align with rp_id.
    final rpError = validateRpBinding(payload);
    if (rpError != null) {
      return QrAuthResult.failure(rpError);
    }

    try {
      // Get current identity fingerprint
      final fingerprint = _engine.fingerprint;
      if (fingerprint == null || fingerprint.isEmpty) {
        return const QrAuthResult.failure('No identity loaded');
      }

      // Build signed_payload with canonical ordering
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final expiresAt = payload.expiresAt ?? (now + 120); // Default 2 minutes

      // For v2+ payloads, include rp_id in the signed canonical JSON
      final pv = payload.v ?? 1;
      final includeRp = pv >= 2 && (payload.rpId != null && payload.rpId!.isNotEmpty);

      final signedPayloadStr = _buildCanonicalSignedPayload(
        origin: payload.origin!,
        sessionId: payload.sessionId!,
        nonce: payload.nonce!,
        issuedAt: now,
        expiresAt: expiresAt,
        rpId: includeRp ? payload.rpId : null,
      );

      final payloadBytes = utf8.encode(signedPayloadStr);
      final payloadHash = sha256.convert(payloadBytes).toString();
      debugPrint(
        'QR_AUTH: payload_len=${payloadBytes.length} payload_sha256=$payloadHash',
      );
      debugPrint('QR_AUTH: Signing payload: $signedPayloadStr');

      // Sign the canonical JSON bytes
      final signature = _engine.signData(Uint8List.fromList(payloadBytes));

      // Base64 encode the signature
      final signatureBase64 = base64Encode(signature);

      // Export Dilithium signing public key (raw bytes -> base64)
      final pubkeyB64 = base64Encode(_engine.signingPublicKey);

      // Build signed_payload object (must correspond to the canonical string)
      final signedPayloadObj = <String, dynamic>{
        'origin': payload.origin!,
        'session_id': payload.sessionId!,
        'nonce': payload.nonce!,
        'issued_at': now,
        'expires_at': expiresAt,
      };

      if (includeRp) {
        // Normalize to match canonical builder behavior
        signedPayloadObj['rp_id'] = payload.rpId!.trim().toLowerCase();
      }

      // Build the response body
      final responseBody = _buildResponseBody(
        sessionId: payload.sessionId!,
        fingerprint: fingerprint,
        pubkeyB64: pubkeyB64,
        signature: signatureBase64,
        signedPayload: signedPayloadObj,
        v: includeRp ? 2 : 1,
      );

      debugPrint('QR_AUTH: Posting to callback: ${payload.callbackUrl}');

      // POST to callback URL
      final result = await _postToCallback(payload.callbackUrl!, responseBody);
      return result;
    } on DnaEngineException catch (e) {
      debugPrint('QR_AUTH ERROR: Engine error during auth: ${e.message}');
      return QrAuthResult.failure('Signing failed: ${e.message}');
    } catch (e) {
      debugPrint('QR_AUTH ERROR: Unexpected error during auth: $e');
      return QrAuthResult.failure('Unexpected error: $e');
    }
  }

  /// Build canonical signed_payload JSON (sorted keys, no whitespace).
  ///
  /// IMPORTANT: Must match server reconstruction byte-for-byte.
  ///
  /// v1 keys (alphabetical):
  ///   expires_at, issued_at, nonce, origin, session_id
  ///
  /// v2+ adds rp_id (alphabetical position between origin and session_id):
  ///   expires_at, issued_at, nonce, origin, rp_id, session_id
  String _buildCanonicalSignedPayload({
    required String origin,
    required String sessionId,
    required String nonce,
    required int issuedAt,
    required int expiresAt,
    String? rpId,
  }) {
    final normOrigin = origin.trim();

    if (rpId != null && rpId.trim().isNotEmpty) {
      final normRpId = rpId.trim().toLowerCase();
      return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$normOrigin","rp_id":"$normRpId","session_id":"$sessionId"}';
    }

    return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$normOrigin","session_id":"$sessionId"}';
  }

  /// Build the complete response body JSON string
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

  /// POST the auth response to the callback URL
  Future<QrAuthResult> _postToCallback(String url, String body) async {
    HttpClient? client;
    try {
      client = HttpClient()
        ..connectionTimeout = const Duration(seconds: 15)
        ..badCertificateCallback = (cert, host, port) {
          // In production, do NOT accept bad certificates.
          debugPrint('QR_AUTH: Bad certificate for $host:$port');
          return false;
        };

      final uri = Uri.parse(url);
      final request = await client.postUrl(uri);

      request.headers.set('Content-Type', 'application/json');
      request.headers.set('Accept', 'application/json');
      request.write(body);

      final response = await request.close().timeout(
        const Duration(seconds: 15),
        onTimeout: () {
          throw const SocketException('Connection timed out');
        },
      );

      final statusCode = response.statusCode;

      // Read body for better errors (server may return JSON detail)
      final respText = await utf8.decoder.bind(response).join();

      if (statusCode >= 200 && statusCode < 300) {
        debugPrint('QR_AUTH: Auth callback success: $statusCode');
        return const QrAuthResult.success();
      } else {
        debugPrint('QR_AUTH ERROR: Auth callback failed: $statusCode body=$respText');

        // Try to extract a nicer message if server returns JSON detail
        String msg = 'Server returned $statusCode';
        try {
          final decoded = jsonDecode(respText);
          if (decoded is Map && decoded['detail'] != null) {
            final detail = decoded['detail'];
            if (detail is Map && detail['message'] is String) {
              msg = detail['message'] as String;
            }
          }
        } catch (_) {
          // ignore, keep generic message
        }

        return QrAuthResult.failure(msg, statusCode: statusCode);
      }
    } on SocketException catch (e) {
      debugPrint('QR_AUTH ERROR: Network error: $e');
      return QrAuthResult.failure('Network error: ${e.message}');
    } on HandshakeException catch (e) {
      debugPrint('QR_AUTH ERROR: TLS error: $e');
      return QrAuthResult.failure('TLS/SSL error: ${e.message}');
    } on HttpException catch (e) {
      debugPrint('QR_AUTH ERROR: HTTP error: $e');
      return QrAuthResult.failure('HTTP error: ${e.message}');
    } catch (e) {
      debugPrint('QR_AUTH ERROR: Unexpected network error: $e');
      return QrAuthResult.failure('Network error: $e');
    } finally {
      client?.close();
    }
  }

  /// Deny an auth request (optional - just navigates away without POSTing)
  void deny(QrPayload payload) {
    debugPrint('QR_AUTH: Auth request denied by user: ${payload.origin}');
    // No network call for denial; server will timeout the session
  }
}
