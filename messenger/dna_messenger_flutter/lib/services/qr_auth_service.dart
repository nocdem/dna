/// QR Auth Service for DNA Messenger
///
/// Handles the QR-based authentication flow:
/// 1. Builds canonical signed_payload JSON
/// 2. Signs with Dilithium5 via FFI
/// 3. POSTs to callback URL
/// 4. Returns success/failure status
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
    if (callbackUri.scheme != 'https') {
      return const QrAuthResult.failure('Callback URL must use HTTPS');
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

      final signedPayload = _buildCanonicalSignedPayload(
        origin: payload.origin!,
        sessionId: payload.sessionId!,
        nonce: payload.nonce!,
        issuedAt: now,
        expiresAt: expiresAt,
      );
      //final payloadHash = sha3_256.convert(utf8.encode(signedPayload)).toString();
      //debugPrint('QR_AUTH: payload_len=${utf8.encode(signedPayload).length} payload_sha3_256=$payloadHash');
      final payloadBytesDbg = utf8.encode(signedPayload);
      final payloadHash = sha256.convert(payloadBytesDbg).toString();
      debugPrint('QR_AUTH: payload_len=${payloadBytesDbg.length} payload_sha256=$payloadHash');
      debugPrint('QR_AUTH: Signing payload: $signedPayload');

      // Sign the canonical JSON bytes
      final payloadBytes = utf8.encode(signedPayload);
      final signature = _engine.signData(Uint8List.fromList(payloadBytes));

      // Base64 encode the signature
      final signatureBase64 = base64Encode(signature);

      // Export Dilithium signing public key (raw bytes -> base64)
      final pubkeyB64 = base64Encode(_engine.signingPublicKey);

      // Build the response body
      final responseBody = _buildResponseBody(
        sessionId: payload.sessionId!,
        fingerprint: fingerprint,
        pubkeyB64: pubkeyB64,
        signature: signatureBase64,
        signedPayload: {
          'origin': payload.origin!,
          'session_id': payload.sessionId!,
          'nonce': payload.nonce!,
          'issued_at': now,
          'expires_at': expiresAt,
        },
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

  /// Build canonical signed_payload JSON (RFC 8785 style: sorted keys, no whitespace)
  String _buildCanonicalSignedPayload({
    required String origin,
    required String sessionId,
    required String nonce,
    required int issuedAt,
    required int expiresAt,
  }) {
    // Keys must be in sorted order for canonical JSON
    // expires_at, issued_at, nonce, origin, session_id (alphabetical)
    return '{"expires_at":$expiresAt,"issued_at":$issuedAt,"nonce":"$nonce","origin":"$origin","session_id":"$sessionId"}';
  }

  /// Build the complete response body
  String _buildResponseBody({
    required String sessionId,
    required String fingerprint,
    required String pubkeyB64,
    required String signature,
    required Map<String, dynamic> signedPayload,
  }) {
    final response = {
      'type': 'dna.auth.response',
      'v': 1,
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
          // In production, we should NOT accept bad certificates
          // This is only for development/testing
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

      // Read response body (do NOT just drain it—this is where error details live)
      final responseText = await response.transform(utf8.decoder).join();
      final contentType = response.headers.contentType?.mimeType;

      if (statusCode >= 200 && statusCode < 300) {
        debugPrint('QR_AUTH: Auth callback success: $statusCode');
        return const QrAuthResult.success();
      }

      // Try to parse a structured error message from JSON responses.
      String? errorMessage;

      if (contentType == 'application/json' && responseText.isNotEmpty) {
        try {
          final decoded = jsonDecode(responseText);

          // FastAPI often returns {"detail": "..."} or {"detail": {...}}
          dynamic detail = decoded is Map<String, dynamic> ? decoded['detail'] : null;

          // Support both:
          // 1) {"detail":{"error":"not_authorized","reason":"identity_not_allowed"}}
          // 2) {"error":"not_authorized","reason":"identity_not_allowed"}
          String? error;
          String? reason;

          if (detail is Map<String, dynamic>) {
            error = detail['error']?.toString();
            reason = detail['reason']?.toString();
          } else if (decoded is Map<String, dynamic>) {
            error = decoded['error']?.toString();
            reason = decoded['reason']?.toString();
            // Sometimes detail is a string:
            if (error == null && reason == null && detail is String) {
              errorMessage = detail;
            }
          }

          // Map known reasons to human-friendly messages
          if (errorMessage == null) {
            if (reason == 'identity_not_allowed') {
              errorMessage = 'Not authorized: this identity is not allowed for this service.';
            } else if (reason == 'invalid_signature') {
              errorMessage = 'Authentication failed: signature was rejected by server.';
            } else if (reason == 'fingerprint_pubkey_mismatch') {
              errorMessage = 'Authentication failed: identity binding mismatch.';
            } else if (reason == 'replay_nonce') {
              errorMessage = 'Authentication failed: replay detected.';
            } else if (error != null || reason != null) {
              // Generic structured error fallback
              final parts = <String>[];
              if (error != null && error.isNotEmpty) parts.add(error);
              if (reason != null && reason.isNotEmpty) parts.add(reason);
              errorMessage = parts.isEmpty ? null : parts.join(' / ');
            }
          }
        } catch (_) {
          // Ignore JSON parsing errors and fall back to generic message below
        }
      }

      // If we couldn't parse a better message, use status code
      errorMessage ??= 'Server returned $statusCode';

      debugPrint('QR_AUTH ERROR: Auth callback failed: $statusCode body="$responseText"');
      return QrAuthResult.failure(
        errorMessage,
        statusCode: statusCode,
      );
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
  /// In the future, this could POST a denial response if the spec requires it.
  void deny(QrPayload payload) {
    debugPrint('QR_AUTH: Auth request denied by user: ${payload.origin}');
    // Currently no network call needed for denial
    // The server will timeout the session
  }
}
