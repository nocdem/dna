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

import '../ffi/dna_engine.dart';
import '../utils/qr_payload_parser.dart';
import '../utils/logger.dart';

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

      DnaLogger.log('QR_AUTH', 'Signing payload: $signedPayload');

      // Sign the canonical JSON bytes
      final payloadBytes = utf8.encode(signedPayload);
      final signature = _engine.signData(Uint8List.fromList(payloadBytes));

      // Base64 encode the signature
      final signatureBase64 = base64Encode(signature);

      // Build the response body
      final responseBody = _buildResponseBody(
        sessionId: payload.sessionId!,
        fingerprint: fingerprint,
        signature: signatureBase64,
        signedPayload: {
          'origin': payload.origin!,
          'session_id': payload.sessionId!,
          'nonce': payload.nonce!,
          'issued_at': now,
          'expires_at': expiresAt,
        },
      );

      DnaLogger.log('QR_AUTH', 'Posting to callback: ${payload.callbackUrl}');

      // POST to callback URL
      final result = await _postToCallback(payload.callbackUrl!, responseBody);
      return result;
    } on DnaEngineException catch (e) {
      DnaLogger.error('QR_AUTH', 'Engine error during auth: ${e.message}');
      return QrAuthResult.failure('Signing failed: ${e.message}');
    } catch (e) {
      DnaLogger.error('QR_AUTH', 'Unexpected error during auth: $e');
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
    required String signature,
    required Map<String, dynamic> signedPayload,
  }) {
    final response = {
      'type': 'dna.auth.response',
      'v': 1,
      'session_id': sessionId,
      'fingerprint': fingerprint,
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
          DnaLogger.log('QR_AUTH', 'Bad certificate for $host:$port');
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

      // Drain the response body
      await response.drain<void>();

      if (statusCode >= 200 && statusCode < 300) {
        DnaLogger.log('QR_AUTH', 'Auth callback success: $statusCode');
        return const QrAuthResult.success();
      } else {
        DnaLogger.error('QR_AUTH', 'Auth callback failed: $statusCode');
        return QrAuthResult.failure(
          'Server returned $statusCode',
          statusCode: statusCode,
        );
      }
    } on SocketException catch (e) {
      DnaLogger.error('QR_AUTH', 'Network error: $e');
      return QrAuthResult.failure('Network error: ${e.message}');
    } on HandshakeException catch (e) {
      DnaLogger.error('QR_AUTH', 'TLS error: $e');
      return QrAuthResult.failure('TLS/SSL error: ${e.message}');
    } on HttpException catch (e) {
      DnaLogger.error('QR_AUTH', 'HTTP error: $e');
      return QrAuthResult.failure('HTTP error: ${e.message}');
    } catch (e) {
      DnaLogger.error('QR_AUTH', 'Unexpected network error: $e');
      return QrAuthResult.failure('Network error: $e');
    } finally {
      client?.close();
    }
  }

  /// Deny an auth request (optional - just navigates away without POSTing)
  /// In the future, this could POST a denial response if the spec requires it.
  void deny(QrPayload payload) {
    DnaLogger.log('QR_AUTH', 'Auth request denied by user: ${payload.origin}');
    // Currently no network call needed for denial
    // The server will timeout the session
  }
}
