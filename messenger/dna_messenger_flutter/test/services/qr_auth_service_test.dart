// test/services/qr_auth_service_test.dart
//
// SEC-03: QR auth JSON injection — byte-identical jsonEncode replacement
// guards v3/v4 canonical signing input byte sequence while correctly
// escaping JSON metacharacters in attacker-controlled fields.
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:dna_connect/services/qr_auth_service.dart';

void main() {
  group('QrAuthService SEC-03 v3 canonical signed payload byte-identical', () {
    test('branch 1: rp_id + rp_id_hash present (alphabetical key order)', () {
      // Legacy interpolated template produced exactly this byte sequence.
      // New jsonEncode(Map literal) must produce the SAME bytes.
      const expected =
          '{"expires_at":1700000000,"issued_at":1699999000,"nonce":"abc123","origin":"https://example.com","rp_id":"example.com","rp_id_hash":"deadbeef","session_id":"sess-1"}';

      final actual = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: 'https://example.com',
        sessionId: 'sess-1',
        nonce: 'abc123',
        issuedAt: 1699999000,
        expiresAt: 1700000000,
        rpId: 'example.com',
        rpIdHashB64: 'deadbeef',
      );

      expect(actual, equals(expected));
    });

    test('branch 2: rp_id only, no rp_id_hash', () {
      const expected =
          '{"expires_at":1700000000,"issued_at":1699999000,"nonce":"abc123","origin":"https://example.com","rp_id":"example.com","session_id":"sess-1"}';

      final actual = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: 'https://example.com',
        sessionId: 'sess-1',
        nonce: 'abc123',
        issuedAt: 1699999000,
        expiresAt: 1700000000,
        rpId: 'example.com',
        rpIdHashB64: null,
      );

      expect(actual, equals(expected));
    });

    test('branch 3: bare (no rp_id, no rp_id_hash)', () {
      const expected =
          '{"expires_at":1700000000,"issued_at":1699999000,"nonce":"abc123","origin":"https://example.com","session_id":"sess-1"}';

      final actual = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: 'https://example.com',
        sessionId: 'sess-1',
        nonce: 'abc123',
        issuedAt: 1699999000,
        expiresAt: 1700000000,
        rpId: null,
        rpIdHashB64: null,
      );

      expect(actual, equals(expected));
    });

    test('normalization: rp_id lowercased and trimmed, rp_id_hash trimmed', () {
      // Legacy code lowercases rp_id and trims rp_id_hash; that behavior
      // must be preserved byte-identically by the new jsonEncode path.
      const expected =
          '{"expires_at":1700000000,"issued_at":1699999000,"nonce":"abc123","origin":"https://example.com","rp_id":"example.com","rp_id_hash":"deadbeef","session_id":"sess-1"}';

      final actual = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: '  https://example.com  ',
        sessionId: 'sess-1',
        nonce: 'abc123',
        issuedAt: 1699999000,
        expiresAt: 1700000000,
        rpId: '  Example.COM  ',
        rpIdHashB64: '  deadbeef  ',
      );

      expect(actual, equals(expected));
    });
  });

  group('QrAuthService SEC-03 JSON injection hardening', () {
    test('nonce with JSON metacharacters round-trips via jsonDecode', () {
      final maliciousNonce = 'a"b\\c\nd}e\u00ff';

      final out = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: 'https://example.com',
        sessionId: 'sess-1',
        nonce: maliciousNonce,
        issuedAt: 1,
        expiresAt: 2,
        rpId: null,
        rpIdHashB64: null,
      );

      // Must be valid JSON (legacy interpolated code would produce
      // syntactically invalid JSON here and jsonDecode would throw).
      final decoded = jsonDecode(out) as Map<String, dynamic>;
      expect(decoded['nonce'], equals(maliciousNonce));
      expect(decoded['origin'], equals('https://example.com'));
      expect(decoded['session_id'], equals('sess-1'));
      expect(decoded['expires_at'], equals(2));
      expect(decoded['issued_at'], equals(1));
    });

    test('origin with JSON metacharacters round-trips', () {
      final maliciousOrigin = 'https://evil"injected\\path\u0000.com';

      final out = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: maliciousOrigin,
        sessionId: 's',
        nonce: 'n',
        issuedAt: 1,
        expiresAt: 2,
        rpId: null,
        rpIdHashB64: null,
      );

      final decoded = jsonDecode(out) as Map<String, dynamic>;
      expect(decoded['origin'], equals(maliciousOrigin));
    });

    test('session_id with injection chars round-trips', () {
      final maliciousSid = 'sess","extra":"value';

      final out = QrAuthService.debugBuildCanonicalSignedPayload(
        origin: 'https://example.com',
        sessionId: maliciousSid,
        nonce: 'n',
        issuedAt: 1,
        expiresAt: 2,
        rpId: null,
        rpIdHashB64: null,
      );

      final decoded = jsonDecode(out) as Map<String, dynamic>;
      expect(decoded['session_id'], equals(maliciousSid));
      // Exactly 5 keys — no smuggled "extra" field.
      expect(decoded.length, equals(5));
      expect(decoded.containsKey('extra'), isFalse);
    });
  });

  group('QrAuthService SEC-03 v4 canonical payload byte-identical', () {
    test('v4 payload matches legacy template byte-for-byte', () {
      // Legacy v4 template (line 432) in exact alphabetical key order:
      // expires_at, issued_at, nonce, origin, rp_id_hash, session_id, sid, st_hash
      const expected =
          '{"expires_at":1700000000,"issued_at":1699999000,"nonce":"abc123","origin":"https://example.com","rp_id_hash":"deadbeef","session_id":"sid-1","sid":"sid-1","st_hash":"sthash"}';

      final actual = QrAuthService.debugBuildCanonicalV4Payload(
        expiresAt: 1700000000,
        issuedAt: 1699999000,
        nonce: 'abc123',
        origin: 'https://example.com',
        rpIdHash: 'deadbeef',
        sessionId: 'sid-1',
        sid: 'sid-1',
        stHash: 'sthash',
      );

      expect(actual, equals(expected));
    });

    test('v4 with JSON injection in nonce round-trips', () {
      final maliciousNonce = 'a"b\\c\nd}e';

      final out = QrAuthService.debugBuildCanonicalV4Payload(
        expiresAt: 2,
        issuedAt: 1,
        nonce: maliciousNonce,
        origin: 'https://example.com',
        rpIdHash: 'deadbeef',
        sessionId: 'sid-1',
        sid: 'sid-1',
        stHash: 'sthash',
      );

      final decoded = jsonDecode(out) as Map<String, dynamic>;
      expect(decoded['nonce'], equals(maliciousNonce));
      expect(decoded.length, equals(8));
    });
  });
}
