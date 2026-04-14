// test/utils/qr_payload_parser_validation_test.dart
//
// SEC-03 defense-in-depth: strict parse-side validator for v3 auth
// payloads. Rejects malformed / oversized / charset-violating payloads
// before they reach signing or UI display.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:dna_connect/utils/qr_payload_parser.dart';

Map<String, dynamic> _validV3Raw() => <String, dynamic>{
      'expires_at': 1700000000,
      'issued_at': 1699999000,
      'nonce': 'abc123',
      'origin': 'https://example.com',
      'rp_id': 'example.com',
      'rp_id_hash': 'deadbeef',
      'session_id': 'sess-1',
    };

void main() {
  group('validateAuthPayload — positive', () {
    test('valid v3 payload with rp_id + rp_id_hash passes', () {
      final r = validateAuthPayload(_validV3Raw());
      expect(r.ok, isTrue);
      expect(r.errorKey, isNull);
    });

    test('valid v3 payload without optional rp_id / rp_id_hash passes', () {
      final raw = _validV3Raw()
        ..remove('rp_id')
        ..remove('rp_id_hash');
      final r = validateAuthPayload(raw);
      expect(r.ok, isTrue);
    });
  });

  group('validateAuthPayload — missing required fields', () {
    test('missing nonce is rejected', () {
      final raw = _validV3Raw()..remove('nonce');
      final r = validateAuthPayload(raw);
      expect(r.ok, isFalse);
      expect(r.errorKey, equals('invalidQrCode'));
    });

    test('missing origin is rejected', () {
      final raw = _validV3Raw()..remove('origin');
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('missing expires_at is rejected', () {
      final raw = _validV3Raw()..remove('expires_at');
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('missing issued_at is rejected', () {
      final raw = _validV3Raw()..remove('issued_at');
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('missing session_id is rejected', () {
      final raw = _validV3Raw()..remove('session_id');
      expect(validateAuthPayload(raw).ok, isFalse);
    });
  });

  group('validateAuthPayload — unexpected fields', () {
    test('extra unknown field is rejected', () {
      final raw = _validV3Raw()..['attacker_key'] = 'boom';
      final r = validateAuthPayload(raw);
      expect(r.ok, isFalse);
      expect(r.errorKey, equals('invalidQrCode'));
    });
  });

  group('validateAuthPayload — type checks', () {
    test('expires_at as string (not int) is rejected', () {
      final raw = _validV3Raw()..['expires_at'] = '1700000000';
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('nonce as int (not String) is rejected', () {
      final raw = _validV3Raw()..['nonce'] = 12345;
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('session_id as null is rejected', () {
      final raw = _validV3Raw()..['session_id'] = null;
      expect(validateAuthPayload(raw).ok, isFalse);
    });
  });

  group('validateAuthPayload — length bounds', () {
    test('oversized nonce (> 128 chars) is rejected', () {
      final raw = _validV3Raw()..['nonce'] = 'a' * 129;
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('empty nonce is rejected', () {
      final raw = _validV3Raw()..['nonce'] = '';
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('oversized origin (> 2048 chars) is rejected', () {
      final raw = _validV3Raw()
        ..['origin'] = 'https://example.com/${'x' * 2100}';
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('oversized rp_id (> 253 chars) is rejected', () {
      final raw = _validV3Raw()..['rp_id'] = 'a' * 254;
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('oversized session_id (> 128 chars) is rejected', () {
      final raw = _validV3Raw()..['session_id'] = 's' * 129;
      expect(validateAuthPayload(raw).ok, isFalse);
    });
  });

  group('validateAuthPayload — charset / URI', () {
    test('nonce with non-[A-Za-z0-9_-] characters is rejected', () {
      final raw = _validV3Raw()..['nonce'] = 'abc!def';
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('nonce with JSON metacharacters is rejected', () {
      final raw = _validV3Raw()..['nonce'] = 'abc"def';
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('origin that is not a valid URI is rejected', () {
      final raw = _validV3Raw()..['origin'] = 'not a url at all!! ';
      expect(validateAuthPayload(raw).ok, isFalse);
    });

    test('origin with non-http(s) scheme is rejected', () {
      final raw = _validV3Raw()..['origin'] = 'ftp://example.com';
      expect(validateAuthPayload(raw).ok, isFalse);
    });
  });

  group('QrPayloadValidationResult', () {
    test('failure result carries stable errorKey for i18n lookup', () {
      final r = validateAuthPayload(_validV3Raw()..['nonce'] = '');
      expect(r.ok, isFalse);
      // Stable key that UI layer converts to AppLocalizations.invalidQrCode.
      expect(r.errorKey, equals('invalidQrCode'));
    });
  });
}
