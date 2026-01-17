import 'package:flutter_test/flutter_test.dart';
import 'package:dna_messenger/utils/qr_payload_parser.dart';

void main() {
  group('QR Payload Parser', () {
    group('Contact URI parsing', () {
      test('parses dna://contact with fingerprint and name', () {
        final fp = 'a' * 128; // 128 hex chars
        final payload = parseQrPayload('dna://contact?fp=$fp&name=Alice');

        expect(payload.type, QrPayloadType.contact);
        expect(payload.fingerprint, fp);
        expect(payload.displayName, 'Alice');
      });

      test('parses dna://onboard with fingerprint parameter', () {
        final fp = 'b' * 128;
        final payload = parseQrPayload('dna://onboard?fingerprint=$fp&displayName=Bob');

        expect(payload.type, QrPayloadType.contact);
        expect(payload.fingerprint, fp);
        expect(payload.displayName, 'Bob');
      });

      test('parses dna://contact with display_name underscore variant', () {
        final fp = 'c' * 128;
        final payload = parseQrPayload('dna://contact?fp=$fp&display_name=Charlie');

        expect(payload.type, QrPayloadType.contact);
        expect(payload.displayName, 'Charlie');
      });

      test('normalizes fingerprint to lowercase', () {
        final fp = 'A' * 128;
        final payload = parseQrPayload('dna://contact?fp=$fp');

        expect(payload.fingerprint, 'a' * 128);
      });

      test('rejects invalid fingerprint length', () {
        final payload = parseQrPayload('dna://contact?fp=tooshort&name=Test');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.fingerprint, isNull);
      });

      test('rejects non-hex fingerprint', () {
        final fp = 'g' * 128; // 'g' is not hex
        final payload = parseQrPayload('dna://contact?fp=$fp');

        expect(payload.type, QrPayloadType.plainText);
      });
    });

    group('Auth URI parsing', () {
      test('parses dna://auth with all fields', () {
        final payload = parseQrPayload(
          'dna://auth?app=MyApp&domain=example.com&challenge=abc123&scopes=read,write',
        );

        expect(payload.type, QrPayloadType.auth);
        expect(payload.appName, 'MyApp');
        expect(payload.domain, 'example.com');
        expect(payload.challenge, 'abc123');
        expect(payload.scopes, ['read', 'write']);
      });

      test('parses dna://login as auth type', () {
        final payload = parseQrPayload('dna://login?app=SSH&domain=server.local');

        expect(payload.type, QrPayloadType.auth);
        expect(payload.appName, 'SSH');
        expect(payload.domain, 'server.local');
      });

      test('parses auth with alternative parameter names', () {
        final payload = parseQrPayload(
          'dna://auth?appName=Test&service=test.com&nonce=xyz&callback=http://callback.url',
        );

        expect(payload.type, QrPayloadType.auth);
        expect(payload.appName, 'Test');
        expect(payload.domain, 'test.com');
        expect(payload.challenge, 'xyz');
        expect(payload.callbackUrl, 'http://callback.url');
      });

      test('handles missing optional fields', () {
        final payload = parseQrPayload('dna://auth?app=MinimalApp');

        expect(payload.type, QrPayloadType.auth);
        expect(payload.appName, 'MinimalApp');
        expect(payload.domain, isNull);
        expect(payload.challenge, isNull);
        expect(payload.scopes, isNull);
      });
    });

    group('JSON parsing', () {
      test('parses JSON contact payload', () {
        final fp = 'd' * 128;
        final payload = parseQrPayload('{"type":"contact","fingerprint":"$fp","name":"Dave"}');

        expect(payload.type, QrPayloadType.contact);
        expect(payload.fingerprint, fp);
        expect(payload.displayName, 'Dave');
      });

      test('parses JSON onboard type as contact', () {
        final fp = 'e' * 128;
        final payload = parseQrPayload('{"type":"onboard","fp":"$fp"}');

        expect(payload.type, QrPayloadType.contact);
        expect(payload.fingerprint, fp);
      });

      test('parses JSON auth payload', () {
        final payload = parseQrPayload(
          '{"type":"auth","app":"TestApp","domain":"test.com","challenge":"challenge123"}',
        );

        expect(payload.type, QrPayloadType.auth);
        expect(payload.appName, 'TestApp');
        expect(payload.domain, 'test.com');
        expect(payload.challenge, 'challenge123');
      });

      test('parses JSON login type as auth', () {
        final payload = parseQrPayload('{"type":"login","app":"SSHClient"}');

        expect(payload.type, QrPayloadType.auth);
        expect(payload.appName, 'SSHClient');
      });

      test('parses JSON scopes as array', () {
        final payload = parseQrPayload(
          '{"type":"auth","scopes":["read","write","admin"]}',
        );

        expect(payload.scopes, ['read', 'write', 'admin']);
      });

      test('parses JSON scopes as comma-separated string', () {
        final payload = parseQrPayload('{"type":"auth","scopes":"read,write"}');

        expect(payload.scopes, ['read', 'write']);
      });

      test('handles unknown JSON type as plain text', () {
        final payload = parseQrPayload('{"type":"unknown","data":"test"}');

        expect(payload.type, QrPayloadType.plainText);
      });

      test('handles invalid JSON as plain text', () {
        final payload = parseQrPayload('{not valid json}');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.rawContent, '{not valid json}');
      });
    });

    group('Plain text detection', () {
      test('detects plain text', () {
        final payload = parseQrPayload('Hello, this is plain text');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.rawContent, 'Hello, this is plain text');
        expect(payload.looksLikeUrl, false);
        expect(payload.looksLikeFingerprint, false);
      });

      test('detects URL with http://', () {
        final payload = parseQrPayload('http://example.com');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeUrl, true);
      });

      test('detects URL with https://', () {
        final payload = parseQrPayload('https://example.com/path');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeUrl, true);
      });

      test('detects URL starting with www.', () {
        final payload = parseQrPayload('www.example.com');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeUrl, true);
      });

      test('detects URL by domain pattern', () {
        final payload = parseQrPayload('example.com');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeUrl, true);
      });

      test('detects fingerprint (128 hex chars)', () {
        final fp = 'f' * 128;
        final payload = parseQrPayload(fp);

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeFingerprint, true);
      });

      test('detects mixed case fingerprint', () {
        final fp = 'aAbBcCdDeEfF' * 10 + 'aabbccdd';
        final payload = parseQrPayload(fp);

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeFingerprint, true);
      });

      test('does not detect short hex as fingerprint', () {
        final payload = parseQrPayload('abcdef123456');

        expect(payload.looksLikeFingerprint, false);
      });
    });

    group('Edge cases', () {
      test('handles empty string', () {
        final payload = parseQrPayload('');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.rawContent, '');
      });

      test('handles whitespace-only string', () {
        final payload = parseQrPayload('   ');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.rawContent, '');
      });

      test('trims whitespace from input', () {
        final fp = 'a' * 128;
        final payload = parseQrPayload('  dna://contact?fp=$fp  ');

        expect(payload.type, QrPayloadType.contact);
        expect(payload.fingerprint, fp);
      });

      test('handles unknown dna:// host', () {
        final payload = parseQrPayload('dna://unknown?param=value');

        expect(payload.type, QrPayloadType.plainText);
        expect(payload.looksLikeUrl, true);
      });

      test('preserves raw content in all payload types', () {
        final raw = 'dna://contact?fp=${'a' * 128}';
        final payload = parseQrPayload(raw);

        expect(payload.rawContent, raw);
      });
    });
  });
}
