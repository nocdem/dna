import 'package:flutter_test/flutter_test.dart';
import 'package:dna_connect/utils/log_sanitizer.dart';

void main() {
  group('LogSanitizer', () {
    test('redacts 12-word BIP39 mnemonic', () {
      const input = '[DEBUG] seed=abandon ability able about above absent '
                    'absorb abstract absurd abuse access accident done';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('[MNEMONIC REDACTED]'));
      expect(out, isNot(contains('abandon ability able')));
    });

    test('redacts long hex keys (>= 64 chars)', () {
      const input = 'secret=0123456789abcdef0123456789abcdef'
                    '0123456789abcdef0123456789abcdef tail';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('[KEY-'));
      expect(out, contains('REDACTED]'));
      expect(out, contains('tail'));
    });

    test('redacts password=value', () {
      const input = 'connecting with password=hunter2 to server';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('password=[REDACTED]'));
      expect(out, isNot(contains('hunter2')));
    });

    test('redacts token=value and secret=value', () {
      const input = 'auth token=abc123xyz and secret=shh';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('token=[REDACTED]'));
      expect(out, contains('secret=[REDACTED]'));
    });

    test('leaves normal log text untouched', () {
      const input = '2026-04-05 [INFO] user tapped button "Send"\n'
                    '[DEBUG] message id = 42 (not a key)';
      final out = LogSanitizer.scrub(input);
      expect(out, equals(input));
    });

    test('redacts base64 block >= 88 chars', () {
      final input = 'payload=${"A" * 100}== done';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('[B64-'));
    });
  });
}
