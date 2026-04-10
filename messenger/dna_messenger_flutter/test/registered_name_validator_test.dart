import 'package:flutter_test/flutter_test.dart';
import 'package:dna_connect/utils/registered_name_validator.dart';

void main() {
  group('isValidRegisteredName', () {
    group('rejects', () {
      test('null', () {
        expect(isValidRegisteredName(null), isFalse);
      });

      test('empty string', () {
        expect(isValidRegisteredName(''), isFalse);
      });

      test('legacy fingerprint fallback (16 hex + ...)', () {
        expect(isValidRegisteredName('f8ebbbb9cb834ab8...'), isFalse);
      });

      test('another 16-hex + ...', () {
        expect(isValidRegisteredName('abcdef0123456789...'), isFalse);
      });

      test('trailing ... on short name', () {
        expect(isValidRegisteredName('name...'), isFalse);
      });

      test('bare 16 hex (fingerprint-like)', () {
        expect(isValidRegisteredName('f8ebbbb9cb834ab8'), isFalse);
      });

      test('32 hex chars', () {
        expect(isValidRegisteredName('f8ebbbb9cb834ab8fcc826f5b9e56316'), isFalse);
      });

      test('full 128-char fingerprint', () {
        final fp = 'f' * 128;
        expect(isValidRegisteredName(fp), isFalse);
      });

      test('overlong (>= 64 chars)', () {
        expect(isValidRegisteredName('a' * 64), isFalse);
        expect(isValidRegisteredName('a' * 100), isFalse);
      });
    });

    group('accepts', () {
      test('normal short name', () {
        expect(isValidRegisteredName('nocdem'), isTrue);
      });

      test('short alnum', () {
        expect(isValidRegisteredName('punk'), isTrue);
      });

      test('alphabetic', () {
        expect(isValidRegisteredName('alice'), isTrue);
      });

      test('mixed alnum', () {
        expect(isValidRegisteredName('user123'), isTrue);
      });

      test('with dash', () {
        expect(isValidRegisteredName('nocdem-test'), isTrue);
      });

      test('single char', () {
        expect(isValidRegisteredName('a'), isTrue);
      });

      test('10 hex chars (below fingerprint threshold)', () {
        expect(isValidRegisteredName('f8ebbbb9cb'), isTrue);
      });

      test('short hex-like (3 chars)', () {
        expect(isValidRegisteredName('abc'), isTrue);
      });

      test('with underscore', () {
        expect(isValidRegisteredName('test_user'), isTrue);
      });

      test('63 non-hex chars (just under limit)', () {
        expect(isValidRegisteredName('z' * 63), isTrue);
      });
    });
  });
}
