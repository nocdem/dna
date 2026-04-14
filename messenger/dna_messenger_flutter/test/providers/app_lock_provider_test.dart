// test/providers/app_lock_provider_test.dart
//
// SEC-08: AppLockProvider SharedPreferences → FlutterSecureStorage migration.
//
// Covers the one-shot migration of 4 fields (per C-04):
//   - app_lock_enabled
//   - app_lock_biometrics
//   - app_lock_failed_attempts
//   - app_lock_lockout_until
//
// Public API of AppLockNotifier must remain unchanged. The tests below
// construct AppLockNotifier.withSecureStorage (a @visibleForTesting named
// constructor — additive, not a breaking change) to inject a mocked
// FlutterSecureStorage. SharedPreferences is mocked via the framework helper
// SharedPreferences.setMockInitialValues.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:mocktail/mocktail.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:dna_connect/providers/app_lock_provider.dart';

class _MockSecureStorage extends Mock implements FlutterSecureStorage {}

/// In-memory secure-storage backing table used by the mock. Each test gets
/// a fresh map so state does not leak across cases.
class _FakeSecure {
  final Map<String, String> store = {};

  void wireMock(_MockSecureStorage mock) {
    when(() => mock.read(key: any(named: 'key'))).thenAnswer(
      (inv) async => store[inv.namedArguments[#key] as String],
    );
    when(() => mock.write(
          key: any(named: 'key'),
          value: any(named: 'value'),
        )).thenAnswer((inv) async {
      final key = inv.namedArguments[#key] as String;
      final value = inv.namedArguments[#value] as String?;
      if (value == null) {
        store.remove(key);
      } else {
        store[key] = value;
      }
    });
    when(() => mock.delete(key: any(named: 'key'))).thenAnswer((inv) async {
      store.remove(inv.namedArguments[#key] as String);
    });
    when(() => mock.containsKey(key: any(named: 'key'))).thenAnswer(
      (inv) async => store.containsKey(inv.namedArguments[#key] as String),
    );
  }
}

/// Pump the Dart event loop until AppLockNotifier's async _load() settles.
Future<void> _settle() async {
  // _load() awaits two secure-storage reads plus a SharedPreferences future.
  // A handful of microtask flushes is enough in practice; 10 is safe.
  for (var i = 0; i < 10; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MockSecureStorage secure;
  late _FakeSecure fake;

  setUp(() {
    secure = _MockSecureStorage();
    fake = _FakeSecure()..wireMock(secure);
  });

  group('SEC-08 AppLockProvider storage migration', () {
    test('fresh install — no legacy, state is defaults', () async {
      SharedPreferences.setMockInitialValues(<String, Object>{});

      final notifier = AppLockNotifier.withSecureStorage(secure);
      await _settle();

      expect(notifier.state.enabled, isFalse);
      expect(notifier.state.biometricsEnabled, isFalse);
      expect(notifier.state.failedAttempts, 0);
      expect(notifier.state.lockoutUntil, isNull);

      // Nothing should have been seeded into secure storage by migration.
      expect(fake.store.containsKey('app_lock_enabled'), isFalse);
      expect(fake.store.containsKey('app_lock_biometrics'), isFalse);
      expect(fake.store.containsKey('app_lock_failed_attempts'), isFalse);
      expect(fake.store.containsKey('app_lock_lockout_until'), isFalse);

      notifier.dispose();
    });

    test('legacy SharedPreferences state migrates to secure storage',
        () async {
      final lockoutMs =
          DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch;
      SharedPreferences.setMockInitialValues(<String, Object>{
        'app_lock_enabled': true,
        'app_lock_biometrics': true,
        'app_lock_failed_attempts': 3,
        'app_lock_lockout_until': lockoutMs,
      });

      final notifier = AppLockNotifier.withSecureStorage(secure);
      await _settle();

      // Secure storage now holds the migrated values (as strings).
      expect(fake.store['app_lock_enabled'], 'true');
      expect(fake.store['app_lock_biometrics'], 'true');
      expect(fake.store['app_lock_failed_attempts'], '3');
      expect(fake.store['app_lock_lockout_until'], lockoutMs.toString());

      // SharedPreferences entries deleted after migration.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.containsKey('app_lock_enabled'), isFalse);
      expect(prefs.containsKey('app_lock_biometrics'), isFalse);
      expect(prefs.containsKey('app_lock_failed_attempts'), isFalse);
      expect(prefs.containsKey('app_lock_lockout_until'), isFalse);

      // State reflects the legacy values.
      expect(notifier.state.enabled, isTrue);
      expect(notifier.state.biometricsEnabled, isTrue);
      expect(notifier.state.failedAttempts, 3);
      expect(notifier.state.lockoutUntil, isNotNull);
      expect(notifier.state.lockoutUntil!.millisecondsSinceEpoch, lockoutMs);

      notifier.dispose();
    });

    test('idempotent: secure storage wins on conflict', () async {
      // Both stores have the key, with different values. Secure wins.
      SharedPreferences.setMockInitialValues(<String, Object>{
        'app_lock_failed_attempts': 9,
      });
      fake.store['app_lock_failed_attempts'] = '2';

      final notifier = AppLockNotifier.withSecureStorage(secure);
      await _settle();

      // Secure value preserved.
      expect(fake.store['app_lock_failed_attempts'], '2');

      // SharedPreferences entry deleted regardless.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.containsKey('app_lock_failed_attempts'), isFalse);

      // State reflects secure value, not legacy.
      expect(notifier.state.failedAttempts, 2);

      notifier.dispose();
    });

    test('second launch after migration does not touch SharedPreferences',
        () async {
      // Simulate already-migrated state: secure populated, SharedPreferences
      // empty.
      SharedPreferences.setMockInitialValues(<String, Object>{});
      fake.store['app_lock_enabled'] = 'true';
      fake.store['app_lock_biometrics'] = 'false';
      fake.store['app_lock_failed_attempts'] = '0';

      final notifier = AppLockNotifier.withSecureStorage(secure);
      await _settle();

      // State loaded from secure.
      expect(notifier.state.enabled, isTrue);
      expect(notifier.state.biometricsEnabled, isFalse);

      // SharedPreferences should still be empty (no writes happened).
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getKeys(), isEmpty);

      notifier.dispose();
    });

    test('lockout state survives provider recreation', () async {
      SharedPreferences.setMockInitialValues(<String, Object>{});

      // First instance: seed a future lockout directly via secure storage,
      // matching what _recordFailedAttempt would do.
      final future = DateTime(2099, 1, 1);
      fake.store['app_lock_lockout_until'] =
          future.millisecondsSinceEpoch.toString();
      fake.store['app_lock_failed_attempts'] = '5';
      fake.store['app_lock_enabled'] = 'true';

      // Recreate the provider (simulating process restart — same backing
      // secure storage).
      final notifier = AppLockNotifier.withSecureStorage(secure);
      await _settle();

      expect(notifier.state.isLockedOut, isTrue);
      expect(notifier.state.lockoutUntil, isNotNull);
      expect(notifier.state.lockoutUntil!.year, 2099);
      expect(notifier.state.failedAttempts, 5);

      notifier.dispose();
    });

    test('bypass guard: flipping SharedPreferences app_lock_enabled does '
        'not disable lock', () async {
      // Secure storage is authoritative. Attacker tampers with
      // SharedPreferences after migration.
      fake.store['app_lock_enabled'] = 'true';
      SharedPreferences.setMockInitialValues(<String, Object>{
        'app_lock_enabled': false, // attacker-controlled
      });

      final notifier = AppLockNotifier.withSecureStorage(secure);
      await _settle();

      // Lock remains enabled (secure wins).
      expect(notifier.state.enabled, isTrue);
      // And the attacker's SharedPreferences entry was scrubbed.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.containsKey('app_lock_enabled'), isFalse);
      // Secure storage still holds 'true'.
      expect(fake.store['app_lock_enabled'], 'true');

      notifier.dispose();
    });

    test('public API shape preserved (compile-time check)', () {
      // Referencing these symbols forces the compiler to verify their
      // signatures. A broken public API breaks this test file's compilation.
      const state = AppLockState();
      expect(state.enabled, isFalse);
      expect(state.biometricsEnabled, isFalse);
      expect(state.pinSet, isFalse);
      expect(state.failedAttempts, 0);
      expect(state.lockoutUntil, isNull);
      // Riverpod provider symbol.
      expect(appLockProvider, isNotNull);
      // Type existence.
      expect(AppLockNotifier, isNotNull);
    });
  });
}
