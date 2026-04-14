import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Storage keys — same string constants used before SEC-08 migration (D-16,
// drop-in replacement). Fields 1-4 below moved from SharedPreferences to
// FlutterSecureStorage in Phase 04 Plan 04-04 per C-04.
const _kAppLockEnabled = 'app_lock_enabled';
const _kBiometricsEnabled = 'app_lock_biometrics';
const _kPinHash = 'app_lock_pin_hash';
const _kPinSalt = 'app_lock_pin_salt';
const _kFailedAttempts = 'app_lock_failed_attempts';
const _kLockoutUntil = 'app_lock_lockout_until';

/// Keys migrated from SharedPreferences to secure storage. Used by the
/// one-shot migration function below.
const List<String> _kMigratedKeys = <String>[
  _kAppLockEnabled,
  _kBiometricsEnabled,
  _kFailedAttempts,
  _kLockoutUntil,
];

// Brute-force protection constants
const _maxAttemptsBeforeLockout = 5;
const _pbkdf2Iterations = 100000;
const _saltLength = 16;

/// Lockout durations: 5s, 15s, 30s, 60s, 120s, 300s (then stays at 300s)
const _lockoutDurations = [5, 15, 30, 60, 120, 300];

/// App lock configuration state
class AppLockState {
  final bool enabled;
  final bool biometricsEnabled;
  final bool pinSet;
  final int failedAttempts;
  final DateTime? lockoutUntil;

  const AppLockState({
    this.enabled = false,
    this.biometricsEnabled = false,
    this.pinSet = false,
    this.failedAttempts = 0,
    this.lockoutUntil,
  });

  bool get isLockedOut =>
      lockoutUntil != null && DateTime.now().isBefore(lockoutUntil!);

  Duration get remainingLockout {
    if (lockoutUntil == null) return Duration.zero;
    final remaining = lockoutUntil!.difference(DateTime.now());
    return remaining.isNegative ? Duration.zero : remaining;
  }

  AppLockState copyWith({
    bool? enabled,
    bool? biometricsEnabled,
    bool? pinSet,
    int? failedAttempts,
    DateTime? lockoutUntil,
    bool clearLockout = false,
  }) =>
      AppLockState(
        enabled: enabled ?? this.enabled,
        biometricsEnabled: biometricsEnabled ?? this.biometricsEnabled,
        pinSet: pinSet ?? this.pinSet,
        failedAttempts: failedAttempts ?? this.failedAttempts,
        lockoutUntil: clearLockout ? null : (lockoutUntil ?? this.lockoutUntil),
      );
}

/// App lock state notifier
class AppLockNotifier extends StateNotifier<AppLockState> {
  final FlutterSecureStorage _secureStorage;
  final LocalAuthentication _localAuth;

  AppLockNotifier()
      : _secureStorage = const FlutterSecureStorage(),
        _localAuth = LocalAuthentication(),
        super(const AppLockState()) {
    _load();
  }

  /// Test-only constructor that injects a custom [FlutterSecureStorage]
  /// instance so unit tests can supply a mock. Not part of the public API;
  /// production code uses the default constructor above.
  @visibleForTesting
  AppLockNotifier.withSecureStorage(FlutterSecureStorage secureStorage)
      : _secureStorage = secureStorage,
        _localAuth = LocalAuthentication(),
        super(const AppLockState()) {
    _load();
  }

  /// One-shot migration from legacy SharedPreferences storage to
  /// FlutterSecureStorage for the 4 app-lock fields (SEC-08, CONTEXT C-04).
  ///
  /// Invariants:
  ///   - Idempotent: safe to run on every launch. Second run is a no-op
  ///     because SharedPreferences entries have been deleted.
  ///   - Secure-wins-on-conflict: if secure storage already has a value for a
  ///     key, the SharedPreferences value is discarded (secure is canonical).
  ///   - Non-destructive of user state: legacy values are copied to secure
  ///     storage before the SharedPreferences entries are removed.
  ///
  /// This closes the app-lock bypass attack surface where a filesystem
  /// attacker could tamper with unencrypted SharedPreferences XML to flip
  /// `app_lock_enabled` to false or reset `app_lock_failed_attempts`.
  Future<void> _migrateFromSharedPreferencesIfNeeded() async {
    final prefs = await SharedPreferences.getInstance();
    for (final key in _kMigratedKeys) {
      if (!prefs.containsKey(key)) continue;

      final secureHas = await _secureStorage.containsKey(key: key);
      if (!secureHas) {
        final legacy = prefs.get(key);
        if (legacy != null) {
          await _secureStorage.write(key: key, value: legacy.toString());
        }
      }
      // Always delete the SharedPreferences entry: it's either been migrated
      // (secure now holds it) or shadowed by an existing secure value.
      await prefs.remove(key);
    }
  }

  Future<void> _load() async {
    // Step 1: migrate any pre-existing SharedPreferences state to secure
    // storage before the first state publication.
    await _migrateFromSharedPreferencesIfNeeded();

    // Step 2: read PIN hash (already in secure storage pre-SEC-08).
    String? pinHash;
    try {
      pinHash = await _secureStorage.read(key: _kPinHash);
    } catch (_) {
      pinHash = null;
    }

    // Step 3: read the 4 migrated fields from secure storage.
    final enabled = await _readSecureBool(_kAppLockEnabled);
    final biometricsEnabled = await _readSecureBool(_kBiometricsEnabled);
    final failedAttempts = await _readSecureInt(_kFailedAttempts);
    final lockoutUntil = await _readSecureLockoutUntil();

    state = AppLockState(
      enabled: enabled,
      biometricsEnabled: biometricsEnabled,
      pinSet: pinHash != null && pinHash.isNotEmpty,
      failedAttempts: failedAttempts,
      lockoutUntil: lockoutUntil,
    );
  }

  Future<bool> _readSecureBool(String key) async {
    try {
      final v = await _secureStorage.read(key: key);
      return v == 'true';
    } catch (_) {
      return false;
    }
  }

  Future<int> _readSecureInt(String key) async {
    try {
      final v = await _secureStorage.read(key: key);
      if (v == null) return 0;
      return int.tryParse(v) ?? 0;
    } catch (_) {
      return 0;
    }
  }

  Future<DateTime?> _readSecureLockoutUntil() async {
    try {
      final v = await _secureStorage.read(key: _kLockoutUntil);
      if (v == null) return null;
      final ms = int.tryParse(v) ?? 0;
      if (ms <= 0) return null;
      final dt = DateTime.fromMillisecondsSinceEpoch(ms);
      if (DateTime.now().isAfter(dt)) return null; // Expired.
      return dt;
    } catch (_) {
      return null;
    }
  }

  /// Enable/disable app lock
  Future<void> setEnabled(bool enabled) async {
    await _secureStorage.write(
        key: _kAppLockEnabled, value: enabled ? 'true' : 'false');
    state = state.copyWith(enabled: enabled);
  }

  /// Enable/disable biometrics
  Future<void> setBiometricsEnabled(bool enabled) async {
    await _secureStorage.write(
        key: _kBiometricsEnabled, value: enabled ? 'true' : 'false');
    state = state.copyWith(biometricsEnabled: enabled);
  }

  /// Set PIN (stores PBKDF2 hash with random salt)
  Future<void> setPin(String pin) async {
    final salt = _generateSalt();
    final hash = _pbkdf2Hash(pin, salt);
    await _secureStorage.write(key: _kPinSalt, value: base64Encode(salt));
    await _secureStorage.write(key: _kPinHash, value: hash);
    state = state.copyWith(pinSet: true);
  }

  /// Clear PIN
  Future<void> clearPin() async {
    await _secureStorage.delete(key: _kPinHash);
    await _secureStorage.delete(key: _kPinSalt);
    await _resetFailedAttempts();
    state = state.copyWith(pinSet: false);
  }

  /// Verify PIN with brute-force protection
  Future<bool> verifyPin(String pin) async {
    // Check lockout
    if (state.isLockedOut) return false;

    try {
      final storedHash = await _secureStorage.read(key: _kPinHash);
      if (storedHash == null) return false;

      // Check if salt exists (new PBKDF2 format) or not (legacy SHA-256)
      final storedSalt = await _secureStorage.read(key: _kPinSalt);
      bool matches;

      if (storedSalt != null && storedSalt.isNotEmpty) {
        // New format: PBKDF2 with salt
        final salt = base64Decode(storedSalt);
        final inputHash = _pbkdf2Hash(pin, salt);
        matches = inputHash == storedHash;
      } else {
        // Legacy format: unsalted SHA-256 — verify then migrate
        final legacyHash = sha256.convert(utf8.encode(pin)).toString();
        matches = legacyHash == storedHash;
        if (matches) {
          // Auto-migrate to PBKDF2
          await setPin(pin);
        }
      }

      if (matches) {
        await _resetFailedAttempts();
        state = state.copyWith(failedAttempts: 0, clearLockout: true);
        return true;
      } else {
        await _recordFailedAttempt();
        return false;
      }
    } catch (_) {
      return false;
    }
  }

  /// Record a failed PIN attempt and apply lockout if needed
  Future<void> _recordFailedAttempt() async {
    final attempts = (await _readSecureInt(_kFailedAttempts)) + 1;
    await _secureStorage.write(
        key: _kFailedAttempts, value: attempts.toString());

    DateTime? lockoutUntil;
    if (attempts >= _maxAttemptsBeforeLockout) {
      final lockoutIndex = ((attempts - _maxAttemptsBeforeLockout) ~/
              _maxAttemptsBeforeLockout)
          .clamp(0, _lockoutDurations.length - 1);
      final seconds = _lockoutDurations[lockoutIndex];
      lockoutUntil = DateTime.now().add(Duration(seconds: seconds));
      await _secureStorage.write(
          key: _kLockoutUntil,
          value: lockoutUntil.millisecondsSinceEpoch.toString());
    }

    state = state.copyWith(
      failedAttempts: attempts,
      lockoutUntil: lockoutUntil,
    );
  }

  /// Reset failed attempt counter
  Future<void> _resetFailedAttempts() async {
    await _secureStorage.delete(key: _kFailedAttempts);
    await _secureStorage.delete(key: _kLockoutUntil);
  }

  /// Generate random salt
  Uint8List _generateSalt() {
    final random = Random.secure();
    return Uint8List.fromList(
        List.generate(_saltLength, (_) => random.nextInt(256)));
  }

  /// PBKDF2-SHA256 hash
  String _pbkdf2Hash(String pin, Uint8List salt) {
    // PBKDF2 with HMAC-SHA256
    final pinBytes = utf8.encode(pin);
    var block = Uint8List(32); // SHA-256 output size

    // PBKDF2 single block (32 bytes is enough for PIN hash)
    final hmacKey = Hmac(sha256, pinBytes);
    // U1 = PRF(password, salt || INT(1))
    final saltPlusBlock = Uint8List(salt.length + 4);
    saltPlusBlock.setAll(0, salt);
    saltPlusBlock[salt.length + 3] = 1; // Block counter = 1
    var u = hmacKey.convert(saltPlusBlock).bytes;
    block = Uint8List.fromList(u);

    // U2..Un
    for (var i = 1; i < _pbkdf2Iterations; i++) {
      u = hmacKey.convert(u).bytes;
      for (var j = 0; j < block.length; j++) {
        block[j] ^= u[j];
      }
    }

    return base64Encode(block);
  }

  /// Check if biometrics available on this device
  Future<bool> isBiometricsAvailable() async {
    try {
      final canCheck = await _localAuth.canCheckBiometrics;
      if (!canCheck) return false;

      final available = await _localAuth.getAvailableBiometrics();
      return available.isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  /// Get available biometric types (for display)
  Future<List<BiometricType>> getAvailableBiometrics() async {
    try {
      return await _localAuth.getAvailableBiometrics();
    } catch (_) {
      return [];
    }
  }

  /// Authenticate with biometrics
  Future<bool> authenticateWithBiometrics() async {
    try {
      final canAuth = await _localAuth.canCheckBiometrics;
      final isDeviceSupported = await _localAuth.isDeviceSupported();

      if (!canAuth || !isDeviceSupported) {
        return false;
      }

      return await _localAuth.authenticate(
        localizedReason: 'Unlock DNA Connect',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: false,
        ),
      );
    } catch (_) {
      return false;
    }
  }
}

/// Whether app is currently locked (needs auth before continuing)
/// Defaults to true - app starts locked
final appLockedProvider = StateProvider<bool>((ref) => true);

/// App lock configuration provider
final appLockProvider = StateNotifierProvider<AppLockNotifier, AppLockState>(
  (ref) => AppLockNotifier(),
);
