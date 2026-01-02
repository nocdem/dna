import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Storage keys
const _kAppLockEnabled = 'app_lock_enabled';
const _kBiometricsEnabled = 'app_lock_biometrics';
const _kPinHash = 'app_lock_pin_hash';

/// App lock configuration state
class AppLockState {
  final bool enabled;
  final bool biometricsEnabled;
  final bool pinSet;

  const AppLockState({
    this.enabled = false,
    this.biometricsEnabled = false,
    this.pinSet = false,
  });

  AppLockState copyWith({
    bool? enabled,
    bool? biometricsEnabled,
    bool? pinSet,
  }) =>
      AppLockState(
        enabled: enabled ?? this.enabled,
        biometricsEnabled: biometricsEnabled ?? this.biometricsEnabled,
        pinSet: pinSet ?? this.pinSet,
      );
}

/// App lock state notifier
class AppLockNotifier extends StateNotifier<AppLockState> {
  final FlutterSecureStorage _secureStorage;
  final LocalAuthentication _localAuth;

  AppLockNotifier()
      : _secureStorage = const FlutterSecureStorage(
          aOptions: AndroidOptions(encryptedSharedPreferences: true),
        ),
        _localAuth = LocalAuthentication(),
        super(const AppLockState()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    String? pinHash;
    try {
      pinHash = await _secureStorage.read(key: _kPinHash);
    } catch (_) {
      // Secure storage may fail on some platforms
      pinHash = null;
    }

    state = AppLockState(
      enabled: prefs.getBool(_kAppLockEnabled) ?? false,
      biometricsEnabled: prefs.getBool(_kBiometricsEnabled) ?? false,
      pinSet: pinHash != null && pinHash.isNotEmpty,
    );
  }

  /// Enable/disable app lock
  Future<void> setEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kAppLockEnabled, enabled);
    state = state.copyWith(enabled: enabled);
  }

  /// Enable/disable biometrics
  Future<void> setBiometricsEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kBiometricsEnabled, enabled);
    state = state.copyWith(biometricsEnabled: enabled);
  }

  /// Set PIN (stores SHA-256 hash)
  Future<void> setPin(String pin) async {
    final hash = sha256.convert(utf8.encode(pin)).toString();
    await _secureStorage.write(key: _kPinHash, value: hash);
    state = state.copyWith(pinSet: true);
  }

  /// Clear PIN
  Future<void> clearPin() async {
    await _secureStorage.delete(key: _kPinHash);
    state = state.copyWith(pinSet: false);
  }

  /// Verify PIN
  Future<bool> verifyPin(String pin) async {
    try {
      final storedHash = await _secureStorage.read(key: _kPinHash);
      if (storedHash == null) return false;
      final inputHash = sha256.convert(utf8.encode(pin)).toString();
      return inputHash == storedHash;
    } catch (_) {
      return false;
    }
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
      return await _localAuth.authenticate(
        localizedReason: 'Unlock DNA Messenger',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
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
