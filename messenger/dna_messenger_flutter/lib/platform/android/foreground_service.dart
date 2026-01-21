// Android Foreground Service - Background execution management
// Phase 14: DHT-only messaging with reliable Android background support
//
// This file is ANDROID-ONLY but can be safely imported on other platforms.
// Platform checks prevent any actual service operations on non-Android.

import 'dart:io' show Platform;
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/engine_provider.dart';
import '../../providers/contacts_provider.dart';
import '../../providers/notification_settings_provider.dart';

/// MethodChannel for Android ForegroundService communication
class ForegroundServiceManager {
  static const _channel = MethodChannel('io.cpunk.dna_messenger/service');

  /// Start the foreground service
  static Future<bool> startService() async {
    try {
      final result = await _channel.invokeMethod<bool>('startService');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Stop the foreground service
  static Future<bool> stopService() async {
    try {
      final result = await _channel.invokeMethod<bool>('stopService');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Check if service is currently running
  static Future<bool> isServiceRunning() async {
    try {
      final result = await _channel.invokeMethod<bool>('isServiceRunning');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Trigger immediate poll for offline messages
  static Future<void> pollNow() async {
    try {
      await _channel.invokeMethod<void>('pollNow');
    } on PlatformException {
      // Silently ignore
    }
  }

  /// Request notification permission (Android 13+)
  static Future<bool> requestNotificationPermission() async {
    try {
      final result = await _channel.invokeMethod<bool>('requestNotificationPermission');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Check if exact alarms can be scheduled (Android 12+)
  /// Returns true on older Android versions or if permission is granted
  static Future<bool> canScheduleExactAlarms() async {
    try {
      final result = await _channel.invokeMethod<bool>('canScheduleExactAlarms');
      return result ?? true;
    } on PlatformException {
      return true;
    }
  }

  /// Request exact alarm permission (Android 12+)
  /// Opens system settings - user must manually enable
  static Future<void> requestExactAlarmPermission() async {
    try {
      await _channel.invokeMethod<void>('requestExactAlarmPermission');
    } on PlatformException {
      // Silently ignore
    }
  }

  /// Tell service whether Flutter is active (in foreground)
  /// When active, service pauses DHT operations to avoid interference
  static Future<void> setFlutterActive(bool active) async {
    try {
      await _channel.invokeMethod<void>('setFlutterActive', {'active': active});
    } on PlatformException {
      // Silently ignore - service might not be running
    }
  }

  /// Set up handler for service callbacks
  static void setMethodCallHandler(
      Future<dynamic> Function(MethodCall call)? handler) {
    _channel.setMethodCallHandler(handler);
  }
}

/// Provider for foreground service running state (Android only)
final foregroundServiceProvider =
    StateNotifierProvider<ForegroundServiceNotifier, bool>(
  (ref) => ForegroundServiceNotifier(ref),
);

/// Notifier that manages foreground service lifecycle
class ForegroundServiceNotifier extends StateNotifier<bool> {
  final Ref _ref;
  bool _initialized = false;

  ForegroundServiceNotifier(this._ref) : super(false) {
    _init();
  }

  void _init() {
    if (_initialized) return;
    _initialized = true;
    print('[ForegroundService] _init called');

    // Listen for identity changes to start/stop service
    _ref.listen<String?>(currentFingerprintProvider, (previous, next) {
      final prevShort = previous != null && previous.length >= 16 ? previous.substring(0, 16) : previous;
      final nextShort = next != null && next.length >= 16 ? next.substring(0, 16) : next;
      print('[ForegroundService] fingerprint changed: prev=$prevShort, next=$nextShort');
      if (next != null && next.isNotEmpty && (previous == null || previous.isEmpty)) {
        // Identity loaded - start service
        print('[ForegroundService] Identity loaded, starting service');
        _startService();
      } else if ((next == null || next.isEmpty) && previous != null && previous.isNotEmpty) {
        // Identity unloaded - stop service
        print('[ForegroundService] Identity unloaded, stopping service');
        _stopService();
      }
    }, fireImmediately: true);

    // Set up handler for service callbacks (e.g., new messages notification)
    ForegroundServiceManager.setMethodCallHandler(_handleServiceCall);
  }

  /// Handle callbacks from native service
  Future<dynamic> _handleServiceCall(MethodCall call) async {
    switch (call.method) {
      case 'onNewMessages':
        // Service detected new messages or requested poll
        await _pollOfflineMessages();
        // Refresh contacts to update UI
        _ref.invalidate(contactsProvider);
        break;
      case 'onNetworkChanged':
        // Network changed - Android service already reinited DHT via JNI.
        // Just refresh UI and poll for any messages that arrived.
        await _pollOfflineMessages();
        _ref.invalidate(contactsProvider);
        break;
    }
    return null;
  }

  /// Start the foreground service (only if notifications enabled)
  Future<void> _startService() async {
    // Only run on Android
    if (!Platform.isAndroid) {
      print('[ForegroundService] Not Android, skipping service start');
      return;
    }

    print('[ForegroundService] _startService called');

    // Check if user has notifications enabled
    final notificationSettings = _ref.read(notificationSettingsProvider);
    print('[ForegroundService] notifications enabled: ${notificationSettings.enabled}');
    if (!notificationSettings.enabled) {
      print('[ForegroundService] Notifications disabled, not starting service');
      return; // User disabled background notifications
    }

    final success = await ForegroundServiceManager.startService();
    print('[ForegroundService] startService result: $success');
    state = success;
  }

  /// Stop the foreground service
  Future<void> _stopService() async {
    await ForegroundServiceManager.stopService();
    state = false;
  }

  /// Poll for offline messages via engine
  Future<void> _pollOfflineMessages() async {
    try {
      final engine = await _ref.read(engineProvider.future);
      await engine.checkOfflineMessages();
    } catch (_) {
      // Ignore errors during background poll
    }
  }

  /// Force an immediate poll (can be called from UI)
  Future<void> forcePoll() async {
    await ForegroundServiceManager.pollNow();
  }
}
