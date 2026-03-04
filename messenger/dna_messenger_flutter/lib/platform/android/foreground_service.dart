// Android Foreground Service - Background execution management
// v0.101.25+: Service is just a process keep-alive. Engine stays alive via pause/resume.
// No polling, no engine management — notifications come via JNI callback.
//
// This file is ANDROID-ONLY but can be safely imported on other platforms.

import 'dart:io' show Platform;
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/engine_provider.dart';
import '../../providers/contacts_provider.dart';
import '../../providers/notification_settings_provider.dart';
import '../../utils/logger.dart';

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

  /// Request notification permission (Android 13+)
  static Future<bool> requestNotificationPermission() async {
    try {
      final result = await _channel.invokeMethod<bool>('requestNotificationPermission');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Clear background notifications (called when app resumes)
  static Future<void> clearNotifications() async {
    try {
      await _channel.invokeMethod<void>('clearNotifications');
    } on PlatformException {
      // Silently ignore - service might not be running
    }
  }

  /// Tell service Flutter is paused (for notification clearing logic only)
  static Future<void> setFlutterPaused(bool paused) async {
    try {
      await _channel.invokeMethod<void>('setFlutterPaused', {'paused': paused});
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
    logPrint('[ForegroundService] _init called');

    // Listen for identity changes to start/stop service
    _ref.listen<String?>(currentFingerprintProvider, (previous, next) {
      final prevShort = previous != null && previous.length >= 16 ? previous.substring(0, 16) : previous;
      final nextShort = next != null && next.length >= 16 ? next.substring(0, 16) : next;
      logPrint('[ForegroundService] fingerprint changed: prev=$prevShort, next=$nextShort');
      if (next != null && next.isNotEmpty && (previous == null || previous.isEmpty)) {
        logPrint('[ForegroundService] Identity loaded, starting service');
        _startService();
      } else if ((next == null || next.isEmpty) && previous != null && previous.isNotEmpty) {
        logPrint('[ForegroundService] Identity unloaded, stopping service');
        _stopService();
      }
    }, fireImmediately: true);

    // Set up handler for service callbacks
    ForegroundServiceManager.setMethodCallHandler(_handleServiceCall);
  }

  /// Handle callbacks from native service
  Future<dynamic> _handleServiceCall(MethodCall call) async {
    switch (call.method) {
      case 'onNetworkChanged':
        // Network changed - service already reinited DHT via JNI.
        // Refresh UI.
        _ref.invalidate(contactsProvider);
        break;
    }
    return null;
  }

  /// Start the foreground service (only if notifications enabled)
  Future<void> _startService() async {
    if (!Platform.isAndroid) {
      logPrint('[ForegroundService] Not Android, skipping service start');
      return;
    }

    logPrint('[ForegroundService] _startService called');

    final notificationSettings = _ref.read(notificationSettingsProvider);
    logPrint('[ForegroundService] notifications enabled: ${notificationSettings.enabled}');
    if (!notificationSettings.enabled) {
      logPrint('[ForegroundService] Notifications disabled, not starting service');
      return;
    }

    final success = await ForegroundServiceManager.startService();
    logPrint('[ForegroundService] startService result: $success');
    state = success;
  }

  /// Stop the foreground service
  Future<void> _stopService() async {
    await ForegroundServiceManager.stopService();
    state = false;
  }
}
