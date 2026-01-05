// Notification Settings Provider - User preferences for notifications
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Storage keys
const _kNotificationsEnabled = 'notifications_enabled';

/// Notification settings state
class NotificationSettingsState {
  final bool enabled;

  const NotificationSettingsState({
    this.enabled = true, // Enabled by default
  });

  NotificationSettingsState copyWith({
    bool? enabled,
  }) =>
      NotificationSettingsState(
        enabled: enabled ?? this.enabled,
      );
}

/// Notification settings state notifier
class NotificationSettingsNotifier extends StateNotifier<NotificationSettingsState> {
  NotificationSettingsNotifier() : super(const NotificationSettingsState()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    state = NotificationSettingsState(
      enabled: prefs.getBool(_kNotificationsEnabled) ?? true,
    );
  }

  /// Enable/disable notifications
  Future<void> setEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kNotificationsEnabled, enabled);
    state = state.copyWith(enabled: enabled);
  }
}

/// Provider for notification settings
final notificationSettingsProvider =
    StateNotifierProvider<NotificationSettingsNotifier, NotificationSettingsState>(
  (ref) => NotificationSettingsNotifier(),
);
