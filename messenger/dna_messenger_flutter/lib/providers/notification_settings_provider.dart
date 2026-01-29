// Notification Settings Provider - User preferences for notifications
// v0.100.64+: Added configurable poll interval
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Storage keys
const _kNotificationsEnabled = 'notifications_enabled';
const _kPollIntervalMinutes = 'poll_interval_minutes';

/// Available poll interval options (in minutes)
const pollIntervalOptions = [1, 2, 5, 10, 15];

/// Notification settings state
class NotificationSettingsState {
  final bool enabled;
  final int pollIntervalMinutes;

  const NotificationSettingsState({
    this.enabled = true, // Enabled by default
    this.pollIntervalMinutes = 5, // 5 minutes default
  });

  NotificationSettingsState copyWith({
    bool? enabled,
    int? pollIntervalMinutes,
  }) =>
      NotificationSettingsState(
        enabled: enabled ?? this.enabled,
        pollIntervalMinutes: pollIntervalMinutes ?? this.pollIntervalMinutes,
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
      pollIntervalMinutes: prefs.getInt(_kPollIntervalMinutes) ?? 5,
    );
  }

  /// Enable/disable notifications
  Future<void> setEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kNotificationsEnabled, enabled);
    state = state.copyWith(enabled: enabled);
  }

  /// Set poll interval in minutes
  Future<void> setPollInterval(int minutes) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_kPollIntervalMinutes, minutes);
    state = state.copyWith(pollIntervalMinutes: minutes);
  }
}

/// Provider for notification settings
final notificationSettingsProvider =
    StateNotifierProvider<NotificationSettingsNotifier, NotificationSettingsState>(
  (ref) => NotificationSettingsNotifier(),
);
