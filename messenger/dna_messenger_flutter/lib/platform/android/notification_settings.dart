// Android Notification Settings - Android-only notification UI
// This file is ANDROID-ONLY. It should only be imported on Android.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../providers/notification_settings_provider.dart';
import '../../utils/logger.dart' show log;
import 'foreground_service.dart';

/// Notification settings section for Android
/// Shows toggle for enabling/disabling notifications
class AndroidNotificationSettings extends ConsumerStatefulWidget {
  const AndroidNotificationSettings({super.key});

  @override
  ConsumerState<AndroidNotificationSettings> createState() =>
      _AndroidNotificationSettingsState();
}

class _AndroidNotificationSettingsState
    extends ConsumerState<AndroidNotificationSettings> {
  bool _canScheduleExactAlarms = true;

  @override
  void initState() {
    super.initState();
    _checkExactAlarmPermission();
  }

  Future<void> _checkExactAlarmPermission() async {
    final canSchedule = await ForegroundServiceManager.canScheduleExactAlarms();
    if (mounted) {
      setState(() {
        _canScheduleExactAlarms = canSchedule;
      });
    }
  }

  Future<void> _requestExactAlarmPermission() async {
    await ForegroundServiceManager.requestExactAlarmPermission();
    // Re-check after returning from settings (user may have toggled it)
    await Future.delayed(const Duration(milliseconds: 500));
    await _checkExactAlarmPermission();
  }

  Future<void> _toggleNotifications(bool enabled) async {
    if (enabled) {
      // Request notification permission on Android 13+
      try {
        final granted =
            await ForegroundServiceManager.requestNotificationPermission();
        if (!granted) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Notification permission denied'),
                duration: Duration(seconds: 2),
              ),
            );
          }
          return; // Don't enable if permission denied
        }
      } catch (e) {
        // Method channel not available (shouldn't happen on Android)
        log('SETTINGS', 'Error requesting notification permission: $e');
      }

      // Start foreground service
      await ForegroundServiceManager.startService();
    } else {
      // Stop foreground service
      await ForegroundServiceManager.stopService();
    }

    ref.read(notificationSettingsProvider.notifier).setEnabled(enabled);
  }

  @override
  Widget build(BuildContext context) {
    final settings = ref.watch(notificationSettingsProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SwitchListTile(
          secondary: const FaIcon(FontAwesomeIcons.bell),
          title: const Text('Background Notifications'),
          subtitle: const Text(
            'Keep app running in background to receive notifications when closed. '
            'Disabling saves battery but you won\'t get alerts until you open the app.',
          ),
          value: settings.enabled,
          onChanged: _toggleNotifications,
        ),
        // Exact alarm permission tile (only show when notifications enabled and permission not granted)
        if (settings.enabled && !_canScheduleExactAlarms)
          ListTile(
            leading: const FaIcon(FontAwesomeIcons.clock),
            title: const Text('Reliable Message Checking'),
            subtitle: const Text(
              'Enable exact alarms for reliable 5-minute message checks. '
              'Without this, checks may be delayed up to 10 minutes in battery saver mode.',
            ),
            trailing: TextButton(
              onPressed: _requestExactAlarmPermission,
              child: const Text('Enable'),
            ),
          ),
      ],
    );
  }
}
