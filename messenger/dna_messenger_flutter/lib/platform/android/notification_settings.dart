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
      ],
    );
  }
}
