// Notification Service - Local notifications for incoming messages
//
// Uses flutter_local_notifications for cross-platform support:
// - Android: NotificationChannel with default notification sound
// - Linux: libnotify via D-Bus
// - Windows: Win32 toast notifications

import 'dart:io' show Platform;
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import '../utils/logger.dart' as logger;

class NotificationService {
  static final NotificationService _instance = NotificationService._();
  static NotificationService get instance => _instance;

  final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  bool _initialized = false;

  NotificationService._();

  /// Initialize the notification plugin. Call once at app startup.
  Future<void> init() async {
    if (_initialized) return;

    const androidSettings =
        AndroidInitializationSettings('@mipmap/ic_launcher');

    const linuxSettings =
        LinuxInitializationSettings(defaultActionName: 'Open');

    const initSettings = InitializationSettings(
      android: androidSettings,
      linux: linuxSettings,
    );

    final success = await _plugin.initialize(initSettings);
    _initialized = success ?? false;

    if (_initialized) {
      logger.log('NOTIFY', 'Notification service initialized');
    } else {
      logger.log('NOTIFY', 'Failed to initialize notifications');
    }

    // Request notification permission on Android 13+
    if (Platform.isAndroid) {
      await _requestAndroidPermission();
    }
  }

  /// Request POST_NOTIFICATIONS permission (Android 13+)
  Future<void> _requestAndroidPermission() async {
    final androidPlugin =
        _plugin.resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>();
    if (androidPlugin != null) {
      await androidPlugin.requestNotificationsPermission();
    }
  }

  /// Show a notification for an incoming message.
  Future<void> showMessageNotification({
    required String senderName,
    required String messagePreview,
    int id = 0,
  }) async {
    if (!_initialized) return;

    const androidDetails = AndroidNotificationDetails(
      'dna_messages',
      'Messages',
      channelDescription: 'Incoming message notifications',
      importance: Importance.high,
      priority: Priority.high,
      playSound: true,
      enableVibration: true,
      visibility: NotificationVisibility.private,
    );

    const linuxDetails = LinuxNotificationDetails();

    const details = NotificationDetails(
      android: androidDetails,
      linux: linuxDetails,
    );

    await _plugin.show(
      id,
      senderName,
      messagePreview,
      details,
    );
  }
}
