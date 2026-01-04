// Notification Service - Cross-platform message notifications
// Phase 14: Push-style notifications for incoming messages

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Notification service provider
final notificationServiceProvider = Provider<NotificationService>((ref) {
  return NotificationService();
});

/// Callback for when user taps a notification
/// Returns the contact fingerprint to navigate to
typedef NotificationTapCallback = void Function(String contactFingerprint);

/// Cross-platform notification service for message alerts
class NotificationService {
  static final FlutterLocalNotificationsPlugin _notifications =
      FlutterLocalNotificationsPlugin();

  static const String _channelId = 'dna_messages';
  static const String _channelName = 'Messages';
  static const String _channelDescription = 'New message notifications';

  static NotificationTapCallback? _onNotificationTap;

  /// Initialize the notification service
  /// Call this once at app startup (e.g., in main.dart)
  static Future<void> initialize({
    NotificationTapCallback? onNotificationTap,
  }) async {
    _onNotificationTap = onNotificationTap;

    // Android initialization
    const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');

    // iOS/macOS initialization
    const darwinSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );

    // Linux initialization
    const linuxSettings = LinuxInitializationSettings(
      defaultActionName: 'Open',
    );

    const initSettings = InitializationSettings(
      android: androidSettings,
      iOS: darwinSettings,
      macOS: darwinSettings,
      linux: linuxSettings,
    );

    await _notifications.initialize(
      initSettings,
      onDidReceiveNotificationResponse: _onNotificationResponse,
    );

    // Create Android notification channel
    if (Platform.isAndroid) {
      await _createAndroidChannel();
      // Request notification permission (required for Android 13+)
      final granted = await _notifications
          .resolvePlatformSpecificImplementation<
              AndroidFlutterLocalNotificationsPlugin>()
          ?.requestNotificationsPermission();
      debugPrint('[Notifications] Android permission granted: $granted');
    }

    debugPrint('[Notifications] Initialized');
  }

  /// Create Android notification channel for messages
  static Future<void> _createAndroidChannel() async {
    const channel = AndroidNotificationChannel(
      _channelId,
      _channelName,
      description: _channelDescription,
      importance: Importance.high,
      playSound: true,
      enableVibration: true,
    );

    await _notifications
        .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>()
        ?.createNotificationChannel(channel);
  }

  /// Handle notification tap
  static void _onNotificationResponse(NotificationResponse response) {
    final payload = response.payload;
    debugPrint('[Notifications] Tapped notification with payload: $payload');

    if (payload != null && _onNotificationTap != null) {
      _onNotificationTap!(payload);
    }
  }

  /// Show a notification for a new message
  ///
  /// [senderName] - Display name of the sender
  /// [messagePreview] - First ~100 chars of the message
  /// [contactFingerprint] - Used as payload for navigation on tap
  /// [notificationId] - Optional unique ID (defaults to fingerprint hash)
  static Future<void> showMessageNotification({
    required String senderName,
    required String messagePreview,
    required String contactFingerprint,
    int? notificationId,
  }) async {
    // Generate notification ID from fingerprint if not provided
    final id = notificationId ?? contactFingerprint.hashCode.abs() % 100000;

    // Truncate message preview
    final preview = messagePreview.length > 100
        ? '${messagePreview.substring(0, 97)}...'
        : messagePreview;

    // Platform-specific notification details
    final androidDetails = AndroidNotificationDetails(
      _channelId,
      _channelName,
      channelDescription: _channelDescription,
      importance: Importance.high,
      priority: Priority.high,
      ticker: 'New message from $senderName',
      category: AndroidNotificationCategory.message,
      visibility: NotificationVisibility.private,
      // Show sender's initial as icon
      styleInformation: BigTextStyleInformation(
        preview,
        contentTitle: senderName,
        summaryText: 'DNA Messenger',
      ),
    );

    const darwinDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    );

    const linuxDetails = LinuxNotificationDetails(
      urgency: LinuxNotificationUrgency.normal,
    );

    final details = NotificationDetails(
      android: androidDetails,
      iOS: darwinDetails,
      macOS: darwinDetails,
      linux: linuxDetails,
    );

    await _notifications.show(
      id,
      senderName,
      preview,
      details,
      payload: contactFingerprint,
    );

    debugPrint('[Notifications] Showed notification for $senderName');
  }

  /// Cancel notification for a specific contact
  /// Call this when user opens the chat
  static Future<void> cancelForContact(String contactFingerprint) async {
    final id = contactFingerprint.hashCode.abs() % 100000;
    await _notifications.cancel(id);
    debugPrint('[Notifications] Cancelled notification for contact');
  }

  /// Cancel all notifications
  static Future<void> cancelAll() async {
    await _notifications.cancelAll();
    debugPrint('[Notifications] Cancelled all notifications');
  }

  /// Request notification permissions (iOS/macOS)
  static Future<bool> requestPermissions() async {
    if (Platform.isIOS || Platform.isMacOS) {
      final result = await _notifications
          .resolvePlatformSpecificImplementation<
              IOSFlutterLocalNotificationsPlugin>()
          ?.requestPermissions(
            alert: true,
            badge: true,
            sound: true,
          );
      return result ?? false;
    }

    if (Platform.isAndroid) {
      final result = await _notifications
          .resolvePlatformSpecificImplementation<
              AndroidFlutterLocalNotificationsPlugin>()
          ?.requestNotificationsPermission();
      return result ?? false;
    }

    // Linux/Windows don't require explicit permission
    return true;
  }
}
