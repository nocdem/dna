import 'dart:io';
import 'package:flutter/services.dart';

/// Controls FLAG_SECURE on Android to prevent screenshots on sensitive screens.
/// No-op on desktop platforms.
class ScreenSecurity {
  static const _channel = MethodChannel('io.cpunk.dna_connect/screen_security');

  /// Enable FLAG_SECURE — blocks screenshots and recent apps thumbnail.
  static Future<void> enable() async {
    if (!Platform.isAndroid) return;
    try {
      await _channel.invokeMethod('enableSecureMode');
    } on MissingPluginException {
      // Not running on Android or channel not available
    }
  }

  /// Disable FLAG_SECURE — allows screenshots again.
  static Future<void> disable() async {
    if (!Platform.isAndroid) return;
    try {
      await _channel.invokeMethod('disableSecureMode');
    } on MissingPluginException {
      // Not running on Android or channel not available
    }
  }
}
