import 'package:flutter/services.dart';

/// Clipboard utilities with security features.
class ClipboardUtils {
  /// Copy sensitive text to clipboard and auto-clear after [delay].
  /// Use for seed phrases, private keys, and other sensitive data.
  static Future<void> copyWithAutoClear(
    String text, {
    Duration delay = const Duration(seconds: 30),
  }) async {
    await Clipboard.setData(ClipboardData(text: text));
    Future.delayed(delay, () async {
      // Only clear if clipboard still contains our text
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == text) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }
}
