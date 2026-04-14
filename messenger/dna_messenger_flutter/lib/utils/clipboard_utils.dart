import 'package:flutter/services.dart';

import 'logger.dart';

/// Clipboard utilities with security features.
///
/// SEC-09 (Phase 5) hardening model:
///   * Sensitive copies (seed phrases, private keys) go through
///     [copyWithAutoClear], which schedules an automatic clear after
///     [Duration(seconds: 10)] — shortened from the previous 30 s default so
///     any clipboard-reader attacker has a much narrower race window.
///   * A private module-level [_lastSensitiveCopy] tracks the most recent
///     sensitive copy. Both the auto-clear timer and [clearIfSensitive]
///     (called from [AppLifecycleObserver] on paused/hidden/detached) route
///     through the single [_clearAndForget] helper — one source of truth for
///     clear semantics.
///   * Non-match guard: if the current clipboard no longer matches the tracked
///     value (the user copied something else mid-window), the clear is a
///     no-op so we never clobber user content.
///   * Rapid successive copies: last-one-wins — the most recent sensitive
///     copy replaces any previous tracking (supersedes CONTEXT.md D-05
///     "first-one-wins" per 05-RESEARCH §1 task 05-01-04; the most recent
///     value is what actually matters for clearing).
///
/// Residual risk (not mitigated, accepted per user decision):
///   * Swipe-away / force-stop before the 10 s timer fires AND before
///     AppLifecycleState.paused gets CPU time — Android tears the process
///     down without guaranteeing async Dart work completes. Userland cannot
///     defend against this; OS cooperation required.
///   * OS-level clipboard history (Gboard, Samsung launcher, etc.) may
///     retain the value outside the app clipboard API.
class ClipboardUtils {
  /// Most recent sensitive copy. Cleared by [_clearAndForget] once the
  /// clipboard has been wiped (or confirmed non-matching).
  static String? _lastSensitiveCopy;

  /// Copy sensitive text to clipboard and auto-clear after [delay].
  ///
  /// Use for seed phrases, private keys, and other sensitive data. The
  /// default [delay] is the SEC-09 hardened window of 10 seconds.
  ///
  /// NOTE: signature unchanged from the pre-Phase-5 version (parameter names
  /// and types identical) — RC stability rule (D-30).
  static Future<void> copyWithAutoClear(
    String text, {
    Duration delay = const Duration(seconds: 10),
  }) async {
    await Clipboard.setData(ClipboardData(text: text));
    // Last-one-wins: the most recent sensitive copy is the one we'll try to
    // clear. A second copyWithAutoClear within the window simply replaces
    // the tracked value.
    _lastSensitiveCopy = text;
    Future.delayed(delay, _clearAndForget);
  }

  /// Clears the system clipboard if and only if it still holds the most
  /// recent sensitive copy tracked by [copyWithAutoClear].
  ///
  /// Called by [AppLifecycleObserver] on `paused`/`hidden`/`detached` to
  /// collapse the exfiltration race window to ~zero on normal backgrounding
  /// (home, task switch, lock).
  ///
  /// Safe to call at any time — if no sensitive copy is currently tracked,
  /// or if the clipboard has been overwritten by the user copying something
  /// else, this is a no-op.
  static Future<void> clearIfSensitive() => _clearAndForget();

  /// Single source of truth for the clear path. Shared by the auto-clear
  /// timer and the lifecycle hook.
  static Future<void> _clearAndForget() async {
    final tracked = _lastSensitiveCopy;
    if (tracked == null) {
      return;
    }
    try {
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      // Non-match guard — never clobber clipboard content the user copied
      // from elsewhere after the sensitive copy.
      if (current?.text == tracked) {
        await Clipboard.setData(const ClipboardData(text: ''));
        log('CLIPBOARD', 'Sensitive clipboard content cleared (SEC-09)');
      }
    } catch (e) {
      // Platform clipboard may not be available (e.g. headless test host
      // without a binary messenger mock). Fail closed — drop the tracking
      // slot so we don't leak across test cases or restarts.
      log('CLIPBOARD', 'clearIfSensitive error: $e');
    } finally {
      _lastSensitiveCopy = null;
    }
  }
}
