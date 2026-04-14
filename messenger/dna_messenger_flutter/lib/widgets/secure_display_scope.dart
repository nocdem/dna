import 'package:flutter/material.dart';

import '../utils/screen_security.dart';

/// Wraps a child widget tree in Android FLAG_SECURE for the duration the widget
/// is mounted. Calls [ScreenSecurity.enable] in [State.initState] and
/// [ScreenSecurity.disable] in [State.dispose].
///
/// Use this to protect any screen or dialog that displays sensitive material
/// (e.g. seed phrases, recovery phrases).
///
/// ## Platform behavior
/// - **Android**: applies FLAG_SECURE via the existing [ScreenSecurity] helper,
///   blocking screenshots, screen recording, and recents-thumbnail leaks.
/// - **Linux / Windows**: no-op. Desktop platforms have no FLAG_SECURE
///   equivalent (X11 has no equivalent API, Wayland is fragmented, Windows
///   has only limited DRM APIs). Physical environment security is the user's
///   responsibility on desktop (SEC-10 / D-14).
/// - **iOS**: out of scope — not a current target platform.
///
/// ## Known limitation
/// The Android OS may still cache a screenshot in the recents thumbnail for a
/// tiny window before FLAG_SECURE is installed (race between `initState` and
/// the first frame). In practice this is imperceptible but documented here
/// for completeness.
///
/// ## Testing
/// The optional [onEnable] / [onDisable] parameters exist only for widget
/// tests (see [visibleForTesting]). They let tests assert the mount/dismount
/// contract without touching the real platform channel — necessary because
/// `Platform.isAndroid` is false on the Linux test host and the real
/// [ScreenSecurity.enable] would early-return before the channel is invoked.
class SecureDisplayScope extends StatefulWidget {
  const SecureDisplayScope({
    super.key,
    required this.child,
    @visibleForTesting this.onEnable,
    @visibleForTesting this.onDisable,
  });

  final Widget child;
  final Future<void> Function()? onEnable;
  final Future<void> Function()? onDisable;

  @override
  State<SecureDisplayScope> createState() => _SecureDisplayScopeState();
}

class _SecureDisplayScopeState extends State<SecureDisplayScope> {
  @override
  void initState() {
    super.initState();
    (widget.onEnable ?? ScreenSecurity.enable)();
  }

  @override
  void dispose() {
    (widget.onDisable ?? ScreenSecurity.disable)();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
