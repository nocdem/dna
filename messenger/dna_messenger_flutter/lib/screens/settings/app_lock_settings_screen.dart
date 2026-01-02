import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../../providers/app_lock_provider.dart';
import '../../theme/dna_theme.dart';

/// App Lock settings screen
class AppLockSettingsScreen extends ConsumerStatefulWidget {
  const AppLockSettingsScreen({super.key});

  @override
  ConsumerState<AppLockSettingsScreen> createState() =>
      _AppLockSettingsScreenState();
}

class _AppLockSettingsScreenState extends ConsumerState<AppLockSettingsScreen> {
  bool _biometricsAvailable = false;

  @override
  void initState() {
    super.initState();
    _checkBiometrics();
  }

  Future<void> _checkBiometrics() async {
    final available =
        await ref.read(appLockProvider.notifier).isBiometricsAvailable();
    if (mounted) {
      setState(() => _biometricsAvailable = available);
    }
  }

  Future<void> _toggleAppLock(bool enabled) async {
    final appLock = ref.read(appLockProvider);

    if (enabled) {
      // Enabling - must set PIN first
      if (!appLock.pinSet) {
        final pin = await _showSetPinDialog();
        if (pin == null) return; // User cancelled
        await ref.read(appLockProvider.notifier).setPin(pin);
      }
      await ref.read(appLockProvider.notifier).setEnabled(true);
    } else {
      // Disabling - verify current PIN first
      final verified = await _showVerifyPinDialog();
      if (!verified) return;
      await ref.read(appLockProvider.notifier).setEnabled(false);
    }
  }

  Future<void> _toggleBiometrics(bool enabled) async {
    if (enabled) {
      // Test biometrics before enabling
      final success =
          await ref.read(appLockProvider.notifier).authenticateWithBiometrics();
      if (!success) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Biometric authentication failed')),
          );
        }
        return;
      }
    }
    await ref.read(appLockProvider.notifier).setBiometricsEnabled(enabled);
  }

  Future<void> _changePin() async {
    // Verify current PIN first
    final verified = await _showVerifyPinDialog();
    if (!verified) return;

    // Set new PIN
    final newPin = await _showSetPinDialog();
    if (newPin == null) return;

    await ref.read(appLockProvider.notifier).setPin(newPin);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('PIN changed successfully')),
      );
    }
  }

  Future<String?> _showSetPinDialog() async {
    String pin1 = '';
    String pin2 = '';
    String? error;
    int step = 1;

    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setDialogState) {
            return AlertDialog(
              title: Text(step == 1 ? 'Set PIN' : 'Confirm PIN'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    step == 1
                        ? 'Enter a 4-6 digit PIN'
                        : 'Enter the same PIN again',
                    style: const TextStyle(color: DnaColors.textMuted),
                  ),
                  const SizedBox(height: 16),
                  _PinEntryField(
                    key: ValueKey('pin_entry_$step'),
                    onChanged: (value) {
                      setDialogState(() {
                        if (step == 1) {
                          pin1 = value;
                        } else {
                          pin2 = value;
                        }
                        error = null;
                      });
                    },
                  ),
                  if (error != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      error!,
                      style: const TextStyle(color: DnaColors.textWarning),
                    ),
                  ],
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, null),
                  child: const Text('Cancel'),
                ),
                TextButton(
                  onPressed: () {
                    final currentPin = step == 1 ? pin1 : pin2;
                    if (currentPin.length < 4) {
                      setDialogState(
                          () => error = 'PIN must be at least 4 digits');
                      return;
                    }
                    if (step == 1) {
                      setDialogState(() {
                        step = 2;
                        error = null;
                      });
                    } else {
                      if (pin1 != pin2) {
                        setDialogState(() => error = 'PINs do not match');
                        return;
                      }
                      Navigator.pop(context, pin1);
                    }
                  },
                  child: Text(step == 1 ? 'Next' : 'Set PIN'),
                ),
              ],
            );
          },
        );
      },
    );
  }

  Future<bool> _showVerifyPinDialog() async {
    String pin = '';
    String? error;

    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setDialogState) {
            return AlertDialog(
              title: const Text('Enter Current PIN'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    'Enter your current PIN to continue',
                    style: TextStyle(color: DnaColors.textMuted),
                  ),
                  const SizedBox(height: 16),
                  _PinEntryField(
                    onChanged: (value) {
                      setDialogState(() {
                        pin = value;
                        error = null;
                      });
                    },
                  ),
                  if (error != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      error!,
                      style: const TextStyle(color: DnaColors.textWarning),
                    ),
                  ],
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('Cancel'),
                ),
                TextButton(
                  onPressed: () async {
                    if (pin.length < 4) {
                      setDialogState(
                          () => error = 'PIN must be at least 4 digits');
                      return;
                    }
                    final verified =
                        await ref.read(appLockProvider.notifier).verifyPin(pin);
                    if (verified) {
                      if (context.mounted) Navigator.pop(context, true);
                    } else {
                      setDialogState(() => error = 'Incorrect PIN');
                    }
                  },
                  child: const Text('Verify'),
                ),
              ],
            );
          },
        );
      },
    );

    return result ?? false;
  }

  @override
  Widget build(BuildContext context) {
    final appLock = ref.watch(appLockProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('App Lock'),
      ),
      body: ListView(
        children: [
          // Enable app lock
          SwitchListTile(
            secondary: const FaIcon(FontAwesomeIcons.lock),
            title: const Text('Enable App Lock'),
            subtitle: const Text('Require authentication to open app'),
            value: appLock.enabled,
            onChanged: _toggleAppLock,
          ),

          if (appLock.enabled) ...[
            const Divider(),

            // Biometrics toggle (if available)
            if (_biometricsAvailable) ...[
              SwitchListTile(
                secondary: const FaIcon(FontAwesomeIcons.fingerprint),
                title: const Text('Use Biometrics'),
                subtitle: const Text('Fingerprint or Face ID'),
                value: appLock.biometricsEnabled,
                onChanged: _toggleBiometrics,
              ),
            ],

            // Change PIN
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.hashtag),
              title: const Text('Change PIN'),
              subtitle: const Text('Update your unlock PIN'),
              trailing: const FaIcon(FontAwesomeIcons.chevronRight),
              onTap: _changePin,
            ),
          ],
        ],
      ),
    );
  }
}

/// PIN entry text field for dialogs
class _PinEntryField extends StatefulWidget {
  final ValueChanged<String> onChanged;

  const _PinEntryField({super.key, required this.onChanged});

  @override
  State<_PinEntryField> createState() => _PinEntryFieldState();
}

class _PinEntryFieldState extends State<_PinEntryField> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: _controller,
      keyboardType: TextInputType.number,
      obscureText: true,
      maxLength: 6,
      textAlign: TextAlign.center,
      style: const TextStyle(
        fontSize: 24,
        letterSpacing: 8,
      ),
      inputFormatters: [
        FilteringTextInputFormatter.digitsOnly,
        LengthLimitingTextInputFormatter(6),
      ],
      decoration: const InputDecoration(
        counterText: '',
        hintText: '••••',
      ),
      autofocus: true,
      onChanged: widget.onChanged,
    );
  }
}
