import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../../providers/app_lock_provider.dart';
import '../../theme/dna_theme.dart';

/// Lock screen - requires biometric or PIN to unlock
class LockScreen extends ConsumerStatefulWidget {
  const LockScreen({super.key});

  @override
  ConsumerState<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends ConsumerState<LockScreen>
    with SingleTickerProviderStateMixin {
  String _enteredPin = '';
  bool _isAuthenticating = false;
  String? _error;
  late AnimationController _shakeController;
  late Animation<double> _shakeAnimation;
  final FocusNode _focusNode = FocusNode();

  @override
  void initState() {
    super.initState();
    _shakeController = AnimationController(
      duration: const Duration(milliseconds: 500),
      vsync: this,
    );
    _shakeAnimation = Tween<double>(begin: 0, end: 10).animate(
      CurvedAnimation(parent: _shakeController, curve: Curves.elasticIn),
    );

    // Auto-trigger biometric auth on load
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _tryBiometricAuth();
      // Request focus for keyboard input on desktop
      _focusNode.requestFocus();
    });
  }

  @override
  void dispose() {
    _shakeController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  /// Handle keyboard input for desktop
  void _handleKeyEvent(KeyEvent event) {
    if (event is! KeyDownEvent) return;
    if (_isAuthenticating) return;

    final key = event.logicalKey;

    // Digits 0-9
    if (key == LogicalKeyboardKey.digit0 || key == LogicalKeyboardKey.numpad0) {
      _onKeyPressed('0');
    } else if (key == LogicalKeyboardKey.digit1 || key == LogicalKeyboardKey.numpad1) {
      _onKeyPressed('1');
    } else if (key == LogicalKeyboardKey.digit2 || key == LogicalKeyboardKey.numpad2) {
      _onKeyPressed('2');
    } else if (key == LogicalKeyboardKey.digit3 || key == LogicalKeyboardKey.numpad3) {
      _onKeyPressed('3');
    } else if (key == LogicalKeyboardKey.digit4 || key == LogicalKeyboardKey.numpad4) {
      _onKeyPressed('4');
    } else if (key == LogicalKeyboardKey.digit5 || key == LogicalKeyboardKey.numpad5) {
      _onKeyPressed('5');
    } else if (key == LogicalKeyboardKey.digit6 || key == LogicalKeyboardKey.numpad6) {
      _onKeyPressed('6');
    } else if (key == LogicalKeyboardKey.digit7 || key == LogicalKeyboardKey.numpad7) {
      _onKeyPressed('7');
    } else if (key == LogicalKeyboardKey.digit8 || key == LogicalKeyboardKey.numpad8) {
      _onKeyPressed('8');
    } else if (key == LogicalKeyboardKey.digit9 || key == LogicalKeyboardKey.numpad9) {
      _onKeyPressed('9');
    } else if (key == LogicalKeyboardKey.backspace) {
      _onKeyPressed('backspace');
    } else if (key == LogicalKeyboardKey.enter || key == LogicalKeyboardKey.numpadEnter) {
      _onKeyPressed('confirm');
    }
  }

  Future<void> _tryBiometricAuth() async {
    final appLock = ref.read(appLockProvider);
    if (!appLock.biometricsEnabled) return;

    setState(() {
      _isAuthenticating = true;
      _error = null;
    });

    final success =
        await ref.read(appLockProvider.notifier).authenticateWithBiometrics();

    if (mounted) {
      setState(() => _isAuthenticating = false);
      if (success) {
        _unlock();
      }
    }
  }

  void _unlock() {
    ref.read(appLockedProvider.notifier).state = false;
  }

  void _onKeyPressed(String key) {
    HapticFeedback.lightImpact();

    if (key == 'backspace') {
      if (_enteredPin.isNotEmpty) {
        setState(() {
          _enteredPin = _enteredPin.substring(0, _enteredPin.length - 1);
          _error = null;
        });
      }
    } else if (key == 'confirm') {
      _verifyPin();
    } else {
      if (_enteredPin.length < 6) {
        setState(() {
          _enteredPin += key;
          _error = null;
        });
        // Auto-verify when 4+ digits entered
        if (_enteredPin.length >= 4) {
          _verifyPin();
        }
      }
    }
  }

  Future<void> _verifyPin() async {
    if (_enteredPin.length < 4) {
      setState(() => _error = 'PIN must be at least 4 digits');
      return;
    }

    setState(() => _isAuthenticating = true);

    final success =
        await ref.read(appLockProvider.notifier).verifyPin(_enteredPin);

    if (mounted) {
      setState(() => _isAuthenticating = false);
      if (success) {
        _unlock();
      } else {
        setState(() {
          _error = 'Incorrect PIN';
          _enteredPin = '';
        });
        _shakeController.forward(from: 0);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final appLock = ref.watch(appLockProvider);

    return Scaffold(
      backgroundColor: DnaColors.background,
      body: KeyboardListener(
        focusNode: _focusNode,
        onKeyEvent: _handleKeyEvent,
        child: SafeArea(
          child: Column(
            children: [
              const Spacer(flex: 2),
              // App icon and branding
              _buildHeader(),
              const Spacer(),
              // Biometric button (if available)
              if (appLock.biometricsEnabled) ...[
                _buildBiometricButton(),
                const SizedBox(height: 24),
                Text(
                  '- OR -',
                  style: TextStyle(
                    color: DnaColors.textMuted,
                    fontSize: 12,
                  ),
                ),
                const SizedBox(height: 24),
              ],
              // PIN dots
              AnimatedBuilder(
              animation: _shakeAnimation,
              builder: (context, child) {
                return Transform.translate(
                  offset: Offset(
                    _shakeAnimation.value *
                        ((_shakeController.value * 10).toInt().isEven ? 1 : -1),
                    0,
                  ),
                  child: child,
                );
              },
              child: _buildPinDots(),
            ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(
                _error!,
                style: const TextStyle(
                  color: DnaColors.textWarning,
                  fontSize: 14,
                ),
              ),
            ],
            const SizedBox(height: 32),
            // Number pad (constrained width for desktop)
            _buildNumberPad(),
            const Spacer(flex: 2),
          ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Column(
      children: [
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: DnaColors.surface,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: DnaColors.borderAccent),
          ),
          child: Center(
            child: SvgPicture.asset(
              'assets/logo-icon.svg',
              width: 48,
              height: 48,
            ),
          ),
        ),
        const SizedBox(height: 16),
        const Text(
          'DNA Messenger',
          style: TextStyle(
            color: DnaColors.text,
            fontSize: 24,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Enter PIN to unlock',
          style: TextStyle(
            color: DnaColors.textMuted,
            fontSize: 14,
          ),
        ),
      ],
    );
  }

  Widget _buildBiometricButton() {
    return GestureDetector(
      onTap: _isAuthenticating ? null : _tryBiometricAuth,
      child: Container(
        width: 64,
        height: 64,
        decoration: BoxDecoration(
          color: DnaColors.surface,
          borderRadius: BorderRadius.circular(32),
          border: Border.all(color: DnaColors.borderAccent),
        ),
        child: Center(
          child: _isAuthenticating
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: DnaColors.primary,
                  ),
                )
              : const FaIcon(
                  FontAwesomeIcons.fingerprint,
                  size: 32,
                  color: DnaColors.primary,
                ),
        ),
      ),
    );
  }

  Widget _buildPinDots() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: List.generate(6, (index) {
        final filled = index < _enteredPin.length;
        return Container(
          width: 16,
          height: 16,
          margin: const EdgeInsets.symmetric(horizontal: 8),
          decoration: BoxDecoration(
            color: filled ? DnaColors.primary : Colors.transparent,
            shape: BoxShape.circle,
            border: Border.all(
              color: filled ? DnaColors.primary : DnaColors.borderAccent,
              width: 2,
            ),
          ),
        );
      }),
    );
  }

  Widget _buildNumberPad() {
    const keys = [
      ['1', '2', '3'],
      ['4', '5', '6'],
      ['7', '8', '9'],
      ['backspace', '0', 'confirm'],
    ];

    // Fixed width keypad - doesn't stretch on desktop
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 280),
        child: Column(
          children: keys.map((row) {
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: row.map((key) {
                  return _buildKey(key);
                }).toList(),
              ),
            );
          }).toList(),
        ),
      ),
    );
  }

  Widget _buildKey(String key) {
    Widget child;
    if (key == 'backspace') {
      child = const FaIcon(
        FontAwesomeIcons.deleteLeft,
        size: 20,
        color: DnaColors.textMuted,
      );
    } else if (key == 'confirm') {
      child = const FaIcon(
        FontAwesomeIcons.check,
        size: 20,
        color: DnaColors.primary,
      );
    } else {
      child = Text(
        key,
        style: const TextStyle(
          color: DnaColors.text,
          fontSize: 24,
          fontWeight: FontWeight.w500,
        ),
      );
    }

    return GestureDetector(
      onTap: _isAuthenticating ? null : () => _onKeyPressed(key),
      child: Container(
        width: 64,
        height: 64,
        decoration: BoxDecoration(
          color: DnaColors.surface,
          borderRadius: BorderRadius.circular(32),
          border: Border.all(color: DnaColors.border),
        ),
        child: Center(child: child),
      ),
    );
  }
}
