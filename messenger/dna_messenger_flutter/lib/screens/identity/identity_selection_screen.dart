// Identity Selection Screen - Unified onboarding flow
// v0.3.0: Single-user model with merged create/restore flow
// v0.4.60: Added auto-sync backup check on identity load
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../../utils/logger.dart' show log, logError;

/// Entry point for onboarding - in v0.3.0 single-user model, this just shows the unified flow
class IdentitySelectionScreen extends ConsumerWidget {
  const IdentitySelectionScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // v0.3.0: Always show unified onboarding (no identity list needed)
    return const OnboardingScreen();
  }
}

/// Unified onboarding flow - handles both new identity and restore
enum _OnboardingStep {
  welcome,          // Choose: generate new or enter existing seed
  showSeed,         // Show generated 24 words (if new)
  enterSeed,        // Enter existing 24 words (if restore)
  processing,       // Deriving keys, checking DHT
  confirmProfile,   // Profile found in DHT - confirm
  enterNickname,    // Profile NOT in DHT - enter nickname
  creating,         // Publishing to DHT
  loading,          // Loading existing identity (post-confirm)
}

class OnboardingScreen extends ConsumerStatefulWidget {
  const OnboardingScreen({super.key});

  @override
  ConsumerState<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends ConsumerState<OnboardingScreen> {
  _OnboardingStep _step = _OnboardingStep.welcome;

  // Seed phrase (24 words)
  String _mnemonic = '';
  bool _seedConfirmed = false;

  // For manual seed entry
  static const int _wordCount = 24;
  final List<TextEditingController> _wordControllers = [];
  final List<FocusNode> _focusNodes = [];

  // Nickname input
  final TextEditingController _nicknameController = TextEditingController();
  bool _isCheckingName = false;
  bool _isNameAvailable = false;
  String? _nameError;
  Timer? _nameCheckDebounce;

  // Restored identity info
  String? _fingerprint;
  String? _existingName;
  String? _existingAvatar;

  @override
  void initState() {
    super.initState();
    // Initialize word controllers for manual entry
    for (int i = 0; i < _wordCount; i++) {
      _wordControllers.add(TextEditingController());
      _focusNodes.add(FocusNode());
    }
  }

  @override
  void dispose() {
    for (var c in _wordControllers) {
      c.dispose();
    }
    for (var f in _focusNodes) {
      f.dispose();
    }
    _nicknameController.dispose();
    _nameCheckDebounce?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _step != _OnboardingStep.welcome ? AppBar(
        leading: IconButton(
          icon: const FaIcon(FontAwesomeIcons.arrowLeft),
          onPressed: _handleBack,
        ),
        title: Text(_getStepTitle()),
      ) : null,
      body: SafeArea(
        child: _buildCurrentStep(),
      ),
    );
  }

  String _getStepTitle() {
    switch (_step) {
      case _OnboardingStep.welcome:
        return '';
      case _OnboardingStep.showSeed:
        return 'Your Recovery Phrase';
      case _OnboardingStep.enterSeed:
        return 'Enter Recovery Phrase';
      case _OnboardingStep.processing:
        return 'Setting Up';
      case _OnboardingStep.confirmProfile:
        return 'Welcome Back';
      case _OnboardingStep.enterNickname:
        return 'Choose Your Name';
      case _OnboardingStep.creating:
        return 'Creating Identity';
      case _OnboardingStep.loading:
        return 'Loading...';
    }
  }

  void _handleBack() {
    switch (_step) {
      case _OnboardingStep.showSeed:
      case _OnboardingStep.enterSeed:
        setState(() {
          _step = _OnboardingStep.welcome;
          _mnemonic = '';
          _seedConfirmed = false;
          _clearWordControllers();
        });
        break;
      case _OnboardingStep.confirmProfile:
      case _OnboardingStep.enterNickname:
        // Go back to seed entry
        if (_mnemonic.isNotEmpty && !_mnemonic.contains(' ')) {
          // Was generated seed
          setState(() => _step = _OnboardingStep.showSeed);
        } else {
          setState(() => _step = _OnboardingStep.enterSeed);
        }
        break;
      default:
        Navigator.of(context).pop();
    }
  }

  void _clearWordControllers() {
    for (var c in _wordControllers) {
      c.clear();
    }
  }

  Widget _buildCurrentStep() {
    switch (_step) {
      case _OnboardingStep.welcome:
        return _buildWelcomeStep();
      case _OnboardingStep.showSeed:
        return _buildShowSeedStep();
      case _OnboardingStep.enterSeed:
        return _buildEnterSeedStep();
      case _OnboardingStep.processing:
        return _buildProcessingStep();
      case _OnboardingStep.confirmProfile:
        return _buildConfirmProfileStep();
      case _OnboardingStep.enterNickname:
        return _buildEnterNicknameStep();
      case _OnboardingStep.creating:
        return _buildCreatingStep();
      case _OnboardingStep.loading:
        return _buildLoadingStep();
    }
  }

  // ==================== STEP 1: Welcome ====================
  Widget _buildWelcomeStep() {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Spacer(),
          SvgPicture.asset(
            'assets/logo-icon.svg',
            width: 128,
            height: 128,
          ),
          const SizedBox(height: 24),
          Text(
            'DNA Messenger',
            style: theme.textTheme.headlineMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),
          Text(
            'Post-Quantum Encrypted Messenger',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurface.withAlpha(179),
            ),
            textAlign: TextAlign.center,
          ),
          const Spacer(),
          ElevatedButton.icon(
            onPressed: _generateNewSeed,
            icon: const FaIcon(FontAwesomeIcons.plus),
            label: const Text('Generate New Seed'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 16),
          OutlinedButton.icon(
            onPressed: () => setState(() => _step = _OnboardingStep.enterSeed),
            icon: const FaIcon(FontAwesomeIcons.key),
            label: const Text('I Have a Seed Phrase'),
            style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 48),
        ],
      ),
    );
  }

  Future<void> _generateNewSeed() async {
    try {
      final mnemonic = await ref.read(identitiesProvider.notifier).generateMnemonic();
      setState(() {
        _mnemonic = mnemonic;
        _step = _OnboardingStep.showSeed;
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to generate seed: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  // ==================== STEP 2a: Show Seed ====================
  Widget _buildShowSeedStep() {
    final theme = Theme.of(context);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: DnaColors.textWarning.withAlpha(26),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: DnaColors.textWarning.withAlpha(77)),
            ),
            child: Row(
              children: [
                FaIcon(FontAwesomeIcons.triangleExclamation, color: DnaColors.textWarning),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Write down these 24 words in order. This is your ONLY way to recover your account.',
                    style: theme.textTheme.bodySmall,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          // Word grid - responsive layout
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: theme.colorScheme.outline.withAlpha(77)),
            ),
            child: _buildMnemonicDisplayGrid(theme),
          ),
          const SizedBox(height: 16),
          // Copy button
          OutlinedButton.icon(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _mnemonic));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Copied to clipboard')),
              );
            },
            icon: const FaIcon(FontAwesomeIcons.copy, size: 18),
            label: const Text('Copy to Clipboard'),
          ),
          const SizedBox(height: 24),
          // Confirmation checkbox
          CheckboxListTile(
            value: _seedConfirmed,
            onChanged: (v) => setState(() => _seedConfirmed = v ?? false),
            title: Text(
              'I have written down my recovery phrase',
              style: theme.textTheme.bodyMedium,
            ),
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: EdgeInsets.zero,
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: _seedConfirmed ? _processSeed : null,
              child: const Text('Continue'),
            ),
          ),
        ],
      ),
    );
  }

  /// Responsive grid for displaying mnemonic words (read-only)
  Widget _buildMnemonicDisplayGrid(ThemeData theme) {
    final words = _mnemonic.split(' ');

    return LayoutBuilder(
      builder: (context, constraints) {
        // 2 columns on mobile (<400), 3 on tablet (<600), 4 on desktop
        final columns = constraints.maxWidth < 400 ? 2 : (constraints.maxWidth < 600 ? 3 : 4);
        final rows = (words.length / columns).ceil();

        return Column(
          children: List.generate(rows, (rowIndex) {
            return Padding(
              padding: EdgeInsets.only(bottom: rowIndex < rows - 1 ? 8 : 0),
              child: Row(
                children: List.generate(columns, (colIndex) {
                  final wordIndex = rowIndex * columns + colIndex;
                  if (wordIndex >= words.length) {
                    return const Expanded(child: SizedBox());
                  }
                  final word = words[wordIndex];
                  final displayIndex = wordIndex + 1;

                  return Expanded(
                    child: Padding(
                      padding: EdgeInsets.only(right: colIndex < columns - 1 ? 8 : 0),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                        decoration: BoxDecoration(
                          color: theme.scaffoldBackgroundColor,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: theme.colorScheme.primary.withAlpha(51)),
                        ),
                        child: Text(
                          '$displayIndex. $word',
                          style: theme.textTheme.bodyMedium?.copyWith(
                            fontFamily: 'monospace',
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                  );
                }),
              ),
            );
          }),
        );
      },
    );
  }

  // ==================== STEP 2b: Enter Seed ====================
  Widget _buildEnterSeedStep() {
    final theme = Theme.of(context);

    // Wrap with CallbackShortcuts to handle Ctrl+V for paste
    return CallbackShortcuts(
      bindings: <ShortcutActivator, VoidCallback>{
        const SingleActivator(LogicalKeyboardKey.keyV, control: true): _pasteFromClipboard,
        // Also support Cmd+V on macOS
        const SingleActivator(LogicalKeyboardKey.keyV, meta: true): _pasteFromClipboard,
      },
      child: Focus(
        autofocus: true,
        child: Column(
          children: [
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'Enter your 24-word recovery phrase:',
                      style: theme.textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'You can paste all words at once (Ctrl+V).',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurface.withAlpha(179),
                      ),
                    ),
                    const SizedBox(height: 16),
                    // Word grid - responsive layout
                    _buildMnemonicInputGrid(theme),
                    const SizedBox(height: 16),
                    // Paste button
                    OutlinedButton.icon(
                      onPressed: _pasteFromClipboard,
                      icon: const FaIcon(FontAwesomeIcons.paste, size: 18),
                      label: const Text('Paste from Clipboard'),
                    ),
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(24.0),
              child: SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _allWordsFilled() ? _processSeed : null,
                  child: const Text('Continue'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Responsive grid for entering mnemonic words (editable)
  Widget _buildMnemonicInputGrid(ThemeData theme) {
    return LayoutBuilder(
      builder: (context, constraints) {
        // 2 columns on mobile (<400), 3 on tablet (<600), 4 on desktop
        final columns = constraints.maxWidth < 400 ? 2 : (constraints.maxWidth < 600 ? 3 : 4);
        final rows = (_wordCount / columns).ceil();

        return Column(
          children: List.generate(rows, (rowIndex) {
            return Padding(
              padding: EdgeInsets.only(bottom: rowIndex < rows - 1 ? 8 : 0),
              child: Row(
                children: List.generate(columns, (colIndex) {
                  final wordIndex = rowIndex * columns + colIndex;
                  if (wordIndex >= _wordCount) {
                    return const Expanded(child: SizedBox());
                  }
                  return Expanded(
                    child: Padding(
                      padding: EdgeInsets.only(right: colIndex < columns - 1 ? 8 : 0),
                      child: _buildWordField(theme, wordIndex),
                    ),
                  );
                }),
              ),
            );
          }),
        );
      },
    );
  }

  Widget _buildWordField(ThemeData theme, int index) {
    final displayIndex = index + 1;

    return Container(
      decoration: BoxDecoration(
        color: theme.scaffoldBackgroundColor,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: _wordControllers[index].text.isNotEmpty
              ? theme.colorScheme.primary.withAlpha(128)
              : theme.colorScheme.primary.withAlpha(51),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 32,
            padding: const EdgeInsets.symmetric(vertical: 12),
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withAlpha(26),
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(7),
                bottomLeft: Radius.circular(7),
              ),
            ),
            child: Text(
              '$displayIndex',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.primary,
                fontWeight: FontWeight.bold,
              ),
              textAlign: TextAlign.center,
            ),
          ),
          Expanded(
            child: TextField(
              controller: _wordControllers[index],
              focusNode: _focusNodes[index],
              decoration: const InputDecoration(
                border: InputBorder.none,
                contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 12),
                isDense: true,
              ),
              style: theme.textTheme.bodyMedium?.copyWith(
                fontFamily: 'monospace',
              ),
              textInputAction: index < _wordCount - 1 ? TextInputAction.next : TextInputAction.done,
              onChanged: (_) => setState(() {}),
              onSubmitted: (_) {
                if (index < _wordCount - 1) {
                  _focusNodes[index + 1].requestFocus();
                } else if (_allWordsFilled()) {
                  _processSeed();
                }
              },
            ),
          ),
        ],
      ),
    );
  }

  bool _allWordsFilled() {
    return _wordControllers.every((c) => c.text.trim().isNotEmpty);
  }

  String _getMnemonicFromControllers() {
    return _wordControllers.map((c) => c.text.trim().toLowerCase()).join(' ');
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text == null) return;

    final words = data!.text!.trim().split(RegExp(r'\s+'));
    if (words.length != _wordCount) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Expected $_wordCount words, got ${words.length}'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
      return;
    }

    for (int i = 0; i < _wordCount; i++) {
      _wordControllers[i].text = words[i].toLowerCase();
    }
    setState(() {});
  }

  // ==================== STEP 3: Processing ====================
  Future<void> _processSeed() async {
    setState(() => _step = _OnboardingStep.processing);

    // Get mnemonic (either generated or from input)
    final mnemonic = _mnemonic.isNotEmpty ? _mnemonic : _getMnemonicFromControllers();
    _mnemonic = mnemonic;  // Store for later use

    await Future.delayed(Duration.zero);  // Let UI update

    try {
      // Validate mnemonic
      final isValid = await ref.read(identitiesProvider.notifier).validateMnemonic(mnemonic);
      if (!isValid) {
        throw Exception('Invalid seed phrase. Please check your words.');
      }

      // Restore/create identity locally (derives keys, stores mnemonic)
      final fingerprint = await ref.read(identitiesProvider.notifier)
          .restoreIdentityFromMnemonic(mnemonic);

      _fingerprint = fingerprint;

      // Check DHT for existing profile
      final engine = ref.read(engineProvider).valueOrNull;
      if (engine == null) {
        throw Exception('Engine not ready');
      }

      String displayName;
      try {
        displayName = await engine.getDisplayName(fingerprint);
      } catch (e) {
        // Network error - but we can still continue to register
        displayName = '';
      }

      // Check if it's a real registered name (not just a shortened fingerprint)
      // getDisplayName returns "abc123..." when no name is registered
      final hasRegisteredName = displayName.isNotEmpty &&
          !displayName.endsWith('...') &&
          !displayName.startsWith(fingerprint.substring(0, 8));

      if (hasRegisteredName) {
        // Profile found in DHT with registered name
        _existingName = displayName;
        try {
          _existingAvatar = await engine.getAvatar(fingerprint);
        } catch (_) {}

        if (mounted) {
          setState(() => _step = _OnboardingStep.confirmProfile);
        }
      } else {
        // Profile NOT found - need to register
        if (mounted) {
          setState(() => _step = _OnboardingStep.enterNickname);
        }
      }
    } catch (e) {
      // Go back to appropriate step
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('$e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
        setState(() {
          _step = _mnemonic.split(' ').length == 24 && _wordControllers[0].text.isEmpty
              ? _OnboardingStep.showSeed
              : _OnboardingStep.enterSeed;
        });
      }
    }
  }

  Widget _buildProcessingStep() {
    final theme = Theme.of(context);

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 24),
          Text(
            'Setting up your identity...',
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'This may take a moment',
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  // ==================== STEP 4a: Confirm Profile ====================
  Widget _buildConfirmProfileStep() {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Spacer(),
          // Avatar
          Center(
            child: CircleAvatar(
              radius: 48,
              backgroundColor: theme.colorScheme.primaryContainer,
              backgroundImage: _existingAvatar != null && _existingAvatar!.isNotEmpty
                  ? MemoryImage(_decodeAvatar(_existingAvatar!))
                  : null,
              child: _existingAvatar == null || _existingAvatar!.isEmpty
                  ? FaIcon(FontAwesomeIcons.user, size: 48, color: theme.colorScheme.primary)
                  : null,
            ),
          ),
          const SizedBox(height: 24),
          Text(
            'Welcome back!',
            style: theme.textTheme.headlineSmall,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),
          Text(
            _existingName ?? '',
            style: theme.textTheme.titleLarge?.copyWith(
              color: theme.colorScheme.primary,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),
          Text(
            '${_fingerprint?.substring(0, 16)}...',
            style: theme.textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
              color: theme.colorScheme.onSurface.withAlpha(128),
            ),
            textAlign: TextAlign.center,
          ),
          const Spacer(),
          ElevatedButton(
            onPressed: _confirmAndLoad,
            child: const Text('Continue'),
          ),
          const SizedBox(height: 48),
        ],
      ),
    );
  }

  Uint8List _decodeAvatar(String base64) {
    try {
      // Handle missing padding
      String padded = base64;
      while (padded.length % 4 != 0) {
        padded += '=';
      }
      return Uint8List.fromList(
        const Base64Decoder().convert(padded.replaceAll('\n', '').replaceAll('\r', '')),
      );
    } catch (_) {
      return Uint8List(0);
    }
  }

  Future<void> _confirmAndLoad() async {
    if (_fingerprint == null) return;

    setState(() => _step = _OnboardingStep.loading);
    await Future.delayed(Duration.zero);

    try {
      await ref.read(identitiesProvider.notifier).loadIdentity(_fingerprint!);

      // Cache the restored profile so sidebar shows correct name immediately
      if (_existingName != null && _existingName!.isNotEmpty) {
        ref.read(identityProfileCacheProvider.notifier).updateIdentity(
          _fingerprint!,
          _existingName!,
          _existingAvatar ?? '',
        );
      }

      // v0.4.60: Check for DHT backup and offer to restore
      if (mounted) {
        await _checkAndOfferRestore();
      }

      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to load: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
        setState(() => _step = _OnboardingStep.confirmProfile);
      }
    }
  }

  /// v0.4.60: Check for backup in DHT and offer to restore messages
  Future<void> _checkAndOfferRestore() async {
    try {
      final engine = ref.read(engineProvider).valueOrNull;
      if (engine == null) return;

      log('ONBOARD', 'Checking for DHT backup...');
      final backupInfo = await engine.checkBackupExists();

      if (!backupInfo.exists || !mounted) {
        log('ONBOARD', 'No backup found');
        return;
      }

      log('ONBOARD', 'Backup found: ${backupInfo.messageCount} messages');

      // Show restore dialog
      final shouldRestore = await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (context) => AlertDialog(
          title: Row(
            children: [
              FaIcon(FontAwesomeIcons.cloudArrowDown, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 12),
              const Text('Backup Found'),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                backupInfo.messageCount == -1
                    ? 'Found message backup in DHT.'
                    : 'Found ${backupInfo.messageCount} messages in DHT backup.',
              ),
              if (backupInfo.timestamp != null) ...[
                const SizedBox(height: 8),
                Text(
                  'Last backup: ${_formatBackupDate(backupInfo.timestamp!)}',
                  style: TextStyle(
                    color: DnaColors.textMuted,
                    fontSize: 13,
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primary.withAlpha(26),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.circleInfo, size: 18, color: Theme.of(context).colorScheme.primary),
                    const SizedBox(width: 8),
                    const Expanded(
                      child: Text(
                        'This will restore your messages, groups, and group encryption keys.',
                        style: TextStyle(fontSize: 13),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Skip'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Restore'),
            ),
          ],
        ),
      );

      if (shouldRestore == true && mounted) {
        // Show restoring indicator
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Row(
              children: [
                SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                ),
                SizedBox(width: 12),
                Text('Restoring messages...'),
              ],
            ),
            duration: Duration(seconds: 30),
          ),
        );

        final result = await engine.restoreMessages();

        if (mounted) {
          ScaffoldMessenger.of(context).hideCurrentSnackBar();

          if (result.success) {
            // Invalidate providers to refresh restored data (groups, contacts, conversations)
            ref.invalidate(groupsProvider);
            ref.invalidate(contactsProvider);

            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Restored ${result.processedCount} messages'),
                backgroundColor: DnaColors.snackbarSuccess,
              ),
            );
          } else {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(result.errorMessage ?? 'Restore failed'),
                backgroundColor: DnaColors.snackbarError,
              ),
            );
          }
        }
      }
    } catch (e) {
      logError('ONBOARD', 'Backup check failed: $e');
      // Silently fail - don't block the user from loading their identity
    }
  }

  String _formatBackupDate(DateTime date) {
    final now = DateTime.now();
    final diff = now.difference(date);
    if (diff.inMinutes < 60) return '${diff.inMinutes} minutes ago';
    if (diff.inHours < 24) return '${diff.inHours} hours ago';
    if (diff.inDays < 7) return '${diff.inDays} days ago';
    return '${date.day}/${date.month}/${date.year}';
  }

  // ==================== STEP 4b: Enter Nickname ====================
  Widget _buildEnterNicknameStep() {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Choose a unique name for your identity.',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'This name will be visible to other users and used to find you.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withAlpha(179),
            ),
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _nicknameController,
            decoration: InputDecoration(
              labelText: 'Nickname',
              hintText: '3-20 characters',
              border: const OutlineInputBorder(),
              errorText: _nameError,
              suffixIcon: _isCheckingName
                  ? const Padding(
                      padding: EdgeInsets.all(12),
                      child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    )
                  : _isNameAvailable && _nicknameController.text.length >= 3
                      ? const Padding(
                          padding: EdgeInsets.all(12),
                          child: FaIcon(FontAwesomeIcons.circleCheck, color: Colors.green, size: 20),
                        )
                      : null,
            ),
            textInputAction: TextInputAction.done,
            onChanged: _onNicknameChanged,
            onSubmitted: (_) {
              if (_isNameAvailable && !_isCheckingName) {
                _registerAndLoad();
              }
            },
          ),
          const Spacer(),
          ElevatedButton(
            onPressed: _isNameAvailable && !_isCheckingName ? _registerAndLoad : null,
            child: const Text('Register & Continue'),
          ),
        ],
      ),
    );
  }

  void _onNicknameChanged(String value) {
    _nameCheckDebounce?.cancel();

    final trimmed = value.trim();

    // Basic validation
    if (trimmed.length < 3) {
      setState(() {
        _isNameAvailable = false;
        _nameError = trimmed.isEmpty ? null : 'Minimum 3 characters';
      });
      return;
    }

    if (trimmed.length > 20) {
      setState(() {
        _isNameAvailable = false;
        _nameError = 'Maximum 20 characters';
      });
      return;
    }

    // Check for uppercase letters (specific error message)
    if (trimmed.contains(RegExp(r'[A-Z]'))) {
      setState(() {
        _isNameAvailable = false;
        _nameError = 'Lowercase only. You can set a display name in your profile later.';
      });
      return;
    }

    // Check for valid characters (a-z, 0-9, underscore, hyphen)
    final validChars = RegExp(r'^[a-z0-9_-]+$');
    if (!validChars.hasMatch(trimmed)) {
      setState(() {
        _isNameAvailable = false;
        _nameError = 'Only lowercase letters, numbers, underscore, hyphen';
      });
      return;
    }

    // Check availability with debounce
    setState(() {
      _isCheckingName = true;
      _nameError = null;
    });

    _nameCheckDebounce = Timer(const Duration(milliseconds: 500), () async {
      try {
        final available = await ref.read(identitiesProvider.notifier).isNameAvailable(trimmed);
        if (mounted && _nicknameController.text.trim() == trimmed) {
          setState(() {
            _isCheckingName = false;
            _isNameAvailable = available;
            _nameError = available ? null : 'Name already taken';
          });
        }
      } catch (e) {
        if (mounted) {
          setState(() {
            _isCheckingName = false;
            _isNameAvailable = false;
            _nameError = 'Failed to check availability';
          });
        }
      }
    });
  }

  Future<void> _registerAndLoad() async {
    if (_fingerprint == null) return;

    final nickname = _nicknameController.text.trim();
    if (nickname.isEmpty || !_isNameAvailable) return;

    setState(() => _step = _OnboardingStep.creating);
    await Future.delayed(Duration.zero);

    try {
      // Load identity first (required before DHT operations)
      await ref.read(identitiesProvider.notifier).loadIdentity(_fingerprint!);

      // Register name on DHT (this publishes full profile including wallet addresses)
      await ref.read(identitiesProvider.notifier).registerName(nickname);

      // v0.4.60: Check for DHT backup and offer to restore
      // (user may be restoring from seed on new device with existing backup)
      if (mounted) {
        await _checkAndOfferRestore();
      }

      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to register: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
        setState(() => _step = _OnboardingStep.enterNickname);
      }
    }
  }

  // ==================== STEP 5: Creating ====================
  Widget _buildCreatingStep() {
    final theme = Theme.of(context);

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 24),
          Text(
            'Creating your identity...',
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'Publishing to the network',
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  // ==================== STEP 6: Loading (existing identity) ====================
  Widget _buildLoadingStep() {
    final theme = Theme.of(context);

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 24),
          Text(
            'Loading identity...',
            style: theme.textTheme.titleMedium,
          ),
        ],
      ),
    );
  }
}
