// Identity Selection Screen - Unified onboarding flow
// v0.3.0: Single-user model with merged create/restore flow
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

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
          icon: const Icon(Icons.arrow_back),
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
          Icon(
            Icons.security,
            size: 80,
            color: theme.colorScheme.primary,
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
            icon: const Icon(Icons.add),
            label: const Text('Generate New Seed'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 16),
          OutlinedButton.icon(
            onPressed: () => setState(() => _step = _OnboardingStep.enterSeed),
            icon: const Icon(Icons.key),
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
                Icon(Icons.warning_amber, color: DnaColors.textWarning),
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
            icon: const Icon(Icons.copy, size: 18),
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
          ElevatedButton(
            onPressed: _seedConfirmed ? _processSeed : null,
            child: const Text('Continue'),
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

    return Column(
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
                  'You can paste all words at once.',
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
                  icon: const Icon(Icons.paste, size: 18),
                  label: const Text('Paste from Clipboard'),
                ),
              ],
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(24.0),
          child: ElevatedButton(
            onPressed: _allWordsFilled() ? _processSeed : null,
            child: const Text('Continue'),
          ),
        ),
      ],
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
                  ? Icon(Icons.person, size: 48, color: theme.colorScheme.primary)
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

    setState(() => _step = _OnboardingStep.creating);
    await Future.delayed(Duration.zero);

    try {
      await ref.read(identitiesProvider.notifier).loadIdentity(_fingerprint!);

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
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: Padding(
                        padding: EdgeInsets.all(12),
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    )
                  : _isNameAvailable && _nicknameController.text.length >= 3
                      ? const Icon(Icons.check_circle, color: Colors.green)
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

    // Check for valid characters
    final validChars = RegExp(r'^[a-zA-Z0-9_]+$');
    if (!validChars.hasMatch(trimmed)) {
      setState(() {
        _isNameAvailable = false;
        _nameError = 'Only letters, numbers, and underscore';
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
}
