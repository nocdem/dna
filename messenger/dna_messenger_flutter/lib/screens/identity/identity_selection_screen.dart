// Identity Selection Screen - Choose or create identity
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

class IdentitySelectionScreen extends ConsumerWidget {
  const IdentitySelectionScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final identities = ref.watch(identitiesProvider);
    final theme = Theme.of(context);

    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SizedBox(height: 48),
              // Logo/Title
              Icon(
                Icons.security,
                size: 64,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(height: 16),
              Text(
                'DNA Messenger',
                style: theme.textTheme.headlineMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                'Post-Quantum Encrypted',
                style: theme.textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 48),

              // Identity list or loading
              Expanded(
                child: identities.when(
                  data: (list) => _buildIdentityList(context, ref, list),
                  loading: () => const Center(
                    child: CircularProgressIndicator(),
                  ),
                  error: (error, stack) => Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.error_outline,
                          size: 48,
                          color: DnaColors.textWarning,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'Failed to load identities',
                          style: theme.textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          error.toString(),
                          style: theme.textTheme.bodySmall,
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 16),
                        ElevatedButton(
                          onPressed: () {
                            ref.invalidate(identitiesProvider);
                          },
                          child: const Text('Retry'),
                        ),
                      ],
                    ),
                  ),
                ),
              ),

              // Action buttons
              const SizedBox(height: 24),
              ElevatedButton.icon(
                onPressed: () => _showCreateIdentityScreen(context),
                icon: const Icon(Icons.add),
                label: const Text('Create New Identity'),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: () => _showRestoreIdentityScreen(context),
                icon: const Icon(Icons.restore),
                label: const Text('Restore from Seed'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildIdentityList(BuildContext context, WidgetRef ref, List<String> identities) {
    final theme = Theme.of(context);

    if (identities.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.person_outline,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No identities yet',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Create a new identity to get started',
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      itemCount: identities.length,
      itemBuilder: (context, index) {
        final fingerprint = identities[index];
        return _IdentityListTile(
          fingerprint: fingerprint,
          onTap: () => _loadIdentity(context, ref, fingerprint),
        );
      },
    );
  }

  Future<void> _loadIdentity(BuildContext context, WidgetRef ref, String fingerprint) async {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => const Center(
        child: CircularProgressIndicator(),
      ),
    );

    try {
      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);
      if (context.mounted) {
        Navigator.of(context).pop();
      }
    } catch (e) {
      if (context.mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to load identity: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  void _showCreateIdentityScreen(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const CreateIdentityScreen(),
      ),
    );
  }

  void _showRestoreIdentityScreen(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const RestoreIdentityScreen(),
      ),
    );
  }
}

/// Create Identity Screen - 3-step: show seed, confirm, nickname, create
class CreateIdentityScreen extends ConsumerStatefulWidget {
  const CreateIdentityScreen({super.key});

  @override
  ConsumerState<CreateIdentityScreen> createState() => _CreateIdentityScreenState();
}

enum _CreateStep { seed, nickname, creating }

class _CreateIdentityScreenState extends ConsumerState<CreateIdentityScreen> {
  String _mnemonic = '';
  bool _seedConfirmed = false;
  _CreateStep _step = _CreateStep.seed;
  final _nicknameController = TextEditingController();
  bool _isGeneratingMnemonic = true;
  String? _mnemonicError;

  // Nickname availability checking
  Timer? _debounceTimer;
  bool _isCheckingAvailability = false;
  String? _availabilityStatus;  // null = not checked, empty = available, non-empty = error message
  bool _isNameAvailable = false;
  String _lastCheckedName = '';

  @override
  void initState() {
    super.initState();
    _generateMnemonic();
  }

  @override
  void dispose() {
    _debounceTimer?.cancel();
    _nicknameController.dispose();
    super.dispose();
  }

  /// Validate nickname locally (3-20 chars, alphanumeric + underscore)
  String? _validateNicknameLocally(String name) {
    if (name.isEmpty) return null;  // Empty is OK (optional)
    if (name.length < 3) return 'At least 3 characters';
    if (name.length > 20) return 'Maximum 20 characters';
    final validChars = RegExp(r'^[a-zA-Z0-9_]+$');
    if (!validChars.hasMatch(name)) {
      return 'Only letters, numbers, underscore';
    }
    return null;  // Valid
  }

  /// Check nickname availability with debounce
  void _onNicknameChanged(String value) {
    setState(() {});

    // Cancel previous timer
    _debounceTimer?.cancel();

    final name = value.trim().toLowerCase();

    // Local validation first
    final localError = _validateNicknameLocally(name);
    if (localError != null) {
      setState(() {
        _availabilityStatus = localError;
        _isNameAvailable = false;
        _isCheckingAvailability = false;
      });
      return;
    }

    // Empty name is OK (nickname is optional)
    if (name.isEmpty) {
      setState(() {
        _availabilityStatus = null;
        _isNameAvailable = true;  // Empty is valid (skip registration)
        _isCheckingAvailability = false;
      });
      return;
    }

    // Already checked this name
    if (name == _lastCheckedName && _availabilityStatus != null) {
      return;
    }

    // Start debounce timer (500ms)
    setState(() => _isCheckingAvailability = true);
    _debounceTimer = Timer(const Duration(milliseconds: 500), () {
      _checkNameAvailability(name);
    });
  }

  Future<void> _checkNameAvailability(String name) async {
    if (!mounted) return;

    try {
      final engine = ref.read(engineProvider).valueOrNull;
      if (engine == null) {
        setState(() {
          _availabilityStatus = 'Engine not ready';
          _isNameAvailable = false;
          _isCheckingAvailability = false;
        });
        return;
      }

      // lookupName returns fingerprint if taken, empty string if available
      final result = await engine.lookupName(name);

      if (!mounted) return;

      _lastCheckedName = name;
      setState(() {
        _isCheckingAvailability = false;
        if (result.isEmpty) {
          _availabilityStatus = 'Available!';
          _isNameAvailable = true;
        } else {
          _availabilityStatus = 'Already taken';
          _isNameAvailable = false;
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isCheckingAvailability = false;
        _availabilityStatus = 'Check failed';
        _isNameAvailable = false;
      });
    }
  }

  Future<void> _generateMnemonic() async {
    setState(() {
      _isGeneratingMnemonic = true;
      _mnemonicError = null;
    });

    try {
      final mnemonic = await ref.read(identitiesProvider.notifier).generateMnemonic();
      if (mounted) {
        setState(() {
          _mnemonic = mnemonic;
          _isGeneratingMnemonic = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _mnemonicError = 'Failed to generate mnemonic: $e';
          _isGeneratingMnemonic = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(_step == _CreateStep.seed
            ? 'Create Identity'
            : _step == _CreateStep.nickname
                ? 'Register Nickname'
                : 'Creating...'),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Content
              Expanded(
                child: switch (_step) {
                  _CreateStep.seed => _buildSeedStep(theme),
                  _CreateStep.nickname => _buildNicknameStep(theme),
                  _CreateStep.creating => _buildCreatingState(theme),
                },
              ),

              // Actions
              if (_step != _CreateStep.creating) _buildActions(theme),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSeedStep(ThemeData theme) {
    if (_isGeneratingMnemonic) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 24),
            Text(
              'Generating seed phrase...',
              style: theme.textTheme.titleMedium,
            ),
          ],
        ),
      );
    }

    if (_mnemonicError != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 48, color: DnaColors.textWarning),
            const SizedBox(height: 16),
            Text(_mnemonicError!, style: theme.textTheme.bodyMedium),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _generateMnemonic,
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }

    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Save your recovery phrase',
            style: theme.textTheme.titleLarge,
          ),
          const SizedBox(height: 8),
          Text(
            'Write down these 24 words in order. This is the ONLY way to recover your identity.',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 24),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: theme.colorScheme.primary.withAlpha(77),
              ),
            ),
            child: Column(
              children: [
                // Display words in a grid
                _buildMnemonicGrid(theme),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: _mnemonic));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Seed phrase copied to clipboard'),
                        duration: Duration(seconds: 2),
                      ),
                    );
                  },
                  icon: const Icon(Icons.copy),
                  label: const Text('Copy to Clipboard'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: DnaColors.textWarning.withAlpha(26),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.warning_amber,
                  color: DnaColors.textWarning,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Never share your seed phrase. Anyone with these words can access your identity.',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: DnaColors.textWarning,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          // Confirmation checkbox
          CheckboxListTile(
            value: _seedConfirmed,
            onChanged: (value) => setState(() => _seedConfirmed = value ?? false),
            title: Text(
              'I have saved my recovery phrase',
              style: theme.textTheme.bodyMedium,
            ),
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: EdgeInsets.zero,
          ),
        ],
      ),
    );
  }

  Widget _buildMnemonicGrid(ThemeData theme) {
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

  Widget _buildNicknameStep(ThemeData theme) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Choose your nickname',
            style: theme.textTheme.titleLarge,
          ),
          const SizedBox(height: 8),
          Text(
            'Your nickname is how others can find you. It will be registered on the DHT network.',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _nicknameController,
            decoration: InputDecoration(
              labelText: 'Nickname',
              hintText: 'Choose a unique nickname (optional)',
              prefixIcon: const Icon(Icons.alternate_email),
              suffixIcon: _buildAvailabilitySuffix(),
            ),
            autofocus: true,
            textInputAction: TextInputAction.done,
            onChanged: _onNicknameChanged,
            onSubmitted: (_) {
              if (_canCreateIdentity()) {
                _createIdentity();
              }
            },
          ),
          const SizedBox(height: 8),
          // Availability status text
          _buildAvailabilityStatus(theme),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: DnaColors.textSuccess.withAlpha(26),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.check_circle,
                  color: DnaColors.textSuccess,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Nickname registration is free!',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: DnaColors.textSuccess,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget? _buildAvailabilitySuffix() {
    if (_isCheckingAvailability) {
      return const Padding(
        padding: EdgeInsets.all(12),
        child: SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      );
    }
    if (_nicknameController.text.trim().isEmpty) {
      return null;
    }
    if (_isNameAvailable) {
      return const Icon(Icons.check_circle, color: DnaColors.textSuccess);
    }
    if (_availabilityStatus != null) {
      return const Icon(Icons.cancel, color: DnaColors.textWarning);
    }
    return null;
  }

  Widget _buildAvailabilityStatus(ThemeData theme) {
    if (_isCheckingAvailability) {
      return Text(
        'Checking availability...',
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
      );
    }
    if (_availabilityStatus == null || _nicknameController.text.trim().isEmpty) {
      return Text(
        '3-20 characters, letters, numbers, underscore',
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
      );
    }
    if (_isNameAvailable) {
      return Text(
        _availabilityStatus!,
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textSuccess),
      );
    }
    return Text(
      _availabilityStatus!,
      style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textWarning),
    );
  }

  bool _canCreateIdentity() {
    final name = _nicknameController.text.trim();
    // Empty name is OK (skip nickname registration)
    if (name.isEmpty) return true;
    // Otherwise, name must be available and not checking
    return _isNameAvailable && !_isCheckingAvailability;
  }

  Widget _buildCreatingState(ThemeData theme) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 24),
          Text(
            'Creating identity...',
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'Generating post-quantum cryptographic keys',
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  Widget _buildActions(ThemeData theme) {
    if (_step == _CreateStep.seed) {
      return ElevatedButton(
        onPressed: _seedConfirmed
            ? () => setState(() => _step = _CreateStep.nickname)
            : null,
        child: const Text('Continue'),
      );
    } else {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ElevatedButton(
            onPressed: _canCreateIdentity() ? _createIdentity : null,
            child: const Text('Create Identity'),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => setState(() => _step = _CreateStep.seed),
            child: const Text('Back'),
          ),
        ],
      );
    }
  }

  Future<void> _createIdentity() async {
    setState(() => _step = _CreateStep.creating);

    // Allow Flutter to render the loading screen before heavy sync operations
    await Future.delayed(Duration.zero);

    try {
      // Create identity from mnemonic (local keys only)
      final nickname = _nicknameController.text.trim();
      final fingerprint = await ref.read(identitiesProvider.notifier)
          .createIdentityFromMnemonic(nickname, _mnemonic);

      // Load the identity (required before DHT operations)
      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

      // Register name on DHT (publishes identity with name)
      if (nickname.isNotEmpty) {
        await ref.read(identitiesProvider.notifier).registerName(nickname);
      }

      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      setState(() => _step = _CreateStep.nickname);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to create identity: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }
}

/// Restore Identity Screen - steps: enter seed, confirm profile (if registered) or register nickname (if not), done
class RestoreIdentityScreen extends ConsumerStatefulWidget {
  const RestoreIdentityScreen({super.key});

  @override
  ConsumerState<RestoreIdentityScreen> createState() => _RestoreIdentityScreenState();
}

enum _RestoreStep { enterSeed, restoring, confirmProfile, registerNickname }

class _RestoreIdentityScreenState extends ConsumerState<RestoreIdentityScreen> {
  static const int _wordCount = 24;
  final List<TextEditingController> _wordControllers = [];
  final List<FocusNode> _focusNodes = [];
  _RestoreStep _step = _RestoreStep.enterSeed;

  // Restored identity data
  String? _restoredFingerprint;
  String? _restoredName;
  String? _restoredAvatar;

  // Nickname registration (for unregistered identities)
  final _nicknameController = TextEditingController();
  Timer? _debounceTimer;
  bool _isCheckingAvailability = false;
  String? _availabilityStatus;
  bool _isNameAvailable = false;
  String _lastCheckedName = '';

  @override
  void initState() {
    super.initState();
    for (int i = 0; i < _wordCount; i++) {
      _wordControllers.add(TextEditingController());
      _focusNodes.add(FocusNode());
    }
  }

  @override
  void dispose() {
    _debounceTimer?.cancel();
    _nicknameController.dispose();
    for (final controller in _wordControllers) {
      controller.dispose();
    }
    for (final node in _focusNodes) {
      node.dispose();
    }
    super.dispose();
  }

  /// Validate nickname locally (3-20 chars, alphanumeric + underscore)
  String? _validateNicknameLocally(String name) {
    if (name.isEmpty) return null;  // Empty is not valid for restore
    if (name.length < 3) return 'At least 3 characters';
    if (name.length > 20) return 'Maximum 20 characters';
    final validChars = RegExp(r'^[a-zA-Z0-9_]+$');
    if (!validChars.hasMatch(name)) {
      return 'Only letters, numbers, underscore';
    }
    return null;  // Valid
  }

  /// Check nickname availability with debounce
  void _onNicknameChanged(String value) {
    setState(() {});

    // Cancel previous timer
    _debounceTimer?.cancel();

    final name = value.trim().toLowerCase();

    // Local validation first
    final localError = _validateNicknameLocally(name);
    if (localError != null) {
      setState(() {
        _availabilityStatus = localError;
        _isNameAvailable = false;
        _isCheckingAvailability = false;
      });
      return;
    }

    // Empty name is NOT valid for restore (must register)
    if (name.isEmpty) {
      setState(() {
        _availabilityStatus = 'Name is required';
        _isNameAvailable = false;
        _isCheckingAvailability = false;
      });
      return;
    }

    // Already checked this name
    if (name == _lastCheckedName && _availabilityStatus != null) {
      return;
    }

    // Start debounce timer (500ms)
    setState(() => _isCheckingAvailability = true);
    _debounceTimer = Timer(const Duration(milliseconds: 500), () {
      _checkNameAvailability(name);
    });
  }

  Future<void> _checkNameAvailability(String name) async {
    if (!mounted) return;

    try {
      final engine = ref.read(engineProvider).valueOrNull;
      if (engine == null) {
        setState(() {
          _availabilityStatus = 'Engine not ready';
          _isNameAvailable = false;
          _isCheckingAvailability = false;
        });
        return;
      }

      // lookupName returns fingerprint if taken, empty string if available
      final result = await engine.lookupName(name);

      if (!mounted) return;

      _lastCheckedName = name;
      setState(() {
        _isCheckingAvailability = false;
        if (result.isEmpty) {
          _availabilityStatus = 'Available!';
          _isNameAvailable = true;
        } else {
          _availabilityStatus = 'Already taken';
          _isNameAvailable = false;
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isCheckingAvailability = false;
        _availabilityStatus = 'Check failed';
        _isNameAvailable = false;
      });
    }
  }

  bool _canRegisterNickname() {
    final name = _nicknameController.text.trim();
    if (name.isEmpty) return false;
    return _isNameAvailable && !_isCheckingAvailability;
  }

  /// Get combined mnemonic from all word fields
  String _getMnemonic() {
    return _wordControllers
        .map((c) => c.text.trim().toLowerCase())
        .join(' ')
        .trim();
  }

  /// Check if all 24 words are filled
  bool _allWordsFilled() {
    return _wordControllers.every((c) => c.text.trim().isNotEmpty);
  }

  /// Handle paste - detect multi-word paste and distribute to fields
  void _onWordChanged(int index, String value) {
    final words = value.trim().split(RegExp(r'\s+'));

    if (words.length > 1) {
      // Multi-word paste detected - distribute words
      _distributeWords(index, words);
    } else if (value.endsWith(' ') && value.trim().isNotEmpty) {
      // Single word with space - move to next field
      _wordControllers[index].text = value.trim();
      if (index < _wordCount - 1) {
        _focusNodes[index + 1].requestFocus();
      }
    }
    setState(() {});
  }

  /// Distribute pasted words across fields starting from index
  void _distributeWords(int startIndex, List<String> words) {
    for (int i = 0; i < words.length && (startIndex + i) < _wordCount; i++) {
      _wordControllers[startIndex + i].text = words[i].toLowerCase();
    }
    // Focus the next empty field or last filled field
    final nextIndex = (startIndex + words.length).clamp(0, _wordCount - 1);
    _focusNodes[nextIndex].requestFocus();
    setState(() {});
  }

  /// Handle backspace on empty field - go to previous field
  void _onKeyEvent(int index, KeyEvent event) {
    if (event is KeyDownEvent &&
        event.logicalKey == LogicalKeyboardKey.backspace &&
        _wordControllers[index].text.isEmpty &&
        index > 0) {
      _focusNodes[index - 1].requestFocus();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(_step == _RestoreStep.confirmProfile
            ? 'Confirm Identity'
            : _step == _RestoreStep.registerNickname
                ? 'Register Nickname'
                : 'Restore Identity'),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: switch (_step) {
            _RestoreStep.enterSeed => _buildEnterSeedStep(theme),
            _RestoreStep.restoring => _buildRestoringStep(theme),
            _RestoreStep.confirmProfile => _buildConfirmProfileStep(theme),
            _RestoreStep.registerNickname => _buildRegisterNicknameStep(theme),
          },
        ),
      ),
    );
  }

  Widget _buildEnterSeedStep(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          'Enter your recovery phrase',
          style: theme.textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        Text(
          'Enter the 24-word seed phrase you saved when creating your identity. You can paste all words at once.',
          style: theme.textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        Expanded(
          child: SingleChildScrollView(
            child: _buildWordGrid(theme),
          ),
        ),
        const SizedBox(height: 24),
        ElevatedButton(
          onPressed: _allWordsFilled() ? _restoreIdentity : null,
          child: const Text('Restore Identity'),
        ),
      ],
    );
  }

  Widget _buildRestoringStep(ThemeData theme) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 24),
          Text(
            'Restoring identity...',
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'Looking up your profile from the network',
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  Widget _buildConfirmProfileStep(ThemeData theme) {
    final shortFp = _restoredFingerprint != null && _restoredFingerprint!.length > 16
        ? '${_restoredFingerprint!.substring(0, 8)}...${_restoredFingerprint!.substring(_restoredFingerprint!.length - 8)}'
        : _restoredFingerprint ?? '';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          'Identity Found',
          style: theme.textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        Text(
          'We found your identity on the network. Please confirm this is you.',
          style: theme.textTheme.bodySmall,
        ),
        const SizedBox(height: 32),
        Expanded(
          child: Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Avatar
                _buildAvatar(theme, _restoredAvatar),
                const SizedBox(height: 16),
                // Name
                Text(
                  _restoredName ?? shortFp,
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                // Fingerprint
                if (_restoredName != null)
                  Text(
                    shortFp,
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontFamily: 'monospace',
                      color: DnaColors.textMuted,
                    ),
                  ),
                const SizedBox(height: 24),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: DnaColors.textSuccess.withAlpha(26),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.check_circle,
                        color: DnaColors.textSuccess,
                      ),
                      const SizedBox(width: 12),
                      Text(
                        'Identity verified on DHT network',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: DnaColors.textSuccess,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 24),
        ElevatedButton(
          onPressed: _confirmAndLoad,
          child: const Text('Continue'),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: () => setState(() => _step = _RestoreStep.enterSeed),
          child: const Text('Back'),
        ),
      ],
    );
  }

  Widget _buildRegisterNicknameStep(ThemeData theme) {
    final shortFp = _restoredFingerprint != null && _restoredFingerprint!.length > 16
        ? '${_restoredFingerprint!.substring(0, 8)}...${_restoredFingerprint!.substring(_restoredFingerprint!.length - 8)}'
        : _restoredFingerprint ?? '';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          'Register Your Identity',
          style: theme.textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        Text(
          'Your seed phrase is valid but not yet registered on the network. Choose a nickname to complete registration.',
          style: theme.textTheme.bodySmall,
        ),
        const SizedBox(height: 16),
        // Show fingerprint
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: theme.colorScheme.primary.withAlpha(51)),
          ),
          child: Row(
            children: [
              Icon(Icons.fingerprint, color: theme.colorScheme.primary),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Your Fingerprint',
                      style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
                    ),
                    Text(
                      shortFp,
                      style: theme.textTheme.bodyMedium?.copyWith(fontFamily: 'monospace'),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        TextField(
          controller: _nicknameController,
          decoration: InputDecoration(
            labelText: 'Nickname',
            hintText: 'Choose a unique nickname',
            prefixIcon: const Icon(Icons.alternate_email),
            suffixIcon: _buildNicknameAvailabilitySuffix(),
          ),
          autofocus: true,
          textInputAction: TextInputAction.done,
          onChanged: _onNicknameChanged,
          onSubmitted: (_) {
            if (_canRegisterNickname()) {
              _registerAndLoad();
            }
          },
        ),
        const SizedBox(height: 8),
        // Availability status text
        _buildNicknameAvailabilityStatus(theme),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: DnaColors.textSuccess.withAlpha(26),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              Icon(Icons.info_outline, color: DnaColors.textSuccess),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Keys and wallets have been created from your seed. Registration will publish your identity to the network.',
                  style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textSuccess),
                ),
              ),
            ],
          ),
        ),
        const Spacer(),
        ElevatedButton(
          onPressed: _canRegisterNickname() ? _registerAndLoad : null,
          child: const Text('Register & Continue'),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: () => setState(() => _step = _RestoreStep.enterSeed),
          child: const Text('Back'),
        ),
      ],
    );
  }

  Widget? _buildNicknameAvailabilitySuffix() {
    if (_isCheckingAvailability) {
      return const Padding(
        padding: EdgeInsets.all(12),
        child: SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      );
    }
    if (_nicknameController.text.trim().isEmpty) {
      return null;
    }
    if (_isNameAvailable) {
      return const Icon(Icons.check_circle, color: DnaColors.textSuccess);
    }
    if (_availabilityStatus != null) {
      return const Icon(Icons.cancel, color: DnaColors.textWarning);
    }
    return null;
  }

  Widget _buildNicknameAvailabilityStatus(ThemeData theme) {
    if (_isCheckingAvailability) {
      return Text(
        'Checking availability...',
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
      );
    }
    if (_availabilityStatus == null || _nicknameController.text.trim().isEmpty) {
      return Text(
        '3-20 characters, letters, numbers, underscore',
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
      );
    }
    if (_isNameAvailable) {
      return Text(
        _availabilityStatus!,
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textSuccess),
      );
    }
    return Text(
      _availabilityStatus!,
      style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textWarning),
    );
  }

  Widget _buildAvatar(ThemeData theme, String? avatarBase64) {
    if (avatarBase64 != null && avatarBase64.isNotEmpty) {
      try {
        final bytes = decodeBase64WithPadding(avatarBase64);
        if (bytes != null) {
          return CircleAvatar(
            radius: 48,
            backgroundImage: MemoryImage(bytes),
          );
        }
      } catch (e) {
        // Invalid base64, fall through to default
      }
    }
    return CircleAvatar(
      radius: 48,
      backgroundColor: theme.colorScheme.primary.withAlpha(51),
      child: Icon(
        Icons.person,
        size: 48,
        color: theme.colorScheme.primary,
      ),
    );
  }

  Widget _buildWordGrid(ThemeData theme) {
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

    return KeyboardListener(
      focusNode: FocusNode(),
      onKeyEvent: (event) => _onKeyEvent(index, event),
      child: Container(
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
                textInputAction: index < _wordCount - 1
                    ? TextInputAction.next
                    : TextInputAction.done,
                onChanged: (value) => _onWordChanged(index, value),
                onSubmitted: (_) {
                  if (index < _wordCount - 1) {
                    _focusNodes[index + 1].requestFocus();
                  } else if (_allWordsFilled()) {
                    _restoreIdentity();
                  }
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _restoreIdentity() async {
    setState(() => _step = _RestoreStep.restoring);

    // Allow Flutter to render the loading screen before heavy sync operations
    await Future.delayed(Duration.zero);

    try {
      final mnemonic = _getMnemonic();

      if (!_allWordsFilled()) {
        throw Exception('Please fill in all 24 words');
      }

      // Validate mnemonic
      final isValid = await ref.read(identitiesProvider.notifier).validateMnemonic(mnemonic);
      if (!isValid) {
        throw Exception('Invalid seed phrase. Please check your words.');
      }

      // Restore identity from mnemonic (creates keys/wallets locally)
      final fingerprint = await ref.read(identitiesProvider.notifier)
          .restoreIdentityFromMnemonic(mnemonic);

      _restoredFingerprint = fingerprint;

      // Lookup profile from DHT - check if identity is already registered
      final engine = ref.read(engineProvider).valueOrNull;
      if (engine == null) {
        throw Exception('Engine not ready');
      }

      // Get display name from DHT - differentiate network error vs not found
      String displayName;
      try {
        displayName = await engine.getDisplayName(fingerprint);
      } catch (e) {
        // Network error - DHT unreachable
        throw Exception('Network error. Please check your connection and try again.');
      }

      if (displayName.isEmpty) {
        // Identity not found on DHT - allow user to register a nickname
        _restoredName = null;
        _restoredAvatar = null;
        if (mounted) {
          setState(() => _step = _RestoreStep.registerNickname);
        }
        return;
      }
      _restoredName = displayName;

      // Try to get avatar (optional)
      try {
        _restoredAvatar = await engine.getAvatar(fingerprint);
      } catch (_) {
        // Avatar is optional, ignore errors
      }

      if (mounted) {
        setState(() => _step = _RestoreStep.confirmProfile);
      }
    } catch (e) {
      setState(() {
        _step = _RestoreStep.enterSeed;
        _restoredFingerprint = null;
        _restoredName = null;
        _restoredAvatar = null;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('$e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  /// Register nickname and load identity (for unregistered seeds)
  Future<void> _registerAndLoad() async {
    if (_restoredFingerprint == null) return;

    final nickname = _nicknameController.text.trim();
    if (nickname.isEmpty || !_isNameAvailable) return;

    setState(() => _step = _RestoreStep.restoring);

    // Allow Flutter to render the loading screen before operations
    await Future.delayed(Duration.zero);

    try {
      // Load identity first (required before DHT operations)
      await ref.read(identitiesProvider.notifier).loadIdentity(_restoredFingerprint!);

      // Register name on DHT
      await ref.read(identitiesProvider.notifier).registerName(nickname);

      _restoredName = nickname;

      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      setState(() => _step = _RestoreStep.registerNickname);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to register: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  Future<void> _confirmAndLoad() async {
    if (_restoredFingerprint == null) return;

    setState(() => _step = _RestoreStep.restoring);

    // Allow Flutter to render the loading screen before operations
    await Future.delayed(Duration.zero);

    try {
      await ref.read(identitiesProvider.notifier).loadIdentity(_restoredFingerprint!);

      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      setState(() => _step = _RestoreStep.confirmProfile);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to load identity: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }
}

/// Identity list tile that fetches display name and avatar from DHT
class _IdentityListTile extends ConsumerWidget {
  final String fingerprint;
  final VoidCallback onTap;

  const _IdentityListTile({
    required this.fingerprint,
    required this.onTap,
  });

  String _shortenFingerprint(String fp) {
    if (fp.length <= 16) return fp;
    return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
  }

  Widget _buildAvatar(ThemeData theme, String? avatarBase64) {
    if (avatarBase64 != null && avatarBase64.isNotEmpty) {
      final bytes = decodeBase64WithPadding(avatarBase64);
      if (bytes != null) {
        return CircleAvatar(
          backgroundImage: MemoryImage(bytes),
        );
      }
    }
    return CircleAvatar(
      backgroundColor: theme.colorScheme.primary.withAlpha(51),
      child: Icon(
        Icons.person,
        color: theme.colorScheme.primary,
      ),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final displayNameAsync = ref.watch(identityDisplayNameProvider(fingerprint));
    final avatarAsync = ref.watch(identityAvatarProvider(fingerprint));
    final shortFp = _shortenFingerprint(fingerprint);

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: avatarAsync.when(
          data: (avatar) => _buildAvatar(theme, avatar),
          loading: () => _buildAvatar(theme, null),
          error: (_, __) => _buildAvatar(theme, null),
        ),
        title: displayNameAsync.when(
          data: (name) => Text(
            name ?? shortFp,
            style: name != null
                ? theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)
                : null,
          ),
          loading: () => Row(
            children: [
              Flexible(
                child: Text(
                  shortFp,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),
              const SizedBox(
                width: 12,
                height: 12,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            ],
          ),
          error: (_, __) => Text(shortFp),
        ),
        subtitle: displayNameAsync.when(
          data: (name) => Text(
            name != null ? shortFp : fingerprint,
            style: theme.textTheme.bodySmall,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          loading: () => Text(
            fingerprint,
            style: theme.textTheme.bodySmall,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          error: (_, __) => Text(
            fingerprint,
            style: theme.textTheme.bodySmall,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
        trailing: const Icon(Icons.arrow_forward_ios, size: 16),
        onTap: onTap,
      ),
    );
  }
}
