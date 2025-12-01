// Identity Selection Screen - Choose or create identity
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
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
        final shortFp = _shortenFingerprint(fingerprint);

        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: CircleAvatar(
              backgroundColor: theme.colorScheme.primary.withAlpha(51),
              child: Icon(
                Icons.person,
                color: theme.colorScheme.primary,
              ),
            ),
            title: Text(shortFp),
            subtitle: Text(
              fingerprint,
              style: theme.textTheme.bodySmall,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: const Icon(Icons.arrow_forward_ios, size: 16),
            onTap: () => _loadIdentity(context, ref, fingerprint),
          ),
        );
      },
    );
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
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
            backgroundColor: DnaColors.textWarning,
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
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: words.asMap().entries.map((entry) {
        final index = entry.key + 1;
        final word = entry.value;
        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: theme.scaffoldBackgroundColor,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: theme.colorScheme.primary.withAlpha(51)),
          ),
          child: Text(
            '$index. $word',
            style: theme.textTheme.bodyMedium?.copyWith(
              fontFamily: 'monospace',
            ),
          ),
        );
      }).toList(),
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

    try {
      // Create identity from mnemonic using real BIP39
      final fingerprint = await ref.read(identitiesProvider.notifier)
          .createIdentityFromMnemonic(_mnemonic);

      // Load the identity first (required before nickname registration)
      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

      // Register nickname on DHT (must be after identity is loaded)
      final nickname = _nicknameController.text.trim();
      if (nickname.isNotEmpty) {
        try {
          await ref.read(identitiesProvider.notifier).registerName(nickname);
        } catch (e) {
          // Nickname registration failed, but identity was created
          // User can register later in settings
          debugPrint('Nickname registration failed: $e');
        }
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
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    }
  }
}

/// Restore Identity Screen
class RestoreIdentityScreen extends ConsumerStatefulWidget {
  const RestoreIdentityScreen({super.key});

  @override
  ConsumerState<RestoreIdentityScreen> createState() => _RestoreIdentityScreenState();
}

class _RestoreIdentityScreenState extends ConsumerState<RestoreIdentityScreen> {
  final _seedController = TextEditingController();
  bool _isRestoring = false;

  @override
  void dispose() {
    _seedController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Restore Identity'),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Enter your recovery phrase',
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 8),
              Text(
                'Enter the 24-word seed phrase you saved when creating your identity.',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 24),
              Expanded(
                child: TextField(
                  controller: _seedController,
                  decoration: const InputDecoration(
                    labelText: 'Seed Phrase',
                    hintText: 'word1 word2 word3 ...',
                    alignLabelWithHint: true,
                  ),
                  maxLines: 4,
                  textInputAction: TextInputAction.done,
                  onChanged: (_) => setState(() {}),
                ),
              ),
              const SizedBox(height: 24),
              if (_isRestoring)
                const Center(child: CircularProgressIndicator())
              else
                ElevatedButton(
                  onPressed: _seedController.text.trim().split(' ').length >= 24
                      ? _restoreIdentity
                      : null,
                  child: const Text('Restore Identity'),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _restoreIdentity() async {
    setState(() => _isRestoring = true);

    try {
      final mnemonic = _seedController.text.trim();
      final words = mnemonic.split(' ');

      if (words.length < 12) {
        throw Exception('Seed phrase must have at least 12 words');
      }

      // Validate mnemonic
      final isValid = await ref.read(identitiesProvider.notifier).validateMnemonic(mnemonic);
      if (!isValid) {
        throw Exception('Invalid seed phrase. Please check your words.');
      }

      // Create identity from mnemonic using real BIP39
      final fingerprint = await ref.read(identitiesProvider.notifier)
          .createIdentityFromMnemonic(mnemonic);

      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      setState(() => _isRestoring = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to restore identity: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    }
  }
}
