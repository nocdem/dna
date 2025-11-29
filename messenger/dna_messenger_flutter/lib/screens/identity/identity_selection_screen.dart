// Identity Selection Screen - Choose or create identity
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

  @override
  void initState() {
    super.initState();
    _generateMnemonic();
  }

  @override
  void dispose() {
    _nicknameController.dispose();
    super.dispose();
  }

  void _generateMnemonic() {
    // TODO: Generate real BIP39 mnemonic from native library
    // For now, use placeholder (24 words for 256-bit entropy - post-quantum security)
    _mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
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
            decoration: const InputDecoration(
              labelText: 'Nickname',
              hintText: 'Choose a unique nickname',
              prefixIcon: Icon(Icons.alternate_email),
            ),
            autofocus: true,
            textInputAction: TextInputAction.done,
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) {
              if (_nicknameController.text.trim().isNotEmpty) {
                _createIdentity();
              }
            },
          ),
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
            onPressed: _nicknameController.text.trim().isNotEmpty
                ? _createIdentity
                : null,
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
      // TODO: Convert mnemonic to seeds using BIP39
      // For now, use dummy seeds
      final signingSeed = List<int>.filled(32, 0);
      final encryptionSeed = List<int>.filled(32, 1);

      final fingerprint = await ref.read(identitiesProvider.notifier)
          .createIdentity(signingSeed, encryptionSeed);

      // TODO: Register nickname on DHT
      final nickname = _nicknameController.text.trim();
      if (nickname.isNotEmpty) {
        // await engine.registerNickname(nickname);
      }

      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

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
      // TODO: Convert mnemonic to seeds using BIP39
      final words = _seedController.text.trim().split(' ');
      if (words.length < 24) {
        throw Exception('Invalid seed phrase');
      }

      final signingSeed = List<int>.filled(32, 0);
      final encryptionSeed = List<int>.filled(32, 1);

      final fingerprint = await ref.read(identitiesProvider.notifier)
          .createIdentity(signingSeed, encryptionSeed);

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
