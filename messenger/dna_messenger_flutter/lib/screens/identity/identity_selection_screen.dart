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
                onPressed: () => _showCreateIdentityDialog(context, ref),
                icon: const Icon(Icons.add),
                label: const Text('Create New Identity'),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: () => _showRestoreIdentityDialog(context, ref),
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
    // Show loading
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
        Navigator.of(context).pop(); // Close loading
        // Navigation to home will happen via provider watching
      }
    } catch (e) {
      if (context.mounted) {
        Navigator.of(context).pop(); // Close loading
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to load identity: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    }
  }

  void _showCreateIdentityDialog(BuildContext context, WidgetRef ref) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const CreateIdentityScreen(),
      ),
    );
  }

  void _showRestoreIdentityDialog(BuildContext context, WidgetRef ref) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const RestoreIdentityScreen(),
      ),
    );
  }
}

/// Create Identity Screen - Step-by-step wizard
class CreateIdentityScreen extends ConsumerStatefulWidget {
  const CreateIdentityScreen({super.key});

  @override
  ConsumerState<CreateIdentityScreen> createState() => _CreateIdentityScreenState();
}

class _CreateIdentityScreenState extends ConsumerState<CreateIdentityScreen> {
  final _nameController = TextEditingController();
  String _mnemonic = '';
  bool _seedCopied = false;
  bool _seedConfirmed = false;
  bool _isCreating = false;

  @override
  void initState() {
    super.initState();
    _generateMnemonic();
  }

  void _generateMnemonic() {
    // TODO: Generate real BIP39 mnemonic
    // For now, use placeholder - will integrate with native library
    _mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  }

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Create Identity'),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Step indicator
              _buildStepIndicator(theme),
              const SizedBox(height: 32),

              // Content
              Expanded(
                child: _buildContent(theme),
              ),

              // Actions
              _buildActions(theme),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStepIndicator(ThemeData theme) {
    return Row(
      children: [
        _buildStep(theme, 1, 'Name', !_seedCopied),
        Expanded(
          child: Container(
            height: 2,
            color: _seedCopied
                ? theme.colorScheme.primary
                : theme.colorScheme.primary.withAlpha(51),
          ),
        ),
        _buildStep(theme, 2, 'Seed', _seedCopied && !_seedConfirmed),
        Expanded(
          child: Container(
            height: 2,
            color: _seedConfirmed
                ? theme.colorScheme.primary
                : theme.colorScheme.primary.withAlpha(51),
          ),
        ),
        _buildStep(theme, 3, 'Create', _seedConfirmed),
      ],
    );
  }

  Widget _buildStep(ThemeData theme, int number, String label, bool active) {
    final color = active
        ? theme.colorScheme.primary
        : theme.colorScheme.primary.withAlpha(128);

    return Column(
      children: [
        Container(
          width: 32,
          height: 32,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: active ? color : Colors.transparent,
            border: Border.all(color: color, width: 2),
          ),
          child: Center(
            child: Text(
              '$number',
              style: TextStyle(
                color: active ? theme.colorScheme.surface : color,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: theme.textTheme.bodySmall?.copyWith(color: color),
        ),
      ],
    );
  }

  Widget _buildContent(ThemeData theme) {
    if (!_seedCopied) {
      return _buildNameStep(theme);
    } else if (!_seedConfirmed) {
      return _buildSeedStep(theme);
    } else {
      return _buildCreateStep(theme);
    }
  }

  Widget _buildNameStep(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          'Choose a display name',
          style: theme.textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        Text(
          'This name will be visible to your contacts. You can register it on the DHT later.',
          style: theme.textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        TextField(
          controller: _nameController,
          decoration: const InputDecoration(
            labelText: 'Display Name',
            hintText: 'Enter your name',
          ),
          textCapitalization: TextCapitalization.words,
          autofocus: true,
        ),
      ],
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
            'Write down these 12 words in order. This is the ONLY way to recover your identity.',
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
                Text(
                  _mnemonic,
                  style: theme.textTheme.bodyLarge?.copyWith(
                    fontFamily: 'monospace',
                    height: 1.8,
                  ),
                  textAlign: TextAlign.center,
                ),
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
        ],
      ),
    );
  }

  Widget _buildCreateStep(ThemeData theme) {
    if (_isCreating) {
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
              'Generating cryptographic keys',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          'Ready to create',
          style: theme.textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        Text(
          'Your identity will be created with post-quantum encryption (Kyber1024 + Dilithium5).',
          style: theme.textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        _buildInfoRow(theme, Icons.person, 'Name', _nameController.text),
        const SizedBox(height: 12),
        _buildInfoRow(theme, Icons.security, 'Encryption', 'ML-KEM-1024 (Kyber)'),
        const SizedBox(height: 12),
        _buildInfoRow(theme, Icons.verified, 'Signing', 'ML-DSA-87 (Dilithium)'),
      ],
    );
  }

  Widget _buildInfoRow(ThemeData theme, IconData icon, String label, String value) {
    return Row(
      children: [
        Icon(icon, size: 20, color: theme.colorScheme.primary),
        const SizedBox(width: 12),
        Text('$label: ', style: theme.textTheme.bodySmall),
        Expanded(
          child: Text(value, style: theme.textTheme.bodyMedium),
        ),
      ],
    );
  }

  Widget _buildActions(ThemeData theme) {
    if (_isCreating) return const SizedBox.shrink();

    if (!_seedCopied) {
      return ElevatedButton(
        onPressed: _nameController.text.trim().isNotEmpty
            ? () => setState(() => _seedCopied = true)
            : null,
        child: const Text('Continue'),
      );
    } else if (!_seedConfirmed) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ElevatedButton(
            onPressed: () => setState(() => _seedConfirmed = true),
            child: const Text('I have saved my seed phrase'),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => setState(() => _seedCopied = false),
            child: const Text('Back'),
          ),
        ],
      );
    } else {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ElevatedButton(
            onPressed: _createIdentity,
            child: const Text('Create Identity'),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => setState(() => _seedConfirmed = false),
            child: const Text('Back'),
          ),
        ],
      );
    }
  }

  Future<void> _createIdentity() async {
    setState(() => _isCreating = true);

    try {
      // TODO: Convert mnemonic to seeds using BIP39
      // For now, use dummy seeds - will integrate properly
      final signingSeed = List<int>.filled(32, 0);
      final encryptionSeed = List<int>.filled(32, 1);

      final fingerprint = await ref.read(identitiesProvider.notifier)
          .createIdentity(signingSeed, encryptionSeed);

      // Load the new identity
      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

      if (mounted) {
        // Pop back to root, identity will be loaded
        Navigator.of(context).popUntil((route) => route.isFirst);
      }
    } catch (e) {
      setState(() => _isCreating = false);
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
                'Enter the 12-word seed phrase you saved when creating your identity.',
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
                  onPressed: _seedController.text.trim().split(' ').length >= 12
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
      if (words.length < 12) {
        throw Exception('Invalid seed phrase');
      }

      // For now, use dummy seeds - will integrate properly
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
