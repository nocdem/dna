// Settings Screen - App settings and profile management
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../profile/profile_editor_screen.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final profile = ref.watch(userProfileProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          // Profile section
          _ProfileSection(
            fingerprint: fingerprint,
            profile: profile,
          ),
          const Divider(),
          // Security
          _SecuritySection(),
          const Divider(),
          // About & Identity
          _IdentitySection(fingerprint: fingerprint),
        ],
      ),
    );
  }
}

class _ProfileSection extends StatelessWidget {
  final String? fingerprint;
  final AsyncValue<UserProfile?> profile;

  const _ProfileSection({
    required this.fingerprint,
    required this.profile,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              CircleAvatar(
                radius: 32,
                backgroundColor: theme.colorScheme.primary.withAlpha(51),
                child: Icon(
                  Icons.person,
                  size: 32,
                  color: theme.colorScheme.primary,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    profile.when(
                      data: (p) => Text(
                        p?.nickname ?? 'Anonymous',
                        style: theme.textTheme.titleLarge,
                      ),
                      loading: () => const SizedBox(
                        width: 100,
                        height: 20,
                        child: LinearProgressIndicator(),
                      ),
                      error: (e, st) => Text(
                        'Anonymous',
                        style: theme.textTheme.titleLarge,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      fingerprint != null
                          ? _shortenFingerprint(fingerprint!)
                          : 'Not loaded',
                      style: theme.textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        ListTile(
          leading: Icon(Icons.edit, color: theme.colorScheme.primary),
          title: const Text('Edit Profile'),
          subtitle: const Text('Wallets, socials, bio, avatar'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const ProfileEditorScreen(),
              ),
            );
          },
        ),
      ],
    );
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 20) return fp;
    return '${fp.substring(0, 10)}...${fp.substring(fp.length - 10)}';
  }
}

class _SecuritySection extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Row(
            children: [
              Icon(
                Icons.security,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                'Security',
                style: theme.textTheme.titleMedium,
              ),
            ],
          ),
        ),
        ListTile(
          leading: const Icon(Icons.vpn_key),
          title: const Text('Export Seed Phrase'),
          subtitle: const Text('Back up your recovery phrase'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showExportSeedDialog(context),
        ),
        ListTile(
          leading: const Icon(Icons.lock),
          title: const Text('App Lock'),
          subtitle: const Text('Require authentication'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Coming soon')),
            );
          },
        ),
      ],
    );
  }

  void _showExportSeedDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Export Seed Phrase'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.warning_amber,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            const Text(
              'Your seed phrase gives full access to your identity. Never share it with anyone.',
              textAlign: TextAlign.center,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Show seed phrase with confirmation
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Feature coming soon')),
              );
            },
            child: const Text('Show Seed'),
          ),
        ],
      ),
    );
  }
}

class _IdentitySection extends ConsumerWidget {
  final String? fingerprint;

  const _IdentitySection({required this.fingerprint});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Row(
            children: [
              Icon(
                Icons.fingerprint,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                'Identity',
                style: theme.textTheme.titleMedium,
              ),
            ],
          ),
        ),
        if (fingerprint != null)
          ListTile(
            leading: const Icon(Icons.content_copy),
            title: const Text('Copy Fingerprint'),
            subtitle: Text(
              fingerprint!,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
              ),
            ),
            onTap: () {
              Clipboard.setData(ClipboardData(text: fingerprint!));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Fingerprint copied')),
              );
            },
          ),
        ListTile(
          leading: Icon(Icons.swap_horiz, color: theme.colorScheme.secondary),
          title: const Text('Switch Identity'),
          subtitle: const Text('Use a different identity'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _confirmSwitchIdentity(context, ref),
        ),
        const SizedBox(height: 16),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            'DNA Messenger v1.0.0',
            style: theme.textTheme.bodySmall,
            textAlign: TextAlign.center,
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            'Post-Quantum Encrypted',
            style: theme.textTheme.labelSmall?.copyWith(
              color: theme.colorScheme.primary,
            ),
            textAlign: TextAlign.center,
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  void _confirmSwitchIdentity(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Switch Identity'),
        content: const Text(
          'Are you sure you want to switch to a different identity? You will need to sign in again.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              ref.read(identitiesProvider.notifier).unloadIdentity();
            },
            child: const Text('Switch'),
          ),
        ],
      ),
    );
  }
}
