// Settings Screen - App settings and profile management
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../profile/profile_editor_screen.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final simpleProfile = ref.watch(userProfileProvider);
    final fullProfile = ref.watch(fullProfileProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          // Profile section
          _ProfileSection(
            fingerprint: fingerprint,
            simpleProfile: simpleProfile,
            fullProfile: fullProfile,
          ),
          // Security
          _SecuritySection(),
          // Log settings
          _LogSettingsSection(),
          // Identity
          _IdentitySection(fingerprint: fingerprint),
          // About
          _AboutSection(),
        ],
      ),
    );
  }
}

/// Section header widget - clearly non-interactive
class _SectionHeader extends StatelessWidget {
  final String title;

  const _SectionHeader(this.title);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
      child: Text(
        title.toUpperCase(),
        style: theme.textTheme.labelSmall?.copyWith(
          color: theme.colorScheme.primary,
          fontWeight: FontWeight.w600,
          letterSpacing: 1.2,
        ),
      ),
    );
  }
}

class _ProfileSection extends StatelessWidget {
  final String? fingerprint;
  final AsyncValue<UserProfile?> simpleProfile;
  final AsyncValue<engine.UserProfile?> fullProfile;

  const _ProfileSection({
    required this.fingerprint,
    required this.simpleProfile,
    required this.fullProfile,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Profile card - tappable to edit
        InkWell(
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const ProfileEditorScreen(),
              ),
            );
          },
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                _buildAvatar(theme),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      simpleProfile.when(
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
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: DnaColors.textMuted,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Tap to edit profile',
                        style: theme.textTheme.labelSmall?.copyWith(
                          color: theme.colorScheme.primary,
                        ),
                      ),
                    ],
                  ),
                ),
                Icon(
                  Icons.chevron_right,
                  color: DnaColors.textMuted,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 20) return fp;
    return '${fp.substring(0, 10)}...${fp.substring(fp.length - 10)}';
  }

  Widget _buildAvatar(ThemeData theme) {
    return fullProfile.when(
      data: (p) {
        final avatarBase64 = p?.avatarBase64 ?? '';
        if (avatarBase64.isNotEmpty) {
          try {
            final bytes = base64Decode(avatarBase64);
            return CircleAvatar(
              radius: 32,
              backgroundImage: MemoryImage(bytes),
            );
          } catch (e) {
            // Fall through to default avatar
          }
        }
        return CircleAvatar(
          radius: 32,
          backgroundColor: theme.colorScheme.primary.withAlpha(51),
          child: Icon(
            Icons.person,
            size: 32,
            color: theme.colorScheme.primary,
          ),
        );
      },
      loading: () => CircleAvatar(
        radius: 32,
        backgroundColor: theme.colorScheme.primary.withAlpha(51),
        child: const SizedBox(
          width: 24,
          height: 24,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      ),
      error: (_, __) => CircleAvatar(
        radius: 32,
        backgroundColor: theme.colorScheme.primary.withAlpha(51),
        child: Icon(
          Icons.person,
          size: 32,
          color: theme.colorScheme.primary,
        ),
      ),
    );
  }
}

class _SecuritySection extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Security'),
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

class _LogSettingsSection extends ConsumerStatefulWidget {
  @override
  ConsumerState<_LogSettingsSection> createState() => _LogSettingsSectionState();
}

class _LogSettingsSectionState extends ConsumerState<_LogSettingsSection> {
  String _currentLevel = 'WARN';
  String _currentTags = '';
  final _tagsController = TextEditingController();

  static const _logLevels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'NONE'];
  static const _commonTags = [
    'DHT',
    'ICE',
    'TURN',
    'MESSENGER',
    'WALLET',
    'MSG',
    'IDENTITY',
  ];

  @override
  void initState() {
    super.initState();
    _loadCurrentSettings();
  }

  @override
  void dispose() {
    _tagsController.dispose();
    super.dispose();
  }

  Future<void> _loadCurrentSettings() async {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      if (mounted) {
        setState(() {
          _currentLevel = engine.getLogLevel();
          _currentTags = engine.getLogTags();
          _tagsController.text = _currentTags;
        });
      }
    });
  }

  Future<void> _setLogLevel(String level) async {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      if (engine.setLogLevel(level)) {
        setState(() {
          _currentLevel = level;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Log level set to $level')),
        );
      }
    });
  }

  Future<void> _setLogTags(String tags) async {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      if (engine.setLogTags(tags)) {
        setState(() {
          _currentTags = tags;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(tags.isEmpty
                ? 'Showing all log tags'
                : 'Log filter applied'),
          ),
        );
      }
    });
  }

  void _toggleTag(String tag) {
    final currentSet = _currentTags.isEmpty
        ? <String>{}
        : _currentTags.split(',').map((t) => t.trim()).toSet();

    if (currentSet.contains(tag)) {
      currentSet.remove(tag);
    } else {
      currentSet.add(tag);
    }

    final newTags = currentSet.join(',');
    _tagsController.text = newTags;
    _setLogTags(newTags);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final selectedTags = _currentTags.isEmpty
        ? <String>{}
        : _currentTags.split(',').map((t) => t.trim()).toSet();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Developer'),
        // Log Level
        ListTile(
          leading: const Icon(Icons.bug_report),
          title: const Text('Log Level'),
          subtitle: Text('Current: $_currentLevel'),
          trailing: DropdownButton<String>(
            value: _currentLevel,
            underline: const SizedBox(),
            items: _logLevels.map((level) {
              return DropdownMenuItem(
                value: level,
                child: Text(level),
              );
            }).toList(),
            onChanged: (value) {
              if (value != null) {
                _setLogLevel(value);
              }
            },
          ),
        ),
        // Log Tags
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Log Tags Filter',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 4),
              Text(
                'Select tags to show (empty = show all)',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textMuted,
                ),
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _commonTags.map((tag) {
                  final isSelected = selectedTags.contains(tag);
                  return FilterChip(
                    label: Text(tag),
                    selected: isSelected,
                    onSelected: (_) => _toggleTag(tag),
                    selectedColor: theme.colorScheme.primary.withAlpha(51),
                    checkmarkColor: theme.colorScheme.primary,
                  );
                }).toList(),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _tagsController,
                decoration: InputDecoration(
                  labelText: 'Custom tags (comma-separated)',
                  hintText: 'DHT,ICE,MSG',
                  border: const OutlineInputBorder(),
                  suffixIcon: IconButton(
                    icon: const Icon(Icons.check),
                    onPressed: () => _setLogTags(_tagsController.text),
                  ),
                ),
                onSubmitted: _setLogTags,
              ),
              if (_currentTags.isNotEmpty) ...[
                const SizedBox(height: 8),
                TextButton.icon(
                  onPressed: () {
                    _tagsController.clear();
                    _setLogTags('');
                  },
                  icon: const Icon(Icons.clear, size: 18),
                  label: const Text('Clear filter (show all)'),
                ),
              ],
            ],
          ),
        ),
      ],
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
        const _SectionHeader('Identity'),
        if (fingerprint != null)
          ListTile(
            leading: const Icon(Icons.fingerprint),
            title: const Text('Fingerprint'),
            subtitle: Text(
              fingerprint!,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
              ),
            ),
            trailing: const Icon(Icons.content_copy),
            onTap: () {
              Clipboard.setData(ClipboardData(text: fingerprint!));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Fingerprint copied')),
              );
            },
          ),
      ],
    );
  }
}

class _AboutSection extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('About'),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'DNA Messenger v1.0.0 alpha',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 4),
              Text(
                'Post-Quantum Encrypted Messenger',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textMuted,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'CRYPTO STACK',
                style: theme.textTheme.labelSmall?.copyWith(
                  color: DnaColors.textMuted,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'ML-DSA-87 · ML-KEM-1024 · AES-256-GCM AEAD',
                style: theme.textTheme.labelSmall?.copyWith(
                  color: theme.colorScheme.primary,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 16),
              Text(
                '© 2025 cpunk.io',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textMuted,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'GNU GPLv3',
                style: theme.textTheme.labelSmall?.copyWith(
                  color: DnaColors.textMuted,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
      ],
    );
  }
}
