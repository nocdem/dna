// Settings Screen - App settings and profile management
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../profile/profile_editor_screen.dart';
import 'blocked_users_screen.dart';
import 'contacts_management_screen.dart';
import 'debug_log_screen.dart';

/// Developer mode state provider - persisted to SharedPreferences
final developerModeProvider = StateNotifierProvider<DeveloperModeNotifier, bool>((ref) {
  return DeveloperModeNotifier();
});

class DeveloperModeNotifier extends StateNotifier<bool> {
  static const _key = 'developer_mode_enabled';

  DeveloperModeNotifier() : super(false) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    state = prefs.getBool(_key) ?? false;
  }

  Future<void> setEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_key, enabled);
    state = enabled;
  }
}

class SettingsScreen extends ConsumerWidget {
  final VoidCallback? onMenuPressed;

  const SettingsScreen({super.key, this.onMenuPressed});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final simpleProfile = ref.watch(userProfileProvider);
    final fullProfile = ref.watch(fullProfileProvider);
    final developerMode = ref.watch(developerModeProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        leading: onMenuPressed != null
            ? IconButton(
                icon: const Icon(Icons.menu),
                onPressed: onMenuPressed,
              )
            : null,
      ),
      body: ListView(
        children: [
          // Profile section
          _ProfileSection(
            fingerprint: fingerprint,
            simpleProfile: simpleProfile,
            fullProfile: fullProfile,
          ),
          // Contacts
          _ContactsSection(),
          // Security
          _SecuritySection(),
          // Data (backup/restore)
          _DataSection(),
          // Developer settings (hidden by default)
          if (developerMode) _LogSettingsSection(),
          // Identity (tap fingerprint 5x to enable developer mode)
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
          final bytes = decodeBase64WithPadding(avatarBase64);
          if (bytes != null) {
            return CircleAvatar(
              radius: 32,
              backgroundImage: MemoryImage(bytes),
            );
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
      error: (e, st) => CircleAvatar(
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

class _ContactsSection extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);
    final contactCount = contacts.when(
      data: (list) => list.length,
      loading: () => 0,
      error: (_, __) => 0,
    );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Contacts'),
        ListTile(
          leading: const Icon(Icons.people),
          title: const Text('Manage Contacts'),
          subtitle: Text(contactCount > 0 ? '$contactCount contacts' : 'No contacts'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const ContactsManagementScreen(),
              ),
            );
          },
        ),
      ],
    );
  }
}

class _SecuritySection extends ConsumerStatefulWidget {
  @override
  ConsumerState<_SecuritySection> createState() => _SecuritySectionState();
}

class _SecuritySectionState extends ConsumerState<_SecuritySection> {
  @override
  Widget build(BuildContext context) {
    final blockedUsers = ref.watch(blockedUsersProvider);
    final blockedCount = blockedUsers.when(
      data: (list) => list.length,
      loading: () => 0,
      error: (e, st) => 0,
    );

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
        ListTile(
          leading: const Icon(Icons.block),
          title: const Text('Blocked Users'),
          subtitle: Text(blockedCount > 0 ? '$blockedCount blocked' : 'No blocked users'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const BlockedUsersScreen(),
              ),
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
              _showSeedPhrase(context);
            },
            child: const Text('Show Seed'),
          ),
        ],
      ),
    );
  }

  void _showSeedPhrase(BuildContext context) {
    final engineAsync = ref.read(engineProvider);

    engineAsync.when(
      data: (engine) {
        try {
          final mnemonic = engine.getMnemonic();
          final words = mnemonic.split(' ');

          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (context) => AlertDialog(
              title: Row(
                children: [
                  Icon(Icons.key, color: DnaColors.textWarning),
                  const SizedBox(width: 8),
                  const Expanded(child: Text('Your Seed Phrase')),
                ],
              ),
              content: SizedBox(
                width: double.maxFinite,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Theme.of(context).colorScheme.surface,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: DnaColors.textMuted.withAlpha(51)),
                      ),
                      child: LayoutBuilder(
                        builder: (context, constraints) {
                          final columns = constraints.maxWidth < 200 ? 2 : (constraints.maxWidth < 300 ? 3 : 4);
                          final rows = (words.length / columns).ceil();
                          final theme = Theme.of(context);

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
                      ),
                    ),
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        Icon(Icons.warning_amber, size: 16, color: DnaColors.textWarning),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Write these words down in order and store them safely. Anyone with this phrase can access your identity.',
                            style: TextStyle(
                              fontSize: 12,
                              color: DnaColors.textMuted,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: mnemonic));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Seed phrase copied to clipboard')),
                    );
                  },
                  child: const Text('Copy'),
                ),
                ElevatedButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Done'),
                ),
              ],
            ),
          );
        } catch (e) {
          String errorMessage = 'Unable to retrieve seed phrase';
          if (e.toString().contains('not stored')) {
            errorMessage = 'Seed phrase not available for this identity. It was created before this feature was added.';
          }
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(errorMessage),
              backgroundColor: DnaColors.snackbarError,
            ),
          );
        }
      },
      loading: () {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Please wait...')),
        );
      },
      error: (e, st) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Engine error: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      },
    );
  }
}

class _DataSection extends ConsumerStatefulWidget {
  @override
  ConsumerState<_DataSection> createState() => _DataSectionState();
}

class _DataSectionState extends ConsumerState<_DataSection> {
  bool _isBackingUp = false;
  bool _isRestoring = false;

  Future<void> _backupMessages(BuildContext context) async {
    // Show confirmation dialog
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Backup Messages'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This will upload all your messages to the DHT network.',
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary.withAlpha(26),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, size: 20, color: Theme.of(context).colorScheme.primary),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'Backup expires after 7 days. Only you can decrypt it.',
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
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Backup'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    setState(() => _isBackingUp = true);

    try {
      final engineAsync = ref.read(engineProvider);
      await engineAsync.when(
        data: (engine) async {
          final result = await engine.backupMessages();
          if (mounted) {
            if (result.success) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Backed up ${result.processedCount} messages'),
                  backgroundColor: DnaColors.snackbarSuccess,
                ),
              );
            } else {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(result.errorMessage ?? 'Backup failed'),
                  backgroundColor: DnaColors.snackbarError,
                ),
              );
            }
          }
        },
        loading: () {
          throw Exception('Engine not ready');
        },
        error: (e, st) {
          throw Exception('Engine error: $e');
        },
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Backup failed: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isBackingUp = false);
      }
    }
  }

  Future<void> _restoreMessages(BuildContext context) async {
    // Show confirmation dialog
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Restore Messages'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This will download messages from your DHT backup.',
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary.withAlpha(26),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, size: 20, color: Theme.of(context).colorScheme.primary),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'Duplicate messages will be skipped automatically.',
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
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Restore'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    setState(() => _isRestoring = true);

    try {
      final engineAsync = ref.read(engineProvider);
      await engineAsync.when(
        data: (engine) async {
          final result = await engine.restoreMessages();
          if (mounted) {
            if (result.success) {
              String message = 'Restored ${result.processedCount} messages';
              if (result.skippedCount > 0) {
                message += ' (${result.skippedCount} duplicates skipped)';
              }
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(message),
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
        },
        loading: () {
          throw Exception('Engine not ready');
        },
        error: (e, st) {
          throw Exception('Engine error: $e');
        },
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Restore failed: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isRestoring = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Data'),
        ListTile(
          leading: _isBackingUp
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.cloud_upload),
          title: const Text('Backup Messages'),
          subtitle: const Text('Upload messages to DHT (7 day TTL)'),
          trailing: _isBackingUp ? null : const Icon(Icons.chevron_right),
          onTap: _isBackingUp || _isRestoring ? null : () => _backupMessages(context),
        ),
        ListTile(
          leading: _isRestoring
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.cloud_download),
          title: const Text('Restore Messages'),
          subtitle: const Text('Download messages from DHT backup'),
          trailing: _isRestoring ? null : const Icon(Icons.chevron_right),
          onTap: _isBackingUp || _isRestoring ? null : () => _restoreMessages(context),
        ),
      ],
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
  bool _debugLogEnabled = false;

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

  Future<void> _loadCurrentSettings() async {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      if (mounted) {
        setState(() {
          _currentLevel = engine.getLogLevel();
          _currentTags = engine.getLogTags();
          _debugLogEnabled = engine.debugLogIsEnabled();
        });
      }
    });
  }

  void _toggleDebugLog(bool enabled) {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      engine.debugLogEnable(enabled);
      if (mounted) {
        setState(() {
          _debugLogEnabled = enabled;
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
    _setLogTags(newTags);
  }

  Future<void> _exportLogs(BuildContext context) async {
    final engineAsync = ref.read(engineProvider);

    await engineAsync.whenData((engine) async {
      try {
        // Get temp directory for export file
        final tempDir = await getTemporaryDirectory();
        final timestamp = DateTime.now().toIso8601String().replaceAll(':', '-').split('.')[0];
        final filepath = '${tempDir.path}/dna_messenger_logs_$timestamp.txt';

        // Export logs to file
        final success = engine.debugLogExport(filepath);
        if (!success) {
          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: const Text('Failed to export logs'),
                backgroundColor: DnaColors.snackbarError,
              ),
            );
          }
          return;
        }

        // Share the file
        final file = XFile(filepath);
        await Share.shareXFiles(
          [file],
          subject: 'DNA Messenger Logs',
          text: 'Debug logs from DNA Messenger',
        );
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Export failed: $e'),
              backgroundColor: DnaColors.snackbarError,
            ),
          );
        }
      }
    });
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
        // Debug Log Toggle
        SwitchListTile(
          secondary: Icon(
            Icons.article_outlined,
            color: _debugLogEnabled ? theme.colorScheme.primary : null,
          ),
          title: const Text('Debug Log Capture'),
          subtitle: Text(_debugLogEnabled ? 'Capturing logs to buffer' : 'Disabled'),
          value: _debugLogEnabled,
          onChanged: _toggleDebugLog,
        ),
        // View Debug Logs
        ListTile(
          leading: const Icon(Icons.visibility),
          title: const Text('View Debug Logs'),
          subtitle: const Text('Open in-app log viewer'),
          trailing: const Icon(Icons.chevron_right),
          enabled: _debugLogEnabled,
          onTap: _debugLogEnabled
              ? () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (context) => const DebugLogScreen(),
                    ),
                  );
                }
              : null,
        ),
        // Export Logs
        ListTile(
          leading: const Icon(Icons.share),
          title: const Text('Export Logs'),
          subtitle: const Text('Share log file for debugging'),
          trailing: const Icon(Icons.chevron_right),
          enabled: _debugLogEnabled,
          onTap: _debugLogEnabled ? () => _exportLogs(context) : null,
        ),
        const Divider(),
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
              Row(
                children: [
                  Icon(Icons.label_outline, size: 20, color: DnaColors.textMuted),
                  const SizedBox(width: 8),
                  Text('Log Tags', style: theme.textTheme.bodyMedium),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                'Filter logs by tag (none = show all)',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textMuted,
                ),
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ..._commonTags.map((tag) {
                    final isSelected = selectedTags.contains(tag);
                    return _PillButton(
                      label: tag,
                      isSelected: isSelected,
                      onTap: () => _toggleTag(tag),
                    );
                  }),
                  if (_currentTags.isNotEmpty)
                    _PillButton(
                      label: 'Clear',
                      isSelected: false,
                      isDestructive: true,
                      onTap: () => _setLogTags(''),
                    ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }
}

/// Pill-style button widget for settings
class _PillButton extends StatelessWidget {
  final String label;
  final bool isSelected;
  final bool isDestructive;
  final VoidCallback onTap;

  const _PillButton({
    required this.label,
    required this.isSelected,
    required this.onTap,
    this.isDestructive = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final Color baseColor;

    if (isDestructive) {
      baseColor = DnaColors.textWarning;
    } else if (isSelected) {
      baseColor = theme.colorScheme.primary;
    } else {
      baseColor = DnaColors.textMuted;
    }

    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: isSelected ? baseColor.withAlpha(26) : Colors.transparent,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isSelected ? baseColor.withAlpha(128) : baseColor.withAlpha(51),
            width: isSelected ? 1.5 : 1,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: isSelected ? baseColor : baseColor.withAlpha(179),
            fontSize: 12,
            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
          ),
        ),
      ),
    );
  }
}

class _IdentitySection extends ConsumerStatefulWidget {
  final String? fingerprint;

  const _IdentitySection({required this.fingerprint});

  @override
  ConsumerState<_IdentitySection> createState() => _IdentitySectionState();
}

class _IdentitySectionState extends ConsumerState<_IdentitySection> {
  bool _isDeleting = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fingerprint = widget.fingerprint;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Identity'),
        if (fingerprint != null)
          ListTile(
            leading: const Icon(Icons.fingerprint),
            title: const Text('Fingerprint'),
            subtitle: Text(
              fingerprint,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
              ),
            ),
            trailing: const Icon(Icons.content_copy),
            onTap: () {
              Clipboard.setData(ClipboardData(text: fingerprint));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Fingerprint copied')),
              );
            },
          ),
        // Delete Identity option
        ListTile(
          leading: Icon(Icons.delete_forever, color: DnaColors.textWarning),
          title: Text(
            'Delete Identity',
            style: TextStyle(color: DnaColors.textWarning),
          ),
          subtitle: const Text('Permanently delete this identity from device'),
          trailing: _isDeleting
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : Icon(Icons.chevron_right, color: DnaColors.textMuted),
          onTap: _isDeleting ? null : () => _showDeleteConfirmation(context),
        ),
      ],
    );
  }

  void _showDeleteConfirmation(BuildContext context) {
    final fingerprint = widget.fingerprint;
    if (fingerprint == null) return;

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: DnaColors.textWarning),
            const SizedBox(width: 8),
            const Text('Delete Identity?'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This will permanently delete all local data for this identity:',
            ),
            const SizedBox(height: 12),
            _buildBulletPoint('Private keys'),
            _buildBulletPoint('Wallets'),
            _buildBulletPoint('Messages'),
            _buildBulletPoint('Contacts'),
            _buildBulletPoint('Groups'),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: DnaColors.textWarning.withAlpha(26),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: DnaColors.textWarning.withAlpha(51)),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, size: 20, color: DnaColors.textWarning),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Make sure you have backed up your seed phrase before deleting!',
                      style: TextStyle(
                        fontSize: 13,
                        color: DnaColors.textWarning,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: DnaColors.textWarning,
              foregroundColor: Colors.white,
            ),
            onPressed: () {
              Navigator.pop(context);
              _deleteIdentity(fingerprint);
            },
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }

  Widget _buildBulletPoint(String text) {
    return Padding(
      padding: const EdgeInsets.only(left: 8, top: 4),
      child: Row(
        children: [
          Icon(Icons.circle, size: 6, color: DnaColors.textMuted),
          const SizedBox(width: 8),
          Text(text, style: TextStyle(color: DnaColors.textMuted)),
        ],
      ),
    );
  }

  Future<void> _deleteIdentity(String fingerprint) async {
    setState(() => _isDeleting = true);

    try {
      final engineAsync = ref.read(engineProvider);
      await engineAsync.when(
        data: (engine) async {
          engine.deleteIdentity(fingerprint);

          // Show success message
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: const Text('Identity deleted successfully'),
                backgroundColor: DnaColors.snackbarSuccess,
              ),
            );

            // Clear current fingerprint - this triggers identityLoadedProvider to return false
            // which causes HomeScreen to show IdentitySelectionScreen
            ref.read(currentFingerprintProvider.notifier).state = null;
          }
        },
        loading: () {
          throw Exception('Engine not ready');
        },
        error: (e, st) {
          throw Exception('Engine error: $e');
        },
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to delete identity: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isDeleting = false);
      }
    }
  }
}

class _AboutSection extends ConsumerStatefulWidget {
  @override
  ConsumerState<_AboutSection> createState() => _AboutSectionState();
}

class _AboutSectionState extends ConsumerState<_AboutSection> {
  int _tapCount = 0;
  DateTime? _lastTapTime;
  static const _requiredTaps = 5;
  static const _tapTimeout = Duration(seconds: 2);

  void _handleVersionTap() {
    final now = DateTime.now();
    final developerMode = ref.read(developerModeProvider);

    // If already enabled, disable on tap
    if (developerMode) {
      ref.read(developerModeProvider.notifier).setEnabled(false);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Developer mode disabled')),
      );
      return;
    }

    // Reset tap count if too much time has passed
    if (_lastTapTime != null && now.difference(_lastTapTime!) > _tapTimeout) {
      _tapCount = 0;
    }

    _lastTapTime = now;
    _tapCount++;

    if (_tapCount >= _requiredTaps) {
      ref.read(developerModeProvider.notifier).setEnabled(true);
      _tapCount = 0;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('Developer mode enabled'),
          backgroundColor: DnaColors.snackbarSuccess,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final developerMode = ref.watch(developerModeProvider);
    final engineAsync = ref.watch(engineProvider);

    // Get version from native library (single source of truth)
    final version = engineAsync.whenOrNull(
      data: (engine) => engine.version,
    ) ?? 'unknown';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('About'),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              GestureDetector(
                onTap: _handleVersionTap,
                child: Text(
                  'DNA Messenger v$version',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: developerMode ? DnaColors.textSuccess : null,
                  ),
                ),
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
