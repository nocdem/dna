// Settings Screen - App settings and profile management
import 'dart:io';
import 'package:archive/archive.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../platform/android/notification_settings.dart';
import '../../providers/providers.dart';
import '../../providers/version_check_provider.dart';
import '../../theme/dna_theme.dart';
import '../../utils/platform_utils.dart';
import '../profile/profile_editor_screen.dart';
import 'app_lock_settings_screen.dart';
import 'blocked_users_screen.dart';
import 'contacts_management_screen.dart';

/// Provider for app package info (version from pubspec.yaml)
final packageInfoProvider = FutureProvider<PackageInfo>((ref) async {
  return await PackageInfo.fromPlatform();
});

class SettingsScreen extends ConsumerWidget {
  final VoidCallback? onMenuPressed;

  const SettingsScreen({super.key, this.onMenuPressed});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final simpleProfile = ref.watch(userProfileProvider);
    final fullProfile = ref.watch(fullProfileProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        leading: onMenuPressed != null
            ? IconButton(
                icon: const FaIcon(FontAwesomeIcons.bars),
                onPressed: onMenuPressed,
              )
            : null,
      ),
      body: SafeArea(
        top: false,
        child: ListView(
          children: [
            // Profile section
            _ProfileSection(
              fingerprint: fingerprint,
              simpleProfile: simpleProfile,
              fullProfile: fullProfile,
            ),
            // Contacts
            _ContactsSection(),
            // Notifications (Android only)
            const _NotificationsSection(),
            // Security
            _SecuritySection(),
            // Data (backup/restore)
            _DataSection(),
            // Logs settings
            _LogSettingsSection(),
            // Identity
            _IdentitySection(fingerprint: fingerprint),
            // About
            _AboutSection(),
          ],
        ),
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
                FaIcon(
                  FontAwesomeIcons.chevronRight,
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
            FontAwesomeIcons.user,
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
        child: FaIcon(
          FontAwesomeIcons.user,
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
      error: (_, _) => 0,
    );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Contacts'),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.users),
          title: const Text('Manage Contacts'),
          subtitle: Text(contactCount > 0 ? '$contactCount contacts' : 'No contacts'),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
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

/// Notifications section - Android only
/// Desktop notifications not yet implemented (see MISSING_FEATURES.md)
class _NotificationsSection extends StatelessWidget {
  const _NotificationsSection();

  @override
  Widget build(BuildContext context) {
    // Only show on Android - Desktop notifications not implemented yet
    if (!PlatformUtils.isAndroid) {
      return const SizedBox.shrink();
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: const [
        _SectionHeader('Notifications'),
        AndroidNotificationSettings(),
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
          leading: const FaIcon(FontAwesomeIcons.key),
          title: const Text('Export Seed Phrase'),
          subtitle: const Text('Back up your recovery phrase'),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () => _showExportSeedDialog(context),
        ),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.lock),
          title: const Text('App Lock'),
          subtitle: const Text('Require authentication'),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const AppLockSettingsScreen(),
              ),
            );
          },
        ),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.ban),
          title: const Text('Blocked Users'),
          subtitle: Text(blockedCount > 0 ? '$blockedCount blocked' : 'No blocked users'),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
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
              FontAwesomeIcons.triangleExclamation,
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
                  FaIcon(FontAwesomeIcons.key, color: DnaColors.textWarning),
                  const SizedBox(width: 8),
                  const Expanded(child: Text('Your Seed Phrase')),
                ],
              ),
              content: SizedBox(
                width: double.maxFinite,
                child: SingleChildScrollView(
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
                        Icon(FontAwesomeIcons.triangleExclamation, size: 16, color: DnaColors.textWarning),
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
  String _formatLastSync(DateTime? lastSync) {
    if (lastSync == null) return 'Never synced';
    final now = DateTime.now();
    final diff = now.difference(lastSync);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes} min ago';
    if (diff.inHours < 24) return '${diff.inHours} hours ago';
    return '${diff.inDays} days ago';
  }

  @override
  Widget build(BuildContext context) {
    final syncState = ref.watch(syncSettingsProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Data'),
        // Auto-sync toggle
        SwitchListTile(
          secondary: FaIcon(
            FontAwesomeIcons.arrowsRotate,
            color: syncState.autoSyncEnabled
                ? Theme.of(context).colorScheme.primary
                : null,
          ),
          title: const Text('Auto Sync'),
          subtitle: Text(
            syncState.autoSyncEnabled
                ? 'Last sync: ${_formatLastSync(syncState.lastSyncTime)}'
                : 'Sync messages automatically every 15 minutes',
          ),
          value: syncState.autoSyncEnabled,
          onChanged: (value) {
            ref.read(syncSettingsProvider.notifier).setAutoSyncEnabled(value);
          },
        ),
        // Sync Now button (visible when auto-sync is enabled)
        if (syncState.autoSyncEnabled)
          ListTile(
            leading: syncState.isSyncing
                ? const SizedBox(
                    width: 24,
                    height: 24,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const FaIcon(FontAwesomeIcons.rotate),
            title: const Text('Sync Now'),
            subtitle: syncState.lastSyncError != null
                ? Text(
                    syncState.lastSyncError!,
                    style: TextStyle(color: DnaColors.textWarning),
                  )
                : const Text('Force immediate sync'),
            trailing: syncState.isSyncing ? null : const FaIcon(FontAwesomeIcons.chevronRight),
            onTap: syncState.isSyncing
                ? null
                : () => ref.read(syncSettingsProvider.notifier).syncNow(),
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
  /// Get the logs directory path
  String _getLogsDir() {
    if (Platform.isLinux || Platform.isMacOS) {
      final home = Platform.environment['HOME'] ?? '/tmp';
      return '$home/.dna/logs';
    } else if (Platform.isWindows) {
      // Match engine_provider.dart: use USERPROFILE\.dna
      final home = Platform.environment['USERPROFILE'] ?? 'C:\\Users';
      return '$home\\.dna\\logs';
    } else {
      // Android - use app-specific directory
      // This will be set after we get the actual path
      return '';
    }
  }

  Future<void> _openOrShareLogs(BuildContext context) async {
    final isDesktop = Platform.isLinux || Platform.isWindows || Platform.isMacOS;

    try {
      if (isDesktop) {
        // Desktop: Open file manager at logs folder
        final logsDir = _getLogsDir();
        final dir = Directory(logsDir);

        if (!await dir.exists()) {
          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: const Text('Logs folder does not exist yet'),
                backgroundColor: DnaColors.snackbarInfo,
              ),
            );
          }
          return;
        }

        // Open file manager using platform-specific command
        ProcessResult result;
        if (Platform.isLinux) {
          result = await Process.run('xdg-open', [logsDir]);
        } else if (Platform.isWindows) {
          result = await Process.run('explorer', [logsDir]);
        } else {
          // macOS
          result = await Process.run('open', [logsDir]);
        }

        // Note: Windows explorer.exe returns exit code 1 even on success,
        // so we only check exit code on non-Windows platforms
        if (!Platform.isWindows && result.exitCode != 0 && context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Could not open folder: ${result.stderr}'),
              backgroundColor: DnaColors.snackbarError,
            ),
          );
        }
      } else {
        // Mobile: Zip log files and share
        // Use getApplicationSupportDirectory() to match engine_provider.dart
        final appDir = await getApplicationSupportDirectory();
        final logsDir = Directory('${appDir.path}/dna_messenger/logs');

        if (!await logsDir.exists()) {
          // Try to list parent directory to see what's there
          final parentDir = Directory('${appDir.path}/dna_messenger');
          String debugInfo = 'Path: ${logsDir.path}';
          if (await parentDir.exists()) {
            final contents = await parentDir.list().map((e) => e.path.split('/').last).toList();
            debugInfo += '\nParent contents: ${contents.join(", ")}';
          } else {
            debugInfo += '\nParent dir does not exist: ${parentDir.path}';
          }

          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('No logs yet. $debugInfo'),
                backgroundColor: DnaColors.snackbarInfo,
                duration: const Duration(seconds: 10),
              ),
            );
          }
          return;
        }

        // Find all log files
        final logFiles = await logsDir
            .list()
            .where((f) => f is File && f.path.contains('dna') && f.path.endsWith('.log'))
            .cast<File>()
            .toList();

        if (logFiles.isEmpty) {
          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: const Text('No log files found'),
                backgroundColor: DnaColors.snackbarInfo,
              ),
            );
          }
          return;
        }

        // Create zip archive
        final archive = Archive();
        for (final file in logFiles) {
          final bytes = await file.readAsBytes();
          final filename = file.path.split('/').last;
          archive.addFile(ArchiveFile(filename, bytes.length, bytes));
        }

        // Encode zip
        final zipData = ZipEncoder().encode(archive);
        if (zipData == null) {
          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: const Text('Failed to create zip archive'),
                backgroundColor: DnaColors.snackbarError,
              ),
            );
          }
          return;
        }

        // Save to temp and share
        final tempDir = await getTemporaryDirectory();
        final timestamp = DateTime.now().toIso8601String().replaceAll(':', '-').split('.')[0];
        final zipPath = '${tempDir.path}/dna_logs_$timestamp.zip';
        await File(zipPath).writeAsBytes(zipData);

        await Share.shareXFiles(
          [XFile(zipPath)],
          subject: 'DNA Messenger Logs',
          text: 'Debug logs from DNA Messenger',
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('Logs'),
        // Open/Share Logs
        ListTile(
          leading: FaIcon(
            Platform.isLinux || Platform.isWindows || Platform.isMacOS
                ? FontAwesomeIcons.folderOpen
                : FontAwesomeIcons.shareNodes,
          ),
          title: Text(
            Platform.isLinux || Platform.isWindows || Platform.isMacOS
                ? 'Open Logs Folder'
                : 'Share Logs',
          ),
          subtitle: Text(
            Platform.isLinux || Platform.isWindows || Platform.isMacOS
                ? 'Open file manager at logs directory'
                : 'Zip and share log files',
          ),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () => _openOrShareLogs(context),
        ),
      ],
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
            leading: const FaIcon(FontAwesomeIcons.fingerprint),
            title: const Text('Fingerprint'),
            subtitle: Text(
              fingerprint,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
              ),
            ),
            trailing: const FaIcon(FontAwesomeIcons.copy),
            onTap: () {
              Clipboard.setData(ClipboardData(text: fingerprint));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Fingerprint copied')),
              );
            },
          ),
        // v0.3.0: Delete Account (renamed from Delete Identity - single-user model)
        ListTile(
          leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.textWarning),
          title: Text(
            'Delete Account',
            style: TextStyle(color: DnaColors.textWarning),
          ),
          subtitle: const Text('Permanently delete all data from device'),
          trailing: _isDeleting
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : FaIcon(FontAwesomeIcons.chevronRight, color: DnaColors.textMuted),
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
            FaIcon(FontAwesomeIcons.triangleExclamation, color: DnaColors.textWarning),
            const SizedBox(width: 8),
            const Text('Delete Account?'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This will permanently delete all local data:',
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
                  FaIcon(FontAwesomeIcons.circleInfo, size: 20, color: DnaColors.textWarning),
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
          FaIcon(FontAwesomeIcons.circle, size: 6, color: DnaColors.textMuted),
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
                content: const Text('Account deleted successfully'),
                backgroundColor: DnaColors.snackbarSuccess,
              ),
            );

            // v0.3.0: Clear fingerprint - app will restart to onboarding
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
            content: Text('Failed to delete account: $e'),
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

class _AboutSection extends ConsumerWidget {
  const _AboutSection();

  static const _downloadUrl = 'https://cpunk.io/products/dna-messenger.html';

  Future<void> _openDownloadPage() async {
    final uri = Uri.parse(_downloadUrl);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final engineAsync = ref.watch(engineProvider);
    final packageInfoAsync = ref.watch(packageInfoProvider);
    final versionCheckAsync = ref.watch(versionCheckProvider);

    // Get library version from native library
    final libVersion = engineAsync.whenOrNull(
      data: (engine) => engine.version,
    ) ?? 'unknown';

    // Get app version from pubspec.yaml
    final appVersion = packageInfoAsync.whenOrNull(
      data: (info) => info.version,
    ) ?? 'unknown';

    // Check if update is available
    final versionCheck = versionCheckAsync.valueOrNull;
    final hasUpdate = versionCheck?.hasUpdate ?? false;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionHeader('About'),
        // Update warning card
        if (hasUpdate && versionCheck != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Card(
              color: DnaColors.textWarning.withValues(alpha: 0.15),
              child: InkWell(
                onTap: _openDownloadPage,
                borderRadius: BorderRadius.circular(12),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      FaIcon(FontAwesomeIcons.triangleExclamation, color: DnaColors.textWarning, size: 20),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Update Available',
                              style: theme.textTheme.bodyMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'Tap to download',
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: DnaColors.textMuted,
                              ),
                            ),
                          ],
                        ),
                      ),
                      FaIcon(FontAwesomeIcons.arrowUpRightFromSquare, size: 14, color: DnaColors.textMuted),
                    ],
                  ),
                ),
              ),
            ),
          ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'DNA Messenger v$appVersion',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 4),
              Text(
                'Library v$libVersion',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textMuted,
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
