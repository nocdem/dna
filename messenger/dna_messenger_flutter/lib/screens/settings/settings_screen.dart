// Settings Screen - App settings and profile management
import 'dart:io';
import 'package:archive/archive.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../../l10n/app_localizations.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../providers/providers.dart';
import '../../providers/version_check_provider.dart';
import '../../design_system/design_system.dart';
import '../profile/profile_editor_screen.dart';
import 'app_lock_settings_screen.dart';

/// Provider for app package info (version from pubspec.yaml)
final packageInfoProvider = FutureProvider<PackageInfo>((ref) async {
  return await PackageInfo.fromPlatform();
});

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final simpleProfile = ref.watch(userProfileProvider);
    final fullProfile = ref.watch(fullProfileProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(AppLocalizations.of(context).settingsTitle),
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
            // Appearance
            const _AppearanceSection(),
            // Language
            const _LanguageSection(),
            // Notifications (Android only)
            const _NotificationsSection(),
            // Security
            _SecuritySection(),
            // Wallet
            const _WalletSection(),
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
                          p?.nickname ?? AppLocalizations.of(context).settingsAnonymous,
                          style: theme.textTheme.titleLarge,
                        ),
                        loading: () => const SizedBox(
                          width: 100,
                          height: 20,
                          child: LinearProgressIndicator(),
                        ),
                        error: (e, st) => Text(
                          AppLocalizations.of(context).settingsAnonymous,
                          style: theme.textTheme.titleLarge,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        fingerprint != null
                            ? _shortenFingerprint(fingerprint!)
                            : AppLocalizations.of(context).settingsNotLoaded,
                        style: theme.textTheme.bodySmall,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        AppLocalizations.of(context).settingsTapToEditProfile,
                        style: theme.textTheme.labelSmall?.copyWith(
                          color: theme.colorScheme.primary,
                        ),
                      ),
                    ],
                  ),
                ),
                FaIcon(
                  FontAwesomeIcons.chevronRight,
                  color: theme.textTheme.bodySmall?.color,
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

class _AppearanceSection extends ConsumerWidget {
  const _AppearanceSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeModeProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsAppearance),
        DnaSwitch(
          label: AppLocalizations.of(context).settingsDarkMode,
          subtitle: AppLocalizations.of(context).settingsDarkModeSubtitle,
          value: themeMode == ThemeMode.dark,
          onChanged: (v) => ref.read(themeModeProvider.notifier).toggle(),
        ),
      ],
    );
  }
}

class _LanguageSection extends ConsumerWidget {
  const _LanguageSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final locale = ref.watch(localeProvider);

    final l10n = AppLocalizations.of(context);
    String currentLabel;
    if (locale == null) {
      currentLabel = l10n.settingsLanguageSystem;
    } else if (locale.languageCode == 'tr') {
      currentLabel = 'Türkçe';
    } else {
      currentLabel = 'English';
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsLanguage),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.language),
          title: Text(AppLocalizations.of(context).settingsLanguage),
          subtitle: Text(currentLabel),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () => _showLanguagePicker(context, ref, locale),
        ),
      ],
    );
  }

  void _showLanguagePicker(BuildContext context, WidgetRef ref, Locale? current) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            RadioListTile<String>(
              title: const Text('System default'),
              value: 'system',
              groupValue: current == null ? 'system' : current.languageCode,
              onChanged: (_) {
                ref.read(localeProvider.notifier).setLocale(null);
                Navigator.pop(context);
              },
            ),
            RadioListTile<String>(
              title: const Text('English'),
              value: 'en',
              groupValue: current == null ? 'system' : current.languageCode,
              onChanged: (_) {
                ref.read(localeProvider.notifier).setLocale(const Locale('en'));
                Navigator.pop(context);
              },
            ),
            RadioListTile<String>(
              title: const Text('Türkçe'),
              value: 'tr',
              groupValue: current == null ? 'system' : current.languageCode,
              onChanged: (_) {
                ref.read(localeProvider.notifier).setLocale(const Locale('tr'));
                Navigator.pop(context);
              },
            ),
          ],
        ),
      ),
    );
  }
}

/// Battery optimization section - Android only
/// Lets user request exemption from Doze mode via system dialog
class _NotificationsSection extends StatefulWidget {
  const _NotificationsSection();

  @override
  State<_NotificationsSection> createState() => _NotificationsSectionState();
}

class _NotificationsSectionState extends State<_NotificationsSection>
    with WidgetsBindingObserver {
  bool? _isExempt;

  @override
  void initState() {
    super.initState();
    if (Platform.isAndroid) {
      WidgetsBinding.instance.addObserver(this);
      _checkStatus();
    }
  }

  @override
  void dispose() {
    if (Platform.isAndroid) {
      WidgetsBinding.instance.removeObserver(this);
    }
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Re-check when user returns from system settings dialog
    if (state == AppLifecycleState.resumed && Platform.isAndroid) {
      _checkStatus();
    }
  }

  Future<void> _checkStatus() async {
    final status = await Permission.ignoreBatteryOptimizations.isGranted;
    if (mounted) setState(() => _isExempt = status);
  }

  Future<void> _requestExemption() async {
    await Permission.ignoreBatteryOptimizations.request();
    await _checkStatus();
  }

  @override
  Widget build(BuildContext context) {
    if (!Platform.isAndroid) return const SizedBox.shrink();

    final isExempt = _isExempt;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsBattery),
        ListTile(
          leading: FaIcon(
            FontAwesomeIcons.batteryFull,
            color: isExempt == true
                ? Theme.of(context).colorScheme.primary
                : null,
          ),
          title: Text(AppLocalizations.of(context).settingsDisableBatteryOpt),
          subtitle: Text(
            isExempt == null
                ? AppLocalizations.of(context).settingsBatteryChecking
                : isExempt
                    ? AppLocalizations.of(context).settingsBatteryDisabled
                    : AppLocalizations.of(context).settingsBatteryTapToKeep,
          ),
          trailing: isExempt == true
              ? FaIcon(FontAwesomeIcons.circleCheck,
                  color: Theme.of(context).colorScheme.primary)
              : const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: _requestExemption,
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
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsSecurity),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.key),
          title: Text(AppLocalizations.of(context).settingsExportSeedPhrase),
          subtitle: Text(AppLocalizations.of(context).settingsExportSeedSubtitle),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () => _showExportSeedDialog(context),
        ),
        ListTile(
          leading: const FaIcon(FontAwesomeIcons.lock),
          title: Text(AppLocalizations.of(context).settingsAppLock),
          subtitle: Text(AppLocalizations.of(context).settingsAppLockSubtitle),
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
      ],
    );
  }

  void _showExportSeedDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).settingsExportSeedPhrase),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              FontAwesomeIcons.triangleExclamation,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              AppLocalizations.of(context).settingsExportSeedWarning,
              textAlign: TextAlign.center,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              _showSeedPhrase(context);
            },
            child: Text(AppLocalizations.of(context).settingsShowSeed),
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
                  Expanded(child: Text(AppLocalizations.of(context).settingsYourSeedPhrase)),
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
                        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
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
                            AppLocalizations.of(context).settingsSeedPhraseWarning,
                            style: Theme.of(context).textTheme.bodySmall,
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
                      SnackBar(content: Text(AppLocalizations.of(context).settingsSeedCopied)),
                    );
                  },
                  child: Text(AppLocalizations.of(context).copy),
                ),
                ElevatedButton(
                  onPressed: () => Navigator.pop(context),
                  child: Text(AppLocalizations.of(context).done),
                ),
              ],
            ),
          );
        } catch (e) {
          String errorMessage = AppLocalizations.of(context).settingsSeedError;
          if (e.toString().contains('not stored')) {
            errorMessage = AppLocalizations.of(context).settingsSeedNotAvailable;
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
          SnackBar(content: Text(AppLocalizations.of(context).pleaseWait)),
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

class _WalletSection extends ConsumerWidget {
  const _WalletSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final walletSettings = ref.watch(walletSettingsProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsWallet),
        SwitchListTile(
          secondary: FaIcon(
            FontAwesomeIcons.eyeSlash,
            color: walletSettings.hideZeroBalances
                ? Theme.of(context).colorScheme.primary
                : null,
          ),
          title: Text(AppLocalizations.of(context).settingsHideZeroBalance),
          subtitle: Text(AppLocalizations.of(context).settingsHideZeroBalanceSubtitle),
          value: walletSettings.hideZeroBalances,
          onChanged: (value) {
            ref.read(walletSettingsProvider.notifier).setHideZeroBalances(value);
          },
        ),
      ],
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
        _SectionHeader(AppLocalizations.of(context).settingsData),
        // Auto-sync toggle
        SwitchListTile(
          secondary: FaIcon(
            FontAwesomeIcons.arrowsRotate,
            color: syncState.autoSyncEnabled
                ? Theme.of(context).colorScheme.primary
                : null,
          ),
          title: Text(AppLocalizations.of(context).settingsAutoSync),
          subtitle: Text(
            syncState.autoSyncEnabled
                ? AppLocalizations.of(context).settingsLastSync(_formatLastSync(syncState.lastSyncTime))
                : AppLocalizations.of(context).settingsAutoSyncSubtitle,
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
            title: Text(AppLocalizations.of(context).settingsSyncNow),
            subtitle: syncState.lastSyncError != null
                ? Text(
                    syncState.lastSyncError!,
                    style: TextStyle(color: DnaColors.textWarning),
                  )
                : Text(AppLocalizations.of(context).settingsSyncNowSubtitle),
            trailing: syncState.isSyncing ? null : const FaIcon(FontAwesomeIcons.chevronRight),
            onTap: syncState.isSyncing
                ? null
                : () => ref.read(syncSettingsProvider.notifier).syncNow(),
          ),
        // Delete All Messages
        ListTile(
          leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.error),
          title: Text(AppLocalizations.of(context).settingsDeleteAllMessages),
          subtitle: Text(AppLocalizations.of(context).settingsDeleteAllMessagesSubtitle),
          onTap: () => _confirmPurgeAll(context, ref),
        ),
      ],
    );
  }

  void _confirmPurgeAll(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.settingsDeleteAllMessagesTitle),
        content: Text(l10n.settingsDeleteAllMessagesWarning),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(context);
              final eng = ref.read(engineProvider).valueOrNull;
              if (eng != null) {
                final success = await eng.deleteAllMessages();
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(success
                          ? l10n.settingsAllMessagesDeleted
                          : l10n.settingsDeleteAllMessagesFailed),
                    ),
                  );
                }
              }
            },
            style: TextButton.styleFrom(foregroundColor: DnaColors.error),
            child: Text(l10n.settingsDeleteEverything),
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
                content: Text(AppLocalizations.of(context).settingsLogsFolderNotExist),
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
                content: Text(AppLocalizations.of(context).settingsNoLogsYet(debugInfo)),
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
                content: Text(AppLocalizations.of(context).settingsNoLogFiles),
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
                content: Text(AppLocalizations.of(context).settingsFailedCreateZip),
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
        _SectionHeader(AppLocalizations.of(context).settingsLogs),
        // Open/Share Logs
        ListTile(
          leading: FaIcon(
            Platform.isLinux || Platform.isWindows || Platform.isMacOS
                ? FontAwesomeIcons.folderOpen
                : FontAwesomeIcons.shareNodes,
          ),
          title: Text(
            Platform.isLinux || Platform.isWindows || Platform.isMacOS
                ? AppLocalizations.of(context).settingsOpenLogsFolder
                : AppLocalizations.of(context).settingsShareLogs,
          ),
          subtitle: Text(
            Platform.isLinux || Platform.isWindows || Platform.isMacOS
                ? AppLocalizations.of(context).settingsOpenLogsFolderSubtitle
                : AppLocalizations.of(context).settingsShareLogsSubtitle,
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
        _SectionHeader(AppLocalizations.of(context).settingsIdentity),
        if (fingerprint != null)
          ListTile(
            leading: const FaIcon(FontAwesomeIcons.fingerprint),
            title: Text(AppLocalizations.of(context).settingsFingerprint),
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
                SnackBar(content: Text(AppLocalizations.of(context).settingsFingerprintCopied)),
              );
            },
          ),
        // v0.3.0: Delete Account (renamed from Delete Identity - single-user model)
        ListTile(
          leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.textWarning),
          title: Text(
            AppLocalizations.of(context).settingsDeleteAccount,
            style: TextStyle(color: DnaColors.textWarning),
          ),
          subtitle: Text(AppLocalizations.of(context).settingsDeleteAccountSubtitle),
          trailing: _isDeleting
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : FaIcon(FontAwesomeIcons.chevronRight, color: Theme.of(context).textTheme.bodySmall?.color),
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
            Text(AppLocalizations.of(context).settingsDeleteAccountConfirm),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              AppLocalizations.of(context).settingsDeleteAccountWarning,
            ),
            const SizedBox(height: 12),
            _buildBulletPoint(AppLocalizations.of(context).settingsDeletePrivateKeys),
            _buildBulletPoint(AppLocalizations.of(context).settingsDeleteWallets),
            _buildBulletPoint(AppLocalizations.of(context).settingsDeleteMessages),
            _buildBulletPoint(AppLocalizations.of(context).settingsDeleteContacts),
            _buildBulletPoint(AppLocalizations.of(context).settingsDeleteGroups),
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
                      AppLocalizations.of(context).settingsDeleteSeedWarning,
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
            child: Text(AppLocalizations.of(context).cancel),
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
            child: Text(AppLocalizations.of(context).delete),
          ),
        ],
      ),
    );
  }

  Widget _buildBulletPoint(String text) {
    final mutedColor = Theme.of(context).textTheme.bodySmall?.color;
    return Padding(
      padding: const EdgeInsets.only(left: 8, top: 4),
      child: Row(
        children: [
          FaIcon(FontAwesomeIcons.circle, size: 6, color: mutedColor),
          const SizedBox(width: 8),
          Text(text, style: TextStyle(color: mutedColor)),
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
                content: Text(AppLocalizations.of(context).settingsDeleteSuccess),
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
            content: Text(AppLocalizations.of(context).settingsDeleteFailed(e.toString())),
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
        _SectionHeader(AppLocalizations.of(context).settingsAbout),
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
                              AppLocalizations.of(context).settingsUpdateAvailable,
                              style: theme.textTheme.bodyMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              AppLocalizations.of(context).settingsTapToDownload,
                              style: theme.textTheme.bodySmall,
                            ),
                          ],
                        ),
                      ),
                      FaIcon(FontAwesomeIcons.arrowUpRightFromSquare, size: 14, color: theme.textTheme.bodySmall?.color),
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
                AppLocalizations.of(context).settingsAppVersion(appVersion),
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 4),
              Text(
                AppLocalizations.of(context).settingsLibVersion(libVersion),
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 4),
              Text(
                AppLocalizations.of(context).settingsPostQuantumMessenger,
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 16),
              Text(
                AppLocalizations.of(context).settingsCryptoStack,
                style: theme.textTheme.labelSmall?.copyWith(
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
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 4),
              Text(
                'GNU GPLv3',
                style: theme.textTheme.labelSmall,
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
      ],
    );
  }
}
