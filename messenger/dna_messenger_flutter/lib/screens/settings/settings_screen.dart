// Settings Screen - App settings and profile management
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart' show compute;
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
import '../../config/app_config.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/clipboard_utils.dart';
import '../../utils/log_sanitizer.dart';
import '../../utils/screen_security.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../providers/providers.dart';
import '../../providers/version_check_provider.dart';
import '../../design_system/design_system.dart';
import '../../services/cache_database.dart';
import '../../services/media_cache_service.dart';
import '../profile/profile_editor_screen.dart';
import 'app_lock_settings_screen.dart';

/// Provider for app package info (version from pubspec.yaml)
final packageInfoProvider = FutureProvider<PackageInfo>((ref) async {
  return await PackageInfo.fromPlatform();
});

class _DebugLogPayload {
  final Uint8List bytes;
  final bool truncated;
  _DebugLogPayload(this.bytes, this.truncated);
}

/// Background isolate: read log file, sanitize secrets, truncate to last 3 MB.
_DebugLogPayload _readAndSanitizeLog(String path) {
  const maxBytes = 3 * 1024 * 1024;
  final file = File(path);
  final raw = file.readAsStringSync();
  final safe = LogSanitizer.scrub(raw);
  final encoded = Uint8List.fromList(utf8.encode(safe));
  if (encoded.length > maxBytes) {
    final tail = Uint8List.fromList(
      encoded.sublist(encoded.length - maxBytes),
    );
    return _DebugLogPayload(tail, true);
  }
  return _DebugLogPayload(encoded, false);
}

/// Background isolate function for zipping log files (avoids UI freeze)
List<int>? _zipLogFiles(List<String> filePaths) {
  final archive = Archive();
  for (final path in filePaths) {
    final file = File(path);
    if (!file.existsSync()) continue;
    final bytes = file.readAsBytesSync();
    final filename = path.split('/').last;
    archive.addFile(ArchiveFile(filename, bytes.length, bytes));
  }
  return ZipEncoder().encode(archive);
}

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
            // Profile
            _ProfileSection(
              fingerprint: fingerprint,
              simpleProfile: simpleProfile,
              fullProfile: fullProfile,
            ),
            // General (Appearance + Language + Notifications)
            const _GeneralSection(),
            // Security
            _SecuritySection(),
            // Wallet
            const _WalletSection(),
            // Data & Storage (Sync + Delete + Cache + Logs)
            _DataStorageSection(),
            // Account (Fingerprint + Delete Account)
            _AccountSection(fingerprint: fingerprint),
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

class _GeneralSection extends ConsumerWidget {
  const _GeneralSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeModeProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsGeneral),
        // Dark mode
        DnaSwitch(
          label: AppLocalizations.of(context).settingsDarkMode,
          subtitle: AppLocalizations.of(context).settingsDarkModeSubtitle,
          value: themeMode == ThemeMode.dark,
          onChanged: (v) => ref.read(themeModeProvider.notifier).toggle(),
        ),
        // Language
        const _LanguageContent(),
        // Battery optimization (Android only)
        const _NotificationsContent(),
      ],
    );
  }
}

class _LanguageContent extends ConsumerWidget {
  const _LanguageContent();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final locale = ref.watch(localeProvider);

    final l10n = AppLocalizations.of(context);
    final languageLabels = {
      'en': 'English',
      'tr': 'Türkçe',
      'it': 'Italiano',
      'es': 'Español',
      'ru': 'Русский',
      'nl': 'Nederlands',
      'de': 'Deutsch',
      'zh': '中文',
      'ja': '日本語',
      'pt': 'Português',
      'ar': 'العربية',
    };

    final currentLabel = locale == null
        ? l10n.settingsLanguageSystem
        : languageLabels[locale.languageCode] ?? 'English';

    return ListTile(
          leading: const FaIcon(FontAwesomeIcons.language),
          title: Text(AppLocalizations.of(context).settingsLanguage),
          subtitle: Text(currentLabel),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: () => _showLanguagePicker(context, ref, locale),
        );
  }

  void _showLanguagePicker(BuildContext context, WidgetRef ref, Locale? current) {
    final languages = [
      ('system', AppLocalizations.of(context).settingsLanguageSystem),
      ('en', 'English'),
      ('tr', 'Türkçe'),
      ('de', 'Deutsch'),
      ('es', 'Español'),
      ('it', 'Italiano'),
      ('ja', '日本語'),
      ('nl', 'Nederlands'),
      ('pt', 'Português'),
      ('ru', 'Русский'),
      ('zh', '中文'),
      ('ar', 'العربية'),
    ];

    final groupValue = current == null ? 'system' : current.languageCode;

    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: languages.map((lang) {
              final (code, label) = lang;
              return RadioListTile<String>(
                title: Text(label),
                value: code,
                groupValue: groupValue,
                onChanged: (_) {
                  ref.read(localeProvider.notifier).setLocale(
                    code == 'system' ? null : Locale(code),
                  );
                  Navigator.pop(context);
                },
              );
            }).toList(),
          ),
        ),
      ),
    );
  }
}

/// Battery optimization section - Android only
/// Lets user request exemption from Doze mode via system dialog
class _NotificationsContent extends StatefulWidget {
  const _NotificationsContent();

  @override
  State<_NotificationsContent> createState() => _NotificationsContentState();
}

class _NotificationsContentState extends State<_NotificationsContent>
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

    return ListTile(
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
          final theme = Theme.of(context);
          final isDark = theme.brightness == Brightness.dark;

          ScreenSecurity.enable();
          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (context) => Dialog(
              insetPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 32),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
              backgroundColor: theme.dialogBackgroundColor,
              child: SingleChildScrollView(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      // Header icon with gradient background
                      Container(
                        width: 56,
                        height: 56,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          gradient: LinearGradient(
                            colors: [
                              DnaColors.gradientStart.withAlpha(40),
                              DnaColors.gradientEnd.withAlpha(40),
                            ],
                          ),
                        ),
                        child: Center(
                          child: FaIcon(
                            FontAwesomeIcons.shieldHalved,
                            color: DnaColors.gradientStart,
                            size: 24,
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      // Title
                      Text(
                        AppLocalizations.of(context).settingsYourSeedPhrase,
                        style: theme.textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 20),
                      // Word grid — 3 columns
                      LayoutBuilder(
                        builder: (context, constraints) {
                          const columns = 3;
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
                                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                                          decoration: BoxDecoration(
                                            color: isDark
                                                ? DnaColors.darkSurfaceVariant
                                                : DnaColors.lightSurfaceVariant,
                                            borderRadius: BorderRadius.circular(10),
                                            border: Border.all(
                                              color: isDark
                                                  ? Colors.white.withAlpha(15)
                                                  : Colors.black.withAlpha(15),
                                            ),
                                          ),
                                          child: Row(
                                            children: [
                                              SizedBox(
                                                width: 22,
                                                child: Text(
                                                  '$displayIndex',
                                                  style: theme.textTheme.bodySmall?.copyWith(
                                                    color: isDark
                                                        ? DnaColors.darkTextSecondary
                                                        : DnaColors.lightTextSecondary,
                                                    fontWeight: FontWeight.w500,
                                                    fontSize: 11,
                                                  ),
                                                ),
                                              ),
                                              Expanded(
                                                child: Text(
                                                  word,
                                                  style: theme.textTheme.bodyMedium?.copyWith(
                                                    fontWeight: FontWeight.w600,
                                                    letterSpacing: 0.3,
                                                  ),
                                                ),
                                              ),
                                            ],
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
                      const SizedBox(height: 20),
                      // Warning banner
                      Container(
                        padding: const EdgeInsets.all(14),
                        decoration: BoxDecoration(
                          color: DnaColors.warning.withAlpha(isDark ? 25 : 30),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: DnaColors.warning.withAlpha(isDark ? 50 : 60),
                          ),
                        ),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Padding(
                              padding: const EdgeInsets.only(top: 1),
                              child: FaIcon(
                                FontAwesomeIcons.triangleExclamation,
                                size: 15,
                                color: DnaColors.warning,
                              ),
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                AppLocalizations.of(context).settingsSeedPhraseWarning,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: isDark
                                      ? DnaColors.warning.withAlpha(220)
                                      : DnaColors.warning.withAlpha(200),
                                  height: 1.4,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 24),
                      // Copy button — gradient style
                      SizedBox(
                        width: double.infinity,
                        height: 46,
                        child: DecoratedBox(
                          decoration: BoxDecoration(
                            gradient: const LinearGradient(
                              colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
                            ),
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: ElevatedButton.icon(
                            onPressed: () async {
                              // SEC-09: pre-copy confirmation gate. Cancel is
                              // the ghost (less-prominent) button per
                              // DnaDialog.confirm default styling.
                              final l10n = AppLocalizations.of(context);
                              final confirmed = await DnaDialog.confirm(
                                context,
                                title: l10n.seedCopyConfirmTitle,
                                message: l10n.seedCopyConfirmBody,
                                confirmLabel: l10n.continueButton,
                                cancelLabel: l10n.cancel,
                              );
                              if (!confirmed) return;
                              if (!context.mounted) return;
                              await ClipboardUtils.copyWithAutoClear(mnemonic);
                              if (!context.mounted) return;
                              DnaSnackBar.info(
                                context,
                                AppLocalizations.of(context).seedCopiedToast,
                              );
                            },
                            icon: const FaIcon(FontAwesomeIcons.copy, size: 16),
                            label: Text(AppLocalizations.of(context).copy),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.transparent,
                              shadowColor: Colors.transparent,
                              foregroundColor: Colors.white,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(12),
                              ),
                              textStyle: const TextStyle(
                                fontWeight: FontWeight.w600,
                                fontSize: 15,
                              ),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 10),
                      // Done button — outlined
                      SizedBox(
                        width: double.infinity,
                        height: 46,
                        child: OutlinedButton(
                          onPressed: () {
                                ScreenSecurity.disable();
                                Navigator.pop(context);
                              },
                          style: OutlinedButton.styleFrom(
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(12),
                            ),
                            side: BorderSide(
                              color: isDark
                                  ? Colors.white.withAlpha(40)
                                  : Colors.black.withAlpha(40),
                            ),
                            textStyle: const TextStyle(
                              fontWeight: FontWeight.w600,
                              fontSize: 15,
                            ),
                          ),
                          child: Text(AppLocalizations.of(context).done),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
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

  static const _chainLabels = <String, String>{
    'dnac': 'DNA Chain (DNAC)',
    'bsc': 'BNB Smart Chain (BEP20)',
    'cellframe': 'Cellframe (CF20)',
    'ethereum': 'Ethereum (ERC20)',
    'solana': 'Solana (SPL)',
    'tron': 'TRON (TRC20)',
  };

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final walletSettings = ref.watch(walletSettingsProvider);
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(l10n.settingsWallet),
        SwitchListTile(
          secondary: FaIcon(
            FontAwesomeIcons.eyeSlash,
            color: walletSettings.hideZeroBalances
                ? theme.colorScheme.primary
                : null,
          ),
          title: Text(l10n.settingsHideZeroBalance),
          subtitle: Text(l10n.settingsHideZeroBalanceSubtitle),
          value: walletSettings.hideZeroBalances,
          onChanged: (value) {
            ref.read(walletSettingsProvider.notifier).setHideZeroBalances(value);
          },
        ),
        const SizedBox(height: 8),
        // Active Chains
        ListTile(
          leading: FaIcon(FontAwesomeIcons.link, color: theme.colorScheme.primary),
          title: Text(l10n.settingsActiveChains),
          subtitle: Text(l10n.settingsActiveChainsSubtitle),
        ),
        // DNAC — always active, not toggleable
        SwitchListTile(
          contentPadding: const EdgeInsets.only(left: 56, right: 16),
          title: Text(_chainLabels['dnac']!),
          value: true,
          onChanged: null, // disabled — always active
        ),
        // Cellframe — always active, not toggleable
        SwitchListTile(
          contentPadding: const EdgeInsets.only(left: 56, right: 16),
          title: Text(_chainLabels['cellframe']!),
          value: true,
          onChanged: null, // disabled — always active
        ),
        // Toggleable chains
        ...allToggleableChains.map((chain) => SwitchListTile(
          contentPadding: const EdgeInsets.only(left: 56, right: 16),
          title: Text(_chainLabels[chain] ?? chain),
          value: walletSettings.isChainActive(chain),
          onChanged: (value) {
            ref.read(walletSettingsProvider.notifier).setChainActive(chain, value);
          },
        )),
      ],
    );
  }
}

class _DataStorageSection extends ConsumerStatefulWidget {
  @override
  ConsumerState<_DataStorageSection> createState() => _DataStorageSectionState();
}

class _DataStorageSectionState extends ConsumerState<_DataStorageSection> {
  String? _cacheSizeString;
  bool _isClearing = false;
  bool _isSendingLog = false;

  @override
  void initState() {
    super.initState();
    _loadCacheSize();
  }

  Future<void> _loadCacheSize() async {
    final mediaCache = await MediaCacheService.getInstance();
    final size = await mediaCache.getCacheSizeString();
    if (mounted) setState(() => _cacheSizeString = size);
  }

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
    final l10n = AppLocalizations.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(l10n.settingsDataStorage),
        // Auto-sync toggle
        SwitchListTile(
          secondary: FaIcon(
            FontAwesomeIcons.arrowsRotate,
            color: syncState.autoSyncEnabled
                ? Theme.of(context).colorScheme.primary
                : null,
          ),
          title: Text(l10n.settingsAutoSync),
          subtitle: Text(
            syncState.autoSyncEnabled
                ? l10n.settingsLastSync(_formatLastSync(syncState.lastSyncTime))
                : l10n.settingsAutoSyncSubtitle,
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
            title: Text(l10n.settingsSyncNow),
            subtitle: syncState.lastSyncError != null
                ? Text(
                    syncState.lastSyncError!,
                    style: TextStyle(color: DnaColors.textWarning),
                  )
                : Text(l10n.settingsSyncNowSubtitle),
            trailing: syncState.isSyncing ? null : const FaIcon(FontAwesomeIcons.chevronRight),
            onTap: syncState.isSyncing
                ? null
                : () => ref.read(syncSettingsProvider.notifier).syncNow(),
          ),
        // Clear Cache
        ListTile(
          leading: _isClearing
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const FaIcon(FontAwesomeIcons.broom),
          title: Text(l10n.settingsClearCache),
          subtitle: Text(
            _cacheSizeString != null
                ? l10n.settingsCacheSize(_cacheSizeString!)
                : l10n.settingsClearCacheSubtitle,
          ),
          trailing: const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: _isClearing ? null : () => _confirmClearCache(context),
        ),
        // Delete All Messages
        ListTile(
          leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.error),
          title: Text(l10n.settingsDeleteAllMessages),
          subtitle: Text(l10n.settingsDeleteAllMessagesSubtitle),
          onTap: () => _confirmPurgeAll(context, ref),
        ),
        // Debug Log (unified entry — export to device OR share with punk)
        ListTile(
          leading: _isSendingLog
              ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const FaIcon(FontAwesomeIcons.fileLines),
          title: Text(l10n.settingsDebugLog),
          subtitle: Text(l10n.settingsDebugLogSubtitle),
          trailing: _isSendingLog ? null : const FaIcon(FontAwesomeIcons.chevronRight),
          onTap: _isSendingLog ? null : () => _showDebugLogOptions(context),
        ),
      ],
    );
  }

  Future<void> _showDebugLogOptions(BuildContext context) async {
    final l10n = AppLocalizations.of(context);
    final choice = await showModalBottomSheet<String>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: FaIcon(
                Platform.isLinux || Platform.isWindows || Platform.isMacOS
                    ? FontAwesomeIcons.folderOpen
                    : FontAwesomeIcons.shareNodes,
              ),
              title: Text(l10n.debugLogExportToDevice),
              subtitle: Text(l10n.debugLogExportToDeviceSubtitle),
              onTap: () => Navigator.pop(ctx, 'export'),
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.paperPlane),
              title: Text(l10n.debugLogShareWithPunk),
              subtitle: Text(l10n.debugLogShareWithPunkSubtitle),
              onTap: () => Navigator.pop(ctx, 'punk'),
            ),
          ],
        ),
      ),
    );
    if (choice == null || !context.mounted) return;
    if (choice == 'export') {
      await _openOrShareLogs(context);
    } else if (choice == 'punk') {
      await _confirmSendDebugLog(context);
    }
  }

  Future<void> _confirmSendDebugLog(BuildContext context) async {
    final l10n = AppLocalizations.of(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.debugLogSendConfirmTitle),
        content: Text(l10n.debugLogSendConfirmBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l10n.debugLogSendToDev),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    if (!context.mounted) return;
    await _sendDebugLog(context);
  }

  Future<void> _sendDebugLog(BuildContext context) async {
    final l10n = AppLocalizations.of(context);
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _isSendingLog = true);
    try {
      // 1. Locate the most recent log file
      File? logFile;
      if (Platform.isLinux || Platform.isMacOS || Platform.isWindows) {
        final dir = Directory(_getLogsDir());
        if (await dir.exists()) {
          final files = await dir
              .list()
              .where((f) =>
                  f is File && f.path.contains('dna') && f.path.endsWith('.log'))
              .cast<File>()
              .toList();
          if (files.isNotEmpty) {
            final stats = await Future.wait(
              files.map((f) async => MapEntry(f, await f.stat())),
            );
            stats.sort((a, b) => b.value.modified.compareTo(a.value.modified));
            logFile = stats.first.key;
          }
        }
      } else {
        // Mobile: use ApplicationSupport dir (where C library writes logs)
        // — matches the existing _openOrShareLogs() path discovery.
        final appDir = await getApplicationSupportDirectory();
        final dir = Directory('${appDir.path}/dna/logs');
        if (await dir.exists()) {
          final files = await dir
              .list()
              .where((f) =>
                  f is File && f.path.contains('dna') && f.path.endsWith('.log'))
              .cast<File>()
              .toList();
          if (files.isNotEmpty) {
            final stats = await Future.wait(
              files.map((f) async => MapEntry(f, await f.stat())),
            );
            stats.sort((a, b) => b.value.modified.compareTo(a.value.modified));
            logFile = stats.first.key;
          }
        }
      }

      if (logFile == null) {
        messenger.showSnackBar(
          SnackBar(content: Text(l10n.settingsNoLogFiles)),
        );
        return;
      }

      // 2. Read + sanitize on a background isolate
      final payloadData = await compute(_readAndSanitizeLog, logFile.path);

      // 3. Engine
      final eng = ref.read(engineProvider).valueOrNull;
      if (eng == null) {
        messenger.showSnackBar(
          SnackBar(content: Text(l10n.debugLogSendFailed('engine not ready'))),
        );
        return;
      }

      // 4. Building hint (platform + app version)
      final pkg = await PackageInfo.fromPlatform();
      final hint = '${Platform.operatingSystem}-v${pkg.version}';

      messenger.showSnackBar(
        SnackBar(
          content: Text(l10n.debugLogSendSending),
          duration: const Duration(seconds: 2),
        ),
      );

      // 5. Send via FFI
      await eng.sendDebugLog(
        receiverFpHex: AppConfig.devDebugFingerprint,
        logBody: payloadData.bytes,
        hint: hint,
      );

      final msg = payloadData.truncated
          ? '${l10n.debugLogSendSuccess} · ${l10n.debugLogSendTruncated}'
          : l10n.debugLogSendSuccess;
      messenger.showSnackBar(SnackBar(content: Text(msg)));
    } catch (e) {
      messenger.showSnackBar(
        SnackBar(content: Text(l10n.debugLogSendFailed(e.toString()))),
      );
    } finally {
      if (mounted) setState(() => _isSendingLog = false);
    }
  }

  void _confirmClearCache(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.settingsClearCacheConfirm),
        content: Text(l10n.settingsClearCacheWarning),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(context);
              setState(() => _isClearing = true);
              try {
                // Clear media cache
                final mediaCache = await MediaCacheService.getInstance();
                await mediaCache.clearAll();
                // Clear profile cache
                await CacheDatabase.instance.clearProfiles();
                // Reload size
                await _loadCacheSize();
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(l10n.settingsCacheCleared)),
                  );
                }
              } finally {
                if (mounted) setState(() => _isClearing = false);
              }
            },
            child: Text(l10n.settingsClearCacheButton),
          ),
        ],
      ),
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

  String _getLogsDir() {
    if (Platform.isLinux || Platform.isMacOS) {
      final home = Platform.environment['HOME'] ?? '/tmp';
      return '$home/.dna/logs';
    } else if (Platform.isWindows) {
      final home = Platform.environment['USERPROFILE'] ?? 'C:\\Users';
      return '$home\\.dna\\logs';
    } else {
      return '';
    }
  }

  Future<void> _openOrShareLogs(BuildContext context) async {
    final isDesktop = Platform.isLinux || Platform.isWindows || Platform.isMacOS;

    try {
      if (isDesktop) {
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

        ProcessResult result;
        if (Platform.isLinux) {
          result = await Process.run('xdg-open', [logsDir]);
        } else if (Platform.isWindows) {
          result = await Process.run('explorer', [logsDir]);
        } else {
          result = await Process.run('open', [logsDir]);
        }

        if (!Platform.isWindows && result.exitCode != 0 && context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Could not open folder: ${result.stderr}'),
              backgroundColor: DnaColors.snackbarError,
            ),
          );
        }
      } else {
        final appDir = await getApplicationSupportDirectory();
        final logsDir = Directory('${appDir.path}/dna/logs');

        if (!await logsDir.exists()) {
          final parentDir = Directory('${appDir.path}/dna');
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

        var logFiles = await logsDir
            .list()
            .where((f) => f is File && f.path.contains('dna') && f.path.endsWith('.log'))
            .cast<File>()
            .toList();

        if (logFiles.length > 1) {
          final stats = await Future.wait(
            logFiles.map((f) async => MapEntry(f, await f.stat())),
          );
          stats.sort((a, b) => b.value.modified.compareTo(a.value.modified));
          logFiles = stats.take(1).map((e) => e.key).toList();

          for (final old in stats.skip(1)) {
            try { await old.key.delete(); } catch (_) {}
          }
        }

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

        final filePaths = logFiles.map((f) => f.path).toList();
        final zipData = await compute(_zipLogFiles, filePaths);
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

        final tempDir = await getTemporaryDirectory();
        final timestamp = DateTime.now().toIso8601String().replaceAll(':', '-').split('.')[0];
        final zipPath = '${tempDir.path}/dna_logs_$timestamp.zip';
        await File(zipPath).writeAsBytes(zipData);

        await Share.shareXFiles(
          [XFile(zipPath)],
          subject: 'DNA Connect Logs',
          text: 'Debug logs from DNA Connect',
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
}

class _AccountSection extends ConsumerStatefulWidget {
  final String? fingerprint;

  const _AccountSection({required this.fingerprint});

  @override
  ConsumerState<_AccountSection> createState() => _AccountSectionState();
}

class _AccountSectionState extends ConsumerState<_AccountSection> {
  bool _isDeleting = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fingerprint = widget.fingerprint;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _SectionHeader(AppLocalizations.of(context).settingsAccount),
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

  static const _downloadUrl = 'https://cpunk.io/products/dna-connect.html';

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
                'Apache License 2.0',
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
