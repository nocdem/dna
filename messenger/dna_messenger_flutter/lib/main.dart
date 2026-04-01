// DNA Connect - Post-Quantum Encrypted P2P Communication
// Phase 14: DHT-only messaging with Android background support
import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:url_launcher/url_launcher.dart';

import 'ffi/dna_engine.dart' show DhtConnectedEvent;
import 'l10n/app_localizations.dart';
import 'providers/portfolio_history_provider.dart';
import 'providers/providers.dart';
import 'providers/version_check_provider.dart';
import 'screens/screens.dart';
import 'screens/lock/lock_screen.dart';
import 'screens/update_required_screen.dart';
import 'design_system/theme/dna_colors.dart';
import 'design_system/theme/dna_theme.dart';
import 'services/cache_database.dart';
import 'services/notification_service.dart';
import 'utils/window_state.dart';
import 'utils/lifecycle_observer.dart';
import 'utils/logger.dart';

/// Global RouteObserver for screens that need to know when they're covered/uncovered
/// Used by QrScannerScreen to stop camera when covered by another route
final RouteObserver<ModalRoute<void>> routeObserver = RouteObserver<ModalRoute<void>>();

void main() {
  // Run app with error zone to capture uncaught exceptions
  // All initialization must be inside the zone to avoid zone mismatch
  runAppWithErrorLogging(() async {
    WidgetsFlutterBinding.ensureInitialized();

    // Setup error handlers to capture exceptions to log file
    setupErrorHandlers();

    // Initialize SQLite FFI for desktop platforms
    if (Platform.isLinux || Platform.isWindows || Platform.isMacOS) {
      sqfliteFfiInit();
      databaseFactory = databaseFactoryFfi;
    }

    // Initialize window manager on desktop (restores position/size)
    if (WindowStateManager.isDesktop) {
      await windowStateManager.init();
    }

    // Initialize local notification service
    await NotificationService.instance.init();

    runApp(
      const ProviderScope(
        child: DnaMessengerApp(),
      ),
    );
  });
}

class DnaMessengerApp extends ConsumerWidget {
  const DnaMessengerApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeModeProvider);
    final locale = ref.watch(localeProvider);
    return MaterialApp(
      title: 'DNA Connect',
      debugShowCheckedModeBanner: false,
      theme: DnaTheme.light(),
      darkTheme: DnaTheme.dark(),
      themeMode: themeMode,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      locale: locale,
      navigatorObservers: [routeObserver],
      home: const _AppLoader(),
    );
  }
}

/// App loader - initializes engine and shows loading screen
/// Phase 14: Added lifecycle observer for resume/pause handling
/// v0.3.0: Single-user model - auto-loads identity if exists, shows onboarding if not
class _AppLoader extends ConsumerStatefulWidget {
  const _AppLoader();

  @override
  ConsumerState<_AppLoader> createState() => _AppLoaderState();
}

class _AppLoaderState extends ConsumerState<_AppLoader> {
  AppLifecycleObserver? _lifecycleObserver;
  bool _startupDone = false;
  bool _syncStarted = false;
  bool _registrationIncomplete = false;
  bool _nameCheckDone = false;
  bool _updateDialogShown = false;
  StreamSubscription? _nameBackfillSub;
  StreamSubscription? _nameEnsureSub;
  Timer? _nameCheckTimeout;

  @override
  void initState() {
    super.initState();
    // Set up lifecycle observer after first frame
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _lifecycleObserver = AppLifecycleObserver(ref);
      WidgetsBinding.instance.addObserver(_lifecycleObserver!);
    });
  }

  @override
  void dispose() {
    _nameBackfillSub?.cancel();
    _nameEnsureSub?.cancel();
    _nameCheckTimeout?.cancel();
    if (_lifecycleObserver != null) {
      WidgetsBinding.instance.removeObserver(_lifecycleObserver!);
    }
    super.dispose();
  }

  /// Async backfill: recover registered name from DHT after DHT connects.
  /// If name found → cache it. If not found → show registration screen.
  /// Uses subscribe-then-check to avoid races between event and connection check.
  void _backfillNameFromDht(dynamic engine, String fp) {
    bool done = false;

    // Timeout: if DHT doesn't connect within 15s, show registration
    _nameCheckTimeout?.cancel();
    _nameCheckTimeout = Timer(const Duration(seconds: 15), () {
      if (!done && mounted && !_nameCheckDone) {
        engine.debugLog('STARTUP', 'Backfill: timeout waiting for DHT — showing registration');
        setState(() {
          _nameCheckDone = true;
          _registrationIncomplete = true;
        });
      }
    });

    Future<void> doBackfill() async {
      if (done || !mounted) return;
      done = true;
      _nameCheckTimeout?.cancel();
      try {
        final registeredName = await engine.getRegisteredName();
        if (registeredName != null && registeredName.isNotEmpty) {
          engine.debugLog('STARTUP', 'Backfill: recovered name from DHT: $registeredName');
          await CacheDatabase.instance.saveRegisteredName(fp, registeredName);
          if (mounted) {
            ref.read(identityProfileCacheProvider.notifier).updateIdentity(fp, registeredName, '');
            setState(() {
              _nameCheckDone = true;
              _registrationIncomplete = false;
            });
          }
        } else {
          engine.debugLog('STARTUP', 'Backfill: no registered name in DHT — showing registration');
          if (mounted) {
            setState(() {
              _nameCheckDone = true;
              _registrationIncomplete = true;
            });
          }
        }
      } catch (e) {
        engine.debugLog('STARTUP', 'Backfill: DHT lookup failed: $e — showing registration');
        if (mounted) {
          setState(() {
            _nameCheckDone = true;
            _registrationIncomplete = true;
          });
        }
      }
    }

    // Subscribe FIRST (prevents race: event fires between check and subscribe)
    _nameBackfillSub?.cancel();
    _nameBackfillSub = engine.events.listen((event) {
      if (event is DhtConnectedEvent) {
        _nameBackfillSub?.cancel();
        doBackfill();
      }
    });

    // Check SECOND (handles already-connected case)
    if (engine.isDhtConnected()) {
      _nameBackfillSub?.cancel();
      doBackfill();
    }
  }

  /// Background check: if local cache has a name but DHT doesn't, re-register it.
  /// If the name was taken by someone else, force registration screen for new name.
  /// Uses subscribe-then-check to avoid races between event and connection check.
  void _ensureNameInDht(dynamic engine, String localName) {
    bool done = false;

    Future<void> doEnsure() async {
      if (done || !mounted) return;
      done = true;
      try {
        final dhtName = await engine.getRegisteredName();
        if (dhtName != null && dhtName.isNotEmpty) return; // Already in DHT, all good

        // Name missing from DHT — check if it's still available
        engine.debugLog('STARTUP', 'Name "$localName" missing from DHT, checking availability...');
        final ownerFp = await engine.lookupName(localName);

        if (!mounted) return;

        if (ownerFp.isEmpty) {
          // Name is available — re-register it
          engine.debugLog('STARTUP', 'Name "$localName" available, re-registering...');
          await ref.read(identitiesProvider.notifier).registerName(localName);
          engine.debugLog('STARTUP', 'Re-registered name to DHT: $localName');
        } else {
          // Name taken by someone else — force new name registration
          final myFp = ref.read(currentFingerprintProvider) ?? '';
          if (ownerFp == myFp) {
            // It's ours but getRegisteredName didn't find it (race) — re-register
            engine.debugLog('STARTUP', 'Name "$localName" is ours but profile missing, re-registering...');
            await ref.read(identitiesProvider.notifier).registerName(localName);
            engine.debugLog('STARTUP', 'Re-registered name to DHT: $localName');
          } else {
            // Someone else took our name — clear local cache, show registration
            engine.debugLog('STARTUP', 'Name "$localName" taken by ${ownerFp.substring(0, 16)}... — forcing new registration');
            await CacheDatabase.instance.saveRegisteredName(myFp, '');
            if (mounted) {
              ref.read(identityProfileCacheProvider.notifier).updateIdentity(myFp, '', '');
              setState(() {
                _nameCheckDone = true;
                _registrationIncomplete = true;
              });
            }
          }
        }
      } catch (e) {
        engine.debugLog('STARTUP', 'DHT name check/re-register failed: $e');
      }
    }

    // Subscribe FIRST (prevents race: event fires between check and subscribe)
    _nameEnsureSub?.cancel();
    _nameEnsureSub = engine.events.listen((event) {
      if (event is DhtConnectedEvent) {
        _nameEnsureSub?.cancel();
        doEnsure();
      }
    });

    // Check SECOND (handles already-connected case)
    if (engine.isDhtConnected()) {
      _nameEnsureSub?.cancel();
      doEnsure();
    }
  }

  /// Sync Dart-side state with the already-loaded engine identity (runs once at startup).
  /// DnaEngine.create() auto-loads identity, so by the time engineProvider resolves,
  /// engine.isIdentityLoaded() is already true. No loadIdentity() call needed here.
  Future<void> _syncIdentityState(dynamic engine) async {
    if (_startupDone || _syncStarted) return;
    _syncStarted = true;

    try {
      if (engine.isIdentityLoaded()) {
        final fp = engine.fingerprint;
        engine.debugLog('STARTUP', 'Identity pre-loaded, syncing Dart state fp=${fp?.substring(0, 16)}...');

        // Profile caches MUST init before HomeScreen (prevents avatar flash)
        await ref.read(contactProfileCacheProvider.notifier).initialized;
        await ref.read(identityProfileCacheProvider.notifier).initialized;

        // Set Riverpod state
        ref.read(currentFingerprintProvider.notifier).state = fp;
        ref.read(identityReadyProvider.notifier).state = true;
        ref.read(dhtConnectionStateProvider.notifier).state =
            engine.isDhtConnected() ? DhtConnectionState.connected : DhtConnectionState.connecting;

        engine.debugLog('STARTUP', 'Dart state synced, checking registered name...');

        // Name check (reuse existing methods)
        if (fp != null) {
          final cached = await CacheDatabase.instance.getIdentity(fp);
          if (cached != null && cached.registeredName.isNotEmpty) {
            engine.debugLog('STARTUP', 'Cached registeredName: ${cached.registeredName}');
            if (mounted) {
              setState(() {
                _nameCheckDone = true;
                _registrationIncomplete = false;
              });
            }
            // Background: verify name exists in DHT
            _ensureNameInDht(engine, cached.registeredName);
          } else {
            engine.debugLog('STARTUP', 'No cached registeredName — backfilling from DHT');
            _backfillNameFromDht(engine, fp);
          }
        } else {
          // No fingerprint despite identity loaded — show registration
          engine.debugLog('STARTUP', 'Fingerprint is null — showing registration');
          _nameCheckDone = true;
          _registrationIncomplete = true;
        }

        // Android: store fingerprint for background service
        if (Platform.isAndroid && fp != null) {
          final prefs = await SharedPreferences.getInstance();
          await prefs.setString('identity_fingerprint', fp);
          engine.debugLog('STARTUP', 'Fingerprint stored for Android service');
        }
      } else if (engine.hasIdentity()) {
        engine.debugLog('STARTUP', 'Identity exists but not loaded (encrypted keys?)');
      } else {
        engine.debugLog('STARTUP', 'No identity — onboarding');
      }
    } catch (e) {
      engine.debugLog('STARTUP', 'State sync failed: $e');
      // Fail-open: let user through to HomeScreen rather than blocking
      _nameCheckDone = true;
      _registrationIncomplete = false;
    }

    // Wallet pre-warm (always, even without identity)
    if (mounted) {
      Future.microtask(() {
        if (mounted) {
          ref.read(allBalancesProvider.notifier).refresh();
          ref.read(portfolioHistoryProvider);
        }
      });
    }

    _startupDone = true;
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final engine = ref.watch(engineProvider);
    final currentFingerprint = ref.watch(currentFingerprintProvider);
    // Watch appFullyReadyProvider to wait for DHT operations (presence lookups) to complete
    // ignore: unused_local_variable
    final _ = ref.watch(appFullyReadyProvider);

    // App lock state
    final appLock = ref.watch(appLockProvider);
    final isLocked = ref.watch(appLockedProvider);

    return engine.when(
      data: (eng) {
        // App lock check
        if (appLock.enabled && isLocked) {
          return const LockScreen();
        }

        // Trigger state sync once
        if (!_startupDone) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            _syncIdentityState(eng);
          });
          return const _LoadingScreen();
        }

        // Identity loaded — show appropriate screen
        if (currentFingerprint != null) {
          // Wait for name check to complete before showing any screen
          if (!_nameCheckDone) return const _LoadingScreen();

          // Name registration check
          final profileCache = ref.watch(identityProfileCacheProvider);
          final cached = profileCache[currentFingerprint];
          final hasName = cached != null && cached.registeredName.isNotEmpty;
          if (_nameCheckDone && !hasName && _registrationIncomplete) {
            return IdentitySelectionScreen(resumeFingerprint: currentFingerprint);
          }

          // Version check
          final versionCheck = ref.watch(versionCheckProvider);
          final versionResult = versionCheck.valueOrNull;
          if (versionResult != null && versionResult.isBelowMinimum) {
            return UpdateRequiredScreen(
              libraryMinimum: versionResult.libraryMinimum,
              appMinimum: versionResult.appMinimum,
              localLibraryVersion: eng.version,
            );
          }

          // Activate providers
          ref.watch(contactsProvider);
          ref.watch(eventHandlerActiveProvider);
          ref.watch(backgroundTasksActiveProvider);

          // Update available dialog (once per session)
          if (versionResult != null && versionResult.hasUpdate && !_updateDialogShown) {
            final dismissed = ref.watch(updateDismissedProvider);
            if (!dismissed) {
              _updateDialogShown = true;
              WidgetsBinding.instance.addPostFrameCallback((_) {
                if (mounted) _showUpdateAvailableDialog(context, ref);
              });
            }
          }

          return const HomeScreen();
        } else if (eng.hasIdentity()) {
          // Identity exists but not loaded (encrypted keys?)
          return const IdentitySelectionScreen();
        } else {
          // No identity — onboarding
          return const IdentitySelectionScreen();
        }
      },
      loading: () => const _LoadingScreen(),
      error: (error, stack) => _ErrorScreen(error: error),
    );
  }

  void _showUpdateAvailableDialog(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);

    showModalBottomSheet(
      context: context,
      backgroundColor: theme.colorScheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(24, 16, 24, 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Drag handle
                Container(
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                const SizedBox(height: 24),
                FaIcon(
                  FontAwesomeIcons.circleArrowUp,
                  size: 48,
                  color: DnaColors.primary,
                ),
                const SizedBox(height: 16),
                Text(
                  l10n.updateAvailableTitle,
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  l10n.updateAvailableMessage,
                  style: theme.textTheme.bodyMedium,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: () {
                      Navigator.of(ctx).pop();
                      launchUrl(
                        Uri.parse('https://cpunk.io/products/dna-connect.html'),
                        mode: LaunchMode.externalApplication,
                      );
                    },
                    icon: const FaIcon(FontAwesomeIcons.download, size: 16),
                    label: Text(l10n.updateDownload),
                  ),
                ),
                const SizedBox(height: 8),
                SizedBox(
                  width: double.infinity,
                  child: TextButton(
                    onPressed: () {
                      ref.read(updateDismissedProvider.notifier).state = true;
                      Navigator.of(ctx).pop();
                    },
                    child: Text(l10n.updateLater),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

class _LoadingScreen extends StatelessWidget {
  const _LoadingScreen();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SvgPicture.asset(
              'assets/logo-icon.svg',
              width: 128,
              height: 128,
            ),
            const SizedBox(height: 24),
            Text(
              AppLocalizations.of(context).appTitle,
              style: theme.textTheme.headlineMedium,
            ),
            const SizedBox(height: 8),
            Text(
              AppLocalizations.of(context).initializing,
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 32),
            const CircularProgressIndicator(),
          ],
        ),
      ),
    );
  }
}

class _ErrorScreen extends StatelessWidget {
  final Object error;

  const _ErrorScreen({required this.error});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              FaIcon(
                FontAwesomeIcons.circleExclamation,
                size: 64,
                color: DnaColors.textWarning,
              ),
              const SizedBox(height: 24),
              Text(
                AppLocalizations.of(context).failedToInitialize,
                style: theme.textTheme.headlineSmall,
              ),
              const SizedBox(height: 16),
              Text(
                error.toString(),
                style: theme.textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 32),
              Text(
                AppLocalizations.of(context).makeSureNativeLibrary,
                style: theme.textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
