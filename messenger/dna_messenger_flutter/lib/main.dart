// DNA Connect - Post-Quantum Encrypted P2P Communication
// Phase 14: DHT-only messaging with Android background support
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:url_launcher/url_launcher.dart';

import 'l10n/app_localizations.dart';
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
  bool _autoLoadStarted = false;
  bool _autoLoadComplete = false;
  bool _hasIdentity = false;
  bool _registrationIncomplete = true;
  bool _updateDialogShown = false;

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
    if (_lifecycleObserver != null) {
      WidgetsBinding.instance.removeObserver(_lifecycleObserver!);
    }
    super.dispose();
  }

  /// Async backfill: recover registered name from DHT after DHT connects.
  /// If name found → cache it. If not found → show registration screen.
  void _backfillNameFromDht(dynamic engine, String fp) {
    Future.delayed(const Duration(seconds: 3), () async {
      // Wait for DHT to connect (up to 15s total, checking every 2s)
      for (int i = 0; i < 6; i++) {
        if (engine.isDhtConnected()) break;
        await Future.delayed(const Duration(seconds: 2));
      }

      if (!mounted) return;

      try {
        final registeredName = await engine.getRegisteredName();
        if (registeredName != null && registeredName.isNotEmpty) {
          engine.debugLog('STARTUP', 'Backfill: recovered name from DHT: $registeredName');
          await CacheDatabase.instance.saveRegisteredName(fp, registeredName);
          if (mounted) {
            ref.read(identityProfileCacheProvider.notifier).updateIdentity(fp, registeredName, '');
            setState(() {
              _registrationIncomplete = false;
            });
          }
        } else {
          // No name in DHT — genuinely incomplete registration
          // _registrationIncomplete stays true (default) — registration screen shown
          engine.debugLog('STARTUP', 'Backfill: no registered name in DHT — showing registration');
        }
      } catch (e) {
        // DHT lookup failed — keep _registrationIncomplete true to force registration
        engine.debugLog('STARTUP', 'Backfill: DHT lookup failed: $e — showing registration');
      }
    });
  }

  /// Background check: if local cache has a name but DHT doesn't, re-register it.
  /// If the name was taken by someone else, force registration screen for new name.
  void _ensureNameInDht(dynamic engine, String localName) {
    Future.delayed(const Duration(seconds: 5), () async {
      // Wait for DHT to connect
      for (int i = 0; i < 6; i++) {
        if (engine.isDhtConnected()) break;
        await Future.delayed(const Duration(seconds: 2));
      }

      if (!mounted) return;

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
                _registrationIncomplete = true;
              });
            }
          }
        }
      } catch (e) {
        engine.debugLog('STARTUP', 'DHT name check/re-register failed: $e');
      }
    });
  }

  /// Try to auto-load identity if one exists on disk (runs once at startup)
  /// v0.100.94: Added try/catch to prevent permanent loading screen on errors.
  /// v0.101.36: If engine is reused (Activity recreation), restore state without re-loading.
  Future<void> _tryAutoLoadIdentity(dynamic engine) async {
    if (_autoLoadStarted) return;
    if (engine == null) return;

    _autoLoadStarted = true;

    try {
      // v0.101.36: Check if engine already has identity loaded (Activity recreation).
      // The cached engine survives Activity recreation with identity + lock intact.
      // Skip loadIdentity() to avoid re-acquiring the lock and re-initializing.
      if (engine.isIdentityLoaded()) {
        final fp = engine.fingerprint;
        engine.debugLog('STARTUP', 'Engine reused: identity already loaded fp=${fp?.substring(0, 16)}...');
        ref.read(currentFingerprintProvider.notifier).state = fp;
        ref.read(identityReadyProvider.notifier).state = true;
        ref.read(dhtConnectionStateProvider.notifier).state =
            engine.isDhtConnected() ? DhtConnectionState.connected : DhtConnectionState.connecting;
      } else {
        // v0.3.0: Check if identity exists and auto-load
        final hasIdentity = engine.hasIdentity();
        engine.debugLog('STARTUP', 'v0.3.0: hasIdentity=$hasIdentity');

        if (hasIdentity) {
          // Ensure profile caches are loaded from SQLite before showing HomeScreen
          await ref.read(contactProfileCacheProvider.notifier).initialized;
          await ref.read(identityProfileCacheProvider.notifier).initialized;
          // Show HomeScreen immediately for cache-first wall display
          if (mounted) setState(() { _hasIdentity = true; });

          // Pre-warm: Set DHT state to "connecting" immediately for UI feedback
          // This shows "Connecting to network..." banner while DHT bootstraps
          ref.read(dhtConnectionStateProvider.notifier).state =
              DhtConnectionState.connecting;
          engine.debugLog('STARTUP', 'v0.3.0: DHT pre-warm - state set to connecting');

          engine.debugLog('STARTUP', 'v0.3.0: Identity exists, auto-loading...');
          await ref.read(identitiesProvider.notifier).loadIdentity();
          engine.debugLog('STARTUP', 'v0.3.0: Identity auto-loaded');

          // Check if registration was completed (user has a registered DNA name)
          // Uses registeredName field (immutable) — not displayName (editable)
          final fp = ref.read(currentFingerprintProvider);
          if (fp != null) {
            final cached = await CacheDatabase.instance.getIdentity(fp);
            if (cached != null && cached.registeredName.isNotEmpty) {
              // Registered name found in local cache — allow HomeScreen
              engine.debugLog('STARTUP', 'Cached registeredName found for ${fp.substring(0, 16)}...: ${cached.registeredName}');
              if (mounted) {
                setState(() {
                  _registrationIncomplete = false;
                });
              }
              // Background: verify name exists in DHT, re-register if missing
              _ensureNameInDht(engine, cached.registeredName);
            } else {
              // No registered name cached — backfill from DHT.
              // _registrationIncomplete stays true, blocking HomeScreen until resolved.
              engine.debugLog('STARTUP', 'No cached registeredName for ${fp.substring(0, 16)}... — backfilling from DHT');
              _backfillNameFromDht(engine, fp);
            }
          }
        } else {
          engine.debugLog('STARTUP', 'v0.3.0: No identity, showing onboarding');
        }
      }
    } catch (e) {
      // v0.100.94: Don't get stuck on loading screen forever.
      // loadIdentity has its own retry logic for lock errors.
      // If we still fail here, show onboarding/error instead of infinite spinner.
      engine.debugLog('STARTUP', 'v0.3.0: Auto-load failed: $e');
    }

    // Pre-warm wallet balances from cache + live RPC in background
    // so DM send sheet and wallet screen have data immediately
    Future.microtask(() {
      if (mounted) {
        ref.read(allBalancesProvider.notifier).refresh();
      }
    });

    // Trigger rebuild after check completes (even on error - prevents stuck loading screen)
    if (mounted) {
      setState(() {
        _autoLoadComplete = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final engine = ref.watch(engineProvider);
    // Watch currentFingerprintProvider to reactively update when identity is loaded
    // This is set by loadIdentity() after successful load, and by createIdentity() path
    final currentFingerprint = ref.watch(currentFingerprintProvider);
    // Watch appFullyReadyProvider to wait for DHT operations (presence lookups) to complete
    // ignore: unused_local_variable
    final _ = ref.watch(appFullyReadyProvider);

    // App lock state
    final appLock = ref.watch(appLockProvider);
    final isLocked = ref.watch(appLockedProvider);

    return engine.when(
      data: (eng) {
        // Check app lock first - before any other logic
        if (appLock.enabled && isLocked) {
          return const LockScreen();
        }

        // Trigger auto-load once at startup (for existing identities)
        if (!_autoLoadStarted) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            _tryAutoLoadIdentity(eng);
          });
          return const _LoadingScreen();
        }

        // Still loading — show HomeScreen early if identity exists (cache-first wall)
        if (!_autoLoadComplete) {
          if (_hasIdentity) {
            return const HomeScreen();
          }
          return const _LoadingScreen();
        }

        // v0.3.0: Route based on whether identity is loaded (reactive)
        // currentFingerprint is non-null when identity is loaded
        if (currentFingerprint != null) {
          // v0.101.38: Check if registration was completed (user has a registered name).
          // Watch the profile cache reactively — when registerName() updates it,
          // this rebuilds and routes to HomeScreen automatically.
          final profileCache = ref.watch(identityProfileCacheProvider);
          final cached = profileCache[currentFingerprint];
          final hasName = cached != null && cached.registeredName.isNotEmpty;

          if (!hasName && _registrationIncomplete) {
            // Keys exist but no registered name — send back to registration
            return IdentitySelectionScreen(resumeFingerprint: currentFingerprint);
          }

          // v0.9.27: Check if app/library version is below DHT minimum — block if so
          final versionCheck = ref.watch(versionCheckProvider);
          final versionResult = versionCheck.valueOrNull;
          if (versionResult != null && versionResult.isBelowMinimum) {
            return UpdateRequiredScreen(
              libraryMinimum: versionResult.libraryMinimum,
              appMinimum: versionResult.appMinimum,
              localLibraryVersion: eng.version,
            );
          }

          // Trigger contacts provider to start presence lookups in background
          // (presence data will update progressively via _updatePresenceInBackground)
          ref.watch(contactsProvider);

          // v0.100.71: Removed appFullyReady blocking check for faster startup
          // UI now shows immediately, presence data updates in background
          // Contacts show "Syncing..." until presence is fetched

          // Only activate providers AFTER identity is loaded
          ref.watch(eventHandlerActiveProvider);
          ref.watch(backgroundTasksActiveProvider);

          // Show update-available dialog once per session when DHT reports a newer version
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
        } else {
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
