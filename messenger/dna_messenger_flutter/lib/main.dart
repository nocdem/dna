// DNA Messenger - Post-Quantum Encrypted P2P Messenger
// Phase 14: DHT-only messaging with Android background support
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import 'providers/providers.dart';
import 'screens/screens.dart';
import 'screens/lock/lock_screen.dart';
import 'services/notification_service.dart';
import 'theme/dna_theme.dart';
import 'utils/window_state.dart';
import 'utils/lifecycle_observer.dart';
import 'utils/logger.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Setup error handlers to capture exceptions to log file
  setupErrorHandlers();

  // Initialize SQLite FFI for desktop platforms
  if (Platform.isLinux || Platform.isWindows || Platform.isMacOS) {
    sqfliteFfiInit();
    databaseFactory = databaseFactoryFfi;
  }

  // Initialize notification service (cross-platform)
  await NotificationService.initialize();

  // Initialize window manager on desktop (restores position/size)
  if (WindowStateManager.isDesktop) {
    await windowStateManager.init();
  }

  // Run app with error zone to capture uncaught exceptions
  runAppWithErrorLogging(() {
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
    return MaterialApp(
      title: 'DNA Messenger',
      debugShowCheckedModeBanner: false,
      theme: DnaTheme.theme,
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

  /// Try to auto-load identity if one exists on disk (runs once at startup)
  Future<void> _tryAutoLoadIdentity(dynamic engine) async {
    if (_autoLoadStarted) return;
    if (engine == null) return;

    _autoLoadStarted = true;

    // v0.3.0: Check if identity exists and auto-load
    final hasIdentity = engine.hasIdentity();
    engine.debugLog('STARTUP', 'v0.3.0: hasIdentity=$hasIdentity');

    if (hasIdentity) {
      engine.debugLog('STARTUP', 'v0.3.0: Identity exists, auto-loading...');
      await ref.read(identitiesProvider.notifier).loadIdentity();
      engine.debugLog('STARTUP', 'v0.3.0: Identity auto-loaded');
    } else {
      engine.debugLog('STARTUP', 'v0.3.0: No identity, showing onboarding');
    }

    // Trigger rebuild after check completes
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

        // Still loading - wait for check to complete
        if (!_autoLoadComplete) {
          return const _LoadingScreen();
        }

        // v0.3.0: Route based on whether identity is loaded (reactive)
        // currentFingerprint is non-null when identity is loaded
        if (currentFingerprint != null) {
          // Only activate providers AFTER identity is loaded
          ref.watch(eventHandlerActiveProvider);
          ref.watch(backgroundTasksActiveProvider);
          ref.watch(foregroundServiceProvider);
          return const HomeScreen();
        } else {
          return const IdentitySelectionScreen();
        }
      },
      loading: () => const _LoadingScreen(),
      error: (error, stack) => _ErrorScreen(error: error),
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
              'DNA Messenger',
              style: theme.textTheme.headlineMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Initializing...',
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
                'Failed to initialize',
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
                'Make sure the native library is available.',
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
