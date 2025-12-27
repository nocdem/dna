// Home Screen - Main navigation with drawer
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/providers.dart';
import '../providers/event_handler.dart';
import '../theme/dna_theme.dart';
import 'identity/identity_selection_screen.dart';
// Feed disabled - will be reimplemented in the future
// import 'feed/feed_screen.dart';
import 'contacts/contacts_screen.dart';
import 'groups/groups_screen.dart';
import 'wallet/wallet_screen.dart';
import 'settings/settings_screen.dart';

/// Current tab index (0=Chats, 1=Groups, 2=Wallet, 3=Settings)
final currentTabProvider = StateProvider<int>((ref) => 0);

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final identityLoaded = ref.watch(identityLoadedProvider);

    // Show identity selection if no identity loaded
    if (!identityLoaded) {
      return const IdentitySelectionScreen();
    }

    return const _MainNavigation();
  }
}

class _MainNavigation extends ConsumerStatefulWidget {
  const _MainNavigation();

  @override
  ConsumerState<_MainNavigation> createState() => _MainNavigationState();
}

class _MainNavigationState extends ConsumerState<_MainNavigation> {
  final _scaffoldKey = GlobalKey<ScaffoldState>();

  void _openDrawer() => _scaffoldKey.currentState?.openDrawer();

  @override
  Widget build(BuildContext context) {
    final currentTab = ref.watch(currentTabProvider);

    return Scaffold(
      key: _scaffoldKey,
      drawer: const _NavigationDrawer(),
      body: IndexedStack(
        index: currentTab,
        children: [
          ContactsScreen(onMenuPressed: _openDrawer),
          GroupsScreen(onMenuPressed: _openDrawer),
          WalletScreen(onMenuPressed: _openDrawer),
          SettingsScreen(onMenuPressed: _openDrawer),
        ],
      ),
    );
  }
}

// =============================================================================
// NAVIGATION DRAWER
// =============================================================================

class _NavigationDrawer extends ConsumerWidget {
  const _NavigationDrawer();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final currentTab = ref.watch(currentTabProvider);

    return NavigationDrawer(
      selectedIndex: currentTab,
      onDestinationSelected: (index) {
        ref.read(currentTabProvider.notifier).state = index;
        Navigator.of(context).pop(); // Close drawer
      },
      children: [
        // Header with profile
        const _DrawerHeader(),
        const SizedBox(height: 8),
        // Navigation items
        // Feed disabled - will be reimplemented in the future
        const NavigationDrawerDestination(
          icon: Icon(Icons.chat_outlined),
          selectedIcon: Icon(Icons.chat),
          label: Text('Chats'),
        ),
        const NavigationDrawerDestination(
          icon: Icon(Icons.groups_outlined),
          selectedIcon: Icon(Icons.groups),
          label: Text('Groups'),
        ),
        const NavigationDrawerDestination(
          icon: Icon(Icons.account_balance_wallet_outlined),
          selectedIcon: Icon(Icons.account_balance_wallet),
          label: Text('Wallet'),
        ),
        const Padding(
          padding: EdgeInsets.symmetric(horizontal: 16),
          child: Divider(),
        ),
        const NavigationDrawerDestination(
          icon: Icon(Icons.settings_outlined),
          selectedIcon: Icon(Icons.settings),
          label: Text('Settings'),
        ),
        // Spacer to push status to bottom
        const Spacer(),
        // DHT Connection Status
        const _DhtStatusIndicator(),
        const SizedBox(height: 16),
      ],
    );
  }
}

// =============================================================================
// DHT STATUS INDICATOR
// =============================================================================

class _DhtStatusIndicator extends ConsumerWidget {
  const _DhtStatusIndicator();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final dhtState = ref.watch(dhtConnectionStateProvider);

    final (String text, Color color, IconData icon) = switch (dhtState) {
      DhtConnectionState.connected => ('DHT Connected', Colors.green, Icons.cloud_done),
      DhtConnectionState.connecting => ('DHT Connecting', Colors.orange, Icons.cloud_sync),
      DhtConnectionState.disconnected => ('DHT Disconnected', Colors.red, Icons.cloud_off),
    };

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 16, color: color),
          const SizedBox(width: 8),
          Text(
            text,
            style: TextStyle(
              color: color,
              fontSize: 12,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// DRAWER HEADER
// =============================================================================

class _DrawerHeader extends ConsumerWidget {
  const _DrawerHeader();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider) ?? '';
    final userProfile = ref.watch(userProfileProvider);
    final fullProfile = ref.watch(fullProfileProvider);
    final shortFp = fingerprint.length > 16
        ? '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}'
        : fingerprint;

    return Container(
      padding: const EdgeInsets.fromLTRB(16, 48, 16, 16),
      decoration: const BoxDecoration(
        color: DnaColors.surface,
        border: Border(bottom: BorderSide(color: DnaColors.border)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Avatar
          _buildAvatar(fullProfile, userProfile.valueOrNull?.nickname ?? shortFp, ref),
          const SizedBox(height: 12),
          // Display name
          userProfile.when(
            data: (profile) => Text(
              profile?.nickname?.isNotEmpty == true ? profile!.nickname! : 'Anonymous',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.bold,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            loading: () => const SizedBox(
              height: 20,
              width: 100,
              child: LinearProgressIndicator(),
            ),
            error: (e, st) => const Text('Anonymous'),
          ),
          const SizedBox(height: 4),
          // Fingerprint
          Text(
            shortFp,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: DnaColors.textMuted,
              fontFamily: 'monospace',
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 12),
          // Switch Identity button
          OutlinedButton.icon(
            onPressed: () => _showSwitchIdentityDialog(context, ref),
            icon: const Icon(Icons.switch_account, size: 18),
            label: const Text('Switch Identity'),
            style: OutlinedButton.styleFrom(
              minimumSize: const Size.fromHeight(36),
              padding: const EdgeInsets.symmetric(horizontal: 12),
            ),
          ),
        ],
      ),
    );
  }

  String _getInitials(String name) {
    if (name.isEmpty) return '?';
    final parts = name.split(' ');
    if (parts.length >= 2) {
      return '${parts[0][0]}${parts[1][0]}'.toUpperCase();
    }
    return name[0].toUpperCase();
  }

  Widget _buildAvatar(AsyncValue<dynamic> fullProfile, String fallbackName, WidgetRef ref) {
    // DEBUG: Log what state fullProfile is in
    final engine = ref.read(engineProvider).valueOrNull;
    engine?.debugLog('FLUTTER', '[AVATAR_DEBUG] _buildAvatar: fullProfile.isLoading=${fullProfile.isLoading}, hasValue=${fullProfile.hasValue}');

    return fullProfile.when(
      data: (profile) {
        final avatarBase64 = profile?.avatarBase64 ?? '';
        engine?.debugLog('FLUTTER', '[AVATAR_DEBUG] _buildAvatar data: avatarBase64.length=${avatarBase64.length}');
        final avatarBytes = profile?.decodeAvatar();
        if (avatarBytes != null) {
          engine?.debugLog('FLUTTER', '[AVATAR_DEBUG] _buildAvatar: decoded ${avatarBytes.length} bytes, showing avatar');
          return CircleAvatar(
            radius: 32,
            backgroundImage: MemoryImage(avatarBytes),
          );
        }
        return CircleAvatar(
          radius: 32,
          backgroundColor: DnaColors.primarySoft,
          child: Text(
            _getInitials(fallbackName),
            style: const TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
              color: DnaColors.primary,
            ),
          ),
        );
      },
      loading: () {
        engine?.debugLog('FLUTTER', '[AVATAR_DEBUG] _buildAvatar: LOADING state');
        return CircleAvatar(
          radius: 32,
          backgroundColor: DnaColors.primarySoft,
          child: const SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
        );
      },
      error: (_, __) => CircleAvatar(
        radius: 32,
        backgroundColor: DnaColors.primarySoft,
        child: Text(
          _getInitials(fallbackName),
          style: const TextStyle(
            fontSize: 24,
            fontWeight: FontWeight.bold,
            color: DnaColors.primary,
          ),
        ),
      ),
    );
  }

  void _showSwitchIdentityDialog(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Switch Identity'),
        content: const Text(
          'This will log you out and return to identity selection.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx); // Close dialog
              Navigator.pop(context); // Close drawer
              // Unload identity - set fingerprint to null which triggers identityLoadedProvider
              ref.read(currentFingerprintProvider.notifier).state = null;
            },
            child: const Text('Switch'),
          ),
        ],
      ),
    );
  }
}
