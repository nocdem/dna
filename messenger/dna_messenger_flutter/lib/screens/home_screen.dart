// Home Screen - Main navigation with drawer
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../providers/providers.dart';
import '../providers/event_handler.dart';
import '../theme/dna_theme.dart';
import '../platform/platform_handler.dart';
// v0.3.0: IdentitySelectionScreen import removed - single-user model
// Feed disabled - will be reimplemented in the future
// import 'feed/feed_screen.dart';
import 'contacts/contacts_screen.dart';
import 'groups/groups_screen.dart';
import 'wallet/wallet_screen.dart';
import 'qr/qr_scanner_screen.dart';
import 'settings/settings_screen.dart';

/// Current tab index
/// Mobile: 0=Chats, 1=Groups, 2=Wallet, 3=QR Scanner, 4=Settings
/// Desktop: 0=Chats, 1=Groups, 2=Wallet, 3=Settings (no QR)
final currentTabProvider = StateProvider<int>((ref) => 0);

/// v0.3.0: Single-user model - HomeScreen always shows main navigation
/// Identity check moved to _AppLoader in main.dart
class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // v0.3.0: Identity is always loaded before reaching HomeScreen
    // See _AppLoader._checkAndLoadIdentity() in main.dart
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
    final supportsQr = PlatformHandler.instance.supportsQrScanner;

    return Scaffold(
      key: _scaffoldKey,
      drawer: const _NavigationDrawer(),
      body: IndexedStack(
        index: currentTab,
        children: [
          ContactsScreen(onMenuPressed: _openDrawer),
          GroupsScreen(onMenuPressed: _openDrawer),
          WalletScreen(onMenuPressed: _openDrawer),
          if (supportsQr) QrScannerScreen(onMenuPressed: _openDrawer),
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
    final supportsQr = PlatformHandler.instance.supportsQrScanner;
    // Settings tab index: 4 on mobile (with QR), 3 on desktop (no QR)
    final settingsTabIndex = supportsQr ? 4 : 3;

    void selectTab(int index) {
      ref.read(currentTabProvider.notifier).state = index;
      Navigator.of(context).pop();
    }

    return Drawer(
      child: SafeArea(
        child: Column(
          children: [
            // Header with profile
            const _DrawerHeader(),
            const SizedBox(height: 8),
            // Navigation items
            Expanded(
              child: ListView(
                padding: EdgeInsets.zero,
                children: [
                  _DrawerItem(
                    icon: FontAwesomeIcons.comments,
                    selectedIcon: FontAwesomeIcons.solidComments,
                    label: 'Chats',
                    selected: currentTab == 0,
                    onTap: () => selectTab(0),
                  ),
                  _DrawerItem(
                    icon: FontAwesomeIcons.users,
                    selectedIcon: FontAwesomeIcons.users,
                    label: 'Groups',
                    selected: currentTab == 1,
                    onTap: () => selectTab(1),
                  ),
                  _DrawerItem(
                    icon: FontAwesomeIcons.wallet,
                    selectedIcon: FontAwesomeIcons.wallet,
                    label: 'Wallet',
                    selected: currentTab == 2,
                    onTap: () => selectTab(2),
                  ),
                  if (supportsQr)
                    _DrawerItem(
                      icon: FontAwesomeIcons.qrcode,
                      selectedIcon: FontAwesomeIcons.qrcode,
                      label: 'QR Scanner',
                      selected: currentTab == 3,
                      onTap: () => selectTab(3),
                    ),
                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 16),
                    child: Divider(),
                  ),
                  _DrawerItem(
                    icon: FontAwesomeIcons.gear,
                    selectedIcon: FontAwesomeIcons.gear,
                    label: 'Settings',
                    selected: currentTab == settingsTabIndex,
                    onTap: () => selectTab(settingsTabIndex),
                  ),
                ],
              ),
            ),
            // DHT Connection Status at bottom
            const _DhtStatusIndicator(),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}

class _DrawerItem extends StatelessWidget {
  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  const _DrawerItem({
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListTile(
      leading: FaIcon(
        selected ? selectedIcon : icon,
        color: selected ? theme.colorScheme.primary : null,
      ),
      title: Text(
        label,
        style: TextStyle(
          color: selected ? theme.colorScheme.primary : null,
          fontWeight: selected ? FontWeight.w600 : null,
        ),
      ),
      selected: selected,
      onTap: onTap,
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
      DhtConnectionState.connected => ('DHT Connected', Colors.green, FontAwesomeIcons.cloud),
      DhtConnectionState.connecting => ('DHT Connecting', Colors.orange, FontAwesomeIcons.cloudArrowUp),
      DhtConnectionState.disconnected => ('DHT Disconnected', Colors.red, FontAwesomeIcons.cloudBolt),
    };

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          FaIcon(icon, size: 16, color: color),
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
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 16),
      decoration: const BoxDecoration(
        color: DnaColors.surface,
        border: Border(bottom: BorderSide(color: DnaColors.border)),
      ),
      child: Row(
        children: [
          // Avatar
          _buildAvatar(fullProfile, userProfile.valueOrNull?.nickname ?? shortFp, ref),
          const SizedBox(width: 12),
          // Name and fingerprint
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
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
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _getInitials(String name) {
    if (name.isEmpty) return '?';
    // Filter out empty strings from split (handles multiple spaces)
    final words = name.split(' ').where((w) => w.isNotEmpty).toList();
    if (words.isEmpty) return '?';
    if (words.length >= 2) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return words[0].substring(0, words[0].length.clamp(0, 2)).toUpperCase();
  }

  Widget _buildAvatar(AsyncValue<dynamic> fullProfile, String fallbackName, WidgetRef ref) {
    return fullProfile.when(
      data: (profile) {
        final avatarBytes = profile?.decodeAvatar();
        if (avatarBytes != null) {
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

  // v0.3.0: _showSwitchIdentityDialog removed - single-user model
}
