// Home Screen - Main navigation with bottom tabs
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../providers/providers.dart';
import 'contacts/contacts_screen.dart';
import 'groups/groups_screen.dart';
import 'feed/feed_screen.dart';
import 'more/more_screen.dart';

/// Current tab index: 0=Chats, 1=Groups, 2=Feed, 3=More
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

class _MainNavigation extends ConsumerWidget {
  const _MainNavigation();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final currentTab = ref.watch(currentTabProvider);

    // Watch unread counts for badges
    final chatUnreadCount = ref.watch(totalUnreadCountProvider);
    final groupUnreadCount = ref.watch(totalGroupUnreadCountProvider);

    return Scaffold(
      body: IndexedStack(
        index: currentTab,
        children: const [
          ContactsScreen(),
          GroupsScreen(),
          FeedScreen(),
          MoreScreen(),
        ],
      ),
      bottomNavigationBar: DnaBottomBar(
        currentIndex: currentTab,
        onTap: (index) => ref.read(currentTabProvider.notifier).state = index,
        items: [
          DnaBottomBarItem(
            icon: FontAwesomeIcons.comment,
            activeIcon: FontAwesomeIcons.solidComment,
            label: 'Chats',
            badgeCount: chatUnreadCount,
          ),
          DnaBottomBarItem(
            icon: FontAwesomeIcons.userGroup,
            activeIcon: FontAwesomeIcons.userGroup,
            label: 'Groups',
            badgeCount: groupUnreadCount,
          ),
          DnaBottomBarItem(
            icon: FontAwesomeIcons.newspaper,
            activeIcon: FontAwesomeIcons.solidNewspaper,
            label: 'Feed',
          ),
          DnaBottomBarItem(
            icon: FontAwesomeIcons.ellipsis,
            activeIcon: FontAwesomeIcons.ellipsis,
            label: 'More',
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// DHT STATUS INDICATOR (kept for future integration)
// =============================================================================

class DhtStatusIndicator extends ConsumerWidget {
  const DhtStatusIndicator({super.key});

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
