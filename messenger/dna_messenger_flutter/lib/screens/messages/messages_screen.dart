// Messages Screen - Unified Chats + Groups with filter tabs
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../providers/providers.dart';
import '../contacts/contacts_screen.dart';
import '../groups/groups_screen.dart';

/// Filter state for messages tab
enum MessagesFilter { all, chats, groups }

final messagesFilterProvider =
    StateProvider<MessagesFilter>((ref) => MessagesFilter.all);

class MessagesScreen extends ConsumerWidget {
  const MessagesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final filter = ref.watch(messagesFilterProvider);
    final chatUnread = ref.watch(totalUnreadCountProvider);
    final groupUnread = ref.watch(totalGroupUnreadCountProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Messages',
        leading: const SizedBox.shrink(),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () {
              ref.read(contactsProvider.notifier).refresh();
              ref.invalidate(groupsProvider);
            },
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: Column(
        children: [
          // Filter chips
          Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: DnaSpacing.md,
              vertical: DnaSpacing.sm,
            ),
            child: Row(
              children: [
                _FilterChip(
                  label: 'All',
                  selected: filter == MessagesFilter.all,
                  onTap: () =>
                      ref.read(messagesFilterProvider.notifier).state =
                          MessagesFilter.all,
                ),
                const SizedBox(width: DnaSpacing.sm),
                _FilterChip(
                  label: 'Chats',
                  badgeCount: chatUnread,
                  selected: filter == MessagesFilter.chats,
                  onTap: () =>
                      ref.read(messagesFilterProvider.notifier).state =
                          MessagesFilter.chats,
                ),
                const SizedBox(width: DnaSpacing.sm),
                _FilterChip(
                  label: 'Groups',
                  badgeCount: groupUnread,
                  selected: filter == MessagesFilter.groups,
                  onTap: () =>
                      ref.read(messagesFilterProvider.notifier).state =
                          MessagesFilter.groups,
                ),
              ],
            ),
          ),
          // Content based on filter
          Expanded(
            child: switch (filter) {
              MessagesFilter.all => const _AllMessagesView(),
              MessagesFilter.chats => const ContactsScreen(embedded: true),
              MessagesFilter.groups => const GroupsScreen(embedded: true),
            },
          ),
        ],
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback onTap;
  final int badgeCount;

  const _FilterChip({
    required this.label,
    required this.selected,
    required this.onTap,
    this.badgeCount = 0,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.md,
          vertical: DnaSpacing.xs,
        ),
        decoration: BoxDecoration(
          color: selected
              ? theme.colorScheme.primary
              : theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(20),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                color: selected
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurface,
                fontWeight: selected ? FontWeight.bold : FontWeight.normal,
              ),
            ),
            if (badgeCount > 0) ...[
              const SizedBox(width: 4),
              Container(
                constraints:
                    const BoxConstraints(minWidth: 18, minHeight: 16),
                padding:
                    const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                decoration: BoxDecoration(
                  color: DnaColors.error,
                  borderRadius: BorderRadius.circular(10),
                ),
                alignment: Alignment.center,
                child: Text(
                  badgeCount > 99 ? '99+' : badgeCount.toString(),
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    height: 1,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// "All" filter: Shows contacts above groups in a single scrollable view
class _AllMessagesView extends ConsumerWidget {
  const _AllMessagesView();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Stack contacts and groups vertically, each taking available space.
    // A true merged-by-timestamp list would require a unified data model;
    // MVP: show both embedded screens in a column.
    return const Column(
      children: [
        Expanded(child: ContactsScreen(embedded: true)),
        Expanded(child: GroupsScreen(embedded: true)),
      ],
    );
  }
}
