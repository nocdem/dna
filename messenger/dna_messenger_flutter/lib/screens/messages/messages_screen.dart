// Chats Screen - Unified Chats + Groups with filter tabs
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../l10n/app_localizations.dart';
import '../../providers/providers.dart';
import '../contacts/contacts_screen.dart';
import '../chat/chat_screen.dart';
/// Filter state for chats tab
enum MessagesFilter { all, unread, chats }

final messagesFilterProvider =
    StateProvider<MessagesFilter>((ref) => MessagesFilter.all);

class MessagesScreen extends ConsumerWidget {
  const MessagesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final filter = ref.watch(messagesFilterProvider);
    final chatUnread = ref.watch(totalUnreadCountProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: AppLocalizations.of(context).navChats,
        leading: const SizedBox.shrink(),
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
                  label: AppLocalizations.of(context).messagesAll,
                  selected: filter == MessagesFilter.all,
                  onTap: () =>
                      ref.read(messagesFilterProvider.notifier).state =
                          MessagesFilter.all,
                ),
                const SizedBox(width: DnaSpacing.sm),
                _FilterChip(
                  label: AppLocalizations.of(context).messagesUnread,
                  badgeCount: chatUnread,
                  selected: filter == MessagesFilter.unread,
                  onTap: () =>
                      ref.read(messagesFilterProvider.notifier).state =
                          MessagesFilter.unread,
                ),
                const SizedBox(width: DnaSpacing.sm),
                _FilterChip(
                  label: AppLocalizations.of(context).navChats,
                  badgeCount: chatUnread,
                  selected: filter == MessagesFilter.chats,
                  onTap: () =>
                      ref.read(messagesFilterProvider.notifier).state =
                          MessagesFilter.chats,
                ),
              ],
            ),
          ),
          // Content based on filter
          Expanded(
            child: switch (filter) {
              MessagesFilter.all => const ContactsScreen(embedded: true),
              MessagesFilter.unread => const _UnreadMessagesView(),
              MessagesFilter.chats => const ContactsScreen(embedded: true),
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

/// "Unread" filter: Shows only contacts with unread messages
class _UnreadMessagesView extends ConsumerWidget {
  const _UnreadMessagesView();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final contacts = ref.watch(contactsProvider);
    final chatUnreads = ref.watch(unreadCountsProvider);

    final unreadChatCounts = chatUnreads.valueOrNull ?? {};

    // Filter contacts with unread messages
    final allContacts = contacts.valueOrNull ?? [];
    final unreadContacts = allContacts
        .where((c) => (unreadChatCounts[c.fingerprint] ?? 0) > 0)
        .toList();

    if (unreadContacts.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.checkDouble,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              AppLocalizations.of(context).messagesAllCaughtUp,
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              AppLocalizations.of(context).messagesNoUnread,
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return ListView(
      children: [
        ...unreadContacts.map((contact) => _UnreadContactTile(
          contact: contact,
          unreadCount: unreadChatCounts[contact.fingerprint] ?? 0,
        )),
      ],
    );
  }
}

class _UnreadContactTile extends ConsumerWidget {
  final Contact contact;
  final int unreadCount;

  const _UnreadContactTile({
    required this.contact,
    required this.unreadCount,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final cachedProfile = ref.watch(
      contactProfileCacheProvider.select((cache) => cache[contact.fingerprint]),
    );
    final avatarBytes = cachedProfile?.decodeAvatar();

    final displayName = contact.effectiveName.isNotEmpty
        ? contact.effectiveName
        : _shortenFp(contact.fingerprint);

    if (cachedProfile == null) {
      Future.microtask(() {
        ref.read(contactProfileCacheProvider.notifier).fetchAndCache(contact.fingerprint);
      });
    }

    return ListTile(
      leading: DnaAvatar(
        imageBytes: avatarBytes,
        name: displayName,
        size: DnaAvatarSize.md,
        showOnlineStatus: true,
        isOnline: contact.isOnline,
      ),
      title: Text(
        displayName,
        style: const TextStyle(fontWeight: FontWeight.bold),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          DnaBadge(
            count: unreadCount,
            child: const SizedBox(width: 20, height: 20),
          ),
          const SizedBox(width: 4),
          FaIcon(
            FontAwesomeIcons.chevronRight,
            size: 14,
            color: theme.textTheme.bodySmall?.color,
          ),
        ],
      ),
      onTap: () {
        ref.read(selectedContactProvider.notifier).state = contact;
        Navigator.of(context).push(
          MaterialPageRoute(builder: (context) => const ChatScreen()),
        );
      },
    );
  }

  static String _shortenFp(String fp) {
    if (fp.length <= 16) return fp;
    return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
  }
}

