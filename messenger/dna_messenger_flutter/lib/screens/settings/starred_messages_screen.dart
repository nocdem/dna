// Starred Messages Screen - View all starred/bookmarked messages
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../services/cache_database.dart';
import '../chat/chat_screen.dart';

/// Provider for all starred messages grouped by contact
final starredMessagesGroupedProvider = FutureProvider<Map<String, List<StarredMessageInfo>>>((ref) async {
  return CacheDatabase.instance.getAllStarredMessagesGrouped();
});

class StarredMessagesScreen extends ConsumerWidget {
  const StarredMessagesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final starredMessages = ref.watch(starredMessagesGroupedProvider);
    final contacts = ref.watch(contactsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Starred Messages'),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.invalidate(starredMessagesGroupedProvider),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: starredMessages.when(
        data: (grouped) {
          if (grouped.isEmpty) {
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FaIcon(
                    FontAwesomeIcons.star,
                    size: 64,
                    color: theme.colorScheme.primary.withAlpha(128),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No starred messages',
                    style: theme.textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Long press a message to star it',
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            );
          }

          // Build list of contact sections
          final contactList = contacts.valueOrNull ?? [];
          final sortedContacts = grouped.keys.toList()
            ..sort((a, b) {
              // Sort by number of starred messages (descending)
              return (grouped[b]?.length ?? 0).compareTo(grouped[a]?.length ?? 0);
            });

          return ListView.builder(
            itemCount: sortedContacts.length,
            itemBuilder: (context, index) {
              final contactFp = sortedContacts[index];
              final starredList = grouped[contactFp] ?? [];

              // Find contact info
              final contact = contactList.firstWhere(
                (c) => c.fingerprint == contactFp,
                orElse: () => Contact(
                  fingerprint: contactFp,
                  displayName: '',
                  nickname: '',
                  isOnline: false,
                  lastSeen: DateTime.fromMillisecondsSinceEpoch(0),
                ),
              );

              final displayName = contact.displayName.isNotEmpty
                  ? contact.displayName
                  : '${contactFp.substring(0, 8)}...';

              return _ContactStarredSection(
                contactFp: contactFp,
                displayName: displayName,
                starredMessages: starredList,
                contact: contact,
              );
            },
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              FaIcon(
                FontAwesomeIcons.triangleExclamation,
                size: 48,
                color: theme.colorScheme.error,
              ),
              const SizedBox(height: 16),
              Text('Failed to load starred messages'),
              const SizedBox(height: 8),
              Text(
                error.toString(),
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

class _ContactStarredSection extends ConsumerWidget {
  final String contactFp;
  final String displayName;
  final List<StarredMessageInfo> starredMessages;
  final Contact contact;

  const _ContactStarredSection({
    required this.contactFp,
    required this.displayName,
    required this.starredMessages,
    required this.contact,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Contact header
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Row(
            children: [
              FaIcon(
                FontAwesomeIcons.user,
                size: 16,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  displayName,
                  style: theme.textTheme.titleSmall?.copyWith(
                    color: theme.colorScheme.primary,
                  ),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withAlpha(26),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  '${starredMessages.length} starred',
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.primary,
                  ),
                ),
              ),
            ],
          ),
        ),
        // Starred message tiles
        ...starredMessages.map((info) => _StarredMessageTile(
          info: info,
          contactFp: contactFp,
          contact: contact,
        )),
        const Divider(),
      ],
    );
  }
}

class _StarredMessageTile extends ConsumerWidget {
  final StarredMessageInfo info;
  final String contactFp;
  final Contact contact;

  const _StarredMessageTile({
    required this.info,
    required this.contactFp,
    required this.contact,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final conversation = ref.watch(conversationProvider(contactFp));

    // Find the message in the conversation
    final message = conversation.valueOrNull?.firstWhere(
      (m) => m.id == info.messageId,
      orElse: () => Message(
        id: info.messageId,
        sender: '',
        recipient: '',
        plaintext: '(Message not found)',
        timestamp: info.starredAt,
        status: MessageStatus.pending,
        isOutgoing: false,
        type: MessageType.chat,
      ),
    );

    final dateFormat = DateFormat('MMM d, yyyy');
    final timeFormat = DateFormat('HH:mm');

    return ListTile(
      leading: FaIcon(
        FontAwesomeIcons.solidStar,
        color: Colors.amber,
        size: 16,
      ),
      title: Text(
        message?.plaintext ?? '(Message not found)',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: Text(
        message != null
            ? '${message.isOutgoing ? "You" : "Them"} • ${dateFormat.format(message.timestamp)} at ${timeFormat.format(message.timestamp)}'
            : 'Starred ${dateFormat.format(info.starredAt)}',
        style: theme.textTheme.bodySmall,
      ),
      trailing: const FaIcon(FontAwesomeIcons.chevronRight, size: 14),
      onTap: () {
        // Navigate to chat with this contact
        ref.read(selectedContactProvider.notifier).state = contact;
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (context) => const ChatScreen(),
          ),
        );
      },
    );
  }
}
