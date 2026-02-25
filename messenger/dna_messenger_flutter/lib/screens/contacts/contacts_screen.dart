// Contacts Screen - Contact list with online status
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../chat/chat_screen.dart';
import 'add_contact_dialog.dart';
import 'contact_requests_screen.dart';

class ContactsScreen extends ConsumerWidget {
  final bool embedded;
  const ContactsScreen({super.key, this.embedded = false});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);

    final body = contacts.when(
      data: (list) => _buildContactList(context, ref, list),
      // Show cached contacts while loading if available, otherwise show spinner
      // This prevents flash of "No contacts" on initial load
      loading: () {
        final cached = contacts.valueOrNull;
        if (cached != null) {
          return _buildContactList(context, ref, cached);
        }
        return const Center(child: CircularProgressIndicator());
      },
      error: (error, stack) => _buildError(context, ref, error),
    );

    if (embedded) {
      return Stack(
        children: [
          body,
          Positioned(
            right: 16,
            bottom: 16,
            child: FloatingActionButton(
              heroTag: 'contacts_fab_embedded',
              onPressed: () => showAddContactDialog(context, ref),
              tooltip: 'Add Contact',
              child: const FaIcon(FontAwesomeIcons.userPlus),
            ),
          ),
        ],
      );
    }

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Chats',
        leading: const SizedBox.shrink(), // No back button
        actions: [
          _ContactRequestsBadge(
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (context) => const ContactRequestsScreen(),
              ),
            ),
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.read(contactsProvider.notifier).refresh(),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: body,
      floatingActionButton: FloatingActionButton(
        heroTag: 'contacts_fab',
        onPressed: () => _showAddContactDialog(context, ref),
        tooltip: 'Add Contact',
        child: const FaIcon(FontAwesomeIcons.userPlus),
      ),
    );
  }

  Widget _buildContactList(BuildContext context, WidgetRef ref, List<Contact> contacts) {
    final theme = Theme.of(context);

    if (contacts.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.users,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No contacts yet',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Tap + to add your first contact',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(contactsProvider.notifier).refresh();
      },
      child: ListView.builder(
        itemCount: contacts.length,
        cacheExtent: 500.0, // Pre-render items for smoother scrolling
        itemBuilder: (context, index) {
          final contact = contacts[index];
          return _ContactTile(
            contact: contact,
            onTap: () => _openChat(context, ref, contact),
          );
        },
      ),
    );
  }

  Widget _buildError(BuildContext context, WidgetRef ref, Object error) {
    final theme = Theme.of(context);

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.circleExclamation,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load contacts',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: () => ref.read(contactsProvider.notifier).refresh(),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  void _openChat(BuildContext context, WidgetRef ref, Contact contact) {
    ref.read(selectedContactProvider.notifier).state = contact;
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const ChatScreen(),
      ),
    );
  }

  void _showAddContactDialog(BuildContext context, WidgetRef ref) {
    showAddContactDialog(context, ref);
  }
}

class _ContactTile extends ConsumerWidget {
  final Contact contact;
  final VoidCallback onTap;

  const _ContactTile({
    required this.contact,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    // Use select() to only rebuild when this specific contact's unread count changes
    final unreadCount = ref.watch(
      unreadCountsProvider.select((async) => async.maybeWhen(
        data: (counts) => counts[contact.fingerprint] ?? 0,
        orElse: () => 0,
      )),
    );

    // Use select() to only rebuild when this specific contact's profile changes
    final cachedProfile = ref.watch(
      contactProfileCacheProvider.select((cache) => cache[contact.fingerprint]),
    );
    final avatarBytes = cachedProfile?.decodeAvatar();

    // Use contact.displayName (resolved by C library from registered name)
    // v0.6.24: UserProfile.displayName removed - Contact.displayName is the source of truth
    final displayName = contact.displayName.isNotEmpty
        ? contact.displayName
        : _shortenFingerprint(contact.fingerprint);

    // Trigger fetch if not cached (fire and forget)
    if (cachedProfile == null) {
      Future.microtask(() {
        ref.read(contactProfileCacheProvider.notifier).fetchAndCache(contact.fingerprint);
      });
    }

    // v0.6.6: Listeners are now started on identity load (not lazy anymore)

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
        style: unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.bold)
            : null,
      ),
      subtitle: Text(
        contact.isOnline
            ? 'Online'
            : 'Last seen ${_formatLastSeen(contact.lastSeen)}',
        style: TextStyle(
          color: contact.isOnline
              ? DnaColors.success
              : theme.textTheme.bodySmall?.color,
        ),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (unreadCount > 0)
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
      onTap: onTap,
    );
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }

  String _formatLastSeen(DateTime lastSeen) {
    // Epoch (0) means presence data not yet fetched
    // v0.100.71: Show "Syncing..." instead of "never" for better UX during startup
    if (lastSeen.millisecondsSinceEpoch == 0) return 'Syncing...';

    final now = DateTime.now();
    final diff = now.difference(lastSeen);

    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return '${lastSeen.day}/${lastSeen.month}/${lastSeen.year}';
  }
}

class _ContactRequestsBadge extends ConsumerWidget {
  final VoidCallback onTap;

  const _ContactRequestsBadge({required this.onTap});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final pendingCount = ref.watch(pendingRequestCountProvider);

    return DnaBadge(
      count: pendingCount,
      child: IconButton(
        icon: const FaIcon(FontAwesomeIcons.userClock),
        onPressed: onTap,
        tooltip: 'Contact Requests',
      ),
    );
  }
}
