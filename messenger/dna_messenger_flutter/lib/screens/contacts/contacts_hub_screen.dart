// Contacts Hub Screen - Unified contacts management with 3 tabs
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../chat/chat_screen.dart';
import 'add_contact_dialog.dart';

class ContactsHubScreen extends ConsumerStatefulWidget {
  const ContactsHubScreen({super.key});

  @override
  ConsumerState<ContactsHubScreen> createState() => _ContactsHubScreenState();
}

class _ContactsHubScreenState extends ConsumerState<ContactsHubScreen>
    with TickerProviderStateMixin {
  late final TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _tabController.addListener(() {
      // Rebuild to show/hide FAB based on tab index
      if (!_tabController.indexIsChanging) {
        setState(() {});
      }
    });
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  void _refreshAll() {
    ref.invalidate(contactsProvider);
    ref.invalidate(contactRequestsProvider);
    ref.invalidate(blockedUsersProvider);
  }

  @override
  Widget build(BuildContext context) {
    final pendingCount = ref.watch(pendingRequestCountProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Contacts',
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: _refreshAll,
            tooltip: 'Refresh',
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          tabs: [
            const Tab(text: 'Contacts'),
            Tab(
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text('Requests'),
                  if (pendingCount > 0) ...[
                    const SizedBox(width: 6),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                      constraints: const BoxConstraints(minWidth: 18),
                      decoration: BoxDecoration(
                        color: DnaColors.error,
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Text(
                        pendingCount > 99 ? '99+' : '$pendingCount',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                        ),
                        textAlign: TextAlign.center,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const Tab(text: 'Blocked'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: const [
          _ContactsTab(),
          _RequestsTab(),
          _BlockedTab(),
        ],
      ),
      floatingActionButton: _tabController.index == 0
          ? FloatingActionButton(
              heroTag: 'contacts_hub_fab',
              onPressed: () => showAddContactDialog(context, ref),
              tooltip: 'Add Contact',
              child: const FaIcon(FontAwesomeIcons.userPlus),
            )
          : null,
    );
  }
}

// =============================================================================
// TAB 0: CONTACTS
// =============================================================================

class _ContactsTab extends ConsumerWidget {
  const _ContactsTab();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);

    return contacts.when(
      data: (list) => _buildContactList(context, ref, list),
      loading: () {
        final cached = contacts.valueOrNull;
        if (cached != null) return _buildContactList(context, ref, cached);
        return const Center(child: CircularProgressIndicator());
      },
      error: (error, stack) => _buildError(context, ref, error),
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
            Text('No contacts yet', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text('Tap + to add your first contact', style: theme.textTheme.bodySmall),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async => ref.read(contactsProvider.notifier).refresh(),
      child: ListView.builder(
        itemCount: contacts.length,
        cacheExtent: 500.0,
        itemBuilder: (context, index) {
          final contact = contacts[index];
          return _HubContactTile(
            contact: contact,
            onTap: () {
              ref.read(selectedContactProvider.notifier).state = contact;
              Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const ChatScreen()),
              );
            },
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
            FaIcon(FontAwesomeIcons.circleExclamation, size: 48, color: DnaColors.textWarning),
            const SizedBox(height: 16),
            Text('Failed to load contacts', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error.toString(), style: theme.textTheme.bodySmall, textAlign: TextAlign.center),
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
}

class _HubContactTile extends ConsumerWidget {
  final Contact contact;
  final VoidCallback onTap;

  const _HubContactTile({required this.contact, required this.onTap});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    final unreadCount = ref.watch(
      unreadCountsProvider.select((async) => async.maybeWhen(
        data: (counts) => counts[contact.fingerprint] ?? 0,
        orElse: () => 0,
      )),
    );

    final cachedProfile = ref.watch(
      contactProfileCacheProvider.select((cache) => cache[contact.fingerprint]),
    );
    final avatarBytes = cachedProfile?.decodeAvatar();

    final displayName = contact.displayName.isNotEmpty
        ? contact.displayName
        : _shortenFingerprint(contact.fingerprint);

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
        style: unreadCount > 0 ? const TextStyle(fontWeight: FontWeight.bold) : null,
      ),
      subtitle: Text(
        contact.isOnline ? 'Online' : 'Last seen ${_formatLastSeen(contact.lastSeen)}',
        style: TextStyle(
          color: contact.isOnline ? DnaColors.success : theme.textTheme.bodySmall?.color,
        ),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (unreadCount > 0)
            DnaBadge(count: unreadCount, child: const SizedBox(width: 20, height: 20)),
          const SizedBox(width: 4),
          PopupMenuButton<String>(
            onSelected: (value) {
              if (value == 'copy') {
                Clipboard.setData(ClipboardData(text: contact.fingerprint));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Fingerprint copied')),
                );
              } else if (value == 'remove') {
                _removeContact(context, ref, contact);
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'copy',
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.copy, size: 20),
                    SizedBox(width: 8),
                    Text('Copy Fingerprint'),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'remove',
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.userMinus, size: 20, color: DnaColors.textWarning),
                    const SizedBox(width: 8),
                    Text('Remove', style: TextStyle(color: DnaColors.textWarning)),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      onTap: onTap,
    );
  }

  Future<void> _removeContact(BuildContext context, WidgetRef ref, Contact contact) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            FaIcon(FontAwesomeIcons.userMinus, color: DnaColors.textWarning),
            const SizedBox(width: 8),
            const Text('Remove Contact'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Remove ${contact.displayName} from your contacts?'),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: DnaColors.textWarning.withAlpha(26),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: DnaColors.textWarning.withAlpha(51)),
              ),
              child: Row(
                children: [
                  FaIcon(FontAwesomeIcons.circleInfo, size: 20, color: DnaColors.textWarning),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Message history will be preserved. You can re-add this contact later.',
                      style: TextStyle(fontSize: 13, color: DnaColors.textWarning),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: DnaColors.textWarning,
              foregroundColor: Colors.white,
            ),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        await ref.read(contactsProvider.notifier).removeContact(contact.fingerprint);
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('${contact.displayName} removed'),
              backgroundColor: DnaColors.snackbarSuccess,
            ),
          );
        }
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to remove contact: $e'),
              backgroundColor: DnaColors.snackbarError,
            ),
          );
        }
      }
    }
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 16) return fp;
    return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
  }

  String _formatLastSeen(DateTime lastSeen) {
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

// =============================================================================
// TAB 1: REQUESTS
// =============================================================================

class _RequestsTab extends ConsumerWidget {
  const _RequestsTab();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final requests = ref.watch(contactRequestsProvider);

    return requests.when(
      data: (list) => _buildRequestList(context, ref, list),
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => _buildError(context, ref, error),
    );
  }

  Widget _buildRequestList(
      BuildContext context, WidgetRef ref, List<ContactRequest> requests) {
    final theme = Theme.of(context);
    final pendingRequests =
        requests.where((r) => r.status == ContactRequestStatus.pending).toList();

    if (pendingRequests.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.userClock,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text('No pending requests', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text('Contact requests will appear here', style: theme.textTheme.bodySmall),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async => ref.read(contactRequestsProvider.notifier).refresh(),
      child: ListView.builder(
        itemCount: pendingRequests.length,
        itemBuilder: (context, index) {
          final request = pendingRequests[index];
          return _RequestTile(
            request: request,
            onApprove: () => _approveRequest(context, ref, request),
            onDeny: () => _denyRequest(context, ref, request),
            onBlock: () => _blockUser(context, ref, request),
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
            FaIcon(FontAwesomeIcons.circleExclamation, size: 48, color: DnaColors.textWarning),
            const SizedBox(height: 16),
            Text('Failed to load requests', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error.toString(), style: theme.textTheme.bodySmall, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: () => ref.invalidate(contactRequestsProvider),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _approveRequest(
      BuildContext context, WidgetRef ref, ContactRequest request) async {
    try {
      await ref.read(contactRequestsProvider.notifier).approve(request.fingerprint);
      ref.invalidate(contactsProvider);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Approved ${_getDisplayName(request)}'),
            backgroundColor: DnaColors.textSuccess,
          ),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to approve: $e'), backgroundColor: DnaColors.textWarning),
        );
      }
    }
  }

  Future<void> _denyRequest(
      BuildContext context, WidgetRef ref, ContactRequest request) async {
    try {
      await ref.read(contactRequestsProvider.notifier).deny(request.fingerprint);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Denied ${_getDisplayName(request)}')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to deny: $e'), backgroundColor: DnaColors.textWarning),
        );
      }
    }
  }

  Future<void> _blockUser(
      BuildContext context, WidgetRef ref, ContactRequest request) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Block User'),
        content: Text(
          'Block ${_getDisplayName(request)}? They will not be able to send you requests or messages.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: TextButton.styleFrom(foregroundColor: DnaColors.textWarning),
            child: const Text('Block'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        await ref.read(contactRequestsProvider.notifier).block(request.fingerprint, null);
        ref.invalidate(blockedUsersProvider);
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Blocked ${_getDisplayName(request)}'),
              backgroundColor: DnaColors.textWarning,
            ),
          );
        }
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to block: $e'), backgroundColor: DnaColors.textWarning),
          );
        }
      }
    }
  }

  String _getDisplayName(ContactRequest request) {
    if (request.displayName.isNotEmpty) return request.displayName;
    return _shortenFingerprint(request.fingerprint);
  }

  String _shortenFingerprint(String fp) {
    if (fp.length > 16) return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
    return fp;
  }
}

class _RequestTile extends ConsumerWidget {
  final ContactRequest request;
  final VoidCallback onApprove;
  final VoidCallback onDeny;
  final VoidCallback onBlock;

  const _RequestTile({
    required this.request,
    required this.onApprove,
    required this.onDeny,
    required this.onBlock,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    final displayName = request.displayName.isNotEmpty
        ? request.displayName
        : _shortenFingerprint(request.fingerprint);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  backgroundColor: theme.colorScheme.primary.withAlpha(51),
                  child: Text(
                    _getInitials(displayName),
                    style: TextStyle(
                      color: theme.colorScheme.primary,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(displayName, style: theme.textTheme.titleMedium),
                      Text(
                        _formatTime(request.requestedAt),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurface.withAlpha(153),
                        ),
                      ),
                    ],
                  ),
                ),
                PopupMenuButton<String>(
                  onSelected: (value) {
                    if (value == 'block') onBlock();
                  },
                  itemBuilder: (context) => [
                    const PopupMenuItem(
                      value: 'block',
                      child: Row(
                        children: [
                          FaIcon(FontAwesomeIcons.ban, color: Colors.red),
                          SizedBox(width: 8),
                          Text('Block User'),
                        ],
                      ),
                    ),
                  ],
                ),
              ],
            ),
            if (request.message.isNotEmpty) ...[
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(request.message, style: theme.textTheme.bodyMedium),
              ),
            ],
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(onPressed: onDeny, child: const Text('Deny')),
                const SizedBox(width: 8),
                FilledButton.icon(
                  onPressed: onApprove,
                  icon: const FaIcon(FontAwesomeIcons.check),
                  label: const Text('Accept'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String _getInitials(String name) {
    if (name.isEmpty) return '?';
    final words = name.split(' ').where((w) => w.isNotEmpty).toList();
    if (words.isEmpty) return '?';
    if (words.length >= 2) return '${words[0][0]}${words[1][0]}'.toUpperCase();
    return words[0].substring(0, words[0].length.clamp(0, 2)).toUpperCase();
  }

  String _shortenFingerprint(String fp) {
    if (fp.length > 16) return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
    return fp;
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);
    if (diff.inDays > 0) return '${diff.inDays}d ago';
    if (diff.inHours > 0) return '${diff.inHours}h ago';
    if (diff.inMinutes > 0) return '${diff.inMinutes}m ago';
    return 'Just now';
  }
}

// =============================================================================
// TAB 2: BLOCKED
// =============================================================================

class _BlockedTab extends ConsumerWidget {
  const _BlockedTab();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final blockedUsers = ref.watch(blockedUsersProvider);

    return blockedUsers.when(
      data: (list) => _buildBlockedList(context, ref, list),
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => _buildError(context, ref, error),
    );
  }

  Widget _buildBlockedList(
      BuildContext context, WidgetRef ref, List<BlockedUser> blockedUsers) {
    final theme = Theme.of(context);

    if (blockedUsers.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.ban,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text('No blocked users', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text('Users you block will appear here', style: theme.textTheme.bodySmall),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async => ref.read(blockedUsersProvider.notifier).refresh(),
      child: ListView.builder(
        itemCount: blockedUsers.length,
        itemBuilder: (context, index) {
          final blocked = blockedUsers[index];
          return _BlockedUserTile(
            blockedUser: blocked,
            onUnblock: () => _unblockUser(context, ref, blocked),
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
            FaIcon(FontAwesomeIcons.circleExclamation, size: 48, color: DnaColors.textWarning),
            const SizedBox(height: 16),
            Text('Failed to load blocked users', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error.toString(), style: theme.textTheme.bodySmall, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: () => ref.invalidate(blockedUsersProvider),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _unblockUser(
      BuildContext context, WidgetRef ref, BlockedUser blockedUser) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unblock User'),
        content: Text(
          'Unblock ${_shortenFingerprint(blockedUser.fingerprint)}? They will be able to send you contact requests again.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Unblock'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        await ref.read(blockedUsersProvider.notifier).unblock(blockedUser.fingerprint);
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('User unblocked')),
          );
        }
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to unblock: $e'),
              backgroundColor: DnaColors.textWarning,
            ),
          );
        }
      }
    }
  }

  String _shortenFingerprint(String fp) {
    if (fp.length > 16) return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
    return fp;
  }
}

class _BlockedUserTile extends StatelessWidget {
  final BlockedUser blockedUser;
  final VoidCallback onUnblock;

  const _BlockedUserTile({required this.blockedUser, required this.onUnblock});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: DnaColors.textWarning.withAlpha(51),
        child: FaIcon(FontAwesomeIcons.ban, color: DnaColors.textWarning),
      ),
      title: Text(
        _shortenFingerprint(blockedUser.fingerprint),
        style: const TextStyle(fontFamily: 'monospace'),
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Blocked ${_formatTime(blockedUser.blockedAt)}', style: theme.textTheme.bodySmall),
          if (blockedUser.reason.isNotEmpty)
            Text(
              blockedUser.reason,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurface.withAlpha(153),
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
        ],
      ),
      trailing: TextButton(onPressed: onUnblock, child: const Text('Unblock')),
      isThreeLine: blockedUser.reason.isNotEmpty,
    );
  }

  String _shortenFingerprint(String fp) {
    if (fp.length > 16) return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
    return fp;
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);
    if (diff.inDays > 0) return '${diff.inDays}d ago';
    if (diff.inHours > 0) return '${diff.inHours}h ago';
    if (diff.inMinutes > 0) return '${diff.inMinutes}m ago';
    return 'Just now';
  }
}
