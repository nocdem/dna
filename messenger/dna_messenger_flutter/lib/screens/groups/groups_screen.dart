// Groups Screen - Group list and invitations
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

class GroupsScreen extends ConsumerWidget {
  final VoidCallback? onMenuPressed;

  const GroupsScreen({super.key, this.onMenuPressed});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final groups = ref.watch(groupsProvider);
    final invitations = ref.watch(invitationsProvider);

    return Scaffold(
      appBar: AppBar(
        leading: onMenuPressed != null
            ? IconButton(
                icon: const FaIcon(FontAwesomeIcons.bars),
                onPressed: onMenuPressed,
              )
            : null,
        title: const Text('Groups'),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () {
              ref.invalidate(groupsProvider);
              ref.invalidate(invitationsProvider);
            },
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: _buildBody(context, ref, groups, invitations),
      floatingActionButton: FloatingActionButton(
        heroTag: 'groups_fab',
        onPressed: () => _showCreateGroupDialog(context, ref),
        tooltip: 'Create Group',
        child: const FaIcon(FontAwesomeIcons.userGroup),
      ),
    );
  }

  Widget _buildBody(
    BuildContext context,
    WidgetRef ref,
    AsyncValue<List<Group>> groups,
    AsyncValue<List<Invitation>> invitations,
  ) {
    return groups.when(
      data: (groupList) => invitations.when(
        data: (inviteList) => _buildContent(context, ref, groupList, inviteList),
        loading: () => _buildContent(context, ref, groupList, []),
        error: (e, st) => _buildContent(context, ref, groupList, []),
      ),
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => _buildError(context, ref, error),
    );
  }

  Widget _buildContent(
    BuildContext context,
    WidgetRef ref,
    List<Group> groups,
    List<Invitation> invitations,
  ) {
    final theme = Theme.of(context);

    if (groups.isEmpty && invitations.isEmpty) {
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
              'No groups yet',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Tap + to create your first group',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(groupsProvider.notifier).refresh();
        await ref.read(invitationsProvider.notifier).refresh();
      },
      child: ListView(
        children: [
          // Invitations section
          if (invitations.isNotEmpty) ...[
            _SectionHeader(
              title: 'Pending Invitations',
              count: invitations.length,
            ),
            ...invitations.map((inv) => _InvitationTile(
              invitation: inv,
              onAccept: () async => _acceptInvitation(context, ref, inv),
              onDecline: () async => _declineInvitation(context, ref, inv),
            )),
            const Divider(),
          ],
          // Groups section
          if (groups.isNotEmpty) ...[
            _SectionHeader(
              title: 'Your Groups',
              count: groups.length,
            ),
            ...groups.map((group) => _GroupTile(
              group: group,
              onTap: () => _openGroupChat(context, ref, group),
            )),
          ],
        ],
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
              'Failed to load groups',
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
              onPressed: () => ref.invalidate(groupsProvider),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  void _showCreateGroupDialog(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => _CreateGroupDialog(ref: ref),
    );
  }

  void _openGroupChat(BuildContext context, WidgetRef ref, Group group) {
    // Clear unread count when opening group chat
    ref.read(groupUnreadCountsProvider.notifier).clearCount(group.uuid);

    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => GroupChatScreen(group: group),
      ),
    );
  }

  Future<void> _acceptInvitation(BuildContext context, WidgetRef ref, Invitation invitation) async {
    try {
      await ref.read(invitationsProvider.notifier).acceptInvitation(invitation.groupUuid);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Joined ${invitation.groupName}')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to accept invitation: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  Future<void> _declineInvitation(BuildContext context, WidgetRef ref, Invitation invitation) async {
    try {
      await ref.read(invitationsProvider.notifier).rejectInvitation(invitation.groupUuid);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invitation declined')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to decline invitation: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;
  final int count;

  const _SectionHeader({required this.title, required this.count});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Row(
        children: [
          Text(
            title,
            style: theme.textTheme.titleSmall?.copyWith(
              color: theme.colorScheme.primary,
            ),
          ),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withAlpha(26),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              count.toString(),
              style: theme.textTheme.labelSmall?.copyWith(
                color: theme.colorScheme.primary,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _GroupTile extends ConsumerWidget {
  final Group group;
  final VoidCallback onTap;

  const _GroupTile({required this.group, required this.onTap});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final unreadCounts = ref.watch(groupUnreadCountsProvider);
    final unreadCount = unreadCounts.maybeWhen(
      data: (counts) => counts[group.uuid] ?? 0,
      orElse: () => 0,
    );

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: theme.colorScheme.secondary.withAlpha(51),
        child: FaIcon(
          FontAwesomeIcons.users,
          color: theme.colorScheme.secondary,
        ),
      ),
      title: Text(
        group.name,
        style: unreadCount > 0
            ? const TextStyle(fontWeight: FontWeight.bold)
            : null,
      ),
      subtitle: Text('${group.memberCount} members'),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (unreadCount > 0)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: theme.colorScheme.primary,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                unreadCount > 99 ? '99+' : unreadCount.toString(),
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          const SizedBox(width: 4),
          const FaIcon(FontAwesomeIcons.chevronRight),
        ],
      ),
      onTap: onTap,
    );
  }
}

class _InvitationTile extends StatefulWidget {
  final Invitation invitation;
  final Future<void> Function() onAccept;
  final Future<void> Function() onDecline;

  const _InvitationTile({
    required this.invitation,
    required this.onAccept,
    required this.onDecline,
  });

  @override
  State<_InvitationTile> createState() => _InvitationTileState();
}

class _InvitationTileState extends State<_InvitationTile> {
  bool _isAccepting = false;
  bool _isDeclining = false;

  bool get _isLoading => _isAccepting || _isDeclining;

  Future<void> _handleAccept() async {
    setState(() => _isAccepting = true);
    try {
      await widget.onAccept();
    } finally {
      if (mounted) {
        setState(() => _isAccepting = false);
      }
    }
  }

  Future<void> _handleDecline() async {
    setState(() => _isDeclining = true);
    try {
      await widget.onDecline();
    } finally {
      if (mounted) {
        setState(() => _isDeclining = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  backgroundColor: theme.colorScheme.primary.withAlpha(51),
                  child: FaIcon(
                    FontAwesomeIcons.envelope,
                    color: theme.colorScheme.primary,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        widget.invitation.groupName,
                        style: theme.textTheme.titleMedium,
                      ),
                      Text(
                        'Invited by ${_shortenFingerprint(widget.invitation.inviter)}',
                        style: theme.textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: _isLoading ? null : _handleDecline,
                  child: _isDeclining
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('Decline'),
                ),
                const SizedBox(width: 8),
                ElevatedButton(
                  onPressed: _isLoading ? null : _handleAccept,
                  child: _isAccepting
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Text('Accept'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }
}

class _CreateGroupDialog extends ConsumerStatefulWidget {
  final WidgetRef ref;

  const _CreateGroupDialog({required this.ref});

  @override
  ConsumerState<_CreateGroupDialog> createState() => _CreateGroupDialogState();
}

class _CreateGroupDialogState extends ConsumerState<_CreateGroupDialog> {
  final _controller = TextEditingController();
  bool _isCreating = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Create Group'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('Enter a name for your new group'),
          const SizedBox(height: 16),
          TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'Group Name',
              hintText: 'My Awesome Group',
            ),
            autofocus: true,
            onChanged: (_) => setState(() {}),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: _isCreating ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _isCreating || _controller.text.trim().isEmpty
              ? null
              : _createGroup,
          child: _isCreating
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Create'),
        ),
      ],
    );
  }

  Future<void> _createGroup() async {
    setState(() => _isCreating = true);

    try {
      await ref.read(groupsProvider.notifier).createGroup(
        _controller.text.trim(),
        [], // Empty members list - can add members later
      );
      if (mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Group "${_controller.text.trim()}" created')),
        );
      }
    } catch (e) {
      setState(() => _isCreating = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to create group: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }
}

/// Group Chat Screen - Chat within a group
class GroupChatScreen extends ConsumerStatefulWidget {
  final Group group;

  const GroupChatScreen({super.key, required this.group});

  @override
  ConsumerState<GroupChatScreen> createState() => _GroupChatScreenState();
}

class _GroupChatScreenState extends ConsumerState<GroupChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();
  bool _isSending = false;

  @override
  void initState() {
    super.initState();
    // Mark this group chat as open (prevents unread count increment while viewing)
    // IMPORTANT: Check mounted to avoid race condition with dispose()
    Future.microtask(() {
      if (!mounted) return;  // Widget disposed before microtask ran
      ref.read(openGroupUuidProvider.notifier).state = widget.group.uuid;
    });
    // Async GEK sync - fire and forget (don't block UI)
    // This ensures we have the latest GEK from DHT for decrypting new messages
    _syncGekInBackground();
  }

  /// Sync GEK from DHT in background (non-blocking)
  /// If a newer GEK is found, refreshes the conversation to re-decrypt messages
  Future<void> _syncGekInBackground() async {
    try {
      final engine = await ref.read(engineProvider.future);
      await engine.syncGroupByUuid(widget.group.uuid);
      // Refresh conversation in case new messages can now be decrypted
      if (mounted) {
        ref.invalidate(groupConversationProvider(widget.group.uuid));
      }
    } catch (e) {
      // Non-fatal - GEK sync failure shouldn't block the chat
      // Old messages still visible with cached GEK
    }
  }

  @override
  void dispose() {
    // Mark group chat as closed
    try {
      ref.read(openGroupUuidProvider.notifier).state = null;
    } catch (_) {
      // Widget already fully disposed, state cleanup not needed
    }
    _messageController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            CircleAvatar(
              radius: 18,
              backgroundColor: theme.colorScheme.secondary.withAlpha(51),
              child: FaIcon(
                FontAwesomeIcons.users,
                size: 16,
                color: theme.colorScheme.secondary,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    widget.group.name,
                    style: theme.textTheme.titleMedium,
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                  ),
                  Text(
                    '${widget.group.memberCount} members',
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.circleInfo),
            onPressed: () => _showGroupInfo(context),
            tooltip: 'Group Info',
          ),
        ],
      ),
      body: Column(
        children: [
          // Group message history
          Expanded(
            child: _buildMessageList(theme),
          ),

          // Message input
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              border: Border(
                top: BorderSide(
                  color: theme.colorScheme.primary.withAlpha(51),
                ),
              ),
            ),
            child: SafeArea(
              top: false,
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _messageController,
                      decoration: InputDecoration(
                        hintText: 'Type a message...',
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: BorderSide.none,
                        ),
                        filled: true,
                        fillColor: theme.scaffoldBackgroundColor,
                        contentPadding: const EdgeInsets.symmetric(
                          horizontal: 16,
                          vertical: 8,
                        ),
                      ),
                      minLines: 1,
                      maxLines: 5,
                      textInputAction: TextInputAction.send,
                      onSubmitted: (_) => _sendMessage(),
                      onChanged: (_) => setState(() {}),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Builder(
                    builder: (context) {
                      final hasText = _messageController.text.trim().isNotEmpty;
                      final canSend = hasText && !_isSending;
                      return Material(
                        color: canSend
                            ? theme.colorScheme.primary
                            : theme.colorScheme.onSurface.withAlpha(30),
                        shape: const CircleBorder(),
                        child: InkWell(
                          onTap: canSend ? _sendMessage : null,
                          customBorder: const CircleBorder(),
                          child: SizedBox(
                            width: 44,
                            height: 44,
                            child: Center(
                              child: _isSending
                                  ? SizedBox(
                                      width: 18,
                                      height: 18,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: theme.colorScheme.onSurface.withAlpha(100),
                                      ),
                                    )
                                  : FaIcon(
                                      FontAwesomeIcons.solidPaperPlane,
                                      size: 18,
                                      color: canSend
                                          ? theme.colorScheme.onPrimary
                                          : theme.colorScheme.onSurface.withAlpha(100),
                                    ),
                            ),
                          ),
                        ),
                      );
                    },
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMessageList(ThemeData theme) {
    // Watch refresh trigger to force rebuild when new messages arrive via listener
    ref.watch(groupConversationRefreshTriggerProvider);
    final conversation = ref.watch(groupConversationProvider(widget.group.uuid));

    return conversation.when(
      data: (messages) {
        if (messages.isEmpty) {
          return Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                FaIcon(
                  FontAwesomeIcons.comments,
                  size: 64,
                  color: theme.colorScheme.primary.withAlpha(128),
                ),
                const SizedBox(height: 16),
                Text(
                  'No messages yet',
                  style: theme.textTheme.titleMedium,
                ),
                const SizedBox(height: 8),
                Text(
                  'Send a message to start the conversation',
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
          );
        }

        // Scroll to bottom when new messages arrive
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_scrollController.hasClients) {
            _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
          }
        });

        return ListView.builder(
          controller: _scrollController,
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
          itemCount: messages.length,
          itemBuilder: (context, index) {
            final message = messages[index];
            return _GroupMessageBubble(
              message: message,
              theme: theme,
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
            Text(
              'Failed to load messages',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            TextButton.icon(
              onPressed: () => ref.invalidate(groupConversationProvider(widget.group.uuid)),
              icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 16),
              label: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _sendMessage() async {
    final message = _messageController.text.trim();
    if (message.isEmpty) return;

    setState(() => _isSending = true);
    _messageController.clear();

    try {
      await ref.read(groupsProvider.notifier).sendGroupMessage(
        widget.group.uuid,
        message,
      );
      // Refresh conversation to show the sent message
      ref.invalidate(groupConversationProvider(widget.group.uuid));
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to send message: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSending = false);
      }
    }
  }

  void _showGroupInfo(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => _GroupInfoDialog(groupUuid: widget.group.uuid),
    );
  }
}

/// Dialog showing detailed group information
class _GroupInfoDialog extends ConsumerStatefulWidget {
  final String groupUuid;

  const _GroupInfoDialog({required this.groupUuid});

  @override
  ConsumerState<_GroupInfoDialog> createState() => _GroupInfoDialogState();
}

class _GroupInfoDialogState extends ConsumerState<_GroupInfoDialog> {
  GroupInfo? _groupInfo;
  List<GroupMember>? _members;
  bool _isLoading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadGroupInfo();
  }

  Future<void> _loadGroupInfo() async {
    try {
      final engine = await ref.read(engineProvider.future);

      // Fetch both info and members in parallel
      final results = await Future.wait([
        engine.getGroupInfo(widget.groupUuid),
        engine.getGroupMembers(widget.groupUuid),
      ]);

      if (mounted) {
        setState(() {
          _groupInfo = results[0] as GroupInfo;
          _members = results[1] as List<GroupMember>;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(
            FontAwesomeIcons.circleInfo,
            size: 20,
            color: theme.colorScheme.primary,
          ),
          const SizedBox(width: 12),
          const Text('Group Info'),
        ],
      ),
      content: _isLoading
          ? const SizedBox(
              height: 100,
              child: Center(child: CircularProgressIndicator()),
            )
          : _error != null
              ? _buildError(theme)
              : _buildContent(theme),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }

  Widget _buildError(ThemeData theme) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        FaIcon(
          FontAwesomeIcons.triangleExclamation,
          size: 48,
          color: theme.colorScheme.error,
        ),
        const SizedBox(height: 16),
        Text(
          'Failed to load group info',
          style: theme.textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        Text(
          _error!,
          style: theme.textTheme.bodySmall,
          textAlign: TextAlign.center,
        ),
      ],
    );
  }

  Widget _buildContent(ThemeData theme) {
    final info = _groupInfo!;
    final members = _members ?? [];
    final contacts = ref.watch(contactsProvider).valueOrNull ?? [];

    // Format creation date
    final createdStr =
        '${info.createdAt.year}-${info.createdAt.month.toString().padLeft(2, '0')}-${info.createdAt.day.toString().padLeft(2, '0')}';

    // Format GEK version as date (gekVersion is Unix timestamp in seconds)
    String gekUpdateStr = 'Never';
    if (info.gekVersion > 0) {
      final gekDate = DateTime.fromMillisecondsSinceEpoch(info.gekVersion * 1000);
      gekUpdateStr =
          '${gekDate.year}-${gekDate.month.toString().padLeft(2, '0')}-${gekDate.day.toString().padLeft(2, '0')} '
          '${gekDate.hour.toString().padLeft(2, '0')}:${gekDate.minute.toString().padLeft(2, '0')}';
    }

    return SingleChildScrollView(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Group name
          _InfoRow(
            icon: FontAwesomeIcons.users,
            label: 'Name',
            value: info.name,
          ),
          const Divider(height: 24),

          // UUID
          _InfoRow(
            icon: FontAwesomeIcons.fingerprint,
            label: 'UUID',
            value: info.uuid,
            isMonospace: true,
          ),
          const Divider(height: 24),

          // Last Key Update (GEK version is timestamp-based)
          _InfoRow(
            icon: FontAwesomeIcons.key,
            label: 'Last Key Update',
            value: gekUpdateStr,
          ),
          const Divider(height: 24),

          // Member count
          _InfoRow(
            icon: FontAwesomeIcons.userGroup,
            label: 'Members',
            value: '${info.memberCount}',
          ),
          const Divider(height: 24),

          // Created at
          _InfoRow(
            icon: FontAwesomeIcons.calendar,
            label: 'Created',
            value: createdStr,
          ),
          const Divider(height: 24),

          // Role
          _InfoRow(
            icon: info.isOwner ? FontAwesomeIcons.crown : FontAwesomeIcons.user,
            label: 'Your Role',
            value: info.isOwner ? 'Owner' : 'Member',
            valueColor: info.isOwner ? DnaColors.textInfo : null,
          ),

          // Members section
          if (members.isNotEmpty) ...[
            const SizedBox(height: 24),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Members',
                  style: theme.textTheme.titleSmall?.copyWith(
                    color: theme.colorScheme.primary,
                  ),
                ),
                // Add member button (owner only)
                if (info.isOwner)
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.plus, size: 14),
                    tooltip: 'Add Member',
                    onPressed: () => _showAddMemberDialog(context, contacts, members),
                    visualDensity: VisualDensity.compact,
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            ...members.map((member) {
              // Look up contact name
              final contact = contacts
                  .where((c) => c.fingerprint == member.fingerprint)
                  .firstOrNull;
              final displayName = contact?.displayName.isNotEmpty == true
                  ? contact!.displayName
                  : _shortenFingerprint(member.fingerprint);

              return Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Row(
                  children: [
                    FaIcon(
                      member.isOwner
                          ? FontAwesomeIcons.crown
                          : FontAwesomeIcons.user,
                      size: 14,
                      color: member.isOwner
                          ? DnaColors.textInfo
                          : theme.colorScheme.onSurface.withAlpha(179),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        displayName,
                        style: theme.textTheme.bodyMedium,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (member.isOwner)
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: DnaColors.textInfo.withAlpha(26),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          'Owner',
                          style: theme.textTheme.labelSmall?.copyWith(
                            color: DnaColors.textInfo,
                          ),
                        ),
                      ),
                    // Remove button (owner can remove non-owners)
                    if (info.isOwner && !member.isOwner)
                      IconButton(
                        icon: FaIcon(
                          FontAwesomeIcons.xmark,
                          size: 12,
                          color: theme.colorScheme.error,
                        ),
                        tooltip: 'Remove Member',
                        onPressed: () => _showRemoveMemberDialog(context, member, displayName),
                        visualDensity: VisualDensity.compact,
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                      ),
                  ],
                ),
              );
            }),
          ],
        ],
      ),
    );
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }

  /// Show dialog to add a member from contacts
  void _showAddMemberDialog(
    BuildContext context,
    List<Contact> contacts,
    List<GroupMember> currentMembers,
  ) {
    // Filter to contacts not already in the group
    final memberFingerprints = currentMembers.map((m) => m.fingerprint).toSet();
    final availableContacts = contacts
        .where((c) => !memberFingerprints.contains(c.fingerprint))
        .toList();

    if (availableContacts.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('All your contacts are already members of this group'),
        ),
      );
      return;
    }

    showDialog(
      context: context,
      builder: (ctx) => _AddMemberDialog(
        groupUuid: widget.groupUuid,
        availableContacts: availableContacts,
        onMemberAdded: () {
          _loadGroupInfo();  // Refresh member list
        },
      ),
    );
  }

  /// Show confirmation dialog to remove a member
  void _showRemoveMemberDialog(
    BuildContext context,
    GroupMember member,
    String displayName,
  ) {
    showDialog(
      context: context,
      builder: (ctx) => _RemoveMemberDialog(
        groupUuid: widget.groupUuid,
        memberFingerprint: member.fingerprint,
        memberDisplayName: displayName,
        onMemberRemoved: () {
          _loadGroupInfo();  // Refresh member list
        },
      ),
    );
  }
}

/// Dialog to add a member to the group
class _AddMemberDialog extends ConsumerStatefulWidget {
  final String groupUuid;
  final List<Contact> availableContacts;
  final VoidCallback onMemberAdded;

  const _AddMemberDialog({
    required this.groupUuid,
    required this.availableContacts,
    required this.onMemberAdded,
  });

  @override
  ConsumerState<_AddMemberDialog> createState() => _AddMemberDialogState();
}

class _AddMemberDialogState extends ConsumerState<_AddMemberDialog> {
  String? _selectedFingerprint;
  bool _isLoading = false;
  String? _error;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(
            FontAwesomeIcons.userPlus,
            size: 20,
            color: theme.colorScheme.primary,
          ),
          const SizedBox(width: 12),
          const Text('Add Member'),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Select a contact to add to the group:',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 16),
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 200),
            child: SingleChildScrollView(
              child: Column(
                children: widget.availableContacts.map((contact) {
                  final isSelected = _selectedFingerprint == contact.fingerprint;
                  return ListTile(
                    dense: true,
                    leading: FaIcon(
                      FontAwesomeIcons.user,
                      size: 16,
                      color: isSelected
                          ? theme.colorScheme.primary
                          : theme.colorScheme.onSurface.withAlpha(179),
                    ),
                    title: Text(
                      contact.displayName.isNotEmpty
                          ? contact.displayName
                          : contact.fingerprint.substring(0, 16),
                      overflow: TextOverflow.ellipsis,
                    ),
                    selected: isSelected,
                    onTap: () {
                      setState(() {
                        _selectedFingerprint = contact.fingerprint;
                        _error = null;
                      });
                    },
                  );
                }).toList(),
              ),
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(
              _error!,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
          ],
        ],
      ),
      actions: [
        TextButton(
          onPressed: _isLoading ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        TextButton(
          onPressed: _isLoading || _selectedFingerprint == null
              ? null
              : _addMember,
          child: _isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Add'),
        ),
      ],
    );
  }

  Future<void> _addMember() async {
    if (_selectedFingerprint == null) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await ref.read(groupsProvider.notifier).addGroupMember(
            widget.groupUuid,
            _selectedFingerprint!,
          );

      if (mounted) {
        Navigator.of(context).pop();
        widget.onMemberAdded();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _error = e.toString();
        });
      }
    }
  }
}

/// Dialog to confirm removing a member from the group
class _RemoveMemberDialog extends ConsumerStatefulWidget {
  final String groupUuid;
  final String memberFingerprint;
  final String memberDisplayName;
  final VoidCallback onMemberRemoved;

  const _RemoveMemberDialog({
    required this.groupUuid,
    required this.memberFingerprint,
    required this.memberDisplayName,
    required this.onMemberRemoved,
  });

  @override
  ConsumerState<_RemoveMemberDialog> createState() => _RemoveMemberDialogState();
}

class _RemoveMemberDialogState extends ConsumerState<_RemoveMemberDialog> {
  bool _isLoading = false;
  String? _error;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(
            FontAwesomeIcons.userMinus,
            size: 20,
            color: theme.colorScheme.error,
          ),
          const SizedBox(width: 12),
          const Text('Remove Member'),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Are you sure you want to remove ${widget.memberDisplayName} from this group?',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'The group encryption key will be rotated for forward secrecy.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withAlpha(153),
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(
              _error!,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
          ],
        ],
      ),
      actions: [
        TextButton(
          onPressed: _isLoading ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        TextButton(
          onPressed: _isLoading ? null : _removeMember,
          style: TextButton.styleFrom(
            foregroundColor: theme.colorScheme.error,
          ),
          child: _isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Remove'),
        ),
      ],
    );
  }

  Future<void> _removeMember() async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await ref.read(groupsProvider.notifier).removeGroupMember(
            widget.groupUuid,
            widget.memberFingerprint,
          );

      if (mounted) {
        Navigator.of(context).pop();
        widget.onMemberRemoved();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _error = e.toString();
        });
      }
    }
  }
}

/// Info row widget for displaying key-value pairs
class _InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final bool isMonospace;
  final Color? valueColor;

  const _InfoRow({
    required this.icon,
    required this.label,
    required this.value,
    this.isMonospace = false,
    this.valueColor,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FaIcon(
          icon,
          size: 16,
          color: theme.colorScheme.primary.withAlpha(179),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: theme.textTheme.labelSmall?.copyWith(
                  color: theme.colorScheme.onSurface.withAlpha(153),
                ),
              ),
              const SizedBox(height: 2),
              SelectableText(
                value,
                style: theme.textTheme.bodyMedium?.copyWith(
                  fontFamily: isMonospace ? 'monospace' : null,
                  color: valueColor,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

/// Message bubble widget for group chat
class _GroupMessageBubble extends ConsumerWidget {
  final Message message;
  final ThemeData theme;

  const _GroupMessageBubble({
    required this.message,
    required this.theme,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOutgoing = message.isOutgoing;
    final alignment = isOutgoing ? Alignment.centerRight : Alignment.centerLeft;
    final bubbleColor = isOutgoing
        ? theme.colorScheme.primary
        : theme.colorScheme.surfaceContainerHighest;
    final textColor = isOutgoing
        ? theme.colorScheme.onPrimary
        : theme.colorScheme.onSurface;

    // Format timestamp
    final timestamp = message.timestamp;
    final timeStr = '${timestamp.hour.toString().padLeft(2, '0')}:${timestamp.minute.toString().padLeft(2, '0')}';

    // Convert sender fingerprint to display name if contact exists
    String senderDisplay = 'You';
    if (!isOutgoing) {
      final contacts = ref.watch(contactsProvider).valueOrNull ?? [];
      final contact = contacts.where((c) => c.fingerprint == message.sender).firstOrNull;
      senderDisplay = contact?.displayName.isNotEmpty == true
          ? contact!.displayName
          : '${message.sender.substring(0, 8)}...';
    }

    return Align(
      alignment: alignment,
      child: Container(
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.75,
        ),
        margin: const EdgeInsets.symmetric(vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: bubbleColor,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Column(
          crossAxisAlignment: isOutgoing ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            // Sender name (only for incoming messages)
            if (!isOutgoing)
              Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Text(
                  senderDisplay,
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            // Message text
            Text(
              message.plaintext,
              style: theme.textTheme.bodyMedium?.copyWith(color: textColor),
            ),
            // Timestamp
            const SizedBox(height: 4),
            Text(
              timeStr,
              style: theme.textTheme.labelSmall?.copyWith(
                color: textColor.withAlpha(179),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
