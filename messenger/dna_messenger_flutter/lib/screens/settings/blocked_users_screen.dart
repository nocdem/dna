// Blocked Users Screen - Manage blocked users list
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/contact_requests_provider.dart';
import '../../theme/dna_theme.dart';

class BlockedUsersScreen extends ConsumerWidget {
  const BlockedUsersScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final blockedUsers = ref.watch(blockedUsersProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Blocked Users'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(blockedUsersProvider),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: blockedUsers.when(
        data: (list) => _buildBlockedList(context, ref, list),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildError(context, ref, error),
      ),
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
            Icon(
              Icons.block_flipped,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No blocked users',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Users you block will appear here',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(blockedUsersProvider.notifier).refresh();
      },
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
            Icon(
              Icons.error_outline,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load blocked users',
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
    // Show confirmation dialog
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
            const SnackBar(
              content: Text('User unblocked'),
            ),
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

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length > 16) {
      return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
    }
    return fingerprint;
  }
}

class _BlockedUserTile extends StatelessWidget {
  final BlockedUser blockedUser;
  final VoidCallback onUnblock;

  const _BlockedUserTile({
    required this.blockedUser,
    required this.onUnblock,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: DnaColors.textWarning.withAlpha(51),
        child: Icon(
          Icons.block,
          color: DnaColors.textWarning,
        ),
      ),
      title: Text(
        _shortenFingerprint(blockedUser.fingerprint),
        style: const TextStyle(fontFamily: 'monospace'),
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Blocked ${_formatTime(blockedUser.blockedAt)}',
            style: theme.textTheme.bodySmall,
          ),
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
      trailing: TextButton(
        onPressed: onUnblock,
        child: const Text('Unblock'),
      ),
      isThreeLine: blockedUser.reason.isNotEmpty,
    );
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length > 16) {
      return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
    }
    return fingerprint;
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);

    if (diff.inDays > 0) {
      return '${diff.inDays}d ago';
    } else if (diff.inHours > 0) {
      return '${diff.inHours}h ago';
    } else if (diff.inMinutes > 0) {
      return '${diff.inMinutes}m ago';
    } else {
      return 'Just now';
    }
  }
}
