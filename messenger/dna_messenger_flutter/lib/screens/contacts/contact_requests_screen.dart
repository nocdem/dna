// Contact Requests Screen - ICQ-style incoming contact requests
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../providers/contact_requests_provider.dart';
import '../../theme/dna_theme.dart';

class ContactRequestsScreen extends ConsumerWidget {
  const ContactRequestsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final requests = ref.watch(contactRequestsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Contact Requests'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(contactRequestsProvider),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: requests.when(
        data: (list) => _buildRequestList(context, ref, list),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildError(context, ref, error),
      ),
    );
  }

  Widget _buildRequestList(
      BuildContext context, WidgetRef ref, List<ContactRequest> requests) {
    final theme = Theme.of(context);

    // Filter to show only pending requests
    final pendingRequests =
        requests.where((r) => r.status == ContactRequestStatus.pending).toList();

    if (pendingRequests.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.person_add_disabled,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No pending requests',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Contact requests will appear here',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(contactRequestsProvider.notifier).refresh();
      },
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
            Icon(
              Icons.error_outline,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load requests',
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
      // Refresh contacts list since we added a new contact
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
          SnackBar(
            content: Text('Failed to approve: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
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
          SnackBar(
            content: Text('Denied ${_getDisplayName(request)}'),
          ),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to deny: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    }
  }

  Future<void> _blockUser(
      BuildContext context, WidgetRef ref, ContactRequest request) async {
    // Show confirmation dialog
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
            style: TextButton.styleFrom(
              foregroundColor: DnaColors.textWarning,
            ),
            child: const Text('Block'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        await ref.read(contactRequestsProvider.notifier).block(request.fingerprint, null);
        // Refresh blocked users list
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
            SnackBar(
              content: Text('Failed to block: $e'),
              backgroundColor: DnaColors.textWarning,
            ),
          );
        }
      }
    }
  }

  String _getDisplayName(ContactRequest request) {
    if (request.displayName.isNotEmpty) {
      return request.displayName;
    }
    return _shortenFingerprint(request.fingerprint);
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length > 16) {
      return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
    }
    return fingerprint;
  }
}

class _RequestTile extends StatelessWidget {
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
  Widget build(BuildContext context) {
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
                      Text(
                        displayName,
                        style: theme.textTheme.titleMedium,
                      ),
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
                    if (value == 'block') {
                      onBlock();
                    }
                  },
                  itemBuilder: (context) => [
                    const PopupMenuItem(
                      value: 'block',
                      child: Row(
                        children: [
                          Icon(Icons.block, color: Colors.red),
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
                child: Text(
                  request.message,
                  style: theme.textTheme.bodyMedium,
                ),
              ),
            ],
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: onDeny,
                  child: const Text('Deny'),
                ),
                const SizedBox(width: 8),
                FilledButton.icon(
                  onPressed: onApprove,
                  icon: const Icon(Icons.check),
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
    final words = name.trim().split(' ');
    if (words.length >= 2) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return name.substring(0, name.length.clamp(0, 2)).toUpperCase();
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
