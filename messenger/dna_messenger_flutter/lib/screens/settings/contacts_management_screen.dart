// Contacts Management Screen - View and remove contacts
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

class ContactsManagementScreen extends ConsumerWidget {
  const ContactsManagementScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Manage Contacts'),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.read(contactsProvider.notifier).refresh(),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: contacts.when(
        data: (list) => _buildContactList(context, ref, list),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildError(context, ref, error),
      ),
    );
  }

  Widget _buildContactList(
      BuildContext context, WidgetRef ref, List<Contact> contacts) {
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
              'No contacts',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Your contacts will appear here',
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
        itemBuilder: (context, index) {
          final contact = contacts[index];
          return _ContactTile(
            contact: contact,
            onRemove: () => _removeContact(context, ref, contact),
            onCopyFingerprint: () => _copyFingerprint(context, contact),
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

  Future<void> _removeContact(
      BuildContext context, WidgetRef ref, Contact contact) async {
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
            Text(
              'Remove ${contact.displayName} from your contacts?',
            ),
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
                      style: TextStyle(
                        fontSize: 13,
                        color: DnaColors.textWarning,
                      ),
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

  void _copyFingerprint(BuildContext context, Contact contact) {
    Clipboard.setData(ClipboardData(text: contact.fingerprint));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Fingerprint copied')),
    );
  }
}

class _ContactTile extends StatelessWidget {
  final Contact contact;
  final VoidCallback onRemove;
  final VoidCallback onCopyFingerprint;

  const _ContactTile({
    required this.contact,
    required this.onRemove,
    required this.onCopyFingerprint,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: contact.isOnline
            ? DnaColors.textSuccess.withAlpha(51)
            : theme.colorScheme.primary.withAlpha(51),
        child: FaIcon(
          FontAwesomeIcons.user,
          color: contact.isOnline
              ? DnaColors.textSuccess
              : theme.colorScheme.primary,
        ),
      ),
      title: Text(contact.displayName),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            _shortenFingerprint(contact.fingerprint),
            style: theme.textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
              color: DnaColors.textMuted,
            ),
          ),
          Text(
            contact.isOnline ? 'Online' : 'Last seen ${_formatTime(contact.lastSeen)}',
            style: theme.textTheme.bodySmall?.copyWith(
              color: contact.isOnline ? DnaColors.textSuccess : DnaColors.textMuted,
            ),
          ),
        ],
      ),
      isThreeLine: true,
      trailing: PopupMenuButton<String>(
        onSelected: (value) {
          if (value == 'remove') {
            onRemove();
          } else if (value == 'copy') {
            onCopyFingerprint();
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
    );
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length > 20) {
      return '${fingerprint.substring(0, 10)}...${fingerprint.substring(fingerprint.length - 10)}';
    }
    return fingerprint;
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);

    if (time.millisecondsSinceEpoch == 0) {
      return 'Unknown';
    } else if (diff.inDays > 0) {
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
