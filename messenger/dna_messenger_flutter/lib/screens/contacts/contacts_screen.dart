// Contacts Screen - Contact list with online status
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../chat/chat_screen.dart';

class ContactsScreen extends ConsumerWidget {
  const ContactsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Contacts'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(contactsProvider),
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => _openSettings(context),
            tooltip: 'Settings',
          ),
        ],
      ),
      body: contacts.when(
        data: (list) => _buildContactList(context, ref, list),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildError(context, ref, error),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showAddContactDialog(context, ref),
        tooltip: 'Add Contact',
        child: const Icon(Icons.person_add),
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
            Icon(
              Icons.people_outline,
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
            Icon(
              Icons.error_outline,
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
              onPressed: () => ref.invalidate(contactsProvider),
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

  void _openSettings(BuildContext context) {
    // TODO: Navigate to settings screen
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Settings coming soon')),
    );
  }

  void _showAddContactDialog(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => _AddContactDialog(ref: ref),
    );
  }
}

class _ContactTile extends StatelessWidget {
  final Contact contact;
  final VoidCallback onTap;

  const _ContactTile({
    required this.contact,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      leading: Stack(
        children: [
          CircleAvatar(
            backgroundColor: theme.colorScheme.primary.withAlpha(51),
            child: Text(
              _getInitials(contact.displayName),
              style: TextStyle(
                color: theme.colorScheme.primary,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          Positioned(
            right: 0,
            bottom: 0,
            child: Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: contact.isOnline
                    ? DnaColors.textSuccess
                    : DnaColors.offline,
                border: Border.all(
                  color: theme.scaffoldBackgroundColor,
                  width: 2,
                ),
              ),
            ),
          ),
        ],
      ),
      title: Text(
        contact.displayName.isNotEmpty
            ? contact.displayName
            : _shortenFingerprint(contact.fingerprint),
      ),
      subtitle: Text(
        contact.isOnline
            ? 'Online'
            : 'Last seen ${_formatLastSeen(contact.lastSeen)}',
        style: TextStyle(
          color: contact.isOnline
              ? DnaColors.textSuccess
              : theme.textTheme.bodySmall?.color,
        ),
      ),
      trailing: const Icon(Icons.chevron_right),
      onTap: onTap,
    );
  }

  String _getInitials(String name) {
    if (name.isEmpty) return '?';
    final words = name.split(' ');
    if (words.length >= 2) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return name.substring(0, name.length.clamp(0, 2)).toUpperCase();
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }

  String _formatLastSeen(DateTime lastSeen) {
    final now = DateTime.now();
    final diff = now.difference(lastSeen);

    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return '${lastSeen.day}/${lastSeen.month}/${lastSeen.year}';
  }
}

class _AddContactDialog extends ConsumerStatefulWidget {
  final WidgetRef ref;

  const _AddContactDialog({required this.ref});

  @override
  ConsumerState<_AddContactDialog> createState() => _AddContactDialogState();
}

class _AddContactDialogState extends ConsumerState<_AddContactDialog> {
  final _controller = TextEditingController();
  bool _isAdding = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Add Contact'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text(
            'Enter a fingerprint or registered name',
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'Fingerprint or Name',
              hintText: 'Enter contact identifier',
            ),
            autofocus: true,
            onChanged: (_) => setState(() {}),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: _isAdding ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _isAdding || _controller.text.trim().isEmpty
              ? null
              : _addContact,
          child: _isAdding
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

  Future<void> _addContact() async {
    setState(() => _isAdding = true);

    try {
      await widget.ref.read(contactsProvider.notifier).addContact(
            _controller.text.trim(),
          );
      if (mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Contact added')),
        );
      }
    } catch (e) {
      setState(() => _isAdding = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to add contact: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    }
  }
}
