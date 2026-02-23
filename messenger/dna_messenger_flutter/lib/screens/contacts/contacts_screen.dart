// Contacts Screen - Contact list with online status
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../chat/chat_screen.dart';
import 'contact_requests_screen.dart';

class ContactsScreen extends ConsumerWidget {
  const ContactsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);

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
      body: contacts.when(
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
      ),
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
    showDialog(
      context: context,
      builder: (context) => _AddContactDialog(ref: ref),
    );
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

class _AddContactDialog extends ConsumerStatefulWidget {
  final WidgetRef ref;

  const _AddContactDialog({required this.ref});

  @override
  ConsumerState<_AddContactDialog> createState() => _AddContactDialogState();
}

class _AddContactDialogState extends ConsumerState<_AddContactDialog> {
  final _controller = TextEditingController();
  Timer? _debounceTimer;

  // Search state
  bool _isSearching = false;
  String _lastSearchedInput = '';

  // Found contact info
  String? _foundFingerprint;
  String? _foundName;
  Uint8List? _foundAvatarBytes;

  // Error state
  String? _errorMessage;

  // Adding state
  bool _isAdding = false;

  @override
  void dispose() {
    _debounceTimer?.cancel();
    _controller.dispose();
    super.dispose();
  }

  bool _isValidFingerprint(String input) {
    // Fingerprint is 128 hex characters
    if (input.length != 128) return false;
    return RegExp(r'^[0-9a-fA-F]+$').hasMatch(input);
  }

  void _onInputChanged(String value) {
    final input = value.trim().toLowerCase();

    // Cancel previous debounce timer
    _debounceTimer?.cancel();

    // Clear previous results if input changed significantly
    if (input != _lastSearchedInput) {
      setState(() {
        _foundFingerprint = null;
        _foundName = null;
        _foundAvatarBytes = null;
        _errorMessage = null;
      });
    }

    // Don't search if too short
    if (input.length < 3) {
      setState(() {
        _isSearching = false;
      });
      return;
    }

    // Debounce 500ms before searching
    _debounceTimer = Timer(const Duration(milliseconds: 500), () {
      if (input == _lastSearchedInput) return;
      _performLookup(input);
    });
  }

  Future<void> _performLookup(String input) async {
    if (!mounted) return;

    setState(() {
      _isSearching = true;
      _errorMessage = null;
      _foundFingerprint = null;
      _foundName = null;
      _foundAvatarBytes = null;
      _lastSearchedInput = input;
    });

    try {
      final engine = await widget.ref.read(engineProvider.future);
      final currentFingerprint = widget.ref.read(currentFingerprintProvider);
      final contacts = widget.ref.read(contactsProvider).valueOrNull ?? [];

      String? fingerprint;
      String? displayName;

      if (_isValidFingerprint(input)) {
        // Input is a fingerprint - lookup the name
        fingerprint = input;
        try {
          displayName = await engine.getDisplayName(input);
          if (displayName.isEmpty) displayName = null;
        } catch (_) {
          // No name registered, that's OK
        }
      } else {
        // Input is a name - lookup the fingerprint
        try {
          final fp = await engine.lookupName(input);
          if (fp.isNotEmpty) {
            fingerprint = fp;
            displayName = input;
          }
        } catch (e) {
          if (mounted) {
            setState(() {
              _isSearching = false;
              _errorMessage = 'DHT lookup failed';
            });
          }
          return;
        }
      }

      if (!mounted) return;

      // Check if found
      if (fingerprint == null || fingerprint.isEmpty) {
        setState(() {
          _isSearching = false;
          _errorMessage = 'Identity not found on DHT';
        });
        return;
      }

      // Check if trying to add self
      if (fingerprint == currentFingerprint) {
        setState(() {
          _isSearching = false;
          _errorMessage = 'You cannot add yourself as a contact';
        });
        return;
      }

      // Check if already in contacts
      final alreadyExists = contacts.any((c) => c.fingerprint == fingerprint);
      if (alreadyExists) {
        setState(() {
          _isSearching = false;
          _errorMessage = 'Contact already exists in your list';
        });
        return;
      }

      // Success - found valid contact, now fetch their profile for avatar
      // NOTE: displayName comes from getDisplayName() above, not profile (v0.6.24)
      Uint8List? avatarBytes;
      try {
        final profile = await engine.lookupProfile(fingerprint);
        if (profile != null) {
          avatarBytes = profile.decodeAvatar();
        }
      } catch (_) {
        // Profile lookup failed, continue without avatar
      }

      if (!mounted) return;

      setState(() {
        _isSearching = false;
        _foundFingerprint = fingerprint;
        _foundName = displayName;
        _foundAvatarBytes = avatarBytes;
      });

    } catch (e) {
      if (mounted) {
        setState(() {
          _isSearching = false;
          _errorMessage = 'Lookup failed: $e';
        });
      }
    }
  }

  Future<void> _addContact() async {
    if (_foundFingerprint == null) return;

    setState(() => _isAdding = true);

    try {
      // Send contact request instead of direct add
      await widget.ref.read(contactRequestsProvider.notifier).sendRequest(
            _foundFingerprint!,
            null, // No message for now
          );
      if (mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Contact request sent to ${_foundName ?? 'user'}'),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      }
    } catch (e) {
      setState(() => _isAdding = false);
      if (mounted) {
        setState(() {
          _errorMessage = 'Failed to send request: $e';
        });
      }
    }
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 20) return fp;
    return '${fp.substring(0, 10)}...${fp.substring(fp.length - 10)}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final inputLength = _controller.text.trim().length;

    return AlertDialog(
      title: const Text('Add Contact'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Enter a fingerprint or registered name',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _controller,
              decoration: InputDecoration(
                labelText: 'Fingerprint or Name',
                hintText: 'Enter contact identifier',
                suffixIcon: _isSearching
                    ? const Padding(
                        padding: EdgeInsets.all(12),
                        child: SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                      )
                    : _foundFingerprint != null
                        ? FaIcon(FontAwesomeIcons.circleCheck, color: DnaColors.success)
                        : null,
              ),
              autofocus: true,
              onChanged: _onInputChanged,
              enabled: !_isAdding,
            ),
            const SizedBox(height: 8),

            // Hint for minimum characters
            if (inputLength > 0 && inputLength < 3)
              Text(
                'Type at least 3 characters to search',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.textTheme.bodySmall?.color,
                ),
              ),

            // Error message
            if (_errorMessage != null) ...[
              const SizedBox(height: 8),
              Row(
                children: [
                  FaIcon(FontAwesomeIcons.circleExclamation,
                       color: DnaColors.warning, size: 16),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      _errorMessage!,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: DnaColors.warning,
                      ),
                    ),
                  ),
                ],
              ),
            ],

            // Found contact preview
            if (_foundFingerprint != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surface,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: DnaColors.success.withAlpha(128),
                  ),
                ),
                child: Row(
                  children: [
                    DnaAvatar(
                      imageBytes: _foundAvatarBytes,
                      name: _foundName ?? '?',
                      size: DnaAvatarSize.md,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              FaIcon(FontAwesomeIcons.circleCheck,
                                   color: DnaColors.success, size: 14),
                              const SizedBox(width: 4),
                              Text(
                                'Found on DHT',
                                style: theme.textTheme.labelSmall?.copyWith(
                                  color: DnaColors.success,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          if (_foundName != null)
                            Text(
                              _foundName!,
                              style: theme.textTheme.titleMedium,
                            ),
                          Text(
                            _shortenFingerprint(_foundFingerprint!),
                            style: theme.textTheme.bodySmall?.copyWith(
                              fontFamily: 'monospace',
                              color: theme.textTheme.bodySmall?.color,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _isAdding ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _isAdding || _foundFingerprint == null
              ? null
              : _addContact,
          child: _isAdding
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Send Request'),
        ),
      ],
    );
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
