// Add Contact Dialog - Search by name or fingerprint, send contact request
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../l10n/app_localizations.dart';
import '../../providers/providers.dart';

/// Show the Add Contact dialog
void showAddContactDialog(BuildContext context, WidgetRef ref) {
  showDialog(
    context: context,
    builder: (context) => AddContactDialog(ref: ref),
  );
}

class AddContactDialog extends ConsumerStatefulWidget {
  final WidgetRef ref;

  const AddContactDialog({super.key, required this.ref});

  @override
  ConsumerState<AddContactDialog> createState() => _AddContactDialogState();
}

class _AddContactDialogState extends ConsumerState<AddContactDialog> {
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
          _errorMessage = 'not_found';
        });
        return;
      }

      // Check if trying to add self
      if (fingerprint == currentFingerprint) {
        setState(() {
          _isSearching = false;
          _errorMessage = 'cannot_add_self';
        });
        return;
      }

      // Check if already in contacts
      final alreadyExists = contacts.any((c) => c.fingerprint == fingerprint);
      if (alreadyExists) {
        setState(() {
          _isSearching = false;
          _errorMessage = 'already_contact';
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
            content: Text(AppLocalizations.of(context).addContactRequestSent),
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

  String _localizedError(AppLocalizations l10n, String errorKey) {
    switch (errorKey) {
      case 'not_found':
        return l10n.addContactNotFound;
      case 'cannot_add_self':
        return l10n.addContactCannotAddSelf;
      case 'already_contact':
        return l10n.addContactAlreadyContact;
      default:
        return errorKey;
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

    final l10n = AppLocalizations.of(context);

    return AlertDialog(
      title: Text(l10n.addContactTitle),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              l10n.addContactHint,
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _controller,
              decoration: InputDecoration(
                labelText: l10n.addContactHint,
                hintText: l10n.addContactHint,
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
                      _localizedError(l10n, _errorMessage!),
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
                                l10n.addContactFoundOnNetwork,
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
          child: Text(l10n.cancel),
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
              : Text(l10n.addContactSendRequest),
        ),
      ],
    );
  }
}
