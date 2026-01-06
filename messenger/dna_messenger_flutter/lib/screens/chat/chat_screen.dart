// Chat Screen - Conversation with message bubbles
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import 'package:emoji_picker_flutter/emoji_picker_flutter.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../../widgets/emoji_shortcode_field.dart';
import '../../widgets/formatted_text.dart';
import 'contact_profile_dialog.dart';

class ChatScreen extends ConsumerStatefulWidget {
  const ChatScreen({super.key});

  @override
  ConsumerState<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends ConsumerState<ChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();
  final _focusNode = FocusNode();
  bool _showEmojiPicker = false;
  bool _isCheckingOffline = false;
  bool _justInsertedEmoji = false;
  bool _hasText = false; // Track empty/non-empty to minimize rebuilds

  @override
  void initState() {
    super.initState();
    // Listen to text changes to update send button state
    _messageController.addListener(_onTextChanged);

    // Mark messages as read when chat opens
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _markMessagesAsRead();
    });
  }

  Future<void> _markMessagesAsRead() async {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;

    try {
      final engine = await ref.read(engineProvider.future);
      await engine.markConversationRead(contact.fingerprint);
      // Clear unread count in the provider
      ref.read(unreadCountsProvider.notifier).clearCount(contact.fingerprint);
    } catch (e) {
      debugPrint('[CHAT] Failed to mark messages as read: $e');
    }

    // Refresh contact profile in background (for latest avatar/name)
    ref.read(contactProfileCacheProvider.notifier).refreshProfile(contact.fingerprint);

    // Auto-check offline messages when chat opens (silent, no snackbar)
    _checkOfflineMessagesSilent();
  }

  /// Check offline messages silently (no UI feedback)
  /// Called automatically when chat opens
  Future<void> _checkOfflineMessagesSilent() async {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;

    try {
      final engine = await ref.read(engineProvider.future);
      debugPrint('[CHAT] Auto-checking offline messages for ${contact.fingerprint.substring(0, 16)}...');
      await engine.checkOfflineMessages();

      // Refresh conversation to show any new messages
      if (mounted) {
        ref.invalidate(conversationProvider(contact.fingerprint));
      }
    } catch (e) {
      debugPrint('[CHAT] Silent offline check failed: $e');
    }
  }

  @override
  void dispose() {
    _messageController.removeListener(_onTextChanged);
    _messageController.dispose();
    _scrollController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _onTextChanged() {
    // Close emoji picker when user types (but not when emoji was just inserted)
    final shouldCloseEmoji = _showEmojiPicker && !_justInsertedEmoji;
    _justInsertedEmoji = false;

    // Only rebuild when empty<->non-empty changes (for send button state)
    final hasTextNow = _messageController.text.trim().isNotEmpty;
    if (hasTextNow != _hasText || shouldCloseEmoji) {
      setState(() {
        _hasText = hasTextNow;
        if (shouldCloseEmoji) _showEmojiPicker = false;
      });
    }
  }

  Future<void> _checkOfflineMessages() async {
    if (_isCheckingOffline) return;

    setState(() => _isCheckingOffline = true);
    debugPrint('[OFFLINE_CHECK] Starting offline message check...');

    try {
      final engineAsync = ref.read(engineProvider);
      await engineAsync.when(
        data: (engine) async {
          debugPrint('[OFFLINE_CHECK] Engine ready, calling checkOfflineMessages()');
          final startTime = DateTime.now();
          await engine.checkOfflineMessages();
          final elapsed = DateTime.now().difference(startTime);
          debugPrint('[OFFLINE_CHECK] Check completed in ${elapsed.inMilliseconds}ms');

          // Refresh conversation to show any new messages
          final contact = ref.read(selectedContactProvider);
          if (contact != null) {
            debugPrint('[OFFLINE_CHECK] Refreshing conversation for ${contact.fingerprint.substring(0, 16)}...');
            ref.invalidate(conversationProvider(contact.fingerprint));
          }

          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Offline check complete (${elapsed.inMilliseconds}ms)'),
                backgroundColor: DnaColors.snackbarSuccess,
                duration: const Duration(seconds: 2),
              ),
            );
          }
        },
        loading: () {
          debugPrint('[OFFLINE_CHECK] Engine still loading...');
        },
        error: (e, st) {
          debugPrint('[OFFLINE_CHECK] Engine error: $e');
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Engine error: $e'),
                backgroundColor: DnaColors.snackbarError,
              ),
            );
          }
        },
      );
    } catch (e, st) {
      debugPrint('[OFFLINE_CHECK] Exception: $e\n$st');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Check failed: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isCheckingOffline = false);
        debugPrint('[OFFLINE_CHECK] Check finished');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final contact = ref.watch(selectedContactProvider);
    final messages = ref.watch(currentConversationProvider);
    final theme = Theme.of(context);

    if (contact == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Chat')),
        body: const Center(
          child: Text('No contact selected'),
        ),
      );
    }

    // Get cached profile for display name fallback
    final profileCache = ref.watch(contactProfileCacheProvider);
    final cachedProfile = profileCache[contact.fingerprint];

    // Use cached display name if contact.displayName is empty (fallback chain)
    final displayName = contact.displayName.isNotEmpty
        ? contact.displayName
        : (cachedProfile?.displayName.isNotEmpty == true
            ? cachedProfile!.displayName
            : _shortenFingerprint(contact.fingerprint));

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            _ContactAvatar(contact: contact),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    displayName,
                    style: theme.textTheme.titleMedium,
                  ),
                  Text(
                    contact.isOnline
                        ? 'Online'
                        : 'Last seen ${_formatLastSeen(contact.lastSeen)}',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: contact.isOnline
                          ? DnaColors.textSuccess
                          : theme.textTheme.bodySmall?.color,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          // Send CPUNK button
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.moneyBillTransfer),
            tooltip: 'Send CPUNK',
            onPressed: () => _showSendCpunk(context, contact),
          ),
          // Check offline messages button
          IconButton(
            icon: _isCheckingOffline
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const FaIcon(FontAwesomeIcons.cloudArrowDown),
            tooltip: 'Check offline messages',
            onPressed: _isCheckingOffline ? null : _checkOfflineMessages,
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.ellipsisVertical),
            onPressed: () => _showContactOptions(context),
          ),
        ],
      ),
      body: Stack(
        children: [
          // Main content column
          Column(
            children: [
              // Messages list
              Expanded(
                child: messages.when(
                  data: (list) => _buildMessageList(context, list),
                  loading: () => const Center(child: CircularProgressIndicator()),
                  error: (error, stack) => Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        FaIcon(FontAwesomeIcons.circleExclamation, color: DnaColors.textWarning),
                        const SizedBox(height: 8),
                        Text('Failed to load messages'),
                        TextButton(
                          onPressed: () => ref.invalidate(
                            conversationProvider(contact.fingerprint),
                          ),
                          child: const Text('Retry'),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
              // Input area
              _buildInputArea(context, contact),
            ],
          ),

          // Floating emoji picker (bottom-left, above input area)
          if (_showEmojiPicker)
            Positioned(
              left: 8,
              bottom: 70,
              child: Material(
                elevation: 8,
                borderRadius: BorderRadius.circular(12),
                color: theme.colorScheme.surface,
                child: Container(
                  width: 360,
                  height: 280,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: DnaColors.border),
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(12),
                    child: Padding(
                      padding: const EdgeInsets.all(8),
                      child: EmojiPicker(
                        onEmojiSelected: (category, emoji) {
                          _onEmojiSelected(emoji);
                        },
                        config: Config(
                          checkPlatformCompatibility: true,
                          emojiViewConfig: EmojiViewConfig(
                            columns: 8,
                            emojiSizeMax: 28,
                            backgroundColor: theme.colorScheme.surface,
                          ),
                          categoryViewConfig: CategoryViewConfig(
                            indicatorColor: theme.colorScheme.primary,
                            iconColorSelected: theme.colorScheme.primary,
                            iconColor: DnaColors.textMuted,
                            backgroundColor: theme.colorScheme.surface,
                          ),
                          bottomActionBarConfig: BottomActionBarConfig(
                            backgroundColor: theme.colorScheme.surface,
                            buttonColor: theme.colorScheme.primary,
                          ),
                          searchViewConfig: SearchViewConfig(
                            backgroundColor: theme.colorScheme.surface,
                            buttonIconColor: theme.colorScheme.primary,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildMessageList(BuildContext context, List<Message> messages) {
    if (messages.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.comment,
              size: 48,
              color: Theme.of(context).colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No messages yet',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Send a message to start the conversation',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      controller: _scrollController,
      reverse: true,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      itemCount: messages.length,
      itemBuilder: (context, index) {
        // Reverse index since list is reversed
        final message = messages[messages.length - 1 - index];
        final prevMessage = index < messages.length - 1
            ? messages[messages.length - 2 - index]
            : null;

        final showDate = prevMessage == null ||
            !_isSameDay(message.timestamp, prevMessage.timestamp);

        return Column(
          children: [
            if (showDate) _buildDateHeader(context, message.timestamp),
            _MessageBubble(message: message),
          ],
        );
      },
    );
  }

  Widget _buildDateHeader(BuildContext context, DateTime date) {
    final theme = Theme.of(context);
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final messageDate = DateTime(date.year, date.month, date.day);

    String text;
    if (messageDate == today) {
      text = 'Today';
    } else if (messageDate == today.subtract(const Duration(days: 1))) {
      text = 'Yesterday';
    } else {
      text = DateFormat('MMMM d, y').format(date);
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Center(
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Text(
            text,
            style: theme.textTheme.bodySmall,
          ),
        ),
      ),
    );
  }

  Widget _buildInputArea(BuildContext context, Contact contact) {
    final theme = Theme.of(context);
    final dhtState = ref.watch(dhtConnectionStateProvider);
    final isConnected = dhtState == DhtConnectionState.connected;
    final isConnecting = dhtState == DhtConnectionState.connecting;

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // DHT Status Banner - shows when not connected
        if (!isConnected)
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            color: isConnecting
                ? DnaColors.textWarning.withAlpha(30)
                : DnaColors.textError.withAlpha(30),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                if (isConnecting) ...[
                  SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: DnaColors.textWarning,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Connecting to network...',
                    style: TextStyle(
                      color: DnaColors.textWarning,
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ] else ...[
                  FaIcon(
                    FontAwesomeIcons.cloudBolt,
                    size: 14,
                    color: DnaColors.textError,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Disconnected - messages will queue',
                    style: TextStyle(
                      color: DnaColors.textError,
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ],
            ),
          ),
        // Input area
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
            // Emoji button
            IconButton(
              icon: FaIcon(
                _showEmojiPicker
                    ? FontAwesomeIcons.keyboard
                    : FontAwesomeIcons.faceSmile,
              ),
              onPressed: () {
                setState(() {
                  _showEmojiPicker = !_showEmojiPicker;
                });
                if (!_showEmojiPicker) {
                  _focusNode.requestFocus();
                }
              },
            ),

            // Text input with :shortcode: support
            Expanded(
              child: EmojiShortcodeField(
                controller: _messageController,
                focusNode: _focusNode,
                autofocus: true,
                hintText: 'Type a message...',
                minLines: 1,
                maxLines: 5,
                onEnterPressed: () {
                  if (_hasText) {
                    _sendMessage(contact);
                  }
                },
                // Note: onChanged not needed - _messageController.addListener handles state
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
                onTap: () {
                  // Hide emoji picker when text field is tapped
                  if (_showEmojiPicker) {
                    setState(() => _showEmojiPicker = false);
                  }
                },
              ),
            ),

            const SizedBox(width: 8),

            // Send button
            IconButton(
              icon: const FaIcon(FontAwesomeIcons.paperPlane),
              onPressed: _hasText ? () => _sendMessage(contact) : null,
            ),
          ],
        ),
        ),
      ),
      ],
    );
  }

  void _sendMessage(Contact contact) {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;

    _messageController.clear();

    // Queue message for async sending (returns immediately)
    final result = ref.read(conversationProvider(contact.fingerprint).notifier)
        .sendMessage(text);

    if (result == -1) {
      // Queue full - show error and restore text
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Message queue full. Please wait and try again.'),
            backgroundColor: DnaColors.snackbarError,
            action: SnackBarAction(
              label: 'OK',
              textColor: Colors.white,
              onPressed: () {},
            ),
          ),
        );
        _messageController.text = text;
      }
    } else if (result == -2) {
      // Other error
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Failed to send message. Please try again.'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
        _messageController.text = text;
      }
    }
    // On success (result >= 0), message is already shown in UI with spinner
  }

  void _onEmojiSelected(Emoji emoji) {
    final text = _messageController.text;
    final selection = _messageController.selection;
    final newText = text.replaceRange(
      selection.start,
      selection.end,
      emoji.emoji,
    );
    // Flag to prevent closing picker when this text change fires
    _justInsertedEmoji = true;
    _messageController.value = TextEditingValue(
      text: newText,
      selection: TextSelection.collapsed(
        offset: selection.start + emoji.emoji.length,
      ),
    );
    // Keep focus on the text field after emoji insert
    _focusNode.requestFocus();
    // Note: setState not needed - listener handles _hasText updates
  }

  void _showSendCpunk(BuildContext context, Contact contact) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => _ChatSendSheet(contact: contact),
    );
  }

  void _showContactOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.user),
              title: const Text('View Profile'),
              onTap: () {
                Navigator.pop(context);
                final contact = ref.read(selectedContactProvider);
                if (contact != null) {
                  showContactProfileDialog(
                    context,
                    ref,
                    contact.fingerprint,
                    contact.displayName,
                  );
                }
              },
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.cloudArrowDown),
              title: const Text('Check Offline Messages'),
              subtitle: const Text('Fetch from DHT queue'),
              onTap: () {
                Navigator.pop(context);
                _checkOfflineMessages();
              },
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.qrcode),
              title: const Text('Show QR Code'),
              onTap: () {
                Navigator.pop(context);
                final contact = ref.read(selectedContactProvider);
                if (contact != null) {
                  _showQrCodeDialog(contact);
                }
              },
            ),
            ListTile(
              leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.textWarning),
              title: Text(
                'Remove Contact',
                style: TextStyle(color: DnaColors.textWarning),
              ),
              onTap: () {
                Navigator.pop(context);
                final contact = ref.read(selectedContactProvider);
                if (contact != null) {
                  _removeContact(contact);
                }
              },
            ),
          ],
        ),
      ),
    );
  }

  void _showQrCodeDialog(Contact contact) {
    final theme = Theme.of(context);
    final displayName = contact.displayName.isNotEmpty
        ? contact.displayName
        : '${contact.fingerprint.substring(0, 8)}...';

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            const FaIcon(FontAwesomeIcons.qrcode),
            const SizedBox(width: 8),
            Expanded(child: Text(displayName, overflow: TextOverflow.ellipsis)),
          ],
        ),
        content: SizedBox(
          width: 250,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 232,
                height: 232,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: QrImageView(
                  data: contact.fingerprint,
                  version: QrVersions.auto,
                  size: 200,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'Scan to add contact',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 8),
              Container(
                width: 250,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  contact.fingerprint,
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontFamily: 'monospace',
                    fontSize: 9,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> _removeContact(Contact contact) async {
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
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('${contact.displayName} removed'),
              backgroundColor: DnaColors.snackbarSuccess,
            ),
          );
          // Navigate back to contacts list since this chat is no longer valid
          ref.read(selectedContactProvider.notifier).state = null;
        }
      } catch (e) {
        if (mounted) {
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

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }

  bool _isSameDay(DateTime a, DateTime b) {
    return a.year == b.year && a.month == b.month && a.day == b.day;
  }

  String _formatLastSeen(DateTime lastSeen) {
    // Epoch (0) means never seen
    if (lastSeen.millisecondsSinceEpoch == 0) return 'never';

    final now = DateTime.now();
    final diff = now.difference(lastSeen);

    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return '${lastSeen.day}/${lastSeen.month}/${lastSeen.year}';
  }
}

/// Separate widget for contact avatar to prevent rebuilds on text input
class _ContactAvatar extends ConsumerWidget {
  final Contact contact;

  const _ContactAvatar({required this.contact});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    // Get cached avatar
    final profileCache = ref.watch(contactProfileCacheProvider);
    final cachedProfile = profileCache[contact.fingerprint];
    final avatarBytes = cachedProfile?.decodeAvatar();

    // Trigger fetch if not cached
    if (cachedProfile == null) {
      Future.microtask(() {
        ref.read(contactProfileCacheProvider.notifier).fetchAndCache(contact.fingerprint);
      });
    }

    Widget avatarWidget;
    if (avatarBytes != null) {
      avatarWidget = CircleAvatar(
        radius: 18,
        backgroundImage: MemoryImage(avatarBytes),
      );
    } else {
      avatarWidget = CircleAvatar(
        radius: 18,
        backgroundColor: theme.colorScheme.primary.withAlpha(51),
        child: Text(
          _getInitials(contact.displayName),
          style: TextStyle(
            color: theme.colorScheme.primary,
            fontWeight: FontWeight.bold,
            fontSize: 14,
          ),
        ),
      );
    }

    return Stack(
      children: [
        avatarWidget,
        Positioned(
          right: 0,
          bottom: 0,
          child: Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: contact.isOnline ? DnaColors.textSuccess : DnaColors.offline,
              border: Border.all(
                color: theme.scaffoldBackgroundColor,
                width: 2,
              ),
            ),
          ),
        ),
      ],
    );
  }

  String _getInitials(String name) {
    if (name.isEmpty) return '?';
    final words = name.split(' ').where((w) => w.isNotEmpty).toList();
    if (words.isEmpty) return '?';
    if (words.length >= 2) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return words[0].substring(0, words[0].length.clamp(0, 2)).toUpperCase();
  }
}

class _MessageBubble extends StatelessWidget {
  final Message message;

  const _MessageBubble({required this.message});

  /// Check if message is a CPUNK transfer by parsing JSON content
  Map<String, dynamic>? _parseTransferData() {
    try {
      final data = jsonDecode(message.plaintext) as Map<String, dynamic>;
      if (data['type'] == 'cpunk_transfer') {
        return data;
      }
    } catch (_) {
      // Not JSON or invalid format - treat as regular message
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    // Handle transfer messages with special bubble (detected by JSON tag)
    final transferData = _parseTransferData();
    if (transferData != null) {
      return _TransferBubble(message: message, transferData: transferData);
    }

    final theme = Theme.of(context);
    final isOutgoing = message.isOutgoing;

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(
          top: 4,
          bottom: 4,
          left: isOutgoing ? 48 : 0,
          right: isOutgoing ? 0 : 48,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: isOutgoing
              ? theme.colorScheme.primary
              : theme.colorScheme.surface,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 16),
          ),
        ),
        child: Column(
          crossAxisAlignment:
              isOutgoing ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            FormattedText(
              message.plaintext,
              selectable: true,
              style: TextStyle(
                color: isOutgoing
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurface,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('HH:mm').format(message.timestamp),
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontSize: 10,
                    color: isOutgoing
                        ? theme.colorScheme.onPrimary.withAlpha(179)
                        : theme.textTheme.bodySmall?.color,
                  ),
                ),
                if (isOutgoing) ...[
                  const SizedBox(width: 4),
                  _buildStatusIndicator(message.status, theme),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusIndicator(MessageStatus status, ThemeData theme) {
    final color = theme.colorScheme.onPrimary.withAlpha(179);
    const size = 16.0;

    if (status == MessageStatus.pending) {
      // Show spinner for pending messages
      return SizedBox(
        width: size,
        height: size,
        child: CircularProgressIndicator(
          strokeWidth: 1.5,
          color: color,
        ),
      );
    }

    if (status == MessageStatus.failed) {
      // Show red error icon for failed messages
      return FaIcon(
        FontAwesomeIcons.circleExclamation,
        size: size,
        color: DnaColors.textWarning,
      );
    }

    return FaIcon(
      _getStatusIcon(status),
      size: size,
      color: color,
    );
  }

  IconData _getStatusIcon(MessageStatus status) {
    switch (status) {
      case MessageStatus.pending:
        return FontAwesomeIcons.clock;
      case MessageStatus.sent:
        return FontAwesomeIcons.check;
      case MessageStatus.failed:
        return FontAwesomeIcons.circleExclamation;
      case MessageStatus.delivered:
        return FontAwesomeIcons.checkDouble;
      case MessageStatus.read:
        return FontAwesomeIcons.checkDouble; // Would be colored differently
    }
  }
}

/// Simplified send sheet for CPUNK transfers from chat
class _ChatSendSheet extends ConsumerStatefulWidget {
  final Contact contact;

  const _ChatSendSheet({required this.contact});

  @override
  ConsumerState<_ChatSendSheet> createState() => _ChatSendSheetState();
}

class _ChatSendSheetState extends ConsumerState<_ChatSendSheet> {
  final _amountController = TextEditingController();
  bool _isSending = false;
  String? _resolvedAddress;
  String? _resolveError;
  String? _sendError;  // Error message to display in dialog
  bool _isResolving = true;
  int _selectedGasSpeed = 1; // 0=slow, 1=normal, 2=fast

  // Backbone network fees (validator fee varies by speed, network fee is fixed)
  static const double _backboneNetworkFee = 0.002;
  static const double _backboneValidatorSlow = 0.0001;
  static const double _backboneValidatorNormal = 0.01;
  static const double _backboneValidatorFast = 0.05;

  @override
  void initState() {
    super.initState();
    _resolveContactWallet();
  }

  @override
  void dispose() {
    _amountController.dispose();
    super.dispose();
  }

  Future<void> _resolveContactWallet() async {
    try {
      final engine = await ref.read(engineProvider.future);
      final profile = await engine.lookupProfile(widget.contact.fingerprint);

      if (!mounted) return;

      if (profile == null || profile.backbone.isEmpty) {
        setState(() {
          _isResolving = false;
          _resolveError = 'Contact has no Backbone wallet';
        });
        return;
      }

      setState(() {
        _isResolving = false;
        _resolvedAddress = profile.backbone;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isResolving = false;
        _resolveError = 'Failed to lookup wallet address';
      });
    }
  }

  /// Get current CPUNK balance
  String? _getCpunkBalance() {
    final walletsAsync = ref.watch(walletsProvider);
    return walletsAsync.whenOrNull(
      data: (wallets) {
        if (wallets.isEmpty) return null;
        // Use first wallet (current identity's wallet)
        final balancesAsync = ref.watch(balancesProvider(0));
        return balancesAsync.whenOrNull(
          data: (balances) {
            for (final b in balances) {
              if (b.token == 'CPUNK' && b.network == 'Backbone') {
                return b.balance;
              }
            }
            return null;
          },
        );
      },
    );
  }

  /// Calculate max sendable amount (CPUNK has no fee deduction since fees are paid in CELL)
  double? _calculateMaxAmount() {
    final balanceStr = _getCpunkBalance();
    if (balanceStr == null || balanceStr.isEmpty) return null;
    final balance = double.tryParse(balanceStr);
    if (balance == null || balance <= 0) return null;
    return balance;
  }

  bool _canSend() {
    if (_isSending || _isResolving) return false;
    if (_resolvedAddress == null || _resolveError != null) return false;
    if (_amountController.text.trim().isEmpty) return false;
    final amount = double.tryParse(_amountController.text.trim());
    if (amount == null || amount <= 0) return false;
    return true;
  }

  Future<void> _send() async {
    // Clear previous error
    setState(() {
      _sendError = null;
      _isSending = true;
    });

    // Validate amount against balance before sending
    final amountStr = _amountController.text.trim();
    final amount = double.tryParse(amountStr);
    final maxAmount = _calculateMaxAmount();

    if (amount == null || amount <= 0) {
      setState(() {
        _isSending = false;
        _sendError = 'Please enter a valid amount';
      });
      return;
    }

    if (maxAmount != null && amount > maxAmount) {
      setState(() {
        _isSending = false;
        _sendError = 'Insufficient CPUNK balance';
      });
      return;
    }

    try {
      final txHash = await ref.read(walletsProvider.notifier).sendTokens(
        walletIndex: 0, // Current identity's wallet
        recipientAddress: _resolvedAddress!,
        amount: amountStr,
        token: 'CPUNK',
        network: 'Backbone',
        gasSpeed: _selectedGasSpeed,
      );

      if (mounted) {
        // Create transfer message in chat with tx hash
        final transferData = jsonEncode({
          'type': 'cpunk_transfer',
          'amount': amountStr,
          'token': 'CPUNK',
          'network': 'Backbone',
          'txHash': txHash,
          'recipientAddress': _resolvedAddress,
          'recipientName': widget.contact.displayName,
        });

        // Send the transfer message to the conversation
        ref.read(conversationProvider(widget.contact.fingerprint).notifier)
            .sendMessage(transferData);

        // Close dialog and show success
        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Sent $amountStr CPUNK'),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        // Show error in dialog - don't close
        final message = e is DnaEngineException ? e.message : e.toString();
        setState(() {
          _isSending = false;
          _sendError = message;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final balance = _getCpunkBalance();
    final maxAmount = _calculateMaxAmount();

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(16)),
      ),
      child: Padding(
        padding: EdgeInsets.only(
          left: 24,
          right: 24,
          top: 24,
          bottom: MediaQuery.of(context).viewInsets.bottom + 24,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Header
            Row(
              children: [
                const FaIcon(FontAwesomeIcons.moneyBillTransfer, size: 24),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Send CPUNK',
                        style: theme.textTheme.titleLarge,
                      ),
                      Text(
                        'to ${widget.contact.displayName.isNotEmpty ? widget.contact.displayName : "contact"}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: DnaColors.textMuted,
                        ),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.xmark),
                  onPressed: () => Navigator.pop(context),
                ),
              ],
            ),
            const SizedBox(height: 24),

            // Wallet resolution status
            if (_isResolving)
              const Center(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Column(
                    children: [
                      CircularProgressIndicator(),
                      SizedBox(height: 12),
                      Text('Looking up wallet address...'),
                    ],
                  ),
                ),
              )
            else if (_resolveError != null)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: DnaColors.textWarning.withAlpha(30),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.circleExclamation, color: DnaColors.textWarning),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        _resolveError!,
                        style: TextStyle(color: DnaColors.textWarning),
                      ),
                    ),
                  ],
                ),
              )
            else ...[
              // Resolved address indicator
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: DnaColors.textSuccess.withAlpha(20),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: DnaColors.textSuccess.withAlpha(50)),
                ),
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.circleCheck, color: DnaColors.textSuccess, size: 20),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        '${_resolvedAddress!.substring(0, 12)}...${_resolvedAddress!.substring(_resolvedAddress!.length - 8)}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),

              // Amount input
              TextField(
                controller: _amountController,
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
                decoration: InputDecoration(
                  labelText: 'Amount',
                  hintText: '0.00',
                  suffixText: 'CPUNK',
                  helperText: balance != null ? 'Available: $balance CPUNK' : null,
                ),
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 8),

              // Max button
              if (maxAmount != null && maxAmount > 0)
                Align(
                  alignment: Alignment.centerRight,
                  child: TextButton(
                    onPressed: () {
                      _amountController.text = maxAmount.toStringAsFixed(
                        maxAmount < 0.01 ? 8 : (maxAmount < 1 ? 4 : 2),
                      );
                      setState(() {});
                    },
                    child: const Text('Max'),
                  ),
                ),
              const SizedBox(height: 16),

              // Transaction speed selector
              Text(
                'Transaction Speed',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  _buildSpeedChip('Slow', _backboneValidatorSlow + _backboneNetworkFee, 0),
                  const SizedBox(width: 8),
                  _buildSpeedChip('Normal', _backboneValidatorNormal + _backboneNetworkFee, 1),
                  const SizedBox(width: 8),
                  _buildSpeedChip('Fast', _backboneValidatorFast + _backboneNetworkFee, 2),
                ],
              ),
              const SizedBox(height: 16),

              // Error display
              if (_sendError != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: DnaColors.textError.withAlpha(20),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: DnaColors.textError.withAlpha(50)),
                  ),
                  child: Row(
                    children: [
                      FaIcon(FontAwesomeIcons.circleExclamation,
                             color: DnaColors.textError, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _sendError!,
                          style: TextStyle(color: DnaColors.textError, fontSize: 13),
                        ),
                      ),
                    ],
                  ),
                ),

              // Send button
              ElevatedButton(
                onPressed: _canSend() ? _send : null,
                child: _isSending
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Send CPUNK'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSpeedChip(String label, double fee, int speed) {
    final selected = _selectedGasSpeed == speed;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _selectedGasSpeed = speed),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
          decoration: BoxDecoration(
            color: selected ? DnaColors.primary.withAlpha(30) : Colors.transparent,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: selected ? DnaColors.primary : DnaColors.textMuted.withAlpha(50),
            ),
          ),
          child: Column(
            children: [
              Text(
                label,
                style: TextStyle(
                  fontWeight: selected ? FontWeight.bold : FontWeight.normal,
                  color: selected ? DnaColors.primary : null,
                ),
              ),
              Text(
                '${fee.toStringAsFixed(fee < 0.01 ? 4 : 3)} CELL',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  fontSize: 10,
                  color: DnaColors.textMuted,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Special bubble for CPUNK transfer messages
class _TransferBubble extends StatelessWidget {
  final Message message;
  final Map<String, dynamic> transferData;

  const _TransferBubble({required this.message, required this.transferData});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOutgoing = message.isOutgoing;

    final amount = transferData['amount'] ?? '?';
    final token = transferData['token'] ?? 'CPUNK';
    final txHash = transferData['txHash'] as String?;

    // Shorten tx hash for display (e.g., 0xABC...XYZ)
    String? shortTxHash;
    if (txHash != null && txHash.length > 16) {
      shortTxHash = '${txHash.substring(0, 10)}...${txHash.substring(txHash.length - 6)}';
    } else {
      shortTxHash = txHash;
    }

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(
          top: 4,
          bottom: 4,
          left: isOutgoing ? 48 : 0,
          right: isOutgoing ? 0 : 48,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: isOutgoing
                ? [DnaColors.primary.withAlpha(200), DnaColors.accent.withAlpha(150)]
                : [theme.colorScheme.surface, theme.colorScheme.surface],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 16),
          ),
          border: isOutgoing
              ? null
              : Border.all(color: DnaColors.primary.withAlpha(50)),
        ),
        child: Column(
          crossAxisAlignment:
              isOutgoing ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            // Transfer icon and label
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                FaIcon(
                  isOutgoing ? FontAwesomeIcons.arrowUp : FontAwesomeIcons.arrowDown,
                  size: 16,
                  color: isOutgoing
                      ? theme.colorScheme.onPrimary
                      : DnaColors.primary,
                ),
                const SizedBox(width: 4),
                Text(
                  isOutgoing ? 'Sent' : 'Received',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: isOutgoing
                        ? theme.colorScheme.onPrimary.withAlpha(200)
                        : DnaColors.textMuted,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 4),

            // Amount
            Text(
              '$amount $token',
              style: theme.textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.bold,
                color: isOutgoing
                    ? theme.colorScheme.onPrimary
                    : DnaColors.primary,
              ),
            ),

            // Transaction hash (tap to copy full hash)
            if (shortTxHash != null && txHash != null) ...[
              const SizedBox(height: 2),
              GestureDetector(
                onTap: () {
                  Clipboard.setData(ClipboardData(text: txHash));
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('Copied: $txHash'),
                      backgroundColor: DnaColors.snackbarSuccess,
                      duration: const Duration(seconds: 3),
                    ),
                  );
                },
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      shortTxHash,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontSize: 9,
                        fontFamily: 'monospace',
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary.withAlpha(150)
                            : DnaColors.textMuted,
                      ),
                    ),
                    const SizedBox(width: 4),
                    FaIcon(
                      FontAwesomeIcons.copy,
                      size: 10,
                      color: isOutgoing
                          ? theme.colorScheme.onPrimary.withAlpha(150)
                          : DnaColors.textMuted,
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 4),

            // Timestamp and status
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('HH:mm').format(message.timestamp),
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontSize: 10,
                    color: isOutgoing
                        ? theme.colorScheme.onPrimary.withAlpha(179)
                        : theme.textTheme.bodySmall?.color,
                  ),
                ),
                if (isOutgoing) ...[
                  const SizedBox(width: 4),
                  FaIcon(
                    message.status == MessageStatus.pending
                        ? FontAwesomeIcons.clock
                        : (message.status == MessageStatus.failed
                            ? FontAwesomeIcons.circleExclamation
                            : FontAwesomeIcons.check),
                    size: 14,
                    color: message.status == MessageStatus.failed
                        ? DnaColors.textWarning
                        : theme.colorScheme.onPrimary.withAlpha(179),
                  ),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }
}
