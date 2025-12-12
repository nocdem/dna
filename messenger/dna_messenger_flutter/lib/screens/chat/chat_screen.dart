// Chat Screen - Conversation with message bubbles
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:emoji_picker_flutter/emoji_picker_flutter.dart';
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
    // Rebuild to update send button enabled state
    setState(() {});
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

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            _buildAvatar(contact, theme),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    contact.displayName.isNotEmpty
                        ? contact.displayName
                        : _shortenFingerprint(contact.fingerprint),
                    style: theme.textTheme.titleMedium,
                  ),
                  Text(
                    contact.isOnline ? 'Online' : 'Offline',
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
          // Check offline messages button
          IconButton(
            icon: _isCheckingOffline
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.cloud_download),
            tooltip: 'Check offline messages',
            onPressed: _isCheckingOffline ? null : _checkOfflineMessages,
          ),
          IconButton(
            icon: const Icon(Icons.more_vert),
            onPressed: () => _showContactOptions(context),
          ),
        ],
      ),
      body: Stack(
        children: [
          // Main content
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
                        Icon(Icons.error_outline, color: DnaColors.textWarning),
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

          // Emoji picker (overlays chat, positioned above emoji button on left)
          if (_showEmojiPicker)
            Positioned(
              left: 8,
              bottom: 70, // Above input area
              child: Material(
                elevation: 8,
                borderRadius: BorderRadius.circular(12),
                color: theme.colorScheme.surface,
                child: Container(
                  constraints: const BoxConstraints(maxWidth: 380, maxHeight: 280),
                  clipBehavior: Clip.antiAlias,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: EmojiPicker(
                    onEmojiSelected: (category, emoji) {
                      _onEmojiSelected(emoji);
                    },
                    config: Config(
                      checkPlatformCompatibility: true,
                      emojiViewConfig: EmojiViewConfig(
                        columns: 7,
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
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildAvatar(Contact contact, ThemeData theme) {
    return Stack(
      children: [
        CircleAvatar(
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
        ),
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

  Widget _buildMessageList(BuildContext context, List<Message> messages) {
    if (messages.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.chat_bubble_outline,
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

    return Container(
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
              icon: Icon(
                _showEmojiPicker
                    ? Icons.keyboard
                    : Icons.emoji_emotions_outlined,
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
                  if (_messageController.text.trim().isNotEmpty) {
                    _sendMessage(contact);
                  }
                },
                onChanged: (_) {
                  // Rebuild to update send button enabled state
                  setState(() {});
                },
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
              icon: const Icon(Icons.send),
              onPressed: _messageController.text.trim().isEmpty
                  ? null
                  : () => _sendMessage(contact),
            ),
          ],
        ),
      ),
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
    _messageController.value = TextEditingValue(
      text: newText,
      selection: TextSelection.collapsed(
        offset: selection.start + emoji.emoji.length,
      ),
    );
    // Keep focus on the text field after emoji insert
    _focusNode.requestFocus();
    setState(() {});
  }

  void _showContactOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.person),
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
              leading: const Icon(Icons.cloud_download),
              title: const Text('Check Offline Messages'),
              subtitle: const Text('Fetch from DHT queue'),
              onTap: () {
                Navigator.pop(context);
                _checkOfflineMessages();
              },
            ),
            ListTile(
              leading: const Icon(Icons.qr_code),
              title: const Text('Show QR Code'),
              onTap: () {
                Navigator.pop(context);
                // TODO: Show QR
              },
            ),
            ListTile(
              leading: Icon(Icons.delete, color: DnaColors.textWarning),
              title: Text(
                'Remove Contact',
                style: TextStyle(color: DnaColors.textWarning),
              ),
              onTap: () {
                Navigator.pop(context);
                // TODO: Confirm and remove
              },
            ),
          ],
        ),
      ),
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

  bool _isSameDay(DateTime a, DateTime b) {
    return a.year == b.year && a.month == b.month && a.day == b.day;
  }
}

class _MessageBubble extends StatelessWidget {
  final Message message;

  const _MessageBubble({required this.message});

  @override
  Widget build(BuildContext context) {
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
      return Icon(
        Icons.error_outline,
        size: size,
        color: DnaColors.textWarning,
      );
    }

    return Icon(
      _getStatusIcon(status),
      size: size,
      color: color,
    );
  }

  IconData _getStatusIcon(MessageStatus status) {
    switch (status) {
      case MessageStatus.pending:
        return Icons.schedule;
      case MessageStatus.sent:
        return Icons.check;
      case MessageStatus.failed:
        return Icons.error_outline;
      case MessageStatus.delivered:
        return Icons.done_all;
      case MessageStatus.read:
        return Icons.done_all; // Would be colored differently
    }
  }
}
