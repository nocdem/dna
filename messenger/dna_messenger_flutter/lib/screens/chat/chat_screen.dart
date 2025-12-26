// Chat Screen - Conversation with message bubbles
import 'dart:convert';
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
          // Send CPUNK button
          IconButton(
            icon: const Icon(Icons.currency_exchange),
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
    setState(() => _isSending = true);

    try {
      final txHash = await ref.read(walletsProvider.notifier).sendTokens(
        walletIndex: 0, // Current identity's wallet
        recipientAddress: _resolvedAddress!,
        amount: _amountController.text.trim(),
        token: 'CPUNK',
        network: 'Backbone',
        gasSpeed: _selectedGasSpeed,
      );

      if (mounted) {
        Navigator.pop(context);

        // Create transfer message in chat with tx hash
        final transferData = jsonEncode({
          'type': 'cpunk_transfer',
          'amount': _amountController.text.trim(),
          'token': 'CPUNK',
          'network': 'Backbone',
          'txHash': txHash,
          'recipientAddress': _resolvedAddress,
          'recipientName': widget.contact.displayName,
        });

        // Send the transfer message to the conversation
        ref.read(conversationProvider(widget.contact.fingerprint).notifier)
            .sendMessage(transferData);

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Sent ${_amountController.text.trim()} CPUNK'),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isSending = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to send: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
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
                const Icon(Icons.currency_exchange, size: 24),
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
                  icon: const Icon(Icons.close),
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
                    Icon(Icons.error_outline, color: DnaColors.textWarning),
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
                    Icon(Icons.check_circle, color: DnaColors.textSuccess, size: 20),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        '${_resolvedAddress!.substring(0, 12)}...${_resolvedAddress!.substring(_resolvedAddress!.length - 8)}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontFamily: 'NotoSansMono',
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
              const SizedBox(height: 24),

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
                Icon(
                  isOutgoing ? Icons.arrow_upward : Icons.arrow_downward,
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

            // Transaction hash
            if (shortTxHash != null) ...[
              const SizedBox(height: 2),
              Text(
                shortTxHash,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontSize: 9,
                  fontFamily: 'NotoSansMono',
                  color: isOutgoing
                      ? theme.colorScheme.onPrimary.withAlpha(150)
                      : DnaColors.textMuted,
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
                  Icon(
                    message.status == MessageStatus.pending
                        ? Icons.schedule
                        : (message.status == MessageStatus.failed
                            ? Icons.error_outline
                            : Icons.check),
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
