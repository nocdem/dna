// Chat Screen - Conversation with message bubbles
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import 'package:emoji_picker_flutter/emoji_picker_flutter.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:image_picker/image_picker.dart';
import '../../ffi/dna_engine.dart';
import '../../l10n/app_localizations.dart';
import '../../providers/providers.dart' hide UserProfile;
import '../../utils/logger.dart';
import '../../design_system/design_system.dart';
import '../../widgets/emoji_shortcode_field.dart';
import '../../widgets/formatted_text.dart';
import '../../widgets/image_message_bubble.dart';
import '../../widgets/media_message_bubble.dart';
import '../../services/image_attachment_service.dart';
import '../../services/media_service.dart';
import '../../models/media_ref.dart';
import 'contact_profile_dialog.dart';
import 'widgets/message_bubble.dart';

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
  Message? _replyingTo; // Message being replied to

  // Track seen message IDs to only animate new ones
  final Set<int> _seenMessageIds = {};
  bool _initialLoadDone = false;

  // Search state
  bool _isSearching = false;
  String _searchQuery = '';
  final _searchController = TextEditingController();
  final _searchFocusNode = FocusNode();

  @override
  void initState() {
    super.initState();
    // Listen to text changes to update send button state
    _messageController.addListener(_onTextChanged);
    // Listen to scroll for loading older messages
    _scrollController.addListener(_onScroll);

    // Mark messages as read when chat opens
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _markMessagesAsRead(); // DB only - fast, keep immediate

      // Defer DHT operations to reduce lag on chat open
      // Lets UI render first, then starts network calls
      Future.delayed(const Duration(milliseconds: 300), () {
        if (mounted) {
          _checkOfflineMessagesSilent(); // With cooldown
          // Presence polling handled by EventHandler background timer
        }
      });
    });
  }

  void _onScroll() {
    // For reversed ListView, maxScrollExtent is the "top" (older messages)
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      final contact = ref.read(selectedContactProvider);
      if (contact != null) {
        ref.read(conversationProvider(contact.fingerprint).notifier).loadMore();
      }
    }
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
      log('CHAT', 'Failed to mark messages as read: $e');
    }

    // Refresh contact profile in background (for latest avatar/name)
    ref.read(contactProfileCacheProvider.notifier).refreshProfile(contact.fingerprint);

    // NOTE: DHT offline check removed from chat open - it was downloading ~1MB
    // of data just to find duplicates. New messages arrive via DHT listeners
    // and background sync instead.
  }

  /// Check offline messages with cooldown
  /// Called automatically when chat opens
  /// Skips if checked recently (listeners already handle new messages)
  Future<void> _checkOfflineMessagesSilent() async {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;

    // Skip if checked recently (cooldown)
    if (!shouldFetchOfflineMessages(ref, contact.fingerprint)) {
      log('CHAT', 'Skipping offline check (cooldown) for ${contact.fingerprint.substring(0, 16)}...');
      return;
    }

    try {
      final engine = await ref.read(engineProvider.future);
      if (!mounted) return;

      log('CHAT', 'Checking offline messages from ${contact.fingerprint.substring(0, 16)}...');

      // Use targeted fetch for this specific contact (faster than checking all)
      await engine.checkOfflineMessagesFrom(contact.fingerprint);
      if (!mounted) return;

      // Record fetch time for cooldown
      recordOfflineFetch(ref, contact.fingerprint);

      // Merge any new messages without showing loading state
      await ref.read(conversationProvider(contact.fingerprint).notifier).mergeLatest();
    } catch (e) {
      if (mounted) {
        log('CHAT', 'Offline check failed: $e');
      }
    }
  }

  @override
  void deactivate() {
    // Clear selected contact when leaving chat screen
    // Capture notifier before widget is disposed, then defer the state change
    final notifier = ref.read(selectedContactProvider.notifier);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) return; // Only clear if widget is actually being disposed
      notifier.state = null;
    });
    super.deactivate();
  }

  @override
  void dispose() {
    _messageController.removeListener(_onTextChanged);
    _scrollController.removeListener(_onScroll);
    _messageController.dispose();
    _scrollController.dispose();
    _focusNode.dispose();
    _searchController.dispose();
    _searchFocusNode.dispose();
    super.dispose();
  }

  void _onTextChanged() {
    // Close emoji picker when user types (but not when emoji was just inserted)
    if (_showEmojiPicker && !_justInsertedEmoji) {
      setState(() => _showEmojiPicker = false);
    }
    _justInsertedEmoji = false;
    // Note: send button state handled by ValueListenableBuilder - no setState needed
  }

  /// Retry a failed message
  void _retryMessage(int messageId) async {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;

    try {
      final engine = await ref.read(engineProvider.future);
      final success = engine.retryMessage(messageId);
      if (success) {
        // Refresh conversation to show updated status
        ref.invalidate(conversationProvider(contact.fingerprint));
      } else {
        // Show error snackbar
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('Failed to retry message'),
              backgroundColor: DnaColors.snackbarError,
            ),
          );
        }
      }
    } catch (e) {
      log('CHAT', 'Retry failed: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Retry error: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  Future<void> _checkOfflineMessages() async {
    if (_isCheckingOffline) return;

    setState(() => _isCheckingOffline = true);
    log('OFFLINE', 'Starting offline message check...');

    try {
      final engineAsync = ref.read(engineProvider);
      await engineAsync.when(
        data: (engine) async {
          log('OFFLINE', 'Engine ready, calling checkOfflineMessages()');
          final startTime = DateTime.now();
          await engine.checkOfflineMessages();
          final elapsed = DateTime.now().difference(startTime);
          log('OFFLINE', 'Check completed in ${elapsed.inMilliseconds}ms');

          // Refresh conversation to show any new messages
          final contact = ref.read(selectedContactProvider);
          if (contact != null) {
            log('OFFLINE', 'Refreshing conversation for ${contact.fingerprint.substring(0, 16)}...');
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
          log('OFFLINE', 'Engine still loading...');
        },
        error: (e, st) {
          logError('OFFLINE', e, st);
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
      logError('OFFLINE', e, st);
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
        log('OFFLINE', 'Check finished');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final contact = ref.watch(selectedContactProvider);
    final messages = ref.watch(currentConversationProvider);
    final theme = Theme.of(context);
    // Watch starred messages for the current contact
    final starredIds = contact != null
        ? ref.watch(starredMessagesProvider(contact.fingerprint))
        : <int>{};

    if (contact == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Chat')),
        body: const Center(
          child: Text('No contact selected'),
        ),
      );
    }

    // Get cached profile for display name fallback
    // ignore: unused_local_variable
    final profileCache = ref.watch(contactProfileCacheProvider);

    // Use contact.displayName (resolved by C library from registered name)
    // v0.6.24: UserProfile.displayName removed - Contact.displayName is the source of truth
    final displayName = contact.displayName.isNotEmpty
        ? contact.displayName
        : _shortenFingerprint(contact.fingerprint);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        leading: _isSearching
            ? IconButton(
                icon: const FaIcon(FontAwesomeIcons.arrowLeft),
                onPressed: () {
                  setState(() {
                    _isSearching = false;
                    _searchQuery = '';
                    _searchController.clear();
                  });
                },
              )
            : null,
        title: _isSearching
            ? TextField(
                controller: _searchController,
                focusNode: _searchFocusNode,
                autofocus: true,
                decoration: InputDecoration(
                  hintText: AppLocalizations.of(context).chatSearchMessages,
                  border: InputBorder.none,
                  hintStyle: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.textTheme.bodySmall?.color,
                  ),
                ),
                style: theme.textTheme.bodyMedium,
                onChanged: (value) {
                  setState(() {
                    _searchQuery = value.toLowerCase();
                  });
                },
              )
            : Row(
                children: [
                  DnaAvatar(
                    imageBytes: ref.watch(
                      contactProfileCacheProvider.select(
                        (cache) => cache[contact.fingerprint]?.decodeAvatar(),
                      ),
                    ),
                    name: displayName,
                    size: DnaAvatarSize.sm,
                    showOnlineStatus: true,
                    isOnline: contact.isOnline,
                  ),
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
                              ? AppLocalizations.of(context).chatOnline
                              : AppLocalizations.of(context).chatLastSeen(_formatLastSeen(contact.lastSeen)),
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: contact.isOnline
                                ? DnaColors.success
                                : theme.textTheme.bodySmall?.color,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
        actions: _isSearching
            ? [
                if (_searchQuery.isNotEmpty)
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.xmark),
                    onPressed: () {
                      setState(() {
                        _searchQuery = '';
                        _searchController.clear();
                      });
                    },
                  ),
              ]
            : [
                // Search button
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.magnifyingGlass),
                  tooltip: AppLocalizations.of(context).chatSearchMessages,
                  onPressed: () {
                    setState(() {
                      _isSearching = true;
                    });
                    // Request focus after the TextField is built
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      _searchFocusNode.requestFocus();
                    });
                  },
                ),
                // Jump to date button
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.calendar),
                  tooltip: 'Jump to date',
                  onPressed: () => _jumpToDate(messages.valueOrNull ?? []),
                ),
                // Send tokens button
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.dollarSign),
                  tooltip: 'Send Tokens',
                  onPressed: () => _showSendTokens(context, contact),
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
                  data: (list) => _buildMessageList(context, list, starredIds, contact),
                  loading: () => const Center(child: CircularProgressIndicator()),
                  error: (error, stack) {
                    return Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          FaIcon(FontAwesomeIcons.circleExclamation, color: DnaColors.warning),
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
                    );
                  },
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
                    border: Border.all(color: theme.dividerColor),
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
                            iconColor: theme.textTheme.bodySmall?.color ?? Colors.grey,
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

  Widget _buildMessageList(BuildContext context, List<Message> messages, Set<int> starredIds, Contact contact) {
    // Track seen messages for animation (only animate truly new ones)
    // On initial load, mark all current messages as seen (no animation for them)
    if (!_initialLoadDone && messages.isNotEmpty) {
      // First load - mark all as seen (no animation)
      for (final msg in messages) {
        _seenMessageIds.add(msg.id);
      }
      // Use post-frame callback to avoid setState during build
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          setState(() => _initialLoadDone = true);
        }
      });
    }
    // NOTE: Don't add messages to _seenMessageIds here after initial load!
    // New messages should NOT be in the set so they get animated.
    // They get added to _seenMessageIds after being rendered (see below).

    // Filter messages if searching
    final filteredMessages = _searchQuery.isEmpty
        ? messages
        : messages.where((m) => m.plaintext.toLowerCase().contains(_searchQuery)).toList();

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
              AppLocalizations.of(context).chatNoMessages,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              AppLocalizations.of(context).chatSendFirstMessage,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    // Show no results message if searching and no matches
    if (_searchQuery.isNotEmpty && filteredMessages.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.magnifyingGlass,
              size: 48,
              color: Theme.of(context).colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No messages found',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Try a different search term',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    final isLoadingMore = ref.watch(isLoadingMoreProvider(contact.fingerprint));
    final hasMore = ref.watch(hasMoreMessagesProvider(contact.fingerprint));
    // Add 1 for loading indicator if loading or has more
    final extraItems = (isLoadingMore || hasMore) ? 1 : 0;

    return ListView.builder(
      controller: _scrollController,
      reverse: true,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      cacheExtent: 500.0, // Pre-render items for smoother scrolling
      itemCount: filteredMessages.length + extraItems,
      itemBuilder: (context, index) {
        // Last item (appears at top in reversed list) is the loading indicator
        if (index == filteredMessages.length) {
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 16),
            child: Center(
              child: isLoadingMore
                  ? const SizedBox(
                      width: 24,
                      height: 24,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const SizedBox.shrink(),
            ),
          );
        }
        // Reverse index since list is reversed
        final message = filteredMessages[filteredMessages.length - 1 - index];
        final prevMessage = index < filteredMessages.length - 1
            ? filteredMessages[filteredMessages.length - 2 - index]
            : null;

        final showDate = prevMessage == null ||
            !_isSameDay(message.timestamp, prevMessage.timestamp);

        return Column(
          children: [
            if (showDate) _buildDateHeader(context, message.timestamp),
            Dismissible(
              key: ValueKey('msg_${message.id}'),
              confirmDismiss: (direction) async {
                if (direction == DismissDirection.startToEnd) {
                  // Swipe right → Copy
                  _copyMessage(message);
                } else if (direction == DismissDirection.endToStart) {
                  // Swipe left → Reply/Forward options
                  _showReplyForwardOptions(message);
                }
                return false; // Don't actually dismiss
              },
              background: Container(
                alignment: Alignment.centerLeft,
                padding: const EdgeInsets.only(left: 20),
                color: DnaColors.info.withAlpha(50),
                child: FaIcon(
                  FontAwesomeIcons.copy,
                  color: DnaColors.info,
                ),
              ),
              secondaryBackground: Container(
                alignment: Alignment.centerRight,
                padding: const EdgeInsets.only(right: 20),
                color: Theme.of(context).colorScheme.primary.withAlpha(50),
                child: FaIcon(
                  FontAwesomeIcons.reply,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
              child: Builder(
                builder: (context) {
                  // Check if this is a new message that should animate
                  final shouldAnimate = _initialLoadDone && !_seenMessageIds.contains(message.id);
                  // Mark as seen so it won't animate again on rebuild
                  if (shouldAnimate) {
                    _seenMessageIds.add(message.id);
                  }
                  return MessageBubbleWrapper(
                    message: message,
                    isStarred: starredIds.contains(message.id),
                    animate: shouldAnimate,
                    onTap: () => _showMessageInfo(message),
                    onLongPress: () => _showMessageActions(message),
                    onReply: _replyMessage,
                    onCopy: _copyMessage,
                    onForward: _forwardMessage,
                    onStar: (msg) => _toggleStarMessage(msg, contact.fingerprint),
                    onDelete: _confirmDeleteMessage,
                    onRetry: message.isOutgoing &&
                            (message.status == MessageStatus.failed || message.status == MessageStatus.pending)
                        ? () => _retryMessage(message.id)
                        : null,
                    child: _MessageBubble(
                      message: message,
                      isStarred: starredIds.contains(message.id),
                      onRetry: message.isOutgoing &&
                              (message.status == MessageStatus.failed || message.status == MessageStatus.pending)
                          ? () => _retryMessage(message.id)
                          : null,
                      engine: ref.read(engineProvider).valueOrNull,
                    ),
                  );
                },
              ),
            ),
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
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // DHT Status Banner
        if (dhtState != DhtConnectionState.connected)
          Builder(builder: (_) {
            final isConnecting = dhtState == DhtConnectionState.connecting;
            final color = isConnecting ? Colors.orange : DnaColors.error;
            final icon = isConnecting ? FontAwesomeIcons.cloudArrowUp : FontAwesomeIcons.cloudBolt;
            final text = isConnecting ? AppLocalizations.of(context).chatConnecting : 'Disconnected - messages will queue';
            return Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              color: color.withAlpha(30),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  FaIcon(icon, size: 14, color: color),
                  const SizedBox(width: 8),
                  Text(
                    text,
                    style: TextStyle(
                      color: color,
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            );
          }),
        // Reply preview banner
        if (_replyingTo != null)
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withAlpha(20),
              border: Border(
                left: BorderSide(
                  color: theme.colorScheme.primary,
                  width: 3,
                ),
              ),
            ),
            child: Row(
              children: [
                FaIcon(
                  FontAwesomeIcons.reply,
                  size: 14,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        'Replying to ${_replyingTo!.isOutgoing ? "yourself" : contact.displayName.isNotEmpty ? contact.displayName : "message"}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.primary,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        _replyingTo!.plaintext.length > 50
                            ? '${_replyingTo!.plaintext.substring(0, 50)}...'
                            : _replyingTo!.plaintext,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.textTheme.bodySmall?.color,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.xmark, size: 16),
                  onPressed: _cancelReply,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
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
            // Attachment button
            IconButton(
              icon: const FaIcon(FontAwesomeIcons.paperclip),
              onPressed: () => _showAttachmentOptions(context, contact),
              tooltip: 'Attach image',
            ),
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
                hintText: AppLocalizations.of(context).chatTypeMessage,
                minLines: 1,
                maxLines: 5,
                onEnterPressed: () {
                  if (_messageController.text.trim().isNotEmpty) {
                    _sendMessage(contact);
                  }
                },
                // Note: onChanged not needed - _messageController.addListener handles state
                decoration: InputDecoration(
                  hintText: AppLocalizations.of(context).chatTypeMessage,
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

            // Send button - uses ValueListenableBuilder for zero parent rebuilds
            ValueListenableBuilder<TextEditingValue>(
              valueListenable: _messageController,
              builder: (context, value, child) {
                final hasText = value.text.trim().isNotEmpty;
                return Material(
                  color: hasText
                      ? theme.colorScheme.primary
                      : theme.colorScheme.onSurface.withAlpha(30),
                  shape: const CircleBorder(),
                  child: InkWell(
                    onTap: hasText ? () => _sendMessage(contact) : null,
                    customBorder: const CircleBorder(),
                    child: SizedBox(
                      width: 44,
                      height: 44,
                      child: Center(
                        child: FaIcon(
                          FontAwesomeIcons.solidPaperPlane,
                          size: 18,
                          color: hasText
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
    );
  }

  void _sendMessage(Contact contact) {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;

    _messageController.clear();

    // Build message text with reply marker if replying
    String messageText = text;
    if (_replyingTo != null) {
      final replyTo = _replyingTo!;
      final senderName = replyTo.isOutgoing
          ? 'me'
          : (contact.displayName.isNotEmpty ? contact.displayName : replyTo.sender.substring(0, 12));
      // Truncate quoted text to 100 chars
      final quotedText = replyTo.plaintext.length > 100
          ? '${replyTo.plaintext.substring(0, 100)}...'
          : replyTo.plaintext;
      // Format: ↩ Re: [sender]\n> [quoted]\n[message]
      messageText = '↩ Re: $senderName\n> $quotedText\n$text';
      // Clear reply state
      setState(() {
        _replyingTo = null;
      });
    }

    // Queue message for async sending (returns immediately)
    final result = ref.read(conversationProvider(contact.fingerprint).notifier)
        .sendMessage(messageText);

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

  void _showAttachmentOptions(BuildContext context, Contact contact) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.images),
              title: Text(AppLocalizations.of(context).chatPhotoLibrary),
              onTap: () {
                Navigator.pop(context);
                _pickAndSendImage(contact, ImageSource.gallery);
              },
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.camera),
              title: Text(AppLocalizations.of(context).chatCamera),
              onTap: () {
                Navigator.pop(context);
                _pickAndSendImage(contact, ImageSource.camera);
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _pickAndSendImage(Contact contact, ImageSource source) async {
    final imageService = ImageAttachmentService();

    try {
      // Pick image
      final bytes = await imageService.pickImage(source);
      if (bytes == null) return; // User cancelled

      if (!mounted) return;

      // Show caption dialog first (before uploading)
      final caption = await _showCaptionDialog(context);
      if (!mounted) return;

      // Show loading indicator
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (_) => const Center(child: CircularProgressIndicator()),
      );

      // Upload via MediaService (compress + thumbnail + DHT upload)
      final engine = await ref.read(engineProvider.future);
      final mediaService = MediaService(engine);
      final mediaRef = await mediaService.uploadImage(
        bytes,
        encrypted: true,
        caption: caption,
        ttl: 604800,
      );

      if (!mounted) return;
      Navigator.pop(context); // Dismiss loading

      // Send media_ref JSON via existing message queue
      final messageJson = mediaRef.toMessageJson();
      final result = ref
          .read(conversationProvider(contact.fingerprint).notifier)
          .sendMessage(messageJson);

      if (result == -1) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Message queue full. Please wait and try again.'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      } else if (result == -2) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Failed to send image. Please try again.'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } on MediaServiceException catch (e) {
      if (!mounted) return;
      if (Navigator.canPop(context)) {
        Navigator.pop(context);
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(e.message),
          backgroundColor: DnaColors.snackbarError,
        ),
      );
    } on ImageAttachmentException catch (e) {
      if (!mounted) return;
      if (Navigator.canPop(context)) {
        Navigator.pop(context);
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(e.message),
          backgroundColor: DnaColors.snackbarError,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      if (Navigator.canPop(context)) {
        Navigator.pop(context);
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error: $e'),
          backgroundColor: DnaColors.snackbarError,
        ),
      );
    }
  }

  Future<String?> _showCaptionDialog(BuildContext context) async {
    final controller = TextEditingController();

    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).chatAddCaption),
        content: TextField(
          controller: controller,
          decoration: InputDecoration(
            hintText: AppLocalizations.of(context).chatAddCaption,
          ),
          autofocus: true,
          maxLines: 3,
          maxLength: 500,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, null),
            child: const Text('Skip'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: Text(AppLocalizations.of(context).chatSendPhoto),
          ),
        ],
      ),
    );
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

  void _showSendTokens(BuildContext context, Contact contact) {
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
              leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.error),
              title: Text(
                AppLocalizations.of(context).chatDeleteConversation,
                style: TextStyle(color: DnaColors.error),
              ),
              onTap: () {
                Navigator.pop(context);
                _confirmDeleteConversation();
              },
            ),
            ListTile(
              leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.warning),
              title: Text(
                'Remove Contact',
                style: TextStyle(color: DnaColors.warning),
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

  void _showMessageInfo(Message message) {
    final theme = Theme.of(context);
    final contact = ref.read(selectedContactProvider);
    final contactName = contact?.displayName.isNotEmpty == true
        ? contact!.displayName
        : 'contact';

    // Format full timestamp
    final fullTimestamp = DateFormat('MMMM d, y \'at\' HH:mm:ss').format(message.timestamp);

    // Get status info (v15: simplified 4-state model)
    String statusText;
    IconData statusIcon;
    Color statusColor;
    final mutedColor = theme.textTheme.bodySmall?.color ?? Colors.grey;
    switch (message.status) {
      case MessageStatus.pending:
        statusText = 'Sending...';
        statusIcon = FontAwesomeIcons.clock;
        statusColor = mutedColor;
        break;
      case MessageStatus.sent:
        statusText = 'Sent';
        statusIcon = FontAwesomeIcons.check;
        statusColor = mutedColor;
        break;
      case MessageStatus.received:
        statusText = 'Received';
        statusIcon = FontAwesomeIcons.checkDouble;
        statusColor = DnaColors.success;
        break;
      case MessageStatus.failed:
        statusText = 'Failed to send';
        statusIcon = FontAwesomeIcons.circleExclamation;
        statusColor = DnaColors.error;
        break;
    }

    showModalBottomSheet(
      context: context,
      builder: (ctx) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  FaIcon(
                    FontAwesomeIcons.circleInfo,
                    size: 18,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Message Info',
                    style: theme.textTheme.titleMedium,
                  ),
                ],
              ),
              const Divider(height: 24),

              // Timestamp
              _buildInfoRow(
                theme,
                FontAwesomeIcons.clock,
                'Time',
                fullTimestamp,
              ),
              const SizedBox(height: 12),

              // Direction
              _buildInfoRow(
                theme,
                message.isOutgoing
                    ? FontAwesomeIcons.arrowUp
                    : FontAwesomeIcons.arrowDown,
                'Direction',
                message.isOutgoing ? 'Sent to $contactName' : 'Received from $contactName',
              ),
              const SizedBox(height: 12),

              // Status (only for outgoing)
              if (message.isOutgoing)
                _buildInfoRow(
                  theme,
                  statusIcon,
                  'Status',
                  statusText,
                  iconColor: statusColor,
                ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInfoRow(
    ThemeData theme,
    IconData icon,
    String label,
    String value, {
    Color? iconColor,
  }) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 24,
          child: FaIcon(
            icon,
            size: 14,
            color: iconColor ?? theme.textTheme.bodySmall?.color,
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: theme.textTheme.bodySmall,
              ),
              Text(
                value,
                style: theme.textTheme.bodyMedium,
              ),
            ],
          ),
        ),
      ],
    );
  }

  void _showMessageActions(Message message) {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;

    final starredIds = ref.read(starredMessagesProvider(contact.fingerprint));
    final isStarred = starredIds.contains(message.id);

    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.reply),
              title: Text(AppLocalizations.of(context).messageMenuReply),
              onTap: () {
                Navigator.pop(context);
                _replyMessage(message);
              },
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.copy),
              title: Text(AppLocalizations.of(context).messageMenuCopy),
              onTap: () {
                Navigator.pop(context);
                _copyMessage(message);
              },
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.share),
              title: Text(AppLocalizations.of(context).messageMenuForward),
              onTap: () {
                Navigator.pop(context);
                _forwardMessage(message);
              },
            ),
            ListTile(
              leading: FaIcon(
                isStarred ? FontAwesomeIcons.solidStar : FontAwesomeIcons.star,
                color: isStarred ? Colors.amber : null,
              ),
              title: Text(isStarred ? AppLocalizations.of(context).messageMenuUnstar : AppLocalizations.of(context).messageMenuStar),
              onTap: () {
                Navigator.pop(context);
                _toggleStarMessage(message, contact.fingerprint);
              },
            ),
            ListTile(
              leading: FaIcon(FontAwesomeIcons.trash, color: DnaColors.error),
              title: Text(AppLocalizations.of(context).messageMenuDelete, style: TextStyle(color: DnaColors.error)),
              onTap: () {
                Navigator.pop(context);
                _confirmDeleteMessage(message);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _toggleStarMessage(Message message, String contactFp) {
    ref.read(starredMessagesProvider(contactFp).notifier).toggleStar(message.id);
  }

  Future<void> _jumpToDate(List<Message> messages) async {
    if (messages.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('No messages to jump to'),
          backgroundColor: DnaColors.snackbarInfo,
          duration: const Duration(seconds: 2),
        ),
      );
      return;
    }

    // Get date range from messages
    final dates = messages.map((m) => m.timestamp).toList()..sort();
    final firstDate = DateTime(dates.first.year, dates.first.month, dates.first.day);
    final lastDate = DateTime(dates.last.year, dates.last.month, dates.last.day);

    // Show date picker
    final selectedDate = await showDatePicker(
      context: context,
      initialDate: lastDate,
      firstDate: firstDate,
      lastDate: lastDate,
      helpText: 'Jump to date',
    );

    if (selectedDate == null || !mounted) return;

    // Find the first message on or after the selected date
    final targetDate = DateTime(selectedDate.year, selectedDate.month, selectedDate.day);
    int? targetIndex;
    for (int i = 0; i < messages.length; i++) {
      final msgDate = DateTime(
        messages[i].timestamp.year,
        messages[i].timestamp.month,
        messages[i].timestamp.day,
      );
      if (msgDate.isAtSameMomentAs(targetDate) || msgDate.isAfter(targetDate)) {
        targetIndex = i;
        break;
      }
    }

    if (targetIndex != null) {
      // The ListView is reversed, so we need to convert the index
      // ListView index = messages.length - 1 - targetIndex
      final scrollIndex = messages.length - 1 - targetIndex;

      // Estimate position (assuming ~80 pixels per message bubble)
      final estimatedOffset = scrollIndex * 80.0;

      _scrollController.animateTo(
        estimatedOffset.clamp(0.0, _scrollController.position.maxScrollExtent),
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Jumped to ${DateFormat('MMM d, yyyy').format(selectedDate)}'),
          backgroundColor: DnaColors.snackbarSuccess,
          duration: const Duration(seconds: 2),
        ),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('No messages found for this date'),
          backgroundColor: DnaColors.snackbarInfo,
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  void _confirmDeleteMessage(Message message) {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.chatDeleteMessageTitle),
        content: Text(l10n.chatDeleteMessageConfirm),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              _deleteMessage(message);
            },
            style: TextButton.styleFrom(foregroundColor: DnaColors.error),
            child: Text(l10n.delete),
          ),
        ],
      ),
    );
  }

  Future<void> _deleteMessage(Message message) async {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;

    final success = await ref
        .read(conversationProvider(contact.fingerprint).notifier)
        .deleteMessage(message.id);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(success ? AppLocalizations.of(context).chatMessageDeleted : 'Failed to delete message'),
          backgroundColor: success ? DnaColors.snackbarSuccess : DnaColors.error,
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  void _confirmDeleteConversation() {
    final contact = ref.read(selectedContactProvider);
    if (contact == null) return;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.chatDeleteConversationTitle),
        content: Text(l10n.chatDeleteConversationConfirm),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(context);
              final success = await ref
                  .read(conversationProvider(contact.fingerprint).notifier)
                  .deleteConversation();
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(success
                        ? l10n.chatConversationDeleted
                        : l10n.chatDeleteConversationFailed),
                    backgroundColor: success ? DnaColors.snackbarSuccess : DnaColors.error,
                  ),
                );
              }
            },
            style: TextButton.styleFrom(foregroundColor: DnaColors.error),
            child: Text(l10n.delete),
          ),
        ],
      ),
    );
  }

  void _showReplyForwardOptions(Message message) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.reply),
              title: Text(AppLocalizations.of(context).messageMenuReply),
              onTap: () {
                Navigator.pop(context);
                _replyMessage(message);
              },
            ),
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.share),
              title: Text(AppLocalizations.of(context).messageMenuForward),
              onTap: () {
                Navigator.pop(context);
                _forwardMessage(message);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _replyMessage(Message message) {
    setState(() {
      _replyingTo = message;
    });
    _focusNode.requestFocus();
  }

  void _cancelReply() {
    setState(() {
      _replyingTo = null;
    });
  }

  void _copyMessage(Message message) {
    Clipboard.setData(ClipboardData(text: message.plaintext));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Message copied'),
        backgroundColor: DnaColors.snackbarSuccess,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  Future<void> _forwardMessage(Message message) async {
    final contacts = await ref.read(contactsProvider.future);

    if (!mounted) return;

    final selectedContact = await showModalBottomSheet<Contact>(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        minChildSize: 0.3,
        maxChildSize: 0.9,
        expand: false,
        builder: (context, scrollController) => Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Text(
                    'Forward to',
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.xmark),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
            Expanded(
              child: contacts.isEmpty
                  ? const Center(child: Text('No contacts'))
                  : ListView.builder(
                      controller: scrollController,
                      itemCount: contacts.length,
                      itemBuilder: (context, index) {
                        final contact = contacts[index];
                        return ListTile(
                          leading: DnaAvatar(
                            name: contact.displayName.isNotEmpty
                                ? contact.displayName
                                : null,
                            size: DnaAvatarSize.md,
                          ),
                          title: Text(contact.displayName.isNotEmpty
                              ? contact.displayName
                              : '${contact.fingerprint.substring(0, 16)}...'),
                          subtitle: Text(
                            '${contact.fingerprint.substring(0, 16)}...',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                          onTap: () => Navigator.pop(context, contact),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );

    if (selectedContact != null && mounted) {
      // Determine original sender name
      final currentContact = ref.read(selectedContactProvider);
      String originalSender;
      if (message.isOutgoing) {
        originalSender = 'me';
      } else if (currentContact != null && currentContact.displayName.isNotEmpty) {
        originalSender = currentContact.displayName;
      } else {
        originalSender = message.sender.substring(0, 12);
      }

      // Build forwarded message with marker
      // Format: ⤷ Fwd: [name]\n[original message]
      final forwardedText = '⤷ Fwd: $originalSender\n${message.plaintext}';

      // Send the message to the selected contact
      ref.read(conversationProvider(selectedContact.fingerprint).notifier)
          .sendMessage(forwardedText);

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Message forwarded to ${selectedContact.displayName.isNotEmpty ? selectedContact.displayName : 'contact'}'),
          backgroundColor: DnaColors.snackbarSuccess,
        ),
      );
    }
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
            FaIcon(FontAwesomeIcons.userMinus, color: DnaColors.warning),
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
                color: DnaColors.warning.withAlpha(26),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: DnaColors.warning.withAlpha(51)),
              ),
              child: Row(
                children: [
                  FaIcon(FontAwesomeIcons.circleInfo, size: 20, color: DnaColors.warning),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Message history will be preserved. You can re-add this contact later.',
                      style: TextStyle(
                        fontSize: 13,
                        color: DnaColors.warning,
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
              backgroundColor: DnaColors.warning,
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

class _MessageBubble extends StatelessWidget {
  final Message message;
  final bool isStarred;
  final VoidCallback? onRetry;
  final DnaEngine? engine;

  const _MessageBubble({required this.message, this.isStarred = false, this.onRetry, this.engine});

  /// Check if message is a token transfer by parsing JSON content
  Map<String, dynamic>? _parseTransferData() {
    try {
      final data = jsonDecode(message.plaintext) as Map<String, dynamic>;
      if (data['type'] == 'token_transfer') {
        return data;
      }
    } catch (_) {
      // Not JSON or invalid format - treat as regular message
    }
    return null;
  }

  /// Check if message is a media_ref (new chunked media format)
  Map<String, dynamic>? _parseMediaRef() {
    try {
      final data = jsonDecode(message.plaintext) as Map<String, dynamic>;
      if (data['type'] == 'media_ref') {
        return data;
      }
    } catch (_) {
      // Not JSON or invalid format
    }
    return null;
  }

  /// Check if message is an image attachment by parsing JSON content
  Map<String, dynamic>? _parseImageData() {
    try {
      final data = jsonDecode(message.plaintext) as Map<String, dynamic>;
      if (data['type'] == 'image_attachment') {
        return data;
      }
    } catch (_) {
      // Not JSON or invalid format - treat as regular message
    }
    return null;
  }

  /// Check if message is a group invitation by parsing JSON content
  Map<String, dynamic>? _parseInvitationData() {
    // Check message type first
    if (message.type == MessageType.groupInvitation) {
      try {
        final data = jsonDecode(message.plaintext) as Map<String, dynamic>;
        // Accept both formats: with and without underscores
        final type = data['type'] as String?;
        if (type == 'group_invite' || type == 'groupinvite') {
          return data;
        }
      } catch (_) {
        // Not valid JSON - still try to show as invitation
      }
      // Return minimal data if JSON parsing failed but type is invitation
      return {'type': 'group_invite'};
    }
    return null;
  }

  /// Check if message is forwarded and extract sender name + original text
  /// Format: "⤷ Fwd: [name]\n[original message]"
  ({String sender, String text})? _parseForwardedData() {
    final text = message.plaintext;
    if (text.startsWith('⤷ Fwd: ')) {
      final newlineIndex = text.indexOf('\n');
      if (newlineIndex != -1) {
        final sender = text.substring(7, newlineIndex); // After "⤷ Fwd: "
        final originalText = text.substring(newlineIndex + 1);
        return (sender: sender, text: originalText);
      }
    }
    return null;
  }

  /// Check if message is a reply and extract sender name, quoted text, and reply
  /// Format: "↩ Re: [sender]\n> [quoted]\n[reply message]"
  ({String sender, String quoted, String text})? _parseReplyData() {
    final text = message.plaintext;
    if (text.startsWith('↩ Re: ')) {
      final firstNewline = text.indexOf('\n');
      if (firstNewline != -1) {
        final sender = text.substring(6, firstNewline); // After "↩ Re: "
        final afterSender = text.substring(firstNewline + 1);
        if (afterSender.startsWith('> ')) {
          final secondNewline = afterSender.indexOf('\n');
          if (secondNewline != -1) {
            final quoted = afterSender.substring(2, secondNewline); // After "> "
            final replyText = afterSender.substring(secondNewline + 1);
            return (sender: sender, quoted: quoted, text: replyText);
          }
        }
      }
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    // Handle media_ref messages (new chunked media format)
    final mediaData = _parseMediaRef();
    if (mediaData != null && engine != null) {
      return MediaMessageBubble(message: message, mediaData: mediaData, engine: engine!);
    }

    // Handle legacy image attachments with special bubble
    final imageData = _parseImageData();
    if (imageData != null) {
      return ImageMessageBubble(message: message, imageData: imageData);
    }

    // Handle group invitations with special bubble
    final invitationData = _parseInvitationData();
    if (invitationData != null) {
      return _InvitationBubble(message: message, invitationData: invitationData);
    }

    // Handle transfer messages with special bubble (detected by JSON tag)
    final transferData = _parseTransferData();
    if (transferData != null) {
      return _TransferBubble(message: message, transferData: transferData);
    }

    final theme = Theme.of(context);
    final isOutgoing = message.isOutgoing;
    final forwardedData = _parseForwardedData();
    final replyData = _parseReplyData();
    // Priority: reply > forwarded > plain text
    final displayText = replyData?.text ?? forwardedData?.text ?? message.plaintext;

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
            // Show reply header with quoted text if this is a reply
            if (replyData != null) ...[
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: isOutgoing
                      ? theme.colorScheme.onPrimary.withAlpha(25)
                      : theme.colorScheme.primary.withAlpha(25),
                  borderRadius: BorderRadius.circular(8),
                  border: Border(
                    left: BorderSide(
                      color: isOutgoing
                          ? theme.colorScheme.onPrimary.withAlpha(128)
                          : theme.colorScheme.primary,
                      width: 2,
                    ),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        FaIcon(
                          FontAwesomeIcons.reply,
                          size: 10,
                          color: isOutgoing
                              ? theme.colorScheme.onPrimary.withAlpha(179)
                              : theme.colorScheme.primary,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          replyData.sender,
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            color: isOutgoing
                                ? theme.colorScheme.onPrimary.withAlpha(200)
                                : theme.colorScheme.primary,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 2),
                    Text(
                      replyData.quoted.length > 80
                          ? '${replyData.quoted.substring(0, 80)}...'
                          : replyData.quoted,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontSize: 12,
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary.withAlpha(153)
                            : theme.textTheme.bodySmall?.color,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 6),
            ],
            // Show forwarded header if this is a forwarded message
            if (forwardedData != null && replyData == null) ...[
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FaIcon(
                    FontAwesomeIcons.share,
                    size: 10,
                    color: isOutgoing
                        ? theme.colorScheme.onPrimary.withAlpha(179)
                        : theme.textTheme.bodySmall?.color,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    'Forwarded from ${forwardedData.sender}',
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontSize: 11,
                      fontStyle: FontStyle.italic,
                      color: isOutgoing
                          ? theme.colorScheme.onPrimary.withAlpha(179)
                          : theme.textTheme.bodySmall?.color,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 4),
            ],
            FormattedText(
              displayText,
              selectable: true,
              style: TextStyle(
                color: isOutgoing
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurface,
              ),
            ),
            if (message.deletedBySender)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    FaIcon(
                      FontAwesomeIcons.trash,
                      size: 10,
                      color: isOutgoing
                          ? theme.colorScheme.onPrimary.withAlpha(179)
                          : DnaColors.textMuted,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      AppLocalizations.of(context).chatSenderDeletedThis,
                      style: TextStyle(
                        fontSize: 11,
                        fontStyle: FontStyle.italic,
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary.withAlpha(179)
                            : DnaColors.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
            const SizedBox(height: 4),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (isStarred) ...[
                  FaIcon(
                    FontAwesomeIcons.solidStar,
                    size: 10,
                    color: Colors.amber,
                  ),
                  const SizedBox(width: 4),
                ],
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

    if (status == MessageStatus.failed) {
      // Show tappable retry icon for failed messages
      return GestureDetector(
        onTap: onRetry,
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.circleExclamation,
              size: size - 2,
              color: DnaColors.warning,
            ),
            if (onRetry != null) ...[
              const SizedBox(width: 4),
              FaIcon(
                FontAwesomeIcons.arrowsRotate,
                size: size - 2,
                color: DnaColors.warning,
              ),
            ],
          ],
        ),
      );
    }

    // Show tappable retry for pending messages (tap clock to retry)
    if (status == MessageStatus.pending && onRetry != null) {
      return GestureDetector(
        onTap: onRetry,
        child: FaIcon(
          FontAwesomeIcons.clock,
          size: size,
          color: color,
        ),
      );
    }

    return FaIcon(
      _getStatusIcon(status),
      size: size,
      color: color,
    );
  }

  // v15: Simplified 4-state status icon
  IconData _getStatusIcon(MessageStatus status) {
    switch (status) {
      case MessageStatus.pending:
        // Clock for pending (queued, waiting for DHT PUT)
        return FontAwesomeIcons.clock;
      case MessageStatus.sent:
        // Single tick for sent (DHT PUT succeeded)
        return FontAwesomeIcons.check;
      case MessageStatus.received:
        // Double tick for received (recipient ACK'd)
        return FontAwesomeIcons.checkDouble;
      case MessageStatus.failed:
        return FontAwesomeIcons.circleExclamation;
    }
  }
}

/// Token entry for the send sheet dropdown
class _TokenOption {
  final String token;
  final String network;
  final String chain;
  final String displayName;
  final String profileField;

  const _TokenOption({
    required this.token,
    required this.network,
    required this.chain,
    required this.displayName,
    required this.profileField,
  });

  static const List<_TokenOption> all = [
    _TokenOption(token: 'CPUNK', network: 'Cellframe', chain: 'cellframe', displayName: 'CPUNK (Cellframe)', profileField: 'backbone'),
    _TokenOption(token: 'USDT', network: 'Ethereum', chain: 'ethereum', displayName: 'USDT (Ethereum)', profileField: 'eth'),
    _TokenOption(token: 'USDT', network: 'Solana', chain: 'solana', displayName: 'USDT (Solana)', profileField: 'sol'),
    _TokenOption(token: 'USDT', network: 'Tron', chain: 'tron', displayName: 'USDT (TRON)', profileField: 'trx'),
    _TokenOption(token: 'USDC', network: 'Cellframe', chain: 'cellframe', displayName: 'USDC (Cellframe)', profileField: 'backbone'),
    _TokenOption(token: 'USDC', network: 'Ethereum', chain: 'ethereum', displayName: 'USDC (Ethereum)', profileField: 'eth'),
    _TokenOption(token: 'USDC', network: 'Solana', chain: 'solana', displayName: 'USDC (Solana)', profileField: 'sol'),
    _TokenOption(token: 'USDC', network: 'Tron', chain: 'tron', displayName: 'USDC (TRON)', profileField: 'trx'),
  ];

  static List<_TokenOption> forProfile(UserProfile profile) {
    return all.where((opt) {
      switch (opt.profileField) {
        case 'backbone': return profile.backbone.isNotEmpty;
        case 'eth': return profile.eth.isNotEmpty;
        case 'sol': return profile.sol.isNotEmpty;
        case 'trx': return profile.trx.isNotEmpty;
        default: return false;
      }
    }).toList();
  }

  String getAddress(UserProfile profile) {
    switch (profileField) {
      case 'backbone': return profile.backbone;
      case 'eth': return profile.eth;
      case 'sol': return profile.sol;
      case 'trx': return profile.trx;
      default: return '';
    }
  }
}

/// 3-step animated send sheet for token transfers from chat
class _ChatSendSheet extends ConsumerStatefulWidget {
  final Contact contact;

  const _ChatSendSheet({required this.contact});

  @override
  ConsumerState<_ChatSendSheet> createState() => _ChatSendSheetState();
}

class _ChatSendSheetState extends ConsumerState<_ChatSendSheet>
    with SingleTickerProviderStateMixin {
  final _amountController = TextEditingController();
  bool _isSending = false;
  String? _sendError;
  bool _isResolving = true;
  UserProfile? _contactProfile;
  List<_TokenOption> _availableTokens = [];
  _TokenOption? _selectedToken;

  /// Current step: 0=token, 1=network, 2=amount
  int _step = 0;
  String? _selectedTokenName; // 'CPUNK', 'USDT', 'USDC'

  late AnimationController _animController;
  late Animation<double> _fadeAnim;

  @override
  void initState() {
    super.initState();
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
    _fadeAnim = CurvedAnimation(parent: _animController, curve: Curves.easeInOut);
    _animController.forward();
    _resolveContactProfile();
    // Trigger balance refresh so send sheet shows current balances
    Future.microtask(() {
      if (mounted) {
        ref.read(allBalancesProvider.notifier).refresh();
      }
    });
  }

  @override
  void dispose() {
    _amountController.dispose();
    _animController.dispose();
    super.dispose();
  }

  void _goToStep(int step) {
    _animController.reverse().then((_) {
      if (!mounted) return;
      setState(() {
        _step = step;
        _sendError = null;
      });
      _animController.forward();
    });
  }

  Future<void> _resolveContactProfile() async {
    try {
      final engine = await ref.read(engineProvider.future);
      final profile = await engine.lookupProfile(widget.contact.fingerprint);

      if (!mounted) return;

      if (profile == null) {
        setState(() => _isResolving = false);
        return;
      }

      final tokens = _TokenOption.forProfile(profile);
      setState(() {
        _isResolving = false;
        _contactProfile = profile;
        _availableTokens = tokens;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _isResolving = false);
    }
  }

  /// Get balance for a specific token+network combo (searches ALL wallets)
  String _getBalance(String token, String network) {
    final allBalances = ref.watch(allBalancesProvider);
    return allBalances.whenOrNull(
      data: (balances) {
        for (final wb in balances) {
          if (wb.balance.token == token &&
              wb.balance.network.toLowerCase() == network.toLowerCase()) {
            return wb.balance.balance;
          }
        }
        return '0';
      },
    ) ?? '0';
  }

  /// Get total balance for a token across all networks
  String _getTotalBalance(String token) {
    final networks = token == 'CPUNK'
        ? ['Cellframe']
        : ['Ethereum', 'Solana', 'Tron'];
    double total = 0;
    for (final net in networks) {
      total += double.tryParse(_getBalance(token, net)) ?? 0;
    }
    if (total == 0) return '0';
    return total < 0.01
        ? total.toStringAsFixed(8)
        : (total < 1 ? total.toStringAsFixed(4) : total.toStringAsFixed(2));
  }

  /// Get balance for the currently selected token option
  String? _getSelectedBalance() {
    if (_selectedToken == null) return null;
    final bal = _getBalance(_selectedToken!.token, _selectedToken!.network);
    return bal == '0' ? null : bal;
  }

  double? _calculateMaxAmount() {
    final balanceStr = _getSelectedBalance();
    if (balanceStr == null || balanceStr.isEmpty) return null;
    final balance = double.tryParse(balanceStr);
    if (balance == null || balance <= 0) return null;
    return balance;
  }

  bool _canSend() {
    if (_isSending || _isResolving) return false;
    if (_selectedToken == null || _contactProfile == null) return false;
    if (_amountController.text.trim().isEmpty) return false;
    final amount = double.tryParse(_amountController.text.trim());
    if (amount == null || amount <= 0) return false;
    return true;
  }

  Future<void> _send() async {
    setState(() {
      _sendError = null;
      _isSending = true;
    });

    final amountStr = _amountController.text.trim();
    final amount = double.tryParse(amountStr);
    final maxAmount = _calculateMaxAmount();

    if (amount == null || amount <= 0) {
      setState(() {
        _isSending = false;
        _sendError = AppLocalizations.of(context).chatInvalidAmount;
      });
      return;
    }

    if (maxAmount != null && amount > maxAmount) {
      setState(() {
        _isSending = false;
        _sendError = AppLocalizations.of(context).chatInsufficientBalance(_selectedToken!.token);
      });
      return;
    }

    try {
      final recipientAddress = _selectedToken!.getAddress(_contactProfile!);
      final txHash = await ref.read(walletsProvider.notifier).sendTokens(
        walletIndex: 0,
        recipientAddress: recipientAddress,
        amount: amountStr,
        token: _selectedToken!.token,
        network: _selectedToken!.network,
        gasSpeed: 1,
      );

      if (mounted) {
        final transferData = jsonEncode({
          'type': 'token_transfer',
          'amount': amountStr,
          'token': _selectedToken!.token,
          'network': _selectedToken!.network,
          'chain': _selectedToken!.chain,
          'txHash': txHash,
          'recipientAddress': recipientAddress,
          'recipientName': widget.contact.displayName,
        });

        ref.read(conversationProvider(widget.contact.fingerprint).notifier)
            .sendMessage(transferData);

        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppLocalizations.of(context).chatSentSuccess(amountStr, _selectedToken!.token)),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        final message = e is DnaEngineException ? e.message : e.toString();
        setState(() {
          _isSending = false;
          _sendError = message;
        });
      }
    }
  }

  void _selectToken(String tokenName) {
    _selectedTokenName = tokenName;
    if (tokenName == 'CPUNK') {
      // CPUNK has only Cellframe — skip network step
      _selectedToken = _availableTokens.firstWhere(
        (t) => t.token == 'CPUNK',
        orElse: () => _availableTokens.first,
      );
      _goToStep(2);
    } else {
      _goToStep(1);
    }
  }

  void _selectNetwork(String network) {
    _selectedToken = _availableTokens.firstWhere(
      (t) => t.token == _selectedTokenName && t.network == network,
      orElse: () => _availableTokens.first,
    );
    _goToStep(2);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final contactName = widget.contact.displayName.isNotEmpty
        ? widget.contact.displayName
        : 'contact';

    final totalSteps = _selectedTokenName == 'CPUNK' ? '2' : '3';
    final currentStep = _selectedTokenName == 'CPUNK'
        ? (_step == 0 ? '1' : '2')
        : '${_step + 1}';

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Padding(
        padding: EdgeInsets.only(
          left: 24,
          right: 24,
          top: 16,
          bottom: MediaQuery.of(context).viewInsets.bottom + 24,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Drag handle
            Container(
              width: 40,
              height: 4,
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(
                color: theme.colorScheme.onSurface.withAlpha(40),
                borderRadius: BorderRadius.circular(2),
              ),
            ),

            // Header with back button
            Row(
              children: [
                if (_step > 0)
                  IconButton(
                    icon: FaIcon(FontAwesomeIcons.arrowLeft, size: 18,
                      color: theme.colorScheme.primary),
                    onPressed: () {
                      if (_step == 2 && _selectedTokenName == 'CPUNK') {
                        _goToStep(0);
                      } else {
                        _goToStep(_step - 1);
                      }
                    },
                  )
                else
                  const SizedBox(width: 48),
                Expanded(
                  child: Column(
                    children: [
                      Text(
                        l10n.chatSendTokensTo(contactName),
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      if (!_isResolving && _availableTokens.isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.only(top: 4),
                          child: Text(
                            l10n.chatStepOf(currentStep, totalSteps),
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.primary,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
                IconButton(
                  icon: FaIcon(FontAwesomeIcons.xmark, size: 18,
                    color: theme.colorScheme.onSurface.withAlpha(150)),
                  onPressed: () => Navigator.pop(context),
                ),
              ],
            ),

            // Step progress indicator
            if (!_isResolving && _availableTokens.isNotEmpty) ...[
              const SizedBox(height: 12),
              _buildProgressBar(theme),
            ],

            const SizedBox(height: 20),

            // Content with fade animation
            if (_isResolving)
              _buildLoading(l10n)
            else if (_availableTokens.isEmpty)
              _buildNoWallets(l10n, theme)
            else
              FadeTransition(
                opacity: _fadeAnim,
                child: _step == 0
                    ? _buildTokenStep(theme, l10n, isDark)
                    : _step == 1
                        ? _buildNetworkStep(theme, l10n, isDark)
                        : _buildAmountStep(theme, l10n),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildProgressBar(ThemeData theme) {
    final steps = _selectedTokenName == 'CPUNK' ? 2 : 3;
    final activeStep = _selectedTokenName == 'CPUNK'
        ? (_step == 0 ? 0 : 1)
        : _step;
    return Row(
      children: List.generate(steps, (i) {
        final isActive = i <= activeStep;
        return Expanded(
          child: Container(
            height: 3,
            margin: EdgeInsets.only(right: i < steps - 1 ? 4 : 0),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(2),
              color: isActive
                  ? theme.colorScheme.primary
                  : theme.colorScheme.onSurface.withAlpha(30),
            ),
          ),
        );
      }),
    );
  }

  Widget _buildLoading(AppLocalizations l10n) {
    return Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 16),
          Text(l10n.chatLookingUpWallets),
        ],
      ),
    );
  }

  Widget _buildNoWallets(AppLocalizations l10n, ThemeData theme) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: DnaColors.warning.withAlpha(20),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          FaIcon(FontAwesomeIcons.circleExclamation, color: DnaColors.warning),
          const SizedBox(width: 12),
          Expanded(
            child: Text(l10n.chatNoWalletAddresses,
                style: TextStyle(color: DnaColors.warning)),
          ),
        ],
      ),
    );
  }

  /// Step 1: Token selection
  Widget _buildTokenStep(ThemeData theme, AppLocalizations l10n, bool isDark) {
    final tokens = ['CPUNK', 'USDT', 'USDC'];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(l10n.chatSelectToken,
            style: theme.textTheme.bodySmall?.copyWith(
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5,
              color: theme.colorScheme.onSurface.withAlpha(150),
            )),
        const SizedBox(height: 12),
        ...tokens.map((token) {
          final balance = _getTotalBalance(token);
          final hasBalance = balance != '0';
          return Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: _SendOptionCard(
              icon: _tokenIcon(token),
              iconColor: _tokenColor(token),
              title: token,
              subtitle: hasBalance ? balance : '0.00',
              isDark: isDark,
              onTap: () => _selectToken(token),
            ),
          );
        }),
      ],
    );
  }

  /// Step 2: Network selection (USDT/USDC only)
  Widget _buildNetworkStep(ThemeData theme, AppLocalizations l10n, bool isDark) {
    final networks = [
      ('Ethereum', 'ERC-20'),
      ('Solana', 'Solana'),
      ('Tron', 'TRC-20'),
    ];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(l10n.chatSelectNetwork,
            style: theme.textTheme.bodySmall?.copyWith(
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5,
              color: theme.colorScheme.onSurface.withAlpha(150),
            )),
        const SizedBox(height: 12),
        ...networks.where((net) {
          // Hide networks with 0 balance
          final bal = _getBalance(_selectedTokenName!, net.$1);
          return (double.tryParse(bal) ?? 0) > 0;
        }).map((net) {
          final balance = _getBalance(_selectedTokenName!, net.$1);
          return Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: _SendOptionCard(
              icon: _networkIcon(net.$1),
              iconColor: _networkColor(net.$1),
              title: net.$2,
              subtitle: balance,
              isDark: isDark,
              onTap: () => _selectNetwork(net.$1),
            ),
          );
        }),
      ],
    );
  }

  /// Step 3: Amount + Send
  Widget _buildAmountStep(ThemeData theme, AppLocalizations l10n) {
    final balance = _getSelectedBalance();
    final maxAmount = _calculateMaxAmount();
    final networkLabel = _selectedToken?.network == 'Ethereum'
        ? 'ERC-20'
        : _selectedToken?.network == 'Tron'
            ? 'TRC-20'
            : _selectedToken?.network ?? '';
    final tokenLabel = _selectedTokenName == 'CPUNK'
        ? 'CPUNK'
        : '$_selectedTokenName ($networkLabel)';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Selected token display
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            color: theme.colorScheme.primary.withAlpha(15),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: theme.colorScheme.primary.withAlpha(40)),
          ),
          child: Row(
            children: [
              FaIcon(_tokenIcon(_selectedTokenName ?? 'CPUNK'),
                  size: 20, color: _tokenColor(_selectedTokenName ?? 'CPUNK')),
              const SizedBox(width: 12),
              Text(tokenLabel,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                  )),
              const Spacer(),
              if (balance != null)
                Text(
                  '$balance ${_selectedToken?.token ?? ''}',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withAlpha(150),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 20),

        // Amount input
        TextField(
          controller: _amountController,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          autofocus: true,
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.w600,
          ),
          decoration: InputDecoration(
            hintText: '0.00',
            hintStyle: theme.textTheme.headlineSmall?.copyWith(
              color: theme.colorScheme.onSurface.withAlpha(60),
              fontWeight: FontWeight.w600,
            ),
            suffixText: _selectedToken?.token ?? '',
            suffixStyle: theme.textTheme.titleMedium?.copyWith(
              color: theme.colorScheme.primary,
              fontWeight: FontWeight.w600,
            ),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
            ),
            contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
          ),
          onChanged: (_) => setState(() {}),
        ),
        const SizedBox(height: 8),

        // Max button
        if (maxAmount != null && maxAmount > 0)
          Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              onPressed: () {
                _amountController.text = maxAmount.toStringAsFixed(
                  maxAmount < 0.01 ? 8 : (maxAmount < 1 ? 4 : 2),
                );
                setState(() {});
              },
              icon: FaIcon(FontAwesomeIcons.arrowUp, size: 12,
                  color: theme.colorScheme.primary),
              label: Text(l10n.chatSendMax),
            ),
          ),
        const SizedBox(height: 12),

        // Error display
        if (_sendError != null)
          Container(
            padding: const EdgeInsets.all(12),
            margin: const EdgeInsets.only(bottom: 12),
            decoration: BoxDecoration(
              color: DnaColors.error.withAlpha(15),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: DnaColors.error.withAlpha(40)),
            ),
            child: Row(
              children: [
                FaIcon(FontAwesomeIcons.circleExclamation,
                    color: DnaColors.error, size: 16),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(_sendError!,
                      style: TextStyle(color: DnaColors.error, fontSize: 13)),
                ),
              ],
            ),
          ),

        // Send button with gradient
        Container(
          height: 50,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            gradient: _canSend()
                ? LinearGradient(
                    colors: [
                      theme.colorScheme.primary,
                      theme.colorScheme.primary.withAlpha(200),
                    ],
                  )
                : null,
            color: _canSend() ? null : theme.colorScheme.onSurface.withAlpha(30),
          ),
          child: Material(
            color: Colors.transparent,
            child: InkWell(
              borderRadius: BorderRadius.circular(12),
              onTap: _canSend() ? _send : null,
              child: Center(
                child: _isSending
                    ? SizedBox(
                        width: 22,
                        height: 22,
                        child: CircularProgressIndicator(
                          strokeWidth: 2.5,
                          color: theme.colorScheme.onPrimary,
                        ),
                      )
                    : Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          FaIcon(FontAwesomeIcons.paperPlane, size: 16,
                              color: _canSend()
                                  ? theme.colorScheme.onPrimary
                                  : theme.colorScheme.onSurface.withAlpha(100)),
                          const SizedBox(width: 10),
                          Text(
                            l10n.chatSendButton(_selectedToken?.token ?? 'Tokens'),
                            style: TextStyle(
                              color: _canSend()
                                  ? theme.colorScheme.onPrimary
                                  : theme.colorScheme.onSurface.withAlpha(100),
                              fontWeight: FontWeight.w600,
                              fontSize: 16,
                            ),
                          ),
                        ],
                      ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  IconData _tokenIcon(String token) {
    switch (token) {
      case 'CPUNK': return FontAwesomeIcons.coins;
      case 'USDT': return FontAwesomeIcons.dollarSign;
      case 'USDC': return FontAwesomeIcons.dollarSign;
      default: return FontAwesomeIcons.coins;
    }
  }

  Color _tokenColor(String token) {
    switch (token) {
      case 'CPUNK': return const Color(0xFF8B5CF6);
      case 'USDT': return const Color(0xFF26A17B);
      case 'USDC': return const Color(0xFF2775CA);
      default: return Colors.grey;
    }
  }

  IconData _networkIcon(String network) {
    switch (network) {
      case 'Ethereum': return FontAwesomeIcons.ethereum;
      case 'Solana': return FontAwesomeIcons.bolt;
      case 'Tron': return FontAwesomeIcons.bolt;
      default: return FontAwesomeIcons.networkWired;
    }
  }

  Color _networkColor(String network) {
    switch (network) {
      case 'Ethereum': return const Color(0xFF627EEA);
      case 'Solana': return const Color(0xFF9945FF);
      case 'Tron': return const Color(0xFFEB0029);
      default: return Colors.grey;
    }
  }
}

/// Reusable card button for token/network selection
class _SendOptionCard extends StatelessWidget {
  final IconData icon;
  final Color iconColor;
  final String title;
  final String subtitle;
  final bool isDark;
  final VoidCallback onTap;

  const _SendOptionCard({
    required this.icon,
    required this.iconColor,
    required this.title,
    required this.subtitle,
    required this.isDark,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 200),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            color: isDark
                ? Colors.white.withAlpha(8)
                : Colors.black.withAlpha(5),
            border: Border.all(
              color: isDark
                  ? Colors.white.withAlpha(15)
                  : Colors.black.withAlpha(10),
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  color: iconColor.withAlpha(25),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Center(
                  child: FaIcon(icon, size: 18, color: iconColor),
                ),
              ),
              const SizedBox(width: 14),
              Text(title,
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  )),
              const Spacer(),
              Text(subtitle,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurface.withAlpha(150),
                    fontWeight: FontWeight.w500,
                  )),
              const SizedBox(width: 8),
              FaIcon(FontAwesomeIcons.chevronRight, size: 12,
                  color: theme.colorScheme.onSurface.withAlpha(80)),
            ],
          ),
        ),
      ),
    );
  }
}

/// Special bubble for group invitation messages
class _InvitationBubble extends ConsumerStatefulWidget {
  final Message message;
  final Map<String, dynamic> invitationData;

  const _InvitationBubble({required this.message, required this.invitationData});

  @override
  ConsumerState<_InvitationBubble> createState() => _InvitationBubbleState();
}

class _InvitationBubbleState extends ConsumerState<_InvitationBubble> {
  bool _isProcessing = false;

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 16) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }

  Future<void> _acceptInvitation(String groupUuid, String groupName) async {
    setState(() => _isProcessing = true);
    try {
      await ref.read(invitationsProvider.notifier).acceptInvitation(groupUuid);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Joined "$groupName"')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to accept: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<void> _declineInvitation(String groupUuid) async {
    setState(() => _isProcessing = true);
    try {
      await ref.read(invitationsProvider.notifier).rejectInvitation(groupUuid);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invitation declined')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to decline: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOutgoing = widget.message.isOutgoing;
    final data = widget.invitationData;

    // Extract invitation data - try both formats (with/without underscores)
    final groupUuid = (data['group_uuid'] ?? data['groupuuid'] ?? '') as String;
    final groupName = (data['group_name'] ?? data['groupname'] ?? 'Unknown Group') as String;
    final inviter = (data['inviter'] ?? widget.message.sender) as String;
    final memberCount = (data['member_count'] ?? data['membercount'] ?? 0) as int;

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(
          top: 4,
          bottom: 4,
          left: isOutgoing ? 48 : 0,
          right: isOutgoing ? 0 : 48,
        ),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [
              theme.colorScheme.secondary.withAlpha(30),
              theme.colorScheme.primary.withAlpha(20),
            ],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 16),
          ),
          border: Border.all(color: theme.colorScheme.secondary.withAlpha(60)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header with icon
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                CircleAvatar(
                  radius: 16,
                  backgroundColor: theme.colorScheme.secondary.withAlpha(40),
                  child: FaIcon(
                    FontAwesomeIcons.userGroup,
                    size: 14,
                    color: theme.colorScheme.secondary,
                  ),
                ),
                const SizedBox(width: 8),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Group Invitation',
                      style: theme.textTheme.labelSmall?.copyWith(
                        color: theme.colorScheme.secondary,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    if (!isOutgoing)
                      Text(
                        'From ${_shortenFingerprint(inviter)}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontSize: 10,
                          color: theme.textTheme.bodySmall?.color,
                        ),
                      ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 10),

            // Group name
            Text(
              groupName,
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            if (memberCount > 0)
              Text(
                '$memberCount member${memberCount == 1 ? '' : 's'}',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.textTheme.bodySmall?.color,
                ),
              ),

            // Accept/Decline buttons (only for incoming invitations)
            if (!isOutgoing && groupUuid.isNotEmpty) ...[
              const SizedBox(height: 12),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextButton(
                    onPressed: _isProcessing ? null : () => _declineInvitation(groupUuid),
                    child: const Text('Decline'),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: _isProcessing ? null : () => _acceptInvitation(groupUuid, groupName),
                    child: _isProcessing
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Text('Accept'),
                  ),
                ],
              ),
            ],

            // Timestamp
            const SizedBox(height: 6),
            Text(
              DateFormat.jm().format(widget.message.timestamp),
              style: theme.textTheme.bodySmall?.copyWith(
                fontSize: 10,
                color: theme.textTheme.bodySmall?.color,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Special bubble for token transfer messages with blockchain verification
class _TransferBubble extends StatefulWidget {
  final Message message;
  final Map<String, dynamic> transferData;

  const _TransferBubble({required this.message, required this.transferData});

  @override
  State<_TransferBubble> createState() => _TransferBubbleState();
}

class _TransferBubbleState extends State<_TransferBubble> {
  // Static cache: once verified(1) or denied(2), never re-check via FFI.
  // Survives widget rebuilds and navigation within the same app session.
  static final Map<String, int> _verifiedCache = {};

  /// 0=pending, 1=verified, 2=denied
  int _verificationStatus = 0;
  bool _isVerifying = false;
  Timer? _retryTimer;
  int _retryCount = 0;
  static const int _maxRetries = 6;
  static const Duration _retryInterval = Duration(seconds: 10);
  static const Duration _initialDelay = Duration(seconds: 5);

  @override
  void initState() {
    super.initState();

    // Check in-memory cache first — skip FFI for already-verified TXs
    final txHash = widget.transferData['txHash'] as String?;
    if (txHash != null && _verifiedCache.containsKey(txHash)) {
      _verificationStatus = _verifiedCache[txHash]!;
      return;  // No FFI call needed
    }

    // Outgoing transfers sent in the last 30s: delay to let blockchain process
    // Everything else (incoming + old outgoing): verify immediately
    final isRecent = DateTime.now().difference(widget.message.timestamp).inSeconds < 30;
    if (widget.message.isOutgoing && isRecent) {
      _retryTimer = Timer(_initialDelay, _verifyTransaction);
    } else {
      _verifyTransaction();
    }
  }

  @override
  void dispose() {
    _retryTimer?.cancel();
    super.dispose();
  }

  Future<void> _verifyTransaction() async {
    final txHash = widget.transferData['txHash'] as String?;
    final chain = widget.transferData['chain'] as String? ?? 'cellframe';
    if (txHash == null || txHash.isEmpty) return;

    // Already in a final state — no need to re-check
    if (_verificationStatus == 1 || _verificationStatus == 2) return;

    if (_isVerifying) return;
    setState(() { _isVerifying = true; });

    try {
      final container = ProviderScope.containerOf(context);
      final engine = container.read(engineProvider).valueOrNull;
      if (engine == null) {
        logError('TRANSFER', 'Engine not available for tx verification');
        setState(() { _isVerifying = false; });
        return;
      }

      final status = await engine.getTxStatus(txHash: txHash, chain: chain);
      if (mounted) {
        setState(() {
          _verificationStatus = status;
          _isVerifying = false;
        });

        // Cache final states — no need to re-check on future widget rebuilds
        if (status == 1 || status == 2) {
          _verifiedCache[txHash] = status;
        }

        // Auto-retry if still pending
        if (status == 0 && _retryCount < _maxRetries) {
          _retryCount++;
          _retryTimer?.cancel();
          _retryTimer = Timer(_retryInterval, _verifyTransaction);
        }
      }
    } catch (e) {
      logError('TRANSFER', e);
      if (mounted) {
        setState(() { _isVerifying = false; });
      }
    }
  }

  Color _getBorderColor() {
    switch (_verificationStatus) {
      case 1: return Colors.green;
      case 2: return Colors.red;
      default: return Colors.orange;
    }
  }

  IconData _getStatusIcon() {
    switch (_verificationStatus) {
      case 1: return FontAwesomeIcons.circleCheck;
      case 2: return FontAwesomeIcons.circleXmark;
      default: return FontAwesomeIcons.clock;
    }
  }

  String _getStatusText() {
    switch (_verificationStatus) {
      case 1: return 'Verified';
      case 2: return 'Failed';
      default: return 'Pending';
    }
  }

  void _showTransferInfo() async {
    await _verifyTransaction();
    if (!mounted) return;

    final theme = Theme.of(context);
    final amount = widget.transferData['amount'] ?? '?';
    final token = widget.transferData['token'] ?? 'CPUNK';
    final network = widget.transferData['network'] ?? 'Cellframe';
    final txHash = widget.transferData['txHash'] as String?;
    final recipientName = widget.transferData['recipientName'] as String?;
    final isOutgoing = widget.message.isOutgoing;
    final fullTimestamp = DateFormat('MMMM d, y \'at\' HH:mm:ss').format(widget.message.timestamp);

    final statusText = _getStatusText();
    final statusIcon = _getStatusIcon();
    final statusColor = _getBorderColor();

    showModalBottomSheet(
      context: context,
      builder: (ctx) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  FaIcon(FontAwesomeIcons.arrowRightArrowLeft, size: 18, color: theme.colorScheme.primary),
                  const SizedBox(width: 8),
                  Text('Token Transfer', style: theme.textTheme.titleMedium),
                ],
              ),
              const Divider(height: 24),
              _transferInfoRow(theme, FontAwesomeIcons.coins, 'Amount', '$amount $token'),
              const SizedBox(height: 12),
              _transferInfoRow(theme, FontAwesomeIcons.networkWired, 'Network', network),
              const SizedBox(height: 12),
              _transferInfoRow(
                theme,
                isOutgoing ? FontAwesomeIcons.arrowUp : FontAwesomeIcons.arrowDown,
                'Direction',
                isOutgoing ? 'Sent${recipientName != null ? ' to $recipientName' : ''}' : 'Received',
              ),
              const SizedBox(height: 12),
              _transferInfoRow(theme, FontAwesomeIcons.clock, 'Time', fullTimestamp),
              const SizedBox(height: 12),
              _transferInfoRow(theme, statusIcon, 'Blockchain Status', statusText, iconColor: statusColor),
              if (txHash != null && txHash.isNotEmpty) ...[
                const SizedBox(height: 12),
                GestureDetector(
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: txHash));
                    ScaffoldMessenger.of(ctx).showSnackBar(
                      SnackBar(content: Text('Copied: $txHash'), backgroundColor: DnaColors.snackbarSuccess, duration: const Duration(seconds: 3)),
                    );
                  },
                  child: _transferInfoRow(theme, FontAwesomeIcons.fingerprint, 'Tx Hash', txHash, mono: true),
                ),
              ],
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
    );
  }

  Widget _transferInfoRow(ThemeData theme, IconData icon, String label, String value, {Color? iconColor, bool mono = false}) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(width: 24, child: FaIcon(icon, size: 14, color: iconColor ?? theme.textTheme.bodySmall?.color)),
        const SizedBox(width: 8),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label, style: theme.textTheme.bodySmall),
              Text(value, style: mono
                  ? theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 11)
                  : theme.textTheme.bodyMedium),
            ],
          ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOutgoing = widget.message.isOutgoing;

    final amount = widget.transferData['amount'] ?? '?';
    final token = widget.transferData['token'] ?? 'CPUNK';
    final txHash = widget.transferData['txHash'] as String?;
    final borderColor = _getBorderColor();

    // Shorten tx hash for display (e.g., 0xABC...XYZ)
    String? shortTxHash;
    if (txHash != null && txHash.length > 16) {
      shortTxHash = '${txHash.substring(0, 10)}...${txHash.substring(txHash.length - 6)}';
    } else {
      shortTxHash = txHash;
    }

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        onTap: _showTransferInfo,
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
                  ? [theme.colorScheme.primary.withAlpha(200), theme.colorScheme.secondary.withAlpha(150)]
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
            border: Border.all(color: borderColor, width: 2),
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
                        : theme.colorScheme.primary,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    isOutgoing ? 'Sent' : 'Received',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: isOutgoing
                          ? theme.colorScheme.onPrimary.withAlpha(200)
                          : theme.textTheme.bodySmall?.color,
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
                      : theme.colorScheme.primary,
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
                              : theme.textTheme.bodySmall?.color,
                        ),
                      ),
                      const SizedBox(width: 4),
                      FaIcon(
                        FontAwesomeIcons.copy,
                        size: 10,
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary.withAlpha(150)
                            : theme.textTheme.bodySmall?.color,
                      ),
                    ],
                  ),
                ),
              ],
              const SizedBox(height: 4),

              // Timestamp, verification status, and message status
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    DateFormat('HH:mm').format(widget.message.timestamp),
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontSize: 10,
                      color: isOutgoing
                          ? theme.colorScheme.onPrimary.withAlpha(179)
                          : theme.textTheme.bodySmall?.color,
                    ),
                  ),
                  const SizedBox(width: 6),
                  // Verification status indicator
                  if (_isVerifying)
                    SizedBox(
                      width: 12,
                      height: 12,
                      child: CircularProgressIndicator(
                        strokeWidth: 1.5,
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary.withAlpha(179)
                            : theme.textTheme.bodySmall?.color,
                      ),
                    )
                  else
                    FaIcon(
                      _getStatusIcon(),
                      size: 12,
                      color: borderColor,
                    ),
                  const SizedBox(width: 3),
                  Text(
                    _isVerifying ? 'Checking...' : _getStatusText(),
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontSize: 9,
                      color: _isVerifying
                          ? (isOutgoing
                              ? theme.colorScheme.onPrimary.withAlpha(179)
                              : theme.textTheme.bodySmall?.color)
                          : borderColor,
                    ),
                  ),
                  if (isOutgoing) ...[
                    const SizedBox(width: 4),
                    // Message delivery status icon
                    FaIcon(
                      widget.message.status == MessageStatus.pending
                          ? FontAwesomeIcons.clock
                          : (widget.message.status == MessageStatus.sent
                              ? FontAwesomeIcons.check
                              : (widget.message.status == MessageStatus.failed
                                  ? FontAwesomeIcons.circleExclamation
                                  : FontAwesomeIcons.checkDouble)),
                      size: 14,
                      color: widget.message.status == MessageStatus.failed
                          ? DnaColors.warning
                          : theme.colorScheme.onPrimary.withAlpha(179),
                    ),
                  ],
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
