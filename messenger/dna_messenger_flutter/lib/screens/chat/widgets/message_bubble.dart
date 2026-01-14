// Message Bubble Wrapper - Adds desktop context menu and RepaintBoundary
import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import '../../../ffi/dna_engine.dart';
import 'message_context_menu.dart';

/// Callback type for message actions
typedef MessageCallback = void Function(Message message);

/// Interactive wrapper that adds platform-aware gestures to message bubbles:
/// - Desktop: Right-click shows context menu
/// - Mobile: Long-press shows bottom sheet (delegated to onLongPress)
/// - Both: Tap shows message info (delegated to onTap)
/// - RepaintBoundary isolates rebuilds from other messages
class MessageBubbleWrapper extends StatelessWidget {
  /// The message widget to wrap (any bubble type)
  final Widget child;

  /// The message data for action callbacks
  final Message message;

  /// Whether the message is starred
  final bool isStarred;

  /// Tap handler (shows message info)
  final VoidCallback? onTap;

  /// Long-press handler (shows bottom sheet on mobile)
  final VoidCallback? onLongPress;

  /// Retry handler for failed/pending messages
  final VoidCallback? onRetry;

  /// Reply action
  final MessageCallback onReply;

  /// Copy action
  final MessageCallback onCopy;

  /// Forward action
  final MessageCallback onForward;

  /// Star/unstar action
  final MessageCallback onStar;

  /// Delete action
  final MessageCallback onDelete;

  const MessageBubbleWrapper({
    super.key,
    required this.child,
    required this.message,
    required this.isStarred,
    required this.onReply,
    required this.onCopy,
    required this.onForward,
    required this.onStar,
    required this.onDelete,
    this.onTap,
    this.onLongPress,
    this.onRetry,
  });

  static bool get _isDesktop =>
      Platform.isLinux || Platform.isWindows || Platform.isMacOS;

  @override
  Widget build(BuildContext context) {
    // Wrap in RepaintBoundary to isolate rebuilds from other messages
    return RepaintBoundary(
      child: GestureDetector(
        onTap: onTap,
        onLongPress: onLongPress,
        // Desktop right-click context menu
        onSecondaryTapUp: _isDesktop
            ? (details) => _showContextMenu(context, details.globalPosition)
            : null,
        child: child,
      ),
    );
  }

  void _showContextMenu(BuildContext context, Offset position) {
    MessageContextMenu.show(
      context: context,
      position: position,
      isStarred: isStarred,
      onReply: () => onReply(message),
      onCopy: () => onCopy(message),
      onForward: () => onForward(message),
      onStar: () => onStar(message),
      onDelete: () => onDelete(message),
      onRetry: onRetry != null && message.isOutgoing &&
              (message.status == MessageStatus.failed ||
                  message.status == MessageStatus.pending ||
                  message.status == MessageStatus.stale)
          ? onRetry
          : null,
    );
  }
}
