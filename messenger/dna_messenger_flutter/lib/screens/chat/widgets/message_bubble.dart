// Message Bubble Wrapper - Adds desktop context menu, RepaintBoundary, and animations
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
/// - Entry animation: slide + fade when first built
class MessageBubbleWrapper extends StatefulWidget {
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

  /// Whether to animate this bubble (only for new messages)
  final bool animate;

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
    this.animate = false,
  });

  @override
  State<MessageBubbleWrapper> createState() => _MessageBubbleWrapperState();
}

class _MessageBubbleWrapperState extends State<MessageBubbleWrapper>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<double> _fadeAnimation;
  late final Animation<Offset> _slideAnimation;

  static bool get _isDesktop =>
      Platform.isLinux || Platform.isWindows || Platform.isMacOS;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(milliseconds: 200),
      vsync: this,
    );

    _fadeAnimation = CurvedAnimation(
      parent: _controller,
      curve: Curves.easeOut,
    );

    // Slide from bottom for outgoing, from top for incoming
    final slideBegin = widget.message.isOutgoing
        ? const Offset(0.0, 0.3)  // Slide up from below
        : const Offset(0.0, -0.3); // Slide down from above

    _slideAnimation = Tween<Offset>(
      begin: slideBegin,
      end: Offset.zero,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: Curves.easeOutCubic,
    ));

    // Only animate if requested (new messages only)
    if (widget.animate) {
      _controller.forward();
    } else {
      // Skip to end for existing messages
      _controller.value = 1.0;
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // Wrap in RepaintBoundary to isolate rebuilds from other messages
    return RepaintBoundary(
      child: FadeTransition(
        opacity: _fadeAnimation,
        child: SlideTransition(
          position: _slideAnimation,
          child: GestureDetector(
            onTap: widget.onTap,
            onLongPress: widget.onLongPress,
            // Desktop right-click context menu
            onSecondaryTapUp: _isDesktop
                ? (details) => _showContextMenu(context, details.globalPosition)
                : null,
            child: widget.child,
          ),
        ),
      ),
    );
  }

  void _showContextMenu(BuildContext context, Offset position) {
    MessageContextMenu.show(
      context: context,
      position: position,
      isStarred: widget.isStarred,
      onReply: () => widget.onReply(widget.message),
      onCopy: () => widget.onCopy(widget.message),
      onForward: () => widget.onForward(widget.message),
      onStar: () => widget.onStar(widget.message),
      onDelete: () => widget.onDelete(widget.message),
      onRetry: widget.onRetry != null && widget.message.isOutgoing &&
              (widget.message.status == MessageStatus.failed ||
                  widget.message.status == MessageStatus.pending)
          ? widget.onRetry
          : null,
    );
  }
}
