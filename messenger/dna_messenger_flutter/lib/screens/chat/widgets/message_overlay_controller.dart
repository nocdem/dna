import 'dart:async';

import 'package:flutter/material.dart';

import '../../../ffi/dna_engine.dart';
import 'message_action_card.dart';
import 'reaction_emoji_bar.dart';

/// Shows a Telegram-style floating overlay for a message:
///   - Pill-shape emoji reaction bar above the message
///   - Dimmed backdrop (tap to dismiss)
///   - Action card below (or above) the message with Reply/Copy/Forward/Star/
///     Delete + embedded details (timestamp, direction, status).
///
/// The selected message is anchored via the [messageKey] GlobalKey so the
/// overlay can position itself relative to the bubble's screen rect.
///
/// Returns once the overlay is dismissed (backdrop tap or action selection).
Future<void> showMessageOverlay({
  required BuildContext context,
  required GlobalKey messageKey,
  required Message message,
  required String contactName,
  required bool isStarred,
  required Set<String> currentUserEmojis,
  required void Function(String emoji) onEmojiTap,
  required VoidCallback onReply,
  required VoidCallback onCopy,
  required VoidCallback onForward,
  required VoidCallback onStar,
  required VoidCallback onDelete,
}) async {
  final overlay = Overlay.of(context);
  final renderBox =
      messageKey.currentContext?.findRenderObject() as RenderBox?;
  if (renderBox == null) return;

  final messagePos = renderBox.localToGlobal(Offset.zero);
  final messageSize = renderBox.size;
  final screenSize = MediaQuery.of(context).size;
  final padding = MediaQuery.of(context).padding;

  // Visual scale for both pill and action card. Transform.scale paints the
  // widgets smaller without changing their layout box; the height constants
  // below are reduced to match so the cardGoesBelow heuristic stays correct.
  const overlayScale = 0.75;

  // Estimated layout constants (already scaled to overlayScale).
  const pillHeight = 56.0 * overlayScale;
  const cardHeightEstimate = 340.0 * overlayScale;
  const gap = 8.0;

  final spaceBelow =
      screenSize.height - (messagePos.dy + messageSize.height) - padding.bottom;
  final cardGoesBelow = spaceBelow > cardHeightEstimate + gap;

  final completer = Completer<void>();
  late final OverlayEntry entry;

  void close() {
    if (entry.mounted) {
      entry.remove();
    }
    if (!completer.isCompleted) {
      completer.complete();
    }
  }

  entry = OverlayEntry(
    builder: (overlayContext) {
      // BackButtonListener intercepts the Android system back button so the
      // overlay dismisses cleanly instead of being orphaned when the chat
      // route is popped. Returning true consumes the event.
      return BackButtonListener(
        onBackButtonPressed: () async {
          close();
          return true;
        },
        child: Stack(
          children: [
            // Dim backdrop — tap to dismiss.
            Positioned.fill(
              child: GestureDetector(
                behavior: HitTestBehavior.opaque,
                onTap: close,
                child: Container(color: Colors.black.withValues(alpha: 0.55)),
              ),
            ),
            // Pill-shape emoji bar above the message.
            Positioned(
              left: 0,
              right: 0,
              top: (messagePos.dy - pillHeight - gap)
                  .clamp(padding.top + 8, double.infinity),
              child: Center(
                child: Transform.scale(
                  scale: overlayScale,
                  alignment: Alignment.center,
                  child: ReactionEmojiBar(
                    currentUserEmojis: currentUserEmojis,
                    onSelected: (emoji) {
                      close();
                      onEmojiTap(emoji);
                    },
                  ),
                ),
              ),
            ),
            // Action card below the message (or above if there's not enough
            // room below).
            Positioned(
              left: 16,
              right: 16,
              top: cardGoesBelow
                  ? messagePos.dy + messageSize.height + gap
                  : (messagePos.dy - cardHeightEstimate - pillHeight - (gap * 2))
                      .clamp(padding.top + pillHeight + gap + 8, double.infinity),
              child: Transform.scale(
                scale: overlayScale,
                alignment: Alignment.topCenter,
                child: MessageActionCard(
                  message: message,
                  contactName: contactName,
                  isStarred: isStarred,
                  onReply: () {
                    close();
                    onReply();
                  },
                  onCopy: () {
                    close();
                    onCopy();
                  },
                  onForward: () {
                    close();
                    onForward();
                  },
                  onStar: () {
                    close();
                    onStar();
                  },
                  onDelete: () {
                    close();
                    onDelete();
                  },
                ),
              ),
            ),
          ],
        ),
      );
    },
  );

  overlay.insert(entry);
  return completer.future;
}
