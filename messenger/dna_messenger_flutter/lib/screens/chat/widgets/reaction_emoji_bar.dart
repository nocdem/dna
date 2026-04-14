import 'package:flutter/material.dart';

/// The 8 preset reaction emojis. Order is intentional — most common first.
/// These are glyph "icons", not user-facing strings, so they are not localized.
const List<String> kReactionEmojis = [
  '\u2764\ufe0f', // ❤️ heart
  '\ud83d\udc4d', // 👍 thumbs up
  '\ud83d\ude02', // 😂 joy
  '\ud83d\ude2e', // 😮 open mouth
  '\ud83d\ude22', // 😢 cry
  '\ud83d\ude4f', // 🙏 folded hands
  '\ud83d\udd25', // 🔥 fire
  '\ud83c\udf89', // 🎉 party popper
];

/// Floating pill-shape bar of preset reaction emojis used in the Telegram-style
/// message overlay. Shown above the selected message.
///
/// Emojis the current user has already applied to this message are shown
/// with a filled background so tapping them feels like a toggle.
class ReactionEmojiBar extends StatelessWidget {
  final void Function(String emoji) onSelected;
  final Set<String> currentUserEmojis;

  const ReactionEmojiBar({
    super.key,
    required this.onSelected,
    this.currentUserEmojis = const {},
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Material(
      color: Colors.transparent,
      child: Container(
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(32),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.25),
              blurRadius: 16,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: kReactionEmojis.map((emoji) {
            final active = currentUserEmojis.contains(emoji);
            return InkWell(
              onTap: () => onSelected(emoji),
              borderRadius: BorderRadius.circular(24),
              child: Container(
                margin: const EdgeInsets.symmetric(horizontal: 2),
                padding: const EdgeInsets.all(6),
                decoration: active
                    ? BoxDecoration(
                        color: theme.colorScheme.primary.withValues(alpha: 0.25),
                        shape: BoxShape.circle,
                      )
                    : null,
                child: Text(emoji, style: const TextStyle(fontSize: 26)),
              ),
            );
          }).toList(),
        ),
      ),
    );
  }
}
