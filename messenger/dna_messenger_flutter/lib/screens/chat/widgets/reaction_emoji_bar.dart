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

/// Horizontal bar of preset reaction emojis used at the top of the
/// message actions bottom sheet.
///
/// Emojis the current user has already applied to this message are shown
/// with a filled background pill so tapping them feels like a toggle.
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
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: kReactionEmojis.map((emoji) {
          final active = currentUserEmojis.contains(emoji);
          return InkWell(
            onTap: () => onSelected(emoji),
            borderRadius: BorderRadius.circular(24),
            child: Container(
              padding: const EdgeInsets.all(8),
              decoration: active
                  ? BoxDecoration(
                      color: theme.colorScheme.primary.withValues(alpha: 0.2),
                      shape: BoxShape.circle,
                    )
                  : null,
              child: Text(
                emoji,
                style: const TextStyle(fontSize: 26),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }
}
