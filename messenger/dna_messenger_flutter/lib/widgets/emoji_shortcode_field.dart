// Emoji Shortcode TextField - Supports :shortcode: search like Telegram/Discord
import 'package:flutter/material.dart';
import 'package:emoji_picker_flutter/emoji_picker_flutter.dart';
import '../theme/dna_theme.dart';

/// TextField with :shortcode: emoji search popup
///
/// When user types `:` followed by 2+ characters, shows matching emoji suggestions
/// in an overlay above the text field. Uses same emoji database as the picker.
class EmojiShortcodeField extends StatefulWidget {
  final TextEditingController controller;
  final String hintText;
  final int minLines;
  final int maxLines;
  final VoidCallback? onSubmitted;
  final VoidCallback? onTap;
  final InputDecoration? decoration;
  final TextInputAction? textInputAction;
  final FocusNode? focusNode;

  const EmojiShortcodeField({
    super.key,
    required this.controller,
    this.hintText = 'Type a message...',
    this.minLines = 1,
    this.maxLines = 5,
    this.onSubmitted,
    this.onTap,
    this.decoration,
    this.textInputAction,
    this.focusNode,
  });

  @override
  State<EmojiShortcodeField> createState() => _EmojiShortcodeFieldState();
}

class _EmojiShortcodeFieldState extends State<EmojiShortcodeField> {
  final LayerLink _layerLink = LayerLink();
  OverlayEntry? _overlayEntry;
  List<Emoji> _matchingEmojis = [];
  int _colonIndex = -1;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onTextChanged);
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onTextChanged);
    _removeOverlay();
    super.dispose();
  }

  void _onTextChanged() {
    final text = widget.controller.text;
    final selection = widget.controller.selection;

    if (!selection.isValid || selection.start != selection.end) {
      _removeOverlay();
      return;
    }

    final cursorPos = selection.start;

    // Find the last ':' before cursor
    int colonIdx = -1;
    for (int i = cursorPos - 1; i >= 0; i--) {
      if (text[i] == ':') {
        colonIdx = i;
        break;
      }
      // Stop if we hit whitespace or another special char
      if (text[i] == ' ' || text[i] == '\n') {
        break;
      }
    }

    if (colonIdx == -1) {
      _removeOverlay();
      return;
    }

    // Extract query between : and cursor
    final query = text.substring(colonIdx + 1, cursorPos).toLowerCase();

    // Need at least 2 chars to search
    if (query.length < 2) {
      _removeOverlay();
      return;
    }

    _colonIndex = colonIdx;

    // Search emojis using emoji_picker_flutter's utils
    _searchEmojis(query);
  }

  Future<void> _searchEmojis(String query) async {
    // Use emoji_picker_flutter's search - same database as the picker
    final results = await EmojiPickerUtils().searchEmoji(query, defaultEmojiSet);

    if (results.isEmpty) {
      _removeOverlay();
      return;
    }

    // Take first 8 results
    final limited = results.take(8).toList();

    if (mounted) {
      setState(() {
        _matchingEmojis = limited;
      });
      _showOverlay();
    }
  }

  void _showOverlay() {
    _removeOverlay();

    _overlayEntry = OverlayEntry(
      builder: (context) => Positioned(
        width: 300,
        child: CompositedTransformFollower(
          link: _layerLink,
          showWhenUnlinked: false,
          offset: const Offset(0, -8),
          followerAnchor: Alignment.bottomLeft,
          targetAnchor: Alignment.topLeft,
          child: Material(
            elevation: 8,
            borderRadius: BorderRadius.circular(8),
            color: Theme.of(context).colorScheme.surface,
            child: Container(
              constraints: const BoxConstraints(maxHeight: 250),
              decoration: BoxDecoration(
                border: Border.all(color: DnaColors.border),
                borderRadius: BorderRadius.circular(8),
              ),
              child: ListView.builder(
                shrinkWrap: true,
                padding: const EdgeInsets.symmetric(vertical: 4),
                itemCount: _matchingEmojis.length,
                itemBuilder: (context, index) {
                  final emoji = _matchingEmojis[index];
                  return InkWell(
                    onTap: () => _selectEmoji(emoji),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      child: Row(
                        children: [
                          Text(
                            emoji.emoji,
                            style: const TextStyle(fontSize: 24),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              emoji.name,
                              style: TextStyle(
                                fontSize: 13,
                                color: DnaColors.textMuted,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),
          ),
        ),
      ),
    );

    Overlay.of(context).insert(_overlayEntry!);
  }

  void _removeOverlay() {
    _overlayEntry?.remove();
    _overlayEntry = null;
  }

  void _selectEmoji(Emoji emoji) {
    final text = widget.controller.text;
    final cursorPos = widget.controller.selection.start;

    // Replace :query with emoji
    final newText = text.replaceRange(_colonIndex, cursorPos, emoji.emoji);
    final newCursorPos = _colonIndex + emoji.emoji.length;

    widget.controller.value = TextEditingValue(
      text: newText,
      selection: TextSelection.collapsed(offset: newCursorPos),
    );

    _removeOverlay();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return CompositedTransformTarget(
      link: _layerLink,
      child: TextField(
        controller: widget.controller,
        focusNode: widget.focusNode,
        decoration: widget.decoration ?? InputDecoration(
          hintText: widget.hintText,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(24),
            borderSide: BorderSide.none,
          ),
          filled: true,
          fillColor: theme.scaffoldBackgroundColor,
          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        ),
        minLines: widget.minLines,
        maxLines: widget.maxLines,
        textInputAction: widget.textInputAction,
        textCapitalization: TextCapitalization.sentences,
        onSubmitted: widget.onSubmitted != null ? (_) => widget.onSubmitted!() : null,
        onTap: () {
          widget.onTap?.call();
        },
      ),
    );
  }
}
