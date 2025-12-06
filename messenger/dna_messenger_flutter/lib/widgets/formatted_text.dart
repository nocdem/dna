// Formatted Text Widget - Renders markdown-style formatting
// Supports: *bold*, _italic_, ~strikethrough~, `code`
// Also renders single-emoji messages at larger size (like Telegram)
import 'package:flutter/material.dart';

/// Regex to match emoji characters
final _emojiRegex = RegExp(
  r'[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]|[\u{1F600}-\u{1F64F}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]',
  unicode: true,
);

/// Check if text is exactly one emoji (no other text)
bool _isSingleEmoji(String text) {
  final trimmed = text.trim();
  if (trimmed.isEmpty) return false;

  final emojis = _emojiRegex.allMatches(trimmed).toList();
  if (emojis.length != 1) return false;

  // Check that removing the emoji leaves nothing
  final withoutEmoji = trimmed.replaceAll(_emojiRegex, '');
  return withoutEmoji.isEmpty;
}

/// Renders text with markdown-style formatting
///
/// Supported formats:
/// - *bold* or **bold**
/// - _italic_ or /italic/
/// - ~strikethrough~
/// - `code`
/// - ```code block```
///
/// Single-emoji messages are rendered at 48px (like Telegram)
class FormattedText extends StatelessWidget {
  final String text;
  final TextStyle? style;
  final TextAlign? textAlign;
  final int? maxLines;
  final TextOverflow? overflow;

  const FormattedText(
    this.text, {
    super.key,
    this.style,
    this.textAlign,
    this.maxLines,
    this.overflow,
  });

  @override
  Widget build(BuildContext context) {
    final defaultStyle = style ?? DefaultTextStyle.of(context).style;

    // Single emoji = large size
    if (_isSingleEmoji(text)) {
      return Text(
        text.trim(),
        style: defaultStyle.copyWith(fontSize: 48),
        textAlign: textAlign ?? TextAlign.start,
      );
    }

    final spans = _parseText(text, defaultStyle);

    return RichText(
      text: TextSpan(children: spans),
      textAlign: textAlign ?? TextAlign.start,
      maxLines: maxLines,
      overflow: overflow ?? TextOverflow.clip,
    );
  }

  List<InlineSpan> _parseText(String text, TextStyle baseStyle) {
    final spans = <InlineSpan>[];
    final buffer = StringBuffer();
    int i = 0;

    while (i < text.length) {
      // Check for code block ```
      if (i + 2 < text.length && text.substring(i, i + 3) == '```') {
        // Flush buffer
        if (buffer.isNotEmpty) {
          spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
          buffer.clear();
        }
        // Find closing ```
        final endIdx = text.indexOf('```', i + 3);
        if (endIdx != -1) {
          final code = text.substring(i + 3, endIdx);
          spans.add(TextSpan(
            text: code,
            style: baseStyle.copyWith(
              fontFamily: 'NotoSansMono',
              backgroundColor: Colors.grey.withValues(alpha: 0.2),
            ),
          ));
          i = endIdx + 3;
          continue;
        }
      }

      // Check for inline code `
      if (text[i] == '`') {
        // Flush buffer
        if (buffer.isNotEmpty) {
          spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
          buffer.clear();
        }
        // Find closing `
        final endIdx = text.indexOf('`', i + 1);
        if (endIdx != -1) {
          final code = text.substring(i + 1, endIdx);
          spans.add(TextSpan(
            text: code,
            style: baseStyle.copyWith(
              fontFamily: 'NotoSansMono',
              backgroundColor: Colors.grey.withValues(alpha: 0.2),
            ),
          ));
          i = endIdx + 1;
          continue;
        }
      }

      // Check for bold ** or *
      if (text[i] == '*') {
        // Check for **bold**
        if (i + 1 < text.length && text[i + 1] == '*') {
          if (buffer.isNotEmpty) {
            spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
            buffer.clear();
          }
          final endIdx = text.indexOf('**', i + 2);
          if (endIdx != -1) {
            final boldText = text.substring(i + 2, endIdx);
            spans.add(TextSpan(
              text: boldText,
              style: baseStyle.copyWith(fontWeight: FontWeight.bold),
            ));
            i = endIdx + 2;
            continue;
          }
        } else {
          // Single *bold*
          if (buffer.isNotEmpty) {
            spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
            buffer.clear();
          }
          final endIdx = _findClosingMarker(text, i + 1, '*');
          if (endIdx != -1) {
            final boldText = text.substring(i + 1, endIdx);
            spans.add(TextSpan(
              text: boldText,
              style: baseStyle.copyWith(fontWeight: FontWeight.bold),
            ));
            i = endIdx + 1;
            continue;
          }
        }
      }

      // Check for italic _ or /
      if (text[i] == '_' || text[i] == '/') {
        final marker = text[i];
        if (buffer.isNotEmpty) {
          spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
          buffer.clear();
        }
        final endIdx = _findClosingMarker(text, i + 1, marker);
        if (endIdx != -1) {
          final italicText = text.substring(i + 1, endIdx);
          spans.add(TextSpan(
            text: italicText,
            style: baseStyle.copyWith(fontStyle: FontStyle.italic),
          ));
          i = endIdx + 1;
          continue;
        }
      }

      // Check for strikethrough ~
      if (text[i] == '~') {
        if (buffer.isNotEmpty) {
          spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
          buffer.clear();
        }
        final endIdx = _findClosingMarker(text, i + 1, '~');
        if (endIdx != -1) {
          final strikeText = text.substring(i + 1, endIdx);
          spans.add(TextSpan(
            text: strikeText,
            style: baseStyle.copyWith(decoration: TextDecoration.lineThrough),
          ));
          i = endIdx + 1;
          continue;
        }
      }

      // Regular character
      buffer.write(text[i]);
      i++;
    }

    // Flush remaining buffer
    if (buffer.isNotEmpty) {
      spans.add(TextSpan(text: buffer.toString(), style: baseStyle));
    }

    return spans;
  }

  /// Find closing marker, ensuring it's not escaped and not at word boundary
  int _findClosingMarker(String text, int startIdx, String marker) {
    for (int i = startIdx; i < text.length; i++) {
      if (text[i] == marker) {
        // Make sure there's content between markers
        if (i > startIdx) {
          return i;
        }
      }
    }
    return -1;
  }
}
