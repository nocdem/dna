// Message Context Menu - Desktop right-click menu for messages
import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../../theme/dna_theme.dart';

/// Callback types for context menu actions
typedef MessageAction = void Function();

/// Desktop context menu for messages (right-click)
/// On mobile, this is triggered by long-press via bottom sheet
class MessageContextMenu {
  /// Show context menu at tap position (desktop only)
  /// Returns the selected action or null if dismissed
  static Future<void> show({
    required BuildContext context,
    required Offset position,
    required bool isStarred,
    required MessageAction onReply,
    required MessageAction onCopy,
    required MessageAction onForward,
    required MessageAction onStar,
    required MessageAction onDelete,
    MessageAction? onRetry,
  }) async {
    final RenderBox overlay = Overlay.of(context).context.findRenderObject() as RenderBox;

    await showMenu<String>(
      context: context,
      position: RelativeRect.fromRect(
        position & const Size(1, 1),
        Offset.zero & overlay.size,
      ),
      elevation: 8,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      items: [
        _buildMenuItem(
          icon: FontAwesomeIcons.reply,
          label: 'Reply',
          value: 'reply',
        ),
        _buildMenuItem(
          icon: FontAwesomeIcons.copy,
          label: 'Copy',
          value: 'copy',
        ),
        _buildMenuItem(
          icon: FontAwesomeIcons.share,
          label: 'Forward',
          value: 'forward',
        ),
        _buildMenuItem(
          icon: isStarred ? FontAwesomeIcons.solidStar : FontAwesomeIcons.star,
          label: isStarred ? 'Unstar' : 'Star',
          value: 'star',
          iconColor: isStarred ? Colors.amber : null,
        ),
        if (onRetry != null)
          _buildMenuItem(
            icon: FontAwesomeIcons.arrowsRotate,
            label: 'Retry',
            value: 'retry',
            iconColor: DnaColors.textWarning,
          ),
        const PopupMenuDivider(),
        _buildMenuItem(
          icon: FontAwesomeIcons.trash,
          label: 'Delete',
          value: 'delete',
          iconColor: DnaColors.textError,
          textColor: DnaColors.textError,
        ),
      ],
    ).then((value) {
      switch (value) {
        case 'reply':
          onReply();
          break;
        case 'copy':
          onCopy();
          break;
        case 'forward':
          onForward();
          break;
        case 'star':
          onStar();
          break;
        case 'retry':
          onRetry?.call();
          break;
        case 'delete':
          onDelete();
          break;
      }
    });
  }

  static PopupMenuItem<String> _buildMenuItem({
    required IconData icon,
    required String label,
    required String value,
    Color? iconColor,
    Color? textColor,
  }) {
    return PopupMenuItem<String>(
      value: value,
      height: 40,
      child: Row(
        children: [
          SizedBox(
            width: 24,
            child: FaIcon(icon, size: 16, color: iconColor),
          ),
          const SizedBox(width: 12),
          Text(label, style: textColor != null ? TextStyle(color: textColor) : null),
        ],
      ),
    );
  }

  /// Check if we're on a desktop platform
  static bool get isDesktop =>
      Platform.isLinux || Platform.isWindows || Platform.isMacOS;
}
