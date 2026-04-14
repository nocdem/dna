import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';

import '../../../design_system/design_system.dart';
import '../../../ffi/dna_engine.dart';
import '../../../l10n/app_localizations.dart';

/// Telegram-style action card shown beneath the selected message in the
/// message overlay. Includes Reply/Copy/Forward/Star/Delete actions plus an
/// embedded "details" section (timestamp, direction, status).
class MessageActionCard extends StatelessWidget {
  final Message message;
  final String contactName;
  final bool isStarred;
  final VoidCallback onReply;
  final VoidCallback onCopy;
  final VoidCallback onForward;
  final VoidCallback onStar;
  final VoidCallback onDelete;

  const MessageActionCard({
    super.key,
    required this.message,
    required this.contactName,
    required this.isStarred,
    required this.onReply,
    required this.onCopy,
    required this.onForward,
    required this.onStar,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final isDark = theme.brightness == Brightness.dark;

    final fullTimestamp =
        DateFormat('MMMM d, y \'at\' HH:mm:ss').format(message.timestamp);

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

    Widget actionRow({
      required IconData icon,
      required Color iconColor,
      required String label,
      required VoidCallback onTap,
    }) {
      return InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.lg,
            vertical: DnaSpacing.sm,
          ),
          child: Row(
            children: [
              FaIcon(icon, size: 18, color: iconColor),
              const SizedBox(width: DnaSpacing.md),
              Expanded(
                child: Text(label, style: theme.textTheme.bodyMedium),
              ),
            ],
          ),
        ),
      );
    }

    Widget detailRow(IconData icon, String label, Color color) {
      return Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: 4,
        ),
        child: Row(
          children: [
            FaIcon(icon, size: 14, color: color),
            const SizedBox(width: DnaSpacing.md),
            Expanded(
              child: Text(
                label,
                style: theme.textTheme.bodySmall?.copyWith(color: mutedColor),
              ),
            ),
          ],
        ),
      );
    }

    return Material(
      color: Colors.transparent,
      child: Container(
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.4 : 0.2),
              blurRadius: 16,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: DnaSpacing.xs),
            actionRow(
              icon: FontAwesomeIcons.reply,
              iconColor: DnaColors.info,
              label: l10n.messageMenuReply,
              onTap: onReply,
            ),
            actionRow(
              icon: FontAwesomeIcons.copy,
              iconColor: DnaColors.info,
              label: l10n.messageMenuCopy,
              onTap: onCopy,
            ),
            actionRow(
              icon: FontAwesomeIcons.share,
              iconColor: DnaColors.success,
              label: l10n.messageMenuForward,
              onTap: onForward,
            ),
            actionRow(
              icon: isStarred ? FontAwesomeIcons.solidStar : FontAwesomeIcons.star,
              iconColor: isStarred ? Colors.amber : DnaColors.warning,
              label: isStarred ? l10n.messageMenuUnstar : l10n.messageMenuStar,
              onTap: onStar,
            ),
            const SizedBox(height: 4),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
              child: Divider(height: 1, color: theme.dividerColor),
            ),
            actionRow(
              icon: FontAwesomeIcons.trash,
              iconColor: DnaColors.error,
              label: l10n.messageMenuDelete,
              onTap: onDelete,
            ),
            const SizedBox(height: 4),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
              child: Divider(height: 1, color: theme.dividerColor),
            ),
            const SizedBox(height: DnaSpacing.sm),
            detailRow(FontAwesomeIcons.clock, fullTimestamp, DnaColors.info),
            detailRow(
              message.isOutgoing ? FontAwesomeIcons.arrowUp : FontAwesomeIcons.arrowDown,
              message.isOutgoing
                  ? 'Sent to $contactName'
                  : 'Received from $contactName',
              message.isOutgoing ? DnaColors.success : DnaColors.info,
            ),
            if (message.isOutgoing)
              detailRow(statusIcon, statusText, statusColor),
            const SizedBox(height: DnaSpacing.sm),
          ],
        ),
      ),
    );
  }
}
