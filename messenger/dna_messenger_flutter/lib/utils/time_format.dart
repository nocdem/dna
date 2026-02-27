import 'package:intl/intl.dart';

/// Format a [DateTime] as a relative time string for display in posts,
/// comments, and feed tiles.
///
/// Returns "Xm ago", "Xh ago", "Xd ago", or "MMM d" for older dates.
String formatRelativeTime(DateTime time) {
  final now = DateTime.now();
  final diff = now.difference(time);

  if (diff.inMinutes < 1) {
    return 'just now';
  } else if (diff.inMinutes < 60) {
    return '${diff.inMinutes}m ago';
  } else if (diff.inHours < 24) {
    return '${diff.inHours}h ago';
  } else if (diff.inDays < 7) {
    return '${diff.inDays}d ago';
  } else {
    return DateFormat('MMM d').format(time);
  }
}
