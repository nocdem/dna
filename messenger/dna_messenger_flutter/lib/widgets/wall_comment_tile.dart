import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../l10n/app_localizations.dart';
import '../providers/engine_provider.dart';
import '../screens/profile/user_profile_screen.dart';
import '../utils/logger.dart';
import '../utils/time_format.dart';

void _openAuthorProfile(BuildContext context, WallComment comment) {
  Navigator.push(
    context,
    MaterialPageRoute(
      builder: (_) => UserProfileScreen(
        fingerprint: comment.authorFingerprint,
        initialDisplayName:
            comment.authorName.isNotEmpty ? comment.authorName : null,
      ),
    ),
  );
}

/// Displays a single wall comment (top-level or reply)
class WallCommentTile extends StatelessWidget {
  final WallComment comment;
  final VoidCallback? onReply;
  final bool isReply;

  const WallCommentTile({
    super.key,
    required this.comment,
    this.onReply,
    this.isReply = false,
  });

  @override
  Widget build(BuildContext context) {
    if (comment.isTip) {
      return _TipCommentTile(comment: comment);
    }
    return _TextCommentTile(
      comment: comment,
      onReply: onReply,
      isReply: isReply,
    );
  }
}

/// Regular text comment
class _TextCommentTile extends StatelessWidget {
  final WallComment comment;
  final VoidCallback? onReply;
  final bool isReply;

  const _TextCommentTile({
    required this.comment,
    this.onReply,
    this.isReply = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: EdgeInsets.only(
        left: isReply ? DnaSpacing.xl : 0,
        bottom: DnaSpacing.sm,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Author name + timestamp
                Row(
                  children: [
                    InkWell(
                      onTap: () => _openAuthorProfile(context, comment),
                      child: Text(
                        comment.authorName.isNotEmpty
                            ? comment.authorName
                            : comment.authorFingerprint.substring(0, 12),
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.primary,
                        ),
                      ),
                    ),
                    const SizedBox(width: DnaSpacing.sm),
                    Text(
                      formatRelativeTime(comment.createdAt),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 2),
                // Comment body
                Text(
                  comment.body,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    height: 1.3,
                  ),
                ),
                const SizedBox(height: 2),
                // Reply button
                if (!isReply)
                  InkWell(
                    onTap: onReply,
                    borderRadius: BorderRadius.circular(4),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        vertical: 2,
                        horizontal: 4,
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          FaIcon(
                            FontAwesomeIcons.reply,
                            size: 11,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            AppLocalizations.of(context).wallReply,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                              fontSize: 11,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Gold tip comment with transaction verification
class _TipCommentTile extends ConsumerStatefulWidget {
  final WallComment comment;

  const _TipCommentTile({required this.comment});

  @override
  ConsumerState<_TipCommentTile> createState() => _TipCommentTileState();
}

class _TipCommentTileState extends ConsumerState<_TipCommentTile> {
  // Static cache: once verified(1) or denied(2), never re-check via FFI.
  static final Map<String, int> _verifiedCache = {};

  /// 0=pending, 1=verified, 2=denied
  int _verificationStatus = 0;
  bool _isVerifying = false;
  Timer? _retryTimer;
  int _retryCount = 0;
  static const int _maxRetries = 6;
  static const Duration _retryInterval = Duration(seconds: 10);

  Map<String, dynamic>? _tipData;

  @override
  void initState() {
    super.initState();
    _parseTipData();

    // Check in-memory cache first — skip FFI for already-verified TXs
    final txHash = _tipData?['txHash'] as String?;
    if (txHash != null && _verifiedCache.containsKey(txHash)) {
      _verificationStatus = _verifiedCache[txHash]!;
      return;
    }

    _verifyTransaction();
  }

  @override
  void dispose() {
    _retryTimer?.cancel();
    super.dispose();
  }

  void _parseTipData() {
    try {
      _tipData = jsonDecode(widget.comment.body) as Map<String, dynamic>;
    } catch (e) {
      logError('TIP', e);
    }
  }

  Future<void> _verifyTransaction() async {
    final txHash = _tipData?['txHash'] as String?;
    final chain = _tipData?['chain'] as String? ?? 'cellframe';
    if (txHash == null || txHash.isEmpty) return;

    // Already in a final state — no need to re-check
    if (_verificationStatus == 1 || _verificationStatus == 2) return;

    if (_isVerifying) return;
    setState(() => _isVerifying = true);

    try {
      final engine = await ref.read(engineProvider.future);
      final status = await engine.getTxStatus(txHash: txHash, chain: chain);
      if (mounted) {
        setState(() {
          _verificationStatus = status;
          _isVerifying = false;
        });

        // Cache final states — no need to re-check on future widget rebuilds
        if (status == 1 || status == 2) {
          _verifiedCache[txHash] = status;
        }

        if (status == 0 && _retryCount < _maxRetries) {
          _retryCount++;
          _retryTimer?.cancel();
          _retryTimer = Timer(_retryInterval, _verifyTransaction);
        }
      }
    } catch (e) {
      logError('TIP', e);
      if (mounted) {
        setState(() => _isVerifying = false);
      }
    }
  }

  Color _getBorderColor() {
    switch (_verificationStatus) {
      case 1: return Colors.green;
      case 2: return Colors.red;
      default: return Colors.orange;
    }
  }

  IconData _getStatusIcon() {
    switch (_verificationStatus) {
      case 1: return FontAwesomeIcons.circleCheck;
      case 2: return FontAwesomeIcons.circleXmark;
      default: return FontAwesomeIcons.clock;
    }
  }

  String _getStatusText(AppLocalizations l10n) {
    switch (_verificationStatus) {
      case 1: return l10n.wallTipVerified;
      case 2: return l10n.wallTipFailedStatus;
      default: return l10n.wallTipPending;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    final amount = _tipData?['amount'] as String? ?? '?';

    return Padding(
      padding: const EdgeInsets.only(bottom: DnaSpacing.sm),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Author + timestamp
                Row(
                  children: [
                    InkWell(
                      onTap: () =>
                          _openAuthorProfile(context, widget.comment),
                      child: Text(
                        widget.comment.authorName.isNotEmpty
                            ? widget.comment.authorName
                            : widget.comment.authorFingerprint.substring(0, 12),
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.primary,
                        ),
                      ),
                    ),
                    const SizedBox(width: DnaSpacing.sm),
                    Text(
                      formatRelativeTime(widget.comment.createdAt),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                // Gold tip card
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: DnaSpacing.md,
                    vertical: DnaSpacing.sm,
                  ),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0x30FFD700), Color(0x20FFA500)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                    border: Border.all(
                      color: _getBorderColor().withAlpha(150),
                      width: 1.5,
                    ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const FaIcon(
                        FontAwesomeIcons.coins,
                        color: Color(0xFFFFD700),
                        size: 18,
                      ),
                      const SizedBox(width: DnaSpacing.sm),
                      Flexible(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              l10n.wallTippedAmount(amount),
                              style: theme.textTheme.bodyMedium?.copyWith(
                                fontWeight: FontWeight.bold,
                                color: const Color(0xFFFFD700),
                              ),
                            ),
                            const SizedBox(height: 2),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                if (_isVerifying)
                                  const SizedBox(
                                    width: 10,
                                    height: 10,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 1.5,
                                      color: Colors.orange,
                                    ),
                                  )
                                else
                                  FaIcon(
                                    _getStatusIcon(),
                                    size: 10,
                                    color: _getBorderColor(),
                                  ),
                                const SizedBox(width: 4),
                                Text(
                                  _getStatusText(l10n),
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: _getBorderColor(),
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
