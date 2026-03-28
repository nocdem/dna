import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../l10n/app_localizations.dart';
import '../providers/engine_provider.dart';
import '../providers/wall_provider.dart' show wallImageCache, wallImageCachePut;
import '../utils/time_format.dart';

/// Pure presentational widget — receives ALL data via constructor.
/// Zero provider watches, zero async operations in build.
class WallPostTile extends StatelessWidget {
  final WallPost post;
  final String myFingerprint;
  final String? authorDisplayName;
  final Uint8List? authorAvatar;
  final Uint8List? decodedImage;
  final VoidCallback? onDelete;
  final VoidCallback? onBlock;
  final VoidCallback? onAuthorTap;
  final VoidCallback? onShare;
  final VoidCallback? onReply;
  final VoidCallback? onTip;
  final List<WallComment>? comments;
  final VoidCallback? onViewAllComments;
  final int likeCount;
  final bool isLikedByMe;
  final VoidCallback? onLike;
  final bool isBoosted;

  const WallPostTile({
    super.key,
    required this.post,
    required this.myFingerprint,
    this.authorDisplayName,
    this.authorAvatar,
    this.decodedImage,
    this.onDelete,
    this.onBlock,
    this.onAuthorTap,
    this.onShare,
    this.onReply,
    this.onTip,
    this.comments,
    this.onViewAllComments,
    this.likeCount = 0,
    this.isLikedByMe = false,
    this.onLike,
    this.isBoosted = false,
  });

  @override
  Widget build(BuildContext context) {
    final isOwn = post.isOwn(myFingerprint);
    final theme = Theme.of(context);

    // Use pre-resolved display name, fallback to post data
    final displayName = authorDisplayName ??
        (post.authorName.isNotEmpty
            ? post.authorName
            : post.authorFingerprint.substring(0, 16));

    final fireLevel = _fireLevel(likeCount);

    Widget card = DnaCard(
      padding: const EdgeInsets.only(
        left: DnaSpacing.lg,
        right: DnaSpacing.lg,
        top: DnaSpacing.lg,
        bottom: DnaSpacing.sm,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author row
          Row(
            children: [
              GestureDetector(
                onTap: onAuthorTap,
                child: DnaAvatar(
                  imageBytes: authorAvatar,
                  name: displayName,
                  size: DnaAvatarSize.md,
                ),
              ),
              const SizedBox(width: DnaSpacing.md),
              Expanded(
                child: GestureDetector(
                  onTap: onAuthorTap,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        displayName,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        formatRelativeTime(post.timestamp),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              if (isOwn && onDelete != null || !isOwn && onBlock != null)
                PopupMenuButton<String>(
                  icon: FaIcon(
                    FontAwesomeIcons.ellipsisVertical,
                    size: 16,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  onSelected: (value) {
                    if (value == 'delete') onDelete?.call();
                    if (value == 'block') onBlock?.call();
                  },
                  itemBuilder: (context) => [
                    if (isOwn && onDelete != null)
                      PopupMenuItem(
                        value: 'delete',
                        child: Row(
                          children: [
                            FaIcon(FontAwesomeIcons.trash, size: 16, color: DnaColors.textWarning),
                            const SizedBox(width: 8),
                            Text(AppLocalizations.of(context).wallDelete, style: TextStyle(color: DnaColors.textWarning)),
                          ],
                        ),
                      ),
                    if (!isOwn && onBlock != null)
                      PopupMenuItem(
                        value: 'block',
                        child: Row(
                          children: [
                            FaIcon(FontAwesomeIcons.ban, size: 16, color: DnaColors.textWarning),
                            const SizedBox(width: 8),
                            Text(AppLocalizations.of(context).wallBlockUser, style: TextStyle(color: DnaColors.textWarning)),
                          ],
                        ),
                      ),
                  ],
                ),
            ],
          ),
          const SizedBox(height: DnaSpacing.md),
          // Image — pre-decoded bytes or lazy load from SQLite cache
          if (decodedImage != null)
            _WallPostImage(imageBytes: decodedImage!)
          else if (post.hasImage)
            _LazyWallPostImage(postUuid: post.uuid),
          // Post text
          Text(
            post.text,
            style: theme.textTheme.bodyMedium?.copyWith(
              height: 1.4,
            ),
          ),
          const SizedBox(height: DnaSpacing.sm),
          // Inline comments preview
          if (comments != null && comments!.isNotEmpty) ...[
            Divider(
              height: 1,
              color: theme.colorScheme.outlineVariant.withAlpha(80),
            ),
            _InlineComments(
              comments: comments!,
              onViewAll: onViewAllComments ?? onReply,
            ),
          ],
          // Action bar
          Divider(
            height: 1,
            color: theme.colorScheme.outlineVariant.withAlpha(80),
          ),
          Row(
            children: [
              _ActionButton(
                icon: FontAwesomeIcons.fire,
                label: likeCount > 0 ? '$likeCount' : '',
                onTap: isLikedByMe ? null : onLike,
                color: isLikedByMe
                    ? const Color(0xFFFF6B35)
                    : likeCount > 0
                        ? const Color(0xFFFF8C42)
                        : null,
              ),
              if (!isOwn)
                _ActionButton(
                  icon: FontAwesomeIcons.coins,
                  label: AppLocalizations.of(context).wallTip,
                  onTap: onTip,
                ),
              _ActionButton(
                icon: FontAwesomeIcons.comment,
                label: comments != null && comments!.isNotEmpty
                    ? '${AppLocalizations.of(context).wallReply} (${comments!.length})'
                    : AppLocalizations.of(context).wallReply,
                onTap: onReply,
              ),
              if (!isOwn && onShare != null)
                _ActionButton(
                  icon: FontAwesomeIcons.retweet,
                  label: AppLocalizations.of(context).wallRepost,
                  onTap: onShare,
                ),
            ],
          ),
        ],
      ),
    );

    if (fireLevel > 0) {
      card = RepaintBoundary(child: _FireGlow(level: fireLevel, child: card));
    }

    if (isBoosted) {
      card = RepaintBoundary(child: _BoostGlow(child: card));
    }

    return card;
  }

  /// Returns fire level 0-5 based on like count
  static int _fireLevel(int count) {
    if (count <= 0) return 0;
    if (count < 20) return 1;
    if (count < 50) return 2;
    if (count < 80) return 3;
    if (count < 100) return 4;
    return 5; // 100 = max fire
  }
}

/// Wraps a card with a fire glow effect based on level (1-5)
class _FireGlow extends StatelessWidget {
  final int level;
  final Widget child;

  const _FireGlow({required this.level, required this.child});

  @override
  Widget build(BuildContext context) {
    final Color glowColor;
    final double blur;
    final double spread;
    final double borderWidth;

    switch (level) {
      case 1:
        glowColor = const Color(0x40FF8C42);
        blur = 4;
        spread = 0;
        borderWidth = 1;
      case 2:
        glowColor = const Color(0x66FF6B35);
        blur = 8;
        spread = 1;
        borderWidth = 1.5;
      case 3:
        glowColor = const Color(0x80FF4500);
        blur = 12;
        spread = 2;
        borderWidth = 2;
      case 4:
        glowColor = const Color(0x99FF2200);
        blur = 16;
        spread = 3;
        borderWidth = 2;
      case 5:
        glowColor = const Color(0xBFFFD700);
        blur = 20;
        spread = 4;
        borderWidth = 2.5;
      default:
        return child;
    }

    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        border: Border.all(
          color: glowColor.withAlpha(180),
          width: borderWidth,
        ),
        boxShadow: [
          BoxShadow(
            color: glowColor,
            blurRadius: blur,
            spreadRadius: spread,
          ),
          if (level >= 3)
            BoxShadow(
              color: glowColor.withAlpha(glowColor.alpha ~/ 2),
              blurRadius: blur * 2,
              spreadRadius: spread / 2,
            ),
        ],
      ),
      child: child,
    );
  }
}

/// Wraps a card with a boost glow effect (blue-purple gradient border)
class _BoostGlow extends StatelessWidget {
  final Widget child;

  const _BoostGlow({required this.child});

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        gradient: const LinearGradient(
          colors: [Color(0xFF6C63FF), Color(0xFFAB47BC)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Container(
        margin: const EdgeInsets.all(1.5),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusMd - 1),
          color: Theme.of(context).colorScheme.surface,
        ),
        child: child,
      ),
    );
  }
}

/// Displays an image from pre-decoded bytes (fast path)
class _WallPostImage extends StatelessWidget {
  final Uint8List imageBytes;

  const _WallPostImage({required this.imageBytes});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: DnaSpacing.sm),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
        child: GestureDetector(
          onTap: () => _showFullscreen(context, imageBytes),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 300),
            child: Image.memory(
              imageBytes,
              fit: BoxFit.cover,
              width: double.infinity,
              errorBuilder: (_, e, s) => const SizedBox.shrink(),
            ),
          ),
        ),
      ),
    );
  }

  void _showFullscreen(BuildContext context, Uint8List bytes) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(
            backgroundColor: Colors.black,
            iconTheme: const IconThemeData(color: Colors.white),
          ),
          body: Center(
            child: InteractiveViewer(
              child: Image.memory(bytes),
            ),
          ),
        ),
      ),
    );
  }
}

/// Fallback: decodes image from JSON if pre-decoded bytes not available
class _WallPostImageFallback extends StatelessWidget {
  final String imageJson;

  const _WallPostImageFallback({required this.imageJson});

  Uint8List? _decodeImage() {
    try {
      final map = jsonDecode(imageJson) as Map<String, dynamic>;
      final data = map['data'] as String?;
      if (data == null || data.isEmpty) return null;
      return base64Decode(data);
    } catch (e) {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final bytes = _decodeImage();
    if (bytes == null) return const SizedBox.shrink();
    return _WallPostImage(imageBytes: bytes);
  }
}

/// Lazy-loads image from SQLite cache via FFI when not in memory cache.
class _LazyWallPostImage extends ConsumerStatefulWidget {
  final String postUuid;

  const _LazyWallPostImage({required this.postUuid});

  @override
  ConsumerState<_LazyWallPostImage> createState() => _LazyWallPostImageState();
}

class _LazyWallPostImageState extends ConsumerState<_LazyWallPostImage> {
  Uint8List? _imageBytes;
  bool _loading = false;
  bool _failed = false;

  @override
  void initState() {
    super.initState();
    // Check in-memory cache first
    final cached = wallImageCache(widget.postUuid);
    if (cached != null) {
      _imageBytes = cached;
    } else {
      _loadImage();
    }
  }

  Future<void> _loadImage() async {
    if (_loading) return;
    _loading = true;

    try {
      final engine = await ref.read(engineProvider.future);
      final imageJson = await engine.wallGetImage(widget.postUuid);
      if (!mounted) return;

      if (imageJson == null || imageJson.isEmpty) {
        setState(() => _failed = true);
        return;
      }

      // Decode the JSON and extract base64 data
      final map = jsonDecode(imageJson) as Map<String, dynamic>;
      final data = map['data'] as String?;
      if (data == null || data.isEmpty) {
        setState(() => _failed = true);
        return;
      }

      final bytes = base64Decode(data);
      wallImageCachePut(widget.postUuid, bytes);

      if (mounted) {
        setState(() => _imageBytes = bytes);
      }
    } catch (_) {
      if (mounted) {
        setState(() => _failed = true);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_imageBytes != null) {
      return _WallPostImage(imageBytes: _imageBytes!);
    }
    if (_failed) {
      return const SizedBox.shrink();
    }
    // Loading placeholder
    return Padding(
      padding: const EdgeInsets.only(bottom: DnaSpacing.sm),
      child: SizedBox(
        height: 200,
        child: Center(
          child: SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ),
      ),
    );
  }
}

/// Shows up to 3 most recent comments inline under a wall post
class _InlineComments extends StatelessWidget {
  final List<WallComment> comments;
  final VoidCallback? onViewAll;

  static const int _maxPreview = 3;

  const _InlineComments({
    required this.comments,
    this.onViewAll,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final preview = comments.length <= _maxPreview
        ? comments
        : comments.sublist(0, _maxPreview);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: DnaSpacing.sm),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (comments.length > _maxPreview)
            GestureDetector(
              onTap: onViewAll,
              child: Padding(
                padding: const EdgeInsets.only(bottom: DnaSpacing.xs),
                child: Text(
                  AppLocalizations.of(context)
                      .wallViewAllComments(comments.length),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
          for (final comment in preview)
            Padding(
              padding: const EdgeInsets.only(bottom: 2),
              child: comment.isTip
                  ? _buildTipPreview(context, theme, comment)
                  : Text.rich(
                      TextSpan(
                        children: [
                          TextSpan(
                            text: comment.authorName.isNotEmpty
                                ? comment.authorName
                                : comment.authorFingerprint.length >= 12
                                    ? comment.authorFingerprint.substring(0, 12)
                                    : comment.authorFingerprint,
                            style: theme.textTheme.bodySmall?.copyWith(
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const TextSpan(text: '  '),
                          TextSpan(
                            text: comment.body,
                            style: theme.textTheme.bodySmall,
                          ),
                        ],
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
            ),
        ],
      ),
    );
  }

  Widget _buildTipPreview(
      BuildContext context, ThemeData theme, WallComment comment) {
    String amount = '?';
    try {
      final data = jsonDecode(comment.body) as Map<String, dynamic>;
      amount = data['amount'] as String? ?? '?';
    } catch (_) {}

    final authorName = comment.authorName.isNotEmpty
        ? comment.authorName
        : comment.authorFingerprint.substring(0, 12);

    return Row(
      children: [
        const FaIcon(
          FontAwesomeIcons.coins,
          size: 11,
          color: Color(0xFFFFD700),
        ),
        const SizedBox(width: 4),
        Expanded(
          child: Text.rich(
            TextSpan(
              children: [
                TextSpan(
                  text: authorName,
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const TextSpan(text: '  '),
                TextSpan(
                  text: AppLocalizations.of(context).wallTippedAmount(amount),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: const Color(0xFFFFD700),
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  final Color? color;

  const _ActionButton({
    required this.icon,
    required this.label,
    this.onTap,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final effectiveColor = color ?? theme.colorScheme.onSurfaceVariant;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.md,
          vertical: DnaSpacing.sm,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(icon, size: 13, color: effectiveColor),
            const SizedBox(width: 6),
            Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: effectiveColor,
                fontSize: 12,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
