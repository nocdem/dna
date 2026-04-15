import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../l10n/app_localizations.dart';
import '../models/media_ref.dart';
import '../providers/engine_provider.dart';
import '../providers/event_handler.dart' show DhtConnectionState, dhtConnectionStateProvider;
import '../providers/wall_provider.dart' show wallImageCache, wallImageCachePut;
import '../services/media_cache_service.dart';
import '../services/media_service.dart';
import '../utils/logger.dart';
import '../utils/time_format.dart';

/// Heat value (0..1) for a given like count, using a log curve:
///   heat = log(1 + clamp(likes, 1, 100)) / log(101)
///
/// Results: 0→0.00, 1→0.15, 10→0.52, 50→0.85, 100+→1.00.
/// Top-level (public) only so it can be unit tested — pure function, no state.
double heatValueForLikes(int likes) {
  if (likes <= 0) return 0.0;
  final clamped = likes > 100 ? 100 : likes;
  return math.log(1 + clamped) / math.log(101);
}

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
  final int commentCount;
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
    this.commentCount = 0,
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

    final heat = heatValueForLikes(likeCount);

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
                label: commentCount > 0
                    ? '${AppLocalizations.of(context).wallReply} ($commentCount)'
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

    if (heat > 0) {
      card = RepaintBoundary(child: _CyberFireBorder(heat: heat, child: card));
    }

    if (isBoosted) {
      card = RepaintBoundary(child: _BoostGlow(child: card));
    }

    return card;
  }

}

/// Animated cyber-fire border overlay. Wraps a post card with a
/// `FragmentShader`-driven flame effect that scales with `heat` (0..1).
///
/// If the shader fails to load (unsupported GPU, missing asset), the child
/// is rendered unchanged — graceful degradation, no crash.
class _CyberFireBorder extends StatefulWidget {
  final double heat;
  final Widget child;
  const _CyberFireBorder({required this.heat, required this.child});

  @override
  State<_CyberFireBorder> createState() => _CyberFireBorderState();
}

class _CyberFireBorderState extends State<_CyberFireBorder>
    with SingleTickerProviderStateMixin {
  Ticker? _ticker;
  double _elapsed = 0;
  ui.FragmentShader? _shader;

  @override
  void initState() {
    super.initState();
    _loadShader();
    _ticker = createTicker((d) {
      if (!mounted) return;
      setState(() => _elapsed = d.inMicroseconds / 1e6);
    })..start();
  }

  Future<void> _loadShader() async {
    try {
      final program =
          await ui.FragmentProgram.fromAsset('shaders/cyber_fire.frag');
      if (mounted) {
        setState(() => _shader = program.fragmentShader());
      }
    } catch (e) {
      logError('CYBER_FIRE', e);
    }
  }

  @override
  void dispose() {
    _ticker?.dispose();
    _ticker = null;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final shader = _shader;
    if (shader == null) return widget.child;
    return Stack(children: [
      widget.child,
      Positioned.fill(
        child: IgnorePointer(
          child: CustomPaint(
            painter: _CyberFirePainter(
              shader: shader,
              time: _elapsed,
              heat: widget.heat,
              radius: DnaSpacing.radiusMd,
            ),
          ),
        ),
      ),
    ]);
  }
}

class _CyberFirePainter extends CustomPainter {
  final ui.FragmentShader shader;
  final double time;
  final double heat;
  final double radius;

  _CyberFirePainter({
    required this.shader,
    required this.time,
    required this.heat,
    required this.radius,
  });

  @override
  void paint(Canvas canvas, Size size) {
    shader
      ..setFloat(0, size.width)
      ..setFloat(1, size.height)
      ..setFloat(2, time)
      ..setFloat(3, heat)
      ..setFloat(4, radius);
    final paint = Paint()..shader = shader;
    canvas.drawRect(Offset.zero & size, paint);
  }

  @override
  bool shouldRepaint(covariant _CyberFirePainter old) =>
      old.time != time || old.heat != heat;
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

/// Lazy-loads image from SQLite cache via FFI when not in memory cache.
/// Supports both legacy inline base64 image_json and new media_ref format.
class _LazyWallPostImage extends ConsumerStatefulWidget {
  final String postUuid;

  const _LazyWallPostImage({required this.postUuid});

  @override
  ConsumerState<_LazyWallPostImage> createState() => _LazyWallPostImageState();
}

class _LazyWallPostImageState extends ConsumerState<_LazyWallPostImage> {
  static const String _tag = 'WALL_IMG';

  Uint8List? _imageBytes;
  Uint8List? _thumbnailBytes;
  MediaRef? _mediaRef;
  bool _loading = false;
  bool _downloading = false;
  bool _failed = false;
  bool _retriedOnConnect = false;  // prevent infinite retry loop on DHT connect

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

      final map = jsonDecode(imageJson) as Map<String, dynamic>;

      // Check for new media_ref format
      if (map['type'] == 'media_ref') {
        final ref = MediaRef.fromJson(map);
        if (ref == null) {
          setState(() => _failed = true);
          return;
        }

        // Show thumbnail immediately, then download full image
        Uint8List? thumbBytes;
        try {
          if (ref.thumbnail.isNotEmpty) {
            thumbBytes = base64Decode(ref.thumbnail);
          }
        } catch (_) {}

        setState(() {
          _mediaRef = ref;
          _thumbnailBytes = thumbBytes;
        });

        // Auto-download full image
        _downloadMediaRef(engine, ref);
        return;
      }

      // Legacy inline base64 format
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

  Future<void> _downloadMediaRef(DnaEngine engine, MediaRef ref) async {
    if (_downloading) return;
    _downloading = true;

    try {
      // Check disk cache first — avoid redundant DHT downloads
      final diskCache = MediaCacheService.instance;
      if (diskCache != null) {
        final cached = await diskCache.get(ref.contentHash, ref.mimeType);
        if (cached != null) {
          wallImageCachePut(widget.postUuid, cached);
          if (mounted) {
            setState(() {
              _imageBytes = cached;
              _downloading = false;
            });
          }
          return;
        }
      }

      final mediaService = MediaService(engine);
      final bytes = await mediaService.download(ref);
      wallImageCachePut(widget.postUuid, bytes);

      // Persist to disk cache
      if (diskCache != null) {
        await diskCache.put(ref.contentHash, ref.mimeType, bytes);
      }

      if (mounted) {
        setState(() {
          _imageBytes = bytes;
          _downloading = false;
        });
      }
    } on DnaEngineException catch (e) {
      // -104 = DHT not connected yet — expected during bootstrap, not an error
      if (e.code == -104) {
        log(_tag, 'Media download deferred: DHT not connected yet');
      } else {
        logError(_tag, 'Media download failed: $e');
      }
      if (mounted) {
        setState(() {
          _downloading = false;
          _failed = _thumbnailBytes == null;
        });
      }
    } catch (e) {
      logError(_tag, 'Media download failed: $e');
      if (mounted) {
        setState(() {
          _downloading = false;
          _failed = _thumbnailBytes == null;
        });
      }
    }
  }

  Future<void> _retryDownload() async {
    if (_mediaRef == null) return;
    final engine = await ref.read(engineProvider.future);
    setState(() => _failed = false);
    _downloadMediaRef(engine, _mediaRef!);
  }

  @override
  Widget build(BuildContext context) {
    // Watch DHT state — auto-retry failed media downloads when DHT connects
    final dhtState = ref.watch(dhtConnectionStateProvider);
    if (dhtState != DhtConnectionState.connected) {
      _retriedOnConnect = false;  // reset on disconnect so next connect retries
    } else if (!_downloading && !_retriedOnConnect && _mediaRef != null && _imageBytes == null) {
      _retriedOnConnect = true;
      // Schedule retry after build completes
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && !_downloading && _imageBytes == null) {
          _retryDownload();
        }
      });
    }

    // Full image available (from any source)
    if (_imageBytes != null) {
      return _WallPostImage(imageBytes: _imageBytes!);
    }

    // Media ref with thumbnail: show thumbnail while downloading
    if (_thumbnailBytes != null) {
      return Padding(
        padding: const EdgeInsets.only(bottom: DnaSpacing.sm),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          child: GestureDetector(
            onTap: _failed ? _retryDownload : null,
            child: Stack(
              children: [
                ConstrainedBox(
                  constraints: const BoxConstraints(maxHeight: 300),
                  child: Image.memory(
                    _thumbnailBytes!,
                    fit: BoxFit.cover,
                    width: double.infinity,
                    errorBuilder: (_, _, _) => const SizedBox.shrink(),
                  ),
                ),
                if (_downloading)
                  Positioned.fill(
                    child: Container(
                      color: Colors.black26,
                      child: Center(
                        child: SizedBox(
                          width: 24,
                          height: 24,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white.withAlpha(200),
                          ),
                        ),
                      ),
                    ),
                  )
                else if (_failed)
                  Positioned.fill(
                    child: Container(
                      color: Colors.black38,
                      child: Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const FaIcon(
                              FontAwesomeIcons.arrowRotateRight,
                              color: Colors.white,
                              size: 20,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              AppLocalizations.of(context).chatTapToDownload,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      );
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
