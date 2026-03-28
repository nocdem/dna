// Media Message Bubble - Display widget for media_ref messages in chat
// Shows thumbnail immediately, downloads full media on tap via MediaService.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';

import '../ffi/dna_engine.dart';
import '../design_system/theme/dna_colors.dart';
import '../l10n/app_localizations.dart';
import '../models/media_ref.dart';
import '../services/media_service.dart';
import '../utils/logger.dart';

const String _tag = 'MEDIA_BUBBLE';

/// In-memory cache of downloaded full-resolution media bytes, keyed by content hash.
final Map<String, Uint8List> _mediaCache = {};

/// Message bubble for displaying media_ref messages.
/// Shows thumbnail immediately; full media is lazy-loaded on tap.
class MediaMessageBubble extends StatefulWidget {
  final Message message;
  final Map<String, dynamic> mediaData;
  final DnaEngine engine;

  const MediaMessageBubble({
    super.key,
    required this.message,
    required this.mediaData,
    required this.engine,
  });

  @override
  State<MediaMessageBubble> createState() => _MediaMessageBubbleState();
}

class _MediaMessageBubbleState extends State<MediaMessageBubble> {
  bool _downloading = false;
  bool _downloadFailed = false;
  Uint8List? _fullImageBytes;

  MediaRef? get _ref => MediaRef.fromJson(widget.mediaData);

  @override
  void initState() {
    super.initState();
    // Check cache
    final ref = _ref;
    if (ref != null) {
      _fullImageBytes = _mediaCache[ref.contentHash];
    }
  }

  Uint8List? _decodeThumbnail() {
    try {
      final thumb = widget.mediaData['thumbnail'] as String?;
      if (thumb == null || thumb.isEmpty) return null;
      return base64Decode(thumb);
    } catch (e) {
      return null;
    }
  }

  Future<void> _downloadFullMedia() async {
    final ref = _ref;
    if (ref == null) return;

    // Already cached
    if (_mediaCache.containsKey(ref.contentHash)) {
      setState(() {
        _fullImageBytes = _mediaCache[ref.contentHash];
        _downloadFailed = false;
      });
      return;
    }

    setState(() {
      _downloading = true;
      _downloadFailed = false;
    });

    try {
      final mediaService = MediaService(widget.engine);
      final bytes = await mediaService.download(ref);
      _mediaCache[ref.contentHash] = bytes;
      if (mounted) {
        setState(() {
          _fullImageBytes = bytes;
          _downloading = false;
        });
      }
    } catch (e) {
      logError(_tag, 'Download failed: $e');
      if (mounted) {
        setState(() {
          _downloading = false;
          _downloadFailed = true;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final ref = _ref;
    if (ref == null) return const SizedBox.shrink();

    if (ref.isImage) {
      return _buildImageBubble(context, ref);
    } else if (ref.isVideo) {
      return _buildPlaceholderBubble(
        context,
        ref,
        FontAwesomeIcons.circlePlay,
        AppLocalizations.of(context).chatVideoComingSoon,
      );
    } else if (ref.isAudio) {
      return _buildPlaceholderBubble(
        context,
        ref,
        FontAwesomeIcons.headphones,
        AppLocalizations.of(context).chatAudioComingSoon,
      );
    } else {
      return _buildPlaceholderBubble(
        context,
        ref,
        FontAwesomeIcons.file,
        AppLocalizations.of(context).chatMediaUnsupported,
      );
    }
  }

  Widget _buildImageBubble(BuildContext context, MediaRef ref) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final isOutgoing = widget.message.isOutgoing;
    final thumbnailBytes = _decodeThumbnail();
    final caption = ref.caption;
    final width = ref.width;
    final height = ref.height;

    final aspectRatio =
        width > 0 && height > 0 ? width / height : 4 / 3;

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 280),
        margin: EdgeInsets.only(
          top: 4,
          bottom: 4,
          left: isOutgoing ? 48 : 0,
          right: isOutgoing ? 0 : 48,
        ),
        decoration: BoxDecoration(
          color: isOutgoing
              ? theme.colorScheme.primary
              : theme.colorScheme.surface,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 16),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Thumbnail / full image with overlay
            ClipRRect(
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(16),
                topRight: const Radius.circular(16),
                bottomLeft: Radius.circular(
                    caption != null && caption.isNotEmpty
                        ? 0
                        : (isOutgoing ? 16 : 4)),
                bottomRight: Radius.circular(
                    caption != null && caption.isNotEmpty
                        ? 0
                        : (isOutgoing ? 4 : 16)),
              ),
              child: GestureDetector(
                onTap: () => _onImageTap(context, ref),
                child: AspectRatio(
                  aspectRatio: (aspectRatio as double).clamp(0.5, 2.0),
                  child: Stack(
                    fit: StackFit.expand,
                    children: [
                      // Image layer: full if available, else thumbnail
                      if (_fullImageBytes != null)
                        Image.memory(
                          _fullImageBytes!,
                          fit: BoxFit.cover,
                          errorBuilder: (_, __, ___) => _buildErrorPlaceholder(),
                        )
                      else if (thumbnailBytes != null)
                        Image.memory(
                          thumbnailBytes,
                          fit: BoxFit.cover,
                          errorBuilder: (_, __, ___) => _buildErrorPlaceholder(),
                        )
                      else
                        _buildErrorPlaceholder(),

                      // Overlay: download indicator
                      if (_downloading)
                        Container(
                          color: Colors.black38,
                          child: Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const CircularProgressIndicator(
                                  color: Colors.white,
                                  strokeWidth: 2,
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  l10n.chatDownloadingMedia,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        )
                      else if (_downloadFailed)
                        Container(
                          color: Colors.black38,
                          child: Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const FaIcon(
                                  FontAwesomeIcons.circleExclamation,
                                  color: Colors.white,
                                  size: 24,
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  l10n.chatUploadFailed,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 12,
                                  ),
                                  textAlign: TextAlign.center,
                                ),
                              ],
                            ),
                          ),
                        )
                      else if (_fullImageBytes == null)
                        Container(
                          color: Colors.black26,
                          child: Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const FaIcon(
                                  FontAwesomeIcons.circleDown,
                                  color: Colors.white,
                                  size: 28,
                                ),
                                const SizedBox(height: 6),
                                Text(
                                  l10n.chatTapToDownload,
                                  style: const TextStyle(
                                    color: Colors.white,
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
              ),
            ),

            // Caption, timestamp, status
            Padding(
              padding: const EdgeInsets.all(8),
              child: Column(
                crossAxisAlignment: isOutgoing
                    ? CrossAxisAlignment.end
                    : CrossAxisAlignment.start,
                children: [
                  if (caption != null && caption.isNotEmpty) ...[
                    Text(
                      caption,
                      style: TextStyle(
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary
                            : theme.colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 4),
                  ],
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        DateFormat('HH:mm').format(widget.message.timestamp),
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontSize: 10,
                          color: isOutgoing
                              ? theme.colorScheme.onPrimary.withAlpha(179)
                              : theme.textTheme.bodySmall?.color,
                        ),
                      ),
                      if (isOutgoing) ...[
                        const SizedBox(width: 4),
                        _buildStatusIndicator(widget.message.status, theme),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPlaceholderBubble(
    BuildContext context,
    MediaRef ref,
    IconData icon,
    String label,
  ) {
    final theme = Theme.of(context);
    final isOutgoing = widget.message.isOutgoing;
    final caption = ref.caption;
    final thumbnailBytes = _decodeThumbnail();

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 280),
        margin: EdgeInsets.only(
          top: 4,
          bottom: 4,
          left: isOutgoing ? 48 : 0,
          right: isOutgoing ? 0 : 48,
        ),
        decoration: BoxDecoration(
          color: isOutgoing
              ? theme.colorScheme.primary
              : theme.colorScheme.surface,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 16),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Thumbnail with overlay icon
            ClipRRect(
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(16),
                topRight: Radius.circular(16),
              ),
              child: SizedBox(
                height: 160,
                child: Stack(
                  fit: StackFit.expand,
                  children: [
                    if (thumbnailBytes != null)
                      Image.memory(
                        thumbnailBytes,
                        fit: BoxFit.cover,
                        errorBuilder: (_, __, ___) => Container(
                          color: Colors.grey[800],
                        ),
                      )
                    else
                      Container(color: Colors.grey[800]),
                    Container(
                      color: Colors.black45,
                      child: Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            FaIcon(icon, color: Colors.white, size: 32),
                            const SizedBox(height: 8),
                            Text(
                              label,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                              ),
                              textAlign: TextAlign.center,
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),

            // Caption + timestamp
            Padding(
              padding: const EdgeInsets.all(8),
              child: Column(
                crossAxisAlignment: isOutgoing
                    ? CrossAxisAlignment.end
                    : CrossAxisAlignment.start,
                children: [
                  if (caption != null && caption.isNotEmpty) ...[
                    Text(
                      caption,
                      style: TextStyle(
                        color: isOutgoing
                            ? theme.colorScheme.onPrimary
                            : theme.colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 4),
                  ],
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        DateFormat('HH:mm').format(widget.message.timestamp),
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontSize: 10,
                          color: isOutgoing
                              ? theme.colorScheme.onPrimary.withAlpha(179)
                              : theme.textTheme.bodySmall?.color,
                        ),
                      ),
                      if (isOutgoing) ...[
                        const SizedBox(width: 4),
                        _buildStatusIndicator(widget.message.status, theme),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _onImageTap(BuildContext context, MediaRef ref) {
    if (_fullImageBytes != null) {
      // Show fullscreen viewer
      Navigator.of(context).push(
        MaterialPageRoute(
          builder: (_) => _FullscreenMediaViewer(
            imageBytes: _fullImageBytes!,
            caption: ref.caption,
          ),
        ),
      );
    } else if (!_downloading) {
      // Download first, then show
      _downloadFullMedia();
    }
  }

  Widget _buildErrorPlaceholder() {
    return Container(
      color: Colors.grey[300],
      child: const Center(
        child: FaIcon(FontAwesomeIcons.image, color: Colors.grey),
      ),
    );
  }

  Widget _buildStatusIndicator(MessageStatus status, ThemeData theme) {
    final color = theme.colorScheme.onPrimary.withAlpha(179);
    const size = 16.0;

    if (status == MessageStatus.failed) {
      return FaIcon(
        FontAwesomeIcons.circleExclamation,
        size: size,
        color: DnaColors.textWarning,
      );
    }

    IconData icon;
    switch (status) {
      case MessageStatus.pending:
        icon = FontAwesomeIcons.clock;
      case MessageStatus.sent:
        icon = FontAwesomeIcons.check;
      case MessageStatus.received:
        icon = FontAwesomeIcons.checkDouble;
      case MessageStatus.failed:
        icon = FontAwesomeIcons.circleExclamation;
    }

    return FaIcon(icon, size: size, color: color);
  }
}

/// Fullscreen image viewer with pinch-zoom (same as ImageMessageBubble's viewer)
class _FullscreenMediaViewer extends StatelessWidget {
  final Uint8List imageBytes;
  final String? caption;

  const _FullscreenMediaViewer({
    required this.imageBytes,
    this.caption,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: caption != null && caption!.isNotEmpty
            ? Text(
                caption!,
                style: const TextStyle(fontSize: 14),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              )
            : null,
      ),
      body: InteractiveViewer(
        minScale: 0.5,
        maxScale: 4.0,
        child: Center(
          child: Image.memory(imageBytes),
        ),
      ),
    );
  }
}
