// Image Message Bubble - Display widget for image attachments in chat
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';

import '../ffi/dna_engine.dart';
import '../theme/dna_theme.dart';

/// Message bubble for displaying image attachments
class ImageMessageBubble extends StatelessWidget {
  final Message message;
  final Map<String, dynamic> imageData;

  const ImageMessageBubble({
    super.key,
    required this.message,
    required this.imageData,
  });

  Uint8List? _decodeImage() {
    try {
      final data = imageData['data'] as String?;
      if (data == null || data.isEmpty) return null;
      return base64Decode(data);
    } catch (e) {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOutgoing = message.isOutgoing;
    final imageBytes = _decodeImage();
    final caption = imageData['caption'] as String?;
    final width = (imageData['width'] as num?)?.toInt() ?? 0;
    final height = (imageData['height'] as num?)?.toInt() ?? 0;

    // Calculate aspect ratio for display
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
            // Image with tap to fullscreen
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
                onTap: () => _showFullscreenImage(context, imageBytes),
                child: AspectRatio(
                  aspectRatio: aspectRatio.clamp(0.5, 2.0),
                  child: imageBytes != null
                      ? Image.memory(
                          imageBytes,
                          fit: BoxFit.cover,
                          errorBuilder: (context, error, stackTrace) => _buildErrorPlaceholder(),
                        )
                      : _buildErrorPlaceholder(),
                ),
              ),
            ),

            // Caption, timestamp, and status
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
                        DateFormat('HH:mm').format(message.timestamp),
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontSize: 10,
                          color: isOutgoing
                              ? theme.colorScheme.onPrimary.withAlpha(179)
                              : theme.textTheme.bodySmall?.color,
                        ),
                      ),
                      if (isOutgoing) ...[
                        const SizedBox(width: 4),
                        _buildStatusIndicator(message.status, theme),
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

    // v15: Simplified 4-state status model
    IconData icon;
    switch (status) {
      case MessageStatus.pending:
        // Clock for pending (queued, waiting for DHT PUT)
        icon = FontAwesomeIcons.clock;
      case MessageStatus.sent:
        // Single tick for sent (DHT PUT succeeded)
        icon = FontAwesomeIcons.check;
      case MessageStatus.received:
        // Double tick for received (recipient ACK'd)
        icon = FontAwesomeIcons.checkDouble;
      case MessageStatus.failed:
        icon = FontAwesomeIcons.circleExclamation;
    }

    return FaIcon(icon, size: size, color: color);
  }

  void _showFullscreenImage(BuildContext context, Uint8List? imageBytes) {
    if (imageBytes == null) return;

    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => _FullscreenImageViewer(
          imageBytes: imageBytes,
          caption: imageData['caption'] as String?,
        ),
      ),
    );
  }
}

/// Fullscreen image viewer with pinch-zoom
class _FullscreenImageViewer extends StatelessWidget {
  final Uint8List imageBytes;
  final String? caption;

  const _FullscreenImageViewer({
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
