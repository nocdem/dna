import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:image_picker/image_picker.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../providers/providers.dart';
import '../../services/image_attachment_service.dart';
import '../../l10n/app_localizations.dart';

/// Full-screen post creation page (Instagram/X style)
class CreatePostScreen extends ConsumerStatefulWidget {
  final ImageAttachment? initialAttachment;
  final Uint8List? initialPreview;

  const CreatePostScreen({
    super.key,
    this.initialAttachment,
    this.initialPreview,
  });

  @override
  ConsumerState<CreatePostScreen> createState() => _CreatePostScreenState();
}

class _CreatePostScreenState extends ConsumerState<CreatePostScreen> {
  final _controller = TextEditingController();
  final _imageService = ImageAttachmentService();
  final _focusNode = FocusNode();
  ImageAttachment? _attachment;
  Uint8List? _previewBytes;
  bool _posting = false;
  bool _boost = false;

  @override
  void initState() {
    super.initState();
    _attachment = widget.initialAttachment;
    _previewBytes = widget.initialPreview;
  }

  @override
  void dispose() {
    _controller.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  Future<void> _pickImage(ImageSource source) async {
    try {
      final bytes = await _imageService.pickImage(source);
      if (bytes == null) return;
      final attachment = await _imageService.processImage(bytes);
      setState(() {
        _attachment = attachment;
        _previewBytes = base64Decode(attachment.base64Data);
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e')),
        );
      }
    }
  }

  Future<void> _submit() async {
    final text = _controller.text.trim();
    if (text.isEmpty || _posting) return;

    setState(() => _posting = true);

    try {
      final notifier = ref.read(wallTimelineProvider.notifier);
      if (_attachment != null) {
        final imageJson = _attachment!.toMessageJson();
        await notifier.createPostWithImage(text, imageJson, boost: _boost);
      } else {
        await notifier.createPost(text, boost: _boost);
      }
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      setState(() => _posting = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to post: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final hasText = _controller.text.trim().isNotEmpty;

    // Get user info for header
    final userProfile = ref.watch(userProfileProvider);
    final nickname = userProfile.whenOrNull(data: (p) => p?.nickname);
    final fullProfile = ref.watch(fullProfileProvider);
    final Uint8List? avatarBytes = fullProfile.whenOrNull(
      data: (profile) {
        if (profile == null) return null;
        return (profile as engine.UserProfile).decodeAvatar();
      },
    );

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const FaIcon(FontAwesomeIcons.xmark),
          onPressed: _posting ? null : () => Navigator.pop(context),
        ),
        title: Text(l10n.wallCreatePostTitle),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: DnaSpacing.sm),
            child: DnaButton(
              label: _posting ? l10n.wallPosting : l10n.wallPost,
              onPressed: (hasText && !_posting) ? _submit : null,
              icon: _posting ? null : FontAwesomeIcons.paperPlane,
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          // User header
          Padding(
            padding: const EdgeInsets.fromLTRB(
              DnaSpacing.lg, DnaSpacing.md, DnaSpacing.lg, DnaSpacing.sm,
            ),
            child: Row(
              children: [
                DnaAvatar(
                  imageBytes: avatarBytes,
                  name: nickname,
                  size: DnaAvatarSize.md,
                ),
                const SizedBox(width: DnaSpacing.md),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        nickname ?? '',
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (_boost)
                        Row(
                          children: [
                            FaIcon(
                              FontAwesomeIcons.rocket,
                              size: 12,
                              color: theme.colorScheme.primary,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              l10n.wallBoosted,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.primary,
                                fontWeight: FontWeight.w500,
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

          // Text input
          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
              child: TextField(
                controller: _controller,
                focusNode: _focusNode,
                maxLines: null,
                expands: true,
                maxLength: 2000,
                autofocus: true,
                textAlignVertical: TextAlignVertical.top,
                style: theme.textTheme.bodyLarge,
                decoration: InputDecoration(
                  hintText: l10n.wallWhatsOnYourMind,
                  border: InputBorder.none,
                  counterStyle: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                onChanged: (_) => setState(() {}),
              ),
            ),
          ),

          // Image preview
          if (_previewBytes != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
              child: Stack(
                alignment: Alignment.topRight,
                children: [
                  ClipRRect(
                    borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                    child: Image.memory(
                      _previewBytes!,
                      height: 200,
                      width: double.infinity,
                      fit: BoxFit.cover,
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(DnaSpacing.xs),
                    child: IconButton(
                      icon: const FaIcon(FontAwesomeIcons.circleXmark, size: 22),
                      style: IconButton.styleFrom(
                        backgroundColor: Colors.black54,
                        foregroundColor: Colors.white,
                      ),
                      onPressed: () => setState(() {
                        _attachment = null;
                        _previewBytes = null;
                      }),
                    ),
                  ),
                ],
              ),
            ),

          // Bottom toolbar
          Container(
            decoration: BoxDecoration(
              border: Border(
                top: BorderSide(
                  color: theme.colorScheme.outlineVariant,
                  width: 0.5,
                ),
              ),
            ),
            padding: const EdgeInsets.symmetric(
              horizontal: DnaSpacing.md,
              vertical: DnaSpacing.sm,
            ),
            child: SafeArea(
              child: Row(
                children: [
                  // Image picker buttons
                  if (_previewBytes == null) ...[
                    IconButton(
                      icon: FaIcon(
                        FontAwesomeIcons.image,
                        size: 20,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      tooltip: 'Gallery',
                      onPressed: _posting
                          ? null
                          : () => _pickImage(ImageSource.gallery),
                    ),
                    IconButton(
                      icon: FaIcon(
                        FontAwesomeIcons.camera,
                        size: 20,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      tooltip: 'Camera',
                      onPressed: _posting
                          ? null
                          : () => _pickImage(ImageSource.camera),
                    ),
                  ],

                  const Spacer(),

                  // Boost toggle
                  InkWell(
                    borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                    onTap: _posting ? null : () => setState(() => _boost = !_boost),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: DnaSpacing.md,
                        vertical: DnaSpacing.sm,
                      ),
                      decoration: BoxDecoration(
                        color: _boost
                            ? theme.colorScheme.primaryContainer
                            : Colors.transparent,
                        borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                        border: Border.all(
                          color: _boost
                              ? theme.colorScheme.primary
                              : theme.colorScheme.outlineVariant,
                        ),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          FaIcon(
                            FontAwesomeIcons.rocket,
                            size: 14,
                            color: _boost
                                ? theme.colorScheme.primary
                                : theme.colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: DnaSpacing.xs),
                          Text(
                            l10n.wallBoost,
                            style: theme.textTheme.labelMedium?.copyWith(
                              color: _boost
                                  ? theme.colorScheme.primary
                                  : theme.colorScheme.onSurfaceVariant,
                              fontWeight: _boost ? FontWeight.w600 : null,
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
        ],
      ),
    );
  }
}
