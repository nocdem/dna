import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:image_picker/image_picker.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../providers/providers.dart';
import '../../services/image_attachment_service.dart';
import '../../services/media_service.dart';
import '../../models/media_ref.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/logger.dart';

/// Full-screen post creation page (modern design)
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
  static const String _tag = 'WALL_CREATE';
  final _controller = TextEditingController();
  final _imageService = ImageAttachmentService();
  final _focusNode = FocusNode();
  ImageAttachment? _attachment;
  Uint8List? _rawImageBytes; // Raw bytes for MediaService upload
  Uint8List? _previewBytes;
  bool _posting = false;
  bool _boost = false;
  bool _uploading = false;

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
        _rawImageBytes = bytes;
        _previewBytes = Uint8List.fromList(bytes);
      });
    } catch (e) {
      if (mounted) {
        DnaSnackBar.error(context, '$e');
      }
    }
  }

  Future<void> _submit() async {
    final text = _controller.text.trim();
    if (text.isEmpty || _posting) return;

    setState(() => _posting = true);

    try {
      final notifier = ref.read(wallTimelineProvider.notifier);
      if (_rawImageBytes != null) {
        // Upload image via MediaService (unencrypted, 30-day TTL for wall)
        setState(() => _uploading = true);
        final dnaEngine = await ref.read(engineProvider.future);
        final mediaService = MediaService(dnaEngine);
        final mediaRef = await mediaService.uploadImage(
          _rawImageBytes!,
          encrypted: false,
          ttl: 2592000, // 30 days — matches wall post TTL
        );
        log(_tag, 'Media uploaded: ${mediaRef.contentHash.substring(0, 16)}...');
        setState(() => _uploading = false);

        final imageJson = mediaRef.toMessageJson();
        await notifier.createPostWithImage(text, imageJson, boost: _boost);
      } else {
        await notifier.createPost(text, boost: _boost);
      }
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      setState(() {
        _posting = false;
        _uploading = false;
      });
      if (mounted) {
        DnaSnackBar.error(context, 'Failed to post: $e');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final hasText = _controller.text.trim().isNotEmpty;
    final isDark = theme.brightness == Brightness.dark;

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
      appBar: DnaAppBar(
        title: l10n.wallCreatePostTitle,
        leading: IconButton(
          icon: const FaIcon(FontAwesomeIcons.xmark, size: 20),
          onPressed: _posting ? null : () => Navigator.pop(context),
        ),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: DnaSpacing.sm),
            child: DnaButton(
              label: _uploading
                  ? l10n.wallUploadingImage
                  : _posting
                      ? l10n.wallPosting
                      : l10n.wallPost,
              onPressed: (hasText && !_posting) ? _submit : null,
              icon: _posting ? null : FontAwesomeIcons.paperPlane,
              loading: _posting,
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          // ── Composer area ──
          Expanded(
            child: GestureDetector(
              onTap: () => _focusNode.requestFocus(),
              behavior: HitTestBehavior.translucent,
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(DnaSpacing.lg),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // ── User header row ──
                    Row(
                      children: [
                        DnaAvatar(
                          imageBytes: avatarBytes,
                          name: nickname,
                          size: DnaAvatarSize.lg,
                        ),
                        const SizedBox(width: DnaSpacing.md),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                nickname ?? '',
                                style: theme.textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              const SizedBox(height: 2),
                              if (_boost)
                                _BoostBadge(theme: theme, l10n: l10n)
                              else
                                Text(
                                  l10n.wallCreatePostTitle,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                  ),
                                ),
                            ],
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: DnaSpacing.xl),

                    // ── Text input ──
                    TextField(
                      controller: _controller,
                      focusNode: _focusNode,
                      maxLines: null,
                      minLines: 5,
                      maxLength: 2000,
                      autofocus: true,
                      style: theme.textTheme.bodyLarge?.copyWith(
                        height: 1.5,
                      ),
                      decoration: InputDecoration(
                        hintText: l10n.wallWhatsOnYourMind,
                        hintStyle: theme.textTheme.bodyLarge?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant
                              .withOpacity(0.5),
                        ),
                        border: InputBorder.none,
                        enabledBorder: InputBorder.none,
                        focusedBorder: InputBorder.none,
                        contentPadding: EdgeInsets.zero,
                        counterStyle: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      onChanged: (_) => setState(() {}),
                    ),

                    // ── Image preview ──
                    if (_previewBytes != null) ...[
                      const SizedBox(height: DnaSpacing.lg),
                      Container(
                        decoration: BoxDecoration(
                          borderRadius:
                              BorderRadius.circular(DnaSpacing.radiusLg),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withOpacity(0.2),
                              blurRadius: 12,
                              offset: const Offset(0, 4),
                            ),
                          ],
                        ),
                        child: Stack(
                          children: [
                            ClipRRect(
                              borderRadius:
                                  BorderRadius.circular(DnaSpacing.radiusLg),
                              child: Image.memory(
                                _previewBytes!,
                                width: double.infinity,
                                fit: BoxFit.cover,
                              ),
                            ),
                            // Gradient overlay at top for delete button
                            Positioned(
                              top: 0,
                              left: 0,
                              right: 0,
                              height: 56,
                              child: ClipRRect(
                                borderRadius: const BorderRadius.only(
                                  topLeft:
                                      Radius.circular(DnaSpacing.radiusLg),
                                  topRight:
                                      Radius.circular(DnaSpacing.radiusLg),
                                ),
                                child: DecoratedBox(
                                  decoration: BoxDecoration(
                                    gradient: LinearGradient(
                                      begin: Alignment.topCenter,
                                      end: Alignment.bottomCenter,
                                      colors: [
                                        Colors.black.withOpacity(0.5),
                                        Colors.transparent,
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                            ),
                            // Delete button
                            Positioned(
                              top: DnaSpacing.sm,
                              right: DnaSpacing.sm,
                              child: Material(
                                color: Colors.black45,
                                borderRadius: BorderRadius.circular(
                                    DnaSpacing.radiusFull),
                                child: InkWell(
                                  borderRadius: BorderRadius.circular(
                                      DnaSpacing.radiusFull),
                                  onTap: () => setState(() {
                                    _attachment = null;
                                    _rawImageBytes = null;
                                    _previewBytes = null;
                                  }),
                                  child: const Padding(
                                    padding: EdgeInsets.all(DnaSpacing.sm),
                                    child: FaIcon(
                                      FontAwesomeIcons.xmark,
                                      size: 16,
                                      color: Colors.white,
                                    ),
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),

          // ── Bottom toolbar ──
          Container(
            decoration: BoxDecoration(
              color: isDark
                  ? DnaColors.darkSurface
                  : theme.colorScheme.surfaceContainerLow,
              border: Border(
                top: BorderSide(
                  color: isDark
                      ? DnaColors.darkDivider
                      : theme.colorScheme.outlineVariant,
                  width: 0.5,
                ),
              ),
            ),
            child: SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: DnaSpacing.md,
                  vertical: DnaSpacing.sm,
                ),
                child: Row(
                  children: [
                    // Image picker buttons
                    if (_previewBytes == null) ...[
                      _ToolbarButton(
                        icon: FontAwesomeIcons.image,
                        label: 'Gallery',
                        onTap: _posting
                            ? null
                            : () => _pickImage(ImageSource.gallery),
                        theme: theme,
                      ),
                      const SizedBox(width: DnaSpacing.sm),
                      _ToolbarButton(
                        icon: FontAwesomeIcons.camera,
                        label: 'Camera',
                        onTap: _posting
                            ? null
                            : () => _pickImage(ImageSource.camera),
                        theme: theme,
                      ),
                    ],

                    const Spacer(),

                    // Boost toggle
                    _BoostToggle(
                      active: _boost,
                      enabled: !_posting,
                      onTap: () => setState(() => _boost = !_boost),
                      theme: theme,
                      l10n: l10n,
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Toolbar action button (pill-shaped) ──
class _ToolbarButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  final ThemeData theme;

  const _ToolbarButton({
    required this.icon,
    required this.label,
    required this.onTap,
    required this.theme,
  });

  @override
  Widget build(BuildContext context) {
    final color = onTap != null
        ? theme.colorScheme.onSurfaceVariant
        : theme.colorScheme.onSurfaceVariant.withOpacity(0.4);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.md,
            vertical: DnaSpacing.sm,
          ),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
            border: Border.all(
              color: theme.colorScheme.outlineVariant.withOpacity(0.5),
            ),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              FaIcon(icon, size: 15, color: color),
              const SizedBox(width: DnaSpacing.xs),
              Text(
                label,
                style: theme.textTheme.labelSmall?.copyWith(
                  color: color,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Boost toggle pill ──
class _BoostToggle extends StatelessWidget {
  final bool active;
  final bool enabled;
  final VoidCallback onTap;
  final ThemeData theme;
  final AppLocalizations l10n;

  const _BoostToggle({
    required this.active,
    required this.enabled,
    required this.onTap,
    required this.theme,
    required this.l10n,
  });

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
        onTap: enabled ? onTap : null,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeInOut,
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.md,
            vertical: DnaSpacing.sm,
          ),
          decoration: BoxDecoration(
            gradient: active
                ? const LinearGradient(
                    colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
                  )
                : null,
            color: active ? null : Colors.transparent,
            borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
            border: Border.all(
              color: active
                  ? Colors.transparent
                  : theme.colorScheme.outlineVariant.withOpacity(0.5),
            ),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              FaIcon(
                FontAwesomeIcons.rocket,
                size: 13,
                color: active
                    ? Colors.white
                    : theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: DnaSpacing.xs),
              Text(
                l10n.wallBoost,
                style: theme.textTheme.labelMedium?.copyWith(
                  color: active
                      ? Colors.white
                      : theme.colorScheme.onSurfaceVariant,
                  fontWeight: active ? FontWeight.w600 : FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Boost badge (shown under username) ──
class _BoostBadge extends StatelessWidget {
  final ThemeData theme;
  final AppLocalizations l10n;

  const _BoostBadge({required this.theme, required this.l10n});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.sm,
        vertical: 2,
      ),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
        ),
        borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const FaIcon(
            FontAwesomeIcons.rocket,
            size: 10,
            color: Colors.white,
          ),
          const SizedBox(width: 4),
          Text(
            l10n.wallBoosted,
            style: theme.textTheme.labelSmall?.copyWith(
              color: Colors.white,
              fontWeight: FontWeight.w600,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }
}
