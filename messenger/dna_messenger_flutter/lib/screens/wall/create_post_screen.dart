import 'dart:typed_data';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:image_picker/image_picker.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart' as engine;
import '../../providers/providers.dart';
import '../../services/image_attachment_service.dart';
import '../../services/media_service.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/logger.dart';

/// Full-screen post creation page — refined "liquid glass" aesthetic
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

class _CreatePostScreenState extends ConsumerState<CreatePostScreen>
    with SingleTickerProviderStateMixin {
  static const String _tag = 'WALL_CREATE';
  final _controller = TextEditingController();
  final _imageService = ImageAttachmentService();
  final _focusNode = FocusNode();
  ImageAttachment? _attachment;
  Uint8List? _rawImageBytes;
  Uint8List? _previewBytes;
  bool _posting = false;
  bool _boost = false;
  bool _uploading = false;

  late final AnimationController _boostAnimController;
  late final Animation<double> _boostScale;

  @override
  void initState() {
    super.initState();
    _attachment = widget.initialAttachment;
    _previewBytes = widget.initialPreview;
    _boostAnimController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
    _boostScale = Tween<double>(begin: 1.0, end: 0.92).animate(
      CurvedAnimation(parent: _boostAnimController, curve: Curves.easeOutBack),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    _focusNode.dispose();
    _boostAnimController.dispose();
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

  void _toggleBoost() {
    _boostAnimController.forward().then((_) {
      _boostAnimController.reverse();
    });
    setState(() => _boost = !_boost);
  }

  Future<void> _submit() async {
    final text = _controller.text.trim();
    if (text.isEmpty || _posting) return;

    setState(() => _posting = true);

    try {
      final notifier = ref.read(wallTimelineProvider.notifier);
      if (_rawImageBytes != null) {
        setState(() => _uploading = true);
        final dnaEngine = await ref.read(engineProvider.future);
        final mediaService = MediaService(dnaEngine);
        final mediaRef = await mediaService.uploadImage(
          _rawImageBytes!,
          encrypted: false,
          ttl: 2592000,
        );
        log(_tag,
            'Media uploaded: ${mediaRef.contentHash.substring(0, 16)}...');
        setState(() => _uploading = false);

        final imageJson = mediaRef.toMessageJson();
        final post = await notifier.createPostWithImage(text, imageJson, boost: _boost);
        if (_boost && !post.isBoosted && mounted) {
          DnaSnackBar.info(context, AppLocalizations.of(context).wallBoostLimitReached);
        }
      } else {
        final post = await notifier.createPost(text, boost: _boost);
        if (_boost && !post.isBoosted && mounted) {
          DnaSnackBar.info(context, AppLocalizations.of(context).wallBoostLimitReached);
        }
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

    final userProfile = ref.watch(userProfileProvider);
    final nickname = userProfile.whenOrNull(data: (p) => p?.nickname);
    final fullProfile = ref.watch(fullProfileProvider);
    final Uint8List? avatarBytes = fullProfile.whenOrNull(
      data: (profile) {
        if (profile == null) return null;
        return (profile as engine.UserProfile).decodeAvatar();
      },
    );

    final charCount = _controller.text.length;
    final charRatio = charCount / 2000;

    return Scaffold(
      backgroundColor: isDark ? DnaColors.darkBackground : theme.colorScheme.surface,
      body: Column(
        children: [
          // ── Custom header with gradient accent ──
          _ComposeHeader(
            isDark: isDark,
            theme: theme,
            l10n: l10n,
            hasText: hasText,
            posting: _posting,
            uploading: _uploading,
            onClose: () => Navigator.pop(context),
            onSubmit: _submit,
          ),

          // ── Composer body ──
          Expanded(
            child: GestureDetector(
              onTap: () => _focusNode.requestFocus(),
              behavior: HitTestBehavior.translucent,
              child: SingleChildScrollView(
                physics: const BouncingScrollPhysics(),
                padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.xl),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: DnaSpacing.lg),

                    // ── Author row ──
                    Row(
                      children: [
                        // Avatar with gradient ring when boost active
                        AnimatedContainer(
                          duration: const Duration(milliseconds: 300),
                          curve: Curves.easeInOut,
                          padding: const EdgeInsets.all(2),
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            gradient: _boost
                                ? const LinearGradient(
                                    colors: [
                                      Color(0xFF00D4FF),
                                      Color(0xFF6366F1),
                                      Color(0xFFAB47BC),
                                    ],
                                    transform: GradientRotation(math.pi / 4),
                                  )
                                : null,
                            border: _boost
                                ? null
                                : Border.all(
                                    color: isDark
                                        ? DnaColors.darkDivider
                                        : theme.colorScheme.outlineVariant,
                                    width: 1.5,
                                  ),
                          ),
                          child: DnaAvatar(
                            imageBytes: avatarBytes,
                            name: nickname,
                            size: DnaAvatarSize.lg,
                          ),
                        ),
                        const SizedBox(width: DnaSpacing.md),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                nickname ?? '',
                                style: theme.textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                  letterSpacing: -0.3,
                                ),
                              ),
                              const SizedBox(height: 3),
                              AnimatedSwitcher(
                                duration: const Duration(milliseconds: 250),
                                child: _boost
                                    ? _BoostBadge(key: const ValueKey('boost'), l10n: l10n)
                                    : Text(
                                        key: const ValueKey('public'),
                                        l10n.wallCreatePostTitle,
                                        style: theme.textTheme.bodySmall?.copyWith(
                                          color: theme.colorScheme.onSurfaceVariant
                                              .withValues(alpha: 0.7),
                                          letterSpacing: 0.2,
                                        ),
                                      ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: DnaSpacing.xl),

                    // ── Thin gradient divider ──
                    Container(
                      height: 1,
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          colors: [
                            Colors.transparent,
                            (isDark ? DnaColors.gradientStart : DnaColors.gradientEnd)
                                .withValues(alpha: 0.2),
                            Colors.transparent,
                          ],
                        ),
                      ),
                    ),

                    const SizedBox(height: DnaSpacing.xl),

                    // ── Text input ──
                    TextField(
                      controller: _controller,
                      focusNode: _focusNode,
                      maxLines: null,
                      minLines: 6,
                      maxLength: 2000,
                      autofocus: true,
                      style: theme.textTheme.bodyLarge?.copyWith(
                        height: 1.6,
                        fontSize: 16,
                        letterSpacing: 0.1,
                      ),
                      decoration: InputDecoration(
                        hintText: l10n.wallWhatsOnYourMind,
                        hintStyle: theme.textTheme.bodyLarge?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant
                              .withValues(alpha: 0.35),
                          fontSize: 16,
                          fontStyle: FontStyle.italic,
                        ),
                        border: InputBorder.none,
                        enabledBorder: InputBorder.none,
                        focusedBorder: InputBorder.none,
                        contentPadding: const EdgeInsets.symmetric(
                          horizontal: DnaSpacing.sm,
                          vertical: DnaSpacing.md,
                        ),
                        counterText: '', // hide default counter
                      ),
                      onChanged: (_) => setState(() {}),
                    ),

                    // ── Character counter (custom, subtle) ──
                    if (charCount > 0)
                      Padding(
                        padding: const EdgeInsets.only(top: DnaSpacing.xs),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.end,
                          children: [
                            SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                value: charRatio,
                                strokeWidth: 2,
                                backgroundColor: isDark
                                    ? DnaColors.darkDivider
                                    : theme.colorScheme.outlineVariant
                                        .withValues(alpha: 0.3),
                                valueColor: AlwaysStoppedAnimation(
                                  charRatio > 0.9
                                      ? DnaColors.error
                                      : charRatio > 0.7
                                          ? DnaColors.warning
                                          : DnaColors.gradientStart
                                              .withValues(alpha: 0.5),
                                ),
                              ),
                            ),
                            const SizedBox(width: DnaSpacing.sm),
                            Text(
                              '$charCount / 2000',
                              style: theme.textTheme.labelSmall?.copyWith(
                                color: charRatio > 0.9
                                    ? DnaColors.error
                                    : theme.colorScheme.onSurfaceVariant
                                        .withValues(alpha: 0.4),
                                fontSize: 11,
                                fontFeatures: const [FontFeature.tabularFigures()],
                              ),
                            ),
                          ],
                        ),
                      ),

                    // ── Image preview ──
                    if (_previewBytes != null) ...[
                      const SizedBox(height: DnaSpacing.xl),
                      _ImagePreview(
                        imageBytes: _previewBytes!,
                        onRemove: () => setState(() {
                          _attachment = null;
                          _rawImageBytes = null;
                          _previewBytes = null;
                        }),
                      ),
                    ],

                    const SizedBox(height: DnaSpacing.xxl),
                  ],
                ),
              ),
            ),
          ),

          // ── Bottom toolbar ──
          _ComposeToolbar(
            isDark: isDark,
            theme: theme,
            l10n: l10n,
            posting: _posting,
            boost: _boost,
            hasImage: _previewBytes != null,
            boostScale: _boostScale,
            onPickGallery: () => _pickImage(ImageSource.gallery),
            onPickCamera: () => _pickImage(ImageSource.camera),
            onToggleBoost: _toggleBoost,
          ),
        ],
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// COMPOSE HEADER — gradient accent line below app bar
// ═══════════════════════════════════════════════════════════════

class _ComposeHeader extends StatelessWidget {
  final bool isDark;
  final ThemeData theme;
  final AppLocalizations l10n;
  final bool hasText;
  final bool posting;
  final bool uploading;
  final VoidCallback onClose;
  final VoidCallback onSubmit;

  const _ComposeHeader({
    required this.isDark,
    required this.theme,
    required this.l10n,
    required this.hasText,
    required this.posting,
    required this.uploading,
    required this.onClose,
    required this.onSubmit,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SafeArea(
          bottom: false,
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: DnaSpacing.sm,
              vertical: DnaSpacing.sm,
            ),
            child: Row(
              children: [
                IconButton(
                  icon: FaIcon(
                    FontAwesomeIcons.xmark,
                    size: 20,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  onPressed: posting ? null : onClose,
                ),
                const Spacer(),
                // Post button with gradient
                AnimatedOpacity(
                  duration: const Duration(milliseconds: 200),
                  opacity: hasText ? 1.0 : 0.4,
                  child: _PostButton(
                    label: uploading
                        ? l10n.wallUploadingImage
                        : posting
                            ? l10n.wallPosting
                            : l10n.wallPost,
                    enabled: hasText && !posting,
                    loading: posting,
                    onTap: onSubmit,
                  ),
                ),
              ],
            ),
          ),
        ),
        // Thin gradient accent
        Container(
          height: 1,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [
                Colors.transparent,
                DnaColors.gradientStart.withValues(alpha: isDark ? 0.3 : 0.15),
                DnaColors.gradientEnd.withValues(alpha: isDark ? 0.3 : 0.15),
                Colors.transparent,
              ],
              stops: const [0.0, 0.3, 0.7, 1.0],
            ),
          ),
        ),
      ],
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// POST BUTTON — gradient pill
// ═══════════════════════════════════════════════════════════════

class _PostButton extends StatelessWidget {
  final String label;
  final bool enabled;
  final bool loading;
  final VoidCallback onTap;

  const _PostButton({
    required this.label,
    required this.enabled,
    required this.loading,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: enabled ? onTap : null,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.xl,
          vertical: DnaSpacing.sm + 2,
        ),
        decoration: BoxDecoration(
          gradient: enabled
              ? const LinearGradient(
                  colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
                )
              : null,
          color: enabled ? null : Colors.grey.withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
          boxShadow: enabled
              ? [
                  BoxShadow(
                    color: DnaColors.gradientEnd.withValues(alpha: 0.3),
                    blurRadius: 12,
                    offset: const Offset(0, 4),
                  ),
                ]
              : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (loading)
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  valueColor: AlwaysStoppedAnimation(Colors.white),
                ),
              )
            else
              const FaIcon(
                FontAwesomeIcons.paperPlane,
                size: 13,
                color: Colors.white,
              ),
            const SizedBox(width: DnaSpacing.sm),
            Text(
              label,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 13,
                fontWeight: FontWeight.w600,
                letterSpacing: 0.3,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// COMPOSE TOOLBAR — bottom bar with media + boost
// ═══════════════════════════════════════════════════════════════

class _ComposeToolbar extends StatelessWidget {
  final bool isDark;
  final ThemeData theme;
  final AppLocalizations l10n;
  final bool posting;
  final bool boost;
  final bool hasImage;
  final Animation<double> boostScale;
  final VoidCallback onPickGallery;
  final VoidCallback onPickCamera;
  final VoidCallback onToggleBoost;

  const _ComposeToolbar({
    required this.isDark,
    required this.theme,
    required this.l10n,
    required this.posting,
    required this.boost,
    required this.hasImage,
    required this.boostScale,
    required this.onPickGallery,
    required this.onPickCamera,
    required this.onToggleBoost,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: isDark
            ? DnaColors.darkSurface.withValues(alpha: 0.95)
            : theme.colorScheme.surfaceContainerLow,
        border: Border(
          top: BorderSide(
            color: isDark
                ? DnaColors.darkDivider
                : theme.colorScheme.outlineVariant.withValues(alpha: 0.5),
            width: 0.5,
          ),
        ),
      ),
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.lg,
            vertical: DnaSpacing.md,
          ),
          child: Row(
            children: [
              // Media buttons
              if (!hasImage) ...[
                _MediaButton(
                  icon: FontAwesomeIcons.image,
                  onTap: posting ? null : onPickGallery,
                  isDark: isDark,
                  theme: theme,
                ),
                const SizedBox(width: DnaSpacing.md),
                _MediaButton(
                  icon: FontAwesomeIcons.camera,
                  onTap: posting ? null : onPickCamera,
                  isDark: isDark,
                  theme: theme,
                ),
              ],

              const Spacer(),

              // Boost toggle
              ScaleTransition(
                scale: boostScale,
                child: _BoostToggle(
                  active: boost,
                  enabled: !posting,
                  onTap: onToggleBoost,
                  isDark: isDark,
                  theme: theme,
                  l10n: l10n,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// MEDIA BUTTON — clean icon button with hover ring
// ═══════════════════════════════════════════════════════════════

class _MediaButton extends StatelessWidget {
  final IconData icon;
  final VoidCallback? onTap;
  final bool isDark;
  final ThemeData theme;

  const _MediaButton({
    required this.icon,
    required this.onTap,
    required this.isDark,
    required this.theme,
  });

  @override
  Widget build(BuildContext context) {
    final color = onTap != null
        ? (isDark ? DnaColors.gradientStart : DnaColors.gradientEnd)
        : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.3);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
        onTap: onTap,
        child: Container(
          width: 42,
          height: 42,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(
              color: color.withValues(alpha: 0.3),
              width: 1.5,
            ),
          ),
          child: Center(
            child: FaIcon(icon, size: 16, color: color),
          ),
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// BOOST TOGGLE — animated pill with gradient fill
// ═══════════════════════════════════════════════════════════════

class _BoostToggle extends StatelessWidget {
  final bool active;
  final bool enabled;
  final VoidCallback onTap;
  final bool isDark;
  final ThemeData theme;
  final AppLocalizations l10n;

  const _BoostToggle({
    required this.active,
    required this.enabled,
    required this.onTap,
    required this.isDark,
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
          duration: const Duration(milliseconds: 280),
          curve: Curves.easeOutCubic,
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.lg,
            vertical: DnaSpacing.sm + 1,
          ),
          decoration: BoxDecoration(
            gradient: active
                ? const LinearGradient(
                    colors: [Color(0xFF6366F1), Color(0xFF8B5CF6), Color(0xFFAB47BC)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  )
                : null,
            color: active
                ? null
                : isDark
                    ? DnaColors.darkSurfaceVariant.withValues(alpha: 0.6)
                    : theme.colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
            boxShadow: active
                ? [
                    BoxShadow(
                      color: const Color(0xFF6366F1).withValues(alpha: 0.35),
                      blurRadius: 14,
                      offset: const Offset(0, 3),
                    ),
                  ]
                : null,
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              FaIcon(
                FontAwesomeIcons.rocket,
                size: 13,
                color: active
                    ? Colors.white
                    : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
              ),
              const SizedBox(width: DnaSpacing.sm),
              Text(
                l10n.wallBoost,
                style: TextStyle(
                  color: active
                      ? Colors.white
                      : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                  fontSize: 13,
                  fontWeight: active ? FontWeight.w700 : FontWeight.w500,
                  letterSpacing: active ? 0.5 : 0,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// BOOST BADGE — gradient chip under username
// ═══════════════════════════════════════════════════════════════

class _BoostBadge extends StatelessWidget {
  final AppLocalizations l10n;

  const _BoostBadge({super.key, required this.l10n});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.sm + 2,
        vertical: 3,
      ),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
        ),
        borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF6366F1).withValues(alpha: 0.25),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const FaIcon(
            FontAwesomeIcons.rocket,
            size: 9,
            color: Colors.white,
          ),
          const SizedBox(width: 4),
          Text(
            l10n.wallBoostDescription,
            style: const TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.w600,
              fontSize: 11,
              letterSpacing: 0.3,
            ),
          ),
        ],
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// IMAGE PREVIEW — elevated card with smooth remove
// ═══════════════════════════════════════════════════════════════

class _ImagePreview extends StatelessWidget {
  final Uint8List imageBytes;
  final VoidCallback onRemove;

  const _ImagePreview({
    required this.imageBytes,
    required this.onRemove,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.25),
            blurRadius: 16,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: Stack(
        children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
            child: Image.memory(
              imageBytes,
              width: double.infinity,
              fit: BoxFit.cover,
            ),
          ),
          // Gradient overlay
          Positioned(
            top: 0,
            left: 0,
            right: 0,
            height: 64,
            child: ClipRRect(
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(DnaSpacing.radiusLg),
                topRight: Radius.circular(DnaSpacing.radiusLg),
              ),
              child: DecoratedBox(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      Colors.black.withValues(alpha: 0.55),
                      Colors.transparent,
                    ],
                  ),
                ),
              ),
            ),
          ),
          // Remove button
          Positioned(
            top: DnaSpacing.md,
            right: DnaSpacing.md,
            child: Material(
              color: Colors.black.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
              child: InkWell(
                borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
                onTap: onRemove,
                child: const Padding(
                  padding: EdgeInsets.all(DnaSpacing.sm + 2),
                  child: FaIcon(
                    FontAwesomeIcons.xmark,
                    size: 14,
                    color: Colors.white,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
