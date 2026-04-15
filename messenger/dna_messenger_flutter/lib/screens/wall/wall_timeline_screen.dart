import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:image_picker/image_picker.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../services/image_attachment_service.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/logger.dart' as logger;
import '../../widgets/wall_post_tile.dart';
import '../profile/user_profile_screen.dart';
import 'create_post_screen.dart';
import 'wall_post_detail_screen.dart';
import 'wall_tip_dialog.dart';

class WallTimelineScreen extends ConsumerStatefulWidget {
  const WallTimelineScreen({super.key});

  @override
  ConsumerState<WallTimelineScreen> createState() =>
      _WallTimelineScreenState();
}

class _WallTimelineScreenState extends ConsumerState<WallTimelineScreen> {
  final _scrollController = ScrollController();
  // isScrollingNotifier can only be bound after the ScrollPosition is attached
  // (first layout). We attach once via a post-frame callback and track the
  // bound notifier so dispose can cleanly detach it.
  ValueNotifier<bool>? _scrollingNotifier;

  @override
  void initState() {
    super.initState();
    _checkLostCameraData();
    _scrollController.addListener(_onScroll);
    WidgetsBinding.instance.addPostFrameCallback((_) => _bindScrollingNotifier());
  }

  @override
  void dispose() {
    _scrollController.removeListener(_onScroll);
    _scrollingNotifier?.removeListener(_onScrollingChanged);
    _scrollController.dispose();
    super.dispose();
  }

  void _bindScrollingNotifier() {
    if (!mounted || !_scrollController.hasClients) return;
    final notifier = _scrollController.position.isScrollingNotifier;
    if (identical(notifier, _scrollingNotifier)) return;
    _scrollingNotifier?.removeListener(_onScrollingChanged);
    _scrollingNotifier = notifier;
    notifier.addListener(_onScrollingChanged);
  }

  void _onScrollingChanged() {
    final active = _scrollingNotifier?.value ?? false;
    ref.read(wallTimelineProvider.notifier).setUserScrolling(active);
  }

  void _onScroll() {
    // Lazy-bind in case post-frame callback fired before the ListView mounted
    // (e.g. empty state → content state transition reattaches the position).
    if (_scrollingNotifier == null && _scrollController.hasClients) {
      _bindScrollingNotifier();
    }
    final pos = _scrollController.position;
    if (pos.pixels >= pos.maxScrollExtent - 200) {
      logger.log('WALL_SCROLL', 'SCROLL_BOTTOM pixels=${pos.pixels.toInt()} max=${pos.maxScrollExtent.toInt()}');
      ref.read(wallTimelineProvider.notifier).loadMoreDays();
    }
  }

  /// Recover image data lost when Android killed the Activity during camera use
  Future<void> _checkLostCameraData() async {
    final picker = ImagePicker();
    final response = await picker.retrieveLostData();
    if (response.isEmpty || response.file == null) return;

    try {
      final bytes = await File(response.file!.path).readAsBytes();
      final imageService = ImageAttachmentService();
      final attachment = await imageService.processImage(bytes);
      final previewBytes = base64Decode(attachment.base64Data);

      if (mounted) {
        _showCreatePostDialog(
          initialAttachment: attachment,
          initialPreview: previewBytes,
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to process camera image: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final timeline = ref.watch(wallTimelineProvider);
    final myFp = ref.watch(currentFingerprintProvider) ?? '';

    return Scaffold(
      appBar: DnaAppBar(
        title: AppLocalizations.of(context).wallTitle,
        leading: const SizedBox.shrink(),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.read(wallTimelineProvider.notifier).refresh(),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: timeline.when(
        data: (items) {
            final scrollPx = _scrollController.hasClients ? _scrollController.position.pixels.toInt() : -1;
            final scrollMax = _scrollController.hasClients ? _scrollController.position.maxScrollExtent.toInt() : -1;
            logger.log('WALL_SCROLL', 'BUILD_DATA items=${items.length} scroll=$scrollPx/$scrollMax first=${items.isNotEmpty ? items.first.post.uuid.substring(0, 8) : "empty"}');
            return items.isEmpty
            ? _buildEmptyState(context)
            : RefreshIndicator(
                onRefresh: () =>
                    ref.read(wallTimelineProvider.notifier).refresh(),
                child: ListView.separated(
                  controller: _scrollController,
                  padding: const EdgeInsets.all(DnaSpacing.md),
                  itemCount: items.length,
                  separatorBuilder: (_, _) =>
                      const SizedBox(height: DnaSpacing.sm),
                  itemBuilder: (context, index) {
                    final item = items[index];
                    final isOwn = item.isOwn(myFp);
                    return WallPostTile(
                      key: ValueKey(item.post.uuid),
                      post: item.post,
                      myFingerprint: myFp,
                      authorDisplayName: item.authorDisplayName,
                      authorAvatar: item.authorAvatar,
                      comments: item.previewComments,
                      commentCount: item.commentCount,
                      likeCount: item.likeCount,
                      isLikedByMe: item.isLikedByMe,
                      decodedImage: item.decodedImage,
                      onLike: item.isLikedByMe
                          ? null
                          : () => ref
                              .read(wallTimelineProvider.notifier)
                              .likePost(item.post.uuid),
                      onReply: () => Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) =>
                              WallPostDetailScreen(post: item.post),
                        ),
                      ),
                      onViewAllComments: () => Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) =>
                              WallPostDetailScreen(post: item.post),
                        ),
                      ),
                      onDelete: isOwn
                          ? () => _confirmDelete(
                              context, ref, item.post.uuid)
                          : null,
                      onBlock: !isOwn
                          ? () => _confirmBlock(
                              context, ref, item)
                          : null,
                      onShare: !isOwn
                          ? () => _showRepostDialog(
                              context, ref, item.post)
                          : null,
                      onTip: !isOwn
                          ? () => showWallTipDialog(
                                context: context,
                                ref: ref,
                                post: item.post,
                              )
                          : null,
                      onAuthorTap: () => _showAuthorProfile(
                          context, ref, item),
                    );
                  },
                ),
              );
        },
        loading: () {
          logger.log('WALL_SCROLL', 'BUILD_LOADING');
          final cached = timeline.valueOrNull;
          if (cached != null && cached.isNotEmpty) {
            return ListView.separated(
              controller: _scrollController,
              padding: const EdgeInsets.all(DnaSpacing.md),
              itemCount: cached.length,
              separatorBuilder: (_, _) =>
                  const SizedBox(height: DnaSpacing.sm),
              itemBuilder: (context, index) {
                final item = cached[index];
                final isOwn = item.isOwn(myFp);
                return WallPostTile(
                  key: ValueKey(item.post.uuid),
                  post: item.post,
                  myFingerprint: myFp,
                  authorDisplayName: item.authorDisplayName,
                  authorAvatar: item.authorAvatar,
                  decodedImage: item.decodedImage,
                  comments: item.previewComments,
                  commentCount: item.commentCount,
                  likeCount: item.likeCount,
                  isLikedByMe: item.isLikedByMe,
                  onLike: item.isLikedByMe
                      ? null
                      : () => ref
                          .read(wallTimelineProvider.notifier)
                          .likePost(item.post.uuid),
                  onReply: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) =>
                          WallPostDetailScreen(post: item.post),
                    ),
                  ),
                  onViewAllComments: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) =>
                          WallPostDetailScreen(post: item.post),
                    ),
                  ),
                  onDelete: isOwn
                      ? () => _confirmDelete(
                          context, ref, item.post.uuid)
                      : null,
                  onBlock: !isOwn
                      ? () => _confirmBlock(
                          context, ref, item)
                      : null,
                  onShare: !isOwn
                      ? () => _showRepostDialog(
                          context, ref, item.post)
                      : null,
                  onTip: !isOwn
                      ? () => showWallTipDialog(
                            context: context,
                            ref: ref,
                            post: item.post,
                          )
                      : null,
                  onAuthorTap: () => _showAuthorProfile(
                      context, ref, item),
                );
              },
            );
          }
          return const Center(child: CircularProgressIndicator());
        },
        error: (error, stack) => Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const FaIcon(FontAwesomeIcons.triangleExclamation, size: 48),
              const SizedBox(height: DnaSpacing.md),
              Text(AppLocalizations.of(context).failedToLoadTimeline),
              const SizedBox(height: DnaSpacing.sm),
              DnaButton(
                onPressed: () => ref.invalidate(wallTimelineProvider),
                label: 'Retry',
              ),
            ],
          ),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        heroTag: 'wall_fab',
        onPressed: () => _showCreatePostDialog(),
        tooltip: AppLocalizations.of(context).wallNewPost,
        child: const FaIcon(FontAwesomeIcons.pen),
      ),
    );
  }

  Widget _buildEmptyState(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(DnaSpacing.xl),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            FaIcon(
              FontAwesomeIcons.houseChimney,
              size: 64,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(height: DnaSpacing.lg),
            Text(
              AppLocalizations.of(context).wallWelcome,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: DnaSpacing.sm),
            Text(
              AppLocalizations.of(context).wallWelcomeSubtitle,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showCreatePostDialog({
    ImageAttachment? initialAttachment,
    Uint8List? initialPreview,
  }) async {
    final result = await Navigator.push<bool>(
      context,
      MaterialPageRoute(
        builder: (_) => CreatePostScreen(
          initialAttachment: initialAttachment,
          initialPreview: initialPreview,
        ),
      ),
    );
    if (result == true) {
      // Post was created — timeline provider already updated optimistically
    }
  }

  void _confirmDelete(BuildContext context, WidgetRef ref, String postUuid) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).wallDeletePost),
        content: Text(AppLocalizations.of(context).wallDeletePostConfirm),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () async {
              Navigator.pop(context);
              try {
                await ref
                    .read(wallTimelineProvider.notifier)
                    .deletePost(postUuid);
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to delete: $e')),
                  );
                }
              }
            },
            child: Text(AppLocalizations.of(context).delete),
          ),
        ],
      ),
    );
  }

  void _confirmBlock(BuildContext context, WidgetRef ref, WallFeedItem item) {
    final displayName = item.authorDisplayName;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).wallBlockUser),
        content: Text(AppLocalizations.of(context).wallBlockUserConfirm(displayName)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: DnaColors.textWarning),
            onPressed: () async {
              Navigator.pop(context);
              try {
                await ref
                    .read(blockedUsersProvider.notifier)
                    .block(item.post.authorFingerprint, 'Blocked from wall');
                // Remove blocked user's posts from timeline
                ref.read(wallTimelineProvider.notifier).removePostsByAuthor(
                    item.post.authorFingerprint);
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(AppLocalizations.of(context).wallUserBlocked(displayName)),
                    ),
                  );
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to block: $e')),
                  );
                }
              }
            },
            child: Text(AppLocalizations.of(context).wallBlockUser),
          ),
        ],
      ),
    );
  }

  void _showRepostDialog(BuildContext context, WidgetRef ref, WallPost post) {
    final controller = TextEditingController();
    final authorName = post.authorName.isNotEmpty
        ? post.authorName
        : post.authorFingerprint.substring(0, 16);

    // Build the quote block
    final quotedLines = post.text.split('\n').map((l) => '\u2502 $l').join('\n');
    final quoteBlock = '\u25b8 $authorName wrote:\n$quotedLines';

    showDialog(
      context: context,
      builder: (dialogContext) {
        final theme = Theme.of(dialogContext);
        return AlertDialog(
          title: Row(
            children: [
              FaIcon(FontAwesomeIcons.retweet,
                  size: 16, color: theme.colorScheme.primary),
              const SizedBox(width: DnaSpacing.sm),
              Text(AppLocalizations.of(dialogContext).wallRepost),
            ],
          ),
          content: SizedBox(
            width: double.maxFinite,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Quote preview
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(DnaSpacing.md),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.surfaceContainerHighest,
                      borderRadius:
                          BorderRadius.circular(DnaSpacing.radiusSm),
                      border: Border(
                        left: BorderSide(
                          color: theme.colorScheme.primary,
                          width: 3,
                        ),
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          authorName,
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.primary,
                          ),
                        ),
                        const SizedBox(height: DnaSpacing.xs),
                        Text(
                          post.text,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                          maxLines: 6,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: DnaSpacing.md),
                  // Optional comment
                  TextField(
                    controller: controller,
                    maxLines: 3,
                    maxLength: 2000 - quoteBlock.length - 2,
                    decoration: const InputDecoration(
                      hintText: 'Add a comment (optional)',
                    ),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            DnaButton(
              label: AppLocalizations.of(dialogContext).cancel,
              variant: DnaButtonVariant.ghost,
              onPressed: () => Navigator.pop(dialogContext),
            ),
            DnaButton(
              label: AppLocalizations.of(dialogContext).wallRepost,
              icon: FontAwesomeIcons.retweet,
              onPressed: () async {
                Navigator.pop(dialogContext);
                final comment = controller.text.trim();
                final fullText = comment.isEmpty
                    ? quoteBlock
                    : '$quoteBlock\n\n$comment';
                try {
                  await ref
                      .read(wallTimelineProvider.notifier)
                      .createPost(fullText);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(
                            AppLocalizations.of(context).wallReposted),
                        duration: const Duration(seconds: 2),
                      ),
                    );
                  }
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed to repost: $e')),
                    );
                  }
                }
              },
            ),
          ],
        );
      },
    );
  }

  void _showAuthorProfile(
      BuildContext context, WidgetRef ref, WallFeedItem item) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => UserProfileScreen(
          fingerprint: item.post.authorFingerprint,
          initialDisplayName: item.authorDisplayName,
          initialAvatar: item.authorAvatar,
        ),
      ),
    );
  }

}

