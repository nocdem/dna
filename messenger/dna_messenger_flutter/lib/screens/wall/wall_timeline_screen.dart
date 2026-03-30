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
import '../../widgets/wall_post_tile.dart';
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

  @override
  void initState() {
    super.initState();
    _checkLostCameraData();
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    _scrollController.removeListener(_onScroll);
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
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
        data: (items) => items.isEmpty
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
                      post: item.post,
                      myFingerprint: myFp,
                      authorDisplayName: item.authorDisplayName,
                      authorAvatar: item.authorAvatar,
                      comments: item.previewComments,
                      likeCount: item.likeCount,
                      isLikedByMe: item.isLikedByMe,
                      isBoosted: item.post.isBoosted,
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
              ),
        loading: () {
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
                  post: item.post,
                  myFingerprint: myFp,
                  authorDisplayName: item.authorDisplayName,
                  authorAvatar: item.authorAvatar,
                  decodedImage: item.decodedImage,
                  comments: item.previewComments,
                  likeCount: item.likeCount,
                  isLikedByMe: item.isLikedByMe,
                  isBoosted: item.post.isBoosted,
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
    final profile =
        ref.read(contactProfileCacheProvider)[item.post.authorFingerprint];
    final myFp = ref.read(currentFingerprintProvider) ?? '';
    final isOwn = item.post.authorFingerprint == myFp;
    final authorFp = item.post.authorFingerprint;

    // Check if author is a contact
    final contacts = ref.read(contactsProvider).valueOrNull ?? [];
    final isContact = contacts.any((c) => c.fingerprint == authorFp);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (sheetContext) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        maxChildSize: 0.85,
        minChildSize: 0.3,
        expand: false,
        builder: (sheetContext, scrollController) {
          final theme = Theme.of(sheetContext);
          final l10n = AppLocalizations.of(sheetContext);
          final name = item.authorDisplayName;
          final bio = profile?.bio ?? '';

          return Container(
            padding: const EdgeInsets.all(DnaSpacing.lg),
            child: ListView(
              controller: scrollController,
              children: [
                Center(
                  child: Container(
                    width: 40,
                    height: 4,
                    decoration: BoxDecoration(
                      color: theme.colorScheme.onSurface
                          .withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                ),
                const SizedBox(height: DnaSpacing.lg),
                Center(
                  child: DnaAvatar(
                    imageBytes: item.authorAvatar,
                    name: name,
                    size: DnaAvatarSize.xl,
                  ),
                ),
                const SizedBox(height: DnaSpacing.md),
                Center(
                  child: Text(name,
                      style: theme.textTheme.titleLarge
                          ?.copyWith(fontWeight: FontWeight.bold)),
                ),
                if (bio.isNotEmpty) ...[
                  const SizedBox(height: DnaSpacing.sm),
                  Center(
                    child: Text(bio,
                        style: theme.textTheme.bodyMedium?.copyWith(
                            color: theme.colorScheme.onSurface
                                .withValues(alpha: 0.6)),
                        textAlign: TextAlign.center),
                  ),
                ],
                const SizedBox(height: DnaSpacing.md),
                // Fingerprint
                ListTile(
                  leading: const FaIcon(FontAwesomeIcons.fingerprint,
                      size: 16),
                  title: Text(authorFp,
                      style: theme.textTheme.bodySmall
                          ?.copyWith(fontFamily: 'monospace'),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis),
                ),
                // Social links
                if (profile?.website.isNotEmpty == true)
                  ListTile(
                    leading:
                        const FaIcon(FontAwesomeIcons.globe, size: 16),
                    title: Text(profile!.website),
                  ),
                if (profile?.telegram.isNotEmpty == true)
                  ListTile(
                    leading: const FaIcon(FontAwesomeIcons.telegram,
                        size: 16),
                    title: Text(profile!.telegram),
                  ),
                if (profile?.twitter.isNotEmpty == true)
                  ListTile(
                    leading: const FaIcon(FontAwesomeIcons.xTwitter,
                        size: 16),
                    title: Text(profile!.twitter),
                  ),
                if (profile?.github.isNotEmpty == true)
                  ListTile(
                    leading: const FaIcon(FontAwesomeIcons.github,
                        size: 16),
                    title: Text(profile!.github),
                  ),
                // Action buttons (only for other users)
                if (!isOwn) ...[
                  const SizedBox(height: DnaSpacing.lg),
                  const Divider(),
                  const SizedBox(height: DnaSpacing.sm),
                  if (isContact) ...[
                    // User is a contact — show Unfriend
                    ListTile(
                      leading: const FaIcon(FontAwesomeIcons.userMinus,
                          size: 16),
                      title: Text(l10n.wallUnfriend),
                      onTap: () {
                        Navigator.pop(sheetContext);
                        _confirmUnfriend(context, ref, authorFp, name);
                      },
                    ),
                  ] else ...[
                    // User is NOT a contact — show Contact Request + Follow/Unfollow
                    ListTile(
                      leading: const FaIcon(FontAwesomeIcons.userPlus,
                          size: 16),
                      title: Text(l10n.wallSendContactRequest),
                      onTap: () {
                        Navigator.pop(sheetContext);
                        _showContactRequestDialog(
                            context, ref, authorFp, name);
                      },
                    ),
                    _FollowTile(
                      fingerprint: authorFp,
                      displayName: name,
                    ),
                  ],
                  // Block — always shown for other users
                  ListTile(
                    leading: FaIcon(FontAwesomeIcons.ban,
                        size: 16, color: DnaColors.textWarning),
                    title: Text(l10n.wallBlockUser,
                        style: TextStyle(color: DnaColors.textWarning)),
                    onTap: () {
                      Navigator.pop(sheetContext);
                      _confirmBlock(context, ref, item);
                    },
                  ),
                ],
              ],
            ),
          );
        },
      ),
    );
  }

  void _confirmUnfriend(BuildContext context, WidgetRef ref,
      String fingerprint, String displayName) {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.wallUnfriend),
        content: Text(l10n.wallUnfriendConfirm(displayName)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () async {
              Navigator.pop(context);
              try {
                final engine = await ref.read(engineProvider.future);
                await engine.removeContact(fingerprint);
                ref.invalidate(contactsProvider);
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content:
                          Text(l10n.wallUnfriended(displayName)),
                    ),
                  );
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed: $e')),
                  );
                }
              }
            },
            child: Text(l10n.wallUnfriend),
          ),
        ],
      ),
    );
  }

  void _showContactRequestDialog(BuildContext context, WidgetRef ref,
      String fingerprint, String displayName) {
    final l10n = AppLocalizations.of(context);
    final messageController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.wallSendContactRequest),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(displayName,
                style: Theme.of(context)
                    .textTheme
                    .titleMedium
                    ?.copyWith(fontWeight: FontWeight.w600)),
            const SizedBox(height: DnaSpacing.md),
            TextField(
              controller: messageController,
              decoration: InputDecoration(
                hintText: l10n.wallContactRequestMessage,
                border: const OutlineInputBorder(),
              ),
              maxLines: 2,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () async {
              Navigator.pop(context);
              try {
                final engine = await ref.read(engineProvider.future);
                final msg = messageController.text.trim();
                await engine.sendContactRequest(
                    fingerprint, msg.isEmpty ? null : msg);
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(
                          l10n.wallContactRequestSent(displayName)),
                    ),
                  );
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed: $e')),
                  );
                }
              }
            },
            child: Text(l10n.addContactSendRequest),
          ),
        ],
      ),
    );
  }
}

/// Stateful follow/unfollow tile that checks following status via engine
class _FollowTile extends ConsumerStatefulWidget {
  final String fingerprint;
  final String displayName;

  const _FollowTile({
    required this.fingerprint,
    required this.displayName,
  });

  @override
  ConsumerState<_FollowTile> createState() => _FollowTileState();
}

class _FollowTileState extends ConsumerState<_FollowTile> {
  bool _isFollowing = false;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _checkFollowStatus();
  }

  Future<void> _checkFollowStatus() async {
    try {
      final engine = await ref.read(engineProvider.future);
      // Check via database — the engine exposes following_db_exists via
      // the get_following list. For simplicity, we just check the list.
      // This is fast since it's a local SQLite query.
      final result = engine.isFollowingUser(widget.fingerprint);
      if (mounted) setState(() { _isFollowing = result; _loading = false; });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _toggleFollow() async {
    final l10n = AppLocalizations.of(context);
    setState(() => _loading = true);
    try {
      final engine = await ref.read(engineProvider.future);
      if (_isFollowing) {
        await engine.unfollowUser(widget.fingerprint);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(l10n.wallUnfollowed(widget.displayName))),
          );
        }
      } else {
        await engine.followUser(widget.fingerprint);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(l10n.wallFollowed(widget.displayName))),
          );
        }
      }
      if (mounted) {
        setState(() {
          _isFollowing = !_isFollowing;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _loading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    if (_loading) {
      return const ListTile(
        leading: SizedBox(
          width: 16, height: 16,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
        title: Text('...'),
      );
    }
    return ListTile(
      leading: FaIcon(
        _isFollowing ? FontAwesomeIcons.userCheck : FontAwesomeIcons.userPlus,
        size: 16,
      ),
      title: Text(_isFollowing ? l10n.wallUnfollow : l10n.wallFollow),
      onTap: _toggleFollow,
    );
  }
}
