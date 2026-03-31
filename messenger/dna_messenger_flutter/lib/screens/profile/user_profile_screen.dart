// User Profile Screen - Full-screen profile view for self and other users
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../../ffi/dna_engine.dart';
import '../../l10n/app_localizations.dart';
import '../../providers/providers.dart' hide UserProfile;
import '../../design_system/design_system.dart';
import '../../widgets/wall_post_tile.dart';
import '../wall/wall_post_detail_screen.dart';
import '../wall/wall_tip_dialog.dart';
import '../chat/chat_screen.dart';
import 'profile_editor_screen.dart';

class UserProfileScreen extends ConsumerStatefulWidget {
  final String fingerprint;

  const UserProfileScreen({super.key, required this.fingerprint});

  @override
  ConsumerState<UserProfileScreen> createState() => _UserProfileScreenState();
}

class _UserProfileScreenState extends ConsumerState<UserProfileScreen> {
  UserProfile? _profile;
  String _displayName = '';
  Uint8List? _avatar;
  bool _isFollowing = false;
  bool _isContact = false;
  bool _isSelf = false;
  List<WallFeedItem> _posts = [];
  bool _isLoadingPosts = false;
  bool _isLoadingProfile = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    final engine = await ref.read(engineProvider.future);
    final myFp = ref.read(currentFingerprintProvider) ?? '';

    setState(() {
      _isSelf = widget.fingerprint == myFp;
      _isLoadingProfile = true;
    });

    // Load profile and display name
    try {
      final profile = await engine.lookupProfile(widget.fingerprint);
      final displayName = await engine.getDisplayName(widget.fingerprint);

      _profile = profile;
      _displayName = (displayName.isNotEmpty)
          ? displayName
          : widget.fingerprint.substring(0, 16);

      // Avatar: try cache first, then profile
      final cached =
          ref.read(identityProfileCacheProvider)[widget.fingerprint];
      if (cached != null && cached.avatarBase64.isNotEmpty) {
        try {
          _avatar = decodeBase64WithPadding(cached.avatarBase64);
        } catch (_) {}
      }
      if (_avatar == null && profile != null) {
        _avatar = profile.decodeAvatar();
      }

      // Relationship status (only for other users)
      if (!_isSelf) {
        _isFollowing = engine.isFollowingUser(widget.fingerprint);
        final contacts = ref.read(contactsProvider).valueOrNull ?? [];
        _isContact =
            contacts.any((c) => c.fingerprint == widget.fingerprint);
      }
    } catch (_) {
      // Profile lookup failed — show what we have
    }

    if (mounted) {
      setState(() => _isLoadingProfile = false);
    }

    _loadPosts();
  }

  Future<void> _loadPosts() async {
    if (!mounted) return;
    setState(() => _isLoadingPosts = true);
    try {
      final engine = await ref.read(engineProvider.future);
      final posts = await engine.wallLoad(widget.fingerprint);
      final myFp = ref.read(currentFingerprintProvider) ?? '';

      final feedItems = <WallFeedItem>[];
      if (posts.isNotEmpty) {
        final uuids = posts.map((p) => p.uuid).toList();
        final engMap = <String, WallEngagement>{};
        try {
          final engagements = await engine.wallGetEngagement(uuids);
          for (final e in engagements) {
            engMap[e.postUuid] = e;
          }
        } catch (_) {}

        for (final post in posts) {
          final eng = engMap[post.uuid];
          final preview = eng != null
              ? (eng.comments.length <= 3
                  ? eng.comments
                  : eng.comments.sublist(0, 3))
              : const <WallComment>[];
          feedItems.add(WallFeedItem(
            post: post,
            commentCount: eng?.comments.length ?? 0,
            previewComments: preview,
            likeCount: eng?.likeCount ?? 0,
            isLikedByMe: eng?.isLikedByMe ?? false,
            authorDisplayName: _displayName,
            authorAvatar: _avatar,
          ));
        }
      }

      if (mounted) {
        setState(() {
          _posts = feedItems;
          _isLoadingPosts = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _isLoadingPosts = false);
    }
  }

  // ---------------------------------------------------------------------------
  // BUILD
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(title: Text(_displayName)),
      body: _isLoadingProfile
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _loadData,
              child: CustomScrollView(
                slivers: [
                  // Profile header
                  SliverToBoxAdapter(
                      child: _buildProfileHeader(theme, l10n)),
                  // Action buttons
                  SliverToBoxAdapter(
                      child: _buildActionButtons(theme, l10n)),
                  // Divider + Posts label
                  SliverToBoxAdapter(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(DnaSpacing.md,
                          DnaSpacing.lg, DnaSpacing.md, DnaSpacing.sm),
                      child: Text(l10n.userProfilePosts,
                          style: theme.textTheme.titleMedium
                              ?.copyWith(fontWeight: FontWeight.bold)),
                    ),
                  ),
                  // Posts
                  if (_isLoadingPosts)
                    const SliverToBoxAdapter(
                      child: Padding(
                        padding: EdgeInsets.all(DnaSpacing.xl),
                        child: Center(child: CircularProgressIndicator()),
                      ),
                    )
                  else if (_posts.isEmpty)
                    SliverToBoxAdapter(
                      child: Padding(
                        padding: const EdgeInsets.all(DnaSpacing.xl),
                        child: Center(
                          child: Text(l10n.userProfileNoPosts,
                              style: theme.textTheme.bodyLarge?.copyWith(
                                  color: theme.colorScheme.onSurface
                                      .withValues(alpha: 0.5))),
                        ),
                      ),
                    )
                  else
                    SliverList(
                      delegate: SliverChildBuilderDelegate(
                        (context, index) => _buildPostTile(index),
                        childCount: _posts.length,
                      ),
                    ),
                  // Bottom padding
                  const SliverToBoxAdapter(
                      child: SizedBox(height: DnaSpacing.xl)),
                ],
              ),
            ),
    );
  }

  // ---------------------------------------------------------------------------
  // PROFILE HEADER
  // ---------------------------------------------------------------------------

  Widget _buildProfileHeader(ThemeData theme, AppLocalizations l10n) {
    final bio = _profile?.bio ?? '';
    final location = _profile?.location ?? '';
    final website = _profile?.website ?? '';

    return Padding(
      padding: const EdgeInsets.all(DnaSpacing.lg),
      child: Column(
        children: [
          DnaAvatar(
            imageBytes: _avatar,
            name: _displayName,
            size: DnaAvatarSize.xl,
          ),
          const SizedBox(height: DnaSpacing.md),
          Text(_displayName,
              style: theme.textTheme.headlineSmall
                  ?.copyWith(fontWeight: FontWeight.bold)),
          if (bio.isNotEmpty) ...[
            const SizedBox(height: DnaSpacing.sm),
            Text(bio,
                style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurface
                        .withValues(alpha: 0.7)),
                textAlign: TextAlign.center),
          ],
          if (location.isNotEmpty) ...[
            const SizedBox(height: DnaSpacing.sm),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                FaIcon(FontAwesomeIcons.locationDot,
                    size: 14,
                    color: theme.colorScheme.onSurface
                        .withValues(alpha: 0.5)),
                const SizedBox(width: DnaSpacing.xs),
                Text(location,
                    style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurface
                            .withValues(alpha: 0.5))),
              ],
            ),
          ],
          if (website.isNotEmpty) ...[
            const SizedBox(height: DnaSpacing.xs),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                FaIcon(FontAwesomeIcons.globe,
                    size: 14, color: theme.colorScheme.primary),
                const SizedBox(width: DnaSpacing.xs),
                Flexible(
                  child: Text(website,
                      style: theme.textTheme.bodySmall
                          ?.copyWith(color: theme.colorScheme.primary),
                      overflow: TextOverflow.ellipsis),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // ACTION BUTTONS
  // ---------------------------------------------------------------------------

  Widget _buildActionButtons(ThemeData theme, AppLocalizations l10n) {
    if (_isSelf) {
      return Padding(
        padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
        child: SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(
                  builder: (_) => const ProfileEditorScreen()),
            ),
            icon: const FaIcon(FontAwesomeIcons.penToSquare, size: 14),
            label: Text(l10n.userProfileEditProfile),
          ),
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
      child: Wrap(
        spacing: DnaSpacing.sm,
        runSpacing: DnaSpacing.sm,
        alignment: WrapAlignment.center,
        children: [
          // Message (only if contact)
          if (_isContact)
            FilledButton.icon(
              onPressed: _openChat,
              icon: const FaIcon(FontAwesomeIcons.comment, size: 14),
              label: Text(l10n.userProfileMessage),
            ),
          // Follow / Unfollow
          if (_isFollowing)
            OutlinedButton.icon(
              onPressed: _toggleFollow,
              icon: const FaIcon(FontAwesomeIcons.userCheck, size: 14),
              label: Text(l10n.wallUnfollow),
            )
          else
            FilledButton.tonal(
              onPressed: _toggleFollow,
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const FaIcon(FontAwesomeIcons.userPlus, size: 14),
                  const SizedBox(width: DnaSpacing.xs),
                  Text(l10n.wallFollow),
                ],
              ),
            ),
          // Contact Request / Unfriend
          if (_isContact)
            OutlinedButton.icon(
              onPressed: _confirmUnfriend,
              icon: const FaIcon(FontAwesomeIcons.userMinus, size: 14),
              label: Text(l10n.wallUnfriend),
              style: OutlinedButton.styleFrom(
                  foregroundColor: DnaColors.textWarning),
            )
          else
            OutlinedButton.icon(
              onPressed: _sendContactRequest,
              icon: const FaIcon(FontAwesomeIcons.userPlus, size: 14),
              label: Text(l10n.wallSendContactRequest),
            ),
          // Block
          OutlinedButton.icon(
            onPressed: _confirmBlock,
            icon: FaIcon(FontAwesomeIcons.ban,
                size: 14, color: DnaColors.textWarning),
            label: Text(l10n.wallBlockUser,
                style: TextStyle(color: DnaColors.textWarning)),
            style: OutlinedButton.styleFrom(
                side: BorderSide(color: DnaColors.textWarning)),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // POST TILE
  // ---------------------------------------------------------------------------

  Widget _buildPostTile(int index) {
    final item = _posts[index];
    final myFp = ref.read(currentFingerprintProvider) ?? '';
    final isOwn = item.isOwn(myFp);

    return Padding(
      padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.md, vertical: DnaSpacing.xs),
      child: WallPostTile(
        post: item.post,
        myFingerprint: myFp,
        authorDisplayName: item.authorDisplayName,
        authorAvatar: item.authorAvatar,
        decodedImage: item.decodedImage,
        comments: item.previewComments,
        likeCount: item.likeCount,
        isLikedByMe: item.isLikedByMe,
        isBoosted: item.post.isBoosted,
        onAuthorTap: null, // Already on profile page
        onLike: item.isLikedByMe ? null : () => _likePost(item.post.uuid),
        onReply: () => _navigateToPostDetail(item.post),
        onViewAllComments: () => _navigateToPostDetail(item.post),
        onDelete: isOwn ? () => _confirmDelete(item.post.uuid) : null,
        onBlock: !isOwn ? _confirmBlock : null,
        onTip: !isOwn
            ? () => showWallTipDialog(
                  context: context,
                  ref: ref,
                  post: item.post,
                )
            : null,
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // ACTIONS
  // ---------------------------------------------------------------------------

  Future<void> _toggleFollow() async {
    final engine = await ref.read(engineProvider.future);
    final l10n = AppLocalizations.of(context);
    try {
      if (_isFollowing) {
        await engine.unfollowUser(widget.fingerprint);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
                content: Text(l10n.wallUnfollowed(_displayName))),
          );
        }
      } else {
        await engine.followUser(widget.fingerprint);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
                content: Text(l10n.wallFollowed(_displayName))),
          );
        }
      }
      if (mounted) setState(() => _isFollowing = !_isFollowing);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Failed: $e')));
      }
    }
  }

  void _sendContactRequest() {
    final l10n = AppLocalizations.of(context);
    final messageController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.wallSendContactRequest),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(_displayName,
                style: Theme.of(ctx)
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
            onPressed: () => Navigator.pop(ctx),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              try {
                final engine = await ref.read(engineProvider.future);
                final msg = messageController.text.trim();
                await engine.sendContactRequest(
                    widget.fingerprint, msg.isEmpty ? null : msg);
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                        content: Text(
                            l10n.wallContactRequestSent(_displayName))),
                  );
                }
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed: $e')));
                }
              }
            },
            child: Text(l10n.wallSendContactRequest),
          ),
        ],
      ),
    );
  }

  void _confirmUnfriend() {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.wallUnfriend),
        content: Text(l10n.wallUnfriendConfirm(_displayName)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              try {
                final engine = await ref.read(engineProvider.future);
                await engine.removeContact(widget.fingerprint);
                ref.invalidate(contactsProvider);
                if (mounted) {
                  setState(() => _isContact = false);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                        content:
                            Text(l10n.wallUnfriended(_displayName))),
                  );
                }
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed: $e')));
                }
              }
            },
            child: Text(l10n.wallUnfriend),
          ),
        ],
      ),
    );
  }

  void _confirmBlock() {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.wallBlockUser),
        content: Text(l10n.wallBlockUserConfirm(_displayName)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
                backgroundColor: DnaColors.textWarning),
            onPressed: () async {
              Navigator.pop(ctx);
              try {
                await ref
                    .read(blockedUsersProvider.notifier)
                    .block(widget.fingerprint, 'Blocked from profile');
                ref
                    .read(wallTimelineProvider.notifier)
                    .removePostsByAuthor(widget.fingerprint);
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                        content: Text(
                            l10n.wallUserBlocked(_displayName))),
                  );
                  Navigator.pop(context); // Leave profile after block
                }
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed: $e')));
                }
              }
            },
            child: Text(l10n.wallBlockUser),
          ),
        ],
      ),
    );
  }

  void _openChat() {
    final contacts = ref.read(contactsProvider).valueOrNull ?? [];
    final contact =
        contacts.where((c) => c.fingerprint == widget.fingerprint).firstOrNull;
    if (contact != null) {
      ref.read(selectedContactProvider.notifier).state = contact;
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => const ChatScreen()),
      );
    }
  }

  Future<void> _likePost(String postUuid) async {
    try {
      final engine = await ref.read(engineProvider.future);
      await engine.wallLike(postUuid);
      // Refresh posts to update like state
      _loadPosts();
    } catch (_) {}
  }

  void _confirmDelete(String postUuid) {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.wallDelete),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
                backgroundColor: DnaColors.textWarning),
            onPressed: () async {
              Navigator.pop(ctx);
              try {
                final engine = await ref.read(engineProvider.future);
                await engine.wallDelete(postUuid);
                ref.invalidate(wallTimelineProvider);
                _loadPosts();
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed: $e')));
                }
              }
            },
            child: Text(l10n.wallDelete),
          ),
        ],
      ),
    );
  }

  void _navigateToPostDetail(WallPost post) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => WallPostDetailScreen(post: post)),
    );
  }
}
