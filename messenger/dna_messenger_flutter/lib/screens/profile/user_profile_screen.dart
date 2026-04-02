// User Profile Screen - Full-screen profile view for self and other users
import 'dart:convert';
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
  final String? initialDisplayName;
  final Uint8List? initialAvatar;

  const UserProfileScreen({
    super.key,
    required this.fingerprint,
    this.initialDisplayName,
    this.initialAvatar,
  });

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
  int _totalLikes = 0;
  int _totalTips = 0;
  bool _isLoadingPosts = false;
  bool _isLoadingProfile = true;

  @override
  void initState() {
    super.initState();
    // Use initial data from caller — instant, no spinner
    if (widget.initialDisplayName != null && widget.initialDisplayName!.isNotEmpty) {
      _displayName = widget.initialDisplayName!;
    }
    if (widget.initialAvatar != null) {
      _avatar = widget.initialAvatar;
    }
    // If we have initial data, don't show spinner
    if (_displayName.isNotEmpty) {
      _isLoadingProfile = false;
    }
    _loadData();
  }

  Future<void> _loadData() async {
    final myFp = ref.read(currentFingerprintProvider) ?? '';
    _isSelf = widget.fingerprint == myFp;

    // Step 1: Fill from cache if initState didn't have initial data
    if (_displayName.isEmpty || _profile == null) {
      final identityCache =
          ref.read(identityProfileCacheProvider)[widget.fingerprint];
      final profileCache =
          ref.read(contactProfileCacheProvider)[widget.fingerprint];

      if (_displayName.isEmpty && identityCache != null) {
        _displayName = identityCache.displayName.isNotEmpty
            ? identityCache.displayName
            : widget.fingerprint.substring(0, 16);
      }
      if (_avatar == null && identityCache != null && identityCache.avatarBase64.isNotEmpty) {
        try {
          _avatar = decodeBase64WithPadding(identityCache.avatarBase64);
        } catch (_) {}
      }
      if (_profile == null && profileCache != null) {
        _profile = profileCache;
        if (_avatar == null) {
          _avatar = profileCache.decodeAvatar();
        }
      }
    }

    // Fallback display name
    if (_displayName.isEmpty) {
      _displayName = widget.fingerprint.substring(0, 16);
    }

    // Relationship status (sync providers, no await)
    if (!_isSelf) {
      final contacts = ref.read(contactsProvider).valueOrNull ?? [];
      _isContact =
          contacts.any((c) => c.fingerprint == widget.fingerprint);
    }

    // Show what we have — no spinner if we have a display name
    if (mounted) {
      setState(() => _isLoadingProfile = _displayName.isEmpty);
    }

    // Step 2: Async work — engine, follow status, DHT profile, posts
    final engine = await ref.read(engineProvider.future);

    if (!_isSelf) {
      _isFollowing = engine.isFollowingUser(widget.fingerprint);
      if (mounted) setState(() {});
    }

    // Load fresh profile from DHT and posts in parallel
    await Future.wait([
      _loadProfile(engine),
      _loadPosts(),
    ]);
  }

  Future<void> _loadProfile(DnaEngine engine) async {
    try {
      final profile = await engine.lookupProfile(widget.fingerprint);
      final displayName = await engine.getDisplayName(widget.fingerprint);

      _profile = profile;
      if (displayName.isNotEmpty) {
        _displayName = displayName;
      } else if (_displayName.isEmpty) {
        _displayName = widget.fingerprint.substring(0, 16);
      }

      // Update avatar from full profile if cache didn't have it
      if (_avatar == null && profile != null) {
        _avatar = profile.decodeAvatar();
      }
    } catch (_) {
      // DHT lookup failed — keep cached data
    }

    if (mounted) {
      setState(() => _isLoadingProfile = false);
    }
  }

  Future<void> _loadPosts() async {
    if (!mounted) return;

    // Step 1: Show posts from timeline provider instantly (no async)
    final timeline = ref.read(wallTimelineProvider).valueOrNull ?? [];
    final cachedPosts = timeline
        .where((i) => i.post.authorFingerprint == widget.fingerprint)
        .toList();

    if (cachedPosts.isNotEmpty) {
      int likes = 0;
      for (final item in cachedPosts) {
        likes += item.likeCount;
      }
      if (mounted) {
        setState(() {
          _posts = cachedPosts;
          _totalLikes = likes;
          _isLoadingPosts = false;
        });
      }
      // Load full engagement in background for accurate tip totals
      _loadTipTotals(cachedPosts.map((i) => i.post.uuid).toList());
      return;
    }

    // Step 2: No cached posts — load from engine (DHT/cache)
    setState(() => _isLoadingPosts = true);
    try {
      final engine = await ref.read(engineProvider.future);
      final posts = await engine.wallLoad(widget.fingerprint);

      final feedItems = <WallFeedItem>[];
      int likes = 0;
      int tips = 0;
      if (posts.isNotEmpty) {
        final uuids = posts.map((p) => p.uuid).toList();
        final engMap = <String, WallEngagement>{};
        try {
          final engagements = await engine.wallGetEngagement(uuids);
          for (final e in engagements) {
            engMap[e.postUuid] = e;
            likes += e.likeCount;
            for (final c in e.comments) {
              if (c.isTip) {
                try {
                  final data = jsonDecode(c.body) as Map<String, dynamic>;
                  tips += int.parse(data['amount'] as String? ?? '0');
                } catch (_) {}
              }
            }
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
          _totalLikes = likes;
          _totalTips = tips;
          _isLoadingPosts = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _isLoadingPosts = false);
    }
  }

  /// Fetch full engagement to compute accurate tip totals (cached path).
  Future<void> _loadTipTotals(List<String> uuids) async {
    if (uuids.isEmpty) return;
    try {
      final engine = await ref.read(engineProvider.future);
      final engagements = await engine.wallGetEngagement(uuids);
      int tips = 0;
      for (final e in engagements) {
        for (final c in e.comments) {
          if (c.isTip) {
            try {
              final data = jsonDecode(c.body) as Map<String, dynamic>;
              tips += int.parse(data['amount'] as String? ?? '0');
            } catch (_) {}
          }
        }
      }
      if (mounted && tips > 0) {
        setState(() => _totalTips = tips);
      }
    } catch (_) {}
  }

  // ---------------------------------------------------------------------------
  // BUILD
  // ---------------------------------------------------------------------------

  // Gradient banner height and avatar overlap constants
  static const double _bannerHeight = 140;
  static const double _avatarRadius = 48;
  static const double _avatarBorderWidth = 4;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        scrolledUnderElevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: _isLoadingProfile
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _loadData,
              edgeOffset: 100,
              child: CustomScrollView(
                slivers: [
                  // Gradient banner + avatar overlay + name/bio
                  SliverToBoxAdapter(
                      child: _buildHeroHeader(theme, l10n)),
                  // Action buttons
                  SliverToBoxAdapter(
                      child: _buildActionButtons(theme, l10n)),
                  // Stats row
                  SliverToBoxAdapter(child: _buildStatsRow(theme, l10n)),
                  // Divider
                  SliverToBoxAdapter(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                          horizontal: DnaSpacing.lg),
                      child: Divider(
                        color: theme.colorScheme.onSurface
                            .withValues(alpha: 0.08),
                      ),
                    ),
                  ),
                  // Posts label
                  SliverToBoxAdapter(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(DnaSpacing.lg,
                          DnaSpacing.md, DnaSpacing.lg, DnaSpacing.sm),
                      child: Row(
                        children: [
                          ShaderMask(
                            shaderCallback: DnaGradients.primaryShader,
                            child: const FaIcon(FontAwesomeIcons.newspaper,
                                size: 16, color: Colors.white),
                          ),
                          const SizedBox(width: DnaSpacing.sm),
                          Text(l10n.userProfilePosts,
                              style: theme.textTheme.titleMedium
                                  ?.copyWith(fontWeight: FontWeight.bold)),
                        ],
                      ),
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
                        padding: const EdgeInsets.all(DnaSpacing.xxxl),
                        child: Column(
                          children: [
                            FaIcon(FontAwesomeIcons.feather,
                                size: 32,
                                color: theme.colorScheme.onSurface
                                    .withValues(alpha: 0.2)),
                            const SizedBox(height: DnaSpacing.md),
                            Text(l10n.userProfileNoPosts,
                                style: theme.textTheme.bodyLarge?.copyWith(
                                    color: theme.colorScheme.onSurface
                                        .withValues(alpha: 0.4))),
                          ],
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

  Widget _buildHeroHeader(ThemeData theme, AppLocalizations l10n) {
    final bio = _profile?.bio ?? '';
    final location = _profile?.location ?? '';
    final website = _profile?.website ?? '';
    final isDark = theme.brightness == Brightness.dark;
    final scaffoldBg = theme.scaffoldBackgroundColor;

    return Column(
      children: [
        // ── Gradient banner + Avatar overlay ──
        SizedBox(
          height: _bannerHeight + _avatarRadius + _avatarBorderWidth,
          child: Stack(
            clipBehavior: Clip.none,
            children: [
              // Gradient banner with subtle pattern
              Container(
                height: _bannerHeight,
                width: double.infinity,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [
                      DnaColors.gradientStart,
                      DnaColors.gradientEnd,
                      DnaColors.gradientEnd.withValues(alpha: 0.85),
                    ],
                    stops: const [0.0, 0.6, 1.0],
                  ),
                ),
                // Subtle overlay circles for visual depth
                child: CustomPaint(
                  painter: _BannerPatternPainter(isDark: isDark),
                ),
              ),
              // Avatar centered at bottom of banner
              Positioned(
                bottom: 0,
                left: 0,
                right: 0,
                child: Center(
                  child: Container(
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: scaffoldBg,
                        width: _avatarBorderWidth,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.2),
                          blurRadius: 12,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: DnaAvatar(
                      imageBytes: _avatar,
                      name: _displayName,
                      size: DnaAvatarSize.xl,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: DnaSpacing.md),
        // ── Name ──
        Text(_displayName,
            style: theme.textTheme.headlineSmall
                ?.copyWith(fontWeight: FontWeight.bold)),
        // ── Bio ──
        if (bio.isNotEmpty) ...[
          const SizedBox(height: DnaSpacing.sm),
          Padding(
            padding:
                const EdgeInsets.symmetric(horizontal: DnaSpacing.xl),
            child: Text(bio,
                style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurface
                        .withValues(alpha: 0.7)),
                textAlign: TextAlign.center),
          ),
        ],
        // ── Location & Website row ──
        if (location.isNotEmpty || website.isNotEmpty) ...[
          const SizedBox(height: DnaSpacing.sm),
          Padding(
            padding:
                const EdgeInsets.symmetric(horizontal: DnaSpacing.xl),
            child: Wrap(
              alignment: WrapAlignment.center,
              spacing: DnaSpacing.lg,
              runSpacing: DnaSpacing.xs,
              children: [
                if (location.isNotEmpty)
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      FaIcon(FontAwesomeIcons.locationDot,
                          size: 13,
                          color: theme.colorScheme.onSurface
                              .withValues(alpha: 0.45)),
                      const SizedBox(width: DnaSpacing.xs),
                      Text(location,
                          style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurface
                                  .withValues(alpha: 0.55))),
                    ],
                  ),
                if (website.isNotEmpty)
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      ShaderMask(
                        shaderCallback: DnaGradients.primaryShader,
                        child: const FaIcon(FontAwesomeIcons.globe,
                            size: 13, color: Colors.white),
                      ),
                      const SizedBox(width: DnaSpacing.xs),
                      Flexible(
                        child: ShaderMask(
                          shaderCallback: DnaGradients.primaryShader,
                          child: Text(website,
                              style: theme.textTheme.bodySmall
                                  ?.copyWith(color: Colors.white),
                              overflow: TextOverflow.ellipsis),
                        ),
                      ),
                    ],
                  ),
              ],
            ),
          ),
        ],
        const SizedBox(height: DnaSpacing.lg),
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // ACTION BUTTONS
  // ---------------------------------------------------------------------------

  // Shared button style constants
  static const double _buttonHeight = 42;
  static final BorderRadius _buttonRadius =
      BorderRadius.circular(DnaSpacing.radiusFull);

  /// Gradient primary action button (Message, Follow, Edit Profile)
  Widget _gradientButton({
    required String label,
    required IconData icon,
    required VoidCallback onPressed,
  }) {
    return Expanded(
      child: Container(
        height: _buttonHeight,
        decoration: BoxDecoration(
          gradient: DnaGradients.primary,
          borderRadius: _buttonRadius,
          boxShadow: [
            BoxShadow(
              color: DnaColors.gradientEnd.withValues(alpha: 0.3),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            onTap: onPressed,
            borderRadius: _buttonRadius,
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                FaIcon(icon, size: 14, color: Colors.white),
                const SizedBox(width: DnaSpacing.sm),
                Text(label,
                    style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.w600,
                      fontSize: 13,
                    )),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Outlined secondary action button (Unfollow, Contact Request)
  Widget _outlinedButton({
    required String label,
    required IconData icon,
    required VoidCallback onPressed,
    bool isDanger = false,
  }) {
    final color = isDanger ? DnaColors.textWarning : DnaColors.gradientEnd;
    return Expanded(
      child: SizedBox(
        height: _buttonHeight,
        child: OutlinedButton(
          onPressed: onPressed,
          style: OutlinedButton.styleFrom(
            foregroundColor: color,
            side: BorderSide(color: color.withValues(alpha: 0.5)),
            shape: RoundedRectangleBorder(borderRadius: _buttonRadius),
            padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.md),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              FaIcon(icon, size: 14, color: color),
              const SizedBox(width: DnaSpacing.sm),
              Flexible(
                child: Text(label,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: color,
                      fontWeight: FontWeight.w600,
                      fontSize: 13,
                    )),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildActionButtons(ThemeData theme, AppLocalizations l10n) {
    if (_isSelf) {
      return Padding(
        padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
        child: Row(
          children: [
            _outlinedButton(
              label: l10n.userProfileEditProfile,
              icon: FontAwesomeIcons.penToSquare,
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(
                    builder: (_) => const ProfileEditorScreen()),
              ),
            ),
          ],
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
      child: Column(
        children: [
          // Primary row: Message/ContactRequest + Follow/Unfollow
          Row(
            children: [
              if (_isContact)
                _gradientButton(
                  label: l10n.userProfileMessage,
                  icon: FontAwesomeIcons.comment,
                  onPressed: _openChat,
                )
              else
                _gradientButton(
                  label: l10n.wallSendContactRequest,
                  icon: FontAwesomeIcons.userPlus,
                  onPressed: _sendContactRequest,
                ),
              const SizedBox(width: DnaSpacing.sm),
              if (_isFollowing)
                _outlinedButton(
                  label: l10n.wallUnfollow,
                  icon: FontAwesomeIcons.userCheck,
                  onPressed: _toggleFollow,
                )
              else
                _outlinedButton(
                  label: l10n.wallFollow,
                  icon: FontAwesomeIcons.userPlus,
                  onPressed: _toggleFollow,
                ),
            ],
          ),
          const SizedBox(height: DnaSpacing.sm),
          // Secondary row: Unfriend + Block (danger style)
          Row(
            children: [
              if (_isContact) ...[
                _outlinedButton(
                  label: l10n.wallUnfriend,
                  icon: FontAwesomeIcons.userMinus,
                  onPressed: _confirmUnfriend,
                  isDanger: true,
                ),
                const SizedBox(width: DnaSpacing.sm),
              ],
              _outlinedButton(
                label: l10n.wallBlockUser,
                icon: FontAwesomeIcons.ban,
                onPressed: _confirmBlock,
                isDanger: true,
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // STATS ROW
  // ---------------------------------------------------------------------------

  Widget _buildStatsRow(ThemeData theme, AppLocalizations l10n) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(
          DnaSpacing.lg, DnaSpacing.lg, DnaSpacing.lg, DnaSpacing.sm),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Section title
          Text(
            l10n.userProfileLastMonth,
            style: theme.textTheme.titleSmall?.copyWith(
              color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
            ),
          ),
          const SizedBox(height: DnaSpacing.sm),
          Container(
            padding: const EdgeInsets.symmetric(
                vertical: DnaSpacing.md, horizontal: DnaSpacing.lg),
            decoration: BoxDecoration(
              color: theme.colorScheme.onSurface.withValues(alpha: 0.04),
              borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
            ),
            child: _isLoadingPosts
                ? const Center(
                    child: Padding(
                      padding: EdgeInsets.symmetric(vertical: DnaSpacing.sm),
                      child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    ),
                  )
                : Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _buildStatItem(
                        theme,
                        count: _posts.length,
                        label: l10n.userProfilePosts,
                      ),
                      _buildStatItem(
                        theme,
                        count: _totalLikes,
                        icon: FontAwesomeIcons.fire,
                        iconColor: Colors.orange,
                      ),
                      _buildStatItem(
                        theme,
                        count: _totalTips,
                        label: l10n.userProfileTotalTips,
                        suffix: ' CPUNK',
                      ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatItem(
    ThemeData theme, {
    required int count,
    String? label,
    IconData? icon,
    Color? iconColor,
    String? suffix,
  }) {
    final countText = '$count${suffix ?? ''}';
    return Column(
      children: [
        ShaderMask(
          shaderCallback: DnaGradients.primaryShader,
          child: Text(
            countText,
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
        ),
        const SizedBox(height: DnaSpacing.xs),
        if (icon != null)
          FaIcon(icon, size: 14, color: iconColor ?? Colors.orange)
        else if (label != null)
          Text(label,
              style: theme.textTheme.bodySmall?.copyWith(
                  color:
                      theme.colorScheme.onSurface.withValues(alpha: 0.5))),
      ],
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
                // Refresh contacts (C engine removes contact + messages on block)
                ref.read(contactsProvider.notifier).refresh();
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

/// Paints subtle decorative circles on the gradient banner for visual depth.
class _BannerPatternPainter extends CustomPainter {
  _BannerPatternPainter({required this.isDark});
  final bool isDark;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withValues(alpha: isDark ? 0.06 : 0.1)
      ..style = PaintingStyle.fill;

    // Large circle top-right
    canvas.drawCircle(
      Offset(size.width * 0.85, size.height * 0.15),
      size.height * 0.5,
      paint,
    );

    // Small circle left
    canvas.drawCircle(
      Offset(size.width * 0.1, size.height * 0.7),
      size.height * 0.25,
      paint..color = Colors.white.withValues(alpha: isDark ? 0.04 : 0.07),
    );
  }

  @override
  bool shouldRepaint(covariant _BannerPatternPainter old) =>
      old.isDark != isDark;
}
