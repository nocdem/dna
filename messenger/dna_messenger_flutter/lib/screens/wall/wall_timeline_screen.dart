import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../widgets/wall_post_tile.dart';

class WallTimelineScreen extends ConsumerWidget {
  const WallTimelineScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final timeline = ref.watch(wallTimelineProvider);
    final myFp = ref.watch(currentFingerprintProvider) ?? '';

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Home',
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
        data: (posts) => posts.isEmpty
            ? _buildEmptyState(context)
            : RefreshIndicator(
                onRefresh: () => ref.read(wallTimelineProvider.notifier).refresh(),
                child: ListView.separated(
                  padding: const EdgeInsets.all(DnaSpacing.md),
                  itemCount: posts.length,
                  separatorBuilder: (_, _) => const SizedBox(height: DnaSpacing.sm),
                  itemBuilder: (context, index) {
                    final post = posts[index];
                    return WallPostTile(
                      post: post,
                      myFingerprint: myFp,
                      onDelete: post.isOwn(myFp)
                          ? () => _confirmDelete(context, ref, post.uuid)
                          : null,
                      onShare: !post.isOwn(myFp)
                          ? () => _showRepostDialog(context, ref, post)
                          : null,
                    );
                  },
                ),
              ),
        loading: () {
          final cached = timeline.valueOrNull;
          if (cached != null && cached.isNotEmpty) {
            return ListView.separated(
              padding: const EdgeInsets.all(DnaSpacing.md),
              itemCount: cached.length,
              separatorBuilder: (_, _) => const SizedBox(height: DnaSpacing.sm),
              itemBuilder: (context, index) => WallPostTile(
                post: cached[index],
                myFingerprint: myFp,
              ),
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
              const Text('Failed to load timeline'),
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
        onPressed: () => _showCreatePostDialog(context, ref),
        tooltip: 'New Post',
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
              'Welcome to your timeline!',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: DnaSpacing.sm),
            Text(
              'Post something to your wall or add contacts to see their posts here.',
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

  void _showCreatePostDialog(BuildContext context, WidgetRef ref) {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('New Post'),
        content: TextField(
          controller: controller,
          maxLines: 5,
          maxLength: 2000,
          decoration: const InputDecoration(
            hintText: "What's on your mind?",
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              final text = controller.text.trim();
              if (text.isEmpty) return;
              Navigator.pop(context);
              try {
                await ref.read(wallTimelineProvider.notifier).createPost(text);
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to post: $e')),
                  );
                }
              }
            },
            child: const Text('Post'),
          ),
        ],
      ),
    );
  }

  void _confirmDelete(BuildContext context, WidgetRef ref, String postUuid) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Post'),
        content: const Text('Are you sure you want to delete this post?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () async {
              Navigator.pop(context);
              try {
                await ref.read(wallTimelineProvider.notifier).deletePost(postUuid);
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to delete: $e')),
                  );
                }
              }
            },
            child: const Text('Delete'),
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
              FaIcon(FontAwesomeIcons.retweet, size: 16, color: theme.colorScheme.primary),
              const SizedBox(width: DnaSpacing.sm),
              const Text('Repost'),
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
                      borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
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
                      border: OutlineInputBorder(),
                    ),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () async {
                Navigator.pop(dialogContext);
                final comment = controller.text.trim();
                final fullText = comment.isEmpty
                    ? quoteBlock
                    : '$quoteBlock\n\n$comment';
                try {
                  await ref.read(wallTimelineProvider.notifier).createPost(fullText);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Reposted to your wall'),
                        duration: Duration(seconds: 2),
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
              child: const Text('Repost'),
            ),
          ],
        );
      },
    );
  }
}
