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
import '../../widgets/wall_post_tile.dart';
import 'wall_post_detail_screen.dart';

class WallTimelineScreen extends ConsumerStatefulWidget {
  const WallTimelineScreen({super.key});

  @override
  ConsumerState<WallTimelineScreen> createState() =>
      _WallTimelineScreenState();
}

class _WallTimelineScreenState extends ConsumerState<WallTimelineScreen> {
  @override
  void initState() {
    super.initState();
    _checkLostCameraData();
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
                      onReply: () => Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) => WallPostDetailScreen(post: post),
                        ),
                      ),
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
        onPressed: () => _showCreatePostDialog(),
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

  void _showCreatePostDialog({
    ImageAttachment? initialAttachment,
    Uint8List? initialPreview,
  }) {
    showDialog(
      context: context,
      builder: (dialogContext) => _CreatePostDialog(
        ref: ref,
        parentContext: context,
        initialAttachment: initialAttachment,
        initialPreview: initialPreview,
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
                    ),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            DnaButton(
              label: 'Cancel',
              variant: DnaButtonVariant.ghost,
              onPressed: () => Navigator.pop(dialogContext),
            ),
            DnaButton(
              label: 'Repost',
              icon: FontAwesomeIcons.retweet,
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
            ),
          ],
        );
      },
    );
  }
}

/// Create post dialog with optional image attachment
class _CreatePostDialog extends StatefulWidget {
  final WidgetRef ref;
  final BuildContext parentContext;
  final ImageAttachment? initialAttachment;
  final Uint8List? initialPreview;

  const _CreatePostDialog({
    required this.ref,
    required this.parentContext,
    this.initialAttachment,
    this.initialPreview,
  });

  @override
  State<_CreatePostDialog> createState() => _CreatePostDialogState();
}

class _CreatePostDialogState extends State<_CreatePostDialog> {
  final _controller = TextEditingController();
  final _imageService = ImageAttachmentService();
  ImageAttachment? _attachment;
  Uint8List? _previewBytes;
  bool _posting = false;

  @override
  void initState() {
    super.initState();
    _attachment = widget.initialAttachment;
    _previewBytes = widget.initialPreview;
  }

  @override
  void dispose() {
    _controller.dispose();
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
    Navigator.pop(context);

    try {
      final notifier = widget.ref.read(wallTimelineProvider.notifier);
      if (_attachment != null) {
        final imageJson = _attachment!.toMessageJson();
        await notifier.createPostWithImage(text, imageJson);
      } else {
        await notifier.createPost(text);
      }
    } catch (e) {
      if (widget.parentContext.mounted) {
        ScaffoldMessenger.of(widget.parentContext).showSnackBar(
          SnackBar(content: Text('Failed to post: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(FontAwesomeIcons.pen,
              size: 18, color: theme.colorScheme.primary),
          const SizedBox(width: DnaSpacing.sm),
          const Text('New Post'),
        ],
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: _controller,
                maxLines: 5,
                maxLength: 2000,
                autofocus: true,
                decoration: const InputDecoration(
                  hintText: "What's on your mind?",
                ),
              ),
              // Image preview
              if (_previewBytes != null) ...[
                const SizedBox(height: DnaSpacing.sm),
                Stack(
                  alignment: Alignment.topRight,
                  children: [
                    ClipRRect(
                      borderRadius:
                          BorderRadius.circular(DnaSpacing.radiusSm),
                      child: Image.memory(
                        _previewBytes!,
                        height: 150,
                        width: double.infinity,
                        fit: BoxFit.cover,
                      ),
                    ),
                    IconButton(
                      icon: const FaIcon(FontAwesomeIcons.circleXmark,
                          size: 20),
                      style: IconButton.styleFrom(
                        backgroundColor: Colors.black54,
                        foregroundColor: Colors.white,
                      ),
                      onPressed: () => setState(() {
                        _attachment = null;
                        _previewBytes = null;
                      }),
                    ),
                  ],
                ),
              ],
              // Image picker buttons
              if (_previewBytes == null) ...[
                const SizedBox(height: DnaSpacing.sm),
                Row(
                  children: [
                    IconButton(
                      icon: FaIcon(FontAwesomeIcons.image,
                          size: 18,
                          color: theme.colorScheme.onSurfaceVariant),
                      tooltip: 'Gallery',
                      onPressed: () => _pickImage(ImageSource.gallery),
                    ),
                    IconButton(
                      icon: FaIcon(FontAwesomeIcons.camera,
                          size: 18,
                          color: theme.colorScheme.onSurfaceVariant),
                      tooltip: 'Camera',
                      onPressed: () => _pickImage(ImageSource.camera),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        DnaButton(
          label: 'Cancel',
          variant: DnaButtonVariant.ghost,
          onPressed: () => Navigator.pop(context),
        ),
        DnaButton(
          label: _posting ? 'Posting...' : 'Post',
          icon: FontAwesomeIcons.paperPlane,
          onPressed: _posting ? null : _submit,
        ),
      ],
    );
  }
}
