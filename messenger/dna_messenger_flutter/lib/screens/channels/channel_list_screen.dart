// Channel List Screen - Landing screen for the Channels tab
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../models/channel.dart';
import '../../providers/providers.dart';
import 'channel_detail_screen.dart';
import 'create_channel_screen.dart';
import 'discover_channels_screen.dart';

class ChannelListScreen extends ConsumerWidget {
  const ChannelListScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final channels = ref.watch(channelListProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Channels',
        leading: const SizedBox.shrink(),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.read(channelListProvider.notifier).refresh(),
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.plus),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (context) => const CreateChannelScreen(),
              ),
            ),
            tooltip: 'Create Channel',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.magnifyingGlass),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (context) => const DiscoverChannelsScreen(),
              ),
            ),
            tooltip: 'Discover Channels',
          ),
        ],
      ),
      body: channels.when(
        skipLoadingOnReload: true,
        skipLoadingOnRefresh: true,
        data: (list) => _buildChannelList(context, ref, list),
        loading: () {
          final cached = channels.valueOrNull;
          if (cached != null) {
            return _buildChannelList(context, ref, cached);
          }
          return const Center(child: CircularProgressIndicator());
        },
        error: (error, stack) => _buildError(context, ref, error),
      ),
    );
  }

  Widget _buildChannelList(
      BuildContext context, WidgetRef ref, List<Channel> channels) {
    final theme = Theme.of(context);

    if (channels.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.hashtag,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No channels yet',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Create or discover channels',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(channelListProvider.notifier).refresh();
      },
      child: ListView.builder(
        itemCount: channels.length,
        cacheExtent: 500.0,
        itemBuilder: (context, index) {
          final channel = channels[index];
          return _ChannelTile(
            channel: channel,
            onTap: () => _openChannel(context, ref, channel),
            onLongPress: () => _showChannelOptions(context, ref, channel),
          );
        },
      ),
    );
  }

  Widget _buildError(BuildContext context, WidgetRef ref, Object error) {
    final theme = Theme.of(context);

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.circleExclamation,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load channels',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: () => ref.read(channelListProvider.notifier).refresh(),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  void _openChannel(BuildContext context, WidgetRef ref, Channel channel) {
    ref.read(selectedChannelUuidProvider.notifier).state = channel.uuid;
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => ChannelDetailScreen(
          channelUuid: channel.uuid,
          channelName: channel.name,
        ),
      ),
    );
  }

  void _showChannelOptions(
      BuildContext context, WidgetRef ref, Channel channel) {
    showModalBottomSheet(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const FaIcon(FontAwesomeIcons.rightFromBracket),
              title: Text('Unsubscribe from ${channel.name}'),
              onTap: () {
                Navigator.pop(ctx);
                ref
                    .read(channelSubscriptionsProvider.notifier)
                    .unsubscribe(channel.uuid);
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _ChannelTile extends StatelessWidget {
  final Channel channel;
  final VoidCallback onTap;
  final VoidCallback onLongPress;

  const _ChannelTile({
    required this.channel,
    required this.onTap,
    required this.onLongPress,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: theme.colorScheme.primary.withAlpha(30),
        child: FaIcon(
          FontAwesomeIcons.hashtag,
          size: 18,
          color: theme.colorScheme.primary,
        ),
      ),
      title: Text(
        channel.name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: channel.description.isNotEmpty
          ? Text(
              channel.description,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall,
            )
          : null,
      trailing: FaIcon(
        FontAwesomeIcons.chevronRight,
        size: 14,
        color: theme.textTheme.bodySmall?.color,
      ),
      onTap: onTap,
      onLongPress: onLongPress,
    );
  }
}
