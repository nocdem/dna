// Discover Channels Screen - Browse and subscribe to public channels from DHT
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../models/channel.dart';
import '../../providers/providers.dart';

class DiscoverChannelsScreen extends ConsumerStatefulWidget {
  const DiscoverChannelsScreen({super.key});

  @override
  ConsumerState<DiscoverChannelsScreen> createState() =>
      _DiscoverChannelsScreenState();
}

class _DiscoverChannelsScreenState
    extends ConsumerState<DiscoverChannelsScreen> {
  String _searchQuery = '';

  List<Channel> _filterChannels(List<Channel> channels) {
    if (_searchQuery.isEmpty) return channels;
    final query = _searchQuery.toLowerCase();
    return channels
        .where((c) =>
            c.name.toLowerCase().contains(query) ||
            c.description.toLowerCase().contains(query))
        .toList();
  }

  @override
  Widget build(BuildContext context) {
    final channelsAsync = ref.watch(discoverChannelsProvider);
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Discover Channels',
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 18),
            onPressed: () =>
                ref.read(discoverChannelsProvider.notifier).refresh(),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: Column(
        children: [
          // Search bar
          DnaSearchBar(
            hint: 'Search channels...',
            debounceMs: 300,
            onChanged: (value) {
              setState(() => _searchQuery = value);
            },
          ),
          // Channel list
          Expanded(
            child: channelsAsync.when(
              data: (channels) {
                final filtered = _filterChannels(channels);
                if (filtered.isEmpty) {
                  return Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        FaIcon(
                          FontAwesomeIcons.satelliteDish,
                          size: 48,
                          color: colorScheme.onSurface.withValues(alpha: 0.3),
                        ),
                        const SizedBox(height: DnaSpacing.lg),
                        Text(
                          _searchQuery.isEmpty
                              ? 'No public channels found'
                              : 'No channels match "$_searchQuery"',
                          style: theme.textTheme.bodyLarge?.copyWith(
                            color:
                                colorScheme.onSurface.withValues(alpha: 0.5),
                          ),
                        ),
                      ],
                    ),
                  );
                }
                return RefreshIndicator(
                  onRefresh: () =>
                      ref.read(discoverChannelsProvider.notifier).refresh(),
                  child: ListView.builder(
                    padding:
                        const EdgeInsets.symmetric(vertical: DnaSpacing.sm),
                    itemCount: filtered.length,
                    itemBuilder: (context, index) {
                      final channel = filtered[index];
                      return _ChannelTile(channel: channel);
                    },
                  ),
                );
              },
              loading: () => const Center(child: CircularProgressIndicator()),
              error: (error, stack) => Center(
                child: Padding(
                  padding: const EdgeInsets.all(DnaSpacing.xl),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      FaIcon(
                        FontAwesomeIcons.circleExclamation,
                        size: 48,
                        color: DnaColors.error,
                      ),
                      const SizedBox(height: DnaSpacing.lg),
                      Text(
                        'Failed to load channels',
                        style: theme.textTheme.bodyLarge,
                      ),
                      const SizedBox(height: DnaSpacing.sm),
                      Text(
                        error.toString(),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: colorScheme.onSurface.withValues(alpha: 0.5),
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: DnaSpacing.lg),
                      DnaButton(
                        label: 'Retry',
                        onPressed: () => ref
                            .read(discoverChannelsProvider.notifier)
                            .refresh(),
                      ),
                    ],
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

/// Individual channel tile with subscribe/unsubscribe toggle
class _ChannelTile extends ConsumerWidget {
  final Channel channel;

  const _ChannelTile({required this.channel});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isSubscribed = ref.watch(isChannelSubscribedProvider(channel.uuid));
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    // Shorten fingerprint for display
    final shortFp = channel.creatorFingerprint.length > 16
        ? '${channel.creatorFingerprint.substring(0, 8)}...${channel.creatorFingerprint.substring(channel.creatorFingerprint.length - 8)}'
        : channel.creatorFingerprint;

    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.lg,
        vertical: DnaSpacing.xs,
      ),
      child: DnaCard(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
              // Channel icon
              Container(
                width: DnaSpacing.avatarMd,
                height: DnaSpacing.avatarMd,
                decoration: BoxDecoration(
                  color: DnaColors.primaryFixed.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
                ),
                child: const Center(
                  child: FaIcon(
                    FontAwesomeIcons.towerBroadcast,
                    size: 18,
                    color: DnaColors.primaryFixed,
                  ),
                ),
              ),
              const SizedBox(width: DnaSpacing.md),
              // Channel info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      channel.name,
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (channel.description.isNotEmpty) ...[
                      const SizedBox(height: DnaSpacing.xs),
                      Text(
                        channel.description,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color:
                              colorScheme.onSurface.withValues(alpha: 0.6),
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                    const SizedBox(height: DnaSpacing.xs),
                    Text(
                      'by $shortFp',
                      style: theme.textTheme.labelSmall?.copyWith(
                        color: colorScheme.onSurface.withValues(alpha: 0.4),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: DnaSpacing.sm),
              // Subscribe/Unsubscribe button
              _SubscribeButton(
                channelUuid: channel.uuid,
                isSubscribed: isSubscribed,
              ),
            ],
          ),
      ),
    );
  }
}

/// Subscribe/unsubscribe toggle button
class _SubscribeButton extends ConsumerStatefulWidget {
  final String channelUuid;
  final bool isSubscribed;

  const _SubscribeButton({
    required this.channelUuid,
    required this.isSubscribed,
  });

  @override
  ConsumerState<_SubscribeButton> createState() => _SubscribeButtonState();
}

class _SubscribeButtonState extends ConsumerState<_SubscribeButton> {
  bool _loading = false;

  Future<void> _toggle() async {
    if (_loading) return;
    setState(() => _loading = true);
    try {
      await ref
          .read(channelSubscriptionsProvider.notifier)
          .toggleSubscription(widget.channelUuid);
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const SizedBox(
        width: 24,
        height: 24,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    }

    if (widget.isSubscribed) {
      return TextButton.icon(
        onPressed: _toggle,
        icon: const FaIcon(FontAwesomeIcons.solidCircleCheck, size: 14),
        label: const Text('Subscribed'),
        style: TextButton.styleFrom(
          foregroundColor: DnaColors.success,
        ),
      );
    }

    return TextButton.icon(
      onPressed: _toggle,
      icon: const FaIcon(FontAwesomeIcons.plus, size: 14),
      label: const Text('Subscribe'),
      style: TextButton.styleFrom(
        foregroundColor: DnaColors.primaryFixed,
      ),
    );
  }
}
