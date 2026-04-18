// Stake Dashboard Screen — "Earners" list (Phase 16 Task 73).
//
// Non-technical UI per CLAUDE.md: "earners" hides "validators",
// "Earning X%" hides commission, "Supporters" hides "delegators".
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../ffi/dnac_bindings.dart';
import '../l10n/app_localizations.dart';
import '../providers/stake_provider.dart';
import 'delegation_screen.dart';

class StakeDashboardScreen extends ConsumerWidget {
  const StakeDashboardScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final earnersAsync = ref.watch(validatorListProvider);
    final committeeAsync = ref.watch(committeeProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.stakeDashboardTitle),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 18),
            tooltip: l10n.stakeRefresh,
            onPressed: () async {
              await ref.read(validatorListProvider.notifier).refresh();
              await ref.read(committeeProvider.notifier).refresh();
            },
          ),
        ],
      ),
      body: earnersAsync.when(
        data: (earners) {
          final active = earners
              .where((v) => v.status == DnacValidatorStatus.active)
              .toList();
          if (active.isEmpty) {
            return _EmptyState(l10n: l10n);
          }
          // Sort by total stake descending so biggest earners are on top.
          active.sort((a, b) => b.totalStakeRaw.compareTo(a.totalStakeRaw));

          final committee = committeeAsync.valueOrNull ?? const [];
          final committeeIds =
              committee.map((v) => v.shortId).toSet();

          return RefreshIndicator(
            onRefresh: () async {
              await ref.read(validatorListProvider.notifier).refresh();
              await ref.read(committeeProvider.notifier).refresh();
            },
            child: ListView.builder(
              itemCount: active.length + 1,
              itemBuilder: (context, index) {
                if (index == 0) {
                  return _StakeHeader(l10n: l10n, total: active.length);
                }
                final earner = active[index - 1];
                final onCommittee = committeeIds.contains(earner.shortId);
                return _EarnerTile(
                  earner: earner,
                  onCommittee: onCommittee,
                );
              },
            ),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => _ErrorState(l10n: l10n, onRetry: () {
          ref.read(validatorListProvider.notifier).refresh();
        }),
      ),
    );
  }
}

class _StakeHeader extends StatelessWidget {
  const _StakeHeader({required this.l10n, required this.total});
  final AppLocalizations l10n;
  final int total;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l10n.stakeEarnersHeader,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            l10n.stakeEarnersSubtitle(total),
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withAlpha(160),
            ),
          ),
        ],
      ),
    );
  }
}

class _EarnerTile extends StatelessWidget {
  const _EarnerTile({required this.earner, required this.onCommittee});
  final DnacValidator earner;
  final bool onCommittee;

  static const int _rawPerDnac = 100000000;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final totalDnac = earner.totalStakeRaw / _rawPerDnac;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: InkWell(
        onTap: () {
          Navigator.of(context).push(MaterialPageRoute(
            builder: (_) => DelegationScreen(earner: earner),
          ));
        },
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              _EarnerAvatar(onCommittee: onCommittee),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            l10n.stakeEarnerName(earner.shortId),
                            style: theme.textTheme.titleSmall?.copyWith(
                              fontWeight: FontWeight.w600,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (onCommittee)
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: Colors.amber.withAlpha(40),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              l10n.stakeTrustedBadge,
                              style: theme.textTheme.labelSmall?.copyWith(
                                color: Colors.amber.shade800,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      l10n.stakeEarnerCommission(
                          earner.commissionPct.toStringAsFixed(2)),
                      style: theme.textTheme.bodySmall,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      l10n.stakeEarnerTotalLocked(
                          totalDnac.toStringAsFixed(2)),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurface.withAlpha(160),
                      ),
                    ),
                  ],
                ),
              ),
              const FaIcon(FontAwesomeIcons.chevronRight, size: 12),
            ],
          ),
        ),
      ),
    );
  }
}

class _EarnerAvatar extends StatelessWidget {
  const _EarnerAvatar({required this.onCommittee});
  final bool onCommittee;

  @override
  Widget build(BuildContext context) {
    final color = onCommittee
        ? Colors.amber.shade700
        : Theme.of(context).colorScheme.primary;
    return Container(
      width: 44,
      height: 44,
      decoration: BoxDecoration(
        color: color.withAlpha(30),
        shape: BoxShape.circle,
      ),
      child: Center(
        child: FaIcon(
          onCommittee ? FontAwesomeIcons.crown : FontAwesomeIcons.seedling,
          color: color,
          size: 18,
        ),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.l10n});
  final AppLocalizations l10n;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          FaIcon(FontAwesomeIcons.seedling,
              size: 48,
              color: theme.colorScheme.primary.withAlpha(80)),
          const SizedBox(height: 16),
          Text(l10n.stakeNoEarners,
              style: theme.textTheme.bodyLarge),
          const SizedBox(height: 4),
          Text(l10n.stakeNoEarnersSubtitle,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurface.withAlpha(160),
              )),
        ],
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.l10n, required this.onRetry});
  final AppLocalizations l10n;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(l10n.stakeLoadFailed,
              style: theme.textTheme.bodyLarge),
          const SizedBox(height: 12),
          ElevatedButton.icon(
            onPressed: onRetry,
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 14),
            label: Text(l10n.stakeRefresh),
          ),
        ],
      ),
    );
  }
}
