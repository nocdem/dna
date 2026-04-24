// Stake Dashboard Screen — "Earners" list (Phase 16 Task 73).
//
// Non-technical UI per CLAUDE.md: "earners" hides "validators",
// "Earning X%" hides commission, "Supporters" hides "delegators".
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../ffi/dnac_bindings.dart';
import '../l10n/app_localizations.dart';
import '../providers/engine_provider.dart';
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
              itemCount: active.length + 2,
              itemBuilder: (context, index) {
                if (index == 0) {
                  return _YourSupportsSection(l10n: l10n);
                }
                if (index == 1) {
                  return _StakeHeader(l10n: l10n, total: active.length);
                }
                final earner = active[index - 2];
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

class _YourSupportsSection extends ConsumerWidget {
  const _YourSupportsSection({required this.l10n});
  final AppLocalizations l10n;

  static const int _rawPerDnac = 100000000;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final delegationsAsync = ref.watch(myDelegationsProvider);
    final validators = ref.watch(validatorListProvider).valueOrNull ?? const [];

    return delegationsAsync.when(
      data: (delegations) {
        return Card(
          margin: const EdgeInsets.fromLTRB(12, 12, 12, 4),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const FaIcon(FontAwesomeIcons.handHoldingHeart, size: 16),
                    const SizedBox(width: 10),
                    Text(l10n.stakeYourSupportsHeader,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        )),
                  ],
                ),
                const SizedBox(height: 8),
                if (delegations.isEmpty)
                  Text(l10n.stakeNoSupports,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurface.withAlpha(160),
                      ))
                else
                  ..._buildRows(context, delegations, validators),
              ],
            ),
          ),
        );
      },
      loading: () => const SizedBox.shrink(),
      error: (e, _) => const SizedBox.shrink(),
    );
  }

  List<Widget> _buildRows(
      BuildContext context,
      List<DnacDelegation> delegations,
      List<DnacValidator> validators) {
    // Build a fp→validator map once (cheap — validator list is small).
    // Correlation needs SHA3-512(pubkey), which DnacValidator doesn't expose
    // statically. The tile falls back to a short fp if no match is found
    // (e.g. when validator list is still loading or the validator has
    // retired); tapping such a tile no-ops with a gentle toast.
    final rows = <Widget>[];
    for (final d in delegations) {
      final shortFp = d.validatorFp.length >= 16
          ? '${d.validatorFp.substring(0, 8)}...${d.validatorFp.substring(d.validatorFp.length - 8)}'
          : d.validatorFp;
      final amountDnac = (d.amountRaw / _rawPerDnac).toStringAsFixed(2);
      rows.add(InkWell(
        onTap: () => _openValidator(context, d, validators),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(shortFp,
                        style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 13)),
                    const SizedBox(height: 2),
                    Text(
                        l10n.stakeYourSupportSinceBlock(d.delegatedAtBlock),
                        style: Theme.of(context)
                            .textTheme
                            .bodySmall
                            ?.copyWith(
                              color: Theme.of(context)
                                  .colorScheme
                                  .onSurface
                                  .withAlpha(160),
                            )),
                  ],
                ),
              ),
              Text('$amountDnac DNAC',
                  style: const TextStyle(fontWeight: FontWeight.w600)),
            ],
          ),
        ),
      ));
    }
    return rows;
  }

  void _openValidator(BuildContext context, DnacDelegation d,
      List<DnacValidator> validators) {
    // Ask the engine for each candidate's fp (synchronous FFI call) and
    // navigate to the matching validator's DelegationScreen. On no match,
    // show a toast — the validator may have retired and been removed
    // from the list, or the list is still loading.
    final engine =
        ProviderScope.containerOf(context).read(engineProvider).valueOrNull;
    if (engine == null) return;
    DnacValidator? match;
    for (final v in validators) {
      try {
        final fp = engine.pubkeyToFingerprint(v.pubkey);
        if (fp == d.validatorFp) {
          match = v;
          break;
        }
      } catch (_) {
        continue;
      }
    }
    if (match != null) {
      Navigator.of(context).push(MaterialPageRoute(
          builder: (_) => DelegationScreen(earner: match!)));
    } else {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text(l10n.stakeValidatorUnavailable),
          duration: const Duration(seconds: 2)));
    }
  }
}
