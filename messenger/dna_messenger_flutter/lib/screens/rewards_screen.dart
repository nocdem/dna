// Rewards Screen — "Your rewards" (Phase 16 Task 75).
//
// Non-technical UX: "Your rewards: X DNAC" instead of "pending rewards".
// Claiming requires picking an earner (the claim TX is per-validator);
// this screen shows the aggregate pending amount plus a list of
// ACTIVE earners; tapping an earner triggers the claim flow for that
// earner's contribution.
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../ffi/dnac_bindings.dart';
import '../l10n/app_localizations.dart';
import '../providers/stake_provider.dart';
import '../utils/logger.dart' as logger;

class RewardsScreen extends ConsumerStatefulWidget {
  const RewardsScreen({super.key});

  @override
  ConsumerState<RewardsScreen> createState() => _RewardsScreenState();
}

class _RewardsScreenState extends ConsumerState<RewardsScreen> {
  static const int _rawPerDnac = 100000000;

  // Phase 14 does not expose the witness's current block height to the
  // client, so we pass a sentinel valid_before_block. The witness will
  // still enforce max_pending_amount as the primary replay defense.
  // TODO(phase17): replace with real block height once the RPC ships.
  static const int _validBeforeSentinel = 0x7fffffffffffffff;

  bool _claiming = false;
  String? _claimingId;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final rewardsAsync = ref.watch(pendingRewardsProvider);
    final earnersAsync = ref.watch(validatorListProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.rewardsTitle),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 18),
            tooltip: l10n.stakeRefresh,
            onPressed: () {
              ref.read(pendingRewardsProvider.notifier).refresh();
              ref.read(validatorListProvider.notifier).refresh();
            },
          ),
        ],
      ),
      body: rewardsAsync.when(
        data: (totalRaw) {
          final totalDnac = totalRaw / _rawPerDnac;
          return Column(
            children: [
              _RewardsSummaryCard(
                totalDnac: totalDnac.toStringAsFixed(4),
              ),
              const Divider(height: 0),
              Expanded(
                child: earnersAsync.when(
                  data: (earners) {
                    final active = earners
                        .where((v) => v.status == DnacValidatorStatus.active)
                        .toList();
                    if (active.isEmpty) {
                      return _RewardsEmpty(l10n: l10n);
                    }
                    return ListView(
                      children: [
                        Padding(
                          padding: const EdgeInsets.all(16),
                          child: Text(
                            l10n.rewardsClaimFromHeader,
                            style: Theme.of(context).textTheme.titleSmall,
                          ),
                        ),
                        ...active.map((e) => _EarnerClaimTile(
                              earner: e,
                              claiming:
                                  _claiming && _claimingId == e.shortId,
                              onClaim: _claiming
                                  ? null
                                  : () => _claimFrom(e, totalRaw),
                            )),
                      ],
                    );
                  },
                  loading: () =>
                      const Center(child: CircularProgressIndicator()),
                  error: (e, _) => _RewardsEmpty(l10n: l10n),
                ),
              ),
            ],
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Center(
          child: Text(l10n.rewardsLoadFailed),
        ),
      ),
    );
  }

  Future<void> _claimFrom(DnacValidator earner, int aggregateRaw) async {
    setState(() {
      _claiming = true;
      _claimingId = earner.shortId;
    });
    final l10n = AppLocalizations.of(context);
    try {
      await ref.read(stakeActionsProvider).claimReward(
            targetValidatorPubkey: earner.pubkey,
            // Witness enforces actual_pending <= max_pending_amount; passing
            // the aggregate is safe (real pending <= aggregate).
            maxPendingAmount: aggregateRaw,
            validBeforeBlock: _validBeforeSentinel,
          );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.rewardsClaimSuccess)),
      );
    } catch (e) {
      logger.logError('STAKE', 'claim failed: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.rewardsClaimFailed)),
      );
    } finally {
      if (mounted) {
        setState(() {
          _claiming = false;
          _claimingId = null;
        });
      }
    }
  }
}

class _RewardsSummaryCard extends StatelessWidget {
  const _RewardsSummaryCard({required this.totalDnac});
  final String totalDnac;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    return Card(
      margin: const EdgeInsets.all(16),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            FaIcon(FontAwesomeIcons.gift,
                size: 28, color: theme.colorScheme.primary),
            const SizedBox(height: 10),
            Text(l10n.rewardsPendingLabel,
                style: theme.textTheme.labelLarge?.copyWith(
                  color: theme.colorScheme.onSurface.withAlpha(160),
                )),
            const SizedBox(height: 6),
            Text('$totalDnac DNAC',
                style: theme.textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.bold,
                )),
          ],
        ),
      ),
    );
  }
}

class _EarnerClaimTile extends StatelessWidget {
  const _EarnerClaimTile({
    required this.earner,
    required this.claiming,
    required this.onClaim,
  });
  final DnacValidator earner;
  final bool claiming;
  final VoidCallback? onClaim;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return ListTile(
      leading: const FaIcon(FontAwesomeIcons.seedling, size: 18),
      title: Text(l10n.stakeEarnerName(earner.shortId)),
      subtitle: Text(l10n.stakeEarnerCommission(
          earner.commissionPct.toStringAsFixed(2))),
      trailing: ElevatedButton(
        onPressed: onClaim,
        child: claiming
            ? const SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : Text(l10n.rewardsClaimButton),
      ),
    );
  }
}

class _RewardsEmpty extends StatelessWidget {
  const _RewardsEmpty({required this.l10n});
  final AppLocalizations l10n;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Text(
          l10n.rewardsEmptyList,
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurface.withAlpha(160),
              ),
        ),
      ),
    );
  }
}
