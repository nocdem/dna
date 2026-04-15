// DNAC History Screen - Transaction history list
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/dnac_provider.dart';
import '../../providers/name_resolver_provider.dart';
import '../../l10n/app_localizations.dart';
import 'wallet_screen.dart' show TransactionDetailSheet;

class DnacHistoryScreen extends ConsumerWidget {
  const DnacHistoryScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final historyAsync = ref.watch(dnacHistoryProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.dnacHistoryTitle),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 18),
            onPressed: () => ref.read(dnacHistoryProvider.notifier).refresh(),
            tooltip: l10n.dnacSync,
          ),
        ],
      ),
      body: historyAsync.when(
        data: (history) {
          if (history.isEmpty) {
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FaIcon(FontAwesomeIcons.clockRotateLeft,
                      size: 48,
                      color: Theme.of(context)
                          .colorScheme
                          .primary
                          .withAlpha(80)),
                  const SizedBox(height: 16),
                  Text(l10n.dnacNoTransactions,
                      style: Theme.of(context).textTheme.bodyLarge),
                ],
              ),
            );
          }

          return RefreshIndicator(
            onRefresh: () =>
                ref.read(dnacHistoryProvider.notifier).refresh(),
            child: ListView.builder(
              itemCount: history.length,
              itemBuilder: (context, index) =>
                  _HistoryTile(tx: history[index]),
            ),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(l10n.dnacSyncFailed,
                  style: Theme.of(context).textTheme.bodyLarge),
              const SizedBox(height: 12),
              ElevatedButton.icon(
                onPressed: () =>
                    ref.read(dnacHistoryProvider.notifier).refresh(),
                icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 14),
                label: Text(l10n.dnacSync),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _HistoryTile extends ConsumerWidget {
  final DnacTxHistory tx;

  const _HistoryTile({required this.tx});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    final isGenesis = tx.type == 0;
    final isBurn = tx.type == 2;
    final isPositive = tx.amountDelta >= 0;

    final IconData icon;
    final Color color;
    final String typeLabel;

    if (isGenesis) {
      icon = FontAwesomeIcons.seedling;
      color = Colors.purple;
      typeLabel = l10n.dnacHistoryGenesis;
    } else if (isBurn) {
      icon = FontAwesomeIcons.fire;
      color = Colors.orange;
      typeLabel = l10n.dnacHistoryBurn;
    } else if (isPositive) {
      icon = FontAwesomeIcons.arrowDown;
      color = Colors.green;
      typeLabel = l10n.dnacHistoryReceived;
    } else {
      icon = FontAwesomeIcons.arrowUp;
      color = Colors.red;
      typeLabel = l10n.dnacHistorySent;
    }

    // Sign derived from actual amount_delta, not hardcoded
    final sign = isPositive ? '+' : '-';

    final dateStr = DateFormat.MMMd().add_Hm().format(tx.timestamp);
    // Lazy fingerprint → nickname resolution (contacts → cache → DHT).
    final resolvedName = lazyResolveFingerprint(ref, tx.counterparty);
    final cpLen = tx.counterparty.length;
    final counterparty = resolvedName ??
        (cpLen > 0
            ? '${tx.counterparty.substring(0, cpLen < 12 ? cpLen : 12)}...'
            : '');

    return ListTile(
      onTap: () => showModalBottomSheet(
        context: context,
        isScrollControlled: true,
        backgroundColor: Colors.transparent,
        builder: (_) => TransactionDetailSheet(
          transaction: Transaction.fromDnacTxHistory(tx)
            ..resolvedName = resolvedName,
          network: 'dnac',
        ),
      ),
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: color.withAlpha(25),
          shape: BoxShape.circle,
        ),
        child: Center(child: FaIcon(icon, size: 16, color: color)),
      ),
      title: Row(
        children: [
          Text(typeLabel, style: theme.textTheme.bodyMedium),
          if (counterparty.isNotEmpty) ...[
            const SizedBox(width: 4),
            Expanded(
              child: Text(counterparty,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withAlpha(120),
                  ),
                  overflow: TextOverflow.ellipsis),
            ),
          ],
        ],
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(dateStr, style: theme.textTheme.bodySmall),
          if (tx.memo.isNotEmpty)
            Text(tx.memo,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontStyle: FontStyle.italic,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis),
        ],
      ),
      trailing: Text(
        '$sign${tx.amountFormatted}',
        style: theme.textTheme.titleSmall?.copyWith(
          color: color,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}

