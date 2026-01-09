// Address Book Screen - Saved wallet addresses
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart' show AddressBookEntry;
import '../../providers/addressbook_provider.dart';
import 'address_dialog.dart';
import 'wallet_screen.dart' show getNetworkDisplayLabel;

class AddressBookScreen extends ConsumerWidget {
  const AddressBookScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final addressBook = ref.watch(addressBookProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Address Book'),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.cloudArrowDown),
            onPressed: () => _syncFromDht(context, ref),
            tooltip: 'Sync from DHT',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.invalidate(addressBookProvider),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: addressBook.when(
        data: (entries) => _buildContent(context, ref, entries),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildError(context, ref, error),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showAddDialog(context, ref),
        child: const FaIcon(FontAwesomeIcons.plus),
      ),
    );
  }

  Widget _buildContent(
    BuildContext context,
    WidgetRef ref,
    List<AddressBookEntry> entries,
  ) {
    if (entries.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.addressBook,
              size: 64,
              color: Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(height: 16),
            Text(
              'No saved addresses',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: Theme.of(context).colorScheme.outline,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              'Tap + to add an address',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.outline,
                  ),
            ),
          ],
        ),
      );
    }

    // Group entries by network
    final grouped = <String, List<AddressBookEntry>>{};
    for (final entry in entries) {
      grouped.putIfAbsent(entry.network, () => []).add(entry);
    }

    final networks = grouped.keys.toList()..sort();

    return ListView.builder(
      itemCount: networks.length,
      itemBuilder: (context, index) {
        final network = networks[index];
        final networkEntries = grouped[network]!;

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                getNetworkDisplayLabel(network),
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                      color: Theme.of(context).colorScheme.primary,
                      fontWeight: FontWeight.bold,
                    ),
              ),
            ),
            ...networkEntries.map((entry) => _buildAddressCard(context, ref, entry)),
          ],
        );
      },
    );
  }

  Widget _buildAddressCard(
    BuildContext context,
    WidgetRef ref,
    AddressBookEntry entry,
  ) {
    final theme = Theme.of(context);

    return Dismissible(
      key: Key('address_${entry.id}'),
      direction: DismissDirection.endToStart,
      background: Container(
        color: Colors.red,
        alignment: Alignment.centerRight,
        padding: const EdgeInsets.only(right: 16),
        child: const FaIcon(FontAwesomeIcons.trash, color: Colors.white),
      ),
      confirmDismiss: (direction) async {
        return await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Delete Address'),
            content: Text('Delete "${entry.label}" from address book?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.pop(context, true),
                style: TextButton.styleFrom(foregroundColor: Colors.red),
                child: const Text('Delete'),
              ),
            ],
          ),
        );
      },
      onDismissed: (direction) {
        ref.read(addressBookProvider.notifier).removeAddress(entry.id);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Deleted "${entry.label}"')),
        );
      },
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: _getNetworkColor(entry.network),
          child: Text(
            entry.label.substring(0, 1).toUpperCase(),
            style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
          ),
        ),
        title: Text(entry.label),
        subtitle: Text(
          _truncateAddress(entry.address),
          style: theme.textTheme.bodySmall?.copyWith(
            fontFamily: 'monospace',
            color: theme.colorScheme.outline,
          ),
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (entry.useCount > 0)
              Padding(
                padding: const EdgeInsets.only(right: 8),
                child: Text(
                  '${entry.useCount}x',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.outline,
                  ),
                ),
              ),
            IconButton(
              icon: const FaIcon(FontAwesomeIcons.copy, size: 16),
              onPressed: () => _copyAddress(context, entry),
              tooltip: 'Copy address',
            ),
          ],
        ),
        onTap: () => _copyAddress(context, entry),
        onLongPress: () => _showEditDialog(context, ref, entry),
      ),
    );
  }

  Widget _buildError(BuildContext context, WidgetRef ref, Object error) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          FaIcon(
            FontAwesomeIcons.circleExclamation,
            size: 48,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(height: 16),
          Text('Error loading address book'),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: () => ref.invalidate(addressBookProvider),
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  void _copyAddress(BuildContext context, AddressBookEntry entry) {
    Clipboard.setData(ClipboardData(text: entry.address));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Copied ${entry.label} address'),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  String _truncateAddress(String address) {
    if (address.length <= 20) return address;
    return '${address.substring(0, 10)}...${address.substring(address.length - 8)}';
  }

  Color _getNetworkColor(String network) {
    switch (network.toLowerCase()) {
      case 'backbone':
        return const Color(0xFF6366F1); // Purple for Cellframe
      case 'ethereum':
        return const Color(0xFF627EEA); // Ethereum blue
      case 'solana':
        return const Color(0xFF00D18C); // Solana green
      case 'tron':
        return const Color(0xFFFF060A); // TRON red
      default:
        return Colors.grey;
    }
  }

  Future<void> _showAddDialog(BuildContext context, WidgetRef ref) async {
    final result = await showDialog<AddressDialogResult>(
      context: context,
      builder: (context) => const AddressDialog(),
    );

    if (result != null && context.mounted) {
      try {
        await ref.read(addressBookProvider.notifier).addAddress(
              address: result.address,
              label: result.label,
              network: result.network,
              notes: result.notes,
            );
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Added "${result.label}"')),
          );
        }
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to add address: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  Future<void> _showEditDialog(
    BuildContext context,
    WidgetRef ref,
    AddressBookEntry entry,
  ) async {
    final result = await showDialog<AddressDialogResult>(
      context: context,
      builder: (context) => AddressDialog(entry: entry),
    );

    if (result != null && context.mounted) {
      try {
        await ref.read(addressBookProvider.notifier).updateAddress(
              id: entry.id,
              label: result.label,
              notes: result.notes,
            );
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Updated "${result.label}"')),
          );
        }
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to update address: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  Future<void> _syncFromDht(BuildContext context, WidgetRef ref) async {
    try {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Syncing from DHT...')),
      );
      await ref.read(addressBookProvider.notifier).syncFromDht();
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Sync complete')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Sync failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }
}
