// Address Book Provider - Wallet address book state management
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Address book provider - all addresses
final addressBookProvider =
    AsyncNotifierProvider<AddressBookNotifier, List<AddressBookEntry>>(
  AddressBookNotifier.new,
);

class AddressBookNotifier extends AsyncNotifier<List<AddressBookEntry>> {
  @override
  Future<List<AddressBookEntry>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      // v0.100.82: Preserve previous data during engine lifecycle transitions
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    final entries = await engine.getAddressBook();

    // Sort by label alphabetically
    final sortedEntries = List<AddressBookEntry>.from(entries);
    sortedEntries.sort((a, b) => a.label.toLowerCase().compareTo(b.label.toLowerCase()));

    return sortedEntries;
  }

  /// Refresh address book from database
  Future<void> refresh() async {
    ref.invalidateSelf();
  }

  /// Add a new address
  Future<int> addAddress({
    required String address,
    required String label,
    required String network,
    String notes = '',
  }) async {
    final engine = await ref.read(engineProvider.future);
    final id = engine.addAddress(
      address: address,
      label: label,
      network: network,
      notes: notes,
    );
    ref.invalidateSelf();
    return id;
  }

  /// Update an existing address
  Future<void> updateAddress({
    required int id,
    required String label,
    String notes = '',
  }) async {
    final engine = await ref.read(engineProvider.future);
    engine.updateAddress(id: id, label: label, notes: notes);
    ref.invalidateSelf();
  }

  /// Remove an address
  Future<void> removeAddress(int id) async {
    final engine = await ref.read(engineProvider.future);
    engine.removeAddress(id);
    ref.invalidateSelf();
  }

  /// Increment usage count for an address (call after sending to it)
  Future<void> incrementUsage(int id) async {
    final engine = await ref.read(engineProvider.future);
    engine.incrementAddressUsage(id);
    // Don't invalidate - just update usage count silently
  }

  /// Sync address book to DHT
  Future<void> syncToDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.syncAddressBookToDht();
  }

  /// Sync address book from DHT
  Future<void> syncFromDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.syncAddressBookFromDht();
    ref.invalidateSelf();
  }
}

/// Address book filtered by network
final addressBookByNetworkProvider =
    FutureProvider.family<List<AddressBookEntry>, String>((ref, network) async {
  final identityLoaded = ref.watch(identityLoadedProvider);
  if (!identityLoaded) {
    return [];
  }

  final engine = await ref.watch(engineProvider.future);
  final entries = await engine.getAddressBookByNetwork(network);

  // Sort by label alphabetically
  final sortedEntries = List<AddressBookEntry>.from(entries);
  sortedEntries.sort((a, b) => a.label.toLowerCase().compareTo(b.label.toLowerCase()));

  return sortedEntries;
});

/// Recently used addresses
final recentAddressesProvider =
    FutureProvider.family<List<AddressBookEntry>, int>((ref, limit) async {
  final identityLoaded = ref.watch(identityLoadedProvider);
  if (!identityLoaded) {
    return [];
  }

  final engine = await ref.watch(engineProvider.future);
  return engine.getRecentAddresses(limit: limit);
});

/// Check if address exists in address book
final addressExistsProvider =
    Provider.family<bool, (String, String)>((ref, params) {
  final (address, network) = params;
  final identityLoaded = ref.watch(identityLoadedProvider);
  if (!identityLoaded) {
    return false;
  }

  try {
    final engine = ref.watch(engineProvider).valueOrNull;
    if (engine == null) return false;
    return engine.addressExists(address, network);
  } catch (_) {
    return false;
  }
});

/// Look up an address entry
final lookupAddressProvider =
    Provider.family<AddressBookEntry?, (String, String)>((ref, params) {
  final (address, network) = params;
  final identityLoaded = ref.watch(identityLoadedProvider);
  if (!identityLoaded) {
    return null;
  }

  try {
    final engine = ref.watch(engineProvider).valueOrNull;
    if (engine == null) return null;
    return engine.lookupAddress(address, network);
  } catch (_) {
    return null;
  }
});
