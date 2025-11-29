// Wallet Provider - Wallet and balance state management
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Wallets list provider
final walletsProvider = AsyncNotifierProvider<WalletsNotifier, List<Wallet>>(
  WalletsNotifier.new,
);

class WalletsNotifier extends AsyncNotifier<List<Wallet>> {
  @override
  Future<List<Wallet>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.listWallets();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.listWallets();
    });
  }
}

/// Balances for selected wallet
final balancesProvider = AsyncNotifierProviderFamily<BalancesNotifier, List<Balance>, int>(
  BalancesNotifier.new,
);

class BalancesNotifier extends FamilyAsyncNotifier<List<Balance>, int> {
  @override
  Future<List<Balance>> build(int arg) async {
    final engine = await ref.watch(engineProvider.future);
    return engine.getBalances(arg);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getBalances(arg);
    });
  }
}

/// Selected wallet index
final selectedWalletIndexProvider = StateProvider<int>((ref) => 0);
