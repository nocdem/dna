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

  /// Send tokens from a wallet
  Future<void> sendTokens({
    required int walletIndex,
    required String recipientAddress,
    required String amount,
    required String token,
    required String network,
  }) async {
    print('[Wallet] Sending tokens:');
    print('[Wallet]   Wallet index: $walletIndex');
    print('[Wallet]   Recipient: $recipientAddress');
    print('[Wallet]   Amount: $amount');
    print('[Wallet]   Token: $token');
    print('[Wallet]   Network: $network');

    final engine = await ref.read(engineProvider.future);

    try {
      await engine.sendTokens(
        walletIndex: walletIndex,
        recipientAddress: recipientAddress,
        amount: amount,
        token: token,
        network: network,
      );
      print('[Wallet] Transaction submitted successfully!');
    } catch (e) {
      print('[Wallet] Transaction failed: $e');
      rethrow;
    }

    // Refresh balances after send
    ref.invalidate(balancesProvider(walletIndex));
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

/// Transactions for a wallet and network
final transactionsProvider = AsyncNotifierProviderFamily<
    TransactionsNotifier,
    List<Transaction>,
    ({int walletIndex, String network})>(
  TransactionsNotifier.new,
);

class TransactionsNotifier
    extends FamilyAsyncNotifier<List<Transaction>, ({int walletIndex, String network})> {
  @override
  Future<List<Transaction>> build(({int walletIndex, String network}) arg) async {
    final engine = await ref.watch(engineProvider.future);
    return engine.getTransactions(arg.walletIndex, arg.network);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getTransactions(arg.walletIndex, arg.network);
    });
  }
}
