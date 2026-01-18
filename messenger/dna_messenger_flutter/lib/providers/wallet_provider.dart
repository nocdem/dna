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
  /// [gasSpeed]: 0=slow (0.8x), 1=normal (1x), 2=fast (1.5x) - only for ETH
  /// Returns the transaction hash on success
  Future<String> sendTokens({
    required int walletIndex,
    required String recipientAddress,
    required String amount,
    required String token,
    required String network,
    int gasSpeed = 1,
  }) async {
    final engine = await ref.read(engineProvider.future);

    String txHash;
    try {
      txHash = await engine.sendTokens(
        walletIndex: walletIndex,
        recipientAddress: recipientAddress,
        amount: amount,
        token: token,
        network: network,
        gasSpeed: gasSpeed,
      );
    } catch (e) {
      rethrow;
    }

    // Refresh balances and transactions after send
    ref.invalidate(balancesProvider(walletIndex));
    ref.invalidate(allBalancesProvider);
    ref.invalidate(transactionsProvider((walletIndex: walletIndex, network: network)));

    return txHash;
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

/// Combined balance with wallet info
class WalletBalance {
  final int walletIndex;
  final Wallet wallet;
  final Balance balance;

  WalletBalance({
    required this.walletIndex,
    required this.wallet,
    required this.balance,
  });
}

/// All balances from all wallets combined
final allBalancesProvider = FutureProvider<List<WalletBalance>>((ref) async {
  final walletsAsync = ref.watch(walletsProvider);
  final wallets = walletsAsync.valueOrNull ?? [];

  if (wallets.isEmpty) return [];

  final engine = await ref.read(engineProvider.future);
  final allBalances = <WalletBalance>[];

  for (int i = 0; i < wallets.length; i++) {
    try {
      final balances = await engine.getBalances(i);
      for (final balance in balances) {
        allBalances.add(WalletBalance(
          walletIndex: i,
          wallet: wallets[i],
          balance: balance,
        ));
      }
    } catch (_) {
      // Skip wallet if balance fetch fails
    }
  }

  return allBalances;
});

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
