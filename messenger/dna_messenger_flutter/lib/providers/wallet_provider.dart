// Wallet Provider - Wallet and balance state management
// v0.100.104: SQLite balance cache for stale-while-revalidate pattern
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../utils/logger.dart';
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
      // v0.100.82: Preserve previous data during engine lifecycle transitions
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.listWallets();
  }

  /// Refresh wallets silently — keeps old data visible during fetch
  Future<void> refresh() async {
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

    // Refresh balances and transactions after send (silent background refresh)
    ref.invalidate(balancesProvider(walletIndex));
    ref.read(allBalancesProvider.notifier).refresh();
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

  /// Refresh balances silently — keeps old data visible during fetch
  Future<void> refresh() async {
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

/// All balances from all wallets combined (cached, stale-while-revalidate)
/// v0.100.104: build() loads from SQLite cache (instant), refresh() fetches live
final allBalancesProvider = AsyncNotifierProvider<AllBalancesNotifier, List<WalletBalance>>(
  AllBalancesNotifier.new,
);

class AllBalancesNotifier extends AsyncNotifier<List<WalletBalance>> {
  @override
  Future<List<WalletBalance>> build() async {
    final walletsAsync = ref.watch(walletsProvider);
    final wallets = walletsAsync.valueOrNull ?? [];

    if (wallets.isEmpty) return state.valueOrNull ?? [];

    // v0.100.104: Load from SQLite cache first (instant, no network calls)
    return _fetchCachedBalances(wallets);
  }

  /// Refresh balances from live blockchain APIs in the background
  /// Old data stays visible during fetch (stale-while-revalidate)
  Future<void> refresh() async {
    final walletsAsync = ref.read(walletsProvider);
    final wallets = walletsAsync.valueOrNull ?? [];
    if (wallets.isEmpty) return;

    final newState = await AsyncValue.guard(() => _fetchLiveBalances(wallets));
    state = newState;
  }

  /// Read balances from SQLite cache (instant, no network calls)
  Future<List<WalletBalance>> _fetchCachedBalances(List<Wallet> wallets) async {
    final engine = await ref.read(engineProvider.future);
    final allBalances = <WalletBalance>[];

    for (int i = 0; i < wallets.length; i++) {
      try {
        final balances = await engine.getCachedBalances(i);
        for (final balance in balances) {
          allBalances.add(WalletBalance(
            walletIndex: i,
            wallet: wallets[i],
            balance: balance,
          ));
        }
      } catch (_) {
        // No cached data for this wallet — skip
      }
    }

    if (allBalances.isEmpty) {
      log('WALLET', 'No cached balances, falling back to live fetch');
      return _fetchLiveBalances(wallets);
    }

    return allBalances;
  }

  /// Fetch live balances from blockchain APIs (network calls)
  /// Also writes to SQLite cache via C-side write-through
  Future<List<WalletBalance>> _fetchLiveBalances(List<Wallet> wallets) async {
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
  }
}

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

  /// Refresh transactions silently — keeps old data visible during fetch
  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getTransactions(arg.walletIndex, arg.network);
    });
  }
}
