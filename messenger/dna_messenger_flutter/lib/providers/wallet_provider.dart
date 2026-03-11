// Wallet Provider - Wallet and balance state management
// v0.100.104: SQLite balance cache for stale-while-revalidate pattern
// v0.100.108: Dart-side SharedPreferences cache for instant cold-start display
import 'dart:convert';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../ffi/dna_engine.dart';
import '../utils/logger.dart';
import 'addressbook_provider.dart';
import 'contact_profile_cache_provider.dart';
import 'contacts_provider.dart';
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
  /// [gasSpeed]: 0=slow (1.0x), 1=normal (1.1x), 2=fast (1.5x) - only for ETH
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

  factory WalletBalance.fromJson(Map<String, dynamic> json) {
    return WalletBalance(
      walletIndex: json['walletIndex'] as int,
      wallet: Wallet.fromJson(json['wallet'] as Map<String, dynamic>),
      balance: Balance.fromJson(json['balance'] as Map<String, dynamic>),
    );
  }

  Map<String, dynamic> toJson() => {
    'walletIndex': walletIndex,
    'wallet': wallet.toJson(),
    'balance': balance.toJson(),
  };
}

/// All balances from all wallets combined (cached, stale-while-revalidate)
/// v0.100.104: build() loads from SQLite cache (instant), refresh() fetches live
/// v0.100.108: Dart-side SharedPreferences cache for instant cold-start display
final allBalancesProvider = AsyncNotifierProvider<AllBalancesNotifier, List<WalletBalance>>(
  AllBalancesNotifier.new,
);

class AllBalancesNotifier extends AsyncNotifier<List<WalletBalance>> {
  static const _cacheKey = 'wallet_balances_cache';

  @override
  Future<List<WalletBalance>> build() async {
    final walletsAsync = ref.watch(walletsProvider);
    final wallets = walletsAsync.valueOrNull ?? [];

    if (wallets.isEmpty) {
      // v0.100.108: On cold start, wallets aren't available yet (engine initializing).
      // Try Dart-side cache (SharedPreferences) for instant display without engine.
      final prev = state.valueOrNull;
      if (prev != null && prev.isNotEmpty) return prev;

      final dartCached = await _loadDartCache();
      if (dartCached.isNotEmpty) return dartCached;

      return [];
    }

    // v0.100.104: Load from SQLite cache first (instant, no network calls)
    return _fetchCachedBalances(wallets);
  }

  /// Refresh balances from live blockchain APIs in the background
  /// Old data stays visible during fetch (stale-while-revalidate)
  Future<void> refresh() async {
    final walletsAsync = ref.read(walletsProvider);
    final wallets = walletsAsync.valueOrNull ?? [];
    if (wallets.isEmpty) return;

    final current = state.valueOrNull;
    final newState = await AsyncValue.guard(() => _fetchLiveBalances(wallets));

    // v0.100.108: Preserve cached data on error — don't lose balances
    if (newState is AsyncError && current != null && current.isNotEmpty) {
      return;
    }

    state = newState;

    // Persist to Dart cache for next cold start
    final data = newState.valueOrNull;
    if (data != null && data.isNotEmpty) {
      _saveDartCache(data);
    }
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

    // Persist to Dart cache for next cold start
    _saveDartCache(allBalances);

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

  /// Load from Dart-side cache (SharedPreferences) — no engine needed
  Future<List<WalletBalance>> _loadDartCache() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_cacheKey);
      if (raw == null || raw.isEmpty) return [];

      final List<dynamic> list = jsonDecode(raw);
      final result = list
          .map((item) => WalletBalance.fromJson(item as Map<String, dynamic>))
          .toList();
      if (result.isNotEmpty) {
        log('WALLET', 'Loaded ${result.length} balances from Dart cache (cold start)');
      }
      return result;
    } catch (e) {
      log('WALLET', 'Dart cache read failed: $e');
      return [];
    }
  }

  /// Save to Dart-side cache for next cold start
  void _saveDartCache(List<WalletBalance> balances) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = jsonEncode(balances.map((b) => b.toJson()).toList());
      await prefs.setString(_cacheKey, raw);
    } catch (_) {
      // Non-fatal — SQLite cache is the primary source
    }
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
    // Watch contacts + address book so we re-resolve when they change
    ref.watch(contactsProvider);
    ref.watch(contactProfileCacheProvider);
    ref.watch(addressBookProvider);

    // Cache-first: show cached transactions instantly, then refresh in background
    final engine = await ref.watch(engineProvider.future);
    final cached = await engine.getCachedTransactions(arg.walletIndex, arg.network);

    if (cached.isNotEmpty) {
      _resolveNames(cached, arg.network);
      // Schedule background refresh after returning cached data
      Future.microtask(() => refresh());
      return cached;
    }

    // No cache — fall back to live fetch
    final txs = await engine.getTransactions(arg.walletIndex, arg.network);
    _resolveNames(txs, arg.network);
    return txs;
  }

  /// Refresh transactions from live API — keeps old data visible during fetch
  Future<void> refresh() async {
    final current = state.valueOrNull;
    final newState = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final txs = await engine.getTransactions(arg.walletIndex, arg.network);
      _resolveNames(txs, arg.network);
      return txs;
    });

    // Preserve cached data on network error
    if (newState is AsyncError && current != null && current.isNotEmpty) {
      return;
    }

    state = newState;
  }

  /// Resolve otherAddress to contact name or address book label
  void _resolveNames(List<Transaction> txs, String network) {
    // Build lookup map: address -> name from contact profiles
    final profileCache = ref.read(contactProfileCacheProvider);
    final contacts = ref.read(contactsProvider).valueOrNull ?? [];
    final addressToContact = <String, String>{};

    for (final contact in contacts) {
      final profile = profileCache[contact.fingerprint];
      if (profile == null) continue;

      final address = _getProfileAddress(profile, network);
      if (address.isNotEmpty) {
        addressToContact[address.toLowerCase()] = contact.effectiveName;
      }
    }

    // Resolve each transaction
    for (final tx in txs) {
      if (tx.otherAddress.isEmpty) continue;

      // 1. Check contact profiles
      final contactName = addressToContact[tx.otherAddress.toLowerCase()];
      if (contactName != null) {
        tx.resolvedName = contactName;
        continue;
      }

      // 2. Check address book
      final entry = ref.read(lookupAddressProvider((tx.otherAddress, network)));
      if (entry != null) {
        tx.resolvedName = entry.label;
      }
    }
  }

  /// Get the wallet address from a profile for a given network
  String _getProfileAddress(UserProfile profile, String network) {
    switch (network.toLowerCase()) {
      case 'backbone':
      case 'cellframe':
        return profile.backbone;
      case 'ethereum':
        return profile.eth;
      case 'solana':
        return profile.sol;
      case 'tron':
        return profile.trx;
      default:
        return '';
    }
  }
}
