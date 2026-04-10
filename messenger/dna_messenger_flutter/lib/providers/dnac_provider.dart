// DNAC Provider - Digital cash wallet state management
// Lazy init: DNAC context created on first access
// 30s polling sync for wallet updates
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../utils/logger.dart' as logger;
import 'engine_provider.dart';

// =============================================================================
// BALANCE PROVIDER
// =============================================================================

final dnacBalanceProvider =
    AsyncNotifierProvider<DnacBalanceNotifier, DnacBalance?>(
  DnacBalanceNotifier.new,
);

class DnacBalanceNotifier extends AsyncNotifier<DnacBalance?>
    with WidgetsBindingObserver {
  Timer? _syncTimer;

  @override
  Future<DnacBalance?> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return null;

    WidgetsBinding.instance.addObserver(this);
    ref.onDispose(() {
      _syncTimer?.cancel();
      WidgetsBinding.instance.removeObserver(this);
    });

    // Start 30s polling
    _startPolling();

    // Initial balance fetch
    return _fetchBalance();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive) {
      _syncTimer?.cancel();
      _syncTimer = null;
    } else if (state == AppLifecycleState.resumed) {
      _startPolling();
    }
  }

  Future<DnacBalance?> _fetchBalance() async {
    try {
      final engine = await ref.read(engineProvider.future);
      return await engine.dnacGetBalance();
    } catch (e) {
      logger.logError('DNAC', 'Balance fetch failed: $e');
      return this.state.valueOrNull;
    }
  }

  void _startPolling() {
    _syncTimer?.cancel();
    _syncTimer = Timer.periodic(const Duration(seconds: 30), (_) async {
      try {
        final engine = await ref.read(engineProvider.future);
        await engine.dnacSync();
        final balance = await engine.dnacGetBalance();
        state = AsyncValue.data(balance);
      } catch (e) {
        logger.logError('DNAC', 'Sync poll failed: $e');
      }
    });
  }

  /// Manual sync triggered by user
  Future<void> sync() async {
    try {
      final engine = await ref.read(engineProvider.future);
      await engine.dnacSync();
      final balance = await engine.dnacGetBalance();
      state = AsyncValue.data(balance);
    } catch (e) {
      logger.logError('DNAC', 'Manual sync failed: $e');
      rethrow;
    }
  }

  /// Send DNAC payment and refresh all state.
  ///
  /// [tokenId] selects a custom token (64 bytes). When null, sends native
  /// DNAC. Fee (0.1%) is charged in the same token either way.
  Future<void> sendPayment({
    required String recipientFingerprint,
    required int amount,
    String? memo,
    Uint8List? tokenId,
  }) async {
    final engine = await ref.read(engineProvider.future);
    await engine.dnacSend(
      recipientFingerprint: recipientFingerprint,
      amount: amount,
      memo: memo,
      tokenId: tokenId,
    );

    // Await balance refresh so UI updates immediately
    await refreshBalance();
    ref.invalidate(dnacHistoryProvider);
    ref.invalidate(dnacUtxosProvider);
    // Token balances are keyed by tokenIdHex — invalidate the family
    if (tokenId != null) {
      ref.invalidate(dnacTokenBalanceProvider);
    }
  }

  /// Refresh balance without sync (after send)
  Future<void> refreshBalance() async {
    final balance = await _fetchBalance();
    if (balance != null) {
      state = AsyncValue.data(balance);
    }
  }
}

// =============================================================================
// HISTORY PROVIDER
// =============================================================================

final dnacHistoryProvider =
    AsyncNotifierProvider<DnacHistoryNotifier, List<DnacTxHistory>>(
  DnacHistoryNotifier.new,
);

class DnacHistoryNotifier extends AsyncNotifier<List<DnacTxHistory>> {
  @override
  Future<List<DnacTxHistory>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return [];

    try {
      final engine = await ref.read(engineProvider.future);
      return await engine.dnacGetHistory();
    } catch (e) {
      logger.logError('DNAC', 'History fetch failed: $e');
      return [];
    }
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.dnacGetHistory();
    });
  }
}

// =============================================================================
// UTXO PROVIDER
// =============================================================================

final dnacUtxosProvider =
    AsyncNotifierProvider<DnacUtxosNotifier, List<DnacUtxo>>(
  DnacUtxosNotifier.new,
);

class DnacUtxosNotifier extends AsyncNotifier<List<DnacUtxo>> {
  @override
  Future<List<DnacUtxo>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return [];

    try {
      final engine = await ref.read(engineProvider.future);
      return await engine.dnacGetUtxos();
    } catch (e) {
      logger.logError('DNAC', 'UTXOs fetch failed: $e');
      return [];
    }
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.dnacGetUtxos();
    });
  }
}

// =============================================================================
// TOKEN LIST PROVIDER
// =============================================================================

final dnacTokenListProvider =
    AsyncNotifierProvider<DnacTokenListNotifier, List<DnacToken>>(
  DnacTokenListNotifier.new,
);

class DnacTokenListNotifier extends AsyncNotifier<List<DnacToken>> {
  @override
  Future<List<DnacToken>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return [];

    try {
      final engine = await ref.read(engineProvider.future);
      return await engine.dnacTokenList();
    } catch (e) {
      logger.logError('DNAC', 'Token list fetch failed: $e');
      return [];
    }
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.dnacTokenList();
    });
  }
}

// =============================================================================
// TOKEN BALANCE PROVIDER (per token_id)
// =============================================================================

/// Family parameter is hex string (NOT List<int>) — strings have value equality
/// in Dart, so the same token_id from two rebuilds yields the same provider
/// instance and avoids infinite re-creation.
final dnacTokenBalanceProvider =
    FutureProvider.family<DnacBalance?, String>((ref, tokenIdHex) async {
  final identityLoaded = ref.watch(identityLoadedProvider);
  if (!identityLoaded) return null;

  try {
    final engine = await ref.read(engineProvider.future);
    final tokenId = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      tokenId[i] = int.parse(tokenIdHex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return await engine.dnacTokenBalance(tokenId);
  } catch (e) {
    logger.logError('DNAC', 'Token balance fetch failed: $e');
    return null;
  }
});
