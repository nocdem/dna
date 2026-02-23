// Price Provider - Fetches cryptocurrency prices from BitcoinTry API
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../utils/logger.dart';
import 'wallet_provider.dart';

/// Simple data class for price information
class PriceData {
  final double price;
  final double changePercent24h;

  const PriceData({required this.price, required this.changePercent24h});
}

/// Maps token symbols to their BitcoinTry API pair names
const _tokenPairMap = <String, String?>{
  'ETH': 'ETH_USDT',
  'SOL': 'SOL_USDT',
  'TRX': 'TRX_USDT',
  'CELL': 'CELL_USDT',
  'CPUNK': 'CPUNK_USDT',
  'KEL': 'KEL_USDT',
  'NYS': 'NYS_USDT',
  'USDT': null, // Already USDT — hardcoded
  'USDC': 'USDC_USDT',
};

const _apiUrl = 'https://api.bitcointry.com/api/v1/ticker';
const _cacheDuration = Duration(seconds: 30);
const _refreshInterval = Duration(seconds: 60);
const _connectionTimeout = Duration(seconds: 10);

DateTime? _lastFetchTime;
Map<String, PriceData>? _cachedPrices;

/// Fetches prices from BitcoinTry API.
/// Returns Map<String, PriceData> keyed by uppercase token symbol.
/// Auto-refreshes every 60 seconds. Caches results for 30 seconds.
final priceProvider = FutureProvider<Map<String, PriceData>>((ref) async {
  // Return cache if still fresh
  if (_cachedPrices != null && _lastFetchTime != null) {
    final elapsed = DateTime.now().difference(_lastFetchTime!);
    if (elapsed < _cacheDuration) {
      _scheduleRefresh(ref);
      return _cachedPrices!;
    }
  }

  final prices = await _fetchPrices();
  _cachedPrices = prices;
  _lastFetchTime = DateTime.now();

  // Keep the provider alive and schedule auto-refresh
  ref.keepAlive();
  _scheduleRefresh(ref);

  return prices;
});

void _scheduleRefresh(FutureProviderRef<Map<String, PriceData>> ref) {
  final timer = Timer(_refreshInterval, () {
    _cachedPrices = null;
    _lastFetchTime = null;
    ref.invalidateSelf();
  });
  ref.onDispose(timer.cancel);
}

Future<Map<String, PriceData>> _fetchPrices() async {
  final prices = <String, PriceData>{};

  // Always include USDT as 1:1
  prices['USDT'] = const PriceData(price: 1.0, changePercent24h: 0.0);

  try {
    final client = HttpClient();
    client.connectionTimeout = _connectionTimeout;

    final request = await client.getUrl(Uri.parse(_apiUrl));
    final response = await request.close().timeout(_connectionTimeout);

    if (response.statusCode != 200) {
      log('PRICE', 'API returned status ${response.statusCode}');
      await response.drain<void>();
      client.close();
      return prices;
    }

    final body = await response.transform(utf8.decoder).join();
    client.close();

    final Map<String, dynamic> json = jsonDecode(body) as Map<String, dynamic>;

    for (final entry in _tokenPairMap.entries) {
      final token = entry.key;
      final pair = entry.value;

      if (pair == null) continue; // Skip USDT — already hardcoded

      final pairData = json[pair];
      if (pairData is Map<String, dynamic>) {
        final lastPrice = double.tryParse(
          (pairData['last_price'] ?? '').toString(),
        );
        final change24h = double.tryParse(
          (pairData['price_change_percent_24h'] ?? '0').toString(),
        );

        if (lastPrice != null) {
          prices[token] = PriceData(
            price: lastPrice,
            changePercent24h: change24h ?? 0.0,
          );
        }
      }
    }

    log('PRICE', 'Fetched ${prices.length} token prices');
  } catch (e) {
    logError('PRICE', 'Failed to fetch prices: $e');
  }

  return prices;
}

/// Helper: returns the USDT value for a given token and balance string.
/// Returns null if prices are not loaded or token is unknown.
final tokenUsdValueProvider =
    Provider.family<double?, ({String token, String balance})>((ref, params) {
  final prices = ref.watch(priceProvider);
  return prices.whenOrNull(data: (priceMap) {
    final priceData = priceMap[params.token.toUpperCase()];
    if (priceData == null) return null;
    final balance = double.tryParse(params.balance);
    if (balance == null) return null;
    return balance * priceData.price;
  });
});

/// Sums up (balance * price) across all wallets / tokens.
/// Returns null if prices are not loaded yet.
final totalPortfolioValueProvider = Provider<double?>((ref) {
  final prices = ref.watch(priceProvider);
  final allBalances = ref.watch(allBalancesProvider);

  return prices.whenOrNull(data: (priceMap) {
    return allBalances.whenOrNull(data: (balances) {
      double total = 0.0;
      for (final wb in balances) {
        final token = wb.balance.token.toUpperCase();
        final priceData = priceMap[token];
        if (priceData == null) continue;
        final amount = double.tryParse(wb.balance.balance);
        if (amount == null) continue;
        total += amount * priceData.price;
      }
      return total;
    });
  });
});
