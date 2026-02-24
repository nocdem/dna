// Price Provider - Fetches cryptocurrency prices from BitcoinTry API
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../utils/logger.dart';
import 'wallet_provider.dart';

/// Simple data class for price information
class PriceData {
  final double price;
  final double changePercent24h;

  const PriceData({required this.price, required this.changePercent24h});

  Map<String, dynamic> toJson() => {'p': price, 'c': changePercent24h};

  factory PriceData.fromJson(Map<String, dynamic> json) => PriceData(
    price: (json['p'] as num).toDouble(),
    changePercent24h: (json['c'] as num).toDouble(),
  );
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

const _spPriceCacheKey = 'price_cache';
bool _spPriceCacheChecked = false;

DateTime? _lastFetchTime;
Map<String, PriceData>? _cachedPrices;

/// Fetches prices from BitcoinTry API.
/// Returns Map<String, PriceData> keyed by uppercase token symbol.
/// Auto-refreshes every 60 seconds. Caches results for 30 seconds.
/// v0.100.110: SharedPreferences cache for instant cold-start USD display.
final priceProvider = FutureProvider<Map<String, PriceData>>((ref) async {
  // 1. Return in-memory cache if still fresh
  if (_cachedPrices != null && _lastFetchTime != null) {
    final elapsed = DateTime.now().difference(_lastFetchTime!);
    if (elapsed < _cacheDuration) {
      _scheduleRefresh(ref);
      return _cachedPrices!;
    }
  }

  // 2. Cold start: load SP cache for instant display (checked only once)
  if (_cachedPrices == null && !_spPriceCacheChecked) {
    _spPriceCacheChecked = true;
    final spCached = await _loadPriceCache();
    if (spCached.isNotEmpty) {
      log('PRICE', 'Loaded ${spCached.length} prices from cache (cold start)');
      _cachedPrices = spCached;
      ref.keepAlive();
      // Schedule fresh fetch shortly — SP data shown instantly, API replaces it
      final timer = Timer(const Duration(milliseconds: 500), () {
        _cachedPrices = null;
        ref.invalidateSelf();
      });
      ref.onDispose(timer.cancel);
      return spCached;
    }
  }

  // 3. Fetch from API
  final prices = await _fetchPrices();

  // If API failed (only USDT returned), try SP cache as fallback
  if (prices.length <= 1) {
    final spFallback = await _loadPriceCache();
    if (spFallback.isNotEmpty) {
      _cachedPrices = spFallback;
      _lastFetchTime = DateTime.now();
      ref.keepAlive();
      _scheduleRefresh(ref);
      return spFallback;
    }
  }

  _cachedPrices = prices;
  _lastFetchTime = DateTime.now();

  // Save to SP for next cold start
  if (prices.length > 1) _savePriceCache(prices);

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

/// Save prices to SharedPreferences for cold-start display
void _savePriceCache(Map<String, PriceData> prices) async {
  try {
    final prefs = await SharedPreferences.getInstance();
    final map = prices.map((k, v) => MapEntry(k, v.toJson()));
    await prefs.setString(_spPriceCacheKey, jsonEncode(map));
  } catch (_) {
    // Non-fatal — in-memory cache is primary
  }
}

/// Load prices from SharedPreferences (no network needed)
Future<Map<String, PriceData>> _loadPriceCache() async {
  try {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_spPriceCacheKey);
    if (raw == null || raw.isEmpty) return {};
    final Map<String, dynamic> map = jsonDecode(raw) as Map<String, dynamic>;
    return map.map((k, v) =>
        MapEntry(k, PriceData.fromJson(v as Map<String, dynamic>)));
  } catch (_) {
    return {};
  }
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

/// Cached portfolio total — shows last known USD value on cold start.
/// Watches live total: saves to SP when available, loads from SP as fallback.
/// v0.100.111: Eliminates $0.00 flash on cold start.
const _portfolioTotalCacheKey = 'wallet_portfolio_total_usd';

final cachedPortfolioTotalProvider = FutureProvider<double>((ref) async {
  final liveTotal = ref.watch(totalPortfolioValueProvider);

  if (liveTotal != null && liveTotal > 0) {
    // Live total available — save for next cold start (fire-and-forget)
    SharedPreferences.getInstance().then((prefs) {
      prefs.setDouble(_portfolioTotalCacheKey, liveTotal);
    });
    return liveTotal;
  }

  // Live total not ready — load cached value from SP
  final prefs = await SharedPreferences.getInstance();
  return prefs.getDouble(_portfolioTotalCacheKey) ?? 0.0;
});

/// Weighted 24h portfolio change percentage.
/// Calculates: (currentTotal - previousTotal) / previousTotal × 100
/// where previousTotal uses prices from 24h ago (derived from changePercent24h).
final portfolioChange24hProvider = Provider<double?>((ref) {
  final prices = ref.watch(priceProvider);
  final allBalances = ref.watch(allBalancesProvider);

  return prices.whenOrNull(data: (priceMap) {
    return allBalances.whenOrNull(data: (balances) {
      double currentTotal = 0.0;
      double previousTotal = 0.0;

      for (final wb in balances) {
        final token = wb.balance.token.toUpperCase();
        final priceData = priceMap[token];
        if (priceData == null) continue;
        final amount = double.tryParse(wb.balance.balance);
        if (amount == null || amount <= 0) continue;

        final currentValue = amount * priceData.price;
        final previousPrice = priceData.changePercent24h != -100
            ? priceData.price / (1 + priceData.changePercent24h / 100)
            : priceData.price;
        final previousValue = amount * previousPrice;

        currentTotal += currentValue;
        previousTotal += previousValue;
      }

      if (previousTotal <= 0) return null;
      return ((currentTotal - previousTotal) / previousTotal) * 100;
    });
  });
});
