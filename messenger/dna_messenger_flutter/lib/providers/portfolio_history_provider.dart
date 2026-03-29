// Portfolio History Provider — records hourly portfolio total for sparkline
// Data stored in SharedPreferences, max 168 points (7 days of hourly data).
// Recording is triggered from priceProvider refresh cycle (every 60s check,
// but only writes a new point if 1 hour has passed since the last one).
import 'dart:convert';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../utils/logger.dart';
import 'price_provider.dart';

/// Single data point for portfolio sparkline
class PortfolioDataPoint {
  final int timestamp; // Unix seconds
  final double totalUsd;

  const PortfolioDataPoint({required this.timestamp, required this.totalUsd});

  Map<String, dynamic> toJson() => {'t': timestamp, 'v': totalUsd};

  factory PortfolioDataPoint.fromJson(Map<String, dynamic> json) =>
      PortfolioDataPoint(
        timestamp: json['t'] as int,
        totalUsd: (json['v'] as num).toDouble(),
      );
}

const _spKey = 'portfolio_history_v1';
const _maxPoints = 168; // 7 days * 24 hours
const _recordInterval = Duration(hours: 1);

/// Portfolio history data — list of hourly data points
final portfolioHistoryProvider =
    StateNotifierProvider<PortfolioHistoryNotifier, List<PortfolioDataPoint>>(
  (ref) => PortfolioHistoryNotifier(ref),
);

class PortfolioHistoryNotifier
    extends StateNotifier<List<PortfolioDataPoint>> {
  final Ref _ref;
  bool _initialized = false;

  PortfolioHistoryNotifier(this._ref) : super([]) {
    _init();
  }

  Future<void> _init() async {
    if (_initialized) return;
    _initialized = true;

    // Load existing history from SharedPreferences
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_spKey);
      if (raw != null && raw.isNotEmpty) {
        final List<dynamic> list = jsonDecode(raw);
        state = list
            .map((e) =>
                PortfolioDataPoint.fromJson(e as Map<String, dynamic>))
            .toList();
        log('WALLET', 'Loaded ${state.length} portfolio history points');
      }
    } catch (e) {
      logError('WALLET', 'Failed to load portfolio history: $e');
    }

    // Watch live total and record when interval passes
    _ref.listen<double?>(totalPortfolioValueProvider, (prev, next) {
      if (next != null && next > 0) {
        maybeRecord(next);
      }
    });
  }

  /// Record a data point if enough time has passed since the last one
  void maybeRecord(double totalUsd) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

    if (state.isNotEmpty) {
      final lastTs = state.last.timestamp;
      final elapsed = Duration(seconds: now - lastTs);
      if (elapsed < _recordInterval) return;
    }

    final point = PortfolioDataPoint(timestamp: now, totalUsd: totalUsd);
    final updated = [...state, point];

    // Trim to max points (keep most recent)
    if (updated.length > _maxPoints) {
      state = updated.sublist(updated.length - _maxPoints);
    } else {
      state = updated;
    }

    // Persist (fire-and-forget)
    _persist();
  }

  void _persist() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = jsonEncode(state.map((p) => p.toJson()).toList());
      await prefs.setString(_spKey, raw);
    } catch (_) {
      // Non-fatal
    }
  }
}
