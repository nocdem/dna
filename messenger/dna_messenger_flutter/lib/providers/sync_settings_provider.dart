// Sync Settings Provider - Auto-sync configuration for multi-device message backup
// v0.4.60: Automatically backs up messages to DHT at regular intervals

import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../utils/logger.dart' show log, logError;
import 'engine_provider.dart';

// Storage keys
const _kAutoSyncEnabled = 'auto_sync_enabled';
const _kLastSyncTimestamp = 'last_sync_timestamp';
const _kSyncIntervalMinutes = 'sync_interval_minutes';

// Default sync interval: 15 minutes
const int _defaultSyncInterval = 15;

/// Sync settings state
class SyncSettingsState {
  final bool autoSyncEnabled;
  final int syncIntervalMinutes;
  final DateTime? lastSyncTime;
  final bool isSyncing;
  final String? lastSyncError;

  const SyncSettingsState({
    this.autoSyncEnabled = false, // Disabled by default
    this.syncIntervalMinutes = _defaultSyncInterval,
    this.lastSyncTime,
    this.isSyncing = false,
    this.lastSyncError,
  });

  SyncSettingsState copyWith({
    bool? autoSyncEnabled,
    int? syncIntervalMinutes,
    DateTime? lastSyncTime,
    bool? isSyncing,
    String? lastSyncError,
    bool clearLastSyncError = false,
  }) =>
      SyncSettingsState(
        autoSyncEnabled: autoSyncEnabled ?? this.autoSyncEnabled,
        syncIntervalMinutes: syncIntervalMinutes ?? this.syncIntervalMinutes,
        lastSyncTime: lastSyncTime ?? this.lastSyncTime,
        isSyncing: isSyncing ?? this.isSyncing,
        lastSyncError: clearLastSyncError ? null : (lastSyncError ?? this.lastSyncError),
      );
}

/// Sync settings state notifier
class SyncSettingsNotifier extends StateNotifier<SyncSettingsState> {
  final Ref _ref;
  Timer? _syncTimer;

  SyncSettingsNotifier(this._ref) : super(const SyncSettingsState()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final enabled = prefs.getBool(_kAutoSyncEnabled) ?? false;
    final lastTimestamp = prefs.getInt(_kLastSyncTimestamp);
    final interval = prefs.getInt(_kSyncIntervalMinutes) ?? _defaultSyncInterval;

    state = SyncSettingsState(
      autoSyncEnabled: enabled,
      syncIntervalMinutes: interval,
      lastSyncTime: lastTimestamp != null
          ? DateTime.fromMillisecondsSinceEpoch(lastTimestamp * 1000)
          : null,
    );

    // Start timer if auto-sync was enabled
    if (enabled) {
      _startSyncTimer();
    }
  }

  /// Enable/disable auto-sync
  Future<void> setAutoSyncEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kAutoSyncEnabled, enabled);

    state = state.copyWith(autoSyncEnabled: enabled, clearLastSyncError: true);

    if (enabled) {
      _startSyncTimer();
      // Perform initial sync immediately when enabled
      syncNow();
    } else {
      _stopSyncTimer();
    }

    log('SYNC', 'Auto-sync ${enabled ? "enabled" : "disabled"}');
  }

  /// Set sync interval (in minutes)
  Future<void> setSyncInterval(int minutes) async {
    if (minutes < 1 || minutes > 60) return;

    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_kSyncIntervalMinutes, minutes);

    state = state.copyWith(syncIntervalMinutes: minutes);

    // Restart timer with new interval if auto-sync is enabled
    if (state.autoSyncEnabled) {
      _stopSyncTimer();
      _startSyncTimer();
    }
  }

  /// Manually trigger sync now (DHT-Authoritative Sync)
  ///
  /// Performs full sync:
  /// 1. Pull contacts from DHT (REPLACE local)
  /// 2. Restore groups from DHT grouplist
  /// 3. Restore GEKs from DHT backup
  /// 4. Fetch messages from DM outboxes
  Future<void> syncNow() async {
    if (state.isSyncing) {
      log('SYNC', 'Sync already in progress, skipping');
      return;
    }

    state = state.copyWith(isSyncing: true, clearLastSyncError: true);

    try {
      final engineAsync = _ref.read(engineProvider);
      await engineAsync.when(
        data: (engine) async {
          log('SYNC', 'Starting DHT-authoritative sync...');

          // Step 1: Pull contacts from DHT (REPLACE local)
          try {
            log('SYNC', 'Step 1/4: Syncing contacts from DHT...');
            await engine.syncContactsFromDht();
            log('SYNC', 'Contacts synced from DHT');
          } catch (e) {
            log('SYNC', 'Contacts sync failed (non-fatal): $e');
          }

          // Step 2: Restore groups from DHT grouplist
          try {
            log('SYNC', 'Step 2/4: Restoring groups from DHT...');
            await engine.restoreGroupsFromDht();
            log('SYNC', 'Groups restored from DHT');
          } catch (e) {
            log('SYNC', 'Groups restore failed (non-fatal): $e');
          }

          // Step 3: Restore GEKs from DHT backup (v4 format: GEKs + groups only)
          try {
            log('SYNC', 'Step 3/4: Restoring GEKs from DHT backup...');
            final result = await engine.restoreMessages();
            log('SYNC', 'GEKs restored: ${result.processedCount}');
          } catch (e) {
            log('SYNC', 'GEK restore failed (non-fatal): $e');
          }

          // Step 4: Fetch messages from DM outboxes
          try {
            log('SYNC', 'Step 4/4: Checking offline messages from outboxes...');
            await engine.checkOfflineMessages();
            log('SYNC', 'Offline messages checked');
          } catch (e) {
            log('SYNC', 'Offline message check failed (non-fatal): $e');
          }

          // Update timestamp
          final now = DateTime.now();
          final prefs = await SharedPreferences.getInstance();
          await prefs.setInt(_kLastSyncTimestamp, now.millisecondsSinceEpoch ~/ 1000);

          state = state.copyWith(
            isSyncing: false,
            lastSyncTime: now,
            clearLastSyncError: true,
          );

          log('SYNC', 'DHT-authoritative sync complete');
        },
        loading: () {
          state = state.copyWith(
            isSyncing: false,
            lastSyncError: 'Engine not ready',
          );
        },
        error: (e, st) {
          state = state.copyWith(
            isSyncing: false,
            lastSyncError: 'Engine error: $e',
          );
        },
      );
    } catch (e) {
      state = state.copyWith(
        isSyncing: false,
        lastSyncError: 'Sync error: $e',
      );
      logError('SYNC', 'Sync error: $e');
    }
  }

  void _startSyncTimer() {
    _stopSyncTimer(); // Cancel any existing timer

    final interval = Duration(minutes: state.syncIntervalMinutes);
    _syncTimer = Timer.periodic(interval, (_) {
      log('SYNC', 'Timer triggered, starting sync...');
      syncNow();
    });

    log('SYNC', 'Sync timer started (${state.syncIntervalMinutes} min interval)');
  }

  void _stopSyncTimer() {
    _syncTimer?.cancel();
    _syncTimer = null;
  }

  @override
  void dispose() {
    _stopSyncTimer();
    super.dispose();
  }
}

/// Provider for sync settings
final syncSettingsProvider =
    StateNotifierProvider<SyncSettingsNotifier, SyncSettingsState>(
  (ref) => SyncSettingsNotifier(ref),
);
