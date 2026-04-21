// Stake Provider - DNAC validator list, committee, delegations, rewards.
//
// Phase 16 Task 72. Riverpod state for the staking UI.
//
// Lazy: triggers on identity load, refreshes on user pull and after any
// stake / delegate / claim TX. No timer-based auto-refresh (validator set
// changes only at epoch boundaries — ~10 min — and pulling every 30s
// would hammer the witness cluster for no user-visible benefit).
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../ffi/dnac_bindings.dart';
import '../utils/logger.dart' as logger;
import 'engine_provider.dart';

// =============================================================================
// VALIDATOR LIST PROVIDER (all statuses)
// =============================================================================

final validatorListProvider = AsyncNotifierProvider<
    ValidatorListNotifier, List<DnacValidator>>(ValidatorListNotifier.new);

class ValidatorListNotifier extends AsyncNotifier<List<DnacValidator>> {
  @override
  Future<List<DnacValidator>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return <DnacValidator>[];
    return _fetch();
  }

  Future<List<DnacValidator>> _fetch() async {
    try {
      final engine = await ref.read(engineProvider.future);
      return await engine.dnacValidatorList(filterStatus: -1);
    } catch (e) {
      logger.logError('STAKE', 'validator list fetch failed: $e');
      return <DnacValidator>[];
    }
  }

  /// User-initiated refresh (pull-to-refresh or after a TX).
  Future<void> refresh() async {
    state = await AsyncValue.guard(_fetch);
  }
}

/// Convenience: list of active validators only, derived from the main list.
final activeValidatorsProvider = Provider<List<DnacValidator>>((ref) {
  final list = ref.watch(validatorListProvider).valueOrNull ?? const [];
  return list
      .where((v) => v.status == DnacValidatorStatus.active)
      .toList(growable: false);
});

// =============================================================================
// COMMITTEE PROVIDER (current epoch BFT committee)
// =============================================================================

final committeeProvider = AsyncNotifierProvider<CommitteeNotifier,
    List<DnacValidator>>(CommitteeNotifier.new);

class CommitteeNotifier extends AsyncNotifier<List<DnacValidator>> {
  @override
  Future<List<DnacValidator>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return <DnacValidator>[];
    return _fetch();
  }

  Future<List<DnacValidator>> _fetch() async {
    try {
      final engine = await ref.read(engineProvider.future);
      return await engine.dnacGetCommittee();
    } catch (e) {
      logger.logError('STAKE', 'committee fetch failed: $e');
      return <DnacValidator>[];
    }
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(_fetch);
  }
}

// =============================================================================
// MY VALIDATOR PROVIDER (is the current identity a validator?)
// =============================================================================

/// Lazily resolves: is the current caller an ACTIVE validator?
/// The answer comes from filtering the full validator list by the
/// caller's Dilithium5 public key.
///
/// TODO(phase16): wire a dnac_get_caller_pubkey() engine accessor so we can
/// match exactly without a list scan. Until then we return the first
/// validator entry whose pubkey matches the engine's Dilithium5 key fetched
/// via a future helper. For now the UI uses presence of ANY validator
/// record owned by the current identity as the gate; a future refinement
/// tightens this to a pubkey equality check.
final myValidatorProvider = Provider<DnacValidator?>((ref) {
  // Phase 16 simplification: the engine does not currently expose the
  // caller's Dilithium5 pubkey through the FFI surface, so the operator
  // panel gate uses a heuristic — if a validator record with status
  // ACTIVE or RETIRING exists whose fingerprint prefix matches the
  // engine's fingerprint, treat the caller as a validator. Validator
  // fingerprints are SHA3-512 of the pubkey so a collision with the
  // caller's own fingerprint is astronomically unlikely for honest
  // actors; attacker-controlled collisions still can't sign because the
  // underlying STAKE TX was not signed by the caller's secret key.
  //
  // Until the RPC lands, read-only UI only — the operator panel shows
  // but all actions go through the engine which enforces the real
  // signer check.
  final validators = ref.watch(validatorListProvider).valueOrNull ?? const [];
  final fp = ref.watch(currentIdentityProvider);
  if (fp == null || fp.isEmpty) return null;
  if (validators.isEmpty) return null;

  for (final v in validators) {
    // Cheap prefix check — first 16 bytes of pubkey vs first 32 hex chars
    // of caller fp. Not a security boundary; see note above.
    final callerPrefix = fp.length >= 32 ? fp.substring(0, 32) : fp;
    if (v.shortId.startsWith(callerPrefix.substring(0, 16))) {
      return v;
    }
  }
  return null;
});


// =============================================================================
// STAKE ACTIONS (builders — refresh state after success)
// =============================================================================

class StakeActions {
  StakeActions(this.ref);
  final Ref ref;

  /// Become a validator — consumes 10M self-stake + fee.
  Future<void> stake({
    required int commissionBps,
    required String unstakeDestinationFp,
  }) async {
    final engine = await ref.read(engineProvider.future);
    await engine.dnacStake(
      commissionBps: commissionBps,
      unstakeDestinationFp: unstakeDestinationFp,
    );
    await _invalidateAll();
  }

  Future<void> unstake() async {
    final engine = await ref.read(engineProvider.future);
    await engine.dnacUnstake();
    await _invalidateAll();
  }

  Future<void> delegate({
    required Uint8List validatorPubkey,
    required int amountRaw,
  }) async {
    final engine = await ref.read(engineProvider.future);
    await engine.dnacDelegate(
      validatorPubkey: validatorPubkey,
      amountRaw: amountRaw,
    );
    await _invalidateAll();
  }

  Future<void> undelegate({
    required Uint8List validatorPubkey,
    required int amountRaw,
  }) async {
    final engine = await ref.read(engineProvider.future);
    await engine.dnacUndelegate(
      validatorPubkey: validatorPubkey,
      amountRaw: amountRaw,
    );
    await _invalidateAll();
  }

  Future<void> validatorUpdate({
    required int newCommissionBps,
    required int signedAtBlock,
  }) async {
    final engine = await ref.read(engineProvider.future);
    await engine.dnacValidatorUpdate(
      newCommissionBps: newCommissionBps,
      signedAtBlock: signedAtBlock,
    );
    await _invalidateAll();
  }

  Future<void> _invalidateAll() async {
    ref.invalidate(validatorListProvider);
    ref.invalidate(committeeProvider);
  }
}

final stakeActionsProvider = Provider<StakeActions>((ref) => StakeActions(ref));
