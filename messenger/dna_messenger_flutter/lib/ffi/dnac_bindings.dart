// DNAC Stake & Delegation — high-level FFI wrappers for DnaEngine.
//
// Phase 16 Task 71. Thin async adapters over the raw C bindings
// (dna_bindings.dart) for the stake/delegation APIs shipped in Phase 7
// (builders) and Phase 14 (queries). The engine forwards each call
// through its async task queue — callbacks come back on the main
// isolate via dart:ffi NativeCallable.listener.
//
// ignore_for_file: non_constant_identifier_names, camel_case_types
import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'dna_bindings.dart';
import 'dna_engine.dart';
import '../utils/logger.dart' as logger;

/// One validator / committee member as returned by the witness queries.
class DnacValidator {
  /// 2592-byte Dilithium5 public key.
  final Uint8List pubkey;

  /// Operator's own stake in raw units (0 for committee entries — the
  /// committee projection aggregates self + delegated into [totalDelegated]).
  final int selfStake;

  /// Aggregate stake (delegated + self for committee entries, delegated only
  /// for list entries) in raw units.
  final int totalDelegated;

  /// Commission in basis points (0..10000 → 0%..100%).
  final int commissionBps;

  /// Validator status: 0 = ACTIVE, 1 = RETIRING, 2 = UNSTAKED.
  final int status;

  /// Block height when the validator became ACTIVE (0 for committee entries).
  final int activeSinceBlock;

  const DnacValidator({
    required this.pubkey,
    required this.selfStake,
    required this.totalDelegated,
    required this.commissionBps,
    required this.status,
    required this.activeSinceBlock,
  });

  /// Short display id (first 16 hex chars of the SHA3-512 of pubkey is
  /// the canonical fingerprint — this is a cheaper surface for UI only).
  String get shortId {
    if (pubkey.length < 8) return '????????';
    final b = StringBuffer();
    for (var i = 0; i < 8; i++) {
      b.write(pubkey[i].toRadixString(16).padLeft(2, '0'));
    }
    return b.toString();
  }

  /// Total stake (self + delegated) in raw units. Useful for committee ranking.
  int get totalStakeRaw => selfStake + totalDelegated;

  /// Commission as a fractional percentage (0..100.0).
  double get commissionPct => commissionBps / 100.0;
}

/// Validator status constants — kept separate from DnacValidator so UI code
/// can refer to them without instantiating.
abstract class DnacValidatorStatus {
  static const int active = 0;
  static const int retiring = 1;
  static const int unstaked = 2;
}

/// One of the wallet owner's active delegations (mirror of
/// dnac_delegation_t in dnac/include/dnac/dnac.h).
class DnacDelegation {
  /// 128-char lowercase hex fingerprint of the validator's pubkey.
  /// Rendered server-side — correlate against a validator's pubkey via
  /// DnaEngine.pubkeyToFingerprint when cross-referencing.
  final String validatorFp;

  /// Delegated amount in raw units (1 DNAC = 100_000_000 raw).
  final int amountRaw;

  /// Block height at which the DELEGATE TX committed.
  final int delegatedAtBlock;

  const DnacDelegation({
    required this.validatorFp,
    required this.amountRaw,
    required this.delegatedAtBlock,
  });
}

/// Extension mixing stake/delegation APIs into the main DnaEngine class.
/// Each call submits a task to the async engine and awaits the completion /
/// result callback.
extension DnacStakeDelegation on DnaEngine {
  // ===========================================================================
  // Private helpers
  // ===========================================================================

  /// Convert a pubkey [Uint8List] to a malloc'd C buffer. Caller frees.
  Pointer<Uint8> _pubkeyToNative(Uint8List pubkey) {
    if (pubkey.length != 2592) {
      throw ArgumentError(
          'validator pubkey must be 2592 bytes (Dilithium5), got ${pubkey.length}');
    }
    final ptr = calloc<Uint8>(2592);
    for (var i = 0; i < 2592; i++) {
      ptr[i] = pubkey[i];
    }
    return ptr;
  }

  /// Pull a 2592-byte pubkey out of a dna_dnac_validator_entry_t.
  Uint8List _pubkeyFromStruct(dna_dnac_validator_entry_t s) {
    final bytes = Uint8List(2592);
    for (var i = 0; i < 2592; i++) {
      bytes[i] = s.pubkey[i];
    }
    return bytes;
  }

  // ===========================================================================
  // Builder transactions (await a completion result)
  // ===========================================================================

  /// STAKE — become a validator. Consumes 10M DNAC self-stake + fee.
  ///
  /// [commissionBps] is 0..10000 (basis points).
  /// [unstakeDestinationFp] is the 128-hex fingerprint that receives the
  /// post-cooldown UTXO when UNSTAKE matures (by convention your own fp).
  Future<void> dnacStake({
    required int commissionBps,
    required String unstakeDestinationFp,
  }) async {
    final completer = Completer<void>();
    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, bindings));
      }
    }

    final cb = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    final fpPtr = unstakeDestinationFp.toNativeUtf8();
    try {
      final requestId = bindings.dna_engine_dnac_stake(
        engine,
        commissionBps,
        fpPtr,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(-1, 'Failed to submit DNAC stake request');
      }
      await completer.future;
    } finally {
      calloc.free(fpPtr);
      cb.close();
    }
  }

  /// UNSTAKE — retire the caller's validator record (triggers cooldown).
  Future<void> dnacUnstake() async {
    final completer = Completer<void>();
    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, bindings));
      }
    }

    final cb = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    try {
      final requestId = bindings.dna_engine_dnac_unstake(
          engine, cb.nativeFunction.cast(), nullptr);
      if (requestId == 0) {
        throw DnaEngineException(-1, 'Failed to submit DNAC unstake request');
      }
      await completer.future;
    } finally {
      cb.close();
    }
  }

  /// DELEGATE — stake native DNAC with a validator (min 100 DNAC).
  Future<void> dnacDelegate({
    required Uint8List validatorPubkey,
    required int amountRaw,
  }) async {
    if (amountRaw <= 0) {
      throw ArgumentError('amountRaw must be > 0');
    }
    final completer = Completer<void>();
    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, bindings));
      }
    }

    final cb = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    final pkPtr = _pubkeyToNative(validatorPubkey);
    try {
      final requestId = bindings.dna_engine_dnac_delegate(
        engine,
        pkPtr,
        amountRaw,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(-1, 'Failed to submit DNAC delegate request');
      }
      await completer.future;
    } finally {
      calloc.free(pkPtr);
      cb.close();
    }
  }

  /// UNDELEGATE — withdraw (part of) an existing delegation.
  Future<void> dnacUndelegate({
    required Uint8List validatorPubkey,
    required int amountRaw,
  }) async {
    if (amountRaw <= 0) {
      throw ArgumentError('amountRaw must be > 0');
    }
    final completer = Completer<void>();
    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, bindings));
      }
    }

    final cb = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    final pkPtr = _pubkeyToNative(validatorPubkey);
    try {
      final requestId = bindings.dna_engine_dnac_undelegate(
        engine,
        pkPtr,
        amountRaw,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(
            -1, 'Failed to submit DNAC undelegate request');
      }
      await completer.future;
    } finally {
      calloc.free(pkPtr);
      cb.close();
    }
  }

  /// VALIDATOR_UPDATE — change commission on the caller's validator record.
  ///
  /// An increase takes effect at the next epoch boundary; a decrease is
  /// immediate. [signedAtBlock] is a freshness anchor (use current witness
  /// block height).
  Future<void> dnacValidatorUpdate({
    required int newCommissionBps,
    required int signedAtBlock,
  }) async {
    final completer = Completer<void>();
    void onComplete(int requestId, int error, Pointer<Void> userData) {
      if (error == 0) {
        completer.complete();
      } else {
        completer.completeError(DnaEngineException.fromCode(error, bindings));
      }
    }

    final cb = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
    try {
      final requestId = bindings.dna_engine_dnac_validator_update(
        engine,
        newCommissionBps,
        signedAtBlock,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(
            -1, 'Failed to submit DNAC validator-update request');
      }
      await completer.future;
    } finally {
      cb.close();
    }
  }

  // ===========================================================================
  // Queries (Phase 14)
  // ===========================================================================

  /// List validators (optionally filtered by status).
  ///
  /// Pass -1 to include all statuses, or a DnacValidatorStatus constant.
  Future<List<DnacValidator>> dnacValidatorList({int filterStatus = -1}) async {
    final completer = Completer<List<DnacValidator>>();
    void onComplete(int requestId, int error,
        Pointer<dna_dnac_validator_entry_t> entries, int count,
        Pointer<Void> userData) {
      try {
        if (error != 0) {
          // Treat "not implemented" / "network" as empty list for graceful UI
          logger.log('DNAC_STAKE', 'validator_list error $error');
          completer.complete(<DnacValidator>[]);
          return;
        }
        final out = <DnacValidator>[];
        for (var i = 0; i < count; i++) {
          final s = (entries + i).ref;
          out.add(DnacValidator(
            pubkey: _pubkeyFromStruct(s),
            selfStake: s.self_stake,
            totalDelegated: s.total_delegated,
            commissionBps: s.commission_bps,
            status: s.status,
            activeSinceBlock: s.active_since_block,
          ));
        }
        completer.complete(out);
      } finally {
        if (count > 0 && entries != nullptr) {
          bindings.dna_engine_dnac_free_validator_entries(entries, count);
        }
      }
    }

    final cb = NativeCallable<DnaDnacValidatorListCbNative>.listener(onComplete);
    try {
      final requestId = bindings.dna_engine_dnac_validator_list(
        engine,
        filterStatus,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(
            -1, 'Failed to submit DNAC validator-list request');
      }
      return await completer.future;
    } finally {
      cb.close();
    }
  }

  /// Fetch the current epoch's BFT committee (top-N validators up to
  /// DNAC_COMMITTEE_SIZE == 7). Returns an empty list if no committee is
  /// available (bootstrap or RPC-not-wired).
  Future<List<DnacValidator>> dnacGetCommittee() async {
    final completer = Completer<List<DnacValidator>>();
    void onComplete(int requestId, int error,
        Pointer<dna_dnac_validator_entry_t> entries, int count,
        Pointer<Void> userData) {
      try {
        if (error != 0) {
          logger.log('DNAC_STAKE', 'committee query error $error');
          completer.complete(<DnacValidator>[]);
          return;
        }
        final out = <DnacValidator>[];
        for (var i = 0; i < count; i++) {
          final s = (entries + i).ref;
          out.add(DnacValidator(
            pubkey: _pubkeyFromStruct(s),
            selfStake: s.self_stake,
            totalDelegated: s.total_delegated,
            commissionBps: s.commission_bps,
            status: s.status,
            activeSinceBlock: s.active_since_block,
          ));
        }
        completer.complete(out);
      } finally {
        if (count > 0 && entries != nullptr) {
          bindings.dna_engine_dnac_free_validator_entries(entries, count);
        }
      }
    }

    final cb = NativeCallable<DnaDnacValidatorListCbNative>.listener(onComplete);
    try {
      final requestId = bindings.dna_engine_dnac_get_committee(
        engine,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(
            -1, 'Failed to submit DNAC committee request');
      }
      return await completer.future;
    } finally {
      cb.close();
    }
  }

  /// Fetch the caller's own active delegations from witnesses. Authenticated
  /// server-side via C11 (session fp must match SHA3-512(signing_pubkey)),
  /// so this only ever returns THIS wallet's positions — never another
  /// user's.
  ///
  /// Returns an empty list if the wallet has no active delegations OR the
  /// witness query fails (graceful degradation for offline/degraded UX).
  /// Specific error codes are logged but not surfaced to the caller.
  Future<List<DnacDelegation>> dnacGetMyDelegations() async {
    final completer = Completer<List<DnacDelegation>>();
    void onComplete(int requestId, int error,
        Pointer<dna_dnac_delegation_t> entries, int count,
        Pointer<Void> userData) {
      try {
        if (error != 0) {
          logger.log('DNAC_STAKE', 'my_delegations error $error');
          completer.complete(<DnacDelegation>[]);
          return;
        }
        final out = <DnacDelegation>[];
        for (var i = 0; i < count; i++) {
          final s = (entries + i).ref;
          // validator_fp is NUL-terminated 128-hex; pull chars until NUL.
          final fpBuf = StringBuffer();
          for (var j = 0; j < 129; j++) {
            final c = s.validator_fp[j];
            if (c == 0) break;
            fpBuf.writeCharCode(c);
          }
          out.add(DnacDelegation(
            validatorFp: fpBuf.toString(),
            amountRaw: s.amount_raw,
            delegatedAtBlock: s.delegated_at_block,
          ));
        }
        completer.complete(out);
      } finally {
        if (count > 0 && entries != nullptr) {
          bindings.dna_engine_dnac_free_delegations(entries, count);
        }
      }
    }

    final cb = NativeCallable<DnaDnacDelegationsCbNative>.listener(onComplete);
    try {
      final requestId = bindings.dna_engine_dnac_get_delegations(
        engine,
        cb.nativeFunction.cast(),
        nullptr,
      );
      if (requestId == 0) {
        throw DnaEngineException(
            -1, 'Failed to submit DNAC my-delegations request');
      }
      return await completer.future;
    } finally {
      cb.close();
    }
  }
}
