// Call Provider — PQ VoIP call state (Faz A: signaling; media is Faz B).
//
// Holds the single active call session and drives the call UI. Incoming calls
// and state changes arrive from the engine event stream (routed here by
// event_handler.dart); user actions (call/answer/decline/end) go back to the
// engine via the FFI call methods.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// UI phase of the current call.
enum CallPhase {
  incoming, // they called us — ringing, awaiting our answer
  outgoing, // we called them — waiting for them to answer
  active, // connected (key agreed; media is Faz B)
  ended, // just ended — brief terminal state before the UI dismisses
}

class CallSession {
  final String callId;
  final String peerFingerprint;
  final CallPhase phase;

  const CallSession({
    required this.callId,
    required this.peerFingerprint,
    required this.phase,
  });

  CallSession copyWith({CallPhase? phase}) => CallSession(
        callId: callId,
        peerFingerprint: peerFingerprint,
        phase: phase ?? this.phase,
      );
}

final callProvider =
    NotifierProvider<CallNotifier, CallSession?>(CallNotifier.new);

class CallNotifier extends Notifier<CallSession?> {
  @override
  CallSession? build() => null;

  DnaEngine? get _engine => ref.read(engineProvider).valueOrNull;

  // ---- driven by engine events (event_handler.dart) ----

  /// Inbound INVITE arrived → show the ring UI.
  void onIncoming(String callId, String peerFingerprint) {
    // Ignore a second incoming call while one is active (busy is handled by the
    // engine's default-deny; here we simply don't replace the visible call).
    if (state != null && state!.phase != CallPhase.ended) return;
    state = CallSession(
      callId: callId,
      peerFingerprint: peerFingerprint,
      phase: CallPhase.incoming,
    );
  }

  /// Call state changed (from a signal or our own action echoing back).
  void onStateChanged(
      String callId, String peerFingerprint, int state, bool isIncoming) {
    switch (state) {
      case DnaCallState.ringing:
        // Our outgoing INVITE was sent → "Calling…". (Incoming ringing is
        // already shown via onIncoming.)
        if (!isIncoming) {
          this.state = CallSession(
            callId: callId,
            peerFingerprint: peerFingerprint,
            phase: CallPhase.outgoing,
          );
        }
        break;
      case DnaCallState.active:
        if (this.state != null && this.state!.callId == callId) {
          this.state = this.state!.copyWith(phase: CallPhase.active);
        }
        break;
      case DnaCallState.ended:
        if (this.state != null && this.state!.callId == callId) {
          this.state = this.state!.copyWith(phase: CallPhase.ended);
        }
        break;
    }
  }

  // ---- user actions ----

  /// Place a call to a contact. UI transition happens via the ringing event.
  bool call(String peerFingerprint) {
    final e = _engine;
    if (e == null) return false;
    return e.callInvite(peerFingerprint);
  }

  /// Answer the ringing incoming call.
  bool answer() {
    final e = _engine;
    final s = state;
    if (e == null || s == null) return false;
    return e.callAccept(s.callId);
  }

  /// Decline the ringing incoming call.
  void decline() {
    final e = _engine;
    final s = state;
    if (e != null && s != null) e.callReject(s.callId);
    state = null;
  }

  /// End the active or outgoing call.
  void hangUp() {
    final e = _engine;
    final s = state;
    if (e != null && s != null) e.callHangup(s.callId);
    state = null;
  }

  /// Dismiss a call in the terminal (ended) phase.
  void dismiss() {
    if (state?.phase == CallPhase.ended) state = null;
  }
}
